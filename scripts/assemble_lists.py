#!/usr/bin/env python3
"""
Adblock List Assembler
Compiles, normalizes, deduplicates, and generates multiple adblock list formats
(uBlock Origin, AdGuard, DNS filter, Hosts, and Domains) from raw source lists.
"""

import argparse
import os
import re
import sys
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# RFC-compliant domain regex (supports alphanumeric, hyphens, subdomains, TLDs)
DOMAIN_RE = re.compile(
    r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$',
    re.IGNORECASE
)

# IPv4 address regex
IPV4_RE = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)

# Hosts line regex (starts with loopback or 0.0.0.0 or ::1 / ::)
HOSTS_LINE_RE = re.compile(
    r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1|::|0)\s+(.+)$',
    re.IGNORECASE
)

# Cosmetic filter markers
COSMETIC_MARKERS = ('##', '#@#', '#$#', '#@$#', '#%#', '#@%#', '#?#', '#$?#')

# DNS-compatible modifier keys
DNS_MODIFIERS = ('dnsrewrite=', 'dnstype=', 'client=', 'ctag=', 'denyallow=')

# Known network/browser-only modifier keys
BROWSER_ONLY_MODIFIERS = (
    'image', 'script', 'stylesheet', 'font', 'subdocument', 'xmlhttprequest',
    'websocket', 'media', 'other', 'third-party', '3p', 'first-party', '1p',
    'popup', 'popunder', 'csp=', 'redirect=', 'redirect-rule=', 'removeparam',
    'queryprune', 'empty', 'mp4', 'all', 'elemhide', 'generichide', 'genericblock'
)

# Localhost/loopback domains to ignore in hosts files
IGNORED_HOSTS = {
    'localhost', 'localhost.localdomain', 'local', 'broadcasthost',
    'ip6-localhost', 'ip6-loopback', '0.0.0.0', '127.0.0.1', '::1', '::'
}


def clean_line(line: str) -> str:
    """Strip trailing CRLF, leading/trailing whitespace, and optional enclosing backticks."""
    line = line.replace('\r', '').strip()
    if line.startswith('`') and line.endswith('`') and len(line) >= 2:
        line = line[1:-1].strip()
    return line


def is_comment_or_empty(line: str) -> bool:
    """Return True if line is empty or a standalone comment / header."""
    if not line:
        return True
    if line.startswith('!') or line.startswith('['):
        return True
    # '#' is a comment UNLESS it is the start of a cosmetic filter (e.g. '##.ad', '#@#.ad')
    if line.startswith('#') and not any(line.startswith(m) for m in COSMETIC_MARKERS):
        return True
    return False


def canonical_domain(domain: str) -> Optional[str]:
    """Validate and return normalized lowercase domain without trailing dot."""
    d = domain.strip().rstrip('.').lower()
    if DOMAIN_RE.match(d):
        return d
    return None


def is_valid_domain_or_ip(target: str) -> bool:
    """Check if target is a valid domain or IPv4 address."""
    t = target.strip().rstrip('.').lower()
    return bool(DOMAIN_RE.match(t) or IPV4_RE.match(t))


def normalize_modifiers(rule: str) -> str:
    """Sort comma-separated modifiers after $ for consistent deduplication."""
    if '$' not in rule:
        return rule
    # Ensure $ is not inside a cosmetic rule
    if any(m in rule for m in COSMETIC_MARKERS):
        return rule
    pattern, sep, mods = rule.rpartition('$')
    # If modifiers contain comma, sort them
    if ',' in mods:
        sorted_mods = ','.join(sorted(m.strip() for m in mods.split(',') if m.strip()))
        return f"{pattern}${sorted_mods}"
    return rule


def normalize_cosmetic_rule(rule: str) -> str:
    """Normalize comma-separated domains before cosmetic marker for consistent deduplication."""
    for marker in COSMETIC_MARKERS:
        if marker in rule:
            prefix, _, suffix = rule.partition(marker)
            if ',' in prefix:
                domains = [d.strip().lower() for d in prefix.split(',') if d.strip()]
                normalized_prefix = ','.join(sorted(domains))
                return f"{normalized_prefix}{marker}{suffix}"
            elif prefix:
                return f"{prefix.lower()}{marker}{suffix}"
            return rule
    return rule


class RuleClassifier:
    """
    Classifies a raw filter line into typed components:
    - domain_block: pure domain block or domain block with modifiers
    - domain_exception: pure domain whitelist exception
    - hosts_entry: one or more domains extracted from hosts file line
    - url_param_rule: query param filter like ?param=val or $removeparam
    - cosmetic_rule: element hiding, scriptlet, CSS/JS injection
    - dns_rule: adblock rule targeting DNS specifically
    - network_rule: general network pattern/regex
    - exception_rule: general whitelist @@ rule
    """

    @staticmethod
    def classify(line: str) -> List[Tuple[str, str, dict]]:
        raw = clean_line(line)
        if is_comment_or_empty(raw):
            return []

        # 1. Cosmetic filters (MUST BE CHECKED BEFORE splitting on '#')
        # Examples: ##.ad, example.com##.ad, example.com#@#.ad, ##+js(...), example.com#$#...
        if any(marker in raw for marker in COSMETIC_MARKERS):
            norm = normalize_cosmetic_rule(raw)
            return [("cosmetic_rule", norm, {"raw": raw, "rule": norm})]

        # 2. URL parameters & Query string filters (must check before domain parsing)
        # Examples: ?ciao=aa, ?utm_*=, &ad_box_=, $removeparam=..., ||example.com^$removeparam=...
        is_exception = raw.startswith('@@')
        core = raw[2:] if is_exception else raw

        if (
            '$removeparam' in core or '$queryprune' in core or
            core.startswith('?') or core.startswith('&') or
            core.startswith('||*?') or core.startswith('/*?')
        ):
            norm = normalize_modifiers(raw)
            if is_exception:
                return [("exception_rule", norm, {"raw": raw, "rule": norm, "is_url_param": True})]
            return [("url_param_rule", norm, {"raw": raw, "rule": norm, "is_url_param": True})]

        # 3. Hosts line: e.g. 0.0.0.0 example.com domain2.com # comment
        hosts_match = HOSTS_LINE_RE.match(raw)
        if hosts_match:
            rest = hosts_match.group(1).split('#', 1)[0].strip()
            tokens = rest.split()
            results = []
            for tok in tokens:
                dom = canonical_domain(tok)
                if dom and dom not in IGNORED_HOSTS:
                    results.append(("hosts_entry", dom, {"raw": raw, "domain": dom, "is_pure_domain": True}))
            return results

        # 4. Pure domain line (with optional trailing comment # comment)
        inline_stripped = raw.split('#', 1)[0].strip()
        single_dom = canonical_domain(inline_stripped)
        if single_dom and single_dom not in IGNORED_HOSTS:
            return [("domain_block", single_dom, {"raw": raw, "domain": single_dom, "is_pure_domain": True})]

        # 5. Adblock domain rules: ||domain^ or @@||domain^
        if core.startswith('||'):
            target_part = core[2:]
            # Check if this rule contains path / or query ? BEFORE any ^ or $
            first_separator_idx = None
            for idx, ch in enumerate(target_part):
                if ch in ('^', '$', '/', '?'):
                    first_separator_idx = idx
                    break

            if first_separator_idx is not None:
                first_sep = target_part[first_separator_idx]
                target_host = target_part[:first_separator_idx].rstrip('.').lower()

                # Case 5a: Path or query rule, e.g. ||example.com/ad or ||example.com?ciao=aa
                if first_sep in ('/', '?'):
                    norm = normalize_modifiers(raw)
                    if is_exception:
                        return [("exception_rule", norm, {"raw": raw, "rule": norm})]
                    return [("network_rule", norm, {"raw": raw, "rule": norm})]

                # Case 5b: Domain block/exception with or without modifiers, e.g. ||domain^ or ||domain^$modifier
                if is_valid_domain_or_ip(target_host):
                    remainder = target_part[first_separator_idx:]
                    has_modifiers = '$' in remainder
                    mods = remainder.split('$', 1)[1] if has_modifiers else ''

                    # Check modifier types
                    has_browser_only_mod = any(
                        mod in mods for mod in BROWSER_ONLY_MODIFIERS
                    )
                    has_dns_mod = any(mod in mods for mod in DNS_MODIFIERS)

                    norm = f"@@||{target_host}{remainder}" if is_exception else f"||{target_host}{remainder}"
                    norm = normalize_modifiers(norm)

                    if is_exception:
                        is_pure_allow = (remainder == '^' or remainder == '') and not has_modifiers
                        return [(
                            "domain_exception",
                            target_host,
                            {
                                "raw": raw,
                                "domain": target_host,
                                "rule": norm,
                                "is_pure_domain": is_pure_allow,
                                "is_dns_compatible": not has_browser_only_mod,
                            }
                        )]
                    else:
                        is_pure_domain = (remainder == '^' or remainder == '') and not has_modifiers
                        return [(
                            "domain_block",
                            target_host,
                            {
                                "raw": raw,
                                "domain": target_host,
                                "rule": norm,
                                "is_pure_domain": is_pure_domain,
                                "is_dns_compatible": not has_browser_only_mod or has_dns_mod,
                                "has_modifiers": has_modifiers,
                            }
                        )]

        # 6. General exception rule starting with @@
        if is_exception:
            norm = normalize_modifiers(raw)
            return [("exception_rule", norm, {"raw": raw, "rule": norm})]

        # 7. Regex rule, path rule, or general network rule
        norm = normalize_modifiers(raw)
        return [("network_rule", norm, {"raw": raw, "rule": norm})]


class ListAssembler:
    """
    Assembles raw block and allow sources into 5 deduplicated, format-specific lists:
    1. combined_ublock.txt
    2. combined_adguard.txt
    3. combined_dns_adblock.txt
    4. combined_hosts.txt
    5. combined_domains.txt
    """

    def __init__(self):
        # Master sets of domains
        self.block_domains: OrderedDict[str, str] = OrderedDict()
        self.allow_domains: OrderedDict[str, str] = OrderedDict()

        # Rules for browser (uBlock and AdGuard)
        self.browser_network_rules: OrderedDict[str, str] = OrderedDict()
        self.browser_url_param_rules: OrderedDict[str, str] = OrderedDict()
        self.browser_exception_rules: OrderedDict[str, str] = OrderedDict()

        # Cosmetic rules
        self.cosmetic_standard_rules: OrderedDict[str, str] = OrderedDict()
        self.cosmetic_ublock_rules: OrderedDict[str, str] = OrderedDict()
        self.cosmetic_adguard_rules: OrderedDict[str, str] = OrderedDict()

        # Rules for DNS adblock
        self.dns_block_rules: OrderedDict[str, str] = OrderedDict()
        self.dns_allow_rules: OrderedDict[str, str] = OrderedDict()

    def add_block_entry(self, line: str) -> None:
        """Parse and ingest a line from block sources."""
        items = RuleClassifier.classify(line)
        for kind, key, meta in items:
            if kind == "hosts_entry":
                dom = meta["domain"]
                self.block_domains[dom] = dom
            elif kind == "domain_block":
                dom = meta["domain"]
                if meta.get("is_pure_domain", False):
                    # Pure domain block: goes to block_domains (for hosts and domains)
                    # and will be automatically emitted as ||domain^ for dns and browsers
                    self.block_domains[dom] = dom
                elif meta.get("has_modifiers", False):
                    rule = meta.get("rule", f"||{dom}^")
                    if meta.get("is_dns_compatible", False):
                        self.dns_block_rules[rule] = rule
                    self.browser_network_rules[rule] = rule

            elif kind == "url_param_rule":
                rule = meta["rule"]
                self.browser_url_param_rules[rule] = rule

            elif kind == "cosmetic_rule":
                rule = meta["rule"]
                # Segregate engine-specific cosmetic rules
                if '#%#' in rule or '#@%#' in rule or '#$#' in rule or '#@$#' in rule:
                    # AdGuard-specific scriptlet or CSS injection
                    self.cosmetic_adguard_rules[rule] = rule
                elif '##^' in rule:
                    # uBO-specific HTML filtering
                    self.cosmetic_ublock_rules[rule] = rule
                else:
                    # Standard cosmetic (##, #@#, #?#, ##+js)
                    self.cosmetic_standard_rules[rule] = rule

            elif kind == "network_rule":
                rule = meta["rule"]
                self.browser_network_rules[rule] = rule

            elif kind == "exception_rule":
                rule = meta["rule"]
                self.browser_exception_rules[rule] = rule

    def add_allow_entry(self, line: str) -> None:
        """Parse and ingest a line from allow sources."""
        items = RuleClassifier.classify(line)
        for kind, key, meta in items:
            if kind in ("domain_block", "hosts_entry", "domain_exception"):
                dom = meta["domain"]
                self.allow_domains[dom] = dom
                rule = meta.get("rule", f"@@||{dom}^")
                if meta.get("is_dns_compatible", True):
                    self.dns_allow_rules[rule] = rule
                self.browser_exception_rules[rule] = rule

            elif kind == "cosmetic_rule":
                rule = meta["rule"]
                if '#%#' in rule or '#@%#' in rule or '#$#' in rule or '#@$#' in rule:
                    self.cosmetic_adguard_rules[rule] = rule
                elif '##^' in rule:
                    self.cosmetic_ublock_rules[rule] = rule
                else:
                    self.cosmetic_standard_rules[rule] = rule

            elif kind in ("url_param_rule", "network_rule", "exception_rule"):
                rule = meta["rule"]
                # Ensure exception rule starts with @@
                if not rule.startswith('@@') and not any(m in rule for m in COSMETIC_MARKERS):
                    rule = '@@' + rule
                self.browser_exception_rules[rule] = rule
                if rule.startswith('@@||') and '^' in rule and not any(m in rule for m in BROWSER_ONLY_MODIFIERS):
                    self.dns_allow_rules[rule] = rule

    def is_domain_allowed(self, domain: str) -> bool:
        """Check if domain or any of its parent domains is in allow_domains."""
        if domain in self.allow_domains:
            return True
        # Check parent domains, e.g. audio.spotify.com allowed by spotify.com
        parts = domain.split('.')
        for i in range(1, len(parts) - 1):
            parent = '.'.join(parts[i:])
            if parent in self.allow_domains:
                return True
        return False

    def get_effective_block_domains(self) -> List[str]:
        """Return sorted list of blocked domains, strictly subtracting allowed domains."""
        effective = [
            dom for dom in self.block_domains
            if not self.is_domain_allowed(dom)
        ]
        return sorted(set(effective))

    def generate_hosts(self) -> List[str]:
        """Generate standard 0.0.0.0 hosts list."""
        domains = self.get_effective_block_domains()
        return [f"0.0.0.0 {dom}" for dom in domains]

    def generate_domains(self) -> List[str]:
        """Generate plain domain list."""
        return self.get_effective_block_domains()

    def generate_dns_adblock(self) -> List[str]:
        """
        Generate DNS adblock rules (AdGuard Home, Pi-hole 5.0+ regex/adblock, NextDNS).
        Excludes cosmetic filters and URL parameter filters.
        """
        rules = OrderedDict()

        # 1. Domain rules for all effective blocked domains: ||domain^
        for dom in self.get_effective_block_domains():
            rule = f"||{dom}^"
            rules[rule] = rule

        # 2. Custom DNS block rules (e.g. $dnsrewrite, $client)
        for rule in self.dns_block_rules.values():
            rules[rule] = rule

        # 3. DNS exception rules: @@||domain^
        for rule in self.dns_allow_rules.values():
            rules[rule] = rule

        return list(rules.values())

    def generate_ublock(self) -> List[str]:
        """
        Generate list tailored for uBlock Origin and Brave Shields.
        Includes all network rules, url param rules, uBO scriptlets, HTML filters.
        Excludes AdGuard-specific syntax (#%#, #$#).
        """
        rules = OrderedDict()

        # 1. Pure domain block rules (from effective domains)
        for dom in self.get_effective_block_domains():
            rule = f"||{dom}^"
            rules[rule] = rule

        # 2. URL parameter rules (?ciao=aa, $removeparam)
        for rule in self.browser_url_param_rules.values():
            rules[rule] = rule

        # 3. Other network rules (with modifiers or paths)
        for rule in self.browser_network_rules.values():
            rules[rule] = rule

        # 4. Standard & uBO cosmetic rules
        for rule in self.cosmetic_standard_rules.values():
            rules[rule] = rule
        for rule in self.cosmetic_ublock_rules.values():
            rules[rule] = rule

        # 5. Exception rules
        for rule in self.browser_exception_rules.values():
            rules[rule] = rule

        return list(rules.values())

    def generate_adguard(self) -> List[str]:
        """
        Generate list tailored for AdGuard browser extension & desktop.
        Includes all network rules, url param rules, AdGuard CSS/JS injection.
        Excludes uBO-specific syntax (##^).
        """
        rules = OrderedDict()

        # 1. Pure domain block rules (from effective domains)
        for dom in self.get_effective_block_domains():
            rule = f"||{dom}^"
            rules[rule] = rule

        # 2. URL parameter rules (?ciao=aa, $removeparam)
        for rule in self.browser_url_param_rules.values():
            rules[rule] = rule

        # 3. Other network rules (with modifiers or paths)
        for rule in self.browser_network_rules.values():
            rules[rule] = rule

        # 4. Standard & AdGuard cosmetic rules
        for rule in self.cosmetic_standard_rules.values():
            rules[rule] = rule
        for rule in self.cosmetic_adguard_rules.values():
            rules[rule] = rule

        # 5. Exception rules
        for rule in self.browser_exception_rules.values():
            rules[rule] = rule

        return list(rules.values())


def write_list_with_header(filepath: Path, title: str, rules: List[str]) -> None:
    """Write output file with standard adblock metadata header."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    header = [
        f"! Title: {title}",
        f"! Last modified: {now}",
        f"! Entries: {len(rules)}",
        "! Generated automatically by Adblock List Assembler",
        ""
    ]
    content = "\n".join(header + rules) + "\n"
    filepath.write_text(content, encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="Assemble adblock lists into multiple formats.")
    parser.add_argument("--workdir", default=".", help="Directory containing block_raw.txt and allow_raw.txt")
    parser.add_argument("--output-dir", default="lists", help="Directory where generated lists will be written")
    args = parser.parse_args()

    workdir = Path(args.workdir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    block_raw_file = workdir / "block_raw.txt"
    allow_raw_file = workdir / "allow_raw.txt"

    assembler = ListAssembler()

    if block_raw_file.is_file():
        block_lines = block_raw_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        print(f"Caricamento {len(block_lines)} righe sorgente da block_raw.txt...")
        for line in block_lines:
            assembler.add_block_entry(line)

    if allow_raw_file.is_file():
        allow_lines = allow_raw_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        print(f"Caricamento {len(allow_lines)} righe sorgente da allow_raw.txt...")
        for line in allow_lines:
            assembler.add_allow_entry(line)

    print("Generazione liste di output in corso...")

    ublock_rules = assembler.generate_ublock()
    adguard_rules = assembler.generate_adguard()
    dns_rules = assembler.generate_dns_adblock()
    hosts_rules = assembler.generate_hosts()
    domains_rules = assembler.generate_domains()

    write_list_with_header(
        output_dir / "combined_ublock.txt",
        "Combined Adblock List (uBlock Origin / Brave)",
        ublock_rules
    )
    write_list_with_header(
        output_dir / "combined_adguard.txt",
        "Combined Adblock List (AdGuard)",
        adguard_rules
    )
    write_list_with_header(
        output_dir / "combined_dns_adblock.txt",
        "Combined Adblock List (DNS Adblock)",
        dns_rules
    )

    # Hosts file format (standard plain text)
    hosts_content = "\n".join(hosts_rules) + ("\n" if hosts_rules else "")
    (output_dir / "combined_hosts.txt").write_text(hosts_content, encoding="utf-8")

    # Domains list format (one domain per line)
    domains_content = "\n".join(domains_rules) + ("\n" if domains_rules else "")
    (output_dir / "combined_domains.txt").write_text(domains_content, encoding="utf-8")

    print(
        f"Completato con successo!\n"
        f"  - uBlock: {len(ublock_rules)} regole\n"
        f"  - AdGuard: {len(adguard_rules)} regole\n"
        f"  - DNS: {len(dns_rules)} regole\n"
        f"  - Hosts: {len(hosts_rules)} voci\n"
        f"  - Domini: {len(domains_rules)} voci"
    )


if __name__ == "__main__":
    main()
