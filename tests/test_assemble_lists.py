#!/usr/bin/env python3
"""
Comprehensive unit tests for assemble_lists.py
Verifies parsing, classification, deduplication, URL parameter handling,
cosmetic filters, DNS rules, hosts entries, and allowlist subtractions.
"""

import sys
import unittest
from pathlib import Path

# Add scripts directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from assemble_lists import (
    RuleClassifier,
    ListAssembler,
    canonical_domain,
    normalize_cosmetic_rule,
    normalize_modifiers,
)


class TestClassifierAndNormalization(unittest.TestCase):

    def test_canonical_domain(self):
        self.assertEqual(canonical_domain("EXAMPLE.COM."), "example.com")
        self.assertEqual(canonical_domain("sub.test-domain.org"), "sub.test-domain.org")
        self.assertIsNone(canonical_domain("invalid_domain!"))
        self.assertIsNone(canonical_domain("http://example.com"))
        self.assertIsNone(canonical_domain("?ciao=aa"))
        self.assertIsNone(canonical_domain("localhost"))

    def test_normalize_modifiers(self):
        self.assertEqual(
            normalize_modifiers("||example.com^$script,image,third-party"),
            "||example.com^$image,script,third-party"
        )
        self.assertEqual(
            normalize_modifiers("||example.com^$dnsrewrite=1.2.3.4,client=192.168.1.1"),
            "||example.com^$client=192.168.1.1,dnsrewrite=1.2.3.4"
        )

    def test_normalize_cosmetic(self):
        self.assertEqual(
            normalize_cosmetic_rule("beta.com,alpha.com##.ad-class"),
            "alpha.com,beta.com##.ad-class"
        )
        self.assertEqual(
            normalize_cosmetic_rule("EXAMPLE.COM##.banner"),
            "example.com##.banner"
        )
        self.assertEqual(
            normalize_cosmetic_rule("b.org,a.com#@#.banner"),
            "a.com,b.org#@#.banner"
        )

    def test_classify_hosts_multi_domain(self):
        line = "0.0.0.0   ad1.example.com\tad2.example.com  localhost  ad3.example.com # tracking"
        results = RuleClassifier.classify(line)
        self.assertEqual(len(results), 3)
        domains = [r[1] for r in results]
        self.assertEqual(domains, ["ad1.example.com", "ad2.example.com", "ad3.example.com"])

    def test_classify_pure_domain(self):
        results = RuleClassifier.classify("doubleclick.net # ads")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], "domain_block")
        self.assertEqual(results[0][1], "doubleclick.net")

    def test_classify_adblock_domain_pure(self):
        results = RuleClassifier.classify("||neo7x.com^")
        self.assertEqual(len(results), 1)
        kind, key, meta = results[0]
        self.assertEqual(kind, "domain_block")
        self.assertEqual(key, "neo7x.com")
        self.assertTrue(meta["is_pure_domain"])
        self.assertTrue(meta["is_dns_compatible"])

    def test_classify_url_params(self):
        # Starts with ?
        res1 = RuleClassifier.classify("?ciao=aa")
        self.assertEqual(res1[0][0], "url_param_rule")
        self.assertEqual(res1[0][1], "?ciao=aa")

        # Starts with &
        res2 = RuleClassifier.classify("&ad_box_=")
        self.assertEqual(res2[0][0], "url_param_rule")

        # $removeparam modifier
        res3 = RuleClassifier.classify("||example.com^$removeparam=utm_source")
        self.assertEqual(res3[0][0], "url_param_rule")

        # Standalone $removeparam
        res3b = RuleClassifier.classify("$removeparam=utm_campaign")
        self.assertEqual(res3b[0][0], "url_param_rule")

        # Query param exception @@?ciao=aa
        res4 = RuleClassifier.classify("@@?ciao=aa")
        self.assertEqual(res4[0][0], "exception_rule")
        self.assertTrue(res4[0][2].get("is_url_param"))

        # Query string wildcard pattern
        res5 = RuleClassifier.classify("||*?aff_id=")
        self.assertEqual(res5[0][0], "url_param_rule")

    def test_classify_cosmetic_types(self):
        # Element hiding
        res1 = RuleClassifier.classify("example.com##.ad-banner")
        self.assertEqual(res1[0][0], "cosmetic_rule")

        # Element hiding with no domain
        res1b = RuleClassifier.classify("##.generic-ad-banner")
        self.assertEqual(res1b[0][0], "cosmetic_rule")

        # Cosmetic exception
        res2 = RuleClassifier.classify("example.com#@#.ad-banner")
        self.assertEqual(res2[0][0], "cosmetic_rule")

        # Scriptlet
        res3 = RuleClassifier.classify("example.com##+js(set, foo, false)")
        self.assertEqual(res3[0][0], "cosmetic_rule")

        # Procedural
        res4 = RuleClassifier.classify("example.com#?#.ad:has(> .banner)")
        self.assertEqual(res4[0][0], "cosmetic_rule")

        # AdGuard CSS
        res5 = RuleClassifier.classify("example.com#$#.ad { display: none !important; }")
        self.assertEqual(res5[0][0], "cosmetic_rule")

        # AdGuard JS
        res6 = RuleClassifier.classify("example.com#%#//scriptlet")
        self.assertEqual(res6[0][0], "cosmetic_rule")

        # uBO HTML filter
        res7 = RuleClassifier.classify("example.com##^script:has-text(ad)")
        self.assertEqual(res7[0][0], "cosmetic_rule")

    def test_comments_and_blank_lines(self):
        self.assertEqual(RuleClassifier.classify(""), [])
        self.assertEqual(RuleClassifier.classify("   "), [])
        self.assertEqual(RuleClassifier.classify("! Title: List"), [])
        self.assertEqual(RuleClassifier.classify("# Regular comment"), [])
        self.assertEqual(RuleClassifier.classify("[Adblock Plus 2.0]"), [])


class TestAssemblerPipeline(unittest.TestCase):

    def setUp(self):
        self.assembler = ListAssembler()

    def test_end_to_end_assembly(self):
        # Block entries
        self.assembler.add_block_entry("0.0.0.0 multi1.com multi2.com")
        self.assembler.add_block_entry("puredomain.com")
        self.assembler.add_block_entry("||dns-and-browser.org^")
        self.assembler.add_block_entry("||DNS-AND-BROWSER.ORG^")  # Case deduplication test
        self.assembler.add_block_entry("?ciao=aa")
        self.assembler.add_block_entry("?ciao=aa")  # Duplicate URL param
        self.assembler.add_block_entry("||example.com^$removeparam=tracker")
        self.assembler.add_block_entry("example.com##.ad-banner")
        self.assembler.add_block_entry("example.com##+js(set, test, true)")
        self.assembler.add_block_entry("example.com#$#.ad { display: none; }")
        self.assembler.add_block_entry("example.com#%#//ag-scriptlet")
        self.assembler.add_block_entry("example.com##^script:has-text(tracker)")
        self.assembler.add_block_entry("||special-dns.com^$dnsrewrite=NOERROR;A;1.2.3.4")

        # Block an item that will be allowed later
        self.assembler.add_block_entry("||spotify.com^")
        self.assembler.add_block_entry("||audio.spotify.com^")
        self.assembler.add_block_entry("0.0.0.0 player.spotify.com")

        # Allow entries
        self.assembler.add_allow_entry("spotify.com")
        self.assembler.add_allow_entry("@@?ciao=allowed")

        # 1. Check Hosts
        hosts = self.assembler.generate_hosts()
        self.assertIn("0.0.0.0 multi1.com", hosts)
        self.assertIn("0.0.0.0 multi2.com", hosts)
        self.assertIn("0.0.0.0 puredomain.com", hosts)
        self.assertIn("0.0.0.0 dns-and-browser.org", hosts)
        # Should NOT contain spotify or any subdomains
        self.assertNotIn("0.0.0.0 spotify.com", hosts)
        self.assertNotIn("0.0.0.0 audio.spotify.com", hosts)
        self.assertNotIn("0.0.0.0 player.spotify.com", hosts)
        # Should NOT contain URL params or cosmetics
        self.assertFalse(any("?ciao" in h for h in hosts))
        self.assertFalse(any("##" in h for h in hosts))

        # 2. Check Domains
        domains = self.assembler.generate_domains()
        self.assertIn("multi1.com", domains)
        self.assertIn("puredomain.com", domains)
        self.assertIn("dns-and-browser.org", domains)
        self.assertNotIn("spotify.com", domains)
        self.assertNotIn("audio.spotify.com", domains)
        self.assertNotIn("player.spotify.com", domains)

        # 3. Check DNS Adblock
        dns_rules = self.assembler.generate_dns_adblock()
        self.assertIn("||dns-and-browser.org^", dns_rules)
        self.assertIn("||multi1.com^", dns_rules)
        self.assertIn("||special-dns.com^$dnsrewrite=NOERROR;A;1.2.3.4", dns_rules)
        self.assertIn("@@||spotify.com^", dns_rules)
        # Must not contain cosmetic or url params
        self.assertFalse(any("##" in r for r in dns_rules))
        self.assertFalse(any("#$#" in r for r in dns_rules))
        self.assertFalse(any("?ciao" in r for r in dns_rules))

        # 4. Check uBlock Origin output
        ublock = self.assembler.generate_ublock()
        self.assertIn("?ciao=aa", ublock)
        self.assertIn("||example.com^$removeparam=tracker", ublock)
        self.assertIn("example.com##.ad-banner", ublock)
        self.assertIn("example.com##+js(set, test, true)", ublock)
        self.assertIn("example.com##^script:has-text(tracker)", ublock)
        self.assertIn("@@?ciao=allowed", ublock)
        self.assertIn("@@||spotify.com^", ublock)
        # AdGuard JS #%# and CSS #$# should be excluded from uBO
        self.assertNotIn("example.com#%#//ag-scriptlet", ublock)
        self.assertNotIn("example.com#$#.ad { display: none; }", ublock)

        # 5. Check AdGuard output
        adguard = self.assembler.generate_adguard()
        self.assertIn("?ciao=aa", adguard)
        self.assertIn("example.com##.ad-banner", adguard)
        self.assertIn("example.com#$#.ad { display: none; }", adguard)
        self.assertIn("example.com#%#//ag-scriptlet", adguard)
        self.assertIn("@@?ciao=allowed", adguard)
        self.assertIn("@@||spotify.com^", adguard)
        # uBO HTML filter ##^ should be excluded from AdGuard
        self.assertNotIn("example.com##^script:has-text(tracker)", adguard)

    def test_deduplication_exact(self):
        # Add identical rules in various ways
        self.assembler.add_block_entry("||test.com^")
        self.assembler.add_block_entry("0.0.0.0 test.com")
        self.assembler.add_block_entry("test.com")
        self.assembler.add_block_entry("||TEST.COM^")

        hosts = self.assembler.generate_hosts()
        self.assertEqual(hosts.count("0.0.0.0 test.com"), 1)

        domains = self.assembler.generate_domains()
        self.assertEqual(domains.count("test.com"), 1)

        dns = self.assembler.generate_dns_adblock()
        self.assertEqual(dns.count("||test.com^"), 1)

        ublock = self.assembler.generate_ublock()
        self.assertEqual(ublock.count("||test.com^"), 1)


if __name__ == "__main__":
    unittest.main()
