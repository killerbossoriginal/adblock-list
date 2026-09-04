# Adblock List Assembler

Un sistema automatizzato con GitHub Actions che prende un semplice file [`list.md`](list.md) e lo converte in **5 liste di filtri** ottimizzate, deduplicate e compatibili con i principali ad-blocker e server DNS.

Mantieni un unico file Markdown leggibile ([`list.md`](list.md)) — il workflow elabora e genera automaticamente i file finali.

---

## 📝 Come compilare `list.md`

Il formato è minimale e flessibile:

1. Le sezioni `## blocklist:` e `## allowlist:` devono rimanere presenti.
2. Vengono elaborate solo le righe che iniziano con la casella spuntata: `- [x]` (o `- [X]`).
3. Tutte le altre righe o note vengono ignorate, così puoi inserire commenti liberi.

### Formati e regole supportate

Puoi inserire qualsiasi tipologia di regola o sorgente sia in `## blocklist:` sia in `## allowlist:`:

- **Liste esterne remote**:
  `- [x] list:https://easylist.to/easylist/easylist.txt`
  Scarica e unisce qualsiasi lista adblock, hosts o domini remota.
- **Domini singoli**:
  `- [x] googleads.g.doubleclick.net`
- **Regole standard Adblock**:
  `- [x] ||doubleclick.net^`
  `- [x] ||example.com^$third-party,script`
- **Parametri URL e query string**:
  `- [x] ?ciao=aa`
  `- [x] ?utm_source=*`
  `- [x] &ad_box_=`
  `- [x] $removeparam=tracker`
  `- [x] ||example.com^$removeparam=utm_source`
- **Filtri cosmetici ed element hiding**:
  `- [x] ##.ad-banner`
  `- [x] example.com##.sponsor-box`
  `- [x] example.com#@#.sponsor-box` *(eccezione cosmetica)*
  `- [x] example.com##+js(set, adsDisabled, true)` *(scriptlet uBO / AdGuard)*
  `- [x] example.com#$#.banner { display: none !important; }` *(CSS injection AdGuard)*
  `- [x] example.com#%#//scriptlet` *(JS injection AdGuard)*
- **Formato Hosts (anche con domini multipli per riga)**:
  `- [x] 0.0.0.0 ad1.com ad2.com ad3.com`
- **Regole DNS specifiche**:
  `- [x] ||special-dns.com^$dnsrewrite=NOERROR;A;1.2.3.4`
- **Regole di eccezione / Allowlist**:
  `- [x] spotify.com` *(sottrae spotify.com e i suoi sottodomini da hosts/domains e genera `@@||spotify.com^`)*
  `- [x] @@?ciao=aa` *(eccezione per parametri URL)*
  `- [x] @@||example.com^$document`

---

## ⚡ Sistema di De-duplicazione e Normalizzazione

L'assemblatore include un motore di deduplicazione canonica:
- **Case-insensitivity**: domini e regole identiche con maiuscole/minuscole diverse vengono unificati (es. `EXAMPLE.COM` e `example.com`).
- **Ordinamento modificatori e selettori**: regole con modificatori in ordine diverso (`$image,script` vs `$script,image`) o domini multipli (`b.com,a.com##.ad`) vengono normalizzate per evitare duplicati.
- **Sottrazione intelligente Allowlist**: quando un dominio o pattern è in `allowlist`, viene rimosso da `combined_hosts.txt` e `combined_domains.txt` (compresi i sottodomini), e viene generata la regola di eccezione `@@` per browser e DNS.

---

## 📦 File di Output (`/lists`)

Il workflow genera 5 versioni specializzate nella cartella [`/lists`](lists):

| File | Target / Compatibilità | Contenuto |
|---|---|---|
| [`combined_ublock.txt`](lists/combined_ublock.txt) | **uBlock Origin, Brave Shields** | Regole di rete, filtri parametri URL (`?ciao=aa`, `$removeparam`), filtri cosmetici, scriptlet uBO (`+js`), filtri HTML (`##^`), eccezioni `@@`. |
| [`combined_adguard.txt`](lists/combined_adguard.txt) | **AdGuard (Browser & Desktop)** | Regole di rete, filtri parametri URL (`?ciao=aa`, `$removeparam`), filtri cosmetici standard, AdGuard CSS injection (`#$#`), AdGuard JS (`#%#`), eccezioni `@@`. |
| [`combined_dns_adblock.txt`](lists/combined_dns_adblock.txt) | **AdGuard Home, Pi-hole 5+, NextDNS** | Regole a livello DNS (`\|\|dominio^`, modificatori DNS tipo `$dnsrewrite`, eccezioni DNS `@@\|\|dominio^`). *Esclusi parametri URL e filtri cosmetici in quanto non supportati a livello DNS.* |
| [`combined_hosts.txt`](lists/combined_hosts.txt) | **File Hosts (`/etc/hosts`, Windows hosts, router)** | Formato standard `0.0.0.0 dominio`, deduplicato e ordinato alfabeticamente, al netto delle eccezioni in allowlist. |
| [`combined_domains.txt`](lists/combined_domains.txt) | **Pi-hole (Domains list), dnsmasq** | Elenco puro di soli domini bloccati (uno per riga), al netto delle eccezioni in allowlist. |

---

## 🚀 Utilizzo

Puoi abbonarti direttamente a qualsiasi lista utilizzando i link **Raw** di GitHub nel tuo ad-blocker o resolver DNS. Le liste si aggiornano automaticamente a ogni commit su `list.md` o tramite l'esecuzione periodica schedulata.
