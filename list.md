# Configurazione Liste Adblock

Do not remove 'blocklist\:' e 'allowlist\:'.
You can write everything you want, everything will be ignored for exceptions of lines that starts with `- [x]` (checked backtick).

## blocklist: 
# Filtri Base e Pubblicità
- [x] list:https://easylist.to/easylist/easylist.txt
- [x] list:https://filters.adtidy.org/extension/ublock/filters/2.txt
- [ ] list:https://big.oisd.nl
- [ ] list:https://filters.adtidy.org/extension/ublock/filters/11.txt

# Privacy e Tracciamento
- [x] list:https://easylist.to/easylist/easyprivacy.txt
- [ ] list:https://filters.adtidy.org/extension/ublock/filters/3.txt
- [ ] list:https://raw.githubusercontent.com/curbengh/phishing-filter/master/dist/utils.txt

# Filtri Italiani (ITA-0)
- [x] list:https://raw.githubusercontent.com/FiltersHeroes/ItalyList/master/italylist.txt

# Fastidi (Annoyances, Cookie, Widget)
- [ ] list:https://secure.fanboy.co.nz/fanboy-cookiemonster.txt
- [ ] list:https://filters.adtidy.org/extension/ublock/filters/14.txt
- [ ] list:https://filters.adtidy.org/extension/ublock/filters/4.txt
- [ ] list:https://filters.adtidy.org/extension/ublock/filters/15.txt

# Sicurezza
- [ ] list:https://raw.githubusercontent.com/DandelionSprout/adblock-lists/master/Wiki-based%20Lists/BadwareRisks.txt
- [ ] list:https://urlhaus.abuse.ch/downloads/hostfile/

## allowlist:
# Siti permessi estratti dal tuo JSON
- [x] spotify.com
