# Program STB — reguli de lucru

Aplicație web (PWA) pentru vatmani și șoferi STB: programul de lucru, orele, repartizarea, notificări.
Site: programstb.com (GitHub Pages, ramura `main`). Totul se scrie în română, pe înțeles.

## Fișiere
- `index.html` — toată aplicația (HTML + JS într-un singur fișier).
- `sw.js` — service worker (cache offline, notificări).
- `cloudflare-worker/src/index.js` — serverul (Cloudflare Worker). Se publică singur din GitHub la fiecare Merge pe `main`.
- `db.json`, `live.json` — date (indicatori, trasee). `manifest.json`, `Icons/` — PWA.
- `prezentare.html` — prezentarea pentru colegi (fără numele autorului). `director.html` — prezentarea pentru conducerea STB.

## Cum lucrăm
1. Modificările se fac pe ramura de lucru a sesiunii, niciodată direct pe `main`.
2. Se deschide un pull request spre `main`, cu descriere în română. Autorul apasă singur „Merge”.
3. După Merge, site-ul și worker-ul se actualizează singure.
4. La fiecare schimbare în aplicație:
   - crește `APP_VERSION` în `index.html` (ex. 15.10 → 15.11), cu o notă scurtă `[15.11] …` la începutul comentariului de pe aceeași linie;
   - crește `CACHE_NAME` în `sw.js` (ex. `stb-2026-v228` → `v229`), ca telefoanele să ia versiunea nouă;
   - comentariile din cod noi se marchează cu `// [15.11]`.
5. Verificare înainte de commit: `node --check cloudflare-worker/src/index.js` și verificarea sintaxei scripturilor din `index.html`; pornirea paginii în Chromium (Playwright) fără erori.
6. **Fără „lookbehind” în expresiile regulate** (`(?<=…)`, `(?<!…)`) în `index.html`: iPhone-urile cu iOS sub 16.4 nu-l cunosc și aplicația nu mai pornește deloc. Se verifică cu `grep -n "(?<[=!]" index.html` (trebuie să nu găsească nimic în cod).

## Indicatorii de ore (din poze sau PDF)
Regulile date de autor — se aplică peste tot (tramvai și autobuz, zi de lucru și weekend):
1. **Indicatorii noi sunt definitivi**: valabili de la data de pe foaie până la următorii indicatori. Nu revin singuri la data „până la” scrisă pe foaie. Sunt **temporari doar când autorul spune explicit** că sunt temporari.
2. **Ce e pe foaie trebuie să fie și în aplicație.** Pentru fiecare linie de pe foaie, turele care lipsesc de pe foaie au fost scoase și se **șterg** (la autobuze `"scoate": true` în fișier; la tramvai `"liniiComplete": true`).
3. **Garaj / depou**: se compară ora de retragere a schimbului 1 cu ora de ieșire a schimbului 2.
   - aceeași oră → schimbul se face **la capăt de linie**;
   - oră diferită → schimbul 2 **iese din garaj / depou** (autobuz: `"g2": 1` pe tur; tramvai: `"d": true` la `s2`).
4. Se verifică fiecare tur: duratele calculate din ore trebuie să dea exact coloanele „sch 1” / „sch 2” de pe foaie. Dacă nu se potrivesc, s-a citit greșit o cifră.
5. „sâmbătă + duminică” scris pe foaie = aceleași ore la sâmbătă și duminică.

### Fișierul pentru autobuze (se încarcă din panou: ⏱ Indicatori → 📥 Indicatori noi)
```json
{ "tip": "ore-autobaza", "baza": "giurgiului", "de": "2026-11-21", "scoate": true,
  "sursa": "ce foaie e",
  "l": { "1/243": { "1": ["04:17", "12:57"], "2": ["12:57", "20:25"] } },
  "s": { }, "d": { } }
```
`l` = zi de lucru, `s` = sâmbătă, `d` = duminică. Cheia turului: `tur/linie`. Orele `HH:MM` (după miezul nopții: `00:13`).
Autobaza (`baza`) se află după turele existente în `db.json` → `autobuze._ore._baza`.

### Fișierul pentru tramvai
```json
{ "dep": "dudesti", "de": "2026-11-21", "liniiComplete": true,
  "zl": { "1/10": { "linie": "10", "s1": { "i": "05:00", "r": "13:00", "c": "capătul" }, "s2": { "i": "13:00", "r": "21:00", "c": "capătul" } } },
  "we": { } }
```
Pentru indicatori temporari (doar la cererea autorului) se adaugă `"pana": "AAAA-LL-ZZ"`.
