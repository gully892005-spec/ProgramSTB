# Notificări push — ghid de instalare

Notificarea ajunge pe telefon **cu aplicația închisă**. Nu costă nimic și nu
are nevoie de planul Blaze de la Firebase.

## Cum funcționează

1. Telefonul se abonează la serviciul de push al browserului și trimite
   abonamentul + turele tale din următoarele 10 zile în Realtime Database.
2. Un job pe GitHub Actions rulează **la fiecare 15 minute**, se uită cine
   are tură în curând și trimite notificarea.
3. Telefonul primește notificarea de la Google/Apple — nu contează dacă
   aplicația e deschisă, minimizată sau închisă complet.

Vechiul sistem programa alarme cu `setTimeout` în service worker. Browserul
oprește service worker-ul după ~30 de secunde de inactivitate, deci alarmele
mureau odată cu el. De asta primeai notificări doar cu aplicația deschisă.

---

## Pași de instalare (o singură dată, ~10 minute)

### 1. Urcă fișierele

| fișier | unde |
|---|---|
| `index.html` | rădăcina repo-ului |
| `sw.js` | rădăcina repo-ului |
| `.github/workflows/notificari.yml` | creezi folderele |
| `.github/scripts/trimite.js` | creezi folderele |

Pe GitHub: **Add file → Create new file**, iar la nume scrii
`.github/workflows/notificari.yml` — folderele se creează singure când pui
`/` în nume.

### 2. Adaugă cele 3 secrete

Repo → **Settings** → **Secrets and variables** → **Actions** →
**New repository secret**. Adaugi pe rând:

| nume | valoare |
|---|---|
| `VAPID_PUBLIC` | `BHF-1NE9kQRaNNxbNxNfHcqesBhKBsIDH_Curhq8DxEKsqZZ6wbpMaKd0xuX6G3Sj9eFBxw4FbROJ13tyPDmxL4` |
| `VAPID_PRIVATE` | `SyJ7pu4Y0yOnGPPN5U37dbcfbXBZsXBmF9-jjk-7c-A` |
| `FB_URL` | `https://programstb-chat-default-rtdb.europe-west1.firebasedatabase.app` |

**Cheia privată nu se pune niciodată în cod și nu se urcă în repo.** E singurul
lucru care dovedește că notificările vin de la tine. Cheia publică e deja în
`index.html` — acolo e locul ei, e publică prin definiție.

### 3. Activează Actions

Repo → tab **Actions** → dacă apare un buton verde de activare, apasă-l.

### 4. Activează în aplicație

1. Deschide aplicația (închide-o complet întâi, ca să se ia versiunea nouă)
2. ☁️ **CLOUD** → verifică să ai numărul de serviciu completat
3. 🔔 → secțiunea nouă **📡 Notificări push** → apasă **OFF** ca să devină **ON**
4. Acceptă permisiunea de notificări

### 5. Testează

Repo → **Actions** → **Notificări tură** → **Run workflow**. Se rulează pe loc
și vezi în log cine a fost notificat. Dacă scrie „Niciun abonament înregistrat",
înseamnă că pasul 4 nu a mers.

---

## Ce trebuie să știi

**Cron-ul nu e la secundă fixă.** GitHub poate întârzia rularea cu 3–5 minute
în orele aglomerate. De asta scriptul trimite într-o fereastră de 20 de minute
în jurul țintei, nu la minutul exact. Practic: dacă ai setat „cu 1 oră înainte"
și tura e la 14:54, notificarea vine între 13:54 și 14:14.

Dacă vrei precizie mai mare, schimbi în `notificari.yml` cron-ul din
`*/15` în `*/5` și `FEREASTRA` din `trimite.js` din 20 în 8. Consumă mai multe
minute de Actions, dar la repo public sunt gratuite oricum.

**Pe iPhone** trebuie întâi adăugată aplicația pe ecranul principal
(Partajează → Adaugă la ecranul principal). Safari nu permite push pentru
site-uri simple, doar pentru aplicații instalate. Necesită iOS 16.4 sau mai nou.

**Turele se resincronizează automat.** Când modifici o zi, aplicația trimite
lista actualizată în cloud după 5 secunde. Nu trebuie să reactivezi nimic.

**Reminderul vechi rămâne activ** cât timp ai aplicația deschisă. Cele două nu
se bat cap în cap: push-ul are propria marcare, ca să nu primești de două ori.

---

## Dacă nu merge

| simptom | cauză probabilă |
|---|---|
| „Niciun abonament înregistrat" în Actions | nu ai apăsat ON în aplicație, sau nu ai număr de serviciu setat |
| butonul ON nu rămâne apăsat | permisiunea de notificări e blocată — setările browserului, la permisiuni |
| Actions nu rulează deloc | tab-ul Actions nu e activat, sau secretele lipsesc |
| merge manual, nu automat | normal în prima oră — cron-ul GitHub pornește după primul commit pe branch-ul principal |
| pe iPhone nu apare butonul | aplicația nu e adăugată pe ecranul principal |

---

## Ce urmează

Sistemul trimite acum alerta de tură. Pe aceeași infrastructură se pot adăuga,
fără muncă suplimentară de instalare:

- notificarea de seară cu tura de mâine (câmpul `notifSeara` se trimite deja
  în cloud, mai trebuie doar logica în `trimite.js`)
- anunțuri de la admin, trimise tuturor deodată
- alertă când un coleg caută schimb pe tura ta
