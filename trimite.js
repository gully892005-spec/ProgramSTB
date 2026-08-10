// ══════════════════════════════════════════════════════════════
// Trimite notificările de tură — rulează în GitHub Actions
//
// Citește din Realtime Database abonamentele push salvate de aplicație
// (/push/<nr_serviciu>) și trimite notificarea celor care au tură în
// curând. Rulează la fiecare 15 minute, deci nu depinde deloc de
// telefonul utilizatorului: notificarea ajunge și cu aplicația închisă.
// ══════════════════════════════════════════════════════════════

const webpush = require('web-push');

const FB_URL = process.env.FB_URL;
const VAPID_PUBLIC = process.env.VAPID_PUBLIC;
const VAPID_PRIVATE = process.env.VAPID_PRIVATE;

if (!FB_URL || !VAPID_PUBLIC || !VAPID_PRIVATE) {
  console.error('Lipsesc secretele: FB_URL, VAPID_PUBLIC, VAPID_PRIVATE');
  process.exit(1);
}

webpush.setVapidDetails('mailto:programstb@example.com', VAPID_PUBLIC, VAPID_PRIVATE);

// Jobul rulează pe UTC; turele sunt în ora României.
function acumRo() {
  const f = new Intl.DateTimeFormat('sv-SE', {
    timeZone: 'Europe/Bucharest',
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hour12: false
  });
  const s = f.format(new Date());            // "2026-08-10 22:38"
  const [data, ora] = s.split(' ');
  const [h, m] = ora.split(':').map(Number);
  return { data, minute: h * 60 + m };
}

// Fereastra de trimitere: cron-ul poate întârzia, deci acceptăm
// orice moment între "acum" și "acum + 20 minute" față de ținta calculată.
const FEREASTRA = 20;

async function getJSON(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error('HTTP ' + r.status + ' la ' + url);
  return r.json();
}

async function main() {
  const now = acumRo();
  console.log(`Ora României: ${now.data} ${String(Math.floor(now.minute/60)).padStart(2,'0')}:${String(now.minute%60).padStart(2,'0')}`);

  let toti;
  try {
    toti = await getJSON(`${FB_URL}/push.json`);
  } catch (e) {
    console.error('Nu am putut citi abonamentele:', e.message);
    process.exit(1);
  }
  if (!toti) { console.log('Niciun abonament înregistrat.'); return; }

  const numere = Object.keys(toti);
  console.log(`${numere.length} abonamente de verificat.`);

  let trimise = 0, sarite = 0, expirate = 0;

  for (const nr of numere) {
    const u = toti[nr];
    if (!u || !u.sub || !Array.isArray(u.ture)) { sarite++; continue; }

    for (const t of u.ture) {
      if (!t || !t.data || !t.start) continue;
      if (t.data !== now.data) continue;               // doar turele de azi

      const [h, m] = t.start.split(':').map(Number);
      if (isNaN(h) || isNaN(m)) continue;

      const minBefore = Number(t.minBefore) || 60;
      const tinta = h * 60 + m - minBefore;             // când ar trebui să sune
      const diff = now.minute - tinta;

      if (diff < 0 || diff >= FEREASTRA) continue;      // nu e momentul

      // Nu trimitem de două ori aceeași alertă
      const marcaj = `${t.data}_${t.start}`;
      if (u.trimis === marcaj) { sarite++; continue; }

      const payload = JSON.stringify({
        title: `🚃 Tură în ${minBefore} minute`,
        body: t.text ? `${t.text}\nPregătește-te!` : `Plecare la ${t.start}. Pregătește-te!`,
        tag: 'tura-' + t.data,
        url: '/ProgramSTB/'
      });

      try {
        await webpush.sendNotification(u.sub, payload, { TTL: 3600, urgency: 'high' });
        await fetch(`${FB_URL}/push/${nr}/trimis.json`, {
          method: 'PUT', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(marcaj)
        });
        trimise++;
        console.log(`✓ ${nr} — tură ${t.start}`);
      } catch (e) {
        // 404 / 410 = abonamentul nu mai e valid (aplicație dezinstalată,
        // notificări revocate). Îl ștergem ca să nu mai încercăm degeaba.
        if (e.statusCode === 404 || e.statusCode === 410) {
          await fetch(`${FB_URL}/push/${nr}.json`, { method: 'DELETE' }).catch(() => {});
          expirate++;
          console.log(`✗ ${nr} — abonament expirat, șters`);
        } else {
          console.log(`✗ ${nr} — eroare ${e.statusCode || ''}: ${e.message}`);
        }
      }
      break;   // maxim o notificare pe utilizator per rulare
    }
  }

  console.log(`\nGata: ${trimise} trimise · ${sarite} sărite · ${expirate} expirate`);
}

main().catch(e => { console.error(e); process.exit(1); });
