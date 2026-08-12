// ══════════════════════════════════════════════════════════════
// Trimite notificările de tură — rulează în GitHub Actions
//
// Citește din Realtime Database abonamentele push salvate de aplicație
// (/push/<nr_serviciu>) și trimite notificarea celor care au tură în
// curând. Rulează la fiecare 15 minute, deci nu depinde deloc de
// telefonul utilizatorului: notificarea ajunge și cu aplicația închisă.
// ══════════════════════════════════════════════════════════════

const webpush = require('web-push');
const fs = require('fs');

// ── Raport vizibil direct pe pagina rulării ───────────────────
// Log-ul e greu de deschis pe telefon, așa că scriem tot ce contează
// în „Summary" — apare sub titlul rulării, fără să mai intri nicăieri.
const _raport = [];
function raport(linie) {
  _raport.push(linie);
  console.log(linie.replace(/^#+ /, '').replace(/\*\*/g, ''));
}
function scrieRaport() {
  try {
    if (process.env.GITHUB_STEP_SUMMARY) {
      fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, _raport.join('\n') + '\n');
    }
  } catch (e) {}
}
process.on('exit', scrieRaport);
process.on('uncaughtException', e => {
  raport('## ❌ Eroare neașteptată');
  raport('```');
  raport(String(e && e.stack || e));
  raport('```');
  scrieRaport();
  process.exit(1);
});

// Curățăm secretele: la copy-paste de pe telefon se strecoară des un spațiu
// sau un rând nou invizibil, iar cheile devin invalide.
const curata = v => (v || '').trim().replace(/[\r\n\s]/g, '');
const FB_URL = curata(process.env.FB_URL).replace(/\/+$/, '');
const VAPID_PUBLIC = curata(process.env.VAPID_PUBLIC);
const VAPID_PRIVATE = curata(process.env.VAPID_PRIVATE);

if (!FB_URL || !VAPID_PUBLIC || !VAPID_PRIVATE) {
  raport('## ❌ Lipsește un secret');
  raport('- FB_URL: **' + (FB_URL ? 'OK' : 'LIPSEȘTE') + '**');
  raport('- VAPID_PUBLIC: **' + (VAPID_PUBLIC ? 'OK' : 'LIPSEȘTE') + '**');
  raport('- VAPID_PRIVATE: **' + (VAPID_PRIVATE ? 'OK' : 'LIPSEȘTE') + '**');
  process.exit(1);
}

// Diagnostic — nu afișăm cheile, doar lungimile, ca să vedem dacă sunt întregi
raport('## 🔍 Verificare secrete');
raport('| ce | valoare | ar trebui |');
raport('|---|---|---|');
raport(`| FB_URL | \`${FB_URL}\` | — |`);
raport(`| VAPID_PUBLIC | ${VAPID_PUBLIC.length} caractere | 87 |`);
raport(`| VAPID_PRIVATE | ${VAPID_PRIVATE.length} caractere | 43 |`);
raport(`| VAPID_PUBLIC începe cu B | ${VAPID_PUBLIC.startsWith('B') ? 'da ✅' : 'NU ❌'} | da |`);

if (VAPID_PUBLIC.length !== 87 || VAPID_PRIVATE.length !== 43) {
  raport('');
  raport('## ❌ O cheie are lungimea greșită');
  raport('A fost copiată incomplet, sau cele două au fost inversate.');
  raport('Cheia **publică** are 87 de caractere și începe cu `B`.');
  process.exit(1);
}

try {
  webpush.setVapidDetails('mailto:programstb@example.com', VAPID_PUBLIC, VAPID_PRIVATE);
} catch (e) {
  raport('');
  raport('## ❌ Chei VAPID invalide');
  raport('```');
  raport(e.message);
  raport('```');
  process.exit(1);
}

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

// [FIX] GitHub NU garantează rularea la 15 minute — la încărcare mare poate
// întârzia și o oră, uneori mai mult, indiferent ce scrie în cron. Cu o
// fereastră de doar 20 de minute, multe notificări de tură nu erau prinse
// de nicio rulare: fereastra se închidea între două execuții reale.
//
// Acum: orice țintă DEJA TRECUTĂ e eligibilă, oricât de rar rulează jobul —
// dedup-ul (marcajul 'trimis') previne trimiterea de două ori. Singura
// limită e un plafon de întârziere maximă, ca să nu trimitem o alertă
// „pregătește-te" pentru o tură care oricum s-a terminat de mult.
const INTARZIERE_MAX = 90; // acoperă întârzierile observate (până la ~70 min) cu marjă

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
    raport('');
    raport('## ❌ Nu am putut citi abonamentele');
    raport('```');
    raport(e.message);
    raport('```');
    raport(`Testează în browser: ${FB_URL}/push.json`);
    raport('Cauze uzuale: FB_URL greșit, sau regulile bazei de date blochează citirea.');
    process.exit(1);
  }
  raport('');
  if (!toti) {
    raport('## ⚠️ Niciun abonament înregistrat');
    raport('Baza de date răspunde corect, dar nu există nimic sub `/push`.');
    raport('Înseamnă că butonul de push din aplicație nu a reușit să se aboneze.');
    return;
  }

  const numere = Object.keys(toti);
  raport(`## ✅ ${numere.length} ${numere.length === 1 ? 'abonament găsit' : 'abonamente găsite'}`);
  raport('Numere de serviciu: `' + numere.join('`, `') + '`');

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

      if (diff < 0 || diff >= INTARZIERE_MAX) continue;  // fie prea devreme, fie prea depășit

      // Nu trimitem de două ori aceeași alertă
      const marcaj = `${t.data}_${t.start}`;
      if (u.trimis === marcaj) { sarite++; continue; }

      // [FIX] Când jobul întârzie, timpul rămas real diferă de preferința
      // setată (minBefore). Calculăm câte minute au mai rămas cu adevărat —
      // dacă tura a pornit deja între timp, schimbăm mesajul în loc să
      // afișăm un "în X minute" greșit.
      const startMin = h * 60 + m;
      const ramase = startMin - now.minute;
      const payload = JSON.stringify(ramase > 0 ? {
        title: `🚃 Tură în ${ramase} minute`,
        body: t.text ? `${t.text}\nPregătește-te!` : `Plecare la ${t.start}. Pregătește-te!`,
        tag: 'tura-' + t.data,
        url: '/ProgramSTB/'
      } : {
        title: `🚃 Tura ta a început`,
        body: t.text || `Plecare la ${t.start}`,
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

  raport('');
  raport(`**Ture:** ${trimise} trimise · ${sarite} sărite · ${expirate} expirate`);

  // ── NOTIFICĂRI CHAT (grupate) ─────────────────────────────
  // Rulăm o dată la 15 minute, deci nu trimitem un push per mesaj:
  // adunăm tot ce e nou de la ultima notificare și trimitem unul singur.
  let recent;
  try { recent = await getJSON(`${FB_URL}/chat/recent.json`); }
  catch (e) { console.log('Chat: nu am putut citi mesajele:', e.message); return; }
  if (!recent) { console.log('Chat: niciun mesaj.'); return; }

  const mesaje = Object.values(recent).filter(m => m && m.t).sort((a, b) => a.t - b.t);
  const ultimul = mesaje.length ? mesaje[mesaje.length - 1].t : 0;
  if (!ultimul) return;

  let chatTrimise = 0;
  for (const nr of numere) {
    const u = toti[nr];
    if (!u || !u.sub) continue;
    if (u.chatMute === true) continue;

    const vazut = Number(u.chatSeen) || 0;
    const notificat = Number(u.chatNotificat) || 0;
    const referinta = Math.max(vazut, notificat);

    const noi = mesaje.filter(m => m.t > referinta);
    if (noi.length === 0) continue;

    const nume = [...new Set(noi.map(m => m.n).filter(Boolean))];
    const cine = nume.length === 1 ? nume[0]
               : nume.length === 2 ? `${nume[0]} și ${nume[1]}`
               : `${nume[0]} și încă ${nume.length - 1}`;
    const body = noi.length === 1
      ? `${cine} a scris un mesaj nou`
      : `${noi.length} mesaje noi de la ${cine}`;

    try {
      await webpush.sendNotification(u.sub, JSON.stringify({
        title: '💬 Chat STB',
        body,
        tag: 'chat',
        urgent: false,
        url: '/ProgramSTB/'
      }), { TTL: 1800, urgency: 'normal' });
      await fetch(`${FB_URL}/push/${nr}/chatNotificat.json`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(ultimul)
      });
      chatTrimise++;
    } catch (e) {
      if (e.statusCode === 404 || e.statusCode === 410) {
        await fetch(`${FB_URL}/push/${nr}.json`, { method: 'DELETE' }).catch(() => {});
      }
    }
  }
  raport(`**Chat:** ${chatTrimise} notificări trimise (${mesaje.length} mesaje în jurnal)`);

  // Curățăm jurnalul: păstrăm doar ultimele 24 de ore
  const limita = Date.now() - 24 * 3600 * 1000;
  for (const [k, m] of Object.entries(recent)) {
    if (!m || !m.t || m.t < limita) {
      await fetch(`${FB_URL}/chat/recent/${k}.json`, { method: 'DELETE' }).catch(() => {});
    }
  }
}

main().catch(e => {
  raport('');
  raport('## ❌ Eroare');
  raport('```');
  raport(String(e && e.stack || e));
  raport('```');
  process.exit(1);
});
