// ══════════════════════════════════════════════════════════════
// Trimite notificările de tură și de chat — rulează pe Cloudflare Workers
//
// Aceeași logică ca vechiul .github/scripts/trimite.js, dar aici cron-ul
// e nativ Cloudflare: rulează pe infrastructura de margine, nu într-o
// coadă de build-uri ca GitHub Actions, deci nu mai are întârzieri de
// zeci de minute — pornește la minutul programat, aproape mereu.
// ══════════════════════════════════════════════════════════════

import webpush from 'web-push';

// Fereastră de siguranță — mult mai mică decât la GitHub Actions,
// pentru că aici cron-ul chiar rulează la 5 minute, nu "quand poate".
const INTARZIERE_MAX = 30;

function acumRo() {
  const f = new Intl.DateTimeFormat('sv-SE', {
    timeZone: 'Europe/Bucharest',
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hour12: false
  });
  const s = f.format(new Date());
  const [data, ora] = s.split(' ');
  const [h, m] = ora.split(':').map(Number);
  return { data, minute: h * 60 + m };
}

async function getJSON(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error('HTTP ' + r.status + ' la ' + url);
  return r.json();
}

async function trimiteTure(env, toti, numere, now) {
  let trimise = 0, sarite = 0, expirate = 0;

  for (const nr of numere) {
    const u = toti[nr];
    if (!u || !u.sub || !Array.isArray(u.ture)) { sarite++; continue; }

    for (const t of u.ture) {
      if (!t || !t.data || !t.start) continue;
      if (t.data !== now.data) continue;

      const [h, m] = t.start.split(':').map(Number);
      if (isNaN(h) || isNaN(m)) continue;

      const minBefore = Number(t.minBefore) || 60;
      const startMin = h * 60 + m;
      const tinta = startMin - minBefore;
      const diff = now.minute - tinta;
      if (diff < 0 || diff >= INTARZIERE_MAX) continue;

      const marcaj = `${t.data}_${t.start}`;
      if (u.trimis === marcaj) { sarite++; continue; }

      // Timpul real rămas — poate diferi puțin de minBefore dacă a durat
      // câteva minute până la rulare.
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
        await fetch(`${env.FB_URL}/push/${nr}/trimis.json`, {
          method: 'PUT', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(marcaj)
        });
        trimise++;
      } catch (e) {
        if (e.statusCode === 404 || e.statusCode === 410) {
          await fetch(`${env.FB_URL}/push/${nr}.json`, { method: 'DELETE' }).catch(() => {});
          expirate++;
        }
      }
      break; // maxim o notificare de tură per utilizator per rulare
    }
  }
  return { trimise, sarite, expirate };
}

async function trimiteChat(env, toti, numere) {
  let recent;
  try { recent = await getJSON(`${env.FB_URL}/chat/recent.json`); }
  catch (e) { return { chatTrimise: 0, eroare: e.message }; }
  if (!recent) return { chatTrimise: 0 };

  const mesaje = Object.values(recent).filter(m => m && m.t).sort((a, b) => a.t - b.t);
  const ultimul = mesaje.length ? mesaje[mesaje.length - 1].t : 0;
  if (!ultimul) return { chatTrimise: 0 };

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
    const body = noi.length === 1 ? `${cine} a scris un mesaj nou` : `${noi.length} mesaje noi de la ${cine}`;

    try {
      await webpush.sendNotification(u.sub, JSON.stringify({
        title: '💬 Chat STB', body, tag: 'chat', urgent: false, url: '/ProgramSTB/'
      }), { TTL: 1800, urgency: 'normal' });
      await fetch(`${env.FB_URL}/push/${nr}/chatNotificat.json`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(ultimul)
      });
      chatTrimise++;
    } catch (e) {
      if (e.statusCode === 404 || e.statusCode === 410) {
        await fetch(`${env.FB_URL}/push/${nr}.json`, { method: 'DELETE' }).catch(() => {});
      }
    }
  }

  // curățăm jurnalul de mesaje mai vechi de 24h
  const limita = Date.now() - 24 * 3600 * 1000;
  for (const [k, m] of Object.entries(recent)) {
    if (!m || !m.t || m.t < limita) {
      await fetch(`${env.FB_URL}/chat/recent/${k}.json`, { method: 'DELETE' }).catch(() => {});
    }
  }

  return { chatTrimise };
}

async function ruleaza(env) {
  const raport = [];
  const log = (s) => { raport.push(s); console.log(s); };

  if (!env.FB_URL || !env.VAPID_PUBLIC || !env.VAPID_PRIVATE) {
    // [DIAGNOSTIC] Dashboard-ul poate arăta secretele ca setate, dar codul să
    // primească altceva. Aici afișăm exact ce vede workerul, ca să nu ghicim.
    log('❌ Lipsește un secret.');
    log('');
    log('Ce vede workerul, concret:');
    let chei = [];
    try { chei = Object.keys(env); } catch (e) { chei = ['(nu pot citi env)']; }
    log('  chei disponibile în env: ' + (chei.length ? chei.join(', ') : '(NICIUNA)'));
    for (const n of ['FB_URL', 'VAPID_PUBLIC', 'VAPID_PRIVATE']) {
      const v = env[n];
      const tip = typeof v;
      const lung = (tip === 'string') ? v.length : '-';
      log(`  ${n}: tip=${tip}, lungime=${lung}` + (tip === 'string' && v.length ? `, începe cu "${v.slice(0,4)}"` : ''));
    }
    log('');
    log('Dacă lista de chei e goală sau nu conține numele de mai sus,');
    log('secretele nu ajung la cod, deși apar salvate în dashboard.');
    return raport.join('\n');
  }

  webpush.setVapidDetails('mailto:programstb@example.com', env.VAPID_PUBLIC, env.VAPID_PRIVATE);

  const now = acumRo();
  log(`Ora României: ${now.data} ${String(Math.floor(now.minute / 60)).padStart(2, '0')}:${String(now.minute % 60).padStart(2, '0')}`);

  let toti;
  try { toti = await getJSON(`${env.FB_URL}/push.json`); }
  catch (e) { log('❌ Nu am putut citi abonamentele: ' + e.message); return raport.join('\n'); }

  if (!toti) { log('Niciun abonament înregistrat.'); return raport.join('\n'); }

  const numere = Object.keys(toti);
  log(`${numere.length} abonamente de verificat.`);

  const { trimise, sarite, expirate } = await trimiteTure(env, toti, numere, now);
  log(`Ture: ${trimise} trimise · ${sarite} sărite · ${expirate} expirate`);

  const { chatTrimise, eroare } = await trimiteChat(env, toti, numere);
  if (eroare) log('Chat: eroare — ' + eroare);
  else log(`Chat: ${chatTrimise} notificări trimise`);

  return raport.join('\n');
}

export default {
  // Rulare automată, la fiecare 5 minute (vezi wrangler.toml)
  async scheduled(event, env, ctx) {
    ctx.waitUntil(ruleaza(env));
  },

  // Rulare manuală: deschide URL-ul workerului în browser, ca un buton
  // "Run workflow" — util pentru testare, fără să aștepți următorul cron.
  async fetch(request, env, ctx) {
    const raport = await ruleaza(env);
    return new Response(raport, { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
  }
};
