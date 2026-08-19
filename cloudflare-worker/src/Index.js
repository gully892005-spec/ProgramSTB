// ══════════════════════════════════════════════════════════════
// Trimite notificările de tură și de chat — rulează pe Cloudflare Workers
//
// Aceeași logică ca vechiul .github/scripts/trimite.js, dar aici cron-ul
// e nativ Cloudflare: rulează pe infrastructura de margine, nu într-o
// coadă de build-uri ca GitHub Actions, deci nu mai are întârzieri de
// zeci de minute — pornește la minutul programat, aproape mereu.
// ══════════════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════════════
// PUSH NATIV PENTRU CLOUDFLARE WORKERS
//
// Biblioteca 'web-push' nu merge aici: folosește modulul https din
// Node, care nu există în Workers ("https.request is not implemented").
// Reimplementăm protocolul Web Push direct peste Web Crypto + fetch:
//   - criptare aes128gcm (RFC 8291)
//   - autentificare VAPID cu JWT semnat ES256 (RFC 8292)
// ══════════════════════════════════════════════════════════════

const _enc = new TextEncoder();

function _b64u(b) {
  const a = b instanceof Uint8Array ? b : new Uint8Array(b);
  let s = '';
  for (const x of a) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function _unb64u(str) {
  const s = String(str).replace(/-/g, '+').replace(/_/g, '/');
  const pad = s.length % 4 ? '='.repeat(4 - (s.length % 4)) : '';
  const bin = atob(s + pad);
  const b = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i);
  return b;
}

function _cat(...arr) {
  let n = 0;
  for (const a of arr) n += a.length;
  const out = new Uint8Array(n);
  let i = 0;
  for (const a of arr) { out.set(a, i); i += a.length; }
  return out;
}

async function _hmac(keyBytes, data) {
  const k = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, data));
}

// Token-ul care dovedește serverului de push că noi suntem cei care
// dețin cheia VAPID. Valabil 12 ore, generat la fiecare trimitere.
async function _vapidToken(audience, subject, publicKey, privateKey) {
  const pub = _unb64u(publicKey);
  const jwk = {
    kty: 'EC', crv: 'P-256', ext: true,
    x: _b64u(pub.slice(1, 33)),
    y: _b64u(pub.slice(33, 65)),
    d: String(privateKey).replace(/=+$/, '')
  };
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const head = _b64u(_enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const body = _b64u(_enc.encode(JSON.stringify({
    aud: audience,
    exp: Math.floor(Date.now() / 1000) + 12 * 3600,
    sub: subject
  })));
  const sig = new Uint8Array(await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, key, _enc.encode(head + '.' + body)
  ));
  return head + '.' + body + '.' + _b64u(sig);
}

// Criptăm mesajul astfel încât doar browserul destinatarului să-l poată
// citi — serverul de push (Google/Apple/Mozilla) nu vede conținutul.
async function _cripteaza(sub, text) {
  const uaPub = _unb64u(sub.keys.p256dh);
  const auth  = _unb64u(sub.keys.auth);

  const efemer = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPub  = new Uint8Array(await crypto.subtle.exportKey('raw', efemer.publicKey));
  const uaKey  = await crypto.subtle.importKey('raw', uaPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const secret = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, efemer.privateKey, 256));

  const prkKey = await _hmac(auth, secret);
  const ikm    = await _hmac(prkKey, _cat(_enc.encode('WebPush: info\x00'), uaPub, asPub, new Uint8Array([1])));

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const prk  = await _hmac(salt, ikm);
  const cek   = (await _hmac(prk, _cat(_enc.encode('Content-Encoding: aes128gcm\x00'), new Uint8Array([1])))).slice(0, 16);
  const nonce = (await _hmac(prk, _cat(_enc.encode('Content-Encoding: nonce\x00'),     new Uint8Array([1])))).slice(0, 12);

  const aes = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['encrypt']);
  const ct  = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce }, aes, _cat(_enc.encode(text), new Uint8Array([2]))
  ));

  const rs = new Uint8Array(4);
  new DataView(rs.buffer).setUint32(0, 4096);
  return _cat(salt, rs, new Uint8Array([65]), asPub, ct);
}

// Înlocuitorul lui webpush.sendNotification. Aruncă eroare cu
// .statusCode, ca restul codului să poată curăța abonamentele moarte.
async function trimitePush(sub, text, optiuni, vapid) {
  if (!sub || !sub.endpoint || !sub.keys || !sub.keys.p256dh || !sub.keys.auth) {
    const e = new Error('abonament incomplet');
    e.statusCode = 400;
    throw e;
  }
  const audienta = new URL(sub.endpoint).origin;
  const [token, corp] = await Promise.all([
    _vapidToken(audienta, vapid.subject, vapid.publicKey, vapid.privateKey),
    _cripteaza(sub, text)
  ]);

  const r = await fetch(sub.endpoint, {
    method: 'POST',
    headers: {
      'TTL': String((optiuni && optiuni.TTL) || 3600),
      'Content-Encoding': 'aes128gcm',
      'Content-Type': 'application/octet-stream',
      'Urgency': (optiuni && optiuni.urgency) || 'normal',
      'Authorization': `vapid t=${token}, k=${vapid.publicKey}`
    },
    body: corp
  });

  if (!r.ok) {
    const detaliu = await r.text().catch(() => '');
    const e = new Error(`${r.status} ${detaliu.slice(0, 120)}`.trim());
    e.statusCode = r.status;
    throw e;
  }
  return r.status;
}

// Fereastră de siguranță — mult mai mică decât la GitHub Actions,
// pentru că aici cron-ul chiar rulează la 5 minute, nu "quand poate".
const INTARZIERE_MAX = 30;

// ══════════════════════════════════════════════════════════════
// "DE CÂND" ARE OMUL DREPTUL LA NOTIFICĂRI
//
// Cine activează push-ul azi nu trebuie să primească dintr-o dată tot ce
// s-a trimis înainte: anunțurile din ultimele zile, notificarea de seară
// sau sărbătoarea de dimineață. Aplicația scrie `pushDin` (momentul
// activării) la abonare, iar aici sărim peste orice moment anterior lui.
//
// Abonații vechi nu au câmpul — pentru ei nu filtrăm nimic, altfel le-am
// tăia notificări legitime.
// ══════════════════════════════════════════════════════════════
function inainteDeAbonare(u, momentMs) {
  const din = Number(u && u.pushDin) || 0;
  return din > 0 && momentMs < din;
}

// Transformă o oră din ziua curentă (minute de la miezul nopții) în timp real,
// ca s-o putem compara cu pushDin. Ora României e UTC+3 vara, UTC+2 iarna —
// o luăm din diferența dintre ceasul local formatat și UTC, ca să nu greșim
// la schimbarea orei.
function momentulZilei(dataISO, minute) {
  const [a, l, z] = dataISO.split('-').map(Number);
  const utc = Date.UTC(a, l - 1, z, 0, minute, 0);
  const proba = new Date(utc);
  const local = new Date(proba.toLocaleString('en-US', { timeZone: 'Europe/Bucharest' }));
  const decalaj = local.getTime() - new Date(proba.toLocaleString('en-US', { timeZone: 'UTC' })).getTime();
  return utc - decalaj;
}

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

async function trimiteTure(env, toti, numere, now, vapid) {
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
      // s-a abonat după ce trecuse momentul reminderului
      if (inainteDeAbonare(u, momentulZilei(t.data, tinta))) { sarite++; continue; }

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
        await trimitePush(u.sub, payload, { TTL: 3600, urgency: 'high' }, vapid);
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

async function trimiteChat(env, toti, numere, vapid) {
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
      await trimitePush(u.sub, JSON.stringify({
        title: '💬 Chat STB', body, tag: 'chat', urgent: false, url: '/ProgramSTB/'
      }), { TTL: 1800, urgency: 'normal' }, vapid);
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

// ══════════════════════════════════════════════════════════════
// SĂRBĂTORI LEGALE
// Aceeași listă ca în aplicație, ca să nu apară nepotriviri între ce
// scrie în calendar și ce zice notificarea. Anunțul pleacă dimineața,
// în ziua respectivă, către toți cei cu notificări pornite.
// ══════════════════════════════════════════════════════════════
const SARB={"2026-1-1":"Anul Nou","2026-1-2":"Anul Nou","2026-1-6":"Boboteaza","2026-1-7":"Sf. Ioan Botezătorul","2026-1-24":"Unirea Principatelor","2026-4-10":"Vinerea Mare","2026-4-12":"Paște","2026-4-13":"Paște","2026-5-1":"Ziua Muncii","2026-5-31":"Rusalii","2026-6-1":"Ziua Copilului · Rusalii","2026-8-15":"Sf. Maria","2026-11-30":"Sf. Andrei","2026-12-1":"Ziua Națională","2026-12-25":"Crăciun","2026-12-26":"Crăciun","2027-1-1":"Anul Nou","2027-1-2":"Anul Nou","2027-1-6":"Boboteaza","2027-1-7":"Sf. Ioan Botezătorul","2027-1-24":"Unirea Principatelor","2027-4-30":"Vinerea Mare","2027-5-1":"Ziua Muncii","2027-5-2":"Paște","2027-5-3":"Paște","2027-6-1":"Ziua Copilului","2027-6-20":"Rusalii","2027-6-21":"Rusalii","2027-8-15":"Sf. Maria","2027-11-30":"Sf. Andrei","2027-12-1":"Ziua Națională","2027-12-25":"Crăciun","2027-12-26":"Crăciun","2028-1-1":"Anul Nou","2028-1-2":"Anul Nou","2028-1-6":"Boboteaza","2028-1-7":"Sf. Ioan Botezătorul","2028-1-24":"Unirea Principatelor","2028-4-14":"Vinerea Mare","2028-4-16":"Paște","2028-4-17":"Paște","2028-5-1":"Ziua Muncii","2028-6-1":"Ziua Copilului","2028-6-4":"Rusalii","2028-6-5":"Rusalii","2028-8-15":"Sf. Maria","2028-11-30":"Sf. Andrei","2028-12-1":"Ziua Națională","2028-12-25":"Crăciun","2028-12-26":"Crăciun","2029-1-1":"Anul Nou","2029-1-2":"Anul Nou","2029-1-6":"Boboteaza","2029-1-7":"Sf. Ioan Botezătorul","2029-1-24":"Unirea Principatelor","2029-4-6":"Vinerea Mare","2029-4-8":"Paște","2029-4-9":"Paște","2029-5-1":"Ziua Muncii","2029-5-27":"Rusalii","2029-5-28":"Rusalii","2029-6-1":"Ziua Copilului","2029-8-15":"Sf. Maria","2029-11-30":"Sf. Andrei","2029-12-1":"Ziua Națională","2029-12-25":"Crăciun","2029-12-26":"Crăciun","2030-1-1":"Anul Nou","2030-1-2":"Anul Nou","2030-1-6":"Boboteaza","2030-1-7":"Sf. Ioan Botezătorul","2030-1-24":"Unirea Principatelor","2030-4-26":"Vinerea Mare","2030-4-28":"Paște","2030-4-29":"Paște","2030-5-1":"Ziua Muncii","2030-6-1":"Ziua Copilului","2030-6-16":"Rusalii","2030-6-17":"Rusalii","2030-8-15":"Sf. Maria","2030-11-30":"Sf. Andrei","2030-12-1":"Ziua Națională","2030-12-25":"Crăciun","2030-12-26":"Crăciun","2031-1-1":"Anul Nou","2031-1-2":"Anul Nou","2031-1-6":"Boboteaza","2031-1-7":"Sf. Ioan Botezătorul","2031-1-24":"Unirea Principatelor","2031-4-11":"Vinerea Mare","2031-4-13":"Paște","2031-4-14":"Paște","2031-5-1":"Ziua Muncii","2031-6-1":"Ziua Copilului · Rusalii","2031-6-2":"Rusalii","2031-8-15":"Sf. Maria","2031-11-30":"Sf. Andrei","2031-12-1":"Ziua Națională","2031-12-25":"Crăciun","2031-12-26":"Crăciun","2032-1-1":"Anul Nou","2032-1-2":"Anul Nou","2032-1-6":"Boboteaza","2032-1-7":"Sf. Ioan Botezătorul","2032-1-24":"Unirea Principatelor","2032-4-30":"Vinerea Mare","2032-5-1":"Ziua Muncii","2032-5-2":"Paște","2032-5-3":"Paște","2032-6-1":"Ziua Copilului","2032-6-20":"Rusalii","2032-6-21":"Rusalii","2032-8-15":"Sf. Maria","2032-11-30":"Sf. Andrei","2032-12-1":"Ziua Națională","2032-12-25":"Crăciun","2032-12-26":"Crăciun","2033-1-1":"Anul Nou","2033-1-2":"Anul Nou","2033-1-6":"Boboteaza","2033-1-7":"Sf. Ioan Botezătorul","2033-1-24":"Unirea Principatelor","2033-4-22":"Vinerea Mare","2033-4-24":"Paște","2033-4-25":"Paște","2033-5-1":"Ziua Muncii","2033-6-1":"Ziua Copilului","2033-6-12":"Rusalii","2033-6-13":"Rusalii","2033-8-15":"Sf. Maria","2033-11-30":"Sf. Andrei","2033-12-1":"Ziua Națională","2033-12-25":"Crăciun","2033-12-26":"Crăciun","2034-1-1":"Anul Nou","2034-1-2":"Anul Nou","2034-1-6":"Boboteaza","2034-1-7":"Sf. Ioan Botezătorul","2034-1-24":"Unirea Principatelor","2034-4-7":"Vinerea Mare","2034-4-9":"Paște","2034-4-10":"Paște","2034-5-1":"Ziua Muncii","2034-5-28":"Rusalii","2034-5-29":"Rusalii","2034-6-1":"Ziua Copilului","2034-8-15":"Sf. Maria","2034-11-30":"Sf. Andrei","2034-12-1":"Ziua Națională","2034-12-25":"Crăciun","2034-12-26":"Crăciun","2035-1-1":"Anul Nou","2035-1-2":"Anul Nou","2035-1-6":"Boboteaza","2035-1-7":"Sf. Ioan Botezătorul","2035-1-24":"Unirea Principatelor","2035-4-27":"Vinerea Mare","2035-4-29":"Paște","2035-4-30":"Paște","2035-5-1":"Ziua Muncii","2035-6-1":"Ziua Copilului","2035-6-17":"Rusalii","2035-6-18":"Rusalii","2035-8-15":"Sf. Maria","2035-11-30":"Sf. Andrei","2035-12-1":"Ziua Națională","2035-12-25":"Crăciun","2035-12-26":"Crăciun","2036-1-1":"Anul Nou","2036-1-2":"Anul Nou","2036-1-6":"Boboteaza","2036-1-7":"Sf. Ioan Botezătorul","2036-1-24":"Unirea Principatelor","2036-4-18":"Vinerea Mare","2036-4-20":"Paște","2036-4-21":"Paște","2036-5-1":"Ziua Muncii","2036-6-1":"Ziua Copilului","2036-6-8":"Rusalii","2036-6-9":"Rusalii","2036-8-15":"Sf. Maria","2036-11-30":"Sf. Andrei","2036-12-1":"Ziua Națională","2036-12-25":"Crăciun","2036-12-26":"Crăciun"};

function sarbatoareaZilei(dataISO) {
  const [a, l, z] = dataISO.split('-').map(Number);
  return SARB[`${a}-${l}-${z}`] || null;
}

async function trimiteSarbatori(env, toti, numere, now, vapid) {
  // Fereastră de dimineață: 08:00–09:59, o singură dată pe zi.
  if (now.minute < 8 * 60 || now.minute >= 10 * 60) return { trimise: 0 };

  const nume = sarbatoareaZilei(now.data);
  if (!nume) return { trimise: 0 };

  let trimise = 0;
  const erori = [];

  for (const nr of numere) {
    const u = toti[nr];
    if (!u || !u.sub) continue;
    if (u.sarbTrimis === now.data) continue;
    // s-a abonat după ora la care pleca anunțul de sărbătoare
    if (inainteDeAbonare(u, momentulZilei(now.data, 8 * 60))) continue;

    // Dacă știm ce are omul azi, i-o spunem în același mesaj —
    // sărbătoare legală nu înseamnă automat zi liberă la transport.
    const zi = Array.isArray(u.zile) ? u.zile.find(x => x && x.data === now.data) : null;
    const t  = Array.isArray(u.ture) ? u.ture.find(x => x && x.data === now.data) : null;
    let corp = 'Sărbătoare legală';
    if (t) corp += ` · azi ai tură: ${t.text || t.start}`;
    else if (zi) corp += ` · azi: ${zi.txt}`;

    try {
      await trimitePush(u.sub, JSON.stringify({
        title: `🎉 ${nume}`,
        body: corp,
        tag: 'sarb-' + now.data,
        url: '/ProgramSTB/'
      }), { TTL: 43200, urgency: 'normal' }, vapid);

      await fetch(`${env.FB_URL}/push/${nr}/sarbTrimis.json`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(now.data)
      }).catch(() => {});
      trimise++;
    } catch (e) {
      if (e.statusCode === 404 || e.statusCode === 410) {
        await fetch(`${env.FB_URL}/push/${nr}.json`, { method: 'DELETE' }).catch(() => {});
      } else if (erori.length < 3) {
        erori.push(`${nr}: ${e.statusCode || '-'} ${e.message || e}`);
      }
    }
  }
  return { trimise, erori };
}

// ══════════════════════════════════════════════════════════════
// NOTIFICAREA DE SEARĂ ("ce ai mâine")
//
// Era făcută în aplicație, cu un cronometru în pagină — deci pleca doar
// dacă aplicația era deschisă la ora aia. Cu telefonul blocat nu venea
// niciodată. Aici o trimitem ca push adevărat, la fel ca anunțurile.
// ══════════════════════════════════════════════════════════════
const ZILE_RO = ['Duminică', 'Luni', 'Marți', 'Miercuri', 'Joi', 'Vineri', 'Sâmbătă'];

function ziuaUrmatoare(dataISO) {
  const [a, l, z] = dataISO.split('-').map(Number);
  const d = new Date(Date.UTC(a, l - 1, z));
  d.setUTCDate(d.getUTCDate() + 1);
  const p = n => String(n).padStart(2, '0');
  return {
    iso: `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}`,
    zi: ZILE_RO[d.getUTCDay()],
    numar: d.getUTCDate()
  };
}

async function trimiteSeara(env, toti, numere, now, vapid) {
  // Aceeași fereastră ca în aplicație: 20:00–22:59, o singură dată pe zi.
  // Mutată de la 21:00 la 20:00 la cererea utilizatorului.
  if (now.minute < 20 * 60 || now.minute >= 23 * 60) return { trimise: 0 };

  const maine = ziuaUrmatoare(now.data);
  let trimise = 0;
  const erori = [];

  for (const nr of numere) {
    const u = toti[nr];
    if (!u || !u.sub || !u.notifSeara) continue;
    if (u.searaTrimis === now.data) continue;   // deja trimisă azi
    // s-a abonat după ora 20:00 — notificarea de azi îi scapă, o primește mâine
    if (inainteDeAbonare(u, momentulZilei(now.data, 20 * 60))) continue;

    // Preferăm descrierea completă (acoperă și liber/concediu/sărbătoare).
    // Dacă utilizatorul are o versiune veche a aplicației, care nu trimite
    // încă `zile`, cădem înapoi pe lista de ture.
    const zi = Array.isArray(u.zile) ? u.zile.find(x => x && x.data === maine.iso) : null;
    const t  = Array.isArray(u.ture) ? u.ture.find(x => x && x.data === maine.iso) : null;
    if (!zi && !t) continue;   // ziua nu e completată — nu inventăm nimic

    const orar = t ? (t.end ? `${t.start}–${t.end}` : `de la ${t.start}`) : '';
    const descriere = zi ? zi.txt : (t.text || orar);
    try {
      await trimitePush(u.sub, JSON.stringify({
        title: `🌙 Mâine — ${maine.zi} ${maine.numar}`,
        body: descriere,
        tag: 'seara-' + maine.iso,
        url: '/ProgramSTB/'
      }), { TTL: 43200, urgency: 'normal' }, vapid);

      await fetch(`${env.FB_URL}/push/${nr}/searaTrimis.json`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(now.data)
      }).catch(() => {});
      trimise++;
    } catch (e) {
      if (e.statusCode === 404 || e.statusCode === 410) {
        await fetch(`${env.FB_URL}/push/${nr}.json`, { method: 'DELETE' }).catch(() => {});
      } else if (erori.length < 3) {
        erori.push(`${nr}: ${e.statusCode || '-'} ${e.message || e}`);
      }
    }
  }
  return { trimise, erori };
}

// ══════════════════════════════════════════════════════════════
// ANUNȚURI DE LA ADMIN — push către toți abonații
// Aplicația scrie anunțul în /broadcast, workerul îl livrează, pentru că
// doar el are cheia de semnare. Fiecare coleg primește un anunț o singură
// dată (marcaj broadcastNotificat cu ora ultimului primit).
// ══════════════════════════════════════════════════════════════
async function trimiteAnunturi(env, toti, numere, vapid) {
  let anunturi;
  try { anunturi = await getJSON(`${env.FB_URL}/broadcast.json`); }
  catch (e) { return { trimise: 0, eroare: e.message }; }
  if (!anunturi) return { trimise: 0 };

  const lista = Object.entries(anunturi)
    .filter(([, a]) => a && a.t)
    .sort((a, b) => a[1].t - b[1].t);
  if (!lista.length) return { trimise: 0 };

  const celMaiNou = lista[lista.length - 1][1].t;
  let trimise = 0;
  const erori = [];   // [DIAGNOSTIC] ce anume refuză trimiterea

  for (const nr of numere) {
    const u = toti[nr];
    if (!u || !u.sub) continue;

    const primit = Number(u.broadcastNotificat) || 0;
    // Trimitem doar anunțurile mai noi decât ultimul primit, maxim 3 deodată,
    // și doar pe cele apărute după ce omul și-a activat notificările — altfel
    // cine se abonează azi primește dintr-o dată tot ce s-a anunțat săptămâna
    // trecută.
    const noi = lista
      .filter(([, a]) => a.t > primit && !inainteDeAbonare(u, a.t))
      .slice(-3);

    if (!noi.length) {
      // Abonat nou fără niciun anunț de primit: notăm totuși ultimul anunț ca
      // "văzut", ca să nu recalculăm asta la fiecare rulare de cinci minute.
      if (u.pushDin && primit < celMaiNou) {
        await fetch(`${env.FB_URL}/push/${nr}/broadcastNotificat.json`, {
          method: 'PUT', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(celMaiNou)
        }).catch(() => {});
      }
      continue;
    }

    let okPentruAcesta = false;
    for (const [, a] of noi) {
      try {
        await trimitePush(u.sub, JSON.stringify({
          title: a.titlu || '📢 Anunț Program STB',
          body: a.text || '',
          tag: 'anunt-' + a.t,
          urgent: true,
          url: '/ProgramSTB/'
        }), { TTL: 86400, urgency: 'high' }, vapid);
        okPentruAcesta = true;
        trimise++;
      } catch (e) {
        if (e.statusCode === 404 || e.statusCode === 410) {
          await fetch(`${env.FB_URL}/push/${nr}.json`, { method: 'DELETE' }).catch(() => {});
          break;
        }
        // orice altă eroare: o reținem, ca să apară în raport
        if (erori.length < 3) {
          erori.push(`${nr}: ${e.statusCode || '-'} ${e.name || ''} ${e.message || e}`.trim());
        }
      }
    }
    if (okPentruAcesta) {
      await fetch(`${env.FB_URL}/push/${nr}/broadcastNotificat.json`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(celMaiNou)
      }).catch(() => {});
    }
  }

  // curățăm anunțurile mai vechi de 7 zile
  const limita = Date.now() - 7 * 24 * 3600 * 1000;
  for (const [k, a] of Object.entries(anunturi)) {
    if (!a || !a.t || a.t < limita) {
      await fetch(`${env.FB_URL}/broadcast/${k}.json`, { method: 'DELETE' }).catch(() => {});
    }
  }

  return { trimise, erori };
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

  const vapid = {
    subject: 'mailto:programstb@example.com',
    publicKey: env.VAPID_PUBLIC,
    privateKey: env.VAPID_PRIVATE
  };

  const now = acumRo();
  log(`Ora României: ${now.data} ${String(Math.floor(now.minute / 60)).padStart(2, '0')}:${String(now.minute % 60).padStart(2, '0')}`);

  let toti;
  try { toti = await getJSON(`${env.FB_URL}/push.json`); }
  catch (e) { log('❌ Nu am putut citi abonamentele: ' + e.message); return raport.join('\n'); }

  if (!toti) { log('Niciun abonament înregistrat.'); return raport.join('\n'); }

  const numere = Object.keys(toti);
  log(`${numere.length} abonamente de verificat.`);

  const { trimise, sarite, expirate } = await trimiteTure(env, toti, numere, now, vapid);
  log(`Ture: ${trimise} trimise · ${sarite} sărite · ${expirate} expirate`);

  const sarb = await trimiteSarbatori(env, toti, numere, now, vapid);
  if (sarb.trimise) log(`Sărbătoare: ${sarb.trimise} notificări trimise`);
  if (sarb.erori && sarb.erori.length) {
    log('  ⚠ sărbătoare, refuzate:');
    for (const x of sarb.erori) log('    ' + x);
  }

  const seara = await trimiteSeara(env, toti, numere, now, vapid);
  if (seara.trimise) log(`Seara: ${seara.trimise} notificări trimise`);
  if (seara.erori && seara.erori.length) {
    log('  ⚠ seara, refuzate:');
    for (const x of seara.erori) log('    ' + x);
  }

  const { chatTrimise, eroare } = await trimiteChat(env, toti, numere, vapid);
  if (eroare) log('Chat: eroare — ' + eroare);
  else log(`Chat: ${chatTrimise} notificări trimise`);

  const anunt = await trimiteAnunturi(env, toti, numere, vapid);
  if (anunt.eroare) log('Anunțuri: eroare — ' + anunt.eroare);
  else {
    log(`Anunțuri: ${anunt.trimise} trimise`);
    if (anunt.erori && anunt.erori.length) {
      log('  ⚠ refuzate de serviciul de push:');
      for (const x of anunt.erori) log('    ' + x);
    }
  }

  // ── Raport de utilizare ─────────────────────────────────────
  try {
    const stats = await getJSON(`${env.FB_URL}/stats.json`);
    if (stats) {
      const v = Object.values(stats);
      const nrCu = (f) => v.filter(f).length;
      const grup = (camp) => {
        const g = {};
        for (const x of v) { const k = x[camp] || '?'; g[k] = (g[k] || 0) + 1; }
        return Object.entries(g).sort((a, b) => b[1] - a[1]);
      };
      log('');
      log('── UTILIZARE ──');
      log(`Total cu statistică: ${v.length}`);
      log(`  instalate pe ecran: ${nrCu(x => x.instalat === true)}`);
      log(`  doar în browser:    ${nrCu(x => x.instalat !== true)}`);
      log(`  cu push pornit:     ${nrCu(x => x.push === true)}`);
      log('Pe platformă: ' + grup('platforma').map(([k, n]) => `${k}=${n}`).join(', '));
      log('Pe depou:     ' + grup('depot').map(([k, n]) => `${k}=${n}`).join(', '));

      // Cazul critic: iPhone neinstalat = nu poate primi notificări deloc
      const iphoneRau = v.filter(x => x.platforma === 'iPhone' && x.instalat !== true).length;
      if (iphoneRau) {
        log('');
        log(`⚠️ ${iphoneRau} colegi pe iPhone folosesc aplicația din browser —`);
        log('   pentru ei notificările NU pot funcționa până n-o instalează pe ecran.');
      }
    } else {
      log('');
      log('── UTILIZARE ── încă nicio statistică (apar după ce colegii deschid v1.8+)');
    }
  } catch (e) { log('Statistici: ' + e.message); }

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
    const url = new URL(request.url);

    // ── Aplicația vorbește cu workerul din browser, deci are nevoie de CORS ──
    const cors = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    };
    if (request.method === 'OPTIONS') return new Response(null, { headers: cors });

    if (url.pathname === '/admin') {
      const r = await admin(request, env);
      return new Response(JSON.stringify(r.corp), {
        status: r.status,
        headers: { 'Content-Type': 'application/json; charset=utf-8', ...cors }
      });
    }

    const raport = await ruleaza(env);
    return new Response(raport, { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
  }
};

// ══════════════════════════════════════════════════════════════
// PANOUL DE ADMIN — verificarea se face AICI, nu în telefon
//
// Până acum parola era scrisă în index.html, fișier public pe GitHub:
// oricine îl deschidea putea intra în panou și trimite anunțuri tuturor
// colegilor. Acum parola stă ca secret în Cloudflare, iar aplicația doar
// întreabă workerul „e bună?". Codul nu se poate citi de nicăieri.
//
// Comparația e făcută în timp constant, ca să nu se poată ghici parola
// măsurând cât durează răspunsul.
// ══════════════════════════════════════════════════════════════
function paroleEgale(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let dif = 0;
  for (let i = 0; i < a.length; i++) dif |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return dif === 0;
}

async function admin(request, env) {
  if (request.method !== 'POST') {
    return { status: 405, corp: { ok: false, eroare: 'Doar POST' } };
  }
  if (!env.ADMIN_PASS) {
    return { status: 500, corp: { ok: false, eroare: 'ADMIN_PASS nu e configurat în Cloudflare' } };
  }

  let cerere;
  try { cerere = await request.json(); }
  catch (e) { return { status: 400, corp: { ok: false, eroare: 'Cerere invalidă' } }; }

  if (!paroleEgale(String(cerere.parola || ''), String(env.ADMIN_PASS))) {
    // Mică întârziere, ca încercările repetate să nu fie ieftine
    await new Promise(r => setTimeout(r, 400));
    return { status: 401, corp: { ok: false, eroare: 'Parolă greșită' } };
  }

  switch (cerere.actiune) {
    case 'verifica':
      return { status: 200, corp: { ok: true } };

    default:
      return { status: 400, corp: { ok: false, eroare: 'Acțiune necunoscută: ' + cerere.actiune } };
  }
}
