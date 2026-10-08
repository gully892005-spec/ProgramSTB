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
// [OPTIMIZARE] Tokenul VAPID depinde doar de serverul de push (Google, Apple,
// Mozilla), nu de destinatar, și e valabil 12 ore. Înainte se semna câte unul
// pentru fiecare notificare: la 55 de colegi însemna 55 de semnături ECDSA
// pentru două-trei servere distincte. Acum se calculează o dată pe rulare.
// La fel și importul cheii private, care se făcea tot de atâtea ori.
const _cacheToken = new Map();   // audiență -> { token, expira }
let _cacheCheie = null;

async function _cheieSemnare(publicKey, privateKey) {
  if (_cacheCheie) return _cacheCheie;
  const pub = _unb64u(publicKey);
  const jwk = {
    kty: 'EC', crv: 'P-256', ext: true,
    x: _b64u(pub.slice(1, 33)),
    y: _b64u(pub.slice(33, 65)),
    d: String(privateKey).replace(/=+$/, '')
  };
  _cacheCheie = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  return _cacheCheie;
}

async function _vapidToken(audience, subject, publicKey, privateKey) {
  const acum = Math.floor(Date.now() / 1000);
  const dinCache = _cacheToken.get(audience);
  // Refolosim atâta timp cât mai are cel puțin o oră de trăit
  if (dinCache && dinCache.expira - acum > 3600) return dinCache.token;

  const key = await _cheieSemnare(publicKey, privateKey);
  const head = _b64u(_enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const expira = acum + 12 * 3600;
  const body = _b64u(_enc.encode(JSON.stringify({ aud: audience, exp: expira, sub: subject })));
  const sig = new Uint8Array(await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, key, _enc.encode(head + '.' + body)
  ));
  const token = head + '.' + body + '.' + _b64u(sig);
  _cacheToken.set(audience, { token, expira });
  return token;
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
// [v11] Un număr de serviciu poate avea mai multe telefoane — de serviciu și
// personal. Înainte, în cloud încăpea un singur abonament: fiecare telefon îl
// suprascria pe celălalt la sincronizare, deci notificările ajungeau doar pe
// ultimul care deschisese aplicația, fără ca omul să afle.
//
// Acum abonamentele stau într-o listă, `subs`, cheie = id-ul telefonului.
// `sub` (vechiul câmp) rămâne citit, ca cine n-a apucat să treacă pe versiunea
// nouă a aplicației să nu rămână fără notificări.
function abonamentele(u) {
  const out = [];
  const vazute = new Set();
  const pune = (id, sub) => {
    if (!sub || !sub.endpoint || vazute.has(sub.endpoint)) return;
    vazute.add(sub.endpoint);
    out.push({ id, sub });
  };
  if (u && u.subs && typeof u.subs === 'object') {
    for (const id of Object.keys(u.subs)) {
      const v = u.subs[id];
      pune(id, v && v.sub ? v.sub : v);
    }
  }
  pune('_vechi', u && u.sub);
  return out;
}

// Trimite același mesaj pe toate telefoanele omului. Abonamentele moarte se
// șterg pe loc, fiecare din locul lui, ca să nu se adune gunoi în cloud.
async function trimiteToate(env, nr, u, text, optiuni, vapid) {
  const lista = abonamentele(u);
  if (!lista.length) return { trimise: 0, moarte: 0 };
  let trimise = 0, moarte = 0;
  for (const { id, sub } of lista) {
    try {
      await trimitePush(sub, text, optiuni, vapid);
      trimise++;
    } catch (e) {
      if (e.statusCode === 404 || e.statusCode === 410) {
        moarte++;
        const cale = id === '_vechi' ? `push/${nr}/sub.json` : `push/${nr}/subs/${id}.json`;
        await fetch(urlBroadcast(env, cale), { method: 'DELETE' }).catch(() => {});
      } else {
        throw e;
      }
    }
  }
  return { trimise, moarte };
}

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

// [OPTIMIZARE] Notificările plecau una câte una: fiecare aștepta răspunsul
// serverului de push înainte de următoarea. La zeci de abonați, o rulare
// dura secunde bune degeaba — sunt așteptări de rețea, nu calcul.
// Le trimitem pe grupuri de 10, ca să nu deschidem prea multe conexiuni
// simultan (Cloudflare limitează la 6 conexiuni deschise per worker).
const GRUP = 10;

async function peGrupuri(elemente, treaba) {
  const rezultate = [];
  for (let i = 0; i < elemente.length; i += GRUP) {
    const felie = elemente.slice(i, i + GRUP);
    rezultate.push(...await Promise.all(felie.map(treaba)));
  }
  return rezultate;
}

// Un abonament expirat (utilizator care a șters aplicația) trebuie curățat.
async function stergeAbonament(env, nr) {
  await fetch(`${env.FB_URL}/push/${nr}.json`, { method: 'DELETE' }).catch(() => {});
}

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

// ══════════════════════════════════════════════════════════════
// SCRIEREA ÎN /broadcast — doar workerul are voie
//
// Odată ce regula Firebase pentru /broadcast devine "citire da, scriere nu",
// nimeni din aplicație nu mai poate strecura un anunț fals care ajunge ca
// notificare pe telefoanele tuturor colegilor. Workerul trece de regulă cu
// cheia de serviciu (FB_SECRET), ținută tot ca secret în Cloudflare.
//
// Dacă FB_SECRET nu e configurat, funcționează exact ca înainte — util ca să
// poți urca worker-ul fără să blochezi nimic până schimbi regula.
// ══════════════════════════════════════════════════════════════
function urlBroadcast(env, cale) {
  // [2.7] Nicio cale cu „..”, „#”, „\” sau „.”/„/” codate: fetch le-ar rezolva și ar
  // scrie în alt loc din Firebase decât cel cerut (ex. adminJetoane).
  if (/(^|\/)\.\.?(\/|$)|#|\\|%2e|%2f|%5c/i.test(String(cale).split('?')[0])) throw new Error('Cale nepermisă');
  const u = `${env.FB_URL}/${cale}`;
  return env.FB_SECRET ? `${u}?auth=${encodeURIComponent(env.FB_SECRET)}` : u;
}

// Depourile pentru care se poate urca o repartizare. Aceleași chei ca în
// db.json și în aplicație — se folosesc ca nume de folder în Firebase.
const DEPOURI = ['dudesti', 'giurgiu', 'victoria', 'titan', 'alexandria',
                 'colentina', 'militari', 'budesti', 'autobuze', 'troleibuze'];

// ══════════════════════════════════════════════════════════════
// UTILIZATORI BLOCAȚI
//
// Lista stă în /blocati/<nr> și se scrie DOAR de aici, cu cheia de serviciu.
// Regula Firebase trebuie să fie ".read": true, ".write": false — altfel
// cel blocat s-ar putea șterge singur din listă.
//
// Blocarea oprește cu adevărat notificările (aici, în worker, nu are cum s-o
// ocolească). Ecranul de blocare din aplicație e o măsură de bună-cuviință:
// programul e în telefonul lui și merge și fără internet.
// ══════════════════════════════════════════════════════════════
async function citesteBlocati(env) {
  try {
    const b = await getJSON(`${env.FB_URL}/blocati.json`);
    return b && typeof b === 'object' ? b : {};
  } catch (e) {
    return {};   // dacă nu putem citi lista, nu blocăm pe nimeni din greșeală
  }
}

function nrCurat(x) {
  return String(x || '').replace(/[^0-9]/g, '').slice(0, 12);
}

function acumRo() {
  // [FIX v12.6] Era `hour12: false`, care în unele motoare JS dă ora
  // miezului nopții ca „24\", nu „00\" — și atunci data formatată e a zilei
  // dinainte. În primele minute după miezul nopții cronul ar fi lucrat cu
  // ziua greșită și cu minutul 1440. `hourCycle: 'h23'` cere explicit 00–23,
  // iar dacă totuși vine 24, rotim noi ziua înainte.
  const f = new Intl.DateTimeFormat('sv-SE', {
    timeZone: 'Europe/Bucharest',
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hourCycle: 'h23'
  });
  const s = f.format(new Date());
  const [data, ora] = s.split(' ');
  let [h, m] = ora.split(':').map(Number);
  if (h === 24) {
    const [a, l, z] = data.split('-').map(Number);
    const d = new Date(Date.UTC(a, l - 1, z));
    d.setUTCDate(d.getUTCDate() + 1);
    const p = n => String(n).padStart(2, '0');
    return { data: `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}`, minute: m };
  }
  return { data, minute: h * 60 + m };
}

async function getJSON(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error('HTTP ' + r.status + ' la ' + url);
  return r.json();
}

async function trimiteTure(env, toti, numere, now, vapid) {
  let trimise = 0, sarite = 0, expirate = 0;

  const rezultate = await peGrupuri(numere, async (nr) => {
    const u = toti[nr];
    if (!u || !abonamentele(u).length || !Array.isArray(u.ture)) return { sarit: 1 };

    // Un coleg poate cere mai multe alerte pentru aceeași tură (2 ore, 1 oră,
    // 30 de minute). Fiecare are marcajul ei, altfel a doua ar fi luată drept
    // trimisă. Ținem ultimele marcaje într-o listă, nu doar pe ultimul.
    const trimiseDeja = Array.isArray(u.trimise) ? u.trimise : (u.trimis ? [u.trimis] : []);

    // Plasă de siguranță: aplicația trimite și lista `zile`, cu descrierea
    // fiecărei zile. Dacă acolo scrie că azi e liber sau concediu, nu trimitem
    // alerta de tură, oricât de veche ar fi lista de ture. Așa nu mai ajunge
    // pe telefon tura rămasă în cloud de la alt depou sau de la un coleg.
    const ziAzi = Array.isArray(u.zile) ? u.zile.find(x => x && x.data === now.data) : null;
    const aziLiber = !!(ziAzi && ziAzi.lucrata === false);

    // [2.7] O tură care începe după miezul nopții (ex. 00:30, liniile de noapte)
    // are alerta de „cu o oră înainte" în ziua de dinainte. Înainte nu pleca.
    const maine = (() => { const [a, l, z] = now.data.split('-').map(Number); return new Date(Date.UTC(a, l - 1, z + 1)).toISOString().slice(0, 10); })();
    for (const t of u.ture) {
      if (!t || !t.data || !t.start) continue;
      if (t.data !== now.data && t.data !== maine) continue;
      const peMaine = t.data === maine;
      if (!peMaine && aziLiber) continue;

      const [h, m] = t.start.split(':').map(Number);
      if (isNaN(h) || isNaN(m)) continue;
      if (peMaine && h * 60 + m >= 240) continue;     // doar turele de mâine dinainte de 04:00

      const timpi = Array.isArray(t.mins) && t.mins.length
        ? t.mins.map(Number).filter(x => x > 0)
        : [Number(t.minBefore) || 60];

      const startMin = h * 60 + m + (peMaine ? 1440 : 0);
      let minBefore = null, tinta = null, marcaj = null;

      for (const cat of timpi) {
        const t2 = startMin - cat;
        const d2 = now.minute - t2;
        if (d2 < 0 || d2 >= INTARZIERE_MAX) continue;
        const mc = `${t.data}_${t.start}_${cat}`;
        if (trimiseDeja.includes(mc)) continue;
        minBefore = cat; tinta = t2; marcaj = mc;
        break;
      }
      if (marcaj === null) continue;

      // s-a abonat după ce trecuse momentul reminderului
      if (inainteDeAbonare(u, momentulZilei(peMaine ? now.data : t.data, tinta))) return { sarit: 1 };

      // Timpul real rămas — poate diferi puțin de minBefore dacă a durat
      // câteva minute până la rulare.
      const ramase = startMin - now.minute;
      // „Tură în 116 minute" se citește greu. Peste o oră scriem „1h 56m".
      const cat = ramase >= 60
        ? `${Math.floor(ramase / 60)}h${ramase % 60 ? ' ' + (ramase % 60) + 'm' : ''}`
        : `${ramase} min`;
      const payload = JSON.stringify(ramase > 0 ? {
        title: `🚃 Tură în ${cat}`,
        body: t.text ? `${t.text}\nPregătește-te!` : `Plecare la ${t.start}. Pregătește-te!`,
        tag: 'tura-' + t.data,
        url: './'
      } : {
        title: `🚃 Tura ta a început`,
        body: t.text || `Plecare la ${t.start}`,
        tag: 'tura-' + t.data,
        url: './'
      });

      try {
        const r = await trimiteToate(env, nr, u, payload, { TTL: 3600, urgency: 'high' }, vapid);
        // Marcăm ca trimisă doar dacă a ajuns pe cel puțin un telefon. Altfel,
        // dacă toate abonamentele erau moarte, am pierde alerta definitiv.
        if (!r.trimise) return { expirat: 1 };
        const noi = trimiseDeja.concat(marcaj).slice(-8);
        await fetch(`${env.FB_URL}/push/${nr}/trimise.json`, {
          method: 'PUT', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(noi)
        });
        return { trimis: 1 };
      } catch (e) {
        return {};
      }
    }
    return {};   // maxim o notificare de tură per utilizator per rulare
  });

  for (const r of rezultate) {
    trimise  += r.trimis  || 0;
    sarite   += r.sarit   || 0;
    expirate += r.expirat || 0;
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
  await peGrupuri(numere, async (nr) => {
    const u = toti[nr];
    if (!u || !abonamentele(u).length) return;
    if (u.chatMute === true) return;

    const vazut = Number(u.chatSeen) || 0;
    const notificat = Number(u.chatNotificat) || 0;
    // [FIX v12.6] Toate celelalte notificări sar peste ce s-a întâmplat înainte
    // de activarea push-ului; chatul nu o făcea. Cine pornea notificările
    // primea imediat un „mesaje noi" pentru discuții de dinaintea lui.
    const dinPush = Number(u.pushDin) || 0;
    const referinta = Math.max(vazut, notificat, dinPush);
    const noi = mesaje.filter(m => m.t > referinta);
    if (noi.length === 0) return;

    const nume = [...new Set(noi.map(m => m.n).filter(Boolean))];
    const cine = nume.length === 1 ? nume[0]
               : nume.length === 2 ? `${nume[0]} și ${nume[1]}`
               : `${nume[0]} și încă ${nume.length - 1}`;
    const body = noi.length === 1 ? `${cine} a scris un mesaj nou` : `${noi.length} mesaje noi de la ${cine}`;

    try {
      // [FIX v12.6] la fel ca la seara/sărbători: numărăm doar ce a ajuns
      // chiar pe un telefon. Marcajul primea `.catch` — fără el, o eroare de
      // rețea la scriere ieșea din try și notificarea de chat se repeta la
      // fiecare rulare de cinci minute.
      const rez = await trimiteToate(env, nr, u, JSON.stringify({
        title: '💬 Chat STB', body, tag: 'chat', urgent: false, url: './'
      }), { TTL: 1800, urgency: 'normal' }, vapid);
      if (!rez.trimise) return;
      await fetch(`${env.FB_URL}/push/${nr}/chatNotificat.json`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(ultimul)
      }).catch(() => {});
      chatTrimise++;
    } catch (e) {
      if (e.statusCode === 404 || e.statusCode === 410) {
        await fetch(`${env.FB_URL}/push/${nr}.json`, { method: 'DELETE' }).catch(() => {});
      }
    }
  });

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

  await peGrupuri(numere, async (nr) => {
    const u = toti[nr];
    if (!u || !abonamentele(u).length) return;
    if (u.sarbTrimis === now.data) return;
    // s-a abonat după ora la care pleca anunțul de sărbătoare
    if (inainteDeAbonare(u, momentulZilei(now.data, 8 * 60))) return;

    // Dacă știm ce are omul azi, i-o spunem în același mesaj —
    // sărbătoare legală nu înseamnă automat zi liberă la transport.
    const zi = Array.isArray(u.zile) ? u.zile.find(x => x && x.data === now.data) : null;
    const t  = Array.isArray(u.ture) ? u.ture.find(x => x && x.data === now.data) : null;
    let corp = 'Sărbătoare legală';
    if (t) corp += ` · azi ai tură: ${t.text || t.start}`;
    else if (zi) corp += ` · azi: ${zi.txt}`;

    try {
      // [FIX v12.6] vezi nota de la notificarea de seară: fără verificarea
      // asta, marcajul se punea și când n-a ajuns pe niciun telefon.
      const rez = await trimiteToate(env, nr, u, JSON.stringify({
        title: `🎉 ${nume}`,
        body: corp,
        tag: 'sarb-' + now.data,
        url: './'
      }), { TTL: 43200, urgency: 'normal' }, vapid);
      if (!rez.trimise) return;

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
  });
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

// Ora la care omul vrea notificarea de seara, în minute de la miezul nopții.
// Implicit 20:00, dar fiecare și-o poate muta din aplicație.
function oraSerii(u) {
  const v = Number(u && u.oraSeara);
  return (Number.isFinite(v) && v >= 0 && v < 24 * 60) ? v : 20 * 60;
}

async function trimiteSeara(env, toti, numere, now, vapid) {
  const maine = ziuaUrmatoare(now.data);
  let trimise = 0;
  const erori = [];

  await peGrupuri(numere, async (nr) => {
    const u = toti[nr];
    if (!u || !abonamentele(u).length || !u.notifSeara) return;
    if (u.searaTrimis === now.data) return;   // deja trimisă azi

    // Fereastră de 3 ore de la ora aleasă, ca înainte: dacă telefonul a fost
    // închis exact atunci, o primește la următorul cron, nu o pierde de tot.
    const ora = oraSerii(u);
    if (now.minute < ora || now.minute >= ora + 180) return;

    // s-a abonat după ora aleasă — notificarea de azi îi scapă, o primește mâine
    if (inainteDeAbonare(u, momentulZilei(now.data, ora))) return;

    // Preferăm descrierea completă (acoperă și liber/concediu/sărbătoare).
    // Dacă utilizatorul are o versiune veche a aplicației, care nu trimite
    // încă `zile`, cădem înapoi pe lista de ture.
    const zi = Array.isArray(u.zile) ? u.zile.find(x => x && x.data === maine.iso) : null;
    const t  = Array.isArray(u.ture) ? u.ture.find(x => x && x.data === maine.iso) : null;
    if (!zi && !t) return;   // ziua nu e completată — nu inventăm nimic

    const orar = t ? (t.end ? `${t.start}–${t.end}` : `de la ${t.start}`) : '';
    const descriere = zi ? zi.txt : (t.text || orar);
    try {
      // [FIX v12.6] trimiteToate NU aruncă atunci când toate abonamentele sunt
      // moarte: le șterge și întoarce trimise:0. Fără verificarea asta număram
      // notificarea ca trimisă și puneam marcajul „searaTrimis", deși pe niciun
      // telefon n-a ajuns nimic. Raportul ieșea umflat, iar dacă omul se
      // reabona în aceeași seară nu mai primea nimic, marcajul fiind deja pus.
      const rez = await trimiteToate(env, nr, u, JSON.stringify({
        title: `🌙 Mâine — ${maine.zi} ${maine.numar}`,
        body: descriere,
        tag: 'seara-' + maine.iso,
        url: './'
        // [FIX v14.3] Era `urgency: 'normal'`. Android pune deoparte
        // notificările de prioritate normală cât timp telefonul doarme (Doze)
        // și le livrează abia la următoarea fereastră de trezire — de aici
        // întârzierile de zeci de minute la notificarea de seară. Alerta
        // dinaintea turei era deja 'high', de-aia aia venea la timp.
        // O notificare pe zi, la o oră aleasă de om, merită trezirea.
      }), { TTL: 43200, urgency: 'high' }, vapid);
      if (!rez.trimise) return;

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
  });
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
  // [v12.6] Contoare de livrare, ca butonul din panou să poată spune pe câte
  // telefoane a ajuns anunțul, nu doar câți colegi l-au primit. Înainte
  // exista un al doilea buton, „Trimite la toți", care făcea exact același
  // lucru doar ca să arate cifrele astea — l-am scos și le-am adus aici.
  let telefoane = 0, expirate = 0, faraTelefon = 0;
  const erori = [];   // [DIAGNOSTIC] ce anume refuză trimiterea

  await peGrupuri(numere, async (nr) => {
    const u = toti[nr];
    if (!u || !abonamentele(u).length) { faraTelefon++; return; }

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
      return;
    }

    let okPentruAcesta = false;
    for (const [, a] of noi) {
      try {
        await trimiteToate(env, nr, u, JSON.stringify({
          title: a.titlu || '📢 Anunț Program STB',
          body: a.text || '',
          tag: 'anunt-' + a.t,
          urgent: true,
          url: './'
        }), { TTL: 86400, urgency: 'high' }, vapid).then(r => {
          // [FIX v12.6] marcajul `broadcastNotificat` se punea și când toate
          // abonamentele erau moarte, deci anunțul se pierdea definitiv pentru
          // omul care se reabona după aceea.
          if (r && r.trimise) { okPentruAcesta = true; trimise++; telefoane += r.trimise; }
          if (r && r.moarte) expirate += r.moarte;
        });
      } catch (e) {
        if (e.statusCode === 404 || e.statusCode === 410) {
          await stergeAbonament(env, nr);
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
  });

  // curățăm anunțurile mai vechi de 7 zile
  const limita = Date.now() - 7 * 24 * 3600 * 1000;
  for (const [k, a] of Object.entries(anunturi)) {
    if (!a || !a.t || a.t < limita) {
      await fetch(urlBroadcast(env, `broadcast/${k}.json`), { method: 'DELETE' }).catch(() => {});
    }
  }

  return { trimise, telefoane, expirate, faraTelefon, erori };
}

// ══════════════════════════════════════════════════════════════
// [v17.9] COPIE ZILNICĂ A BACKUPURILOR
//
// Firebase, pe planul gratuit, nu ține versiuni vechi: ce s-a scris peste s-a
// dus. Am pierdut așa programul a doi colegi — un telefon aproape gol a urcat
// peste un program de luni întregi, iar recuperarea n-a mai fost posibilă.
// Aici facem o copie pe zi a întregului nod `backup`, în `arhiva/<data>`, și
// ținem ultimele ARHIVA_ZILE. Nu împiedică greșeala, dar o face reparabilă.
// ══════════════════════════════════════════════════════════════
const ARHIVA_ZILE = 10;

async function facArhiva(env) {
  const azi = new Date().toISOString().slice(0, 10);   // 2026-09-15

  // S-a făcut deja azi? Copia e mare, n-o repetăm la fiecare cinci minute.
  try {
    const gata = await getJSON(urlBroadcast(env, `arhiva/${azi}/ts.json`));
    if (gata) return { sarit: true };
  } catch (e) {}

  let tot;
  try { tot = await getJSON(urlBroadcast(env, 'backup.json')); }
  catch (e) { return { eroare: 'nu am putut citi backupurile: ' + e.message }; }
  if (!tot) return { eroare: 'nu există backupuri' };

  const numere = Object.keys(tot).length;
  let zile = 0;
  for (const u of Object.values(tot)) zile += Number(u && u.zile) || 0;

  const w = await fetch(urlBroadcast(env, `arhiva/${azi}.json`), {
    method: 'PUT', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ts: Date.now(), numere, zile, backup: tot })
  });
  if (!w.ok) return { eroare: 'Firebase ' + w.status };

  // Ștergem copiile mai vechi decât ARHIVA_ZILE, ca să nu creștem la nesfârșit.
  let sterse = 0;
  try {
    const index = await getJSON(urlBroadcast(env, 'arhiva.json?shallow=true'));
    const date = Object.keys(index || {}).filter(d => /^\d{4}-\d{2}-\d{2}$/.test(d)).sort();
    for (const d of date.slice(0, Math.max(0, date.length - ARHIVA_ZILE))) {
      await fetch(urlBroadcast(env, `arhiva/${d}.json`), { method: 'DELETE' }).catch(() => {});
      sterse++;
    }
  } catch (e) {}

  return { azi, numere, zile, sterse };
}

async function ruleaza(env) {
  const pornit = Date.now();
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

  let numere = Object.keys(toti);
  const blocati = await citesteBlocati(env);
  const nrBlocati = numere.filter(n => blocati[n]);
  if (nrBlocati.length) {
    numere = numere.filter(n => !blocati[n]);
    log(`${nrBlocati.length} blocat(i), sărit(i): ${nrBlocati.join(', ')}`);
  }
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

  // Copia zilnică, înainte de restul: dacă ceva se strică mai încolo, măcar
  // programele oamenilor sunt puse deoparte.
  try {
    const arh = await facArhiva(env);
    if (arh.sarit) log('Arhivă: deja făcută azi');
    else if (arh.eroare) log('Arhivă: eroare — ' + arh.eroare);
    else log(`Arhivă ${arh.azi}: ${arh.numere} colegi · ${arh.zile} zile` + (arh.sterse ? ` · ${arh.sterse} copii vechi șterse` : ''));
  } catch (e) { log('Arhivă: eroare — ' + e.message); }

  const anunt = await trimiteAnunturi(env, toti, numere, vapid);
  if (anunt.eroare) log('Anunțuri: eroare — ' + anunt.eroare);
  else {
    log(`Anunțuri: ${anunt.trimise} trimise · ${anunt.telefoane || 0} telefoane · ${anunt.expirate || 0} expirate · ${anunt.faraTelefon || 0} fără abonament`);
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

  await _repAmintireAutomata(env, log);   // [1.0]
  await _curataTrimiteri(env, log);       // [1.2]
  await _sterge6Luni(env, log);           // [1.6]

  log('');
  log(`Rulare terminată în ${Date.now() - pornit} ms.`);
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

    // ── Revendicarea numărului de serviciu ──
    // Backupul programului, prin worker.
    // Până acum telefonul scria direct în Firebase, iar regulile lăsau pe
    // oricine să citească sau să șteargă backupul altuia dacă îi știa numărul
    // de serviciu — fereastra „număr deja folosit" era doar în aplicație și se
    // ocolea complet. Acum trece pe aici, iar worker-ul cere ca telefonul să
    // fie unul dintre cele înregistrate pe numărul ăla.
    // Trimite o notificare de probă chiar acum, către telefonul unui coleg.
    // Fără asta, când cineva zice „nu-mi vin notificările" nu ai cum să afli
    // unde se rupe lanțul: la abonament, la worker sau la setările telefonului.
    if (url.pathname === '/testpush') {
      const r = await testPush(request, env);
      return new Response(JSON.stringify(r.corp), {
        status: r.status,
        headers: { 'Content-Type': 'application/json; charset=utf-8', ...cors }
      });
    }

    if (url.pathname === '/backup') {
      const r = await backup(request, env);
      return new Response(JSON.stringify(r.corp), {
        status: r.status,
        headers: { 'Content-Type': 'application/json; charset=utf-8', ...cors }
      });
    }

    // [v18.1] Notificările de chat plecau doar la rularea de cinci minute, deci
    // ajungeau cu întârziere sau păreau că nu mai vin deloc. Aplicația cheamă
    // acum ruta asta imediat ce cineva trimite un mesaj. Nu poate fi folosită
    // pentru spam: trimite doar dacă există mesaje mai noi decât ultima citire
    // a fiecăruia, iar între două rulări trebuie să treacă 15 secunde.
    if (url.pathname === '/chatping') {
      const raspuns = (corp, status = 200) => new Response(JSON.stringify(corp), {
        status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...cors }
      });
      if (!env.VAPID_PUBLIC || !env.VAPID_PRIVATE) return raspuns({ ok: false, eroare: 'VAPID neconfigurat' }, 500);
      try {
        const acum = Date.now();
        const ultim = Number(await getJSON(urlBroadcast(env, 'chat/ultimPing.json')).catch(() => 0)) || 0;
        if (acum - ultim < 15000) return raspuns({ ok: true, sarit: true });
        await fetch(urlBroadcast(env, 'chat/ultimPing.json'), {
          method: 'PUT', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(acum)
        }).catch(() => {});

        const toti = await getJSON(urlBroadcast(env, 'push.json'));
        if (!toti) return raspuns({ ok: true, trimise: 0 });
        const vapid = {
          subject: 'mailto:programstb@example.com',
          publicKey: env.VAPID_PUBLIC,
          privateKey: env.VAPID_PRIVATE
        };
        const r = await trimiteChat(env, toti, Object.keys(toti), vapid);
        return raspuns({ ok: true, trimise: r.chatTrimise || 0 });
      } catch (e) {
        return raspuns({ ok: false, eroare: e.message }, 500);
      }
    }

    if (url.pathname === '/acces') {
      const r = await acces(request, env);
      return new Response(JSON.stringify(r.corp), {
        status: r.status,
        headers: { 'Content-Type': 'application/json; charset=utf-8', ...cors }
      });
    }

    if (url.pathname === '/revendica') {
      const r = await revendica(request, env);
      return new Response(JSON.stringify(r.corp), {
        status: r.status,
        headers: { 'Content-Type': 'application/json; charset=utf-8', ...cors }
      });
    }

    if (url.pathname === '/indicatori') {
      const r = await indicatoriPublic(env);
      return new Response(JSON.stringify(r.corp), {
        status: r.status,
        headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'public, max-age=60', ...cors }
      });
    }

    // [1.0] „Am citit" la un anunț — se numără în /anuntCitit/<id>/<nr>.
    if (url.pathname === '/citit') {
      let corp = { ok: false }, st = 400;
      try {
        const c = await request.json();
        const id = String(c.id || '').replace(/[^A-Za-z0-9_-]/g, '').slice(0, 40);
        const nr = nrCurat(c.nr);
        if (id && nr) {
          await fetch(urlBroadcast(env, `anuntCitit/${id}/${nr}.json`), { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(Date.now()) });
          corp = { ok: true }; st = 200;
        }
      } catch (e) {}
      return new Response(JSON.stringify(corp), { status: st, headers: { 'Content-Type': 'application/json; charset=utf-8', ...cors } });
    }
    // [1.0] Versiunea minimă cerută (actualizare forțată).
    if (url.pathname === '/versiune') {
      let min = null;
      try { min = await getJSON(urlBroadcast(env, 'config/versiuneMinima.json')); } catch (e) {}
      return new Response(JSON.stringify({ ok: true, min: min || null }), {
        headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'public, max-age=60', ...cors } });
    }

    // [1.2] Banda de avertizare (o citește oricine), ore greșite, foi trimise.
    if (url.pathname === '/banda') {
      let b = null;
      try { b = await getJSON(urlBroadcast(env, 'config/banda.json')); } catch (e) {}
      return new Response(JSON.stringify({ ok: true, banda: b || null }), {
        headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'public, max-age=60', ...cors } });
    }
    if (url.pathname === '/eroare' || url.pathname === '/mesaj-admin' || url.pathname === '/datele-mele') {
      let r;
      try { r = url.pathname === '/eroare' ? await raportEroare(request, env) : url.pathname === '/mesaj-admin' ? await mesajAdmin(request, env) : await dateleMele(request, env); }
      catch (e) { r = { status: 500, corp: { ok: false, eroare: e.message } }; }
      return new Response(JSON.stringify(r.corp), { status: r.status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...cors } });
    }
    if (url.pathname === '/blocat-disp') {                 // [2.9]
      let r;
      try { r = await blocatDisp(request, env); }
      catch (e) { r = { status: 500, corp: { ok: false, eroare: e.message } }; }
      return new Response(JSON.stringify(r.corp), { status: r.status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...cors } });
    }
    if (url.pathname === '/cerere-admin' || url.pathname === '/cerere-stare') {
      let r;
      try { r = url.pathname === '/cerere-admin' ? await cerereAdmin(request, env) : await cerereStare(request, env); }
      catch (e) { r = { status: 500, corp: { ok: false, eroare: e.message } }; }
      return new Response(JSON.stringify(r.corp), { status: r.status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...cors } });
    }
    if (url.pathname === '/trimite-fisier' || url.pathname === '/trimite-gata') {
      let r;
      try { r = url.pathname === '/trimite-fisier' ? await trimiteFisier(request, env) : await trimiteGata(request, env); }
      catch (e) { r = { status: 500, corp: { ok: false, eroare: e.message } }; }
      return new Response(JSON.stringify(r.corp), { status: r.status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...cors } });
    }
    if (url.pathname === '/raport-ore' || url.pathname === '/trimite') {
      let r;
      try { r = url.pathname === '/trimite' ? await trimiteFoaie(request, env) : await raportOre(request, env); }
      catch (e) { r = { status: 500, corp: { ok: false, eroare: e.message } }; }
      return new Response(JSON.stringify(r.corp), { status: r.status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...cors } });
    }

    if (url.pathname === '/numar-nou') {
      const r = await numarNou(request, env);
      return new Response(JSON.stringify(r.corp), {
        status: r.status,
        headers: { 'Content-Type': 'application/json; charset=utf-8', ...cors }
      });
    }

    if (url.pathname === '/admin') {
      const r = await admin(request, env);
      return new Response(JSON.stringify(r.corp), {
        status: r.status,
        headers: { 'Content-Type': 'application/json; charset=utf-8', ...cors }
      });
    }

    // [SECURITATE v4.5] Oricine deschidea adresa workerului pornea o rulare
    // completă și vedea raportul — inclusiv numerele colegilor blocați. Deschisă
    // de multe ori la rând, putea consuma și cota gratuită Firebase. Rularea
    // manuală cere acum parola de admin: .../?cheie=PAROLA
    const cheie = url.searchParams.get('cheie') || '';
    if (!env.ADMIN_PASS || !paroleEgale(cheie, String(env.ADMIN_PASS))) {
      if (cheie) await new Promise(r => setTimeout(r, 600));
      return new Response('Program STB · worker activ.\nRularea manuală: adaugă ?cheie=<parola de admin> la adresă.',
        { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
    }
    const raport = await ruleaza(env);
    return new Response(raport, { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' } });
  }
};

// ══════════════════════════════════════════════════════════════
// REVENDICAREA NUMĂRULUI DE SERVICIU
//
// Un număr de serviciu aparține primului telefon care îl folosește. Altcineva
// care îl tastează nu mai poate nici să vadă, nici să suprascrie backupul
// colegului. Perechea număr–telefon stă în /proprietar/<nr>, nod închis și la
// citire (altfel s-ar putea copia identificatorul altui telefon).
//
// Când cineva își schimbă telefonul, adminul șterge perechea din panou și
// următorul telefon revendică numărul.
// ══════════════════════════════════════════════════════════════
// Un număr poate avea mai multe dispozitive (telefon + tabletă). Câte, spune
// `locuri`; adminul mărește numărul dintr-un buton. Formatul vechi — un singur
// { dev, la } — e citit în continuare și convertit din mers.
function _normalizeaza(actual) {
  if (!actual) return { locuri: 1, disp: {} };
  if (actual.dev) return { locuri: 1, disp: { [actual.dev]: { la: actual.la || Date.now() } } };
  return {
    locuri: Math.max(1, Number(actual.locuri) || 1),
    disp: (actual.disp && typeof actual.disp === 'object') ? actual.disp : {}
  };
}

// Telefonul are voie la backupul numărului doar dacă e înregistrat pe el.
async function _telefonulAreVoie(env, nr, dev) {
  try {
    const brut = await getJSON(urlBroadcast(env, `proprietar/${nr}.json`));
    const { disp } = _normalizeaza(brut);
    // Număr nefolosit încă de nimeni: primul telefon care ajunge aici îl ia,
    // exact ca la revendicare. Altfel un coleg nou n-ar putea salva nimic.
    if (!disp || Object.keys(disp).length === 0) return true;
    return !!disp[dev];
  } catch (e) {
    return false;   // nu putem verifica → nu dăm acces
  }
}

async function testPush(request, env) {
  if (request.method !== 'POST') return { status: 405, corp: { ok: false, eroare: 'Doar POST' } };
  let c;
  try { c = await request.json(); } catch (e) { return { status: 400, corp: { ok: false, eroare: 'JSON invalid' } }; }

  // [SECURITATE v14.4] Ruta asta n-avea NICIO verificare: oricine îi știa
  // adresa putea trimite o notificare, cu ce text voia, pe telefonul oricărui
  // coleg al cărui număr de serviciu îl ghicea — iar numerele au patru-cinci
  // cifre. Nu e o rută publică, e o unealtă de diagnostic din panou, deci
  // cere parola sau jetonul, ca restul panoului.
  if (!env.ADMIN_PASS || !paroleEgale(String(c.parola || ''), String(env.ADMIN_PASS))) {
    let stareTP = c.jeton ? await jetonValid(env, String(c.jeton)) : 'nu';
    if (stareTP !== 'da' && codAdm2Curat(c.parola)) {
      const a = await _adm2DinCod(env, codAdm2Curat(c.parola));
      stareTP = a === 'necunoscut' ? 'necunoscut' : (a ? 'da' : stareTP);
    }
    if (stareTP === 'necunoscut') {
      return { status: 503, corp: { ok: false,
        eroare: 'Nu am putut verifica jetonul' + (_motivJeton ? ': ' + _motivJeton : '.') } };
    }
    if (stareTP !== 'da') {
      await new Promise(r => setTimeout(r, 400));
      return { status: 401, corp: { ok: false, jetonAnulat: !!c.jeton, eroare: 'Nepermis' } };
    }
  }

  const nr = nrCurat(c.nr);
  if (!nr) return { status: 400, corp: { ok: false, eroare: 'Lipsește numărul' } };

  if (!env.VAPID_PUBLIC || !env.VAPID_PRIVATE) {
    return { status: 500, corp: { ok: false, eroare: 'VAPID neconfigurat în Cloudflare' } };
  }
  const vapid = {
    subject: 'mailto:programstb@example.com',
    publicKey: env.VAPID_PUBLIC,
    privateKey: env.VAPID_PRIVATE
  };

  let u;
  try { u = await getJSON(urlBroadcast(env, `push/${nr}.json`)); }
  catch (e) { return { status: 502, corp: { ok: false, eroare: 'Nu am putut citi abonamentul' } }; }

  if (!u) return { status: 404, corp: { ok: false, eroare: 'Numărul ăsta nu are nimic în cloud. Pornește notificările din aplicație.' } };
  const cateTelefoane = abonamentele(u).length;
  if (!cateTelefoane) return { status: 404, corp: { ok: false, eroare: 'Nu există abonament de notificări. Oprește și pornește notificările din aplicație.' } };

  const cateTure = Array.isArray(u.ture) ? u.ture.length : 0;
  // Titlul și mesajul pot veni din panou. Goale → textul de probă obișnuit.
  const titlu = String(c.titlu || '').trim().slice(0, 60);
  const mesaj = String(c.mesaj || '').trim().slice(0, 300);
  const payload = JSON.stringify({
    title: titlu || '✅ Notificare de probă',
    body: mesaj || `Merge. În cloud sunt ${cateTure} ture pe următoarele 10 zile.`,
    tag: 'test-' + Date.now(),
    url: './'
  });

  let r;
  try {
    r = await trimiteToate(env, nr, u, payload, { TTL: 600, urgency: 'high' }, vapid);
  } catch (e) {
    return { status: 502, corp: { ok: false, eroare: 'Trimiterea a eșuat: ' + (e.message || e) } };
  }
  if (!r.trimise) {
    return { status: 410, corp: { ok: false, eroare: 'Toate abonamentele erau expirate — le-am șters. Oprește și pornește notificările din aplicație.' } };
  }

  return {
    status: 200,
    corp: {
      ok: true, nr, ture: cateTure,
      telefoane: r.trimise,
      expirate: r.moarte,
      ultimaSincronizare: u.updat || null,
      zile: Array.isArray(u.zile) ? u.zile.length : 0
    }
  };
}

// ══════════════════════════════════════════════════════════════
// [W-copii] COPII DE SIGURANȚĂ ZILNICE
// Regula Firebase: "backupIstoric": { ".read": false, ".write": false }
// (doar workerul, cu FB_SECRET).
// ══════════════════════════════════════════════════════════════
const ZILE_COPII = 7;

async function _copieZilnica(env, nr, backupVechi) {
  const azi = acumRo().data;
  const caleZi = urlBroadcast(env, `backupIstoric/${nr}/${azi}/ts.json`);
  const r = await fetch(caleZi, { headers: { 'Cache-Control': 'no-cache' } });
  if (r.ok) {
    const exista = await r.json().catch(() => null);
    if (exista) return false;                  // azi avem deja copia
  }
  await fetch(urlBroadcast(env, `backupIstoric/${nr}/${azi}.json`), {
    method: 'PUT', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(Object.assign({}, backupVechi, { copiatLa: Date.now() }))
  });
  // Curățăm copiile mai vechi de 7 zile.
  try {
    const u0 = urlBroadcast(env, `backupIstoric/${nr}.json`);
    const lista = await getJSON(u0 + (u0.includes('?') ? '&' : '?') + 'shallow=true');
    const zile = Object.keys(lista || {}).sort();
    const deSters = zile.slice(0, Math.max(0, zile.length - ZILE_COPII));
    await Promise.all(deSters.map(z =>
      fetch(urlBroadcast(env, `backupIstoric/${nr}/${z}.json`), { method: 'DELETE' })));
  } catch (e) {}
  return true;
}

async function backup(request, env) {
  if (request.method !== 'POST') return { status: 405, corp: { ok: false, eroare: 'Doar POST' } };

  let c;
  try { c = await request.json(); } catch (e) { return { status: 400, corp: { ok: false, eroare: 'JSON invalid' } }; }

  const nr  = nrCurat(c.nr);
  const dev = String(c.dev || '').replace(/[^a-zA-Z0-9-]/g, '').slice(0, 64);
  if (!nr || !dev) return { status: 400, corp: { ok: false, eroare: 'Lipsește numărul sau telefonul' } };

  // ── [v14.4] Citiri care NU cer să fii proprietarul numărului ──────────
  // Odată ce regula Firebase pentru `backup` devine „nici citire, nici
  // scriere", aplicația nu mai poate lua nimic direct. Dar două lucruri
  // trebuie să rămână posibile pentru oricine:
  //   `citesteColeg` — programul unui coleg, exact ce face „Vreau programul
  //                    unui coleg". A fost dintotdeauna deschis; nu ascundem
  //                    aici ceva ce înainte se vedea.
  //   `ts`           — doar momentul ultimei salvări, ca omul să vadă că
  //                    programul lui chiar e în cloud. Câțiva octeți.
  // Ce se închide e SCRIEREA peste backupul altuia — aia trece în continuare
  // prin verificarea de mai jos.
  //
  // ATENȚIE la `fetch`: în Cloudflare Workers opțiunea `cache: 'no-store'` NU
  // e implementată și aruncă „The 'cache' field on 'RequestInitializerDict'
  // is not implemented". Era pusă în cinci locuri în worker, copiată din codul
  // de browser — deci și acțiunea `citeste` era stricată de mult, doar că
  // aplicația cădea tăcut pe citirea directă din Firebase și nu s-a văzut.
  // Prospețimea se cere prin antet, care merge.
  if (c.actiune === 'citesteColeg') {
    // [v14.5] Aici se aplică permisiunea. Un singur loc de trecut, fiindcă
    // nodul `backup` e închis în regulile Firebase și nimeni nu-l mai poate
    // citi pe lângă worker.
    const voie = await _areVoieLaProgram(env, nr, c);
    if (!voie.ok) {
      await new Promise(r => setTimeout(r, 250));
      const mesaje = {
        asteapta: 'Ai cerut deja. Aștepți răspunsul lui.',
        refuzat:  'Nu ți-a dat voie la programul lui.',
        fara:     'N-ai voie la programul lui. Trimite-i o cerere.',
        necunoscut: 'Nu te pot identifica.'
      };
      return { status: 403, corp: { ok: false, stare: voie.motiv,
        eroare: mesaje[voie.motiv] || 'N-ai voie la programul lui.' } };
    }
    try {
      const u = urlBroadcast(env, `backup/${nr}.json`);
      const r = await fetch(u, { headers: { 'Cache-Control': 'no-cache' } });
      if (!r.ok) {
        const t = await r.text().catch(() => '');
        return { status: 502, corp: { ok: false,
          eroare: `Firebase a răspuns ${r.status} la citirea backupului ${t.slice(0, 120)}` } };
      }
      const d = await r.json();
      return { status: 200, corp: { ok: true, backup: d, acum: Date.now() } };
    } catch (e) {
      return { status: 502, corp: { ok: false,
        eroare: 'Nu am putut citi backupul: ' + (e && e.message ? e.message : e) } };
    }
  }

  if (c.actiune === 'ts') {
    try {
      const r = await fetch(urlBroadcast(env, `backup/${nr}/ts.json`), { headers: { 'Cache-Control': 'no-cache' } });
      if (!r.ok) {
        return { status: 502, corp: { ok: false, eroare: `Firebase a răspuns ${r.status} la citirea datei` } };
      }
      const d = await r.json();
      // [v17.8] Trimitem și câte zile are backupul din cloud. Aplicația compară
      // înainte să scrie: un telefon aproape gol nu mai are voie să acopere un
      // program de sute de zile. Așa s-au pierdut programele a doi colegi.
      let zile = null;
      try {
        const rz = await fetch(urlBroadcast(env, `backup/${nr}/zile.json`), { headers: { 'Cache-Control': 'no-cache' } });
        if (rz.ok) zile = await rz.json();
      } catch (e) {}
      return { status: 200, corp: { ok: true, ts: d, zile, acum: Date.now() } };
    } catch (e) {
      return { status: 502, corp: { ok: false,
        eroare: 'Nu am putut citi data salvării: ' + (e && e.message ? e.message : e) } };
    }
  }

  if (!(await _telefonulAreVoie(env, nr, dev))) {
    await new Promise(r => setTimeout(r, 300));
    return { status: 403, corp: { ok: false, eroare: 'Telefonul ăsta nu e înregistrat pe numărul ' + nr } };
  }
  // [2.7] Citirea întregului backup și ștergerea lui cer telefon chiar înregistrat
  // pe număr. Înainte, un număr fără niciun telefon (după „Resetează telefonul”
  // din panou) putea fi citit sau șters de oricine îi știa numărul.
  if ((c.actiune === 'citeste' || c.actiune === 'sterge') && !(await _dispInregistrat(env, nr, dev))) {
    await new Promise(r => setTimeout(r, 300));
    return { status: 403, corp: { ok: false, eroare: 'Telefonul ăsta nu e înregistrat pe numărul ' + nr } };
  }

  const cale = urlBroadcast(env, `backup/${nr}.json`);

  if (c.actiune === 'citeste') {
    try {
      const r = await fetch(cale, { headers: { 'Cache-Control': 'no-cache' } });
      const d = r.ok ? await r.json() : null;
      return { status: 200, corp: { ok: true, backup: d, acum: Date.now() } };
    } catch (e) {
      return { status: 502, corp: { ok: false, eroare: 'Nu am putut citi backupul' } };
    }
  }

  if (c.actiune === 'scrie') {
    if (!c.backup || typeof c.backup !== 'object') {
      return { status: 400, corp: { ok: false, eroare: 'Lipsesc datele' } };
    }

    // [v18.0] ÎMBINARE, NU ÎNLOCUIRE.
    // Până acum, salvarea punea peste tot ce era în cloud exact ce avea
    // telefonul. Un telefon nou, cu două zile completate, ștergea două luni de
    // program. S-a întâmplat de două ori și nu se mai putea recupera.
    // Acum zilele se adună: ce trimite telefonul are întâietate pentru zilele
    // lui, dar zilele care există doar în cloud rămân acolo.
    // Urmarea de care trebuie să știi: o zi ștearsă intenționat de pe telefon
    // nu mai dispare din cloud — se poate doar schimba. Am ales asta pentru că
    // ștergerea din greșeală costă mult mai mult decât o zi rămasă în plus.
    let deScris = c.backup;
    const acumMs = Date.now();
    let vechiBackup = null;
    // [FIX v4.5] PIERDERE DE DATE. Dacă citirea backupului existent eșua (o
    // sughițare a Firebase), `catch`-ul de mai jos lăsa scrierea să plece
    // fără îmbinare — adică exact înlocuirea pe care îmbinarea trebuia s-o
    // împiedice: un telefon cu două zile putea acoperi luni întregi. Acum,
    // fără citire reușită nu scriem nimic; aplicația reîncearcă singură.
    let vechiCitit;
    try { vechiCitit = await getJSON(cale); }
    catch (e) {
      return { status: 503, corp: { ok: false, eroare: 'Nu am putut citi backupul existent. Reîncerc mai târziu.' } };
    }
    // [2.7] Un pachet fără `data` ar fi înlocuit tot backupul.
    if (vechiCitit && vechiCitit.data && (!c.backup.data || typeof c.backup.data !== 'object')) {
      return { status: 400, corp: { ok: false, eroare: 'Salvare fără program — refuzată ca să nu șteargă ce e în cloud.' } };
    }
    // [2.7] Pachet uriaș = ceva nu e în regulă (și ar umple baza).
    if (JSON.stringify(c.backup).length > 3000000) return { status: 413, corp: { ok: false, eroare: 'Backup prea mare.' } };
    try {
      const vechi = vechiCitit;
      vechiBackup = vechi;
      if (vechi && vechi.data && c.backup.data) {
        const dataNoua = Object.assign({}, vechi.data, c.backup.data);
        let pastrate = 0;
        // [2.7] Telefonul a trimis pentru un depou ceva ce nu e program (null, gol,
        // text stricat), dar în cloud e un program bun: îl păstrăm pe cel din cloud.
        const _deScosAcum = Array.isArray(c.backup.stergeChei) ? c.backup.stergeChei : [];
        for (const k of Object.keys(c.backup.data)) {
          if (!k.startsWith('p2026_') || _deScosAcum.includes(k)) continue;
          const nouOk = _bkZile(c.backup.data[k]), vechiOk = _bkZile(vechi.data[k]);
          if (!nouOk && vechiOk) { dataNoua[k] = vechi.data[k]; pastrate++; }
        }

        for (const k of Object.keys(vechi.data)) {
          if (!k.startsWith('p2026_')) continue;
          const aVechi = vechi.data[k], aNou = c.backup.data[k];
          if (typeof aVechi !== 'string' || !aVechi.startsWith('{')) continue;
          if (typeof aNou !== 'string' || !aNou.startsWith('{')) continue;
          try {
            const zileVechi = JSON.parse(aVechi);
            const zileNoi   = JSON.parse(aNou);
            const cand = z => (z && typeof z === 'object' && Number(z._m)) || 0;
            // [W-ceas] Un telefon cu ceasul dat înainte ar câștiga mereu la
            // îmbinare, iar zilele lui n-ar mai putea fi schimbate de nimeni.
            // Nicio zi nu poate fi modificată „în viitor": o aducem la ora serverului.
            for (const zi of Object.keys(zileNoi)) {
              const z = zileNoi[zi];
              if (z && typeof z === 'object' && Number(z._m) > acumMs + 10 * 60 * 1000) z._m = acumMs;
            }

            for (const zi of Object.keys(zileVechi)) {
              if (!(zi in zileNoi)) {
                // Ziua există doar în cloud: rămâne. Așa nu se mai pierd luni
                // întregi când intră un telefon nou, aproape gol.
                zileNoi[zi] = zileVechi[zi];
                pastrate++;
                continue;
              }
              // [v18.2] Ziua există în amândouă. Câștigă cea modificată mai
              // recent, nu automat cea de pe telefon: un telefon rămas în urmă
              // trimitea versiunea veche și o punea peste cea bună, iar omul
              // își găsea ziua schimbată înapoi cum fusese.
              if (cand(zileVechi[zi]) > cand(zileNoi[zi])) {
                zileNoi[zi] = zileVechi[zi];
                pastrate++;
              }
            }
            dataNoua[k] = JSON.stringify(zileNoi);
          } catch (e) { /* text stricat: lăsăm ce a trimis telefonul */ }
        }

        // Numărăm zilele din rezultat, ca `zile` să rămână adevărat.
        let zile = 0;
        for (const v of Object.values(dataNoua)) {
          if (typeof v !== 'string' || !v.startsWith('{')) continue;
          try { zile += Object.keys(JSON.parse(v)).length; } catch (e) {}
        }

        // [W-separare] Programele colegilor urmăriți ajunseseră, din greșeală,
        // în backupul celui care urmărea. Aplicația cere acum explicit scoaterea
        // lor. Doar chei de depou, nimic altceva.
        const deScos = Array.isArray(c.backup.stergeChei) ? c.backup.stergeChei : [];
        for (const k of deScos) {
          if (typeof k === 'string' && DEPOURI.some(d => k === 'p2026_' + d)) delete dataNoua[k];
        }
        zile = 0;
        for (const v of Object.values(dataNoua)) {
          if (typeof v !== 'string' || !v.startsWith('{')) continue;
          try { zile += Object.keys(JSON.parse(v)).length; } catch (e) {}
        }

        deScris = Object.assign({}, c.backup, { data: dataNoua, zile });
        delete deScris.stergeChei;
        if (Array.isArray(deScris.depots)) deScris.depots = deScris.depots.filter(d => dataNoua['p2026_' + d]);
        if (pastrate) deScris.pastrateDinCloud = pastrate;
      }
    } catch (e) { /* dacă nu putem citi ce era, scriem ca înainte */ }
    if (deScris && deScris.stergeChei) delete deScris.stergeChei;

    // [2.5] Depourile șterse de admin nu se mai întorc în cloud.
    let sterse = vechiBackup && vechiBackup.sterse && typeof vechiBackup.sterse === 'object' ? vechiBackup.sterse : null;
    if (sterse) { sterse = Object.fromEntries(Object.entries(sterse).filter(([, ts]) => Date.now() - Number(ts) <= 60 * 864e5)); if (!Object.keys(sterse).length) sterse = null; }
    if (deScris && deScris.sterse) { deScris = Object.assign({}, deScris); delete deScris.sterse; }
    if (sterse && deScris && deScris.data) {
      deScris = Object.assign({}, deScris, { data: Object.assign({}, deScris.data) });
      if (_bkAplicaSterse(deScris.data, sterse)) _bkRecalc(deScris);
      deScris.sterse = sterse;
    }

    // [W-copii] O copie pe zi a backupului, înainte de prima scriere a zilei.
    // Se păstrează ultimele 7 zile, în /backupIstoric/<nr>/<AAAA-LL-ZZ>.
    // Dacă programul cuiva se strică, adminul îl readuce la ziua de ieri.
    if (vechiBackup && vechiBackup.data) {
      try { await _copieZilnica(env, nr, vechiBackup); } catch (e) {}
    }

    const r = await fetch(cale, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(deScris)
    });
    if (!r.ok) {
      const d = await r.text().catch(() => '');
      return { status: 502, corp: { ok: false, eroare: `Firebase ${r.status} ${d.slice(0, 120)}` } };
    }
    return { status: 200, corp: { ok: true,
      zile: deScris.zile, pastrate: deScris.pastrateDinCloud || 0, acum: Date.now(),
      ...(sterse ? { curata: sterse } : {}) } };
  }

  if (c.actiune === 'sterge') {
    const r = await fetch(cale, { method: 'DELETE' });
    if (!r.ok) return { status: 502, corp: { ok: false, eroare: 'Nu am putut șterge' } };
    return { status: 200, corp: { ok: true } };
  }

  return { status: 400, corp: { ok: false, eroare: 'Acțiune necunoscută: ' + c.actiune } };
}

// ══════════════════════════════════════════════════════════════
// [v14.5] PERMISIUNEA DE A VEDEA PROGRAMUL CUIVA
//
// Până acum, oricine îți știa numărul de serviciu îți vedea programul complet:
// unde ești, la ce oră, în fiecare zi. Numerele au patru-cinci cifre și sunt
// scrise în agenda din aplicație, deci nu erau un secret. Acum programul se dă,
// nu se ia: cine vrea trimite o cerere, tu primești o notificare și răspunzi.
//
// Cine cere e identificat de worker, nu crezut pe cuvânt:
//   - dacă telefonul lui e înregistrat pe un număr de serviciu, cheia e numărul
//   - dacă nu (soția care vrea programul soțului), cheia e id-ul telefonului,
//     iar tu vezi „un telefon fără număr de serviciu"
// Numele scris în cerere e doar un text pe care îl trimite el: ajută să
// recunoști omul, dar nu dovedește nimic. Ecranul spune asta limpede.
//
// Datele stau în /acces/<numărul tău>/<cheia celui care cere>:
//   { cine, tip, nume, stare: 'asteapta' | 'da' | 'nu', creat, raspuns }
// Nodul se scrie DOAR de aici, cu cheia de serviciu. Regula Firebase trebuie
// să fie „.read": false, „.write": false.
// ══════════════════════════════════════════════════════════════

const ACCES_CERERI_PE_ZI = 5;          // câte cereri poate trimite un telefon în 24h
const ACCES_REFUZURI_PERMISE = 3;      // după al câtelea refuz se oprește
const ACCES_PAUZA_DUPA_NU = 24 * 3600 * 1000;   // și cât timp nu mai poate cere

function _accesCheie(s) {
  // Cheile Firebase nu suportă . $ # [ ] /
  return String(s || '').replace(/[.$#[\]/\s]/g, '_').slice(0, 64);
}

// Cine e cel care cere? Întoarce {cheie, tip, cine} — verificat, nu declarat.
async function _accesSolicitant(env, c) {
  const dev = String(c.dev || '').replace(/[^a-zA-Z0-9-]/g, '').slice(0, 64);
  if (!dev) return null;
  const nrPropriu = nrCurat(c.nrPropriu);
  if (nrPropriu && await _telefonulAreVoie(env, nrPropriu, dev)) {
    return { cheie: _accesCheie(nrPropriu), tip: 'nr', cine: nrPropriu, dev };
  }
  // Fără număr dovedit, rămâne telefonul. Tot o identitate: stabilă, dar anonimă.
  return { cheie: _accesCheie('tel_' + dev), tip: 'dev', cine: dev, dev };
}

// [2.7] Cheia unei cereri de la un telefon fără număr conține identificatorul
// telefonului (tel_<dev>) — adică exact ce dovedește „eu sunt telefonul ăsta”.
// Omul căruia i se cere programul o primea în listă. Acum vede un alias.
async function _accesAlias(cheie) { return cheie.startsWith('tel_') ? 'h_' + (await hashJeton('acc:' + cheie)).slice(0, 24) : cheie; }
async function _accesDinAlias(env, nr, cheie) {
  if (!cheie.startsWith('h_')) return cheie;
  let d = null; try { d = await getJSON(urlBroadcast(env, `acces/${nr}.json`)); } catch (e) {}
  for (const k of Object.keys(d || {})) if (await _accesAlias(k) === cheie) return k;
  return null;
}
async function _accesStare(env, nrTinta, cheie) {
  try {
    const r = await fetch(urlBroadcast(env, `acces/${nrTinta}/${cheie}.json`),
      { headers: { 'Cache-Control': 'no-cache' } });
    if (!r.ok) return null;
    return await r.json();
  } catch (e) { return null; }
}

// Are voie să citească programul lui `nrTinta`? Proprietarul, mereu.
async function _areVoieLaProgram(env, nrTinta, c) {
  const dev = String(c.dev || '').replace(/[^a-zA-Z0-9-]/g, '').slice(0, 64);
  if (dev && await _telefonulAreVoie(env, nrTinta, dev)) return { ok: true, motiv: 'proprietar' };
  const s = await _accesSolicitant(env, c);
  if (!s) return { ok: false, motiv: 'necunoscut' };
  let inreg = await _accesStare(env, nrTinta, s.cheie);
  // [FIX v15.2] Permisiunea poate fi înregistrată sub cealaltă cheie: omul a
  // cerut înainte să-și pună numărul (sau invers). Ne uităm și acolo, altfel
  // un „da" primit ieri nu mai e găsit azi.
  if (!inreg || inreg.stare !== 'da') {
    const alta = s.tip === 'nr' ? _accesCheie('tel_' + s.dev) : null;
    if (alta) {
      const b2 = await _accesStare(env, nrTinta, alta);
      if (b2 && b2.stare === 'da') inreg = b2;
    }
  }
  if (inreg && inreg.stare === 'da') return { ok: true, motiv: 'permis' };
  if (inreg && inreg.stare === 'asteapta') return { ok: false, motiv: 'asteapta' };
  if (inreg && inreg.stare === 'nu') return { ok: false, motiv: 'refuzat' };
  return { ok: false, motiv: 'fara' };
}

async function acces(request, env) {
  if (request.method !== 'POST') return { status: 405, corp: { ok: false, eroare: 'Doar POST' } };

  let c;
  try { c = await request.json(); } catch (e) { return { status: 400, corp: { ok: false, eroare: 'JSON invalid' } }; }

  const dev = String(c.dev || '').replace(/[^a-zA-Z0-9-]/g, '').slice(0, 64);
  if (!dev) return { status: 400, corp: { ok: false, eroare: 'Lipsește telefonul' } };

  // ── Cer acces la programul cuiva ──────────────────────────────────
  if (c.actiune === 'cere') {
    const tinta = nrCurat(c.nr);
    if (!tinta) return { status: 400, corp: { ok: false, eroare: 'Lipsește numărul' } };
    if (!(await _limitaZi(env, 'acces-ip', _ipCheie(request), 30))) return { status: 429, corp: { ok: false, eroare: 'Prea multe cereri azi. Mai încearcă mâine.' } };

    const s = await _accesSolicitant(env, c);
    if (!s) return { status: 400, corp: { ok: false, eroare: 'Nu te pot identifica' } };
    if (s.tip === 'nr' && String(s.cine) === String(tinta)) {
      return { status: 400, corp: { ok: false, eroare: 'Ăsta e numărul tău.' } };
    }

    const acum = Date.now();
    const vechi = await _accesStare(env, tinta, s.cheie);
    if (vechi && vechi.stare === 'da') {
      return { status: 200, corp: { ok: true, stare: 'da' } };   // deja are voie
    }
    if (vechi && vechi.stare === 'asteapta') {
      return { status: 200, corp: { ok: true, stare: 'asteapta', deja: true } };
    }
    // [v15.0] Un „nu" poate fi și o apăsare greșită — butoanele sunt lipite, iar
    // omul se uită la telefon în mers. Așa că lăsăm să se mai ceară de câteva
    // ori. Abia după al treilea refuz cererea devine bătaie la ușă și se oprește
    // 24 de ore: la a treia oară nu mai e greșeală, e răspuns.
    const refuzuri = Number(vechi && vechi.refuzuri || 0);
    if (vechi && vechi.stare === 'nu' && refuzuri >= ACCES_REFUZURI_PERMISE
        && (acum - (vechi.raspuns || 0)) < ACCES_PAUZA_DUPA_NU) {
      return { status: 429, corp: { ok: false, stare: 'nu',
        eroare: `Te-a refuzat de ${refuzuri} ori. Poți cere din nou peste 24 de ore.` } };
    }

    // Limită zilnică, ca nimeni să nu poată cere la tot depoul într-o seară.
    try {
      const toate = await _accesToateAle(env, s.cheie);
      const azi = toate.filter(x => (acum - (x.creat || 0)) < 24 * 3600 * 1000).length;
      if (azi >= ACCES_CERERI_PE_ZI) {
        return { status: 429, corp: { ok: false,
          eroare: `Ai trimis deja ${ACCES_CERERI_PE_ZI} cereri azi. Mai încearcă mâine.` } };
      }
    } catch (e) { /* dacă nu putem număra, nu blocăm omul */ }

    const inreg = {
      cine: s.cine, tip: s.tip, dev: s.dev,
      nume: String(c.nume || '').trim().slice(0, 40),
      mesaj: String(c.mesaj || '').trim().slice(0, 120),
      stare: 'asteapta', creat: acum,
      refuzuri            // câte „nu" a primit până acum de la omul ăsta
    };
    const w = await fetch(urlBroadcast(env, `acces/${tinta}/${s.cheie}.json`), {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(inreg)
    });
    if (!w.ok) return { status: 502, corp: { ok: false, eroare: 'Nu am putut trimite cererea' } };

    // Îl anunțăm pe loc. Fără asta, cererea zace până deschide el aplicația.
    let anuntat = 0;
    try { anuntat = await _accesAnunta(env, tinta, inreg); } catch (e) { }

    return { status: 200, corp: { ok: true, stare: 'asteapta', anuntat } };
  }

  // ── Ce cereri am eu de aprobat ────────────────────────────────────
  if (c.actiune === 'cereri') {
    const nr = nrCurat(c.nr);
    if (!nr) return { status: 400, corp: { ok: false, eroare: 'Lipsește numărul' } };
    if (!(await _telefonulAreVoie(env, nr, dev))) {
      return { status: 403, corp: { ok: false, eroare: 'Telefonul ăsta nu e înregistrat pe numărul ' + nr } };
    }
    try {
      const r = await fetch(urlBroadcast(env, `acces/${nr}.json`), { headers: { 'Cache-Control': 'no-cache' } });
      const d = r.ok ? (await r.json()) : null;
      const lista = [];
      for (const [cheie, v] of Object.entries(d || {})) {
        const x = Object.assign({}, v, { cheie: await _accesAlias(cheie) });
        delete x.dev;
        if (x.tip === 'dev') x.cine = '';
        lista.push(x);
      }
      return { status: 200, corp: { ok: true,
        asteapta: lista.filter(x => x.stare === 'asteapta').sort((a, b) => (b.creat || 0) - (a.creat || 0)),
        permise:  lista.filter(x => x.stare === 'da').sort((a, b) => (b.raspuns || 0) - (a.raspuns || 0)) } };
    } catch (e) {
      return { status: 502, corp: { ok: false, eroare: 'Nu am putut citi cererile' } };
    }
  }

  // ── Răspund: da sau nu ────────────────────────────────────────────
  if (c.actiune === 'raspunde') {
    const nr = nrCurat(c.nr);
    let cheie = _accesCheie(c.cheie);
    const da = c.raspuns === 'da';
    if (!nr || !cheie) return { status: 400, corp: { ok: false, eroare: 'Cerere incompletă' } };
    if (!(await _telefonulAreVoie(env, nr, dev))) {
      return { status: 403, corp: { ok: false, eroare: 'Telefonul ăsta nu e înregistrat pe numărul ' + nr } };
    }
    cheie = await _accesDinAlias(env, nr, cheie);
    if (!cheie) return { status: 404, corp: { ok: false, eroare: 'Cererea nu mai există' } };
    const vechi = await _accesStare(env, nr, cheie);
    if (!vechi) return { status: 404, corp: { ok: false, eroare: 'Cererea nu mai există' } };
    const w = await fetch(urlBroadcast(env, `acces/${nr}/${cheie}.json`), {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(da
        ? { stare: 'da', raspuns: Date.now(), refuzuri: 0 }
        : { stare: 'nu', raspuns: Date.now(), refuzuri: Number(vechi.refuzuri || 0) + 1 })
    });
    if (!w.ok) return { status: 502, corp: { ok: false, eroare: 'Nu am putut salva răspunsul' } };
    let anuntat = 0;
    try { if (vechi.tip === 'nr') anuntat = await _accesAnuntaRaspuns(env, vechi.cine, nr, da); } catch (e) {}
    return { status: 200, corp: { ok: true, stare: da ? 'da' : 'nu', anuntat } };
  }

  // ── Tai accesul cuiva ─────────────────────────────────────────────
  if (c.actiune === 'taie') {
    const nr = nrCurat(c.nr);
    let cheie = _accesCheie(c.cheie);
    if (!nr || !cheie) return { status: 400, corp: { ok: false, eroare: 'Cerere incompletă' } };
    if (!(await _telefonulAreVoie(env, nr, dev))) {
      return { status: 403, corp: { ok: false, eroare: 'Telefonul ăsta nu e înregistrat pe numărul ' + nr } };
    }
    cheie = await _accesDinAlias(env, nr, cheie);
    if (!cheie) return { status: 404, corp: { ok: false, eroare: 'Cererea nu mai există' } };
    const cui = await _accesStare(env, nr, cheie);
    const w = await fetch(urlBroadcast(env, `acces/${nr}/${cheie}.json`), { method: 'DELETE' });
    if (!w.ok) return { status: 502, corp: { ok: false, eroare: 'Nu am putut tăia accesul' } };
    // Îl anunțăm. Altfel află abia când încearcă să deschidă și primește refuz,
    // și crede că s-a stricat aplicația.
    try { if (cui && cui.tip === 'nr') await _accesAnuntaTaiere(env, cui.cine, nr); } catch (e) {}
    return { status: 200, corp: { ok: true } };
  }

  // ── Îmi retrag cererea ────────────────────────────────────────────
  // Am scris greșit numărul, sau m-am răzgândit. Se șterge doar dacă e încă în
  // așteptare: un „da" sau un „nu" deja dat nu se șterge de către cel care a cerut.
  if (c.actiune === 'anuleaza') {
    const tinta = nrCurat(c.nr);
    if (!tinta) return { status: 400, corp: { ok: false, eroare: 'Lipsește numărul' } };
    const s = await _accesSolicitant(env, c);
    if (!s) return { status: 400, corp: { ok: false, eroare: 'Nu te pot identifica' } };
    const vechi = await _accesStare(env, tinta, s.cheie);
    if (!vechi) return { status: 200, corp: { ok: true } };
    if (vechi.stare !== 'asteapta') {
      return { status: 400, corp: { ok: false, eroare: 'Ți-a răspuns deja la cerere.' } };
    }
    await fetch(urlBroadcast(env, `acces/${tinta}/${s.cheie}.json`), { method: 'DELETE' });
    return { status: 200, corp: { ok: true } };
  }

  // ── Unde am eu voie (ce cereri am trimis și cum au fost rezolvate) ─
  if (c.actiune === 'aleMele') {
    const s = await _accesSolicitant(env, c);
    if (!s) return { status: 400, corp: { ok: false, eroare: 'Nu te pot identifica' } };
    try {
      const lista = await _accesToateAle(env, s.cheie);
      return { status: 200, corp: { ok: true, cereri: lista } };
    } catch (e) {
      return { status: 502, corp: { ok: false, eroare: 'Nu am putut citi cererile' } };
    }
  }

  return { status: 400, corp: { ok: false, eroare: 'Acțiune necunoscută: ' + c.actiune } };
}

// Toate cererile trimise de o anumită cheie, către oricine. Firebase n-are
// index invers, deci citim tot nodul `acces` — e mic (o intrare per pereche).
async function _accesToateAle(env, cheie) {
  const r = await fetch(urlBroadcast(env, 'acces.json'), { headers: { 'Cache-Control': 'no-cache' } });
  if (!r.ok) throw new Error('HTTP ' + r.status);
  const tot = await r.json();
  const rez = [];
  for (const [nrTinta, intrari] of Object.entries(tot || {})) {
    if (intrari && intrari[cheie]) rez.push(Object.assign({ nr: nrTinta }, intrari[cheie]));
  }
  return rez.sort((a, b) => (b.creat || 0) - (a.creat || 0));
}

// Notificare către cel căruia i s-a tăiat accesul. Merge doar dacă are număr
// de serviciu — un telefon fără număr n-are unde primi notificări.
async function _accesAnuntaTaiere(env, catreNr, deLaNr) {
  if (!env.VAPID_PUBLIC || !env.VAPID_PRIVATE) return 0;
  const u = await getJSON(urlBroadcast(env, `push/${catreNr}.json`)).catch(() => null);
  if (!u) return 0;
  const payload = JSON.stringify({
    title: 'Acces oprit',
    body: `${deLaNr} nu îți mai partajează programul. Poți să-i ceri din nou.`,
    tag: 'acces-taiat-' + deLaNr,
    url: './'
  });
  const vapid = {
    subject: 'mailto:programstb@example.com',
    publicKey: env.VAPID_PUBLIC,
    privateKey: env.VAPID_PRIVATE
  };
  const r = await trimiteToate(env, catreNr, u, payload, { TTL: 86400, urgency: 'normal' }, vapid);
  return r.trimise || 0;
}

// [v15.5] Notificare către cel care a cerut, când primește răspuns. Fără ea,
// omul cere, pune telefonul în buzunar și nu mai află nimic până redeschide
// aplicația. Merge doar către cei cu număr de serviciu: abonamentul la
// notificări e legat de număr, iar un telefon fără număr n-are unde primi —
// ăla rămâne cu rândul de pe ecran.
async function _accesAnuntaRaspuns(env, catreNr, deLaNr, da) {
  if (!env.VAPID_PUBLIC || !env.VAPID_PRIVATE) return 0;
  const u = await getJSON(urlBroadcast(env, `push/${catreNr}.json`)).catch(() => null);
  if (!u) return 0;
  const payload = JSON.stringify({
    title: da ? '✓ Cerere acceptată' : 'Cerere refuzată',
    body: da
      ? `${deLaNr} ți-a dat voie la programul lui. Deschide aplicația ca să-l iei.`
      : `${deLaNr} nu ți-a dat voie la programul lui.`,
    tag: 'acces-raspuns-' + deLaNr,
    url: './'
  });
  const vapid = {
    subject: 'mailto:programstb@example.com',
    publicKey: env.VAPID_PUBLIC,
    privateKey: env.VAPID_PRIVATE
  };
  const r = await trimiteToate(env, catreNr, u, payload, { TTL: 86400, urgency: 'normal' }, vapid);
  return r.trimise || 0;
}

// Notificare către cel căruia i se cere programul.
async function _accesAnunta(env, nrTinta, inreg) {
  if (!env.VAPID_PUBLIC || !env.VAPID_PRIVATE) return 0;
  const u = await getJSON(urlBroadcast(env, `push/${nrTinta}.json`)).catch(() => null);
  if (!u) return 0;
  const cine = inreg.tip === 'nr' ? ('Nr. ' + inreg.cine) : 'Un telefon fără număr';
  const nume = inreg.nume ? ` (${inreg.nume})` : '';
  const mes  = inreg.mesaj ? ` — „${inreg.mesaj}"` : '';
  const payload = JSON.stringify({
    title: '👀 Cerere de acces la programul tău',
    body: `${cine}${nume} vrea să îți vadă programul${mes}. Deschide aplicația ca să răspunzi.`,
    tag: 'acces-' + inreg.cine,
    url: './'
  });
  // [FIX v15.4] Aici scria 'mailto:admin@programstb' — nu e o adresă validă,
  // n-are domeniu, iar serviciul de push respinge cererea. De asta cererile de
  // acces nu ajungeau ca notificare, deși omul avea notificările pornite.
  // Restul worker-ului folosea de la început adresa de mai jos.
  const vapid = {
    subject: 'mailto:programstb@example.com',
    publicKey: env.VAPID_PUBLIC,
    privateKey: env.VAPID_PRIVATE
  };
  const r = await trimiteToate(env, nrTinta, u, payload, { TTL: 86400, urgency: 'normal' }, vapid);
  return r.trimise || 0;
}

function _adresaCerere(request) {
  try {
    const o = request.headers.get('Origin') || request.headers.get('Referer') || '';
    return o ? new URL(o).host.slice(0, 80) : '';
  } catch (e) { return ''; }
}

async function revendica(request, env) {
  if (request.method !== 'POST') return { status: 405, corp: { ok: false, eroare: 'Doar POST' } };

  let c;
  try { c = await request.json(); } catch (e) { return { status: 400, corp: { ok: false, eroare: 'JSON invalid' } }; }

  const nr  = nrCurat(c.nr);
  const dev = String(c.dev || '').replace(/[^a-zA-Z0-9-]/g, '').slice(0, 64);
  if (!nr || !dev) return { status: 400, corp: { ok: false, eroare: 'Lipsește numărul sau dispozitivul' } };

  let brut = null;
  try {
    brut = await getJSON(urlBroadcast(env, `proprietar/${nr}.json`));
  } catch (e) {
    // Dacă nu putem citi, nu blocăm pe nimeni — altfel o pană de rețea
    // ar lăsa oamenii pe dinafară.
    return { status: 200, corp: { ok: true, stare: 'necunoscut' } };
  }

  const { locuri, disp } = _normalizeaza(brut);
  const acum = Date.now();
  // [v5.1] De pe ce adresă rulează aplicația telefonului. Colegii rămași pe
  // vechea github.io, cu o versiune de dinainte de ecranul de mutare, rulează
  // la nesfârșit copia veche din memoria telefonului — fișa trebuie să arate asta.
  const adresa = _adresaCerere(request);

  // Dispozitiv cunoscut: îl lăsăm să intre. Actualizăm data ultimei intrări
  // cel mult o dată pe zi, ca să nu scriem în bază la fiecare deschidere.
  if (disp[dev]) {
    const ultima = Number(disp[dev].ultima) || 0;
    if (acum - ultima > 24 * 3600 * 1000 || (adresa && disp[dev].adresa !== adresa)) {
      await fetch(urlBroadcast(env, `proprietar/${nr}/disp/${dev}.json`), {
        method: 'PATCH', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(adresa ? { ultima: acum, adresa } : { ultima: acum })
      }).catch(() => {});
    }
    return { status: 200, corp: { ok: true, stare: 'al tau' } };
  }

  // Dispozitiv nou: intră doar dacă mai e loc liber
  const ocupate = Object.keys(disp).length;
  if (ocupate >= locuri && ocupate > 0) {
    let tel = '';
    try { tel = (await getJSON(`${env.FB_URL}/config/contact.json`)) || ''; } catch (e) {}
    return { status: 200, corp: { ok: false, stare: 'ocupat', tel: String(tel || ''), locuri, ocupate } };
  }

  disp[dev] = adresa ? { la: acum, ultima: acum, adresa } : { la: acum, ultima: acum };
  const r = await fetch(urlBroadcast(env, `proprietar/${nr}.json`), {
    method: 'PUT', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ locuri: Math.max(locuri, Object.keys(disp).length), disp })
  });
  if (!r.ok) return { status: 200, corp: { ok: true, stare: 'nesalvat' } };
  return { status: 200, corp: { ok: true, stare: 'revendicat', locuri, ocupate: Object.keys(disp).length } };
}

// ══════════════════════════════════════════════════════════════
// [v11.17] CEREREA DE NUMĂR NOU, DE PE ECRANUL DE BLOCARE
//
// Cel blocat pentru că și-a scris alt număr (0000) cere să treacă pe numărul
// lui real. NU se deblochează singur — altfel oricine, blocat pentru orice,
// putea scăpa luând numărul unui coleg care nu folosește aplicația. Cererea
// stă în /blocati/<vechi>/cerere până o aprobă adminul; atunci telefonul își
// mută singur numărul și anunță („gata"), iar blocarea vechiului număr se
// șterge, cu tot cu abonamentul de notificări de pe el.
// ══════════════════════════════════════════════════════════════
// [v11.29] Ce poate face un responsabil cu cod: urca repartizarea și/sau
// modifica indicatorii de ore. Codurile vechi (fără câmp) = doar repartizare.
// [v11.31] Autobazele de sub „Autobuze" (titan, giurgiului_ferentari, berceni…).
// Doar forma numelui se verifică aici; lista cu nume e în db.json.
const BAZA_RE = /^[a-z][a-z_]{1,29}$/;
function _autobaze(a) {
  return (Array.isArray(a) ? a : []).map(x => String(x).toLowerCase()).filter(x => BAZA_RE.test(x)).slice(0, 10);
}
function _drepturi(d) {
  if (!d || typeof d !== 'object') return { rep: true, ind: false };
  return { rep: !!d.rep, ind: !!d.ind };
}

// ══════════════════════════════════════════════════════════════
// [v11.29] INDICATORII DE ORE, MODIFICAȚI DIN APLICAȚIE
//
// Responsabilul de depou (cod cu dreptul „ind") sau adminul trimite o
// MODIFICARE (doar turele schimbate / noi / scoase) cu data de la care intră
// în vigoare. A responsabilului stă „în așteptare" până o aprobă adminul;
// a adminului intră direct. Aplicațiile citesc modificările aprobate de la
// GET /indicatori și le pun peste db.json, cu tabelul vechi păstrat pentru
// zilele dinainte de dată. Totul stă în /indicatori/<id>.
// ══════════════════════════════════════════════════════════════
const IND_ORA = /^([01]\d|2[0-3]):[0-5]\d$/;
const IND_CHEIE = /^\d{1,3}\/[A-Za-z0-9]{1,6}$/;
function _indCurataTabel(t, tip) {
  const out = { set: {}, del: [] };
  if (!t || typeof t !== 'object') return out;
  const set = (t.set && typeof t.set === 'object') ? t.set : {};
  for (const [k, v] of Object.entries(set).slice(0, 900)) {
    if (!IND_CHEIE.test(k) || !v || typeof v !== 'object') continue;
    if (tip === 'tram') {
      const sch = x => (x && IND_ORA.test(x.i) && IND_ORA.test(x.r)) ? { i: x.i, r: x.r, c: String(x.c || '').slice(0, 40) } : null;
      const s1 = sch(v.s1), s2 = sch(v.s2);
      if (!s1 && !s2) continue;
      const o = { linie: String(v.linie || k.split('/')[1]).slice(0, 6) };
      if (s1) { o.s1 = s1; if (v.s1 && v.s1.d) o.s1.d = true; }
      if (s2) { o.s2 = s2; o.s2.d = !!(v.s2 && v.s2.d); }
      out.set[k] = o;
    } else {
      const o = {};
      for (const sc of ['1', '2', '0']) {
        const x = v[sc];
        if (Array.isArray(x) && x.length === 2 && IND_ORA.test(x[0]) && IND_ORA.test(x[1])) o[sc] = [x[0], x[1]];
      }
      if (o['2'] && v.g2) o.g2 = 1;   // [v11.44] schimbul 2 iese din garaj
      if (Object.keys(o).length) out.set[k] = o;
    }
  }
  out.del = (Array.isArray(t.del) ? t.del : []).filter(k => IND_CHEIE.test(String(k))).slice(0, 900).map(String);
  return out;
}
function _indNumar(p) {
  let n = 0;
  for (const t of ['zl', 'we', 'l', 's', 'd']) if (p[t]) n += Object.keys(p[t].set || {}).length + (p[t].del || []).length;
  return n;
}
function _indDataRo(iso) { const [a, l, z] = String(iso).split('-'); return `${z}.${l}.${a}`; }
const IND_NUME = { dudesti: 'Depoul Dudești', giurgiu: 'Depoul Giurgiu', victoria: 'Depoul Victoria', titan: 'Depoul Titan',
  alexandria: 'Depoul Alexandria', colentina: 'Depoul Colentina', militari: 'Depoul Militari', budesti: 'Depoul București Noi',
  autobuze: 'Autobuze', troleibuze: 'Troleibuze' };
// [v11.33] Firebase nu primește chei cu „/" (iar „15/1" e cheia unui tur) și
// transformă obiectele cu chei 0/1/2 în liste. De aceea tabelele modificării
// se țin într-un singur câmp text (`tabele`, JSON) și se desfac la citire.
function _indDesface(p) {
  if (p && typeof p.tabele === 'string') {
    try { Object.assign(p, JSON.parse(p.tabele)); } catch (e) {}
    delete p.tabele;
  }
  return p;
}
function _indDeScris(p) {
  const o = Object.assign({}, p), t = {};
  for (const k of ['zl', 'we', 'l', 's', 'd']) if (o[k]) { t[k] = o[k]; delete o[k]; }
  o.tabele = JSON.stringify(t);
  return o;
}
async function _indCiteste(env) {
  try {
    const d = (await getJSON(urlBroadcast(env, 'indicatori.json'))) || {};
    for (const k of Object.keys(d)) _indDesface(d[k]);
    return d;
  } catch (e) { return null; }
}
async function _indAnuntaColegii(env, p) {
  const doc = {
    titlu: '⏱ Indicatori de ore noi',
    text: `${IND_NUME[p.dep] || p.dep}${p.bazaNume ? ' (' + p.bazaNume + ')' : ''}: indicatorii de ore se schimbă din ${_indDataRo(p.valabilDin)} (${_indNumar(p)} ture). Orele din aplicație se actualizează singure de la data asta.${p.nota ? '\n' + p.nota : ''}`,
    target: [p.dep], tip: 'update', creat: Date.now(), de: 'indicatori',
    expira: Date.parse(p.valabilDin + 'T00:00:00Z') + 7 * 86400000
  };
  try {
    await fetch(urlBroadcast(env, 'anunturi.json'), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(doc) });
  } catch (e) {}
}
// GET /indicatori — public: doar modificările aprobate, cât să le pună aplicația peste db.json.
async function indicatoriPublic(env) {
  const toate = await _indCiteste(env);
  if (toate === null) return { status: 503, corp: { ok: false, eroare: 'Firebase indisponibil' } };
  const aprobate = {};
  for (const [id, p] of Object.entries(toate)) {
    if (!p || p.stare !== 'aprobat') continue;
    const { de, motiv, ...rest } = p;
    aprobate[id] = rest;
  }
  return { status: 200, corp: { ok: true, aprobate, t: Date.now() } };
}
async function indicatoriActiune(env, cerere, cine) {
  // cine = { admin:true } sau { rep:{id,nr,nume,depouri,drepturi} }
  const a = cerere.actiune;
  if (a === 'indicatoriPropune') {
    const dep = String(cerere.dep || '').toLowerCase();
    if (!DEPOURI.includes(dep)) return { status: 400, corp: { ok: false, eroare: 'Depou necunoscut' } };
    if (cine.rep && !cine.rep.depouri.includes(dep)) return { status: 403, corp: { ok: false, eroare: 'Poți modifica doar indicatorii depoului tău.' } };
    const v = String(cerere.valabilDin || '');
    if (!/^\d{4}-\d{2}-\d{2}$/.test(v)) return { status: 400, corp: { ok: false, eroare: 'Alege data de la care intră în vigoare.' } };
    const azi = acumRo().data;
    if (cine.rep && v < azi) return { status: 400, corp: { ok: false, eroare: 'Data nu poate fi în trecut.' } };
    const tip = (dep === 'autobuze' || dep === 'troleibuze') ? 'ore' : 'tram';
    // [v11.31] la Autobuze, modificarea e a unei autobaze; responsabilul doar a lui
    let baza = '';
    if (dep === 'autobuze') {
      baza = String(cerere.baza || '').toLowerCase();
      if (!BAZA_RE.test(baza)) baza = '';
      if (cine.rep && !baza) return { status: 400, corp: { ok: false, eroare: 'Alege autobaza.' } };
      if (cine.rep && cine.rep.autobaze.length && !cine.rep.autobaze.includes(baza))
        return { status: 403, corp: { ok: false, eroare: 'Poți modifica doar indicatorii autobazei tale.' } };
    }
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    const p = { id, dep, tip, valabilDin: v, cand: Date.now(), nota: String(cerere.nota || '').slice(0, 300) };
    if (baza) { p.baza = baza; p.bazaNume = String(cerere.bazaNume || baza).slice(0, 40); }
    if (tip === 'tram') { p.zl = _indCurataTabel(cerere.zl, 'tram'); p.we = _indCurataTabel(cerere.we, 'tram'); }
    else {
      // [v11.36] sâmbăta (s) și duminica (d) separat; aplicațiile vechi trimit un singur `we`
      p.l = _indCurataTabel(cerere.l, 'ore');
      if (cerere.s || cerere.d) { p.s = _indCurataTabel(cerere.s, 'ore'); p.d = _indCurataTabel(cerere.d, 'ore'); }
      else p.we = _indCurataTabel(cerere.we, 'ore');
    }
    const n = _indNumar(p);
    if (!n) return { status: 400, corp: { ok: false, eroare: 'Nicio modificare de trimis.' } };
    if (JSON.stringify(p).length > 250000) return { status: 400, corp: { ok: false, eroare: 'Modificarea e prea mare.' } };
    p.de = cine.admin ? { rol: 'admin', nume: String(cerere.de || 'admin').slice(0, 60) }
                      : { rol: 'responsabil', nr: cine.rep.nr, nume: cine.rep.nume, id: cine.rep.id };
    const direct = cine.admin && !cerere.doarPropune;
    p.stare = direct ? 'aprobat' : 'asteapta';
    if (direct) { p.aprobatLa = Date.now(); p.aprobatDe = p.de.nume; }
    const r = await fetch(urlBroadcast(env, `indicatori/${id}.json`), { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(_indDeScris(p)) });
    if (!r.ok) { const t = await r.text().catch(() => ''); return { status: 502, corp: { ok: false, eroare: 'Firebase ' + r.status + (t ? ' ' + t.slice(0, 120) : '') } }; }
    if (direct) { if (cerere.anunta !== false) await _indAnuntaColegii(env, p); }
    else {
      try {
        await _anuntaAdminii(env, '⏱ Indicatori de aprobat',
          `${p.de.nume || p.de.nr} a modificat indicatorii la ${IND_NUME[dep] || dep}${p.bazaNume ? ' (' + p.bazaNume + ')' : ''}: ${n} ture, din ${_indDataRo(v)}. Deschide panoul → Repartizare.`, 'ind-' + id);
      } catch (e) {}
    }
    return { status: 200, corp: { ok: true, id, stare: p.stare, n } };
  }
  if (a === 'indicatoriMele') {
    const toate = await _indCiteste(env) || {};
    const ale = new Set([cine.rep.id].concat(cine.rep.vechi || []));   // [v11.34] și cele trimise cu codurile lui vechi
    const lista = Object.values(toate).filter(p => p && p.de && ale.has(p.de.id))
      .sort((x, y) => (y.cand || 0) - (x.cand || 0)).slice(0, 10)
      .map(p => ({ id: p.id, dep: p.dep, baza: p.baza || '', valabilDin: p.valabilDin, cand: p.cand, stare: p.stare, n: _indNumar(p), motiv: p.motiv || '' }));
    return { status: 200, corp: { ok: true, lista } };
  }
  if (!cine.admin) return { status: 403, corp: { ok: false, eroare: 'Nepermis' } };
  if (a === 'indicatoriLista') {
    const toate = await _indCiteste(env);
    if (toate === null) return { status: 503, corp: { ok: false, eroare: 'Firebase indisponibil' } };
    const lista = Object.values(toate).filter(p => p && !p.ascuns).sort((x, y) => (y.cand || 0) - (x.cand || 0)).slice(0, 60);
    return { status: 200, corp: { ok: true, lista } };
  }
  // [v11.37] Curăță istoricul din panou. Cele aprobate rămân în vigoare (doar nu
  // se mai arată); cele respinse/anulate nu mai folosesc la nimic → se șterg.
  if (a === 'indicatoriAscunde') {
    const toate = await _indCiteste(env);
    if (toate === null) return { status: 503, corp: { ok: false, eroare: 'Firebase indisponibil' } };
    const tinta = cerere.toate ? Object.keys(toate) : [String(cerere.id || '').replace(/[^a-z0-9]/g, '').slice(0, 20)];
    let n = 0;
    for (const id of tinta) {
      const p = toate[id];
      if (!p || p.stare === 'asteapta') continue;
      if (p.stare === 'aprobat') {
        if (p.ascuns) continue;
        await fetch(urlBroadcast(env, `indicatori/${id}/ascuns.json`), { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: 'true' });
      } else await fetch(urlBroadcast(env, `indicatori/${id}.json`), { method: 'DELETE' });
      n++;
    }
    return { status: 200, corp: { ok: true, n } };
  }
  const id = String(cerere.id || '').replace(/[^a-z0-9]/g, '').slice(0, 20);
  if (!id) return { status: 400, corp: { ok: false, eroare: 'Lipsește id-ul' } };
  let p = null;
  try { p = _indDesface(await getJSON(urlBroadcast(env, `indicatori/${id}.json`))); } catch (e) {}
  if (!p) return { status: 404, corp: { ok: false, eroare: 'Nu mai există' } };
  const patch = async o => {
    const r = await fetch(urlBroadcast(env, `indicatori/${id}.json`), { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(o) });
    return r.ok;
  };
  if (a === 'indicatoriAproba') {
    if (p.stare !== 'asteapta') return { status: 400, corp: { ok: false, eroare: 'Nu e în așteptare' } };
    if (!(await patch({ stare: 'aprobat', aprobatLa: Date.now(), aprobatDe: String(cerere.de || 'admin').slice(0, 60) }))) return { status: 502, corp: { ok: false, eroare: 'Firebase' } };
    if (cerere.anunta !== false) await _indAnuntaColegii(env, p);
    return { status: 200, corp: { ok: true } };
  }
  if (a === 'indicatoriRespinge') {
    if (p.stare !== 'asteapta') return { status: 400, corp: { ok: false, eroare: 'Nu e în așteptare' } };
    await patch({ stare: 'respins', motiv: String(cerere.motiv || '').slice(0, 200), respinsLa: Date.now() });
    return { status: 200, corp: { ok: true } };
  }
  if (a === 'indicatoriAnuleaza') {
    if (p.stare !== 'aprobat') return { status: 400, corp: { ok: false, eroare: 'Nu e aprobată' } };
    await patch({ stare: 'anulat', anulatLa: Date.now() });
    return { status: 200, corp: { ok: true } };
  }
  return { status: 400, corp: { ok: false, eroare: 'Acțiune necunoscută: ' + a } };
}

// [v11.18] Notificare către admin(i): numerele trecute în /config/adminNotif.
// Folosită când un blocat cere aprobarea unui număr nou (și, mai târziu, la alte cereri).
// ══════════════════════════════════════════════════════════════
// [1.0] FOILE DE REPARTIZARE PE LUNI + REAMINTIRE CĂTRE RESPONSABILI
// ══════════════════════════════════════════════════════════════
const _lunaUrm = (luna) => { const [a, l] = luna.split('-').map(Number); const d = new Date(Date.UTC(a, l, 1)); return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`; };
async function _repStareLuna(env, dep, luna, cuNumere) {
  let urcat = null, urcatDe = null, nrs = [];
  try { urcat = await getJSON(urlBroadcast(env, `repartizare/${dep}/${luna}/urcat.json`)); } catch (e) {}
  try { urcatDe = await getJSON(urlBroadcast(env, `repartizare/${dep}/${luna}/urcatDe.json`)); } catch (e) {}
  if (urcat || cuNumere) {
    try {
      const u = urlBroadcast(env, `repartizare/${dep}/${luna}/lunara.json`);
      const k = await getJSON(u + (u.includes('?') ? '&' : '?') + 'shallow=true');
      nrs = k && typeof k === 'object' ? Object.keys(k) : [];
    } catch (e) {}
  }
  return { urcat: urcat || 0, urcatDe: urcatDe || '', n: nrs.length, nrs: cuNumere ? nrs : undefined };
}
// Trimite notificare responsabililor (cod cu drept de repartizare) ai depourilor date.
async function _repAminteste(env, depouri, luna) {
  if (!env.VAPID_PUBLIC || !env.VAPID_PRIVATE || !depouri.length) return { trimise: 0, oameni: 0 };
  const rr = await getJSON(urlBroadcast(env, 'repartitori.json')).catch(() => null) || {};
  const vapid = { subject: 'mailto:programstb@example.com', publicKey: env.VAPID_PUBLIC, privateKey: env.VAPID_PRIVATE };
  const [a, l] = luna.split('-');
  const numeLuna = ['ianuarie','februarie','martie','aprilie','mai','iunie','iulie','august','septembrie','octombrie','noiembrie','decembrie'][Number(l) - 1] || luna;
  let trimise = 0, oameni = 0;
  for (const v of Object.values(rr)) {
    if (!v || !v.nr || !_drepturi(v.drepturi).rep) continue;
    const ale = (Array.isArray(v.depouri) ? v.depouri : []).filter(d => depouri.includes(d));
    if (!ale.length) continue;
    try {
      const u = await getJSON(urlBroadcast(env, `push/${nrCurat(v.nr)}.json`));
      if (!u) continue;
      const payload = JSON.stringify({ title: '📋 Repartizarea pe ' + numeLuna,
        body: `Nu e urcată încă foaia pe ${numeLuna} ${a}. Când o ai, urc-o din aplicație (ține apăsat pe titlu → codul tău).`, tag: 'rep-' + luna, url: './' });
      const r = await trimiteToate(env, nrCurat(v.nr), u, payload, { TTL: 86400, urgency: 'normal' }, vapid);
      if (r.trimise) { trimise += r.trimise; oameni++; }
    } catch (e) {}
  }
  return { trimise, oameni };
}
// Rulează din cron: pe 25 ale lunii, după 10:00, o singură dată pe lună.
async function _repAmintireAutomata(env, log) {
  try {
    const { data, minute } = acumRo();
    if (Number(data.slice(8, 10)) !== 25 || minute < 600) return;
    const luna = _lunaUrm(data.slice(0, 7));
    const oprit = await getJSON(urlBroadcast(env, 'config/repAmintireOprita.json')).catch(() => null);
    if (oprit) return;
    const facut = await getJSON(urlBroadcast(env, `config/repAmintit/${luna}.json`)).catch(() => null);
    if (facut) return;
    const lipsa = [];
    for (const dep of DEPOURI) { const st = await _repStareLuna(env, dep, luna, false); if (!st.urcat) lipsa.push(dep); }
    const r = await _repAminteste(env, lipsa, luna);
    await fetch(urlBroadcast(env, `config/repAmintit/${luna}.json`), { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ la: Date.now(), lipsa, ...r }) });
    log(`Reamintire repartizare ${luna}: ${lipsa.length} depouri fără foaie · ${r.oameni} responsabili anunțați`);
  } catch (e) { log('Reamintire repartizare: ' + e.message); }
}


// ══════════════════════════════════════════════════════════════
// [1.2] BANDA DE AVERTIZARE · ORE GREȘITE · FOI TRIMISE DE COLEGI · COLEGI NOI
// ══════════════════════════════════════════════════════════════
const _id12 = () => Date.now().toString(36) + [...crypto.getRandomValues(new Uint8Array(5))].map(x => (x % 36).toString(36)).join('');
const _aziRo = () => acumRo().data;   // [2.7] fusul orar real (vara +3, iarna +2)
const _txt = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
async function _fbPut(env, cale, v) {
  const r = await fetch(urlBroadcast(env, cale + '.json'), { method: v === null ? 'DELETE' : 'PUT', headers: { 'Content-Type': 'application/json' }, body: v === null ? undefined : JSON.stringify(v) });
  if (!r.ok) { const d = await r.text().catch(() => ''); throw new Error(`Firebase ${r.status} ${d.slice(0, 120)}`); }
}
// Notificare către un singur număr de serviciu (toate telefoanele lui).
async function _pushLa(env, nr, titlu, text, tag) {
  if (!env.VAPID_PUBLIC || !env.VAPID_PRIVATE || !nr) return 0;
  try {
    const u = await getJSON(urlBroadcast(env, `push/${nrCurat(nr)}.json`));
    if (!u) return 0;
    const vapid = { subject: 'mailto:programstb@example.com', publicKey: env.VAPID_PUBLIC, privateKey: env.VAPID_PRIVATE };
    const r = await trimiteToate(env, nrCurat(nr), u, JSON.stringify({ title: titlu, body: text, tag: tag || 'info', url: './' }), { TTL: 86400 }, vapid);
    return r.trimise || 0;
  } catch (e) { return 0; }
}
// Doar telefonul înregistrat pe număr poate trimite în numele lui.
async function _dispInregistrat(env, nr, dev) {
  if (!nr || !dev) return false;
  try { const { disp } = _normalizeaza(await getJSON(urlBroadcast(env, `proprietar/${nr}.json`))); return !!(disp && disp[dev]); }
  catch (e) { return false; }
}
// Câte trimiteri pe zi de la un număr (raport / trimite). Întoarce false peste limită.
async function _limitaZi(env, fel, nr, max) {
  const cale = `limite/${fel}/${nr}/${_aziRo()}`;
  let n = 0; try { n = Number(await getJSON(urlBroadcast(env, cale + '.json'))) || 0; } catch (e) {}
  if (n >= max) return false;
  await _fbPut(env, cale, n + 1).catch(() => {});
  return true;
}

async function raportOre(request, env) {
  if (request.method !== 'POST') return { status: 405, corp: { ok: false, eroare: 'Doar POST' } };
  let c; try { c = await request.json(); } catch (e) { return { status: 400, corp: { ok: false, eroare: 'JSON invalid' } }; }
  const nr = nrCurat(c.nr), dev = String(c.dev || '').replace(/[^a-zA-Z0-9-]/g, '').slice(0, 64);
  if (!(await _dispInregistrat(env, nr, dev))) return { status: 403, corp: { ok: false, eroare: 'Telefonul nu e înregistrat pe numărul ăsta.' } };
  const ora = v => /^\d{1,2}:\d{2}$/.test(String(v || '')) ? String(v).padStart(5, '0') : '';
  const r = {
    nr, la: Date.now(),
    dep: DEPOURI.includes(c.dep) ? c.dep : '',      // [2.7] doar depourile cunoscute (textul ajungea în panou)
    baza: _txt(c.baza, 20).replace(/[^a-z0-9_-]/gi, ''),
    linie: _txt(c.linie, 10).replace(/[^0-9A-Za-z]/g, ''), tur: _txt(c.tur, 10).replace(/[^0-9A-Za-z]/g, ''), sch: ['1', '2', '0'].includes(String(c.sch)) ? String(c.sch) : '',
    data: /^\d{4}-\d{2}-\d{2}$/.test(c.data || '') ? c.data : '',
    i: ora(c.i), r: ora(c.r), iApp: ora(c.iApp), rApp: ora(c.rApp), obs: _txt(c.obs, 300)
  };
  if (!r.dep || !r.linie || !r.tur || (!r.i && !r.r && !r.obs)) return { status: 400, corp: { ok: false, eroare: 'Completează linia, turul și ora de pe indicator.' } };
  if (!(await _limitaZi(env, 'raport', nr, 10))) return { status: 429, corp: { ok: false, eroare: 'Ai trimis deja 10 azi. Mulțumim! Încearcă mâine.' } };
  const id = _id12();
  const poza = typeof c.poza === 'string' && /^data:image\/jpeg;base64,/.test(c.poza) && c.poza.length < 3000000 ? c.poza : '';   // [1.8] poze mai clare (2000 px)
  try { await _fbPut(env, `raportOre/${id}`, Object.assign({}, r, { arePoza: !!poza })); if (poza) await _fbPut(env, `raportOrePoza/${id}`, poza); }
  catch (e) { return { status: 502, corp: { ok: false, eroare: e.message } }; }
  let la = 0;
  try {
    const toate = await getJSON(urlBroadcast(env, 'raportOre.json')) || {};
    la = Object.values(toate).filter(x => x && x.dep === r.dep && x.linie === r.linie && x.tur === r.tur && x.sch === r.sch && x.nr !== nr).length;
  } catch (e) {}
  const loc = (DEPOURI.includes(r.dep) ? r.dep : r.dep) + (r.baza ? ' · ' + r.baza : '');
  await _anuntaAdminii(env, '⏱ Oră de verificat', `${loc} · L${r.linie} T${r.tur}${r.sch ? ' sch ' + r.sch : ''}: ${r.iApp || '?'}–${r.rApp || '?'} → ${r.i || '?'}–${r.r || '?'}`, 'raport-ore').catch(() => 0);
  return { status: 200, corp: { ok: true, id, altii: la } };
}

const TRIMITE_MAX_FISIER = 9900000;            // base64 (~7 MB fișier); Firebase primește cel mult 10 MB într-un șir
const TRIMITE_MAX_TOTAL  = 24 * 1024 * 1024;
async function trimiteFoaie(request, env) {
  if (request.method !== 'POST') return { status: 405, corp: { ok: false, eroare: 'Doar POST' } };
  let c; try { c = await request.json(); } catch (e) { return { status: 400, corp: { ok: false, eroare: 'Fișierele sunt prea mari sau s-au trimis greșit.' } }; }
  const nr = nrCurat(c.nr), dev = String(c.dev || '').replace(/[^a-zA-Z0-9-]/g, '').slice(0, 64);
  if (!(await _dispInregistrat(env, nr, dev))) return { status: 403, corp: { ok: false, eroare: 'Telefonul nu e înregistrat pe numărul ăsta.' } };
  const tip = ['rep', 'ind', 'alt'].includes(c.tip) ? c.tip : '';
  const luna = /^\d{4}-\d{2}$/.test(c.luna || '') ? c.luna : '';
  const baza = _txt(c.baza, 30).replace(/[^a-z0-9_-]/gi, '');
  const bazaNume = _txt(c.bazaNume, 40);
  // [1.8] pe_rand: întâi doar lista fișierelor, apoi fiecare fișier în cererea lui (/trimite-fisier) — poze la rezoluția întreagă
  const peRand = c.pe_rand === true;
  const fis = (Array.isArray(c.fisiere) ? c.fisiere : []).filter(f => f && (peRand ? Number(f.marime) > 0 : (typeof f.date === 'string' && f.date.length > 100)));
  if (!tip || (!baza && !bazaNume)) return { status: 400, corp: { ok: false, eroare: 'Alege ce trimiți și de unde.' } };
  if (!fis.length) return { status: 400, corp: { ok: false, eroare: 'Adaugă măcar o poză sau un PDF.' } };
  if (fis.length > 10) return { status: 400, corp: { ok: false, eroare: 'Cel mult 10 fișiere odată.' } };
  if (!peRand && (fis.some(f => f.date.length > TRIMITE_MAX_FISIER) || fis.reduce((s, f) => s + f.date.length, 0) > TRIMITE_MAX_TOTAL))
    return { status: 413, corp: { ok: false, eroare: 'Fișierele sunt prea mari (cel mult 7 MB fiecare).' } };
  if (peRand && fis.some(f => Number(f.marime) > TRIMITE_MAX_FISIER * 0.75))
    return { status: 413, corp: { ok: false, eroare: 'Un fișier e prea mare (cel mult 7 MB).' } };
  if (!(await _limitaZi(env, 'trimite', nr, 5))) return { status: 429, corp: { ok: false, eroare: 'Ai trimis deja de 5 ori azi. Încearcă mâine.' } };
  const id = _id12();
  const meta = { nr, la: Date.now(), tip, luna, baza, bazaNume, nou: !baza, obs: _txt(c.obs, 300),
    fisiere: fis.map(f => ({ nume: _txt(f.nume, 80) || 'fisier', tip: /^(image\/jpeg|image\/png|application\/pdf)$/.test(f.tip) ? f.tip : 'application/octet-stream', marime: peRand ? Math.round(Number(f.marime)) : Math.round(f.date.length * 0.75) })) };
  if (peRand) {
    meta.incomplet = true;
    meta.tok = [...crypto.getRandomValues(new Uint8Array(12))].map(x => x.toString(16).padStart(2, '0')).join('');
    try { await _fbPut(env, `trimiteri/${id}`, meta); } catch (e) { return { status: 502, corp: { ok: false, eroare: 'Nu s-a putut salva. Încearcă din nou.' } }; }
    return { status: 200, corp: { ok: true, id, tok: meta.tok, n: fis.length } };
  }
  try {
    for (let k = 0; k < fis.length; k++) await _fbPut(env, `trimiteriFisiere/${id}/${k}`, fis[k].date);
    await _fbPut(env, `trimiteri/${id}`, meta);
  } catch (e) {
    await _fbPut(env, `trimiteriFisiere/${id}`, null).catch(() => {});
    return { status: 502, corp: { ok: false, eroare: 'Nu s-a putut salva. Încearcă din nou. (' + e.message + ')' } };
  }
  let altii = 0;
  try {
    const toate = await getJSON(urlBroadcast(env, 'trimiteri.json')) || {};
    const cheie = x => `${x.tip}|${x.baza || ('~' + String(x.bazaNume || '').toLowerCase())}|${x.luna || ''}`;
    altii = new Set(Object.values(toate).filter(x => x && cheie(x) === cheie(meta) && x.nr !== nr).map(x => x.nr)).size;
  } catch (e) {}
  const ce = tip === 'rep' ? 'Repartizarea' + (luna ? ' pe ' + luna : '') : tip === 'ind' ? 'Indicatori de ore' : 'Fișiere';
  await _anuntaAdminii(env, '📥 Foaie trimisă', `${ce} · ${bazaNume || baza} · de la ${nr} (${fis.length} fișiere)`, 'trimiteri').catch(() => 0);
  return { status: 200, corp: { ok: true, id, altii } };
}

// [1.8] Un fișier dintr-o trimitere începută cu pe_rand.
async function _trimiteMeta(env, id, tok) {
  id = String(id || '').replace(/[^a-z0-9]/g, '').slice(0, 20);
  if (!id || !tok) return null;
  const m = await getJSON(urlBroadcast(env, `trimiteri/${id}.json`)).catch(() => null);
  return m && m.incomplet && m.tok === String(tok) ? Object.assign({ id }, m) : null;
}
async function trimiteFisier(request, env) {
  let c; try { c = await request.json(); } catch (e) { return { status: 413, corp: { ok: false, eroare: 'Fișierul e prea mare sau s-a trimis greșit.' } }; }
  const m = await _trimiteMeta(env, c.id, c.tok);
  if (!m) return { status: 404, corp: { ok: false, eroare: 'Trimiterea nu mai există. Începe din nou.' } };
  const k = Number(c.k);
  if (!(k >= 0 && k < (m.fisiere || []).length)) return { status: 400, corp: { ok: false, eroare: 'Fișier greșit.' } };
  if (typeof c.date !== 'string' || c.date.length < 100) return { status: 400, corp: { ok: false, eroare: 'Fișier gol.' } };
  if (c.date.length > TRIMITE_MAX_FISIER) return { status: 413, corp: { ok: false, eroare: 'Fișierul e prea mare (cel mult 7 MB).' } };
  try { await _fbPut(env, `trimiteriFisiere/${m.id}/${k}`, c.date); }
  catch (e) { return { status: 502, corp: { ok: false, eroare: 'Nu s-a putut salva fișierul. (' + e.message + ')' } }; }
  return { status: 200, corp: { ok: true, k } };
}
async function trimiteGata(request, env) {
  let c; try { c = await request.json(); } catch (e) { return { status: 400, corp: { ok: false } }; }
  const m = await _trimiteMeta(env, c.id, c.tok);
  if (!m) return { status: 404, corp: { ok: false, eroare: 'Trimiterea nu mai există. Începe din nou.' } };
  const u = urlBroadcast(env, `trimiteriFisiere/${m.id}.json`);
  const are = await getJSON(u + (u.includes('?') ? '&' : '?') + 'shallow=true').catch(() => null) || {};
  const lipsa = (m.fisiere || []).map((f, k) => k).filter(k => !are[k]);
  if (lipsa.length) return { status: 409, corp: { ok: false, lipsa, eroare: 'Lipsesc fișiere: ' + lipsa.map(k => k + 1).join(', ') } };
  await _fbPut(env, `trimiteri/${m.id}/incomplet`, null);
  await _fbPut(env, `trimiteri/${m.id}/tok`, null);
  let altii = 0;
  try {
    const toate = await getJSON(urlBroadcast(env, 'trimiteri.json')) || {};
    const cheie = x => `${x.tip}|${x.baza || ('~' + String(x.bazaNume || '').toLowerCase())}|${x.luna || ''}`;
    altii = new Set(Object.values(toate).filter(x => x && !x.incomplet && cheie(x) === cheie(m) && x.nr !== m.nr).map(x => x.nr)).size;
  } catch (e) {}
  const ce = m.tip === 'rep' ? 'Repartizarea' + (m.luna ? ' pe ' + m.luna : '') : m.tip === 'ind' ? 'Indicatori de ore' : 'Fișiere';
  await _anuntaAdminii(env, '📥 Foaie trimisă', `${ce} · ${m.bazaNume || m.baza} · de la ${m.nr} (${(m.fisiere || []).length} fișiere)`, 'trimiteri').catch(() => 0);
  return { status: 200, corp: { ok: true, id: m.id, altii } };
}

// Ce a rămas uitat: fișiere nedescărcate de 30 de zile, rapoarte de 60.
async function _curataTrimiteri(env, log) {
  const azi = _aziRo();
  try {
    if ((await getJSON(urlBroadcast(env, 'config/curatat.json'))) === azi) return;
    await _fbPut(env, 'config/curatat', azi);
    const t = await getJSON(urlBroadcast(env, 'trimiteri.json')) || {};
    let n = 0;
    for (const [id, x] of Object.entries(t)) {
      if (x && x.la && (Date.now() - x.la > 30 * 864e5 || (x.incomplet && Date.now() - x.la > 864e5))) { await _fbPut(env, `trimiteriFisiere/${id}`, null).catch(() => {}); await _fbPut(env, `trimiteri/${id}`, null).catch(() => {}); n++; }
    }
    const r = await getJSON(urlBroadcast(env, 'raportOre.json')) || {};
    for (const [id, x] of Object.entries(r)) {
      if (x && x.la && Date.now() - x.la > 60 * 864e5) { await _fbPut(env, `raportOre/${id}`, null).catch(() => {}); await _fbPut(env, `raportOrePoza/${id}`, null).catch(() => {}); n++; }
    }
    const er = await getJSON(urlBroadcast(env, 'erori.json')) || {};
    for (const [id, x] of Object.entries(er)) if (!x || !x.ultima || Date.now() - x.ultima > 30 * 864e5) { await _fbPut(env, `erori/${id}`, null).catch(() => {}); n++; }
    // [2.3] jurnalul adminului 2: 90 de zile
    const jr = await getJSON(urlBroadcast(env, ADM2_JURNAL + '.json')).catch(() => null) || {};
    for (const [nrA, intrari] of Object.entries(jr)) {
      for (const [id, x] of Object.entries(intrari || {})) if (!x || !x.la || Date.now() - x.la > 90 * 864e5) { await _fbPut(env, `${ADM2_JURNAL}/${nrA}/${id}`, null).catch(() => {}); n++; }
    }
    await _fbPut(env, 'limite', null).catch(() => {});
    if (n) log(`Curățenie: ${n} trimiteri/rapoarte vechi șterse`);
  } catch (e) { log('Curățenie: ' + e.message); }
}


// ══════════════════════════════════════════════════════════════
// [1.6] ERORI RAPORTATE · SCRIE-I ADMINULUI · DATELE MELE · ȘTERGERE DUPĂ 6 LUNI
// ══════════════════════════════════════════════════════════════
const ERORI_NORMALE = /Failed to fetch|NetworkError|Load failed|AbortError|aborted|timeout|network connection was lost|Internet|offline|ERR_INTERNET|QuotaExceeded/i;
// [2.7] Limită pe zi și pe rețea (IP-ul nu se păstrează — doar o amprentă scurtă).
// Limitele pe telefon se ocoleau schimbând identificatorul trimis.
function _ipCheie(request) { return 'i' + _hashScurt(String(request.headers.get('CF-Connecting-IP') || 'necunoscut')); }
function _hashScurt(t) { let h = 5381; for (let i = 0; i < t.length; i++) h = ((h << 5) + h + t.charCodeAt(i)) >>> 0; return h.toString(36); }
async function raportEroare(request, env) {
  let c; try { c = await request.json(); } catch (e) { return { status: 400, corp: { ok: false } }; }
  const msg = _txt(c.msg, 300), src = _txt(c.src, 60).replace(/[^\w.$<> -]/g, '');
  if (!msg || /^Script error\.?$/i.test(msg)) return { status: 200, corp: { ok: true, sarit: true } };
  const dev = String(c.dev || '').replace(/[^a-zA-Z0-9-]/g, '').slice(0, 64) || 'anonim';
  if (!(await _limitaZi(env, 'eroare', dev.slice(0, 40), 30))) return { status: 200, corp: { ok: true, sarit: true } };
  if (!(await _limitaZi(env, 'eroare-ip', _ipCheie(request), 60))) return { status: 200, corp: { ok: true, sarit: true } };
  const cheie = 'e' + _hashScurt(msg.replace(/\d+/g, '#').slice(0, 160) + '|' + src);
  const cale = `erori/${cheie}`;
  let e = null; try { e = await getJSON(urlBroadcast(env, cale + '.json')); } catch (x) {}
  const acum = Date.now();
  const tel = _txt(dev, 12);
  const nou = e || { msg, src, prima: acum, n: 0, tel: {}, normal: ERORI_NORMALE.test(msg) };
  nou.ultima = acum; nou.n = (nou.n || 0) + 1;
  nou.stack = _txt(c.stack, 600) || nou.stack || '';
  nou.tel = nou.tel || {};
  if (Object.keys(nou.tel).length < 60 || nou.tel[tel])
    nou.tel[tel] = { nr: nrCurat(c.nr), v: _txt(c.v, 10), plat: _txt(c.plat, 20), dep: _txt(c.dep, 20), la: acum };
  delete nou.rezolvat;
  try { await _fbPut(env, cale, nou); } catch (x) { return { status: 502, corp: { ok: false } }; }
  const telefoane = Object.keys(nou.tel).length;
  if (telefoane >= 3 && !nou.normal && !nou.anuntat) {
    await _fbPut(env, cale + '/anuntat', acum).catch(() => {});
    await _anuntaAdminii(env, '🐞 Eroare la ' + telefoane + ' telefoane', msg.slice(0, 120), 'erori').catch(() => 0);
  }
  return { status: 200, corp: { ok: true } };
}
async function mesajAdmin(request, env) {
  let c; try { c = await request.json(); } catch (e) { return { status: 400, corp: { ok: false, eroare: 'JSON invalid' } }; }
  const nr = nrCurat(c.nr), dev = String(c.dev || '').replace(/[^a-zA-Z0-9-]/g, '').slice(0, 64);
  if (!(await _dispInregistrat(env, nr, dev))) return { status: 403, corp: { ok: false, eroare: 'Telefonul nu e înregistrat pe numărul ăsta.' } };
  const text = String(c.text == null ? '' : c.text).replace(/[\u0000-\u0009\u000b-\u001f]/g, ' ').trim().slice(0, 1000);   // rândurile noi rămân
  if (text.length < 3) return { status: 400, corp: { ok: false, eroare: 'Scrie mesajul.' } };
  if (!(await _limitaZi(env, 'mesaj', nr, 5))) return { status: 429, corp: { ok: false, eroare: 'Ai trimis deja 5 mesaje azi. Încearcă mâine.' } };
  const id = _id12();
  await _fbPut(env, `mesajeAdmin/${id}`, { nr, text, la: Date.now(), dep: _txt(c.dep, 20), v: _txt(c.v, 10), fel: ['problema', 'idee', 'altceva'].includes(c.fel) ? c.fel : 'altceva' });
  await _anuntaAdminii(env, '✉️ Mesaj de la ' + nr, text.slice(0, 120), 'mesaj-admin').catch(() => 0);
  return { status: 200, corp: { ok: true } };
}
// Ce ține despre un număr: căile din Firebase (pentru „Descarcă” și „Șterge”).
const CAI_NR = ['backup', 'backupIstoric', 'stats', 'push', 'proprietar'];
async function _stergeNr(env, nr) {
  for (const c of CAI_NR) await _fbPut(env, `${c}/${nr}`, null).catch(() => {});
  for (const col of ['trimiteri', 'raportOre', 'mesajeAdmin']) {
    const d = await getJSON(urlBroadcast(env, col + '.json')).catch(() => null) || {};
    for (const [id, x] of Object.entries(d)) if (x && x.nr === nr) {
      await _fbPut(env, `${col}/${id}`, null).catch(() => {});
      if (col === 'trimiteri') await _fbPut(env, `trimiteriFisiere/${id}`, null).catch(() => {});
      if (col === 'raportOre') await _fbPut(env, `raportOrePoza/${id}`, null).catch(() => {});
    }
  }
}
async function dateleMele(request, env) {
  let c; try { c = await request.json(); } catch (e) { return { status: 400, corp: { ok: false, eroare: 'JSON invalid' } }; }
  const nr = nrCurat(c.nr), dev = String(c.dev || '').replace(/[^a-zA-Z0-9-]/g, '').slice(0, 64);
  if (!(await _dispInregistrat(env, nr, dev))) return { status: 403, corp: { ok: false, eroare: 'Doar telefonul înregistrat pe numărul ăsta poate cere datele.' } };
  if (c.actiune === 'sterge') {
    await _stergeNr(env, nr);
    await _anuntaAdminii(env, '🗑 Date șterse', `${nr} și-a șters singur datele din cloud`, 'date-sterse').catch(() => 0);
    return { status: 200, corp: { ok: true, sters: true } };
  }
  const out = { numar: nr, descarcatLa: new Date().toISOString() };
  for (const cale of CAI_NR) {
    let v = await getJSON(urlBroadcast(env, `${cale}/${nr}.json`)).catch(() => null);
    if (cale === 'push' && v) v = { telefoaneCuNotificari: Object.keys(v.subs || {}).length || (v.sub ? 1 : 0) };   // cheile tehnice nu
    if (v !== null && v !== undefined) out[cale] = v;
  }
  for (const col of ['trimiteri', 'raportOre', 'mesajeAdmin']) {
    const d = await getJSON(urlBroadcast(env, col + '.json')).catch(() => null) || {};
    const ale = Object.values(d).filter(x => x && x.nr === nr);
    if (ale.length) out[col] = ale;
  }
  return { status: 200, corp: { ok: true, date: out } };
}
// Numerele care n-au mai deschis aplicația de 6 luni: se șterg din cloud, câte 3 pe rulare.
async function _sterge6Luni(env, log) {
  const azi = _aziRo();
  try {
    if ((await getJSON(urlBroadcast(env, 'config/sterse6luni.json'))) === azi) return;
    const prag = Date.now() - 182 * 864e5;
    // [2.7] Dacă vreuna din citiri eșuează, NU ștergem nimic azi: înainte o
    // citire picată lăsa decizia doar pe cealaltă sursă și putea șterge oameni activi.
    const [st, bk, pr] = await Promise.all([getJSON(urlBroadcast(env, 'stats.json')), getJSON(urlBroadcast(env, 'backup.json')), getJSON(urlBroadcast(env, 'proprietar.json'))]);
    if (!st || !bk) { log('Ștergere 6 luni: date incomplete, sar azi'); return; }
    const timp = v => { if (v == null || v === '') return 0; const n = Number(v); if (Number.isFinite(n) && n > 0) return n < 1e12 ? n * 1000 : n; const t = Date.parse(v); return Number.isFinite(t) ? t : 0; };
    const ultim = {};
    const pune = (nr, t) => { ultim[nr] = Math.max(ultim[nr] || 0, t || 0); };
    for (const [nr, x] of Object.entries(st || {})) pune(nr, timp(x && x.ultimaVizita));
    for (const [nr, x] of Object.entries(bk || {})) { pune(nr, timp(x && x.ts)); pune(nr, timp(x && (x.updated || x.updat))); }
    for (const [nr, x] of Object.entries(pr || {})) { const { disp } = _normalizeaza(x); for (const d of Object.values(disp || {})) pune(nr, timp(d && (d.ultima || d.la))); }
    const vechi = Object.entries(ultim).filter(([nr, t]) => t && t < prag).map(([nr]) => nr);
    for (const nr of vechi.slice(0, 3)) await _stergeNr(env, nr);
    // [2.7] cel mult 3 pe rulare și cel mult 30 pe zi
    const cate = Number(await getJSON(urlBroadcast(env, `limite/sterse6luni/${azi}.json`)).catch(() => 0)) || 0;
    await _fbPut(env, `limite/sterse6luni/${azi}`, cate + Math.min(3, vechi.length)).catch(() => {});
    if (vechi.length <= 3 || cate + 3 >= 30) await _fbPut(env, 'config/sterse6luni', azi).catch(() => {});
    if (vechi.length) log(`6 luni fără activitate: șterse ${Math.min(3, vechi.length)} (${vechi.slice(0, 3).join(', ')})`);
  } catch (e) { log('Ștergere 6 luni: ' + e.message); }
}


// ══════════════════════════════════════════════════════════════
// [2.0] CERERI DE PE ECRANELE „NUMĂR DEJA FOLOSIT” ȘI „ACCES BLOCAT”
// Telefonul care scrie NU e înregistrat pe număr (de aceea scrie), deci nu-l
// putem verifica. Mesajul ține și codul telefonului: adminul îl poate pune pe
// număr dintr-o apăsare. Ce poate face un străin: cel mult să-ți trimită o
// cerere, pe care o vezi și o ignori.
// ══════════════════════════════════════════════════════════════
async function cerereAdmin(request, env) {
  let c; try { c = await request.json(); } catch (e) { return { status: 400, corp: { ok: false, eroare: 'JSON invalid' } }; }
  const nr = nrCurat(c.nr), dev = String(c.dev || '').replace(/[^a-zA-Z0-9-]/g, '').slice(0, 64);
  const motiv = ['ocupat', 'blocat'].includes(c.motiv) ? c.motiv : '';
  if (!nr || !dev || !motiv) return { status: 400, corp: { ok: false, eroare: 'Lipsește numărul.' } };
  if (!(await _limitaZi(env, 'cerere-ip', _ipCheie(request), 20))) return { status: 429, corp: { ok: false, eroare: 'Prea multe cereri azi. Așteaptă răspunsul adminului.' } };
  if (!(await _limitaZi(env, 'cerere', dev.slice(0, 40), 6))) return { status: 429, corp: { ok: false, eroare: 'Ai trimis deja mai multe cereri azi. Așteaptă răspunsul adminului.' } };
  const info = {};
  if (motiv === 'ocupat') {
    const { locuri, disp } = _normalizeaza(await getJSON(urlBroadcast(env, `proprietar/${nr}.json`)).catch(() => null));
    if (disp[dev]) return { status: 200, corp: { ok: true, aprobat: true } };
    const la = Object.values(disp).map(x => Number(x && x.la) || 0).filter(Boolean);
    info.telefoane = Object.keys(disp).length; info.locuri = locuri; info.din = la.length ? Math.min(...la) : 0;
  } else {
    let b = await getJSON(urlBroadcast(env, `blocati/${nr}.json`)).catch(() => null);
    // [2.9] telefonul poate fi blocat definitiv prin alt număr (cel blocat inițial)
    if (!b) { const bt = await _dispBlocat(env, dev).catch(() => null); if (bt) { b = bt; info.nrBlocat = String(bt.nr); } }
    if (!b) return { status: 200, corp: { ok: true, aprobat: true } };
    info.motivBlocare = _txt(b.motiv, 120);
  }
  const fel = ['telefon_nou', 'al_doilea', 'altceva'].includes(c.fel) ? c.fel : 'altceva';
  const text = String(c.text == null ? '' : c.text).replace(/[\u0000-\u0009\u000b-\u001f]/g, ' ').trim().slice(0, 600);
  // o singură cerere deschisă pe telefon + număr: a doua o înlocuiește pe prima
  const toate = await getJSON(urlBroadcast(env, 'mesajeAdmin.json')).catch(() => null) || {};
  const vechi = Object.entries(toate).find(([id, x]) => x && x.cerere && x.nr === nr && x.dev === dev);
  const id = vechi ? vechi[0] : _id12();
  await _fbPut(env, `mesajeAdmin/${id}`, { cerere: motiv, nr, dev, fel, text, la: Date.now(), plat: _txt(c.plat, 20), dep: _txt(c.dep, 20), v: _txt(c.v, 10), ...info });
  const ce = motiv === 'ocupat' ? ({ telefon_nou: 'și-a schimbat telefonul', al_doilea: 'vrea încă un telefon', altceva: 'număr ocupat' }[fel]) : 'e blocat';
  await _anuntaAdminii(env, (motiv === 'ocupat' ? '📵 ' : '🔒 ') + nr + ' — ' + ce, text ? text.slice(0, 120) : 'Rezolvi din panou, De rezolvat.', 'cerere-admin').catch(() => 0);
  return { status: 200, corp: { ok: true } };
}
// Telefonul întreabă dacă s-a rezolvat (cât stă pe ecranul de așteptare).
// ══════════════════════════════════════════════════════════════
// [2.9] BLOCAREA DEFINITIVĂ PRINDE ȘI TELEFONUL
// Blocarea era doar pe număr: cine băga alt număr intra din nou. Acum, la
// blocarea definitivă, telefoanele numărului se notează în blocatiDisp/<amprentă>
// (amprenta telefonului, nu codul lui — codul e ca o parolă). Un telefon notat e
// blocat pe orice număr, cât timp numărul inițial e blocat definitiv: deblocarea
// numărului (din orice loc) sau trecerea pe „număr greșit” îl eliberează singură.
// ══════════════════════════════════════════════════════════════
async function _dispAmprenta(dev) { return (await hashJeton('bloc:' + dev)).slice(0, 24); }
async function _blocDispNoteaza(env, nr, devs) {
  let n = 0;
  for (const d of devs || []) {
    const dev = String(d || '').replace(/[^a-zA-Z0-9-]/g, '').slice(0, 64); if (!dev) continue;
    await _fbPut(env, `blocatiDisp/${await _dispAmprenta(dev)}`, { nr, la: Date.now() }).catch(() => {});
    n++;
  }
  return n;
}
// Telefoanele înregistrate acum pe număr.
async function _blocDispNumar(env, nr) {
  const { disp } = _normalizeaza(await getJSON(urlBroadcast(env, `proprietar/${nr}.json`)).catch(() => null));
  const n = await _blocDispNoteaza(env, nr, Object.keys(disp || {}));
  if (n) await _fbPut(env, `blocati/${nr}/telefoane`, n).catch(() => {});
  return n;
}
// Întoarce blocarea (cu numărul inițial) dacă telefonul e blocat definitiv; altfel null.
async function _dispBlocat(env, dev) {
  if (!dev) return null;
  const h = await _dispAmprenta(dev);
  const rec = await getJSON(urlBroadcast(env, `blocatiDisp/${h}.json`));
  if (!rec || !rec.nr) return null;
  const b = await getJSON(urlBroadcast(env, `blocati/${nrCurat(rec.nr)}.json`));
  if (b && b.fel === 'definitiv') return Object.assign({}, b, { nr: String(rec.nr), prinTelefon: true });
  await _fbPut(env, `blocatiDisp/${h}`, null).catch(() => {});      // numărul a fost deblocat între timp
  return null;
}
async function blocatDisp(request, env) {
  let c; try { c = await request.json(); } catch (e) { return { status: 400, corp: { ok: false } }; }
  const nr = nrCurat(c.nr), dev = String(c.dev || '').replace(/[^a-zA-Z0-9-]/g, '').slice(0, 64);
  if (!dev) return { status: 400, corp: { ok: false } };
  try {
    // Telefonul deschide aplicația cu un număr blocat definitiv: îl notăm și pe el.
    if (nr) {
      const b = await getJSON(urlBroadcast(env, `blocati/${nr}.json`));
      if (b && b.fel === 'definitiv') {
        const h = await _dispAmprenta(dev);
        if (!(await getJSON(urlBroadcast(env, `blocatiDisp/${h}.json`)))) await _blocDispNoteaza(env, nr, [dev]);
        return { status: 200, corp: { ok: true, blocat: Object.assign({}, b, { nr }) } };
      }
    }
    return { status: 200, corp: { ok: true, blocat: await _dispBlocat(env, dev) } };
  } catch (e) { return { status: 503, corp: { ok: false, eroare: 'Nu am putut verifica.' } }; }
}

async function cerereStare(request, env) {
  let c; try { c = await request.json(); } catch (e) { return { status: 400, corp: { ok: false } }; }
  const nr = nrCurat(c.nr), dev = String(c.dev || '').replace(/[^a-zA-Z0-9-]/g, '').slice(0, 64);
  if (!nr || !dev) return { status: 400, corp: { ok: false } };
  if (c.motiv === 'blocat') {
    // [2.9] o citire picată nu mai înseamnă „deblocat”; și telefonul trebuie să fie liber
    try {
      const b = await getJSON(urlBroadcast(env, `blocati/${nr}.json`));
      const bt = await _dispBlocat(env, dev);
      return { status: 200, corp: { ok: true, aprobat: !b && !bt } };
    } catch (e) { return { status: 200, corp: { ok: true, aprobat: false } }; }
  }
  const { disp } = _normalizeaza(await getJSON(urlBroadcast(env, `proprietar/${nr}.json`)).catch(() => null));
  return { status: 200, corp: { ok: true, aprobat: !!disp[dev] } };
}

async function _anuntaAdminii(env, titlu, text, tag) {
  if (!env.VAPID_PUBLIC || !env.VAPID_PRIVATE) return 0;
  let lista = null;
  try { lista = await getJSON(urlBroadcast(env, 'config/adminNotif.json')); } catch (e) { return 0; }
  if (!lista || typeof lista !== 'object') return 0;
  const vapid = { subject: 'mailto:programstb@example.com', publicKey: env.VAPID_PUBLIC, privateKey: env.VAPID_PRIVATE };
  const payload = JSON.stringify({ title: titlu, body: text, tag: tag || 'admin', url: './' });
  let trimise = 0;
  for (const nr of Object.keys(lista)) {
    if (!lista[nr]) continue;
    try {
      const u = await getJSON(urlBroadcast(env, `push/${nr}.json`));
      if (!u) continue;
      const r = await trimiteToate(env, nr, u, payload, { TTL: 86400, urgency: 'high' }, vapid);
      trimise += r.trimise || 0;
    } catch (e) {}
  }
  return trimise;
}

async function numarNou(request, env) {
  if (request.method !== 'POST') return { status: 405, corp: { ok: false, eroare: 'Doar POST' } };
  if (!(await _limitaZi(env, 'numarnou-ip', _ipCheie(request), 20))) return { status: 429, corp: { ok: false, eroare: 'Prea multe încercări azi.' } };
  let c;
  try { c = await request.json(); } catch (e) { return { status: 400, corp: { ok: false, eroare: 'JSON invalid' } }; }
  const nr  = nrCurat(c.nr);
  const dev = String(c.dev || '').replace(/[^a-zA-Z0-9-]/g, '').slice(0, 64);
  if (!nr || !dev) return { status: 400, corp: { ok: false, eroare: 'Lipsește numărul sau telefonul' } };

  let b = null;
  try { b = await getJSON(urlBroadcast(env, `blocati/${nr}.json`)); }
  catch (e) { return { status: 503, corp: { ok: false, eroare: 'Nu am putut verifica. Încearcă din nou.' } }; }
  if (!b) return { status: 200, corp: { ok: false, stare: 'neblocat', eroare: 'Numărul nu mai e blocat.' } };
  if (b.fel === 'definitiv') return { status: 403, corp: { ok: false, stare: 'definitiv', eroare: 'Blocarea e definitivă. Poți doar să-i scrii adminului.' } };   // [2.1]
  if (!(await _telefonulAreVoie(env, nr, dev))) {
    await new Promise(r => setTimeout(r, 400));
    return { status: 403, corp: { ok: false, eroare: 'Telefonul ăsta nu e înregistrat pe numărul ' + nr } };
  }

  if (c.tip === 'gata') {
    // Telefonul s-a mutat pe numărul aprobat: curățăm numărul vechi.
    if (!b.aprobat || b.aprobat.dev !== dev) return { status: 200, corp: { ok: false, eroare: 'Nicio mutare aprobată' } };
    await fetch(urlBroadcast(env, `blocati/${nr}.json`), { method: 'DELETE' }).catch(() => {});
    await fetch(urlBroadcast(env, `push/${nr}.json`), { method: 'DELETE' }).catch(() => {});
    await fetch(urlBroadcast(env, `proprietar/${nr}/disp/${dev}.json`), { method: 'DELETE' }).catch(() => {});
    return { status: 200, corp: { ok: true } };
  }

  // tip: 'cere'
  const nou = nrCurat(c.nou);
  if (!nou || nou.length < 4 || nou.length > 6 || nou === nr) return { status: 400, corp: { ok: false, eroare: 'Număr nou greșit' } };
  if (b.aprobat) return { status: 200, corp: { ok: false, eroare: 'Ai deja o mutare aprobată. Deschide aplicația din nou.' } };
  let bNou = null;
  try { bNou = await getJSON(urlBroadcast(env, `blocati/${nou}.json`)); } catch (e) {}
  if (bNou) return { status: 200, corp: { ok: false, eroare: `Și ${nou} e blocat.` } };
  let prop = null;
  try { prop = await getJSON(urlBroadcast(env, `proprietar/${nou}.json`)); } catch (e) { return { status: 503, corp: { ok: false, eroare: 'Nu am putut citi telefonele numărului. Încearcă din nou.' } }; }
  const { locuri, disp } = _normalizeaza(prop);
  if (!disp[dev] && Object.keys(disp).length >= locuri && Object.keys(disp).length > 0) {
    return { status: 200, corp: { ok: false, stare: 'ocupat', eroare: `${nou} e deja folosit pe alt telefon.` } };
  }
  const cerere = { nr: nou, la: Date.now(), dev };
  const r = await fetch(urlBroadcast(env, `blocati/${nr}/cerere.json`), {
    method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(cerere)
  });
  if (!r.ok) return { status: 502, corp: { ok: false, eroare: 'Nu am putut salva cererea' } };
  // Adminul află pe loc — altfel cererea putea sta zile întregi neobservată.
  try {
    await _anuntaAdminii(env, '🔒 Cerere de aprobare',
      `${nr} (blocat) cere să treacă pe numărul ${nou}. Deschide panoul de admin → Colegi blocați.`, 'cerere-nr-' + nr);
  } catch (e) {}
  return { status: 200, corp: { ok: true, cerere } };
}

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

// ── JETOANE DE TELEFON (intrare cu amprenta) ──
// În Firebase păstrăm doar amprenta criptografică a jetonului, niciodată
// jetonul în clar: dacă cineva citește baza, tot nu poate intra cu el.
async function hashJeton(j) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(j));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function idJeton(j) { return j.slice(0, 16); }

// ══════════════════════════════════════════════════════════════
// [v11.13] RESPONSABILI DE REPARTIZARE
//
// Câte un om de la fiecare depou poate urca singur repartizarea lunară, fără
// parola de admin. Primește un cod scurt (ex. K7M2-Q9XP), legat de numărul
// lui și de depourile lui. Cu codul poate face DOAR două lucruri: să intre
// (verifica) și să urce repartizarea pentru depourile lui — fără ștergere.
// În Firebase stă doar amprenta (hash) codului, în /repartitori/<id>.
// Regula Firebase: "repartitori": { ".read": false, ".write": false }.
// ══════════════════════════════════════════════════════════════
const REP_ALFABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
function codRepCurat(x) {
  const c = String(x || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  return /^[A-Z0-9]{8}$/.test(c) ? c : null;
}
async function idRep(cod) { return (await hashJeton('rep:' + cod)).slice(0, 16); }
async function repartitorValid(env, cod) {
  try {
    const id = await idRep(cod);
    const r = await fetch(urlBroadcast(env, `repartitori/${id}.json`), { headers: { 'Cache-Control': 'no-cache' } });
    if (!r.ok) return 'necunoscut';
    const d = await r.json().catch(() => null);
    if (!d || !d.hash) return 'nu';
    if (!paroleEgale(await hashJeton('rep:' + cod), String(d.hash))) return 'nu';
    // [v11.15] Cu `await`: un fetch lăsat neașteptat se taie în Cloudflare
    // când pleacă răspunsul, deci „folosit ultima oară" nu se scria niciodată.
    try {
      await fetch(urlBroadcast(env, `repartitori/${id}/ultima.json`), {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(Date.now())
      });
    } catch (e) {}
    return { id, nr: d.nr || '', nume: d.nume || '', depouri: Array.isArray(d.depouri) ? d.depouri : [],
      drepturi: _drepturi(d.drepturi), autobaze: _autobaze(d.autobaze),
      vechi: Array.isArray(d.vechi) ? d.vechi.map(String).slice(-10) : [] };
  } catch (e) { return 'necunoscut'; }
}

// [FIX v12.9] Întoarce 'da' / 'nu' / 'necunoscut', nu doar adevărat-fals.
// Înainte, ORICE eșec — Firebase pică o secundă, rețeaua sughiță — ieșea ca
// „jeton invalid", aplicația primea 401 și ȘTERGEA jetonul din telefon pe
// veci. De aici venea „intrarea cu amprenta nu rămâne activă": o singură
// eroare trecătoare desființa înregistrarea și trebuia iar parola.
// „necunoscut" înseamnă doar că n-am putut verifica acum; jetonul rămâne.
// [v14.4] Motivul exact al eșecului ajunge în `_motivJeton`, ca panoul să
// spună CE a stricat verificarea în loc de „nu am putut". Cauza tipică:
// nodul `adminJetoane` e închis în regulile Firebase, iar worker-ul n-are
// `FB_SECRET` setat în Cloudflare, deci nu trece de reguli.
let _motivJeton = '';
async function jetonValid(env, jeton, out) {
  _motivJeton = '';
  if (!jeton || jeton.length < 32 || !/^[0-9a-f]+$/.test(jeton)) return 'nu';
  let r;
  try {
    r = await fetch(urlBroadcast(env, `adminJetoane/${idJeton(jeton)}.json`), { headers: { 'Cache-Control': 'no-cache' } });
  } catch (e) {
    _motivJeton = 'nu am ajuns la Firebase (' + (e.message || 'rețea') + ')';
    return 'necunoscut';
  }
  if (r.status === 401 || r.status === 403) {
    _motivJeton = `Firebase refuză citirea lui adminJetoane (${r.status})` +
      (env.FB_SECRET ? ' — verifică FB_SECRET și regulile' : ' — FB_SECRET nu e setat în Cloudflare');
    return 'necunoscut';
  }
  if (r.status >= 500) { _motivJeton = `Firebase indisponibil (${r.status})`; return 'necunoscut'; }
  if (!r.ok) { _motivJeton = `Firebase a răspuns ${r.status}`; return 'necunoscut'; }
  let d;
  try { d = await r.json(); } catch (e) { _motivJeton = 'răspuns ilizibil de la Firebase'; return 'necunoscut'; }
  if (d === null) return 'nu';                // jetonul chiar a fost anulat din panou
  if (!d || !d.hash) return 'nu';
  const h = await hashJeton(jeton);
  if (!paroleEgale(h, String(d.hash))) return 'nu';
  if (out) out.d = d;          // [2.3] ca admin() să vadă dacă jetonul e al adminului 2
  // Reînnoim ultima folosire, ca să vezi în panou care telefon mai e activ
  fetch(urlBroadcast(env, `adminJetoane/${idJeton(jeton)}/ultima.json`), {
    method: 'PUT', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(Date.now())
  }).catch(() => {});
  return 'da';
}

// ══════════════════════════════════════════════════════════════
// [2.5] ZILE PE ALTE DEPOURI
// Telefonul ține programul fiecărui depou pe care s-a completat ceva: teste,
// depou schimbat, programe de colegi aduse cu versiuni vechi. Adminul le poate
// șterge. Ștergerea se ține minte în backup/<nr>/sterse/<depou> = momentul ei:
// la fiecare salvare a telefonului, zilele mai vechi de momentul ăla nu mai
// intră în cloud, iar telefonul primește `curata` și le șterge și el.
// Zilele completate DUPĂ ștergere (ex. s-a mutat chiar acolo) rămân.
// ══════════════════════════════════════════════════════════════
function _bkZile(v) {
  if (!v) return null;
  let o; try { o = typeof v === 'string' ? JSON.parse(v) : v; } catch (e) { return null; }
  return o && typeof o === 'object' ? o : null;
}
function _bkIso(k) { const p = String(k).split('-').map(Number); return p.length === 3 && p[0] ? `${p[0]}-${String(p[1]).padStart(2, '0')}-${String(p[2]).padStart(2, '0')}` : ''; }
function _bkRezumat(o) {
  const x = { zile: 0, prima: null, ultima: null, luni: {} };
  for (const [zi, v] of Object.entries(o || {})) {
    if (!v || typeof v !== 'object' || !v.t || v.t === 'gol') continue;
    const z = _bkIso(zi); if (!z) continue;
    x.zile++;
    const l = z.slice(0, 7); x.luni[l] = (x.luni[l] || 0) + 1;
    if (!x.prima || z < x.prima) x.prima = z;
    if (!x.ultima || z > x.ultima) x.ultima = z;
  }
  return x;
}
// [2.5.1] Unde lucrează omul. Înainte câștiga depoul „marcat" de telefon, iar
// versiunile vechi îl marcau greșit (ex. Dudești cu o zi, deși are 32 la Titan).
// Acum, în ordine: 1) depoul pe a cărui repartizare (luna asta sau trecută)
// apare numărul lui; 2) depoul cu cele mai multe zile în ultimele 60 de zile;
// 3) abia apoi marcajul telefonului.
function _bkLucru(depouri, marcat, peFoaie) {
  const D = Object.entries(depouri || {});
  if (!D.length) return { lucru: null, motiv: null };
  const foaie = D.filter(([dep]) => (peFoaie || []).includes(dep)).sort((a, b) => b[1].zile - a[1].zile);
  if (foaie.length) return { lucru: foaie[0][0], motiv: 'foaie' };
  const prag = new Date(Date.now() - 60 * 864e5).toISOString().slice(0, 7);
  const recent = x => Object.entries(x.luni || {}).filter(([l]) => l >= prag).reduce((a, [, v]) => a + v, 0);
  let best = null, bestN = 0;
  for (const [dep, x] of D) { const n = recent(x); if (n > bestN || (n === bestN && n > 0 && dep === marcat)) { best = dep; bestN = n; } }
  if (best) return { lucru: best, motiv: 'zile' };
  if (marcat && depouri[marcat]) return { lucru: marcat, motiv: 'marcat' };
  return { lucru: D.sort((a, b) => b[1].zile - a[1].zile)[0][0], motiv: 'zile' };
}
// Numerele de pe repartizările urcate, luna asta și luna trecută: { depou: Set(nr) }.
async function _repNumere(env, strict) {
  const a = acumRo().data; const [an, lu] = a.split('-').map(Number);
  const luni = [`${an}-${String(lu).padStart(2, '0')}`, lu === 1 ? `${an - 1}-12` : `${an}-${String(lu - 1).padStart(2, '0')}`];
  const out = {};
  await Promise.all(DEPOURI.flatMap(dep => luni.map(async l => {
    try {
      const u = urlBroadcast(env, `repartizare/${dep}/${l}/lunara.json`);
      const k = await getJSON(u + (u.includes('?') ? '&' : '?') + 'shallow=true');
      if (k && typeof k === 'object') { out[dep] = out[dep] || new Set(); Object.keys(k).forEach(n => out[dep].add(n)); }
    } catch (e) { if (strict) throw e; }
  })));
  return out;
}
function _peFoaie(rep, nr) { return Object.keys(rep || {}).filter(dep => rep[dep].has(String(nr))); }
// Programul pe depouri + depoul unde lucrează.
function _bkProgram(b, peFoaie) {
  const d = (b && b.data) || {};
  const obiecte = {}, depouri = {};
  for (const dep of DEPOURI) {
    const o = _bkZile(d['p2026_' + dep]); if (!o) continue;
    const x = _bkRezumat(o);
    if (x.zile) { obiecte[dep] = o; depouri[dep] = x; }
  }
  const marcat = (b && (b.depotLucru || b.depotPropriu)) || null;
  const { lucru, motiv } = _bkLucru(depouri, marcat, peFoaie);
  return { obiecte, depouri, lucru, motiv, marcat, peFoaie: peFoaie || [] };
}
// Semnătura unei zile lucrate (tur/linie/oră); liberele și CO nu contează la „copie".
function _bkSemn(v) {
  if (!v || typeof v !== 'object' || !['zl', 'we', 'sarb'].includes(v.t)) return null;
  const m = v._manual || {};
  if (!v.r && !m.tur && !m.linie) return null;
  return [v.r || '', m.tur || '', m.linie || '', m.i || '', v.s || ''].join('|');
}
// A e copia lui B dacă cel puțin 80% din zilele lucrate ale lui A (minim 5) sunt identice în B.
function _bkECopie(oA, oB) {
  let n = 0, egal = 0;
  for (const [zi, v] of Object.entries(oA || {})) {
    const sa = _bkSemn(v); if (!sa) continue;
    n++;
    if (oB && _bkSemn(oB[zi]) === sa) egal++;
  }
  return n >= 5 && egal >= 0.8 * n;
}
// Ziua A[dep] e copia programului lui Y dacă se potrivesc turele (vezi _bkECopie)
// și Y e „proprietarul" acelui program: l-a ales în telefon sau are mai multe zile acolo.
function _bkECopieDe(A, dep, Y) {
  const a = A.obiecte[dep], y = Y.obiecte[dep];
  if (!a || !y || !Y.depouri[dep] || !A.depouri[dep]) return false;
  if (A.marcat === dep ? !(Y.depouri[dep].zile > A.depouri[dep].zile) : !(Y.marcat === dep || Y.depouri[dep].zile > A.depouri[dep].zile)) return false;
  return _bkECopie(a, y);
}
// Depoul unde lucrează, fără depourile care sunt copia programului altcuiva.
function _bkFinal(p, copii) {
  p.copii = copii || {};
  const fara = Object.fromEntries(Object.entries(p.depouri).filter(([d]) => !p.copii[d]));
  const L = _bkLucru(Object.keys(fara).length ? fara : p.depouri, p.marcat, p.peFoaie);
  p.lucru = L.lucru; p.motiv = L.motiv;
  return p;
}
// Analiza completă pentru un singur om: repartizarea + copiile din programele colegilor.
async function _bkAnaliza(env, nr, bOpt, strict) {
  const [tot, R] = await Promise.all([getJSON(urlBroadcast(env, 'backup.json')).catch(e => { if (strict) throw e; return null; }), _repNumere(env, strict).catch(e => { if (strict) throw e; return {}; })]);
  const b = bOpt || (tot && tot[nr]);
  const p = _bkProgram(b, _peFoaie(R, nr));
  const copii = {};
  for (const dep of Object.keys(p.depouri)) {
    for (const [alt, bb] of Object.entries(tot || {})) {
      if (alt === String(nr) || !bb || !bb.data || !bb.data['p2026_' + dep]) continue;
      const o = _bkZile(bb.data['p2026_' + dep]); if (!o) continue;
      const Y = { marcat: bb.depotLucru || bb.depotPropriu || null, obiecte: { [dep]: o }, depouri: { [dep]: _bkRezumat(o) } };
      if (_bkECopieDe(p, dep, Y)) { copii[dep] = alt; break; }
    }
  }
  return _bkFinal(p, copii);
}
function _bkRecalc(b) {
  let zile = 0;
  for (const v of Object.values(b.data || {})) {
    if (typeof v !== 'string' || !v.startsWith('{')) continue;
    try { zile += Object.keys(JSON.parse(v)).length; } catch (e) {}
  }
  b.zile = zile;
  if (Array.isArray(b.depots)) b.depots = b.depots.filter(d => b.data['p2026_' + d]);
}
// Scoate din `data` zilele depourilor șterse de admin, mai vechi de momentul ștergerii.
function _bkAplicaSterse(data, sterse) {
  let scoase = 0;
  for (const [dep, ts] of Object.entries(sterse || {})) {
    if (!DEPOURI.includes(dep)) continue;
    if (Date.now() - Number(ts) > 60 * 864e5) continue;      // [2.7] după 60 de zile nu mai aplicăm ștergerea
    const k = 'p2026_' + dep;
    if (data[k] == null) continue;
    const o = _bkZile(data[k]); if (!o) continue;
    for (const zi of Object.keys(o)) {
      const z = o[zi];
      if (!(z && typeof z === 'object' && Number(z._m) > Number(ts))) { delete o[zi]; scoase++; }
    }
    if (Object.keys(o).length) data[k] = JSON.stringify(o); else delete data[k];
  }
  return scoase;
}

// ══════════════════════════════════════════════════════════════
// [2.3] ADMIN 2 — un coleg cu acces la tot panoul, cu codul LUI (nu parola).
//
// Codul (9 caractere, ex. K7M-42Q-9XD) e făcut de worker și se arată o singură
// dată. În Firebase stă doar amprenta (hash) lui, în adminJetoane/_admini2/<nr>
// — nod deja închis în reguli, ca nimeni să nu-și poată scrie singur un cod.
// `gen` crește la „Cod nou”: jetoanele de amprentă vechi ale lui nu mai merg.
// Tot ce schimbă el se scrie în adminJetoane/_jurnal/<nr>.
// Doar adminul principal (parola sau jetonul lui) poate face/scoate admini.
// ══════════════════════════════════════════════════════════════
const ADM2_CALE = 'adminJetoane/_admini2';
const ADM2_JURNAL = 'adminJetoane/_jurnal';
function codAdm2Curat(x) {
  const c = String(x || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  return /^[A-Z0-9]{9}$/.test(c) ? c : null;
}
function _adm2CodNou() {
  const b = crypto.getRandomValues(new Uint8Array(9));
  return [...b].map(x => REP_ALFABET[x % REP_ALFABET.length]).join('');
}
function _adm2Afisat(c) { return c.slice(0, 3) + '-' + c.slice(3, 6) + '-' + c.slice(6); }
function _adm2Opriri(o) { o = o || {}; return { definitiv: !!o.definitiv, sterge: !!o.sterge, fortat: !!o.fortat }; }
async function _adm2Toti(env) {
  const r = await fetch(urlBroadcast(env, ADM2_CALE + '.json'), { headers: { 'Cache-Control': 'no-cache' } });
  if (!r.ok) return 'necunoscut';
  return (await r.json().catch(() => null)) || {};
}
async function _adm2DinCod(env, cod) {
  try {
    const toti = await _adm2Toti(env);
    if (toti === 'necunoscut') return 'necunoscut';
    const h = await hashJeton('adm2:' + cod);
    for (const [nr, a] of Object.entries(toti)) {
      if (a && a.hash && paroleEgale(h, String(a.hash))) return Object.assign({ nr }, a, { opriri: _adm2Opriri(a.opriri) });
    }
    return null;
  } catch (e) { return 'necunoscut'; }
}
async function _adm2Citeste(env, nr) {
  try {
    const r = await fetch(urlBroadcast(env, `${ADM2_CALE}/${nr}.json`), { headers: { 'Cache-Control': 'no-cache' } });
    if (!r.ok) return 'necunoscut';
    const a = await r.json().catch(() => null);
    return a ? Object.assign({ nr: String(nr) }, a, { opriri: _adm2Opriri(a.opriri) }) : null;
  } catch (e) { return 'necunoscut'; }
}
// Jetoanele de amprentă ale unui admin 2 (la „Cod nou” și „Taie accesul” pleacă toate).
async function _adm2StergeJetoane(env, nr) {
  let d = null;
  try { d = await getJSON(urlBroadcast(env, 'adminJetoane.json')); } catch (e) {}
  let n = 0;
  for (const [id, v] of Object.entries(d || {})) {
    if (id.startsWith('_')) continue;
    if (v && String(v.adm2 || '') === String(nr)) { await _fbPut(env, `adminJetoane/${id}`, null).catch(() => {}); n++; }
  }
  return n;
}
async function _adm2Scrie(env, nr, cerere, extra) {
  const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 5);
  const e = { la: Date.now(), a: String(cerere.actiune || '').slice(0, 40) };
  const tinta = nrCurat(cerere.nr);
  if (tinta) e.t = tinta;
  const x = extra || _adm2Detaliu(cerere);
  if (x) e.x = String(x).slice(0, 120);
  await _fbPut(env, `${ADM2_JURNAL}/${nr}/${id}`, e).catch(() => {});
}
function _adm2Detaliu(c) {
  switch (c.actiune) {
    case 'blocheaza': case 'blocareFel': return c.fel === 'definitiv' ? 'definitiv' : 'numar';
    case 'repartizare': case 'stergeRepartizare': return [c.depou, c.luna].filter(Boolean).join(' ');
    case 'bandaSeteaza': return c.banda ? _txt(c.banda.text, 80) : 'oprită';
    case 'versiuneMinima': return c.min == null || c.min === '' ? 'oprită' : String(c.min);
    case 'cerereRezolva': return String(c.fa || '');
    case 'stergeDepouDinBackup': return (Array.isArray(c.deps) ? c.deps : [c.dep]).join(', ');
    case 'anunt': case 'anuntEcran': return _txt(c.titlu || c.text || c.mesaj, 80);
    case 'mesajAdminCitit': return c.raspuns ? 'răspuns' : '';
    case 'indicatoriPropune': case 'indicatoriAproba': case 'indicatoriRespinge': case 'indicatoriAnuleaza':
      return String(c.dep || c.depou || c.bazaNume || '');
  }
  return '';
}
// Acțiuni care doar citesc: nu intră în jurnal.
const ADM2_CITIRE = new Set(['verifica', 'cineSunt', 'jetoane', 'indicatoriLista', 'indicatoriMele', 'repStare', 'anunturiCitite',
  'raportOreLista', 'raportOrePoza', 'trimiteriLista', 'trimiteFisier', 'colegiNoi', 'eroriLista', 'mesajeAdminLista',
  'repartitori', 'programeLuni', 'adminNotif', 'adminNotifProba', 'utilizatori', 'rezumatBaza', 'copiiBackup',
  'dispozitive', 'arhive', 'agenda', 'toateDispozitivele', 'cauta', 'fisa', 'programBrut', 'blocati', 'depouriStraine']);
// Doar adminul principal.
const ADM2_INTERZIS = new Set(['adminiLista', 'adminNou', 'adminCodNou', 'adminTaie', 'adminOpriri', 'adminJurnal', 'stergeToateDispozitivele']);
// Acțiuni care nu se pot face pe numărul unui admin.
const ADM2_PROTEJAT = new Set(['blocheaza', 'blocareFel', 'stergeUtilizator', 'reseteazaDispozitiv', 'stergeDispozitiv',
  'scoateLoc', 'readuBackup', 'recupereaza', 'pushStergeNr', 'stergeDepouDinBackup',
  'adaugaLoc', 'aprobaNumar', 'respingeNumar', 'propuneNumar', 'adminNotif', 'cerereRezolva', 'fisa', 'dispozitive', 'programBrut', 'testPush']);

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

  // Intrarea se poate face cu parola SAU cu un jeton de telefon, pe care îl
  // primești o singură dată, după ce ai dat parola corect. Jetonul e legat de
  // telefon, se poate anula oricând din panou, iar parola nu se salvează
  // nicăieri pe telefon — asta e toată ideea.
  const cuParola = paroleEgale(String(cerere.parola || ''), String(env.ADMIN_PASS));
  let stareJeton = 'nu';
  const jd = {};
  if (!cuParola && cerere.jeton) {
    stareJeton = await jetonValid(env, String(cerere.jeton), jd);
  }
  const cuJeton = stareJeton === 'da';

  // Nu am putut verifica jetonul (Firebase indisponibil). 503, nu 401:
  // aplicația trebuie să înțeleagă „încearcă mai târziu", nu „ești dat afară".
  if (!cuParola && stareJeton === 'necunoscut') {
    return { status: 503, corp: { ok: false,
      eroare: 'Nu am putut verifica jetonul' + (_motivJeton ? ': ' + _motivJeton : '. Încearcă din nou.') } };
  }

  // [2.3] Admin 2: cu jetonul lui de amprentă sau cu codul lui.
  let adm2 = null;
  if (cuJeton && jd.d && jd.d.adm2) {
    const a = await _adm2Citeste(env, String(jd.d.adm2));
    if (a === 'necunoscut') return { status: 503, corp: { ok: false, eroare: 'Nu am putut verifica accesul. Încearcă din nou.' } };
    if (!a || Number(a.gen || 1) !== Number(jd.d.gen || 1)) {
      return { status: 401, corp: { ok: false, jetonAnulat: true, eroare: 'Accesul de admin a fost oprit.' } };
    }
    adm2 = a;
  }
  if (!cuParola && !cuJeton) {
    const cod = codAdm2Curat(cerere.adm2 || cerere.parola);
    if (cod) {
      const a = await _adm2DinCod(env, cod);
      if (a === 'necunoscut') return { status: 503, corp: { ok: false, eroare: 'Nu am putut verifica codul. Încearcă din nou.' } };
      if (a) adm2 = a;
    }
  }

  // [v11.13] Responsabil de repartizare: intră cu codul lui (trimis ca `rep`,
  // sau scris în câmpul de parolă). Are voie doar la urcarea repartizării.
  let rep = null;
  if (!cuParola && !cuJeton) {
    const cod = codRepCurat(cerere.rep || cerere.parola);
    if (cod) {
      const v = await repartitorValid(env, cod);
      if (v === 'necunoscut') return { status: 503, corp: { ok: false, eroare: 'Nu am putut verifica codul. Încearcă din nou.' } };
      if (v && v !== 'nu') rep = v;
    }
  }
  if (rep) {
    if (cerere.actiune === 'verifica') {
      return { status: 200, corp: { ok: true, rol: 'repartitor', nr: rep.nr, nume: rep.nume, depouri: rep.depouri, drepturi: rep.drepturi, autobaze: rep.autobaze } };
    }
    // [v11.29] indicatorii de ore: doar cu dreptul „ind", doar pentru depoul lui
    if (cerere.actiune === 'indicatoriPropune' || cerere.actiune === 'indicatoriMele') {
      if (!rep.drepturi.ind) return { status: 403, corp: { ok: false, eroare: 'Codul tău nu are drept la indicatori.' } };
      return await indicatoriActiune(env, cerere, { rep });
    }
    if (cerere.actiune !== 'repartizare' || !rep.drepturi.rep) {
      return { status: 403, corp: { ok: false, eroare: 'Cu codul tău nu ai voie la asta.' } };
    }
    const dep = String(cerere.depou || '').trim().toLowerCase();
    if (!rep.depouri.includes(dep)) {
      return { status: 403, corp: { ok: false, eroare: `Poți urca doar pentru: ${rep.depouri.join(', ') || '—'}.` } };
    }
    cerere.inlocuieste = false;          // responsabilul nu poate șterge luna
    cerere._urcatDe = rep.nr || rep.id;
  }

  if (!cuParola && !cuJeton && !rep && !adm2) {
    // Mică întârziere, ca încercările repetate să nu fie ieftine
    await new Promise(r => setTimeout(r, 400));
    // `jetonAnulat` spune limpede aplicației că jetonul chiar nu mai e bun și
    // poate fi șters din telefon. Fără el, ștergea și la erori trecătoare.
    return {
      status: 401,
      corp: {
        ok: false,
        jetonAnulat: !!cerere.jeton,
        eroare: cerere.jeton ? 'Jeton anulat sau expirat' : 'Parolă greșită'
      }
    };
  }

  // Un jeton nu poate crea alte jetoane: pentru asta trebuie parola.
  // [2.3] Adminul 2, intrat cu codul lui, își poate face jeton pentru amprentă.
  if (cerere.actiune === 'jetonNou' && !cuParola && !(adm2 && !cuJeton)) {
    // [v4.5] `cerereParola`: aplicația știe că nu e o respingere a accesului și
    // nu mai scoate toată sesiunea de amprentă din cauza unei singure acțiuni.
    return { status: 401, corp: { ok: false, cerereParola: true, eroare: 'Pentru asta trebuie parola.' } };
  }

  // [2.3] Ce are voie adminul 2
  if (adm2) {
    const a = cerere.actiune;
    if (ADM2_INTERZIS.has(a)) return { status: 403, corp: { ok: false, eroare: 'Doar adminul principal poate face asta.' } };
    const o = adm2.opriri;
    if (o.definitiv && (a === 'blocheaza' || a === 'blocareFel') && cerere.fel === 'definitiv')
      return { status: 403, corp: { ok: false, eroare: 'Blocarea definitivă e oprită pentru tine. Folosește „număr greșit”.' } };
    if (o.sterge && (a === 'stergeUtilizator' || a === 'stergeToateDispozitivele' || a === 'stergeDepouDinBackup'))
      return { status: 403, corp: { ok: false, eroare: 'Ștergerea datelor e oprită pentru tine.' } };
    if (o.fortat && a === 'versiuneMinima')
      return { status: 403, corp: { ok: false, eroare: 'Actualizarea obligatorie e oprită pentru tine.' } };
    if (ADM2_PROTEJAT.has(a)) {
      let tinta = nrCurat(cerere.nr);
      if (a === 'cerereRezolva') {          // numărul e în cerere, nu în ce trimite panoul
        const id = String(cerere.id || '').replace(/[^a-z0-9]/g, '').slice(0, 20);
        const m = id ? await getJSON(urlBroadcast(env, `mesajeAdmin/${id}.json`)).catch(() => null) : null;
        tinta = m ? nrCurat(m.nr) : null;
      }
      let principal = null;
      try { principal = await getJSON(urlBroadcast(env, 'config/adminPrincipal.json')); } catch (e) {}
      const toti = await _adm2Toti(env).catch(() => ({}));
      if (tinta && (String(principal || '') === tinta || (toti && toti !== 'necunoscut' && toti[tinta] && tinta !== adm2.nr)))
        return { status: 403, corp: { ok: false, eroare: 'Nu poți face asta pe numărul unui admin.' } };
    }
    cerere.de = 'admin 2 · ' + adm2.nr;
    cerere._urcatDe = 'admin 2 · ' + adm2.nr;
    // ultima folosire
    await _fbPut(env, `${ADM2_CALE}/${adm2.nr}/ultima`, Date.now()).catch(() => {});
  }

  const rez = await (async () => { switch (cerere.actiune) {
    // ── [2.3] Cine e intrat (rol) — panoul îl întreabă la deschidere ──
    case 'cineSunt': {
      if (adm2) {
        if (Date.now() - Number(adm2.intrat || 0) > 15 * 60000) {
          await _fbPut(env, `${ADM2_CALE}/${adm2.nr}/intrat`, Date.now()).catch(() => {});
          await _adm2Scrie(env, adm2.nr, { actiune: 'intrare' });
        }
        return { status: 200, corp: { ok: true, rol: 'admin2', nr: adm2.nr, opriri: adm2.opriri } };
      }
      const eu = nrCurat(cerere.eu);
      if (eu && (cuParola || cuJeton)) await _fbPut(env, 'config/adminPrincipal', eu).catch(() => {});
      return { status: 200, corp: { ok: true, rol: 'admin' } };
    }

    // ── [2.5] Zile pe alte depouri ──
    case 'depouriStraine': {
      const doarNr = nrCurat(cerere.nr);
      let tot = null;
      try { tot = await getJSON(urlBroadcast(env, 'backup.json')); }
      catch (e) { return { status: 502, corp: { ok: false, eroare: 'Nu am putut citi programele.' } }; }
      const R = await _repNumere(env);
      const P = {};
      for (const [nr, b] of Object.entries(tot || {})) { try { P[nr] = _bkProgram(b, _peFoaie(R, nr)); } catch (e) {} }
      // copiile se caută doar la cei cu mai multe depouri (ceilalți n-au ce șterge)
      for (const [nr, p] of Object.entries(P)) {
        if (Object.keys(p.depouri).length < 2) { p.copii = {}; continue; }
        const copii = {};
        for (const dep of Object.keys(p.depouri)) {
          for (const [alt, q] of Object.entries(P)) { if (alt !== nr && _bkECopieDe(p, dep, q)) { copii[dep] = alt; break; } }
        }
        _bkFinal(p, copii);
      }
      const lista = [];
      for (const [nr, p] of Object.entries(P)) {
        if (doarNr && nr !== doarNr) continue;
        const straine = [];
        for (const [dep, x] of Object.entries(p.depouri)) {
          if (dep === p.lucru) continue;
          straine.push({ dep, zile: x.zile, prima: x.prima, ultima: x.ultima, copieDe: (p.copii || {})[dep] || null, peFoaie: p.peFoaie.includes(dep) });
        }
        if (straine.length) lista.push({ nr, lucru: p.lucru, motiv: p.motiv, straine });
      }
      lista.sort((a, b) => (b.straine.some(x => x.copieDe) - a.straine.some(x => x.copieDe)) || (b.straine.reduce((s, x) => s + x.zile, 0) - a.straine.reduce((s, x) => s + x.zile, 0)));
      return { status: 200, corp: { ok: true, lista } };
    }
    case 'stergeDepouDinBackup': {
      const nr = nrCurat(cerere.nr);
      if (!nr) return { status: 400, corp: { ok: false, eroare: 'Număr de serviciu lipsă' } };
      let b;
      try { b = await getJSON(urlBroadcast(env, `backup/${nr}.json`)); }
      catch (e) { return { status: 502, corp: { ok: false, eroare: 'Nu am putut citi programul lui.' } }; }
      if (!b || !b.data) return { status: 404, corp: { ok: false, eroare: 'N-are program în cloud.' } };
      let p;
      try { p = await _bkAnaliza(env, nr, b, true); }
      catch (e) { return { status: 503, corp: { ok: false, eroare: 'Nu am putut verifica repartizarea și programele colegilor. Încearcă din nou.' } }; }
      const vrea = (Array.isArray(cerere.deps) ? cerere.deps : [cerere.dep]).map(x => String(x || '').toLowerCase()).filter(x => DEPOURI.includes(x));
      const deps = vrea.filter(d => d !== p.lucru && !p.peFoaie.includes(d));
      if (!deps.length) return { status: 400, corp: { ok: false, eroare: vrea.length ? 'Ăsta e depoul unde lucrează (sau e pe repartizarea lui) — nu se șterge.' : 'Alege depoul.' } };
      try { await _copieZilnica(env, nr, b); } catch (e) {}       // ca să se poată readuce din „Copii de siguranță"
      const acum = Date.now();
      let zile = 0;
      b.sterse = Object.assign({}, b.sterse && typeof b.sterse === 'object' ? b.sterse : {});
      for (const dep of deps) {
        zile += (p.depouri[dep] && p.depouri[dep].zile) || 0;
        delete b.data['p2026_' + dep];
        b.sterse[dep] = acum;
      }
      _bkRecalc(b);
      const r = await fetch(urlBroadcast(env, `backup/${nr}.json`), { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) });
      if (!r.ok) { const t = await r.text().catch(() => ''); return { status: 502, corp: { ok: false, eroare: `Firebase ${r.status} ${t.slice(0, 120)}` } }; }
      return { status: 200, corp: { ok: true, nr, deps, zile, lucru: p.lucru } };
    }

    // ── [2.3] Administratori (doar adminul principal) ──
    case 'adminiLista': {
      const toti = await _adm2Toti(env);
      if (toti === 'necunoscut') return { status: 502, corp: { ok: false, eroare: 'Nu am putut citi lista.' } };
      let jet = null;
      try { jet = await getJSON(urlBroadcast(env, 'adminJetoane.json')); } catch (e) {}
      const tel = {};
      for (const [id, v] of Object.entries(jet || {})) if (!id.startsWith('_') && v && v.adm2) tel[v.adm2] = (tel[v.adm2] || 0) + 1;
      const lista = Object.entries(toti).map(([nr, a]) => ({ nr, creat: a.creat || 0, codLa: a.codLa || 0, ultima: a.ultima || 0,
        opriri: _adm2Opriri(a.opriri), telefoane: tel[nr] || 0 })).sort((x, y) => x.creat - y.creat);
      return { status: 200, corp: { ok: true, lista } };
    }
    case 'adminNou': case 'adminCodNou': {
      const nr = nrCurat(cerere.nr);
      if (!nr) return { status: 400, corp: { ok: false, eroare: 'Scrie numărul de serviciu.' } };
      const vechi = await _adm2Citeste(env, nr);
      if (vechi === 'necunoscut') return { status: 502, corp: { ok: false, eroare: 'Nu am putut verifica. Încearcă din nou.' } };
      if (cerere.actiune === 'adminNou' && vechi) return { status: 409, corp: { ok: false, eroare: `${nr} e deja admin. Dacă a pierdut codul, apasă „Cod nou”.` } };
      if (cerere.actiune === 'adminCodNou' && !vechi) return { status: 404, corp: { ok: false, eroare: `${nr} nu mai e admin.` } };
      const eu = nrCurat(cerere.eu);
      if (eu && eu === nr) return { status: 400, corp: { ok: false, eroare: 'Ăsta e numărul tău.' } };
      if (eu) await _fbPut(env, 'config/adminPrincipal', eu).catch(() => {});
      const cod = _adm2CodNou();
      const a = vechi ? { hash: vechi.hash, gen: vechi.gen, creat: vechi.creat, ultima: vechi.ultima || 0, opriri: vechi.opriri } :
        { creat: Date.now(), ultima: 0, gen: 0, opriri: _adm2Opriri() };
      a.hash = await hashJeton('adm2:' + cod);
      a.gen = Number(a.gen || 0) + 1;
      a.codLa = Date.now();
      const r = await fetch(urlBroadcast(env, `${ADM2_CALE}/${nr}.json`), { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(a) });
      if (!r.ok) { const d = await r.text().catch(() => ''); return { status: 502, corp: { ok: false, eroare: `Firebase ${r.status} ${d.slice(0, 120)}` } }; }
      if (vechi) await _adm2StergeJetoane(env, nr);
      // Codul în clar se întoarce O SINGURĂ DATĂ.
      return { status: 200, corp: { ok: true, nr, cod: _adm2Afisat(cod) } };
    }
    case 'adminTaie': {
      const nr = nrCurat(cerere.nr);
      if (!nr) return { status: 400, corp: { ok: false, eroare: 'Număr lipsă' } };
      await _fbPut(env, `${ADM2_CALE}/${nr}`, null);
      const n = await _adm2StergeJetoane(env, nr);
      await _fbPut(env, `config/adminNotif/${nr}`, null).catch(() => {});
      await _adm2Scrie(env, nr, { actiune: 'scos' });
      return { status: 200, corp: { ok: true, nr, telefoane: n } };
    }
    case 'adminOpriri': {
      const nr = nrCurat(cerere.nr);
      const a = nr ? await _adm2Citeste(env, nr) : null;
      if (!a || a === 'necunoscut') return { status: 404, corp: { ok: false, eroare: 'Nu mai e admin.' } };
      const o = _adm2Opriri(cerere.opriri);
      await _fbPut(env, `${ADM2_CALE}/${nr}/opriri`, o);
      return { status: 200, corp: { ok: true, nr, opriri: o } };
    }
    case 'adminJurnal': {
      const nr = nrCurat(cerere.nr);
      if (!nr) return { status: 400, corp: { ok: false, eroare: 'Număr lipsă' } };
      let d = null;
      try { d = await getJSON(urlBroadcast(env, `${ADM2_JURNAL}/${nr}.json`)); } catch (e) {}
      const lista = Object.values(d || {}).filter(x => x && x.la).sort((a, b) => b.la - a.la).slice(0, 200);
      return { status: 200, corp: { ok: true, nr, lista } };
    }

    // ── Jeton nou pentru telefonul ăsta (cere parola) ──
    case 'jetonNou': {
      const jeton = [...crypto.getRandomValues(new Uint8Array(32))]
        .map(b => b.toString(16).padStart(2, '0')).join('');
      const hash = await hashJeton(jeton);
      const r = await fetch(urlBroadcast(env, `adminJetoane/${idJeton(jeton)}.json`), {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          hash, creat: Date.now(), ultima: Date.now(),
          nume: String(cerere.nume || 'telefon').slice(0, 40),
          ...(adm2 ? { adm2: adm2.nr, gen: Number(adm2.gen || 1) } : {})
        })
      });
      if (!r.ok) {
        const d = await r.text().catch(() => '');
        return { status: 502, corp: { ok: false, eroare: `Firebase ${r.status} ${d.slice(0, 120)}` } };
      }
      // Jetonul în clar se întoarce O SINGURĂ DATĂ, acum; nu se mai poate citi.
      return { status: 200, corp: { ok: true, jeton, id: idJeton(jeton), rol: adm2 ? 'admin2' : 'admin', nr: adm2 ? adm2.nr : undefined } };
    }

    // ── Ce telefoane pot intra fără parolă ──
    case 'jetoane': {
      const r = await fetch(urlBroadcast(env, 'adminJetoane.json'), { headers: { 'Cache-Control': 'no-cache' } });
      const d = r.ok ? (await r.json().catch(() => null)) : null;
      const lista = Object.entries(d || {})
        .filter(([id, v]) => !id.startsWith('_') && (adm2 ? String((v && v.adm2) || '') === adm2.nr : true))
        .map(([id, v]) => ({
        id, nume: (v && v.nume) || 'telefon', adm2: (v && v.adm2) || '',
        creat: (v && v.creat) || 0, ultima: (v && v.ultima) || 0
      })).sort((a, b) => b.ultima - a.ultima);
      return { status: 200, corp: { ok: true, lista } };
    }

    // ── Anulează accesul unui telefon ──
    case 'jetonSterge': {
      const id = String(cerere.id || '').slice(0, 16);
      if (!id || !/^[0-9a-f]{16}$/.test(id)) return { status: 400, corp: { ok: false, eroare: 'Lipsește id-ul' } };
      if (adm2) {
        let v = null;
        try { v = await getJSON(urlBroadcast(env, `adminJetoane/${id}.json`)); } catch (e) {}
        if (!v || String(v.adm2 || '') !== adm2.nr) return { status: 403, corp: { ok: false, eroare: 'Poți scoate doar telefoanele tale.' } };
      }
      const r = await fetch(urlBroadcast(env, `adminJetoane/${id}.json`), { method: 'DELETE' });
      if (!r.ok) {
        const d = await r.text().catch(() => '');
        return { status: 502, corp: { ok: false, eroare: `Firebase ${r.status} ${d.slice(0, 120)}` } };
      }
      return { status: 200, corp: { ok: true, id } };
    }

    case 'verifica':
      return { status: 200, corp: adm2 ? { ok: true, rol: 'admin2', nr: adm2.nr } : { ok: true } };

    // ── [v11.13] Responsabili de repartizare ──
    case 'repartitorNou': {
      const nr = nrCurat(cerere.nr);
      if (!nr) return { status: 400, corp: { ok: false, eroare: 'Scrie numărul de serviciu.' } };
      const depouri = (Array.isArray(cerere.depouri) ? cerere.depouri : []).map(x => String(x).toLowerCase()).filter(x => DEPOURI.includes(x));
      if (!depouri.length) return { status: 400, corp: { ok: false, eroare: 'Alege cel puțin un depou.' } };
      const b = crypto.getRandomValues(new Uint8Array(8));
      const cod = [...b].map(x => REP_ALFABET[x % REP_ALFABET.length]).join('');
      const id = await idRep(cod);
      const r = await fetch(urlBroadcast(env, `repartitori/${id}.json`), {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hash: await hashJeton('rep:' + cod), nr, nume: String(cerere.nume || '').slice(0, 40),
          depouri, creat: Date.now(), ultima: 0, autobaze: depouri.includes('autobuze') ? _autobaze(cerere.autobaze) : [],
          drepturi: { rep: !(cerere.drepturi && cerere.drepturi.rep === false), ind: !!(cerere.drepturi && cerere.drepturi.ind) } })
      });
      if (!r.ok) { const d = await r.text().catch(() => ''); return { status: 502, corp: { ok: false, eroare: `Firebase ${r.status} ${d.slice(0, 120)}` } }; }
      // Codul în clar se întoarce O SINGURĂ DATĂ.
      return { status: 200, corp: { ok: true, id, cod: cod.slice(0, 4) + '-' + cod.slice(4), nr, depouri } };
    }
    case 'indicatoriPropune': case 'indicatoriLista': case 'indicatoriAproba':
    case 'indicatoriRespinge': case 'indicatoriAnuleaza': case 'indicatoriAscunde':
      return await indicatoriActiune(env, cerere, { admin: true });
    // [v11.34] Cod nou pentru același responsabil (a pierdut codul, telefon nou).
    // Codul vechi nu mai merge; drepturile, depourile și istoricul rămân.
    // ── [1.0] Foile urcate pe luni (și numerele de pe foaie, pentru acoperire) ──
    case 'repStare': {
      const luni = (Array.isArray(cerere.luni) ? cerere.luni : []).filter(l => /^\d{4}-\d{2}$/.test(l)).slice(0, 3);
      const cuNumere = /^\d{4}-\d{2}$/.test(cerere.cuNumere || '') ? cerere.cuNumere : '';
      const out = {};
      for (const dep of DEPOURI) {
        out[dep] = {};
        for (const l of luni) out[dep][l] = await _repStareLuna(env, dep, l, l === cuNumere);
      }
      let amintit = null;
      try { amintit = await getJSON(urlBroadcast(env, 'config/repAmintit.json')); } catch (e) {}
      let oprit = null;
      try { oprit = await getJSON(urlBroadcast(env, 'config/repAmintireOprita.json')); } catch (e) {}
      return { status: 200, corp: { ok: true, stare: out, amintit: amintit || {}, amintireOprita: !!oprit } };
    }
    case 'repAminteste': {
      const luna = /^\d{4}-\d{2}$/.test(cerere.luna || '') ? cerere.luna : null;
      if (!luna) return { status: 400, corp: { ok: false, eroare: 'Luna lipsește' } };
      const dep = (Array.isArray(cerere.depouri) ? cerere.depouri : []).map(String).filter(d => DEPOURI.includes(d));
      const r = await _repAminteste(env, dep, luna);
      return { status: 200, corp: { ok: true, ...r } };
    }
    case 'repAmintireOprita': {
      await fetch(urlBroadcast(env, 'config/repAmintireOprita.json'), { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(cerere.oprita ? true : null) });
      return { status: 200, corp: { ok: true } };
    }
    // ── [1.0] Câți au citit fiecare anunț ──
    case 'anunturiCitite': {
      const u = urlBroadcast(env, 'anuntCitit.json');
      let d = null;
      try { d = await getJSON(u); } catch (e) {}
      const out = {};
      for (const [id, v] of Object.entries(d || {})) out[id] = v && typeof v === 'object' ? Object.keys(v) : [];
      return { status: 200, corp: { ok: true, citite: out } };
    }
    // ── [1.0] Actualizare forțată ──
    case 'versiuneMinima': {
      const min = cerere.min === null || cerere.min === '' ? null : String(cerere.min).trim();
      if (min !== null && !/^\d{1,3}\.\d{1,3}$/.test(min)) return { status: 400, corp: { ok: false, eroare: 'Scrie versiunea ca 1.0' } };
      await fetch(urlBroadcast(env, 'config/versiuneMinima.json'), { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(min) });
      return { status: 200, corp: { ok: true, min } };
    }
    // ── [1.2] Banda de avertizare ──
    case 'bandaSeteaza': {
      const b = cerere.banda;
      if (!b) { await _fbPut(env, 'config/banda', null); return { status: 200, corp: { ok: true, banda: null } }; }
      const v = { text: _txt(b.text, 200), tip: ['ore', 'mesaj'].includes(b.tip) ? b.tip : 'text', culoare: ['galben', 'rosu', 'albastru'].includes(b.culoare) ? b.culoare : 'galben',
        tinta: (Array.isArray(b.tinta) ? b.tinta : ['all']).map(String).filter(d => d === 'all' || DEPOURI.includes(d)).slice(0, 12), la: Date.now() };
      if (!v.text) return { status: 400, corp: { ok: false, eroare: 'Scrie textul benzii.' } };
      if (!v.tinta.length) v.tinta = ['all'];
      await _fbPut(env, 'config/banda', v);
      return { status: 200, corp: { ok: true, banda: v } };
    }
    // ── [1.2] Ore greșite semnalate de colegi ──
    case 'raportOreLista': {
      const d = await getJSON(urlBroadcast(env, 'raportOre.json')).catch(() => null) || {};
      return { status: 200, corp: { ok: true, lista: Object.entries(d).map(([id, x]) => Object.assign({ id }, x)).sort((a, b) => b.la - a.la) } };
    }
    case 'raportOrePoza': {
      const id = String(cerere.id || '').replace(/[^a-z0-9]/g, '').slice(0, 20);
      const p = id ? await getJSON(urlBroadcast(env, `raportOrePoza/${id}.json`)).catch(() => null) : null;
      return { status: 200, corp: { ok: true, poza: p || null } };
    }
    case 'raportOreInchide': {
      const ids = (Array.isArray(cerere.ids) ? cerere.ids : []).map(x => String(x).replace(/[^a-z0-9]/g, '').slice(0, 20)).filter(Boolean).slice(0, 50);
      const d = await getJSON(urlBroadcast(env, 'raportOre.json')).catch(() => null) || {};
      const anunt = new Map();
      for (const id of ids) {
        const x = d[id];
        if (x && cerere.corectat) anunt.set(x.nr, x);
        await _fbPut(env, `raportOre/${id}`, null).catch(() => {});
        await _fbPut(env, `raportOrePoza/${id}`, null).catch(() => {});
      }
      let trimise = 0;
      for (const [nr, x] of anunt) trimise += await _pushLa(env, nr, '✓ Ora a fost corectată', `L${x.linie} T${x.tur}${x.sch ? ' sch ' + x.sch : ''} — mulțumim că ai anunțat!`, 'raport-ore');
      return { status: 200, corp: { ok: true, trimise } };
    }
    // ── [1.2] Foi și poze trimise de colegi ──
    case 'trimiteriLista': {
      const d = await getJSON(urlBroadcast(env, 'trimiteri.json')).catch(() => null) || {};
      return { status: 200, corp: { ok: true, lista: Object.entries(d).filter(([id, x]) => x && !x.incomplet).map(([id, x]) => { const o = Object.assign({ id }, x); delete o.tok; return o; }).sort((a, b) => b.la - a.la) } };
    }
    case 'trimiteFisier': {
      const id = String(cerere.id || '').replace(/[^a-z0-9]/g, '').slice(0, 20), k = Number(cerere.k) || 0;
      const date = id ? await getJSON(urlBroadcast(env, `trimiteriFisiere/${id}/${k}.json`)).catch(() => null) : null;
      if (!date) return { status: 404, corp: { ok: false, eroare: 'Fișierul nu mai există (a fost descărcat sau a expirat).' } };
      return { status: 200, corp: { ok: true, date } };
    }
    case 'trimiteDescarcat': {
      const id = String(cerere.id || '').replace(/[^a-z0-9]/g, '').slice(0, 20);
      if (!id) return { status: 400, corp: { ok: false, eroare: 'Lipsește id-ul' } };
      await _fbPut(env, `trimiteriFisiere/${id}`, null);
      await _fbPut(env, `trimiteri/${id}/descarcat`, Date.now()).catch(() => {});
      return { status: 200, corp: { ok: true } };
    }
    case 'trimiteGata': {
      const ids = (Array.isArray(cerere.ids) ? cerere.ids : []).map(x => String(x).replace(/[^a-z0-9]/g, '').slice(0, 20)).filter(Boolean).slice(0, 50);
      const d = await getJSON(urlBroadcast(env, 'trimiteri.json')).catch(() => null) || {};
      const anunt = new Map();
      for (const id of ids) {
        const x = d[id]; if (x && cerere.anunta !== false) anunt.set(x.nr, x);
        await _fbPut(env, `trimiteriFisiere/${id}`, null).catch(() => {});
        await _fbPut(env, `trimiteri/${id}`, null).catch(() => {});
      }
      let trimise = 0;
      for (const [nr, x] of anunt) trimise += await _pushLa(env, nr, x.tip === 'ind' ? '✓ Indicatorii au fost actualizați' : '✓ Foaia a fost urcată',
        `${x.bazaNume || x.baza}${x.luna ? ' · ' + x.luna : ''} — mulțumim că ai trimis-o!`, 'trimiteri');
      return { status: 200, corp: { ok: true, trimise } };
    }
    // ── [1.2] Colegi noi: primul telefon înregistrat pe număr în ultimele N zile ──
    case 'colegiNoi': {
      const zile = Math.min(60, Math.max(1, Number(cerere.zile) || 7)), prag = Date.now() - zile * 864e5;
      const pr = await getJSON(urlBroadcast(env, 'proprietar.json')).catch(() => null) || {};
      const out = [];
      for (const [nr, v] of Object.entries(pr)) {
        const { disp } = _normalizeaza(v);
        const la = Math.min(...Object.values(disp || {}).map(x => Number(x && x.la) || Infinity));
        if (isFinite(la) && la >= prag) out.push({ nr, la });
      }
      out.sort((a, b) => b.la - a.la);
      return { status: 200, corp: { ok: true, lista: out } };
    }
    // ── [1.6] Erori raportate de telefoane ──
    case 'eroriLista': {
      const d = await getJSON(urlBroadcast(env, 'erori.json')).catch(() => null) || {};
      const prag = Date.now() - 30 * 864e5;
      return { status: 200, corp: { ok: true, lista: Object.entries(d).filter(([k, x]) => x && x.ultima > prag).map(([id, x]) => Object.assign({ id }, x)).sort((a, b) => b.ultima - a.ultima) } };
    }
    case 'eroareRezolvata': {
      const ids = (Array.isArray(cerere.ids) ? cerere.ids : [cerere.id]).map(x => String(x || '').replace(/[^a-z0-9]/g, '').slice(0, 20)).filter(Boolean).slice(0, 100);
      for (const id of ids) await _fbPut(env, `erori/${id}`, null).catch(() => {});
      return { status: 200, corp: { ok: true } };
    }
    // ── [1.6] Mesaje de la colegi („Scrie-i adminului”) ──
    case 'mesajeAdminLista': {
      const d = await getJSON(urlBroadcast(env, 'mesajeAdmin.json')).catch(() => null) || {};
      return { status: 200, corp: { ok: true, lista: Object.entries(d).map(([id, x]) => Object.assign({ id }, x)).sort((a, b) => b.la - a.la) } };
    }
    // ── [2.0] Rezolvarea dintr-o apăsare a unei cereri „număr ocupat” / „blocat” ──
    case 'cerereRezolva': {
      const id = String(cerere.id || '').replace(/[^a-z0-9]/g, '').slice(0, 20);
      const m = id ? await getJSON(urlBroadcast(env, `mesajeAdmin/${id}.json`)).catch(() => null) : null;
      if (!m || !m.cerere) return { status: 404, corp: { ok: false, eroare: 'Cererea nu mai există.' } };
      const nr = nrCurat(m.nr), dev = String(m.dev || ''), acum = Date.now();
      if (cerere.fa === 'muta' || cerere.fa === 'adauga') {
        let _pr; try { _pr = await getJSON(urlBroadcast(env, `proprietar/${nr}.json`)); } catch (e) { return { status: 503, corp: { ok: false, eroare: 'Nu am putut citi telefonele numărului. Încearcă din nou.' } }; }
        const { locuri, disp } = _normalizeaza(_pr);
        const nou = cerere.fa === 'muta'
          ? { locuri: 1, disp: { [dev]: { la: acum, ultima: acum } } }
          : { locuri: Math.min(5, Math.max(locuri, Object.keys(disp).length + 1)), disp: Object.assign({}, disp, { [dev]: { la: acum, ultima: acum } }) };
        await _fbPut(env, `proprietar/${nr}`, nou);
      } else if (cerere.fa === 'deblocheaza') {
        await _fbPut(env, `blocati/${nr}`, null);
        try { const bt = await _dispBlocat(env, dev); if (bt && bt.nr) await _fbPut(env, `blocati/${nrCurat(bt.nr)}`, null); } catch (e) {}   // [2.9]
      } else return { status: 400, corp: { ok: false, eroare: 'Acțiune necunoscută' } };
      await _fbPut(env, `mesajeAdmin/${id}`, null).catch(() => {});
      return { status: 200, corp: { ok: true, nr } };
    }
    case 'mesajAdminCitit': {
      const id = String(cerere.id || '').replace(/[^a-z0-9]/g, '').slice(0, 20);
      if (id) await _fbPut(env, `mesajeAdmin/${id}`, null).catch(() => {});
      return { status: 200, corp: { ok: true } };
    }
    case 'repartitorCodNou': {
      const id = String(cerere.id || '').replace(/[^0-9a-f]/g, '').slice(0, 16);
      if (!id) return { status: 400, corp: { ok: false, eroare: 'Lipsește id-ul' } };
      let v = null;
      try { v = await getJSON(urlBroadcast(env, `repartitori/${id}.json`)); } catch (e) {}
      if (!v || !v.hash) return { status: 404, corp: { ok: false, eroare: 'Nu mai există' } };
      const b = crypto.getRandomValues(new Uint8Array(8));
      const cod = [...b].map(x => REP_ALFABET[x % REP_ALFABET.length]).join('');
      const idNou = await idRep(cod);
      const nou = Object.assign({}, v, { hash: await hashJeton('rep:' + cod), ultima: 0, codNou: Date.now(),
        vechi: (Array.isArray(v.vechi) ? v.vechi : []).concat(id).slice(-10) });
      const r = await fetch(urlBroadcast(env, `repartitori/${idNou}.json`), { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(nou) });
      if (!r.ok) { const d = await r.text().catch(() => ''); return { status: 502, corp: { ok: false, eroare: `Firebase ${r.status} ${d.slice(0, 120)}` } }; }
      await fetch(urlBroadcast(env, `repartitori/${id}.json`), { method: 'DELETE' });
      return { status: 200, corp: { ok: true, id: idNou, cod: cod.slice(0, 4) + '-' + cod.slice(4), nr: nou.nr || '', drepturi: _drepturi(nou.drepturi) } };
    }
    case 'repartitorDrepturi': {
      const id = String(cerere.id || '').replace(/[^0-9a-f]/g, '').slice(0, 16);
      if (!id) return { status: 400, corp: { ok: false, eroare: 'Lipsește id-ul' } };
      const dr = { rep: !!(cerere.drepturi && cerere.drepturi.rep), ind: !!(cerere.drepturi && cerere.drepturi.ind) };
      if (!dr.rep && !dr.ind) return { status: 400, corp: { ok: false, eroare: 'Măcar un drept.' } };
      await fetch(urlBroadcast(env, `repartitori/${id}/drepturi.json`), { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(dr) });
      if (Array.isArray(cerere.autobaze)) {
        await fetch(urlBroadcast(env, `repartitori/${id}/autobaze.json`), { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(_autobaze(cerere.autobaze)) });
      }
      return { status: 200, corp: { ok: true, id, drepturi: dr } };
    }
    case 'repartitori': {
      const r = await fetch(urlBroadcast(env, 'repartitori.json'), { headers: { 'Cache-Control': 'no-cache' } });
      const d = r.ok ? (await r.json().catch(() => null)) : null;
      const lista = Object.entries(d || {}).map(([id, v]) => ({ id, nr: (v && v.nr) || '', nume: (v && v.nume) || '',
        depouri: (v && v.depouri) || [], creat: (v && v.creat) || 0, ultima: (v && v.ultima) || 0, drepturi: _drepturi(v && v.drepturi),
        autobaze: _autobaze(v && v.autobaze) }))
        .sort((a, b2) => String(a.nr).localeCompare(String(b2.nr)));
      return { status: 200, corp: { ok: true, lista } };
    }
    case 'repartitorSterge': {
      const id = String(cerere.id || '').replace(/[^0-9a-f]/g, '').slice(0, 16);
      if (!id) return { status: 400, corp: { ok: false, eroare: 'Lipsește id-ul' } };
      const r = await fetch(urlBroadcast(env, `repartitori/${id}.json`), { method: 'DELETE' });
      if (!r.ok) { const d = await r.text().catch(() => ''); return { status: 502, corp: { ok: false, eroare: `Firebase ${r.status} ${d.slice(0, 120)}` } }; }
      return { status: 200, corp: { ok: true, id } };
    }

    // Anunțul se scrie AICI, nu din telefon. Aplicația trimite doar textul;
    // singura cale către notificările colegilor trece prin parola de admin.
    case 'anunt': {
      const titlu = String(cerere.titlu || '').trim().slice(0, 120);
      const text  = String(cerere.text  || '').trim().slice(0, 500);
      if (!titlu && !text) {
        return { status: 400, corp: { ok: false, eroare: 'Anunț gol' } };
      }

      const r = await fetch(urlBroadcast(env, 'broadcast.json'), {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          titlu, text, t: Date.now(),
          de: String(cerere.de || 'admin').slice(0, 60)
        })
      });
      if (!r.ok) {
        const detaliu = await r.text().catch(() => '');
        return { status: 502, corp: { ok: false, eroare: `Firebase ${r.status} ${detaliu.slice(0, 120)}` } };
      }

      // Trimitem imediat, ca omul să nu aștepte următorul cron de 5 minute.
      let trimise = null, telefoane = null, expirate = null, faraTelefon = null;
      try {
        const raport = await ruleaza(env);
        const m = raport.match(/Anunțuri:\s*(\d+) trimise · (\d+) telefoane · (\d+) expirate · (\d+) fără abonament/);
        if (m) {
          trimise = Number(m[1]); telefoane = Number(m[2]);
          expirate = Number(m[3]); faraTelefon = Number(m[4]);
        } else {
          const m2 = raport.match(/Anunțuri:\s*(\d+)/);
          if (m2) trimise = Number(m2[1]);
        }
      } catch (e) { /* tot pleacă la rularea automată */ }

      return { status: 200, corp: { ok: true, trimise, telefoane, expirate, faraTelefon } };
    }

    // ── Anunțul care apare pe ecran în aplicație ──
    // Până acum se scria direct din browser în Firestore, unde regulile lăsau
    // pe oricine să scrie: un străin putea trimite o fereastră pe ecranul
    // tuturor colegilor. Acum trece pe aici, cu parola, și se scrie într-un nod
    // pe care aplicațiile doar îl citesc.
    case 'anuntEcran': {
      const titlu = String(cerere.titlu || '').trim().slice(0, 120);
      const text  = String(cerere.text  || '').trim().slice(0, 800);
      if (!titlu && !text) return { status: 400, corp: { ok: false, eroare: 'Anunț gol' } };

      const tinte = Array.isArray(cerere.target) && cerere.target.length
        ? cerere.target.filter(t => t === 'all' || DEPOURI.includes(String(t))).slice(0, 12)
        : ['all'];

      const ore = Number(cerere.expireHours) || 0;
      const doc = {
        titlu, text,
        target: tinte.length ? tinte : ['all'],
        tip: ['info', 'update', 'atentie', 'urgent'].includes(cerere.tip) ? cerere.tip : 'info',
        creat: Date.now(),
        de: String(cerere.de || 'admin').slice(0, 60)
      };
      if (ore > 0) doc.expira = Date.now() + ore * 3600 * 1000;

      const r = await fetch(urlBroadcast(env, 'anunturi.json'), {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(doc)
      });
      if (!r.ok) {
        const d = await r.text().catch(() => '');
        return { status: 502, corp: { ok: false, eroare: `Firebase ${r.status} ${d.slice(0, 120)}` } };
      }
      const creat = await r.json().catch(() => ({}));
      return { status: 200, corp: { ok: true, id: creat.name || null } };
    }

    case 'anuntEcranSterge': {
      const id = String(cerere.id || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 40);
      if (!id) return { status: 400, corp: { ok: false, eroare: 'Lipsește id-ul' } };
      const r = await fetch(urlBroadcast(env, `anunturi/${id}.json`), { method: 'DELETE' });
      if (!r.ok) return { status: 502, corp: { ok: false, eroare: 'Nu am putut șterge' } };
      return { status: 200, corp: { ok: true, id } };
    }

    // ── Blocarea unui coleg, după numărul de serviciu ──
    case 'blocheaza': {
      const nr = nrCurat(cerere.nr);
      if (!nr) return { status: 400, corp: { ok: false, eroare: 'Număr de serviciu lipsă' } };

      const inreg = {
        motiv: String(cerere.motiv || '').trim().slice(0, 200),
        fel:   cerere.fel === 'definitiv' ? 'definitiv' : 'numar',   // [2.1] număr greșit / blocare definitivă
        la:    Date.now(),
        de:    String(cerere.de || 'admin').slice(0, 60)
      };
      const r = await fetch(urlBroadcast(env, `blocati/${nr}.json`), {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(inreg)
      });
      if (!r.ok) {
        const d = await r.text().catch(() => '');
        return { status: 502, corp: { ok: false, eroare: `Firebase ${r.status} ${d.slice(0, 120)}` } };
      }
      let telefoane = 0;
      if (inreg.fel === 'definitiv') telefoane = await _blocDispNumar(env, nr).catch(() => 0);   // [2.9]
      return { status: 200, corp: { ok: true, nr, inreg, telefoane } };
    }

    // [2.1] Schimbă felul blocării fără să-l deblochezi.
    case 'blocareFel': {
      const nr = nrCurat(cerere.nr);
      if (!nr) return { status: 400, corp: { ok: false, eroare: 'Număr de serviciu lipsă' } };
      const b = await getJSON(urlBroadcast(env, `blocati/${nr}.json`)).catch(() => null);
      if (!b) return { status: 404, corp: { ok: false, eroare: 'Nu mai e blocat.' } };
      const fel = cerere.fel === 'definitiv' ? 'definitiv' : 'numar';
      await _fbPut(env, `blocati/${nr}/fel`, fel);
      if (fel === 'definitiv') await _fbPut(env, `blocati/${nr}/cerere`, null).catch(() => {});
      const telefoane = fel === 'definitiv' ? await _blocDispNumar(env, nr).catch(() => 0) : 0;   // [2.9]
      return { status: 200, corp: { ok: true, nr, fel, telefoane } };
    }

    // [v11.19] Programele tuturor, pe scurt, pentru comparația cu repartizarea.
    // Doar zilele scrise de om (fără cele puse automat din foaie — alea ar
    // semăna mereu cu rândul numărului lui, chiar dacă numărul e al altcuiva).
    case 'programeLuni': {
      const luni = (Array.isArray(cerere.luni) ? cerere.luni : []).map(x => String(x)).filter(x => /^\d{4}-\d{2}$/.test(x)).slice(0, 4);
      const prefixe = luni.map(l => { const [a, m] = l.split('-').map(Number); return a + '-' + m + '-'; });
      let backup = null, push = null;
      try { backup = await getJSON(urlBroadcast(env, 'backup.json')); } catch (e) {}
      try { push = await getJSON(urlBroadcast(env, 'push.json')); } catch (e) {}
      const tok = v => {
        if (!v || typeof v !== 'object' || v._auto) return null;
        const s = (v.s === 1 || v.s === 2) ? '@' + v.s : '';
        switch (v.t) {
          case 'liber': return 'L';
          case 'co': return 'CO';
          case 'cm': return 'CM';
          case 'rezerva': return 'R';
          case 'vma': return 'VMA';
          case 'zl': case 'we':
            if (v.r) return String(v.r).toUpperCase() + s;
            if (v._manual && v._manual.tur && v._manual.linie) return (v._manual.tur + '/' + v._manual.linie).toUpperCase() + s;
        }
        return null;
      };
      const programe = {};
      for (const [nr, b] of Object.entries(backup || {})) {
        const d = (b && b.data) || {};
        const out = {};
        for (const dep of DEPOURI) {
          const k = 'p2026_' + dep;
          if (!d[k]) continue;
          let o; try { o = typeof d[k] === 'string' ? JSON.parse(d[k]) : d[k]; } catch (e) { continue; }
          if (!o || typeof o !== 'object') continue;
          const z = {};
          for (const [zi, v] of Object.entries(o)) {
            if (!prefixe.some(p => zi.startsWith(p))) continue;
            const t = tok(v); if (t) z[zi] = t;
          }
          if (Object.keys(z).length) out[dep] = z;
        }
        if (Object.keys(out).length) programe[nr] = { depot: d.p2026_depot || null, z: out };
      }
      const propuneri = {};
      for (const [nr, u] of Object.entries(push || {})) if (u && u.propunere) propuneri[nr] = u.propunere;
      return { status: 200, corp: { ok: true, programe, propuneri } };
    }

    // [v11.19] Adminul îi propune omului numărul pe care pare să-l aibă de fapt.
    // Stă în /push/<nr>/propunere (nod pe care aplicația îl citește oricum);
    // omul confirmă din aplicație cu un apăsat. `nou: null` retrage propunerea.
    case 'propuneNumar': {
      const nr = nrCurat(cerere.nr), nou = nrCurat(cerere.nou);
      if (!nr) return { status: 400, corp: { ok: false, eroare: 'Număr de serviciu lipsă' } };
      if (!nou) {
        await fetch(urlBroadcast(env, `push/${nr}/propunere.json`), { method: 'DELETE' });
        return { status: 200, corp: { ok: true, nr } };
      }
      if (nou === nr) return { status: 400, corp: { ok: false, eroare: 'E același număr' } };
      const prop = { nou, la: Date.now(), de: String(cerere.de || 'admin').slice(0, 60), scor: String(cerere.scor || '').slice(0, 60) };
      const r = await fetch(urlBroadcast(env, `push/${nr}/propunere.json`), {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(prop)
      });
      if (!r.ok) return { status: 502, corp: { ok: false, eroare: 'Firebase ' + r.status } };
      let trimise = 0;
      try {
        if (env.VAPID_PUBLIC && env.VAPID_PRIVATE) {
          const u = await getJSON(urlBroadcast(env, `push/${nr}.json`));
          const vapid = { subject: 'mailto:programstb@example.com', publicKey: env.VAPID_PUBLIC, privateKey: env.VAPID_PRIVATE };
          const payload = JSON.stringify({ title: '🔎 Verifică numărul de serviciu',
            body: `Numărul tău de serviciu pare să fie ${nou}, nu ${nr}. Deschide aplicația ca să-l corectezi.`, tag: 'propunere-nr', url: './' });
          if (u) trimise = (await trimiteToate(env, nr, u, payload, { TTL: 86400 * 3, urgency: 'normal' }, vapid)).trimise || 0;
        }
      } catch (e) {}
      return { status: 200, corp: { ok: true, nr, prop, trimise } };
    }

    // [v11.18] Pe ce numere primește adminul notificările de admin
    case 'adminNotif': {
      const nr = nrCurat(cerere.nr);
      if (nr && cerere.pornit !== undefined) {
        await fetch(urlBroadcast(env, `config/adminNotif/${nr}.json`), {
          method: cerere.pornit ? 'PUT' : 'DELETE', headers: { 'Content-Type': 'application/json' },
          body: cerere.pornit ? 'true' : undefined
        });
      }
      let lista = null;
      try { lista = await getJSON(urlBroadcast(env, 'config/adminNotif.json')); } catch (e) {}
      const numere = Object.keys(lista || {}).filter(k => lista[k]);
      const cuTel = {};
      for (const n of numere) {
        try { cuTel[n] = abonamentele(await getJSON(urlBroadcast(env, `push/${n}.json`))).length; } catch (e) { cuTel[n] = 0; }
      }
      return { status: 200, corp: { ok: true, numere, telefoane: cuTel } };
    }
    case 'adminNotifProba': {
      const n = await _anuntaAdminii(env, '🔔 Probă', 'Așa arată notificările de admin. Le primești când cineva cere aprobare.', 'admin-proba');
      return { status: 200, corp: { ok: true, trimise: n } };
    }

    // [v11.17] Cererea celui blocat de a trece pe alt număr
    case 'aprobaNumar': {
      const nr = nrCurat(cerere.nr);
      if (!nr) return { status: 400, corp: { ok: false, eroare: 'Număr de serviciu lipsă' } };
      let b = null;
      try { b = await getJSON(urlBroadcast(env, `blocati/${nr}.json`)); } catch (e) {}
      if (!b || !b.cerere || !b.cerere.nr) return { status: 400, corp: { ok: false, eroare: 'Nu are nicio cerere.' } };
      const nou = nrCurat(b.cerere.nr), dev = String(b.cerere.dev || '');
      // Îi facem loc pe numărul nou chiar acum, ca telefonul să nu dea de „număr deja folosit".
      let prop = null;
      try { prop = await getJSON(urlBroadcast(env, `proprietar/${nou}.json`)); } catch (e) { return { status: 503, corp: { ok: false, eroare: 'Nu am putut citi telefonele numărului. Încearcă din nou.' } }; }
      const { locuri, disp } = _normalizeaza(prop);
      if (!disp[dev]) {
        if (Object.keys(disp).length >= locuri && Object.keys(disp).length > 0) {
          return { status: 409, corp: { ok: false, eroare: `${nou} e deja pe alt telefon. Eliberează-l întâi din fișa lui ${nou}.` } };
        }
        disp[dev] = { la: Date.now(), ultima: Date.now() };
        await fetch(urlBroadcast(env, `proprietar/${nou}.json`), {
          method: 'PUT', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ locuri: Math.max(locuri, Object.keys(disp).length), disp })
        });
      }
      const aprobat = { nr: nou, dev, la: Date.now(), de: String(cerere.de || 'admin').slice(0, 60) };
      const r = await fetch(urlBroadcast(env, `blocati/${nr}.json`), {
        method: 'PATCH', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ aprobat, cerere: null })
      });
      if (!r.ok) return { status: 502, corp: { ok: false, eroare: 'Firebase ' + r.status } };
      return { status: 200, corp: { ok: true, nr, nou } };
    }
    case 'respingeNumar': {
      const nr = nrCurat(cerere.nr);
      if (!nr) return { status: 400, corp: { ok: false, eroare: 'Număr de serviciu lipsă' } };
      await fetch(urlBroadcast(env, `blocati/${nr}/cerere.json`), { method: 'DELETE' });
      return { status: 200, corp: { ok: true, nr } };
    }

    case 'deblocheaza': {
      const nr = nrCurat(cerere.nr);
      if (!nr) return { status: 400, corp: { ok: false, eroare: 'Număr de serviciu lipsă' } };
      const r = await fetch(urlBroadcast(env, `blocati/${nr}.json`), { method: 'DELETE' });
      if (!r.ok) {
        const d = await r.text().catch(() => '');
        return { status: 502, corp: { ok: false, eroare: `Firebase ${r.status} ${d.slice(0, 120)}` } };
      }
      return { status: 200, corp: { ok: true, nr } };
    }

    // ── Repartizarea lunii, urcată de admin ──
    // Foaia de la depou, transformată în JSON. O încarcă doar adminul; toți
    // ceilalți doar o citesc, ca să-și vadă programul fără să-l bată de mână.
    // Calea are depoul în ea: /repartizare/<depou>/<an-lună>. Altfel foaia de
    // la autobuze ar suprascrie-o pe cea de la Dudești — o singură lună, un
    // singur fișier pentru toată rețeaua.
    case 'repartizare': {
      const luna = String(cerere.luna || '').match(/^\d{4}-\d{2}$/) ? cerere.luna : null;
      if (!luna) return { status: 400, corp: { ok: false, eroare: 'Luna trebuie scrisă ca 2026-08' } };

      const depou = String(cerere.depou || '').trim().toLowerCase();
      if (!DEPOURI.includes(depou)) {
        return { status: 400, corp: { ok: false, eroare: `Depou necunoscut: "${depou}". Scrie-l în fișier, la cheia "depou" (${DEPOURI.join(', ')}).` } };
      }

      const obj = (x) => (x && typeof x === 'object' && !Array.isArray(x)) ? x : {};
      const lunara  = obj(cerere.lunara);
      const zilnica = obj(cerere.zilnica);
      const schimb  = obj(cerere.schimb);
      const ore     = obj(cerere.ore);

      const baza = `repartizare/${depou}/${luna}`;

      // Sub cupola „Autobuze" intră toate autobazele, iar foile nu vin de la
      // toate deodată — una e gata azi, alta peste trei zile. De aceea urcarea
      // ADAUGĂ peste ce există deja pentru luna aia: numerele de serviciu sunt
      // unice, deci foile nu se calcă. Cine e deja acolo rămâne.
      // Cu `inlocuieste: true` se șterge întâi tot, pentru cazul în care o foaie
      // a fost urcată greșit și trebuie refăcută luna de la zero.
      // [2.7] „Șterge întâi tot” cu o foaie goală ar fi golit luna pentru toți.
      if (cerere.inlocuieste === true && !Object.keys(lunara).length) {
        return { status: 400, corp: { ok: false, eroare: 'Foaia nu are niciun coleg — nu șterg luna.' } };
      }
      if (cerere.inlocuieste === true) {
        const rDel = await fetch(urlBroadcast(env, `${baza}.json`), { method: 'DELETE' });
        if (!rDel.ok) {
          const d = await rDel.text().catch(() => '');
          return { status: 502, corp: { ok: false, eroare: `Firebase ${rDel.status} ${d.slice(0, 120)}` } };
        }
      }

      // PATCH pe fiecare subnod: Firebase îmbină cheile noi cu cele existente.
      const scrie = async (cale, date, metoda) => {
        const r = await fetch(urlBroadcast(env, `${cale}.json`), {
          method: metoda, headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(date)
        });
        if (!r.ok) {
          const d = await r.text().catch(() => '');
          throw new Error(`Firebase ${r.status} ${d.slice(0, 120)}`);
        }
      };

      try {
        await scrie(baza, { luna, depou, urcat: Date.now(), urcatDe: cerere._urcatDe || 'admin' }, 'PATCH');
        if (Object.keys(lunara).length)  await scrie(`${baza}/lunara`,  lunara,  'PATCH');
        if (Object.keys(schimb).length)  await scrie(`${baza}/schimb`,  schimb,  'PATCH');
        if (Object.keys(ore).length)     await scrie(`${baza}/ore`,     ore,     'PATCH');
        // Zilnica e pe zile, iar o zi urcată din nou trebuie să o înlocuiască
        // pe cea veche, nu să se amestece cu ea: PATCH pe fiecare zi în parte.
        for (const zi of Object.keys(zilnica)) {
          if (!/^\d{4}-\d{1,2}-\d{1,2}$/.test(zi)) continue;      // [2.7] doar date, altfel cheia ar putea ieși din /repartizare
          await scrie(`${baza}/zilnica/${zi}`, obj(zilnica[zi]), 'PATCH');
        }
      } catch (e) {
        return { status: 502, corp: { ok: false, eroare: String(e.message || e) } };
      }

      // Câți sunt în total după îmbinare — ca să vezi dacă s-au adunat foile
      let total = Object.keys(lunara).length;
      try {
        const rc = await fetch(urlBroadcast(env, `${baza}/lunara.json?shallow=true`));
        if (rc.ok) {
          const d = await rc.json();
          if (d && typeof d === 'object') total = Object.keys(d).length;
        }
      } catch (e) {}

      return {
        status: 200,
        corp: {
          ok: true, luna, depou,
          oameni: Object.keys(lunara).length,
          total,
          zile: Object.keys(zilnica).length,
          inlocuit: cerere.inlocuieste === true
        }
      };
    }

    // ── Ștergerea unei repartizări urcate greșit ──
    case 'stergeRepartizare': {
      const luna = String(cerere.luna || '').match(/^\d{4}-\d{2}$/) ? cerere.luna : null;
      const depou = String(cerere.depou || '').trim().toLowerCase();
      if (!luna || !DEPOURI.includes(depou)) {
        return { status: 400, corp: { ok: false, eroare: 'Trebuie luna (2026-08) și depoul.' } };
      }
      const r = await fetch(urlBroadcast(env, `repartizare/${depou}/${luna}.json`), { method: 'DELETE' });
      if (!r.ok) {
        const d = await r.text().catch(() => '');
        return { status: 502, corp: { ok: false, eroare: `Firebase ${r.status} ${d.slice(0, 120)}` } };
      }
      return { status: 200, corp: { ok: true, luna, depou } };
    }

    // ── Cine n-a mai deschis aplicația ─────────────────────────
    // Pentru curățenie. Nu șterge nimic: doar strânge la un loc ce se știe
    // despre fiecare număr, ca să vezi pe cine are rost să scoți din bază.
    // Sursa pentru „ultima vizită" e stats/<nr>.ultimaVizita, scrisă o dată pe
    // zi de aplicație; cine n-a mai deschis-o de la v1.8 încoace n-are nimic
    // acolo și apare cu „necunoscut".
    case 'utilizatori': {
      let stats = null, push = null, backup = null, chei = null;
      try { stats = await getJSON(urlBroadcast(env, 'stats.json')); } catch (e) {}
      try { push  = await getJSON(urlBroadcast(env, 'push.json'));  } catch (e) {}
      // Fiecare salvare în cloud își notează momentul (`ts`). E singurul semn
      // de activitate pe care îl au și cei care n-au deschis niciodată o
      // versiune cu statistici. Citim tot nodul o dată, la cerere.
      try { backup = await getJSON(urlBroadcast(env, 'backup.json')); } catch (e) {}
      if (!backup) {
        try {
          const u = urlBroadcast(env, 'backup.json');
          chei = await getJSON(u + (u.includes('?') ? '&' : '?') + 'shallow=true');
        } catch (e) {}
      }

      const blocatiU = await citesteBlocati(env);
      const azi = Date.now();
      const numere = new Set([
        ...Object.keys(stats  || {}),
        ...Object.keys(push   || {}),
        ...Object.keys(backup || chei || {})
      ]);

      const lista = [];
      for (const nr of numere) {
        const s = (stats  && stats[nr])  || null;
        const p = (push   && push[nr])   || null;
        const b = (backup && backup[nr]) || null;

        // Cea mai recentă urmă: vizita însemnată de aplicație sau salvarea în cloud
        let ultim = null;
        if (s && s.ultimaVizita) {
          const t = Date.parse(s.ultimaVizita + 'T12:00:00Z');
          if (!isNaN(t)) ultim = t;
        }
        const tsB = b ? (Number(b.ts) || Date.parse(b.updated || '') || null) : null;
        if (tsB && (!ultim || tsB > ultim)) ultim = tsB;

        lista.push({
          nr,
          zile: ultim ? Math.floor((azi - ultim) / 86400000) : null,
          ultima: ultim ? new Date(ultim).toISOString().slice(0, 10) : null,
          sursa: (s && s.ultimaVizita) ? (tsB && tsB > Date.parse(s.ultimaVizita + 'T12:00:00Z') ? 'salvare' : 'vizită') : (tsB ? 'salvare' : null),
          depot:     (s && s.depot)     || (b && Array.isArray(b.depots) && b.depots[0]) || null,
          platforma: (s && s.platforma) || null,
          instalat:  s ? s.instalat === true : null,
          versiune:  (s && s.versiune)  || null,
          telefoane: p ? abonamentele(p).length : 0,
          areBackup: !!(b || (chei && chei[nr])),
          blocat: !!blocatiU[nr]
        });
      }
      lista.sort((a, b2) => (b2.zile === null ? 1e9 : b2.zile) - (a.zile === null ? 1e9 : a.zile));
      return { status: 200, corp: { ok: true, total: lista.length, lista } };
    }

    // ── [W-rezumat] Rezumatul bazei pentru statisticile din panou ──
    // De când regula Firebase pentru `backup` e închisă, panoul nu mai poate
    // citi direct lista programelor. Worker-ul citește cu FB_SECRET și trimite
    // doar rezumatul: câte zile are fiecare, ultima zi, depoul, când a salvat —
    // nu programele întregi.
    case 'rezumatBaza': {
      let backup = null, push = null;
      try { backup = await getJSON(urlBroadcast(env, 'backup.json')); } catch (e) {}
      try { push = await getJSON(urlBroadcast(env, 'push.json')); } catch (e) {}
      const chei = DEPOURI.map(d => 'p2026_' + d);
      const rezumat = {};
      for (const [nr, b] of Object.entries(backup || {})) {
        let zile = 0, ultima = null;
        const d = (b && b.data) || {};
        for (const k of chei) {
          if (!d[k]) continue;
          let o;
          try { o = typeof d[k] === 'string' ? JSON.parse(d[k]) : d[k]; } catch (e) { continue; }
          if (!o || typeof o !== 'object') continue;
          for (const zi of Object.keys(o)) {
            const v = o[zi];
            if (!v || typeof v !== 'object' || !v.t || v.t === 'gol') continue;
            zile++;
            if (/^\d{4}-\d{1,2}-\d{1,2}$/.test(zi) && (!ultima || zi > ultima)) ultima = zi;
          }
        }
        rezumat[nr] = {
          zile, ultima,
          depot: d.p2026_depot || (Array.isArray(b && b.depots) ? b.depots[0] : null) || null,
          updat: (b && (b.updated || b.updat)) || null,
          ts: (b && Number(b.ts)) || null
        };
      }
      const telefoane = {};
      for (const [nr, u] of Object.entries(push || {})) telefoane[nr] = abonamentele(u).length;
      return { status: 200, corp: { ok: true, backup: rezumat, push: telefoane } };
    }

    // ── Ștergerea completă a unui utilizator din bază ──
    // Curățenie: conturi de test, numere greșite (cineva a introdus numărul de
    // telefon în loc de cel de serviciu), colegi care n-au mai deschis aplicația.
    case 'stergeUtilizator': {
      const nr = nrCurat(cerere.nr);
      if (!nr) return { status: 400, corp: { ok: false, eroare: 'Număr de serviciu lipsă' } };

      const cai = ['push', 'backup', 'backupIstoric', 'stats', 'proprietar', 'blocati'];
      const sterse = [];
      const esuate = [];
      await Promise.all(cai.map(async (cale) => {
        try {
          const r = await fetch(urlBroadcast(env, `${cale}/${nr}.json`), { method: 'DELETE' });
          if (r.ok) sterse.push(cale); else esuate.push(`${cale}:${r.status}`);
        } catch (e) { esuate.push(`${cale}:${e.message}`); }
      }));
      return { status: 200, corp: { ok: true, nr, sterse, esuate } };
    }

    // ── [W-copii] Copiile de siguranță ale unui număr ──
    case 'copiiBackup': {
      const nr = nrCurat(cerere.nr);
      if (!nr) return { status: 400, corp: { ok: false, eroare: 'Număr de serviciu lipsă' } };
      let toate = null;
      try { toate = await getJSON(urlBroadcast(env, `backupIstoric/${nr}.json`)); } catch (e) {}
      const copii = Object.keys(toate || {}).sort().reverse().map(zi => ({
        zi, zile: (toate[zi] && toate[zi].zile) || 0,
        salvatLa: (toate[zi] && toate[zi].ts) || null
      }));
      let curent = null;
      try { curent = await getJSON(urlBroadcast(env, `backup/${nr}/zile.json`)); } catch (e) {}
      return { status: 200, corp: { ok: true, nr, copii, zileAcum: curent } };
    }

    // ── [W-copii] Readucerea programului la o copie ──
    // Înainte de readucere, starea de acum se păstrează ca „<zi>-inainte",
    // ca readucerea să poată fi și ea anulată.
    case 'readuBackup': {
      const nr = nrCurat(cerere.nr);
      // [2.7] și copiile „…-inainte” (făcute înaintea unei readuceri) se pot readuce
      const zi = String(cerere.zi || '').trim();
      if (!nr || !/^\d{4}-\d{2}-\d{2}(-inainte(-\d+)?)?$/.test(zi)) return { status: 400, corp: { ok: false, eroare: 'Lipsește numărul sau ziua' } };
      let copie = null;
      try { copie = await getJSON(urlBroadcast(env, `backupIstoric/${nr}/${zi}.json`)); } catch (e) {}
      if (!copie || !copie.data) return { status: 404, corp: { ok: false, eroare: 'Nu există copia din ' + zi } };
      try {
        const acum = await getJSON(urlBroadcast(env, `backup/${nr}.json`));
        if (acum && acum.data) {
          await fetch(urlBroadcast(env, `backupIstoric/${nr}/${acumRo().data}-inainte-${Date.now() % 100000}.json`), {
            method: 'PUT', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(Object.assign({}, acum, { copiatLa: Date.now() }))
          });
        }
      } catch (e) { return { status: 503, corp: { ok: false, eroare: 'Nu am putut face copia de siguranță înainte. Încearcă din nou.' } }; }
      const nou = Object.assign({}, copie, { ts: Date.now(), dev: 'admin-readucere', updated: new Date().toISOString() });
      delete nou.copiatLa;
      // [v4.7] Zilele readuse primesc ora de acum: la îmbinarea cu un telefon
      // care încă are versiunea stricată, ele trebuie să câștige.
      const acumR = Date.now();
      for (const [k, v] of Object.entries(nou.data || {})) {
        if (!k.startsWith('p2026_') || typeof v !== 'string' || !v.startsWith('{')) continue;
        try {
          const o = JSON.parse(v);
          for (const z of Object.values(o)) if (z && typeof z === 'object') z._m = acumR;
          nou.data[k] = JSON.stringify(o);
        } catch (e) {}
      }
      const r = await fetch(urlBroadcast(env, `backup/${nr}.json`), {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(nou)
      });
      if (!r.ok) {
        const d = await r.text().catch(() => '');
        return { status: 502, corp: { ok: false, eroare: `Firebase ${r.status} ${d.slice(0, 120)}` } };
      }
      return { status: 200, corp: { ok: true, nr, zi, zile: nou.zile || 0 } };
    }

    // ── Eliberarea unui număr, când colegul își schimbă telefonul ──
    case 'reseteazaDispozitiv': {
      const nr = nrCurat(cerere.nr);
      if (!nr) return { status: 400, corp: { ok: false, eroare: 'Număr de serviciu lipsă' } };
      const r = await fetch(urlBroadcast(env, `proprietar/${nr}.json`), { method: 'DELETE' });
      if (!r.ok) {
        const d = await r.text().catch(() => '');
        return { status: 502, corp: { ok: false, eroare: `Firebase ${r.status} ${d.slice(0, 120)}` } };
      }
      return { status: 200, corp: { ok: true, nr } };
    }

    // ── Încă un loc pe același număr (telefon + tabletă) ──
    case 'adaugaLoc': {
      const nr = nrCurat(cerere.nr);
      if (!nr) return { status: 400, corp: { ok: false, eroare: 'Număr de serviciu lipsă' } };

      let brut = null;
      try { brut = await getJSON(urlBroadcast(env, `proprietar/${nr}.json`)); } catch (e) { return { status: 503, corp: { ok: false, eroare: 'Nu am putut citi telefonele numărului. Încearcă din nou.' } }; }
      const { locuri, disp } = _normalizeaza(brut);
      const noiLocuri = Math.min(5, locuri + 1);

      const r = await fetch(urlBroadcast(env, `proprietar/${nr}.json`), {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ locuri: noiLocuri, disp })
      });
      if (!r.ok) return { status: 502, corp: { ok: false, eroare: 'Firebase ' + r.status } };
      return { status: 200, corp: { ok: true, nr, locuri: noiLocuri, ocupate: Object.keys(disp).length } };
    }

    // ── [v16.7] Scoaterea unui loc ──
    // Locurile se puteau doar adăuga. După ce eliberai un număr rămâneau
    // locurile libere de dinainte — iar un loc liber înseamnă că oricine poate
    // revendica numărul ăla. Acum se poate strânge la loc, dar nu sub câte
    // telefoane sunt deja înregistrate, ca să nu rămână cineva pe dinafară.
    case 'scoateLoc': {
      const nr = nrCurat(cerere.nr);
      if (!nr) return { status: 400, corp: { ok: false, eroare: 'Număr de serviciu lipsă' } };

      let brut = null;
      try { brut = await getJSON(urlBroadcast(env, `proprietar/${nr}.json`)); } catch (e) { return { status: 503, corp: { ok: false, eroare: 'Nu am putut citi telefonele numărului. Încearcă din nou.' } }; }
      const { locuri, disp } = _normalizeaza(brut);
      const ocupate = Object.keys(disp).length;
      const noiLocuri = Math.max(1, ocupate, locuri - 1);
      if (noiLocuri === locuri) {
        return { status: 200, corp: { ok: true, nr, locuri, ocupate,
          nota: ocupate >= locuri ? 'Toate locurile sunt ocupate.' : 'E deja un singur loc.' } };
      }

      const r = await fetch(urlBroadcast(env, `proprietar/${nr}.json`), {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ locuri: noiLocuri, disp })
      });
      if (!r.ok) return { status: 502, corp: { ok: false, eroare: 'Firebase ' + r.status } };
      return { status: 200, corp: { ok: true, nr, locuri: noiLocuri, ocupate } };
    }

    // ── Ce dispozitive are un număr ──
    case 'dispozitive': {
      const nr = nrCurat(cerere.nr);
      if (!nr) return { status: 400, corp: { ok: false, eroare: 'Număr de serviciu lipsă' } };
      let brut = null;
      try { brut = await getJSON(urlBroadcast(env, `proprietar/${nr}.json`)); } catch (e) { return { status: 503, corp: { ok: false, eroare: 'Nu am putut citi telefonele numărului. Încearcă din nou.' } }; }
      const { locuri, disp } = _normalizeaza(brut);
      return { status: 200, corp: { ok: true, nr, locuri, disp } };
    }

    // ── [v17.9] Copiile zilnice: ce avem și de când ──
    case 'arhive': {
      let index = null;
      try { index = await getJSON(urlBroadcast(env, 'arhiva.json?shallow=true')); } catch (e) {}
      const date = Object.keys(index || {}).filter(d => /^\d{4}-\d{2}-\d{2}$/.test(d)).sort().reverse();
      // Pentru un număr anume spunem și câte zile are în fiecare copie —
      // așa se vede dintr-o privire de unde merită recuperat.
      const nr = nrCurat(cerere.nr);
      const lista = [];
      for (const d of date.slice(0, 20)) {
        const el = { data: d };
        if (nr) {
          try {
            const z = await getJSON(urlBroadcast(env, `arhiva/${d}/backup/${nr}/zile.json`));
            el.zile = (z === null || z === undefined) ? null : Number(z);
          } catch (e) { el.zile = null; }
        }
        lista.push(el);
      }
      return { status: 200, corp: { ok: true, lista } };
    }

    // Aduce înapoi programul unui coleg dintr-o copie. Backupul de acum se
    // pune deoparte întâi, ca recuperarea să nu strice și mai tare.
    case 'recupereaza': {
      const nr = nrCurat(cerere.nr);
      const data = String(cerere.data || '').slice(0, 10);
      if (!nr || !/^\d{4}-\d{2}-\d{2}$/.test(data)) {
        return { status: 400, corp: { ok: false, eroare: 'Lipsește numărul sau data' } };
      }
      let vechi = null;
      try { vechi = await getJSON(urlBroadcast(env, `arhiva/${data}/backup/${nr}.json`)); } catch (e) {}
      if (!vechi) return { status: 404, corp: { ok: false, eroare: `În copia din ${data} nu există nimic pentru ${nr}` } };

      try {
        const acum = await getJSON(urlBroadcast(env, `backup/${nr}.json`));
        if (acum) {
          await fetch(urlBroadcast(env, `arhiva/_inainteDeRecuperare/${nr}.json`), {
            method: 'PUT', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ts: Date.now(), backup: acum })
          }).catch(() => {});
        }
      } catch (e) {}

      vechi.ts = Date.now();
      vechi.recuperatDin = data;
      // [2.7] Ca la „readuBackup”: zilele readuse primesc ora de acum, altfel
      // telefonul cu versiunea stricată le-ar pune la loc peste ele la prima salvare.
      const acumR = Date.now();
      for (const [k, v] of Object.entries(vechi.data || {})) {
        if (!k.startsWith('p2026_') || typeof v !== 'string' || !v.startsWith('{')) continue;
        try { const o = JSON.parse(v); for (const z of Object.values(o)) if (z && typeof z === 'object') z._m = acumR; vechi.data[k] = JSON.stringify(o); } catch (e) {}
      }
      const w = await fetch(urlBroadcast(env, `backup/${nr}.json`), {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(vechi)
      });
      if (!w.ok) return { status: 502, corp: { ok: false, eroare: 'Firebase ' + w.status } };
      return { status: 200, corp: { ok: true, nr, data, zile: Number(vechi.zile) || null } };
    }

    // ── [v16.8] Abonamentele la notificări ──
    // Fiecare adresă de site înseamnă alt abonament, iar reinstalările lasă
    // în urmă abonamente vechi care încă funcționează. Rezultatul: aceeași
    // notificare de două-trei ori. De aici le vezi și le cureți.
    case 'pushToate': {
      let tot = null;
      try { tot = await getJSON(urlBroadcast(env, 'push.json')); } catch (e) {}
      const lista = [];
      let abonamente = 0;
      for (const [nr, u] of Object.entries(tot || {})) {
        const subs = (u && u.subs && typeof u.subs === 'object') ? u.subs : {};
        const cate = Object.keys(subs).length + ((u && u.sub) ? 1 : 0);
        if (!cate) continue;
        let ultima = 0;
        for (const v of Object.values(subs)) {
          const t = Number(v && v.updat) || 0;
          if (t > ultima) ultima = t;
        }
        abonamente += cate;
        lista.push({ nr, cate, vechi: !!(u && u.sub), ultima });
      }
      lista.sort((a, b) => b.cate - a.cate || String(a.nr).localeCompare(String(b.nr)));
      return { status: 200, corp: { ok: true, numere: lista.length, abonamente, lista } };
    }

    // Curăță dublurile: pe fiecare număr rămâne doar cel mai nou abonament.
    // `nr` gol înseamnă „pe toate numerele".
    case 'pushCurata': {
      const doarNr = nrCurat(cerere.nr);
      let tot = null;
      try { tot = await getJSON(urlBroadcast(env, 'push.json')); } catch (e) {}
      let sterse = 0, atinse = 0;
      for (const [nr, u] of Object.entries(tot || {})) {
        if (doarNr && String(nr) !== String(doarNr)) continue;
        const subs = (u && u.subs && typeof u.subs === 'object') ? u.subs : {};
        const id = Object.keys(subs).filter(k => subs[k]);
        const inainte = sterse;
        // forma veche, fără id: [2.7] se șterge doar dacă omul are și abonamente noi
        if (u && u.sub && id.length) {
          await fetch(urlBroadcast(env, `push/${nr}/sub.json`), { method: 'DELETE' }).catch(() => {});
          sterse++;
        }
        if (id.length > 1) {
          id.sort((a, b) => (Number(subs[b] && subs[b].updat) || 0) - (Number(subs[a] && subs[a].updat) || 0));
          for (const vechi of id.slice(1)) {
            await fetch(urlBroadcast(env, `push/${nr}/subs/${vechi}.json`), { method: 'DELETE' }).catch(() => {});
            sterse++;
          }
        }
        if (sterse > inainte) atinse++;
      }
      return { status: 200, corp: { ok: true, sterse, numere: atinse } };
    }

    // Șterge tot abonamentul unui număr — omul nu mai primește notificări
    // până nu le repornește singur din aplicație.
    case 'pushStergeNr': {
      const nr = nrCurat(cerere.nr);
      if (!nr) return { status: 400, corp: { ok: false, eroare: 'Număr de serviciu lipsă' } };
      const r = await fetch(urlBroadcast(env, `push/${nr}.json`), { method: 'DELETE' });
      if (!r.ok) return { status: 502, corp: { ok: false, eroare: 'Firebase ' + r.status } };
      return { status: 200, corp: { ok: true, nr } };
    }

    // ── [v16.3] Agenda cu telefoanele colegilor ──
    // Stă aici, nu în aplicație. Până acum era scrisă în index.html, iar fișierul
    // e public: parola de la panou nu ajuta cu nimic, fiindcă ea decide ce se
    // afișează, nu ce se descarcă. Cazul ăsta e mai simplu decât restul — agenda
    // nu e a colegilor, e a lui: nimeni altcineva n-o primește, niciodată.
    case 'agenda': {
      let brut = null;
      try { brut = await getJSON(urlBroadcast(env, 'agenda.json')); } catch (e) {}
      const contacte = Object.entries(brut || {})
        .map(([nr, v]) => ({ nr, tel: (v && v.tel) || '', nume: (v && v.nume) || '' }))
        .sort((a, b) => String(a.nume).localeCompare(String(b.nume), 'ro'));
      return { status: 200, corp: { ok: true, contacte } };
    }

    // Scrierea agendei: se trimite lista întreagă și înlocuiește ce era.
    case 'agendaScrie': {
      const contacte = Array.isArray(cerere.contacte) ? cerere.contacte : null;
      if (!contacte) return { status: 400, corp: { ok: false, eroare: 'Lipsește lista' } };
      const obiect = {};
      for (const c of contacte.slice(0, 2000)) {
        const nr = nrCurat(c && c.nr);
        if (!nr) continue;
        obiect[nr] = {
          tel:  String((c && c.tel)  || '').replace(/[^0-9+ ]/g, '').slice(0, 20),
          nume: String((c && c.nume) || '').trim().slice(0, 80)
        };
      }
      const r = await fetch(urlBroadcast(env, 'agenda.json'), {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(obiect)
      });
      if (!r.ok) return { status: 502, corp: { ok: false, eroare: 'Firebase ' + r.status } };
      return { status: 200, corp: { ok: true, cate: Object.keys(obiect).length } };
    }

    // ── [v16.0] Privire de ansamblu: câte telefoane ține fiecare număr ──
    // Până acum te puteai uita doar număr cu număr, ceea ce nu ajută când vrei
    // să vezi starea întregului depou — de exemplu după mutarea pe alt domeniu,
    // când toate telefoanele capătă identitate nouă și numerele par ocupate.
    case 'toateDispozitivele': {
      let tot = null;
      try { tot = await getJSON(urlBroadcast(env, 'proprietar.json')); } catch (e) {}
      const lista = [];
      let telefoane = 0;
      for (const [nr, brut] of Object.entries(tot || {})) {
        const { locuri, disp } = _normalizeaza(brut);
        const cate = disp ? Object.keys(disp).length : 0;
        telefoane += cate;
        lista.push({ nr, cate, locuri });
      }
      lista.sort((a, b) => b.cate - a.cate || String(a.nr).localeCompare(String(b.nr)));
      return { status: 200, corp: { ok: true, numere: lista.length, telefoane, lista } };
    }

    // ── [v16.0] Golirea întregii evidențe de telefoane ──
    // Se șterge DOAR cine-ține-ce-număr. Programele, backupurile și
    // permisiunile stau în alte noduri și rămân neatinse. După asta, primul
    // telefon care scrie un număr îl revendică din nou, ca la început.
    case 'stergeToateDispozitivele': {
      const r = await fetch(urlBroadcast(env, 'proprietar.json'), { method: 'DELETE' });
      if (!r.ok) return { status: 502, corp: { ok: false, eroare: 'Firebase ' + r.status } };
      return { status: 200, corp: { ok: true } };
    }

    // ── Scoaterea unui singur dispozitiv ──
    case 'stergeDispozitiv': {
      const nr  = nrCurat(cerere.nr);
      const dev = String(cerere.dev || '').replace(/[^a-zA-Z0-9-]/g, '').slice(0, 64);
      if (!nr || !dev) return { status: 400, corp: { ok: false, eroare: 'Lipsește numărul sau dispozitivul' } };
      const r = await fetch(urlBroadcast(env, `proprietar/${nr}/disp/${dev}.json`), { method: 'DELETE' });
      if (!r.ok) return { status: 502, corp: { ok: false, eroare: 'Firebase ' + r.status } };
      return { status: 200, corp: { ok: true, nr, dev } };
    }

    // ── Telefonul de contact arătat pe ecranele de blocare/ocupat ──
    case 'contact': {
      const tel = String(cerere.tel || '').trim().slice(0, 30);
      const r = await fetch(urlBroadcast(env, 'config/contact.json'), {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(tel)
      });
      if (!r.ok) return { status: 502, corp: { ok: false, eroare: 'Firebase ' + r.status } };
      return { status: 200, corp: { ok: true, tel } };
    }

    // ── [v4.7] CĂUTARE: după număr de serviciu (bucăți din el) sau după nume ──
    // Numele vin din agendă; numerele din toate locurile în care apare cineva
    // (program salvat, statistică, notificări, telefoane înregistrate).
    case 'cauta': {
      const q = String(cerere.q || '').trim().slice(0, 40);
      if (!q) return { status: 400, corp: { ok: false, eroare: 'Scrie un număr sau un nume' } };
      const sh = async (cale) => {
        try { const u = urlBroadcast(env, cale + '.json'); return await getJSON(u + (u.includes('?') ? '&' : '?') + 'shallow=true') || {}; }
        catch (e) { return {}; }
      };
      const [b, st, pu, pr] = await Promise.all([sh('backup'), sh('stats'), sh('push'), sh('proprietar')]);
      let agenda = {}, stats = {};
      try { agenda = await getJSON(urlBroadcast(env, 'agenda.json')) || {}; } catch (e) {}
      try { stats = await getJSON(urlBroadcast(env, 'stats.json')) || {}; } catch (e) {}
      const blocatiC = await citesteBlocati(env);
      const toate = new Set([...Object.keys(b), ...Object.keys(st), ...Object.keys(pu), ...Object.keys(pr), ...Object.keys(agenda)]);
      const fara = x => String(x || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
      const cifre = q.replace(/[^0-9]/g, '');
      const cuvinte = fara(q).split(/\s+/).filter(Boolean);
      const gasite = [];
      for (const nr of toate) {
        const nume = (agenda[nr] && agenda[nr].nume) || '';
        const dupaNr = cifre && cifre.length === q.replace(/\s/g, '').length && nr.includes(cifre);
        const dupaNume = !cifre && nume && cuvinte.every(c => fara(nume).includes(c));
        if (!dupaNr && !dupaNume) continue;
        gasite.push({ nr, nume, depot: (stats[nr] && stats[nr].depot) || null,
          areProgram: !!b[nr], areNotificari: !!pu[nr], blocat: !!blocatiC[nr], exact: nr === cifre });
      }
      gasite.sort((x, y) => (y.exact - x.exact) || x.nr.localeCompare(y.nr));
      return { status: 200, corp: { ok: true, total: gasite.length, lista: gasite.slice(0, 30) } };
    }

    // ── [v4.7] FIȘA COMPLETĂ a unui număr: tot ce se știe despre el ──
    case 'fisa': {
      const nr = nrCurat(cerere.nr);
      if (!nr) return { status: 400, corp: { ok: false, eroare: 'Număr de serviciu lipsă' } };
      const ia = async (cale) => { try { return await getJSON(urlBroadcast(env, cale + '.json')); } catch (e) { return null; } };
      const [b, st, pu, prBrut, bl, ag, acc] = await Promise.all([
        ia(`backup/${nr}`), ia(`stats/${nr}`), ia(`push/${nr}`), ia(`proprietar/${nr}`),
        ia(`blocati/${nr}`), ia(`agenda/${nr}`), ia(`acces/${nr}`)
      ]);
      let copii = {};
      try { const u = urlBroadcast(env, `backupIstoric/${nr}.json`); copii = await getJSON(u + (u.includes('?') ? '&' : '?') + 'shallow=true') || {}; } catch (e) {}

      // Programul, PE DEPOURI. [v4.8] Telefonul ține programul fiecărui depou pe
      // care s-a completat ceva — teste, programe văzute de la colegi cu versiuni
      // vechi — și toate ajung în backup. Adunate la un loc, dădeau cifre fără
      // sens (585 de zile, câte 3 intrări pe zi). Acum fiecare depou separat, iar
      // fișa îl pune în față pe cel în care lucrează omul.
      const iso = k => { const p = k.split('-').map(Number); return p.length === 3 ? `${p[0]}-${String(p[1]).padStart(2, '0')}-${String(p[2]).padStart(2, '0')}` : ''; };
      const acum = acumRo().data;                         // AAAA-LL-ZZ, ora României
      const program = { depouri: {}, depotLucru: null };
      const d = (b && b.data) || {};
      for (const dep of DEPOURI) {
        const k = 'p2026_' + dep;
        if (!d[k]) continue;
        let o; try { o = typeof d[k] === 'string' ? JSON.parse(d[k]) : d[k]; } catch (e) { continue; }
        if (!o || typeof o !== 'object') continue;
        const x = { zile: 0, prima: null, ultima: null, luni: {}, ultimaModificare: null };
        for (const [zi, v] of Object.entries(o)) {
          if (!v || typeof v !== 'object' || !v.t || v.t === 'gol') continue;
          const z = iso(zi); if (!z) continue;
          x.zile++;
          const luna = z.slice(0, 7); x.luni[luna] = (x.luni[luna] || 0) + 1;
          if (!x.prima || z < x.prima) x.prima = z;
          if (!x.ultima || z > x.ultima) x.ultima = z;
          const m = Number(v._m) || 0; if (m && (!x.ultimaModificare || m > x.ultimaModificare)) x.ultimaModificare = m;
        }
        if (x.zile) program.depouri[dep] = x;
      }
      // [2.5.1] Depoul în care lucrează: repartizarea pe care apare, apoi cele
      // mai multe zile din ultimele 60, apoi marcajul telefonului (vezi _bkLucru).
      if (b) {
        try {
          const A = await _bkAnaliza(env, nr, b);
          program.depotLucru = A.lucru; program.motivLucru = A.motiv; program.peFoaie = A.peFoaie; program.copii = A.copii;
        } catch (e) {
          const L = _bkLucru(program.depouri, b.depotLucru || b.depotPropriu, []);
          program.depotLucru = L.lucru; program.motivLucru = L.motiv;
        }
      }

      // Notificări: pe câte telefoane, prin ce serviciu, ce setări
      let notificari = null;
      if (pu) {
        const serv = ep => { try { const h = new URL(ep).host; return /apple/.test(h) ? 'iPhone (Apple)' : /google|fcm/.test(h) ? 'Android (Google)' : /mozilla/.test(h) ? 'Firefox' : /windows|notify/.test(h) ? 'Windows' : h; } catch (e) { return '?'; } };
        const tel = abonamentele(pu).map(x => ({ id: x.id, serviciu: serv(x.sub && x.sub.endpoint) }));
        const ture = Array.isArray(pu.ture) ? pu.ture : [];
        notificari = {
          telefoane: tel, pushDin: pu.pushDin || null, updat: pu.updat || null, depot: pu.depot || null,
          notifSeara: !!pu.notifSeara, oraSeara: Number.isFinite(Number(pu.oraSeara)) ? Number(pu.oraSeara) : null,
          chatMute: pu.chatMute === true, chatSeen: pu.chatSeen || null,
          ture: ture.length, urmatoareaTura: ture.filter(t => t && t.data >= acum).sort((a, b2) => (a.data + a.start).localeCompare(b2.data + b2.start))[0] || null,
          ultimaAlerta: Array.isArray(pu.trimise) ? pu.trimise[pu.trimise.length - 1] : (pu.trimis || null),
          searaTrimis: pu.searaTrimis || null, broadcastNotificat: pu.broadcastNotificat || null
        };
      }
      const { locuri, disp } = _normalizeaza(prBrut);
      const permise = Object.entries(acc || {}).filter(([, v]) => v && v.stare === 'da').map(([cheie, v]) => ({ cheie, cine: v.cine || '', tip: v.tip || '', nume: v.nume || '', raspuns: v.raspuns || v.creat || null }));
      const asteapta = Object.values(acc || {}).filter(v => v && v.stare === 'asteapta').length;
      const setari = {};
      for (const k of ['p2026_depot', 'p2026_sch', 'p2026_chatname', 'p2026_push_on', 'p2026_notif_maine', 'p2026_reminder_active']) if (d[k] !== undefined) setari[k.replace('p2026_', '')] = d[k];

      return { status: 200, corp: { ok: true, nr,
        nume: (ag && ag.nume) || '', tel: (ag && ag.tel) || '',
        exista: !!(b || st || pu || prBrut || ag),
        backup: b ? { ts: Number(b.ts) || null, updated: b.updated || null, dev: b.dev || null, depotPropriu: b.depotPropriu || null,
          depotLucru: b.depotLucru || null, depots: b.depots || [], zile: b.zile || 0, setari } : null,
        program, statistica: st || null, notificari,
        dispozitive: { locuri, lista: Object.entries(disp).map(([id, v]) => ({ id, la: (v && v.la) || null, ultima: (v && v.ultima) || null, adresa: (v && v.adresa) || null })) },
        blocat: bl || null, acces: { permise, asteapta },
        copii: Object.keys(copii).sort().reverse()
      } };
    }

    // [v11.9] Programul unui om, zi cu zi, ca să-l vezi din panoul de admin.
    // Doar cheile de program (p2026_<depou>) din backup — nimic altceva.
    case 'programBrut': {
      const nr = nrCurat(cerere.nr);
      if (!nr) return { status: 400, corp: { ok: false, eroare: 'Număr de serviciu lipsă' } };
      let b = null;
      try { b = await getJSON(urlBroadcast(env, `backup/${nr}.json`)); } catch (e) {}
      if (!b) return { status: 200, corp: { ok: true, nr, exista: false, depouri: {} } };
      const d = b.data || {};
      const depouri = {};
      for (const dep of DEPOURI) {
        const k = 'p2026_' + dep;
        if (!d[k]) continue;
        let o; try { o = typeof d[k] === 'string' ? JSON.parse(d[k]) : d[k]; } catch (e) { continue; }
        if (!o || typeof o !== 'object') continue;
        const zile = {};
        for (const [zi, v] of Object.entries(o)) if (v && typeof v === 'object' && v.t && v.t !== 'gol') zile[zi] = v;
        if (Object.keys(zile).length) depouri[dep] = zile;
      }
      // [2.5.1] aceeași regulă ca în fișă, ca să se deschidă depoul unde lucrează de fapt
      let lucru = null;
      try { lucru = (await _bkAnaliza(env, nr, b)).lucru; } catch (e) {}
      return { status: 200, corp: { ok: true, nr, exista: true, ts: Number(b.ts) || null,
        depotLucru: lucru || b.depotLucru || b.depotPropriu || d.p2026_depot || null, sch: d.p2026_sch || null, depouri } };
    }

    case 'blocati': {
      const lista = await citesteBlocati(env);
      return { status: 200, corp: { ok: true, blocati: lista } };
    }

    default:
      return { status: 400, corp: { ok: false, eroare: 'Acțiune necunoscută: ' + cerere.actiune } };
  } })();

  // [2.3] Ce a făcut adminul 2 rămâne scris (doar ce a reușit și a schimbat ceva).
  if (adm2 && rez && rez.status === 200 && !ADM2_CITIRE.has(cerere.actiune)) {
    await _adm2Scrie(env, adm2.nr, cerere);
  }
  return rez;
}
