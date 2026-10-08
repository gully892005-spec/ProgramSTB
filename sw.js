// ══════════════════════════════════════════════════════
// SERVICE WORKER — Program STB 2026+
// Funcții: Cache offline, Notificări tură, Widget zilnic
// ══════════════════════════════════════════════════════

const CACHE_NAME = 'stb-2026-v165';   // [2.8] fără ultimele ture la autobuze   // [2.7] verificare completă, copii offline corecte   // [2.6] unde lucrează corect   // [2.5] depouri străine   // [2.4] linii de noapte N117   // [2.3] admin 2   // [2.2] calendar la indicatori   // [2.1] blocare număr greșit / definitivă   // [2.0] număr folosit / blocat → scrie-i adminului   // [1.9] banda → scrie-i adminului   // [1.8] poze la rezoluția întreagă   // [1.7] confidențialitate jos în meniu   // [1.6] confidențialitate: luată de pe net întâi   // [1.6] confidențialitate, scrie-i adminului, erori raportate   // [1.5] Statistici reordonate, colegi noi jos   // [1.4] admin: liste care se strâng, banda în Mesaje   // [1.3] ✕ pe foile de jos   // [1.2] banda de avertizare, trimite foaia la admin, colegi noi, FB pe poză, Susține pe Acasă   // [1.1] admin: de rezolvat, acoperire, citiri, foile pe luni, actualizare obligatorie   // [1.0] alegerea din fereastra zilei se vede clar   // [1.0] numerotarea pornește de la 1.0; versiunea mai vizibilă   // [v11.47] fără bulină de anunțuri în browser   // [v11.46] iPhone: ghid obligatoriu din browser + doar Safari   // [v11.45] poza de pe Acasă: „Troleibuz” corect   // [v11.44] autobuze: schimbul 2 „iese din garaj” în indicatori   // [v11.43] Acasă rămâne la mijloc și când te uiți la programul unui coleg   // [v11.42] grupul de Facebook pe Acasă   // [v11.41] titlul pe un rând și pe ecrane mici   // [v11.40] butonul de admin sub depou, mai vizibil   // [v11.39] buton de panou sus pentru admin/responsabili   // [v11.38] 🏠 Acasă în mijlocul barei de jos   // [v11.37] istoricul de indicatori se strânge și se curăță   // [v11.36] indicatori din PDF (admin) + sâmbătă/duminică separat la autobuze   // [v11.35] anunțul citit dispare de pe Acasă   // [v11.34] responsabili: „Cod nou” când își pierde codul   // [v11.33] responsabilul nu mai vede „Are repartizarea urcată?”   // [v11.32] Giurgiului și Ferentari despărțite   // [v11.31] indicatori autobuze separați pe autobaze   // [v11.30] editor indicatori: alegere clară „schimb la capăt / iese din depou”, toate liniile   // [v11.29] indicatorii de ore se modifică din aplicație (admin + responsabili, cu aprobare)   // [v11.28] repartizarea PDF de la Vatra Luminoasă + orele de troleibuz de acolo   // [v11.27] un singur formular pentru mesaje: notificare și/sau fereastră   // [v11.26] panoul de admin: swipe între file   // [v11.25] panoul de admin pe file, casete care se strâng   // [v11.24] ghidul de iPhone cu capturi reale (iOS nou)   // [v11.23] „Pune-o pe ecran” la fiecare intrare, până instalează   // [v11.22] ghid de instalare pe iPhone, pas cu pas, cu desene   // [v11.21] admin: cine folosește aplicația din browser (numerele)   // [v11.20] statistici: zilele speciale cu numele motivului, nu „Sindicat”   // [v11.19] analiza numerelor: programul altcuiva, dubluri, propunerea de număr   // [v11.18] notificare la admin când un blocat cere aprobare   // [v11.17] numărul nou de pe ecranul de blocare se aprobă de admin   // [v11.16] numărul de serviciu verificat cu repartizarea   // [v11.15] admin: lista „Colegi blocați”, blocarea doar din fișă   // [v11.14] schimbul se alege o dată, după numărul de serviciu   // [v11.13] responsabili de repartizare cu cod   // [v11.12] grilele din admin pe zilele săptămânii (Lu…Du)   // [v11.11] repartizarea întreabă schimbul când foaia nu-l scrie   // [v11.10] admin: programul pe grilă, ca la repartizare   // [v11.9] admin: programul unui om, zi cu zi   // [v11.8] buton „Susține aplicația” (Revolut) + codul QR se scanează corect   // [v11.7] troleibuzele (Bujoreni) sub Autobuze + „ești pe foaia de la X”   // [v11.6] admin: verifică dacă un număr are repartizarea urcată   // [v11.5] PDF Bujoreni: pagini fără numere + rândul 2 + luna fără an   // [v11.4] PDF Berceni (15/97+ITP) + orele de autobuz de la Berceni   // [v11.3] PDF: Ferentari recunoscut ca autobuze, fără ghicit greșit   // [v11.2] repartizarea lunară urcată direct din PDF   // [v11.1] orele de sâmbătă separate de duminică la autobuze   // [v11.0] orele de autobuz din tabelul permanent din db.json   // [v10.9] weekendul nu mai ia orele de zi lucrătoare (mai multe autobaze)   // [v10.8] fracția: se deschide din nou, apare mâine și în fereastra zilei   // [v10.7] felii multiple în statistici, fără butonul de ore din bara lunii   // [v10.6] formular de tură simplificat (autobuze/troleibuze)   // [v10.5] text nou în avertismentul de aplicație neoficială   // [v10.4] căsuța din avertisment se bifează   // [v10.3] avertisment neoficial mai lizibil   // [v10.2] linii cu litere (N122) la completarea manuală   // [v10.1] buton de închidere pe ecranul Număr deja folosit   // [v10.0] ștergerea unei zile ajunge și în cloud   // [v9.9] rezerva cu orele reale + rezervă după tur   // [v9.8] ore de noapte doar la turele terminate după 01:00, de la 22:00   // [v9.6] buton Special: tur manual + motiv (sindicat/sânge/deces/conc.sp.) cu ore editabile   // [v9.5] ture lizibile + sindicat   // [v9.4] salvarea automată merge și pe iPhone   // [v9.3] salvarea nu mai eșuează în tăcere   // [v9.2] filtre pe depou în panou   // [v9.1] detașarea se alege din indicatori   // [v9.0] panoul de admin scrie pe înțeles   // [v8.9] detașarea se vede peste tot   // [v8.8] nicio cerere nu mai atârnă · foaia rămâne în telefon · chat corectat   // [v8.7] zilele se văd + weekend în pontaj   // [v8.6] zile plătite dublu   // [v8.5] înapoi la rezumatul lunii   // [v8.4] zile necompletate + starea repartizării   // [v8.3] bara lunii pe un rând   // [v8.2] fără eticheta de procent   // [v8.1] ore de noapte + blocări S+D   // [v8.0] orele cu spor pe cerc   // [v7.9] vizitatorul nu vede statistici   // [v7.8] rămase = neluate   // [v7.7] CM nu mai consumă din CO   // [v7.6] planificarea concediului   // [v7.5] concediu pe fiecare an   // [v7.4] sărbătorile cu nume și indicatori de weekend   // [v7.3] săptămâna desfăcută la pornire   // [v7.2] ștergere și din cloud   // [v7.1] standalone   // [v7.0] refresh fără salt pe prima pagină   // [v6.9] VMA în card și în pontaj   // [v6.8] site curat, un singur buton   // [v6.7] instalare dintr-o apăsare   // [v6.6] fereastra de instalare revine pe site   // [v6.5] numărul se cere doar instalat   // [v6.4] recunoaște aplicația instalată   // [v6.3] total utilizatori   // [v6.2] blocările peste program   // [v6.1] repartizarea nu trece peste ce a scris omul   // [v6.0] repartizarea intră singură   // [v5.9] doar rubricile completate   // [v4.5] link corect la atingerea notificării   // [v3.7] poza corectată: „pentru un București mai bun!"
// [v15.8] Caile erau scrise fix, cu /ProgramSTB/. Pe programstb.com aplicatia
// sta in radacina, deci nu exista acolo nimic: cache-ul ramanea gol, iar
// manifestul si service worker-ul nu se incarcau. Relativ merge pe ambele
// adrese — se socoteste fata de locul in care sta sw.js.
const CACHE_FILES = [
  './',
  './index.html',
  './manifest.json',
  './db.json',
  './Icons/icon-192.png',
  './Icons/icon-72.png',
  './Icons/fundal-alege-complet.jpg',  // [v18.6] fundalul cu butoanele Tramvai / Autobuz
  './Icons/banner-sus.jpg'             // [v19.12] poza din antet
];

// ── INSTALL: cache fișiere esențiale ──
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      // [1.6] pagina de confidențialitate separat: dacă lipsește de pe site, nu strică restul
      cache.add('./confidentialitate.html').catch(() => {});
      // [2.7] Dacă pică un singur fișier, addAll nu păstrează nimic. Atunci le
      // luăm pe rând, ca măcar pagina să fie în copie.
      return cache.addAll(CACHE_FILES).catch(() => Promise.all(CACHE_FILES.map(u => cache.add(u).catch(() => {}))));
    })
  );
  self.skipWaiting();
});

// ── ACTIVATE: șterge cache vechi ──
self.addEventListener('activate', e => {
  e.waitUntil(
    // [2.7] Copiile vechi se șterg doar dacă cea nouă chiar are pagina aplicației.
    // Altfel, după o actualizare prinsă pe semnal slab, fără net rămânea ecran alb.
    caches.open(CACHE_NAME).then(c => c.match('./')).then(arePagina => arePagina ? caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    ) : null)
  );
  self.clients.claim();

  // Programează notificarea zilnică la activare
  scheduleDailyCheck();
});

// ── FETCH: network-first pentru HTML/JS, cache-first pentru rest ──
// ══════════════════════════════════════════════════════════════
// [v8.8] REȚEAUA NU MAI POATE ȚINE APLICAȚIA ÎNCHISĂ
//
// Până acum, pentru fișierele aplicației se cerea ÎNTÂI rețeaua, iar copia
// din telefon era folosită doar dacă cererea eșua. Problema: pe semnal prost
// cererea nu eșuează, ci atârnă — uneori un minut. În tot timpul ăla omul se
// uita la ecran alb, deși aplicația întreagă era deja în telefon.
//
// Acum punem rețeaua la întrecere cu un ceas. Dacă rețeaua nu răspunde în
// câteva secunde, pornim din copia locală și gata. Cererea de rețea NU e
// anulată: merge mai departe în fundal și, dacă ajunge, împrospătează copia
// pentru data viitoare. Deci: pornire instant acum, versiune nouă la
// următoarea deschidere.
// ══════════════════════════════════════════════════════════════
const RABDARE_RETEA = 3500;   // cât așteptăm rețeaua pentru fișierele aplicației
const RABDARE_DB    = 3000;   // pentru db.json (indicatoarele)

// [2.7] Copiile se țin sub adresa fără „?…”: înainte fiecare db.json?v=<timp>
// rămânea separat, iar fără net se lua mereu cel mai vechi.
function _cheie(req){ return req.url.split('#')[0].split('?')[0]; }
function _dinCache(req, cuPaginaPrincipala){
  return caches.match(_cheie(req)).then(c => c || caches.match(req, { ignoreSearch: true })).then(c => {
    if(c) return c;
    return cuPaginaPrincipala ? caches.match('./', { ignoreSearch: true }) : null;
  });
}

function reteaSauCopie(req, ms, cuPaginaPrincipala){
  return new Promise(resolve => {
    let raspuns = false;
    const dau = r => { if(!raspuns && r){ raspuns = true; resolve(r); } };

    const ceas = setTimeout(() => {
      if(raspuns) return;
      _dinCache(req, cuPaginaPrincipala).then(dau);
    }, ms);

    fetch(req).then(resp => {
      // Copia se împrospătează chiar dacă între timp am pornit din cache.
      // [2.7] Se păstrează doar răspunsurile bune (nu pagina de logare a unui
      // Wi-Fi, nu o eroare de server). La eroare dăm copia, dacă avem.
      const bun = resp && resp.ok && !resp.redirected && resp.type !== 'opaque';
      if(bun){
        const clona = resp.clone();
        caches.open(CACHE_NAME).then(c => c.put(_cheie(req), clona)).catch(()=>{});
      }
      clearTimeout(ceas);
      if((resp && resp.ok) || raspuns) return dau(resp);
      _dinCache(req, cuPaginaPrincipala).then(c => dau(c || resp));
    }).catch(() => {
      clearTimeout(ceas);
      if(raspuns) return;
      _dinCache(req, cuPaginaPrincipala).then(c => {
        if(c) dau(c);
        else if(!raspuns){ raspuns = true; resolve(Response.error()); }
      });
    });
  });
}

self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;

  const url = e.request.url;
  // [v6.4] `start_url` are acum marcajul `?pwa=1` (ca telefonul să știe că
  // aplicația a pornit de pe ecran, nu din browser). Fără curățarea de mai jos,
  // adresa cu semnul de întrebare nu mai era „pagina principală": cădea pe
  // ramura cache-first, unde potrivirea se face exact, nu găsea nimic și
  // aplicația nu se mai deschidea fără internet.
  const urlCurat = url.split('?')[0].split('#')[0];
  // [v7.1] `manifest.json` trecea pe ramura cache-first, deci telefonul putea
  // citi luni la rând vechea variantă din memorie — iar manifestul e cel care
  // spune cum pornește aplicația (acum `standalone`). Îl luăm de pe net întâi,
  // cu copia locală drept plasă de siguranță.
  const isCore = urlCurat === self.registration.scope || urlCurat.includes('index.html')
              || urlCurat.includes('sw.js') || urlCurat.includes('manifest.json')
              || urlCurat.includes('confidentialitate.html');   // [1.6] textul paginii se poate schimba oricând

  // [FIX] db.json — rețea întâi, dar păstrăm ultima copie bună pentru offline
  if (url.includes('db.json')) {
    e.respondWith(reteaSauCopie(e.request, RABDARE_DB, false));
    return;
  }

  if (isCore) {
    // Network-first: încearcă rețeaua, fallback la cache dacă offline
    e.respondWith(reteaSauCopie(e.request, RABDARE_RETEA, true));
  } else {
    // Cache-first pentru resurse statice (fonturi, icoane etc.)
    e.respondWith(
      caches.match(e.request).then(cached => {
        return cached || fetch(e.request).then(resp => {
          if (resp && resp.status === 200 && url.startsWith(self.registration.scope)) {
            const clone = resp.clone();
            caches.open(CACHE_NAME).then(c => c.put(e.request, clone));
          }
          return resp;
        }).catch(() => cached);
      })
    );
  }
});

// ══════════════════════════════════════════════════════
// REMINDER TURĂ — primit de la aplicație
// ══════════════════════════════════════════════════════
let scheduledReminders = [];

self.addEventListener('message', e => {
  if (!e.data) return;

  if (e.data.type === 'SHOW_DAILY_NOTIF') {
    self.registration.showNotification(e.data.title || '📅 Program STB', {
      body: e.data.body || '',
      icon: './Icons/icon-192.png',
      badge: './Icons/icon-72.png',
      tag: 'daily-tura',
      renotify: true,
      vibrate: [100, 50, 100],
      data: { url: self.registration.scope }
    });
  }

  if (e.data.type === 'NOTIF_MAINE_ON') {
    self._notifMaine = true;
  }
  if (e.data.type === 'NOTIF_MAINE_OFF') {
    self._notifMaine = false;
  }
  if (e.data.type === 'TURA_MAINE_DATA') {
    self._turamaine = e.data.msg;
  }
  if (e.data.type === 'CANCEL_REMINDERS') {
    if (self._reminderTimers) {
      self._reminderTimers.forEach(t => clearTimeout(t));
      self._reminderTimers = [];
    }
    scheduledReminders = [];
  }

  if (e.data.type === 'SCHEDULE_REMINDERS') {
    const { ture, minBefore } = e.data;
    scheduledReminders = ture || [];

    // Anulează alarme vechi
    if (self._reminderTimers) {
      self._reminderTimers.forEach(t => clearTimeout(t));
    }
    self._reminderTimers = [];

    const now = Date.now();

    ture.forEach(tura => {
      const [h, m] = tura.start.split(':').map(Number);
      const [y, mo, d] = tura.date.split('-').map(Number);
      const turaDt = new Date(y, mo - 1, d, h, m, 0).getTime();
      // [FIX] înainte se folosea un singur minBefore global pentru toate turele,
      // deci setarea separată dimineață/seară era ignorată
      const mb = (typeof tura.minBefore === 'number' && tura.minBefore > 0) ? tura.minBefore : minBefore;
      const alertDt = turaDt - mb * 60000;
      const delay = alertDt - now;

      if (delay > 0 && delay < 48 * 3600 * 1000) {
        const t = setTimeout(() => {
          showTuraNotification(tura, mb);
        }, delay);
        self._reminderTimers.push(t);
      }
    });

    // Confirmă
    e.source && e.source.postMessage({ type: 'REMINDERS_SCHEDULED', count: ture.length });
  }
});

// ── Afișează notificare tură ──
async function showTuraNotification(tura, minBefore) {
  // Dacă aplicația e deschisă, trimite alert in-app
  const clients = await self.clients.matchAll({ type: 'window' });
  if (clients.length > 0) {
    clients.forEach(c => c.postMessage({
      type: 'SHOW_ALERT',
      turaStart: tura.start,
      minBefore: minBefore
    }));
    return; // Nu mai afișăm notificare browser dacă app e deschisă
  }

  const opts = {
    body: `Ora de plecare: ${tura.start}${tura.end ? ' → ' + tura.end : ''}\nPregătește-te!`,
    icon: './Icons/icon-192.png',
    badge: './Icons/icon-72.png',
    tag: 'tura-reminder-' + tura.date,
    renotify: true,
    requireInteraction: true,
    vibrate: [200, 100, 200, 100, 400],
    actions: [
      { action: 'open', title: '📅 Deschide program' },
      { action: 'dismiss', title: 'OK' }
    ],
    data: { url: self.registration.scope }
  };

  // Peste o oră, „1h 30m" se citește mai ușor decât „90 minute".
  const cat = minBefore >= 60
    ? `${Math.floor(minBefore / 60)}h${minBefore % 60 ? ' ' + (minBefore % 60) + 'm' : ''}`
    : `${minBefore} min`;

  self.registration.showNotification(
    `🚃 Tură în ${cat}`,
    opts
  );
}

// ══════════════════════════════════════════════════════
// NOTIFICARE ZILNICĂ — "tura de azi și mâine"
// Se trimite în fiecare dimineață la 07:00
// ══════════════════════════════════════════════════════
function scheduleDailyCheck() {
  const now = new Date();
  const next7am = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 7, 0, 0);
  if (next7am <= now) next7am.setDate(next7am.getDate() + 1);
  const delay = next7am - now;

  setTimeout(() => {
    sendDailyUpdate();
    // Reprogramează pentru a doua zi
    setInterval(sendDailyUpdate, 24 * 3600 * 1000);
  }, delay);
}

async function sendDailyUpdate() {
  // Citește date din IndexedDB sau trimite mesaj la client
  const clients = await self.clients.matchAll({ type: 'window' });
  if (clients.length > 0) {
    // Aplicația e deschisă — trimite mesaj
    clients.forEach(c => c.postMessage({ type: 'DAILY_UPDATE_REQUEST' }));
  } else {
    // Aplicația e închisă — afișează notificare generică
    self.registration.showNotification('📅 Program STB 2026+', {
      body: 'Deschide aplicația să vezi tura de azi și mâine.',
      icon: './Icons/icon-192.png',
      badge: './Icons/icon-72.png',
      tag: 'daily-update',
      actions: [{ action: 'open', title: '📅 Deschide' }],
      data: { url: self.registration.scope }
    });
  }
}

// [FIX v4.5] Workerul trimitea în notificări adresa „/ProgramSTB/", rămasă de pe
// github.io. Pe programstb.com aplicația stă în rădăcină, deci atingerea unei
// notificări cu aplicația închisă deschidea o pagină inexistentă (404).
// Orice adresă din afara aplicației devine adresa aplicației.
function _adresaSigura(u){
  try{
    const sc = new URL(self.registration.scope);
    const x  = new URL(u || './', sc);
    // Doar pagina aplicației (cu eventuale ?parametri), nimic altceva.
    const ok = x.origin === sc.origin && (x.pathname === sc.pathname || x.pathname === sc.pathname + 'index.html');
    return ok ? x.href : sc.href;
  }catch(e){ return self.registration.scope; }
}

// ── Click pe notificare ──
self.addEventListener('notificationclick', e => {
  e.notification.close();

  if (e.action === 'dismiss') return;

  const url = _adresaSigura(e.notification.data && e.notification.data.url);

  e.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clients => {
      // Dacă aplicația e deja deschisă, o focusează
      for (const client of clients) {
        if (client.url.startsWith(self.registration.scope) && 'focus' in client) {
          return client.focus();
        }
      }
      // Altfel deschide o fereastră nouă
      if (self.clients.openWindow) {
        return self.clients.openWindow(url);
      }
    })
  );
});

// ── Push notifications (pentru viitor) ──
// ══════════════════════════════════════════════════════
// PUSH — notificări reale, care ajung și cu aplicația închisă.
// Sunt trimise de un job programat (GitHub Actions), nu de telefon,
// deci nu depind de faptul că aplicația e deschisă sau nu.
// ══════════════════════════════════════════════════════
self.addEventListener('push', e => {
  let data = {};
  try { data = e.data ? e.data.json() : {}; }
  catch(err) { data = { title: 'Program STB', body: e.data ? e.data.text() : '' }; }

  const title = data.title || '🚃 Program STB';
  const opts = {
    body: data.body || '',
    icon: './Icons/icon-192.png',
    badge: './Icons/icon-72.png',
    tag: data.tag || 'push-tura',
    renotify: true,
    requireInteraction: data.urgent !== false,
    vibrate: [200, 100, 200, 100, 400],
    actions: [
      { action: 'open', title: '📅 Deschide' },
      { action: 'dismiss', title: 'OK' }
    ],
    data: { url: _adresaSigura(data.url) }
  };

  e.waitUntil(self.registration.showNotification(title, opts));
});

// Dacă browserul reînnoiește abonamentul, îl re-salvăm în cloud
self.addEventListener('pushsubscriptionchange', e => {
  e.waitUntil((async () => {
    try {
      const clients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
      clients.forEach(c => c.postMessage({ type: 'PUSH_RESUBSCRIBE' }));
    } catch(err) {}
  })());
});
