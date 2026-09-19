// ══════════════════════════════════════════════════════
// SERVICE WORKER — Program STB 2026+
// Funcții: Cache offline, Notificări tură, Widget zilnic
// ══════════════════════════════════════════════════════

const CACHE_NAME = 'stb-2026-v39';   // [v4.5] link corect la atingerea notificării   // [v3.7] poza corectată: „pentru un București mai bun!"
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
      return cache.addAll(CACHE_FILES).catch(() => {});
    })
  );
  self.skipWaiting();
});

// ── ACTIVATE: șterge cache vechi ──
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();

  // Programează notificarea zilnică la activare
  scheduleDailyCheck();
});

// ── FETCH: network-first pentru HTML/JS, cache-first pentru rest ──
self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;

  const url = e.request.url;
  const isCore = url === self.registration.scope || url.includes('index.html') || url.includes('sw.js');

  // [FIX] db.json — rețea întâi, dar păstrăm ultima copie bună pentru offline
  if (url.includes('db.json')) {
    e.respondWith(
      fetch(e.request).then(resp => {
        if (resp && resp.status === 200) {
          const clone = resp.clone();
          caches.open(CACHE_NAME).then(c => c.put(e.request, clone));
        }
        return resp;
      }).catch(() => caches.match(e.request, { ignoreSearch: true }))
    );
    return;
  }

  if (isCore) {
    // Network-first: încearcă rețeaua, fallback la cache dacă offline
    e.respondWith(
      fetch(e.request).then(resp => {
        if (resp && resp.status === 200) {
          const clone = resp.clone();
          caches.open(CACHE_NAME).then(c => c.put(e.request, clone));
        }
        return resp;
      }).catch(() => caches.match(e.request))
    );
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
