// ══════════════════════════════════════════════════════
// SERVICE WORKER — Program STB 2026+
// Funcții: Cache offline, Notificări tură, Widget zilnic
// ══════════════════════════════════════════════════════

const CACHE_NAME = 'stb-2026-v7';
const CACHE_FILES = [
  '/ProgramSTB/',
  '/ProgramSTB/index.html',
  '/ProgramSTB/manifest.json',
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
  const isCore = url.endsWith('/ProgramSTB/') || url.includes('index.html') || url.includes('sw.js');

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
          if (resp && resp.status === 200 && url.includes('/ProgramSTB/')) {
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
      icon: '/ProgramSTB/icon-192.png',
      badge: '/ProgramSTB/icon-72.png',
      tag: 'daily-tura',
      renotify: true,
      vibrate: [100, 50, 100],
      data: { url: '/ProgramSTB/' }
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
      const alertDt = turaDt - minBefore * 60000;
      const delay = alertDt - now;

      if (delay > 0 && delay < 48 * 3600 * 1000) {
        const t = setTimeout(() => {
          showTuraNotification(tura, minBefore);
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
    icon: '/ProgramSTB/icon-192.png',
    badge: '/ProgramSTB/icon-72.png',
    tag: 'tura-reminder-' + tura.date,
    renotify: true,
    requireInteraction: true,
    vibrate: [200, 100, 200, 100, 400],
    actions: [
      { action: 'open', title: '📅 Deschide program' },
      { action: 'dismiss', title: 'OK' }
    ],
    data: { url: '/ProgramSTB/' }
  };

  self.registration.showNotification(
    `🚃 Tură în ${minBefore} minute!`,
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
      icon: '/ProgramSTB/icon-192.png',
      badge: '/ProgramSTB/icon-72.png',
      tag: 'daily-update',
      actions: [{ action: 'open', title: '📅 Deschide' }],
      data: { url: '/ProgramSTB/' }
    });
  }
}

// ── Click pe notificare ──
self.addEventListener('notificationclick', e => {
  e.notification.close();

  if (e.action === 'dismiss') return;

  const url = (e.notification.data && e.notification.data.url) || '/ProgramSTB/';

  e.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clients => {
      // Dacă aplicația e deja deschisă, o focusează
      for (const client of clients) {
        if (client.url.includes('/ProgramSTB/') && 'focus' in client) {
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
self.addEventListener('push', e => {
  if (!e.data) return;
  try {
    const data = e.data.json();
    self.registration.showNotification(data.title || 'Program STB', {
      body: data.body || '',
      icon: '/ProgramSTB/icon-192.png',
      data: { url: data.url || '/ProgramSTB/' }
    });
  } catch(err) {}
});
