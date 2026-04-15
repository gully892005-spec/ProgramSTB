// =============================================
// Service Worker - Program STB 2026
// Când schimbi indicatorii în db.json pe GitHub,
// aplicația ia automat datele noi la următoarea deschidere.
// =============================================

const CACHE_NAME = 'stb-app-v1';
const DB_URL = './db.json';

// Fișiere de cached static (UI, fonts etc.)
const STATIC_ASSETS = [
  '/ProgramSTB/',
  '/ProgramSTB/index.html',
  '/ProgramSTB/manifest.json',
  '/ProgramSTB/icon-192.png',
  '/ProgramSTB/icon-512.png'
];

// --- INSTALL: cache static assets ---
self.addEventListener('install', event => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(STATIC_ASSETS))
  );
});

// --- ACTIVATE: curăță cache vechi ---
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

// --- FETCH: strategie diferită pentru db.json vs restul ---
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  // db.json: Network First (mereu încearcă serverul, fallback pe cache)
  if (url.pathname.endsWith('db.json')) {
    event.respondWith(
      fetch(event.request)
        .then(response => {
          if (response.ok) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
          }
          return response;
        })
        .catch(() => caches.match(event.request))
    );
    return;
  }

  // Restul: Cache First (offline first)
  event.respondWith(
    caches.match(event.request).then(cached => {
      if (cached) return cached;
      return fetch(event.request).then(response => {
        if (response.ok) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
        }
        return response;
      });
    })
  );
});
