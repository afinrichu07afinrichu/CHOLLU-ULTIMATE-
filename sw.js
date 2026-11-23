self.addEventListener('install',e=>{e.waitUntil(caches.open('c1').then(c=>c.addAll(['/','/icon.svg'])));self.skipWaiting()});
self.addEventListener('activate',e=>e.waitUntil(clients.claim()));
self.addEventListener('fetch',e=>{if(e.request.method!='GET'||e.request.url.includes('/api/'))return;e.respondWith(fetch(e.request).catch(()=>caches.match(e.request)))});
self.addEventListener('push',e=>e.waitUntil(clients.matchAll({type:'window'}).then(l=>{if(l.some(c=>c.visibilityState=='visible'))return;return self.registration.showNotification('CHOLLU',{body:'പുതിയ സന്ദേശം / call',icon:'/icon.svg',tag:'chollu'})})));
self.addEventListener('notificationclick',e=>{e.notification.close();e.waitUntil(clients.matchAll({type:'window'}).then(l=>l[0]?l[0].focus():clients.openWindow('/')))});
