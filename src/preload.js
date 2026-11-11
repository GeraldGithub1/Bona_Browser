'use strict';
// Exposes a minimal, fixed API to the browser chrome UI only (never to websites).
const { contextBridge, ipcRenderer } = require('electron');

const ALLOWED = new Set(['state', 'downloads', 'downloads-open', 'focus-address']);

contextBridge.exposeInMainWorld('bona', {
  cmd: (name, arg) => ipcRenderer.send('cmd', String(name), arg),
  on: (channel, fn) => {
    if (!ALLOWED.has(channel)) return;
    ipcRenderer.on(channel, (_e, data) => fn(data));
  }
});
