'use strict';
/*
 * BONA — a secure web browser.  "Bona" means "seeing" in Setswana.
 * Main process: windows, tabs, and all security enforcement.
 */
const {
  app, BrowserWindow, WebContentsView, ipcMain, session, protocol, Menu, dialog, shell, nativeImage
} = require('electron');
const path = require('path');
const fs = require('fs');
const { isBlockedHost, TRACKER_COUNT } = require('./security/blocklist');
const { checkUrl, registrableDomain, isLocalHost, isDangerousFile } = require('./security/url-check');

const UI_HEIGHT = 86;      // tab strip + toolbar, must match ui.css
const PANEL_WIDTH = 360;   // side panel width, must match ui.css
const ICON = path.join(__dirname, '..', 'build', 'icon.png');
const PAGES = path.join(__dirname, 'pages');

app.setName('BONA');
if (process.platform === 'win32') app.setAppUserModelId('za.co.bona.browser');

// Hardening switches
app.commandLine.appendSwitch('disable-features', 'InterestFeedContentSuggestions,PrivacySandboxSettings4');
app.commandLine.appendSwitch('enable-features', 'StrictOriginIsolation');

protocol.registerSchemesAsPrivileged([
  { scheme: 'bona', privileges: { standard: true, secure: true, supportFetchAPI: true } }
]);

// ---------------------------------------------------------------- settings
const DEFAULTS = {
  httpsOnly: true,
  blockTrackers: true,
  phishingProtection: true,
  blockThirdPartyCookies: false,
  doNotTrack: true,
  warnDangerousDownloads: true,
  clearOnExit: false,
  searchEngine: 'duckduckgo'
};
const SEARCH = {
  duckduckgo: { name: 'DuckDuckGo', url: 'https://duckduckgo.com/?q=' },
  google: { name: 'Google', url: 'https://www.google.com/search?q=' },
  bing: { name: 'Bing', url: 'https://www.bing.com/search?q=' },
  brave: { name: 'Brave Search', url: 'https://search.brave.com/search?q=' }
};
let settingsFile;
let settings = { ...DEFAULTS };
function loadSettings() {
  settingsFile = path.join(app.getPath('userData'), 'settings.json');
  try { settings = { ...DEFAULTS, ...JSON.parse(fs.readFileSync(settingsFile, 'utf8')) }; } catch { /* first run */ }
}
function saveSettings() {
  try { fs.writeFileSync(settingsFile, JSON.stringify(settings, null, 2)); } catch (e) { console.error(e); }
}

// ---------------------------------------------------------------- state
const windows = new Map();    // BrowserWindow.id -> { win, tabs: Map, order: [], active, panel, private, ses }
const tabByWc = new Map();    // webContents.id -> tab
const httpAllowed = new Set();     // hosts the user allowed over plain HTTP
const phishAllowed = new Set();    // hosts the user chose to visit despite warning
const permissionDecisions = new Map(); // `${partition}|${origin}|${perm}` -> boolean
const downloads = [];
let nextTabId = 1;
let privateCounter = 0;
const configuredSessions = new WeakSet();

function homeUrl() { return `bona://home/?engine=${encodeURIComponent(settings.searchEngine)}`; }

// ---------------------------------------------------------------- session security
function configureSession(ses, partition) {
  if (configuredSessions.has(ses)) return;
  configuredSessions.add(ses);

  // Internal pages
  ses.protocol.handle('bona', async (req) => {
    const u = new URL(req.url);
    const page = u.hostname.replace(/[^a-z]/g, '');
    let file = path.basename(decodeURIComponent(u.pathname)) || 'index.html';
    if (u.pathname === '/' || u.pathname === '') file = 'index.html';
    const full = path.join(PAGES, page, file);
    if (!full.startsWith(PAGES) || !fs.existsSync(full)) {
      return new Response('Not found', { status: 404 });
    }
    const type = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.svg': 'image/svg+xml' }[path.extname(full)] || 'application/octet-stream';
    return new Response(fs.readFileSync(full), {
      headers: {
        'content-type': type,
        'content-security-policy': "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; form-action https:; base-uri 'none'; frame-ancestors 'none'"
      }
    });
  });

  // Request filter: tracker blocking, HTTPS-only upgrade, phishing interstitial
  ses.webRequest.onBeforeRequest((details, cb) => {
    let u;
    try { u = new URL(details.url); } catch { return cb({}); }
    const tab = tabByWc.get(details.webContentsId);

    if (details.resourceType === 'mainFrame') {
      if (u.protocol === 'http:' && settings.httpsOnly && !isLocalHost(u.hostname) && !httpAllowed.has(u.hostname)) {
        u.protocol = 'https:';
        if (tab) tab.upgradedFrom = details.url;
        return cb({ redirectURL: u.toString() });
      }
      if (settings.phishingProtection && /^https?:$/.test(u.protocol) && !phishAllowed.has(u.hostname)) {
        const verdict = checkUrl(details.url);
        if (tab) tab.urlVerdict = verdict;
        if (verdict && verdict.level === 'danger' && tab) {
          const q = new URLSearchParams({ url: details.url, reasons: JSON.stringify(verdict.reasons) });
          tab.interstitial = true;
          setImmediate(() => tab.view.webContents.loadURL(`bona://warning/?${q}`));
          return cb({ cancel: true });
        }
      } else if (tab) tab.urlVerdict = null;
      return cb({});
    }

    if (settings.blockTrackers && /^(https?|wss?):$/.test(u.protocol) && isBlockedHost(u.hostname)) {
      if (tab) {
        tab.blocked += 1;
        if (!tab.blockedHosts.includes(u.hostname)) tab.blockedHosts.unshift(u.hostname);
        tab.blockedHosts.length = Math.min(tab.blockedHosts.length, 30);
        totalBlocked += 1;
        scheduleUpdate(tab.winId);
      }
      return cb({ cancel: true });
    }
    // Block mixed content (http subresources on https pages)
    if (u.protocol === 'http:' && settings.httpsOnly && tab && tab.view.webContents.getURL().startsWith('https:') && !isLocalHost(u.hostname)) {
      u.protocol = 'https:';
      return cb({ redirectURL: u.toString() });
    }
    cb({});
  });

  // Privacy headers & third-party cookie stripping
  ses.webRequest.onBeforeSendHeaders((details, cb) => {
    const h = details.requestHeaders;
    if (settings.doNotTrack) { h['DNT'] = '1'; h['Sec-GPC'] = '1'; }
    if (settings.blockThirdPartyCookies && details.resourceType !== 'mainFrame' && isThirdParty(details)) {
      delete h['Cookie']; delete h['cookie'];
    }
    cb({ requestHeaders: h });
  });
  ses.webRequest.onHeadersReceived((details, cb) => {
    if (settings.blockThirdPartyCookies && details.resourceType !== 'mainFrame' && isThirdParty(details) && details.responseHeaders) {
      for (const k of Object.keys(details.responseHeaders)) if (k.toLowerCase() === 'set-cookie') delete details.responseHeaders[k];
    }
    cb({ responseHeaders: details.responseHeaders });
  });

  // Permissions: ask the user, remember per site
  const ALWAYS_OK = new Set(['fullscreen', 'clipboard-sanitized-write', 'pointerLock', 'window-management']);
  const LABELS = {
    media: 'camera / microphone', geolocation: 'location', notifications: 'notifications',
    midi: 'MIDI devices', midiSysex: 'MIDI devices', 'clipboard-read': 'clipboard',
    'display-capture': 'screen', hid: 'HID devices', serial: 'serial ports', usb: 'USB devices',
    openExternal: 'external applications', 'idle-detection': 'idle detection', 'storage-access': 'cross-site storage'
  };
  ses.setPermissionRequestHandler(async (wc, permission, callback, details) => {
    if (ALWAYS_OK.has(permission)) return callback(true);
    const origin = safeOrigin(details.requestingUrl || wc.getURL());
    let label = LABELS[permission] || permission;
    if (permission === 'media' && details.mediaTypes) {
      label = details.mediaTypes.map(m => m === 'video' ? 'camera' : 'microphone').join(' and ') || label;
    }
    const key = `${partition}|${origin}|${permission}`;
    if (permissionDecisions.has(key)) return callback(permissionDecisions.get(key));
    const parent = BrowserWindow.fromWebContents(wc) || BrowserWindow.getFocusedWindow();
    const r = await dialog.showMessageBox(parent, {
      type: 'question', title: 'BONA — Permission request', icon: nativeImage.createFromPath(ICON),
      message: `${origin} wants to use your ${label}.`,
      detail: 'Only allow this if you trust the site.',
      buttons: ['Block', 'Allow'], defaultId: 0, cancelId: 0,
      checkboxLabel: 'Remember my choice for this site', checkboxChecked: true
    });
    const allow = r.response === 1;
    if (r.checkboxChecked) permissionDecisions.set(key, allow);
    callback(allow);
    broadcastAll();
  });
  ses.setPermissionCheckHandler((wc, permission, requestingOrigin) => {
    if (ALWAYS_OK.has(permission)) return true;
    return permissionDecisions.get(`${partition}|${safeOrigin(requestingOrigin)}|${permission}`) === true;
  });
  ses.setDevicePermissionHandler(() => false);

  // Downloads: warn on dangerous file types
  ses.on('will-download', (event, item, wc) => {
    const name = item.getFilename();
    const parent = BrowserWindow.fromWebContents(wc) || BrowserWindow.getFocusedWindow();
    if (settings.warnDangerousDownloads && isDangerousFile(name)) {
      const r = dialog.showMessageBoxSync(parent, {
        type: 'warning', title: 'BONA — Potentially dangerous download', icon: nativeImage.createFromPath(ICON),
        message: `"${name}" can run programs on your computer.`,
        detail: `From: ${safeOrigin(item.getURL())}\n\nOnly keep this file if you trust where it came from.`,
        buttons: ['Cancel download', 'Keep file'], defaultId: 0, cancelId: 0
      });
      if (r !== 1) { item.cancel(); return; }
    }
    const dir = app.getPath('downloads');
    let target = path.join(dir, name);
    let n = 1;
    while (fs.existsSync(target)) {
      const ext = path.extname(name);
      target = path.join(dir, `${path.basename(name, ext)} (${n++})${ext}`);
    }
    item.setSavePath(target);
    const d = { id: Date.now() + Math.random(), name: path.basename(target), path: target, state: 'progressing', received: 0, total: item.getTotalBytes() };
    downloads.unshift(d);
    item.on('updated', (_e, state) => { d.state = state; d.received = item.getReceivedBytes(); d.total = item.getTotalBytes(); broadcastDownloads(); });
    item.once('done', (_e, state) => { d.state = state; d.received = item.getReceivedBytes(); broadcastDownloads(); });
    broadcastDownloads();
    for (const w of windows.values()) if (!w.win.isDestroyed()) w.win.webContents.send('downloads-open');
  });
}

let totalBlocked = 0;

function safeOrigin(url) { try { return new URL(url).origin; } catch { return String(url || ''); } }
function isThirdParty(details) {
  try {
    const first = details.frame?.top?.url || details.referrer || (tabByWc.get(details.webContentsId)?.view.webContents.getURL());
    if (!first) return false;
    return registrableDomain(new URL(details.url).hostname) !== registrableDomain(new URL(first).hostname);
  } catch { return false; }
}

// ---------------------------------------------------------------- windows & tabs
function createWindow({ isPrivate = false } = {}) {
  const partition = isPrivate ? `bona-private-${++privateCounter}` : 'persist:bona';
  const ses = session.fromPartition(partition, { cache: !isPrivate });
  configureSession(ses, partition);

  const win = new BrowserWindow({
    width: 1280, height: 820, minWidth: 640, minHeight: 420,
    title: isPrivate ? 'BONA — Private' : 'BONA',
    icon: ICON,
    backgroundColor: isPrivate ? '#1e1633' : '#f4f7f9',
    autoHideMenuBar: true,
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true, sandbox: true, nodeIntegration: false, webSecurity: true, spellcheck: false
    }
  });
  win.setMenuBarVisibility(false);
  const state = { win, tabs: new Map(), order: [], active: null, panel: false, private: isPrivate, ses, partition };
  windows.set(win.id, state);
  win.loadFile(path.join(__dirname, 'ui', 'index.html'), { query: { private: isPrivate ? '1' : '0' } });
  win.once('ready-to-show', () => win.show());
  win.webContents.once('did-finish-load', () => { newTab(win.id, homeUrl()); });
  win.on('resize', () => layout(win.id));
  win.on('closed', () => {
    for (const t of state.tabs.values()) { tabByWc.delete(t.wcId); try { t.view.webContents.close(); } catch {} }
    windows.delete(win.id);
    if (isPrivate) { ses.clearStorageData().catch(() => {}); ses.clearCache().catch(() => {}); }
  });
  // The UI page must never navigate away
  win.webContents.on('will-navigate', e => e.preventDefault());
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  return win;
}

function newTab(winId, url, { activate = true } = {}) {
  const w = windows.get(winId);
  if (!w) return;
  const view = new WebContentsView({
    webPreferences: {
      session: w.ses, sandbox: true, contextIsolation: true, nodeIntegration: false,
      webSecurity: true, allowRunningInsecureContent: false, safeDialogs: true,
      navigateOnDragDrop: false, spellcheck: true, webviewTag: false
    }
  });
  view.setBackgroundColor('#ffffff');
  const tab = {
    id: nextTabId++, winId, view, wcId: view.webContents.id, title: 'New Tab', favicon: null,
    loading: false, blocked: 0, blockedHosts: [], urlVerdict: null, upgradedFrom: null
  };
  w.tabs.set(tab.id, tab);
  w.order.push(tab.id);
  tabByWc.set(tab.wcId, tab);
  wireTab(tab);
  view.webContents.loadURL(url || homeUrl());
  if (activate) activateTab(winId, tab.id); else scheduleUpdate(winId);
  return tab;
}

function wireTab(tab) {
  const wc = tab.view.webContents;
  const upd = () => scheduleUpdate(tab.winId);
  wc.on('page-title-updated', (_e, t) => { tab.title = t; upd(); });
  wc.on('page-favicon-updated', (_e, f) => { tab.favicon = f && f[0] || null; upd(); });
  wc.on('did-start-loading', () => { tab.loading = true; upd(); });
  wc.on('did-stop-loading', () => { tab.loading = false; upd(); });
  wc.on('did-start-navigation', (d) => {
    if (d.isMainFrame && !d.isSameDocument) { tab.blocked = 0; tab.blockedHosts = []; tab.favicon = null; }
  });
  wc.on('did-navigate', upd);
  wc.on('did-navigate-in-page', upd);
  wc.on('did-fail-load', (_e, code, desc, url, isMain) => {
    if (!isMain || code === -3) return; // -3 = aborted (e.g. redirect)
    if (tab.interstitial && code === -20) { tab.interstitial = false; return; } // we blocked it ourselves
    const q = new URLSearchParams({ code: String(code), desc, url, upgraded: tab.upgradedFrom && url.startsWith('https:') ? '1' : '0' });
    wc.loadURL(`bona://error/?${q}`);
  });
  wc.on('did-finish-load', () => { if (!wc.getURL().startsWith('bona://error')) tab.upgradedFrom = null; });

  // Links from interstitial pages: bona://proceed/?url=…  bona://proceed-http/?url=…
  const intercept = (e, url) => {
    if (!url.startsWith('bona://proceed')) return;
    e.preventDefault();
    const cur = wc.getURL();
    if (!cur.startsWith('bona://warning') && !cur.startsWith('bona://error')) return; // only from our own pages
    const target = new URL(url).searchParams.get('url');
    if (!target || !/^https?:/.test(target)) return;
    const host = new URL(target).hostname;
    if (url.startsWith('bona://proceedhttp') || url.startsWith('bona://proceed-http')) {
      httpAllowed.add(host);
      wc.loadURL(target.replace(/^https:/, 'http:'));
    } else {
      phishAllowed.add(host);
      wc.loadURL(target);
    }
  };
  wc.on('will-navigate', intercept);
  wc.on('will-redirect', intercept);

  // Popups -> new tab (never a raw window)
  wc.setWindowOpenHandler(({ url, disposition }) => {
    if (/^(https?|bona):/.test(url)) newTab(tab.winId, url, { activate: disposition !== 'background-tab' });
    else if (/^mailto:/.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
  wc.on('before-input-event', (e, input) => handleShortcut(e, input, tab.winId));
  wc.on('context-menu', (_e, p) => contextMenu(tab, p));
  wc.on('enter-html-full-screen', () => { const w = windows.get(tab.winId); if (w) { w.fullscreen = true; layout(tab.winId); } });
  wc.on('leave-html-full-screen', () => { const w = windows.get(tab.winId); if (w) { w.fullscreen = false; layout(tab.winId); } });
}

function activateTab(winId, tabId) {
  const w = windows.get(winId);
  if (!w || !w.tabs.has(tabId)) return;
  if (w.active && w.tabs.has(w.active)) w.win.contentView.removeChildView(w.tabs.get(w.active).view);
  w.active = tabId;
  w.win.contentView.addChildView(w.tabs.get(tabId).view);
  layout(winId);
  w.tabs.get(tabId).view.webContents.focus();
  scheduleUpdate(winId);
}

function closeTab(winId, tabId) {
  const w = windows.get(winId);
  if (!w || !w.tabs.has(tabId)) return;
  const tab = w.tabs.get(tabId);
  const idx = w.order.indexOf(tabId);
  if (w.active === tabId) w.win.contentView.removeChildView(tab.view);
  w.order.splice(idx, 1);
  w.tabs.delete(tabId);
  tabByWc.delete(tab.wcId);
  tab.view.webContents.close();
  if (w.order.length === 0) { w.win.close(); return; }
  if (w.active === tabId) { w.active = null; activateTab(winId, w.order[Math.min(idx, w.order.length - 1)]); }
  else scheduleUpdate(winId);
}

function layout(winId) {
  const w = windows.get(winId);
  if (!w || !w.active) return;
  const [cw, ch] = w.win.getContentSize();
  const view = w.tabs.get(w.active)?.view;
  if (!view) return;
  if (w.fullscreen) return view.setBounds({ x: 0, y: 0, width: cw, height: ch });
  const pw = w.panel ? PANEL_WIDTH : 0;
  view.setBounds({ x: 0, y: UI_HEIGHT, width: Math.max(0, cw - pw), height: Math.max(0, ch - UI_HEIGHT) });
}

// ---------------------------------------------------------------- UI sync
const pending = new Set();
function scheduleUpdate(winId) {
  if (pending.has(winId)) return;
  pending.add(winId);
  setTimeout(() => { pending.delete(winId); sendState(winId); }, 30);
}
function broadcastAll() { for (const id of windows.keys()) scheduleUpdate(id); }

function securityInfo(tab) {
  const url = tab.view.webContents.getURL();
  let scheme = '';
  try { scheme = new URL(url).protocol; } catch {}
  let level = 'neutral';
  if (scheme === 'bona:') level = 'internal';
  else if (scheme === 'https:') level = tab.urlVerdict ? 'warn' : 'secure';
  else if (scheme === 'http:') level = 'insecure';
  return { level, verdict: tab.urlVerdict };
}

function sendState(winId) {
  const w = windows.get(winId);
  if (!w || w.win.isDestroyed()) return;
  const tabs = w.order.map(id => {
    const t = w.tabs.get(id);
    const wc = t.view.webContents;
    const url = wc.getURL();
    const origin = safeOrigin(url);
    const perms = [];
    for (const [k, v] of permissionDecisions) {
      const [part, o, p] = k.split('|');
      if (part === w.partition && o === origin) perms.push({ permission: p, allowed: v });
    }
    return {
      id: t.id, title: t.title || url, url: addressFor(url), displayUrl: url,
      favicon: t.favicon, loading: t.loading,
      canGoBack: wc.navigationHistory.canGoBack(), canGoForward: wc.navigationHistory.canGoForward(),
      blocked: t.blocked, blockedHosts: t.blockedHosts, security: securityInfo(t), permissions: perms
    };
  });
  w.win.webContents.send('state', {
    tabs, active: w.active, private: w.private, settings, totalBlocked,
    searchEngines: Object.fromEntries(Object.entries(SEARCH).map(([k, v]) => [k, v.name])),
    trackerRules: TRACKER_COUNT, version: app.getVersion()
  });
}
function addressFor(url) {
  if (url.startsWith('bona://home')) return '';
  if (url.startsWith('bona://warning') || url.startsWith('bona://error')) {
    try { return new URL(url).searchParams.get('url') || url; } catch { return url; }
  }
  return url;
}
function broadcastDownloads() {
  for (const w of windows.values()) if (!w.win.isDestroyed()) w.win.webContents.send('downloads', downloads.slice(0, 50));
}

// ---------------------------------------------------------------- navigation helpers
function toUrl(input) {
  const s = input.trim();
  if (!s) return homeUrl();
  if (/^(https?|bona|file):\/\//i.test(s)) return s;
  if (/^(localhost|(\d{1,3}\.){3}\d{1,3})(:\d+)?(\/.*)?$/i.test(s)) return 'http://' + s;
  if (!/\s/.test(s) && /^[^\s/]+\.[a-z]{2,}(:\d+)?(\/.*)?$/i.test(s)) return 'https://' + s;
  return (SEARCH[settings.searchEngine] || SEARCH.duckduckgo).url + encodeURIComponent(s);
}
function activeTab(winId) { const w = windows.get(winId); return w && w.active ? w.tabs.get(w.active) : null; }

function handleShortcut(e, input, winId) {
  if (input.type !== 'keyDown') return;
  const ctrl = input.control || input.meta;
  const k = input.key.toLowerCase();
  const w = windows.get(winId);
  const t = activeTab(winId);
  let handled = true;
  if (ctrl && input.shift && k === 'n') createWindow({ isPrivate: true });
  else if (ctrl && k === 'n') createWindow();
  else if (ctrl && k === 't') newTab(winId, homeUrl());
  else if (ctrl && k === 'w') t && closeTab(winId, t.id);
  else if ((ctrl && k === 'r') || k === 'f5') t && t.view.webContents.reload();
  else if (ctrl && k === 'l') { w.win.webContents.focus(); w.win.webContents.send('focus-address'); }
  else if (input.alt && k === 'arrowleft') t && t.view.webContents.navigationHistory.goBack();
  else if (input.alt && k === 'arrowright') t && t.view.webContents.navigationHistory.goForward();
  else if (ctrl && k === 'tab') {
    const i = w.order.indexOf(w.active);
    const n = w.order.length;
    activateTab(winId, w.order[(i + (input.shift ? n - 1 : 1)) % n]);
  }
  else if (k === 'f12' || (ctrl && input.shift && k === 'i')) t && t.view.webContents.toggleDevTools();
  else if (ctrl && (k === '=' || k === '+')) t && t.view.webContents.setZoomLevel(t.view.webContents.getZoomLevel() + 0.5);
  else if (ctrl && k === '-') t && t.view.webContents.setZoomLevel(t.view.webContents.getZoomLevel() - 0.5);
  else if (ctrl && k === '0') t && t.view.webContents.setZoomLevel(0);
  else if (ctrl && k === 'p') t && t.view.webContents.print();
  else if (k === 'f11') w.win.setFullScreen(!w.win.isFullScreen());
  else handled = false;
  if (handled) e.preventDefault();
}

function contextMenu(tab, p) {
  const wc = tab.view.webContents;
  const items = [];
  if (p.linkURL) {
    items.push({ label: 'Open link in new tab', click: () => newTab(tab.winId, p.linkURL, { activate: false }) });
    items.push({ label: 'Open link in private window', click: () => { const pw = createWindow({ isPrivate: true }); pw.webContents.once('did-finish-load', () => { const st = windows.get(pw.id); setTimeout(() => st && st.active && st.tabs.get(st.active).view.webContents.loadURL(p.linkURL), 50); }); } });
    items.push({ label: 'Copy link address', click: () => require('electron').clipboard.writeText(p.linkURL) });
    items.push({ type: 'separator' });
  }
  if (p.hasImageContents && p.srcURL) {
    items.push({ label: 'Open image in new tab', click: () => newTab(tab.winId, p.srcURL) });
    items.push({ label: 'Save image as…', click: () => wc.downloadURL(p.srcURL) });
    items.push({ type: 'separator' });
  }
  if (p.isEditable) items.push({ role: 'cut' }, { role: 'copy' }, { role: 'paste' }, { type: 'separator' });
  else if (p.selectionText) {
    items.push({ role: 'copy' });
    items.push({ label: `Search for "${p.selectionText.slice(0, 30)}"`, click: () => newTab(tab.winId, toUrl(p.selectionText)) });
    items.push({ type: 'separator' });
  }
  items.push({ label: 'Back', enabled: wc.navigationHistory.canGoBack(), click: () => wc.navigationHistory.goBack() });
  items.push({ label: 'Forward', enabled: wc.navigationHistory.canGoForward(), click: () => wc.navigationHistory.goForward() });
  items.push({ label: 'Reload', click: () => wc.reload() });
  items.push({ type: 'separator' });
  items.push({ label: 'Inspect element', click: () => wc.inspectElement(p.x, p.y) });
  Menu.buildFromTemplate(items).popup({ window: windows.get(tab.winId)?.win });
}

// ---------------------------------------------------------------- IPC from browser UI
function winIdOf(e) { const w = BrowserWindow.fromWebContents(e.sender); return w && w.id; }
ipcMain.on('cmd', async (e, cmd, arg) => {
  const winId = winIdOf(e);
  const w = windows.get(winId);
  if (!w) return;
  const t = activeTab(winId);
  switch (cmd) {
    case 'navigate': if (t) t.view.webContents.loadURL(toUrl(String(arg || ''))); break;
    case 'back': t && t.view.webContents.navigationHistory.goBack(); break;
    case 'forward': t && t.view.webContents.navigationHistory.goForward(); break;
    case 'reload': t && t.view.webContents.reload(); break;
    case 'stop': t && t.view.webContents.stop(); break;
    case 'home': t && t.view.webContents.loadURL(homeUrl()); break;
    case 'new-tab': newTab(winId, homeUrl()); break;
    case 'close-tab': closeTab(winId, Number(arg)); break;
    case 'activate-tab': activateTab(winId, Number(arg)); break;
    case 'new-window': createWindow(); break;
    case 'new-private': createWindow({ isPrivate: true }); break;
    case 'panel': w.panel = !!arg; layout(winId); break;
    case 'devtools': t && t.view.webContents.toggleDevTools(); break;
    case 'zoom-in': t && t.view.webContents.setZoomLevel(t.view.webContents.getZoomLevel() + 0.5); break;
    case 'zoom-out': t && t.view.webContents.setZoomLevel(t.view.webContents.getZoomLevel() - 0.5); break;
    case 'print': t && t.view.webContents.print(); break;
    case 'set-setting': {
      const { key, value } = arg || {};
      if (key in DEFAULTS && typeof value === typeof DEFAULTS[key]) {
        if (key === 'searchEngine' && !SEARCH[value]) break;
        settings[key] = value; saveSettings(); broadcastAll();
      }
      break;
    }
    case 'revoke-permission': {
      const origin = t ? safeOrigin(t.view.webContents.getURL()) : '';
      permissionDecisions.delete(`${w.partition}|${origin}|${arg}`);
      broadcastAll();
      break;
    }
    case 'clear-data': {
      const r = await dialog.showMessageBox(w.win, {
        type: 'warning', title: 'BONA — Clear browsing data', icon: nativeImage.createFromPath(ICON),
        message: 'Clear cookies, cache, site data and history?',
        detail: 'You will be signed out of most websites.', buttons: ['Cancel', 'Clear everything'], defaultId: 0, cancelId: 0
      });
      if (r.response === 1) {
        await w.ses.clearStorageData(); await w.ses.clearCache(); await w.ses.clearAuthCache();
        for (const tab of w.tabs.values()) tab.view.webContents.navigationHistory.clear();
        for (const k of [...permissionDecisions.keys()]) if (k.startsWith(w.partition + '|')) permissionDecisions.delete(k);
        httpAllowed.clear(); phishAllowed.clear();
        broadcastAll();
      }
      break;
    }
    case 'open-download': { const d = downloads.find(x => x.id === arg); if (d) shell.showItemInFolder(d.path); break; }
    case 'request-state': sendState(winId); broadcastDownloads(); break;
  }
});

// ---------------------------------------------------------------- app lifecycle
app.on('web-contents-created', (_e, contents) => {
  contents.on('will-attach-webview', e => e.preventDefault());
});

// Reject every invalid certificate (Electron's default) — the tab shows our error page.
app.on('certificate-error', (event, _wc, _url, _err, _cert, callback) => { callback(false); });

const gotLock = app.requestSingleInstanceLock();
if (!gotLock) app.quit();
app.on('second-instance', (_e, argv) => {
  const url = argv.find(a => /^https?:\/\//.test(a));
  const first = [...windows.values()][0];
  if (first) { if (first.win.isMinimized()) first.win.restore(); first.win.focus(); if (url) newTab(first.win.id, url); }
  else createWindow();
});

app.whenReady().then(() => {
  loadSettings();
  Menu.setApplicationMenu(null);
  const win = createWindow();
  const startUrl = process.argv.find(a => /^https?:\/\//.test(a));
  if (startUrl) win.webContents.once('did-finish-load', () => setTimeout(() => { const t = activeTab(win.id); t && t.view.webContents.loadURL(startUrl); }, 100));
});

app.on('window-all-closed', async () => {
  if (settings.clearOnExit) {
    const ses = session.fromPartition('persist:bona');
    try { await ses.clearStorageData(); await ses.clearCache(); } catch {}
  }
  app.quit();
});
