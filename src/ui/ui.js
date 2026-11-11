'use strict';
/* BONA browser chrome. Untrusted text (titles, URLs) is only ever set via textContent. */
const $ = (id) => document.getElementById(id);
const api = window.bona;
let state = null;
let downloads = [];
let panel = null; // 'shield' | 'downloads' | 'menu' | null
let editing = false;

const isPrivate = new URLSearchParams(location.search).get('private') === '1';
if (isPrivate) { document.body.classList.add('private'); $('privbadge').hidden = false; document.title = 'BONA — Private'; }

function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'text') el.textContent = v;
    else if (k === 'style') el.style.cssText = v; // CSSOM is CSP-safe, unlike a style attribute
    else if (v !== false && v != null) el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat()) if (c != null) el.append(c.nodeType ? c : document.createTextNode(String(c)));
  return el;
}

// ------------------------------------------------------------ toolbar wiring
$('back').onclick = () => api.cmd('back');
$('forward').onclick = () => api.cmd('forward');
$('reload').onclick = () => api.cmd(activeTab()?.loading ? 'stop' : 'reload');
$('home').onclick = () => api.cmd('home');
$('newtab').onclick = () => api.cmd('new-tab');
$('shield').onclick = () => togglePanel('shield');
$('lock').onclick = () => togglePanel('shield');
$('dl').onclick = () => togglePanel('downloads');
$('menu').onclick = () => togglePanel('menu');
$('panel-close').onclick = () => togglePanel(null);

const addr = $('address');
addr.addEventListener('focus', () => { editing = true; setTimeout(() => addr.select(), 0); });
addr.addEventListener('blur', () => { editing = false; render(); });
addr.addEventListener('keydown', (e) => { if (e.key === 'Escape') { addr.blur(); } });
$('addressform').addEventListener('submit', (e) => {
  e.preventDefault();
  api.cmd('navigate', addr.value);
  addr.blur();
});

document.addEventListener('keydown', (e) => {
  const c = e.ctrlKey || e.metaKey;
  const k = e.key.toLowerCase();
  if (c && e.shiftKey && k === 'n') api.cmd('new-private');
  else if (c && k === 'n') api.cmd('new-window');
  else if (c && k === 't') api.cmd('new-tab');
  else if (c && k === 'w') activeTab() && api.cmd('close-tab', activeTab().id);
  else if (c && k === 'l') { addr.focus(); }
  else if ((c && k === 'r') || k === 'f5') api.cmd('reload');
  else return;
  e.preventDefault();
});

api.on('focus-address', () => addr.focus());
api.on('state', (s) => { state = s; render(); });
api.on('downloads', (d) => { downloads = d; if (panel === 'downloads') renderDownloads(); });
api.on('downloads-open', () => { if (panel !== 'downloads') togglePanel('downloads'); });
api.cmd('request-state');

function activeTab() { return state && state.tabs.find(t => t.id === state.active); }

function togglePanel(name) {
  panel = (name && panel !== name) ? name : null;
  $('panel').hidden = !panel;
  for (const p of ['shield', 'downloads', 'menu']) {
    $('p-' + p).hidden = panel !== p;
    $(p === 'downloads' ? 'dl' : p).classList.toggle('on', panel === p);
  }
  $('panel-title').textContent = { shield: 'BONA Shield', downloads: 'Downloads', menu: 'Menu & Settings' }[panel] || '';
  api.cmd('panel', !!panel);
  render();
}

// ------------------------------------------------------------ rendering
function render() {
  if (!state) return;
  const tabsEl = $('tabs');
  tabsEl.replaceChildren(...state.tabs.map(t => {
    const icon = t.loading ? h('span', { class: 'spin' })
      : t.favicon && /^(https?|data):/.test(t.favicon) ? h('img', { src: t.favicon, alt: '', onerror: (e) => e.target.replaceWith(h('span', { class: 'ph' })) })
      : h('img', { src: 'logo.svg', alt: '' });
    const el = h('div', { class: 'tab' + (t.id === state.active ? ' active' : ''), title: t.title,
      onmousedown: (e) => { if (e.button === 1) { e.preventDefault(); api.cmd('close-tab', t.id); } else if (e.button === 0) api.cmd('activate-tab', t.id); } },
      icon, h('span', { class: 'title', text: t.title || 'New Tab' }),
      h('button', { class: 'x', title: 'Close tab (Ctrl+W)', text: '×', onmousedown: (e) => { e.stopPropagation(); if (e.button === 0) api.cmd('close-tab', t.id); } }));
    return el;
  }));

  const t = activeTab();
  if (!t) return;
  $('back').disabled = !t.canGoBack;
  $('forward').disabled = !t.canGoForward;
  $('ico-reload').toggleAttribute('hidden', t.loading);
  $('ico-stop').toggleAttribute('hidden', !t.loading);
  if (!editing) addr.value = t.url;

  const lv = t.security.level;
  const lock = $('lock');
  lock.className = lv;
  $('locktext').textContent = { secure: 'Secure', insecure: 'Not secure', warn: 'Caution', internal: 'BONA', neutral: '' }[lv];

  const sc = $('shieldcount');
  sc.hidden = !t.blocked;
  sc.textContent = t.blocked > 99 ? '99+' : t.blocked;
  $('shield').classList.toggle('off', !state.settings.blockTrackers);

  if (panel === 'shield') renderShield(t);
  if (panel === 'menu') renderMenu();
  if (panel === 'downloads') renderDownloads();
}

function toggleRow(key, label, hint) {
  return h('div', { class: 'row' },
    h('label', { for: 'set-' + key }, label, hint ? h('small', { text: hint }) : null),
    h('input', { type: 'checkbox', class: 'switch', id: 'set-' + key, checked: !!state.settings[key],
      onchange: (e) => api.cmd('set-setting', { key, value: e.target.checked }) }));
}

function renderShield(t) {
  const lv = t.security.level;
  let host = '';
  try { host = new URL(t.displayUrl).hostname; } catch {}
  const headline = {
    secure: ['✓', 'Connection is secure', 'Information you send to this site is encrypted (HTTPS) and its certificate is valid.'],
    insecure: ['!', 'Connection is not secure', 'This page uses plain HTTP. Do not enter passwords or card details.'],
    warn: ['?', 'Be careful on this site', 'BONA found signs this site may be imitating another one.'],
    internal: ['B', 'BONA page', 'This is a built-in, trusted BONA page.'],
    neutral: ['·', 'Page', '']
  }[lv];
  const kids = [
    h('div', { class: 'card' },
      h('div', { class: 'status' }, h('div', { class: 'big ' + lv, text: headline[0] }),
        h('div', {}, h('h3', { text: headline[1] }), h('div', { class: 'muted', text: host }))),
      headline[2] ? h('p', { class: 'muted', text: headline[2] }) : null,
      t.security.verdict ? h('ul', { class: 'hosts' }, t.security.verdict.reasons.map(r => h('li', { text: r }))) : null)
  ];
  kids.push(h('div', { class: 'card' },
    h('h3', { text: 'Trackers & ads blocked on this page' }),
    h('div', { class: 'stat', text: String(t.blocked) }),
    h('div', { class: 'muted', text: `${state.totalBlocked} blocked since BONA started · ${state.trackerRules} built-in rules` }),
    t.blockedHosts.length ? h('ul', { class: 'hosts' }, t.blockedHosts.map(x => h('li', { text: x }))) : null));
  if (t.permissions.length) {
    kids.push(h('div', { class: 'card' }, h('h3', { text: 'Site permissions' }),
      t.permissions.map(p => h('div', { class: 'row' },
        h('label', {}, p.permission, h('small', { text: p.allowed ? 'Allowed' : 'Blocked' })),
        h('button', { class: 'btn small', text: 'Reset', onclick: () => api.cmd('revoke-permission', p.permission) })))));
  }
  kids.push(h('div', { class: 'card' }, h('h3', { text: 'Protection' }),
    toggleRow('blockTrackers', 'Block trackers, ads & crypto-miners'),
    toggleRow('httpsOnly', 'HTTPS-Only mode', 'Upgrades every connection to encrypted HTTPS'),
    toggleRow('phishingProtection', 'Phishing & fake-site warnings', 'Checked locally — nothing is sent anywhere'),
    toggleRow('blockThirdPartyCookies', 'Block third-party cookies', 'Stops cross-site tracking; some logins may break'),
    toggleRow('doNotTrack', 'Send Do-Not-Track & Global Privacy Control')));
  $('p-shield').replaceChildren(...kids);
}

function renderMenu() {
  const item = (label, kbd, fn) => h('button', { onclick: fn }, h('span', { text: label }), kbd ? h('kbd', { text: kbd }) : null);
  const engines = state.searchEngines;
  $('p-menu').replaceChildren(
    h('div', { class: 'card menu-list' },
      item('New tab', 'Ctrl+T', () => api.cmd('new-tab')),
      item('New window', 'Ctrl+N', () => api.cmd('new-window')),
      item('New private window', 'Ctrl+Shift+N', () => api.cmd('new-private')),
      item('Zoom in', 'Ctrl +', () => api.cmd('zoom-in')),
      item('Zoom out', 'Ctrl −', () => api.cmd('zoom-out')),
      item('Print…', 'Ctrl+P', () => api.cmd('print')),
      item('Developer tools', 'F12', () => api.cmd('devtools'))),
    h('div', { class: 'card' }, h('h3', { text: 'Search' }),
      h('div', { class: 'row' }, h('label', { for: 'eng', text: 'Search engine' }),
        h('select', { id: 'eng', onchange: (e) => api.cmd('set-setting', { key: 'searchEngine', value: e.target.value }) },
          Object.entries(engines).map(([k, n]) => h('option', { value: k, selected: state.settings.searchEngine === k, text: n }))))),
    h('div', { class: 'card' }, h('h3', { text: 'Privacy & security' }),
      toggleRow('warnDangerousDownloads', 'Warn before dangerous downloads', '.exe, .msi, .bat, .ps1, .sh, .apk and more'),
      toggleRow('clearOnExit', 'Clear cookies & cache when BONA closes'),
      h('div', { class: 'row' }, h('label', {}, 'Browsing data', h('small', { text: 'Cookies, cache, site storage, history' })),
        h('button', { class: 'btn danger small', text: 'Clear now', onclick: () => api.cmd('clear-data') }))),
    h('div', { class: 'card about' },
      h('img', { src: 'logo.svg', alt: '' }),
      h('h3', { text: `BONA ${state.version}` }),
      h('div', { class: 'muted', text: '“Bona” means seeing in Setswana.' }),
      h('div', { class: 'muted', text: 'Sandboxed tabs · HTTPS-Only · Tracker shield · Phishing guard' }))
  );
}

function fmt(n) { if (!n) return '0 B'; const u = ['B', 'KB', 'MB', 'GB']; let i = 0; while (n >= 1024 && i < 3) { n /= 1024; i++; } return n.toFixed(i ? 1 : 0) + ' ' + u[i]; }
function renderDownloads() {
  if (!downloads.length) { $('p-downloads').replaceChildren(h('p', { class: 'muted', text: 'No downloads yet.' })); return; }
  $('p-downloads').replaceChildren(h('div', { class: 'card' }, downloads.map(d => {
    const pct = d.total ? Math.round(d.received / d.total * 100) : 0;
    const label = d.state === 'completed' ? `Done · ${fmt(d.received)}` : d.state === 'cancelled' ? 'Cancelled'
      : d.state === 'interrupted' ? 'Failed' : `${fmt(d.received)} of ${d.total ? fmt(d.total) : '?'}`;
    return h('div', { class: 'dl' }, h('div', { class: 'name', text: d.name }),
      d.state === 'progressing' ? h('div', { class: 'bar' }, h('div', { style: `width:${pct}%` })) : null,
      h('div', { class: 'row' }, h('span', { class: 'muted', text: label }),
        d.state === 'completed' ? h('button', { class: 'btn small', text: 'Show in folder', onclick: () => api.cmd('open-download', d.id) }) : null));
  })));
}
