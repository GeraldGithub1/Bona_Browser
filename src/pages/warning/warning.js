'use strict';
const p = new URLSearchParams(location.search);
const url = p.get('url') || '';
document.getElementById('url').textContent = url;
let reasons = [];
try { reasons = JSON.parse(p.get('reasons') || '[]'); } catch {}
const ul = document.getElementById('reasons');
for (const r of reasons) { const li = document.createElement('li'); li.textContent = r; ul.append(li); }
document.getElementById('proceed').href = 'bona://proceed/?url=' + encodeURIComponent(url);
document.getElementById('back').onclick = () => {
  if (history.length > 1) history.back(); else location.href = 'bona://home/';
};
