'use strict';
const ENGINES = {
  duckduckgo: ['DuckDuckGo', 'https://duckduckgo.com/'],
  google: ['Google', 'https://www.google.com/search'],
  bing: ['Bing', 'https://www.bing.com/search'],
  brave: ['Brave Search', 'https://search.brave.com/search']
};
const key = new URLSearchParams(location.search).get('engine');
const [name, action] = ENGINES[key] || ENGINES.duckduckgo;
const form = document.getElementById('f');
form.action = action;
document.getElementById('engine').textContent = 'Searching with ' + name;
form.addEventListener('submit', (e) => {
  const v = document.getElementById('q').value.trim();
  if (!v) { e.preventDefault(); return; }
  // Typed an address? Go straight there.
  if (!/\s/.test(v) && /^(https?:\/\/)?[^\s/]+\.[a-z]{2,}(\/.*)?$/i.test(v)) {
    e.preventDefault();
    location.href = /^https?:\/\//i.test(v) ? v : 'https://' + v;
  }
});
