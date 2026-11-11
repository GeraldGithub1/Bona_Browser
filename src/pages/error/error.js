'use strict';
const p = new URLSearchParams(location.search);
const url = p.get('url') || '';
const code = Number(p.get('code'));
const desc = p.get('desc') || '';
const upgraded = p.get('upgraded') === '1';
const $ = (id) => document.getElementById(id);
$('url').textContent = url;
$('code').textContent = `${desc} (${code})`;

const isCert = code <= -200 && code > -300;
if (isCert) {
  $('title').textContent = 'Your connection is not private';
  $('msg').textContent = 'BONA blocked this site because its security certificate is invalid, expired or does not match the address. Someone may be trying to intercept your information.';
  $('msg').className = 'cert';
} else if (code === -105 || code === -137) {
  $('title').textContent = 'Site not found';
  $('msg').textContent = 'The address could not be found. Check the spelling or your internet connection.';
} else if (code === -106) {
  $('title').textContent = 'You are offline';
  $('msg').textContent = 'Check your network connection and try again.';
} else if (code === -20) {
  $('title').textContent = 'Blocked by BONA Shield';
  $('msg').textContent = 'This address is on BONA’s tracker / malware block list.';
} else {
  $('msg').textContent = 'Something went wrong while loading this page.';
}

if (upgraded && !isCert) {
  // HTTPS-Only mode upgraded this site, but it does not support HTTPS.
  $('title').textContent = 'Secure connection not available';
  $('msg').textContent = 'BONA’s HTTPS-Only mode tried to load this site securely, but it does not support HTTPS. If you continue, anything you send can be read by others on the network.';
  const a = $('http');
  a.hidden = false;
  a.href = 'bona://proceed-http/?url=' + encodeURIComponent(url);
}
$('retry').onclick = () => { if (url) location.href = url; else history.back(); };
