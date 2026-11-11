'use strict';
// Built-in tracker / ad / malware-host blocklist. Matching is by domain suffix,
// so "doubleclick.net" also blocks "stats.g.doubleclick.net".
const TRACKER_DOMAINS = [
  // Advertising networks
  'doubleclick.net', 'googlesyndication.com', 'googleadservices.com', 'adservice.google.com',
  'adnxs.com', 'adsrvr.org', 'advertising.com', 'amazon-adsystem.com', 'criteo.com', 'criteo.net',
  'taboola.com', 'outbrain.com', 'pubmatic.com', 'rubiconproject.com', 'openx.net', 'casalemedia.com',
  'smartadserver.com', 'moatads.com', 'adform.net', 'bidswitch.net', 'media.net', 'yieldmo.com',
  'sharethrough.com', 'teads.tv', 'zedo.com', 'revcontent.com', 'mgid.com', 'propellerads.com',
  'popads.net', 'popcash.net', 'adcolony.com', 'applovin.com', 'unityads.unity3d.com', 'inmobi.com',
  // Analytics / telemetry / session recording
  'google-analytics.com', 'googletagmanager.com', 'googletagservices.com', 'analytics.google.com',
  'hotjar.com', 'hotjar.io', 'mouseflow.com', 'fullstory.com', 'crazyegg.com', 'luckyorange.com',
  'clarity.ms', 'quantserve.com', 'scorecardresearch.com', 'chartbeat.com', 'chartbeat.net',
  'mixpanel.com', 'segment.io', 'segment.com', 'amplitude.com', 'heap.io', 'heapanalytics.com',
  'newrelic.com', 'nr-data.net', 'optimizely.com', 'kissmetrics.com', 'statcounter.com',
  'bat.bing.com', 'mc.yandex.ru', 'top-fwz1.mail.ru', 'hm.baidu.com',
  // Social tracking pixels & widgets
  'connect.facebook.net', 'pixel.facebook.com', 'ads.linkedin.com', 'px.ads.linkedin.com',
  'analytics.twitter.com', 'ads-twitter.com', 'static.ads-twitter.com', 'analytics.tiktok.com',
  'ads.tiktok.com', 'ct.pinterest.com', 'sc-static.net', 'tr.snapchat.com',
  // Data brokers / fingerprinting
  'bluekai.com', 'krxd.net', 'demdex.net', 'everesttech.net', 'exelator.com', 'rlcdn.com',
  'tapad.com', 'agkn.com', 'adsymptotic.com', 'lijit.com', 'mathtag.com', 'contextweb.com',
  'turn.com', 'addthis.com', 'sharethis.com', 'fingerprintjs.com', 'fpjs.io',
  // Crypto-jacking
  'coinhive.com', 'coin-hive.com', 'cryptoloot.pro', 'webminepool.com', 'minero.cc', 'jsecoin.com'
];

const set = new Set(TRACKER_DOMAINS);

function isBlockedHost(hostname) {
  if (!hostname) return false;
  let h = hostname.toLowerCase().replace(/\.$/, '');
  while (h.includes('.')) {
    if (set.has(h)) return true;
    h = h.slice(h.indexOf('.') + 1);
  }
  return false;
}

module.exports = { isBlockedHost, TRACKER_COUNT: TRACKER_DOMAINS.length };
