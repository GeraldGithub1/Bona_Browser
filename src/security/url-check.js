'use strict';
// Heuristic phishing / dangerous-URL detection. Runs locally — no URL is ever
// sent to a third-party service.

// Two-part public suffixes common in South Africa and elsewhere.
const MULTI_SUFFIXES = new Set([
  'co.za', 'org.za', 'gov.za', 'ac.za', 'net.za', 'web.za', 'edu.za',
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.in',
  'com.br', 'co.jp', 'com.ng', 'co.ke', 'com.na', 'co.bw', 'co.zw', 'com.gh', 'com.mx'
]);

// Brands that phishers commonly impersonate (including SA banks & services).
const BRANDS = [
  'paypal', 'apple', 'icloud', 'microsoft', 'office365', 'outlook', 'google', 'gmail', 'facebook',
  'instagram', 'whatsapp', 'netflix', 'amazon', 'binance', 'coinbase', 'metamask', 'dhl', 'fedex',
  'absa', 'fnb', 'standardbank', 'nedbank', 'capitecbank', 'capitec', 'investec', 'tymebank',
  'discovery', 'sars', 'efiling', 'takealot', 'vodacom', 'mtn', 'telkom', 'postoffice'
];

const SUSPICIOUS_TLDS = new Set([
  'zip', 'mov', 'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'click', 'link', 'work', 'rest',
  'country', 'kim', 'loan', 'download', 'review', 'racing', 'cam', 'monster'
]);

function registrableDomain(host) {
  if (!host) return '';
  host = host.toLowerCase().replace(/\.$/, '');
  if (isIp(host)) return host;
  const parts = host.split('.');
  if (parts.length <= 2) return host;
  const last2 = parts.slice(-2).join('.');
  if (MULTI_SUFFIXES.has(last2)) return parts.slice(-3).join('.');
  return last2;
}

function isIp(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[') || /^[0-9a-f:]+$/i.test(host) && host.includes(':');
}

function isLocalHost(host) {
  host = (host || '').toLowerCase();
  return host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') ||
    host === '127.0.0.1' || host === '[::1]' ||
    /^10\./.test(host) || /^192\.168\./.test(host) || /^172\.(1[6-9]|2\d|3[01])\./.test(host);
}

// Replace common look-alike characters so "paypa1" and "rnicrosoft" match brands.
function deconfuse(s) {
  return s.replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e').replace(/5/g, 's')
    .replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/-/g, '');
}

/**
 * Returns null when the URL looks fine, otherwise { level, reasons[] }.
 * level: 'danger' (likely phishing) | 'warn' (suspicious)
 */
function checkUrl(rawUrl) {
  let u;
  try { u = new URL(rawUrl); } catch { return null; }
  if (!/^https?:$/.test(u.protocol)) return null;
  const host = u.hostname.toLowerCase();
  if (isLocalHost(host)) return null;

  const reasons = [];
  let score = 0;
  const reg = registrableDomain(host);
  const label = reg.split('.')[0] || '';
  const tld = host.split('.').pop();

  if (u.username || u.password) { score += 3; reasons.push('The address hides its real destination using an "@" sign.'); }
  if (isIp(host)) { score += 2; reasons.push('The site uses a raw IP address instead of a domain name.'); }
  if (host.split('.').some(p => p.startsWith('xn--'))) { score += 2; reasons.push('The domain uses international characters that can imitate other sites (punycode).'); }
  if (SUSPICIOUS_TLDS.has(tld)) { score += 1; reasons.push(`The ".${tld}" domain ending is frequently used for scams.`); }
  if (host.split('.').length > 5) { score += 1; reasons.push('The address has an unusually deep chain of sub-domains.'); }
  if (host.length > 60) { score += 1; reasons.push('The domain name is unusually long.'); }

  // Brand impersonation: brand appears in host but is not the registrable label itself.
  // Tokens are host pieces split on "." and "-", e.g. "paypal-login.secure-x.com".
  const tokens = host.split(/[.-]/).filter(Boolean);
  for (const b of BRANDS) {
    if (label === b) continue; // the brand really owns this domain
    if (deconfuse(label) === b) {
      score += 3; reasons.push(`"${reg}" looks like a disguised copy of "${b}".`); break;
    }
    // A real brand domain embedded as a sub-domain, e.g. "paypal.com.verify-acct.ru"
    if (new RegExp(`(^|\\.)${b}\\.(com|net|org|co\\.za|co\\.uk)\\.`).test(host)) {
      score += 3; reasons.push(`The address pretends to be "${b}" but really belongs to "${reg}".`); break;
    }
    if (tokens.some(t => t === b || (t.length >= 5 && deconfuse(t) === b))) {
      score += 2; reasons.push(`The address mentions "${b}" but the site actually belongs to "${reg}".`); break;
    }
  }

  if (score >= 3) return { level: 'danger', reasons };
  if (score >= 2) return { level: 'warn', reasons };
  return null;
}

const DANGEROUS_EXT = new Set([
  'exe', 'msi', 'msix', 'bat', 'cmd', 'com', 'scr', 'pif', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh',
  'ps1', 'psm1', 'hta', 'cpl', 'jar', 'lnk', 'reg', 'dll', 'sh', 'run', 'bin', 'appimage', 'deb',
  'rpm', 'apk', 'iso', 'img', 'docm', 'xlsm', 'pptm'
]);

function isDangerousFile(filename) {
  const ext = (filename.split('.').pop() || '').toLowerCase();
  return DANGEROUS_EXT.has(ext);
}

module.exports = { checkUrl, registrableDomain, isLocalHost, isDangerousFile };
