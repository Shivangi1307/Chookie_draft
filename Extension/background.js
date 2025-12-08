// chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
//   if (msg.action === "getCookies") {
//     chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
//       const url = tabs[0].url;

//       chrome.cookies.getAll({ url }, (cookies) => {
//         sendResponse({ cookies });
//       });
//     });

//     // Keep the message channel open for async response
//     return true;
//   }
// });
// background.js - Cookielicious service worker
// Provides cookie scoring and responds to popup requests.
// Note: in MV3 this runs as a service worker; avoid using window.*

/* CONFIG/TUNABLES */
const CONFIG = {
  WEIGHTS: {
    AUTH_BASE: 20,
    MISSING_HTTPONLY_AUTH: 30,
    MISSING_HTTPONLY_NONAUTH: 10,
    MISSING_SECURE_AUTH: 30,
    MISSING_SECURE_NONAUTH: 15,
    SAMESITE_NONE: 20,
    SAMESITE_NONE_NO_SECURE_EXTRA: 40,
    SAMESITE_LAX: 5,
    DOMAIN_BROAD: 10,
    PATH_ROOT_AUTH: 10,
    EXPIRES_30_DAYS: 8,
    EXPIRES_365_DAYS_EXTRA: 10,
    VALUE_PII_OR_JWT: 25,
    LOW_ENTROPY: 12,
    PARTITIONED_BONUS: -10,
    CROSSSITE_PENALTY: 15,
    SIZE_OVER_4KB: 8
  },
  THRESHOLDS: {
    AUTH_MIN_LENGTH: 20,
    TOKEN_SHORT_LENGTH: 12,
    ENTROPY_SUSPICIOUS: 3.0,
    EXPIRES_DAYS_WARN: 30,
    EXPIRES_DAYS_BAD: 365,
    SIZE_BYTES_SUSPICIOUS: 4096
  },
  AUTH_NAME_KEYWORDS: [
    'session','sessionid','sess','auth','token','jwt','access','refresh','sid','userid'
  ],
  PII_REGEX: /\b(email|user|username|pwd|password|phone|tel|ssn|socialsecurity|account)\b|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/i,
  JWT_REGEX: /^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$/,
  SAMESITE_MAP: {
    'no_restriction': 'None',
    'unspecified': 'Lax',
    'none': 'None',
    'lax': 'Lax',
    'strict': 'Strict'
  }
};

/* Utility functions */

function shannonEntropyPerChar(s) {
  if (!s || s.length === 0) return 0;
  const freq = Object.create(null);
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    freq[c] = (freq[c] || 0) + 1;
  }
  const len = s.length;
  let H = 0;
  for (const c in freq) {
    const p = freq[c] / len;
    H -= p * Math.log2(p);
  }
  return H;
}

function daysUntilExpiry(cookie) {
  const exp = cookie.expirationDate || cookie.expires || null;
  if (!exp) return null;
  const expMs = (exp > 1e12) ? exp : exp * 1000;
  const days = (expMs - Date.now()) / (1000 * 60 * 60 * 24);
  return days;
}

function isDomainBroad(domain) {
  if (!domain) return false;
  if (domain.startsWith('.')) return true;
  const parts = domain.replace(/^\./,'').split('.');
  if (parts.length <= 2) return true;
  return false;
}

function normalizeSameSite(raw) {
  if (!raw) return 'Lax';
  const r = String(raw).toLowerCase();
  for (const k in CONFIG.SAMESITE_MAP) {
    if (k === r) return CONFIG.SAMESITE_MAP[k];
  }
  if (r === 'none' || r === 'lax' || r === 'strict') return r[0].toUpperCase() + r.slice(1);
  return 'Lax';
}

function looksLikeJWT(val) {
  if (!val) return false;
  return CONFIG.JWT_REGEX.test(val.trim());
}

function containsPII(val) {
  if (!val) return false;
  return CONFIG.PII_REGEX.test(val);
}

function isLikelyAuthByName(name) {
  if (!name) return false;
  const n = name.toLowerCase();
  for (const kw of CONFIG.AUTH_NAME_KEYWORDS) {
    if (n.includes(kw)) return true;
  }
  return false;
}

/* Core scoring function - returns score + details */
function scoreCookieRaw(cookie) {
  let score = 0;
  const issues = [];

  const name = cookie.name || '';
  const value = (cookie.value === undefined || cookie.value === null) ? '' : String(cookie.value);
  const httpOnly = !!cookie.httpOnly;
  const secure = !!cookie.secure;
  const path = cookie.path || '/';
  const domain = cookie.domain || '';
  const size = cookie.value ? new Blob([cookie.value]).size : (cookie.size || 0);
  const sameSite = normalizeSameSite(cookie.sameSite || cookie.same_site || cookie.sameSiteStatus);
  const partitioned = !!(cookie.partitionKey || cookie.partitioned || cookie.partitioned === true);
  const crossSite = !!cookie.crossSite || !!cookie.sameParty;
  const isThirdParty = !!cookie.thirdParty;

  // Auth detection
  const isAuthByName = isLikelyAuthByName(name);
  const isJWT = looksLikeJWT(value);
  const isLongToken = value.length >= CONFIG.THRESHOLDS.AUTH_MIN_LENGTH;
  const isAuth = isAuthByName || isJWT || isLongToken;

  if (isAuth) {
    score += CONFIG.WEIGHTS.AUTH_BASE;
    issues.push({
      code: 'IS_AUTH',
      severity: 'info',
      message: 'Looks like authentication/session token.',
      fix: 'Treat as sensitive. Set HttpOnly, Secure and proper SameSite on server.'
    });
  }

  // HttpOnly
  if (!httpOnly) {
    const points = isAuth ? CONFIG.WEIGHTS.MISSING_HTTPONLY_AUTH : CONFIG.WEIGHTS.MISSING_HTTPONLY_NONAUTH;
    score += points;
    issues.push({
      code: 'NO_HTTPONLY',
      severity: isAuth ? 'critical' : 'warning',
      message: 'Cookie is not HttpOnly — JavaScript can read it.',
      fix: isAuth
        ? 'Set HttpOnly on auth cookies: Set-Cookie: HttpOnly'
        : 'If not needed in JS, set HttpOnly on server.'
    });
  }

  // Secure
  if (!secure) {
    const points = isAuth ? CONFIG.WEIGHTS.MISSING_SECURE_AUTH : CONFIG.WEIGHTS.MISSING_SECURE_NONAUTH;
    score += points;
    issues.push({
      code: 'NO_SECURE',
      severity: isAuth ? 'critical' : 'warning',
      message: 'Cookie is not Secure — may be sent over HTTP.',
      fix: 'Serve via HTTPS and set Secure: Set-Cookie: Secure'
    });
  }

  // SameSite
  if (sameSite === 'None') {
    if (!secure) {
      score += CONFIG.WEIGHTS.SAMESITE_NONE_NO_SECURE_EXTRA;
      issues.push({
        code: 'SAMESITE_NONE_NO_SECURE',
        severity: 'critical',
        message: 'SameSite=None but cookie is not Secure — unsafe and may be rejected.',
        fix: 'If using SameSite=None, set Secure. Prefer Lax/Strict for auth cookies.'
      });
    } else {
      score += CONFIG.WEIGHTS.SAMESITE_NONE;
      issues.push({
        code: 'SAMESITE_NONE',
        severity: isAuth ? 'high' : 'warning',
        message: 'SameSite=None allows cross-site sending (CSRF/tracking risk).',
        fix: 'Use SameSite=Lax/Strict for auth tokens unless cross-site is required.'
      });
    }
  } else if (sameSite === 'Lax') {
    score += CONFIG.WEIGHTS.SAMESITE_LAX;
  }

  // Domain & Path
  if (isDomainBroad(domain)) {
    score += CONFIG.WEIGHTS.DOMAIN_BROAD;
    issues.push({
      code: 'BROAD_DOMAIN',
      severity: 'medium',
      message: `Cookie domain appears broad (${domain}).`,
      fix: 'Use host-only domain or restrict to specific subdomain.'
    });
  }
  if (path === '/') {
    score += isAuth ? CONFIG.WEIGHTS.PATH_ROOT_AUTH : 2;
    if (isAuth) {
      issues.push({
        code: 'ROOT_PATH',
        severity: 'medium',
        message: 'Auth cookie path is "/", sent to all site paths.',
        fix: 'Restrict path (e.g., /auth or /api).'
      });
    }
  }

  // Expiry
  const days = daysUntilExpiry(cookie);
  if (days !== null) {
    if (days > CONFIG.THRESHOLDS.EXPIRES_DAYS_WARN && isAuth) {
      score += CONFIG.WEIGHTS.EXPIRES_30_DAYS;
      issues.push({
        code: 'LONG_EXPIRY',
        severity: 'medium',
        message: `Auth cookie expires in ${Math.round(days)} days.`,
        fix: 'Consider shorter expiry or refresh tokens with rotation.'
      });
    }
    if (days > CONFIG.THRESHOLDS.EXPIRES_DAYS_BAD) {
      score += CONFIG.WEIGHTS.EXPIRES_365_DAYS_EXTRA;
      issues.push({
        code: 'VERY_LONG_EXPIRY',
        severity: 'high',
        message: `Cookie expiry is very long (${Math.round(days)} days).`,
        fix: 'Reduce lifetime; implement server-side revocation/rotation.'
      });
    }
  }

  // Value checks: JWT / PII / entropy
  if (isJWT) {
    score += CONFIG.WEIGHTS.VALUE_PII_OR_JWT;
    issues.push({
      code: 'JWT_DETECTED',
      severity: 'high',
      message: 'JWT detected; payload is readable and may contain sensitive claims.',
      fix: 'Avoid putting PII in JWT payload; ensure exp is present; use HttpOnly+Secure.'
    });

    try {
      const parts = value.split('.');
      const payloadB64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
      const padded = payloadB64.padEnd(Math.ceil(payloadB64.length / 4) * 4, '=');
      const json = atob(padded);
      if (CONFIG.PII_REGEX.test(json)) {
        score += 10;
        issues.push({
          code: 'JWT_PII_IN_PAYLOAD',
          severity: 'high',
          message: 'JWT payload contains PII (email/username).',
          fix: 'Do not store PII in JWT payloads.'
        });
      }
      if (!/("exp"\s*:)/i.test(json)) {
        score += 10;
        issues.push({
          code: 'JWT_NO_EXP',
          severity: 'high',
          message: 'JWT payload appears to lack exp.',
          fix: 'Include exp in JWT and keep tokens short-lived.'
        });
      }
    } catch (e) {
      // decoding failed - ignore silently
    }
  }

  if (containsPII(value)) {
    score += CONFIG.WEIGHTS.VALUE_PII_OR_JWT;
    issues.push({
      code: 'PII_IN_VALUE',
      severity: 'high',
      message: 'Cookie contains PII (email/username).',
      fix: 'Avoid storing PII in cookies; keep PII server-side.'
    });
  }

  const ent = shannonEntropyPerChar(value);
  if (value.length < CONFIG.THRESHOLDS.TOKEN_SHORT_LENGTH || ent < CONFIG.THRESHOLDS.ENTROPY_SUSPICIOUS) {
    score += CONFIG.WEIGHTS.LOW_ENTROPY;
    issues.push({
      code: 'LOW_ENTROPY',
      severity: 'medium',
      message: `Low entropy (${ent.toFixed(2)} bits/char) or too short (${value.length} chars).`,
      fix: 'Use long, CSPRNG-generated tokens server-side.'
    });
  }

  // Partitioning & cross-site
  if (partitioned) {
    score += CONFIG.WEIGHTS.PARTITIONED_BONUS;
  } else if (isThirdParty) {
    score += 10;
    issues.push({
      code: '3P_NOT_PARTITIONED',
      severity: 'medium',
      message: 'Third-party cookie not partitioned — tracking risk.',
      fix: 'Consider Partitioned or privacy-preserving alternatives.'
    });
  }

  if (crossSite && sameSite !== 'Strict') {
    score += CONFIG.WEIGHTS.CROSSSITE_PENALTY;
    issues.push({
      code: 'CROSS_SITE_AVAILABLE',
      severity: 'medium',
      message: 'Cookie is available cross-site with SameSite != Strict.',
      fix: 'Re-evaluate need for cross-site access; add CSRF tokens if required.'
    });
  }

  if (size > CONFIG.THRESHOLDS.SIZE_BYTES_SUSPICIOUS) {
    score += CONFIG.WEIGHTS.SIZE_OVER_4KB;
    issues.push({
      code: 'LARGE_COOKIE_SIZE',
      severity: 'info',
      message: `Cookie size > ${CONFIG.THRESHOLDS.SIZE_BYTES_SUSPICIOUS} bytes.`,
      fix: 'Avoid storing large data in cookies; use server-side session storage.'
    });
  }

  if (score < 0) score = 0;
  if (score > 100) score = 100;

  let classification = 'Safe';
  if (score > 50) classification = 'High risk';
  else if (score > 20) classification = 'Medium risk';

  return {
    score,
    classification,
    entropy: ent,
    isAuth,
    issues
  };
}

/* Expose scorer on globalThis if needed */
globalThis.cookieScorer = {
  scoreCookie: scoreCookieRaw,
  CONFIG
};

/* Message handler: respond to getCookies from popup */
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.action === 'getCookies') {
    // find active tab to use its URL as cookie filter
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = (tabs && tabs[0]) ? tabs[0] : null;
      const url = tab && tab.url ? tab.url : msg.url;
      if (!url) {
        sendResponse({ error: 'No active tab URL found.' });
        return;
      }

      chrome.cookies.getAll({ url }, (cookies) => {
        const results = cookies.map(c => {
          const r = scoreCookieRaw(c);
          return { cookie: c, result: r };
        });
        sendResponse({ cookies: results });
      });
    });
    // keep channel open
    return true;
  }
});

