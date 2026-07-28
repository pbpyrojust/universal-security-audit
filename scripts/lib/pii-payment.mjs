// ── PII exposure scanning + payment/donation processor detection ──

const EMAIL_RE = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi;
const PHONE_RE = /(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b/g;
const SSN_RE = /\b\d{3}-\d{2}-\d{4}\b/g;
// Loose 13-19 digit sequences with optional separators, then Luhn-validated to cut false positives.
const CC_CANDIDATE_RE = /\b(?:\d[ -]?){13,19}\b/g;

const SECRET_PATTERNS = [
  { name: 'AWS Access Key ID', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'Stripe live secret key', re: /\bsk_live_[0-9a-zA-Z]{16,}\b/g },
  { name: 'Stripe live publishable key', re: /\bpk_live_[0-9a-zA-Z]{16,}\b/g },
  { name: 'Google API key', re: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
  { name: 'Slack token', re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g },
  { name: 'Generic private key block', re: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g },
  { name: 'GitHub token', re: /\bgh[pousr]_[0-9A-Za-z]{36,}\b/g },
];

function luhnValid(digits) {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

export function scanForPii(text = '') {
  const findings = { emails: new Set(), phones: new Set(), ssnLike: new Set(), cardLike: new Set(), secrets: [] };
  for (const m of text.matchAll(EMAIL_RE)) findings.emails.add(m[0].toLowerCase());
  for (const m of text.matchAll(PHONE_RE)) findings.phones.add(m[0]);
  for (const m of text.matchAll(SSN_RE)) findings.ssnLike.add(m[0]);
  for (const m of text.matchAll(CC_CANDIDATE_RE)) {
    const digits = m[0].replace(/[ -]/g, '');
    if (digits.length >= 13 && digits.length <= 19 && luhnValid(digits)) {
      findings.cardLike.add(digits.replace(/\d(?=\d{4})/g, '*'));
    }
  }
  for (const pattern of SECRET_PATTERNS) {
    const matches = [...text.matchAll(pattern.re)];
    if (matches.length) findings.secrets.push({ type: pattern.name, count: matches.length, sample: matches[0][0].slice(0, 12) + '…' });
  }
  return {
    emails: [...findings.emails],
    phones: [...findings.phones],
    ssnLike: [...findings.ssnLike],
    cardLike: [...findings.cardLike],
    secrets: findings.secrets,
  };
}

const PAYMENT_SIGNATURES = [
  { name: 'Stripe', re: /js\.stripe\.com|api\.stripe\.com|checkout\.stripe\.com/i },
  { name: 'PayPal', re: /paypal(?:objects)?\.com\/sdk|paypalobjects\.com/i },
  { name: 'Square', re: /squareup\.com|square\.site|js\.squarecdn\.com/i },
  { name: 'Donorbox', re: /donorbox\.org/i },
  { name: 'Classy', re: /classy\.org|classydonation/i },
  { name: 'Network for Good', re: /networkforgood\.com/i },
  { name: 'GiveWP', re: /give-\w+\.js|givewp/i },
  { name: 'WooCommerce', re: /woocommerce/i },
  { name: 'Shopify Checkout', re: /checkout\.shopify\.com|cdn\.shopify\.com\/s\/checkout/i },
  { name: 'Venmo', re: /venmo\.com/i },
  { name: 'Braintree', re: /braintreegateway\.com|js\.braintreegateway\.com/i },
  { name: 'Authorize.Net', re: /authorize\.net/i },
  { name: 'Kindful', re: /kindful\.com/i },
  { name: 'Bloomerang', re: /bloomerang\.co/i },
  { name: 'Salesforce/Luminate', re: /convio\.net|luminateonline\.com/i },
];

export function detectPaymentProcessors(html = '', scriptSrcs = []) {
  const haystack = html + ' ' + scriptSrcs.join(' ');
  const found = PAYMENT_SIGNATURES.filter((sig) => sig.re.test(haystack)).map((sig) => sig.name);
  const hasCardInputForm = /<input[^>]+(?:name|id|autocomplete)=["'][^"']*(?:card[-_]?number|cardnumber|cc-number)/i.test(html);
  const hasDonationLanguage = /\b(donate|donation|give now|make a gift)\b/i.test(html);
  return { processors: [...new Set(found)], hasCardInputForm, hasDonationLanguage };
}
