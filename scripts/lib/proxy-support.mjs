// ── Route all fetch() traffic through an upstream proxy (e.g. Burp Suite / OWASP ZAP) so a human
// can inspect/replay requests for manual follow-up testing. Node's global fetch is powered by
// undici, so setting a global ProxyAgent dispatcher covers every fetch() call in the process —
// Playwright's browser traffic is proxied separately via its own native `proxy` launch option. ──
import { ProxyAgent, setGlobalDispatcher } from 'undici';

export function configureFetchProxy(proxyUrl) {
  if (!proxyUrl) return;
  setGlobalDispatcher(new ProxyAgent(proxyUrl));
}

export function playwrightProxyOption(proxyUrl) {
  return proxyUrl ? { server: proxyUrl } : undefined;
}
