// ── TLS protocol-version enumeration: actually attempts a handshake pinned to each protocol
// version, rather than only reporting whatever the server negotiated on one default connection.
// Node's bundled OpenSSL refuses to even attempt TLSv1/TLSv1.1 by default (SECLEVEL restriction) —
// `@SECLEVEL=0` in the cipher string lifts that CLIENT-side restriction so the server's real answer
// comes through. Forcing individually weak cipher suites (RC4/3DES/NULL/export-grade) is NOT
// included: modern Node's OpenSSL build has those compiled out entirely ("no cipher match" even
// with SECLEVEL=0), so we cannot reliably ask the server that question from this client at all —
// claiming to test for them would risk a false "not vulnerable" reading. ──
import tls from 'node:tls';

const PROTOCOLS = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'];
const LEGACY_PROTOCOLS = new Set(['TLSv1', 'TLSv1.1']);

function probeProtocol(host, port, protocol, timeoutMs) {
  return new Promise((resolve) => {
    let settled = false;
    let socket;
    try {
      socket = tls.connect({
        host, port, servername: host, minVersion: protocol, maxVersion: protocol,
        rejectUnauthorized: false, timeout: timeoutMs, ciphers: 'DEFAULT@SECLEVEL=0',
      });
    } catch (e) {
      resolve({ protocol, supported: false, testable: true, error: String(e?.message || e) });
      return;
    }
    const finish = (supported, error) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ protocol, supported, testable: true, error: error || null });
    };
    socket.setTimeout(timeoutMs, () => finish(false, 'timeout'));
    socket.once('secureConnect', () => finish(true, null));
    socket.once('error', (e) => finish(false, String(e?.message || e)));
  });
}

export async function enumerateTlsProtocols(host, { port = 443, timeoutMs = 6000 } = {}) {
  const results = [];
  for (const protocol of PROTOCOLS) {
    results.push(await probeProtocol(host, port, protocol, timeoutMs));
  }
  return results;
}

export function getWeakProtocolFindings(protocolResults = []) {
  return protocolResults.filter((r) => r.supported && LEGACY_PROTOCOLS.has(r.protocol));
}
