// ── Lightweight TCP connect-scan (node:net only, no nmap dependency). A "connect scan" just
// completes the standard TCP handshake and closes — the same thing any browser/client does when it
// connects to a service. No SYN-stealth tricks, no payloads sent beyond an optional passive banner read. ──
import net from 'node:net';

export const COMMON_SERVICE_PORTS = [
  { port: 21, name: 'FTP' }, { port: 22, name: 'SSH' }, { port: 23, name: 'Telnet' },
  { port: 25, name: 'SMTP' }, { port: 53, name: 'DNS' }, { port: 110, name: 'POP3' },
  { port: 111, name: 'RPCbind' }, { port: 135, name: 'MSRPC' }, { port: 139, name: 'NetBIOS' },
  { port: 143, name: 'IMAP' }, { port: 389, name: 'LDAP' }, { port: 443, name: 'HTTPS' },
  { port: 445, name: 'SMB' }, { port: 465, name: 'SMTPS' }, { port: 587, name: 'SMTP-Submission' },
  { port: 993, name: 'IMAPS' }, { port: 995, name: 'POP3S' }, { port: 1433, name: 'MSSQL' },
  { port: 1521, name: 'Oracle DB' }, { port: 2049, name: 'NFS' }, { port: 2181, name: 'ZooKeeper' },
  { port: 27017, name: 'MongoDB' }, { port: 3000, name: 'Dev server (Node/Grafana)' },
  { port: 3306, name: 'MySQL' }, { port: 3389, name: 'RDP' }, { port: 5000, name: 'Dev server (Flask/UPnP)' },
  { port: 5432, name: 'PostgreSQL' }, { port: 5601, name: 'Kibana' }, { port: 5672, name: 'RabbitMQ' },
  { port: 5900, name: 'VNC' }, { port: 5984, name: 'CouchDB' }, { port: 6379, name: 'Redis' },
  { port: 7001, name: 'WebLogic' }, { port: 8000, name: 'Dev server (generic)' },
  { port: 8080, name: 'HTTP-alt' }, { port: 8443, name: 'HTTPS-alt' }, { port: 8500, name: 'Consul' },
  { port: 8888, name: 'Dev server (Jupyter/generic)' }, { port: 9000, name: 'PHP-FPM / SonarQube' },
  { port: 9042, name: 'Cassandra' }, { port: 9200, name: 'Elasticsearch' }, { port: 9300, name: 'Elasticsearch-transport' },
  { port: 11211, name: 'Memcached' }, { port: 15672, name: 'RabbitMQ-mgmt' }, { port: 27018, name: 'MongoDB-shard' },
];

export const INTENSITY_PORT_PROFILES = {
  light: { ports: COMMON_SERVICE_PORTS.slice(0, 15), concurrency: 10, timeoutMs: 1200 },
  normal: { ports: COMMON_SERVICE_PORTS.slice(0, 35), concurrency: 20, timeoutMs: 1800 },
  aggressive: { ports: COMMON_SERVICE_PORTS, concurrency: 40, timeoutMs: 2500 },
};

// Sensitive services that should almost never be reachable from the public internet.
export const SENSITIVE_PORTS = new Set([21, 22, 23, 111, 135, 139, 445, 1433, 1521, 27017, 3306, 3389, 5432, 5900, 5984, 6379, 9200, 11211]);

function connectScan(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    let banner = '';
    const finish = (state) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve({ port, state, banner: banner.trim() });
    };
    const timer = setTimeout(() => finish('filtered'), timeoutMs);
    socket.once('connect', () => {
      // Passive read only — give the service up to 400ms to volunteer a banner (SSH/FTP/SMTP do this
      // unprompted). Never send bytes first.
      socket.once('data', (chunk) => { banner = chunk.toString('utf8', 0, 120).replace(/[^\x20-\x7e]/g, ''); });
      setTimeout(() => finish('open'), 400);
    });
    socket.once('error', () => finish('closed'));
    socket.connect(port, host);
  });
}

export async function scanPorts(host, { ports = COMMON_SERVICE_PORTS, concurrency = 20, timeoutMs = 1800, onProgress = null } = {}) {
  const results = [];
  const queue = [...ports];
  const total = queue.length;
  async function worker() {
    while (queue.length) {
      const entry = queue.shift();
      const r = await connectScan(host, entry.port, timeoutMs);
      results.push({ ...entry, ...r });
      if (onProgress) onProgress(results.length, total, { ...entry, ...r });
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, queue.length || 1) }, worker));
  return results.sort((a, b) => a.port - b.port);
}
