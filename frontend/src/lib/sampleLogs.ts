// Realistic, self-contained log samples for the Analyze page so anyone can see
// Argus work without pasting real data. Each sample is crafted to trip a real
// detection rule, and uses RFC 5737 documentation IPs (198.51.100.x /
// 203.0.113.x) distinct from the dashboard's seeded demo data.

export interface LogSample {
  id: string
  label: string
  blurb: string
  text: string
}

// auth.log — 6 failed SSH logins from one IP in ~10s trips brute_force_ssh
// (>=5 / 60s). The trailing successful login is legitimate and is ignored.
const SSH_BRUTE_FORCE = [
  'Jun 10 06:11:01 web-01 sshd[20144]: Failed password for invalid user admin from 198.51.100.42 port 54001 ssh2',
  'Jun 10 06:11:03 web-01 sshd[20146]: Failed password for invalid user admin from 198.51.100.42 port 54002 ssh2',
  'Jun 10 06:11:05 web-01 sshd[20148]: Failed password for root from 198.51.100.42 port 54003 ssh2',
  'Jun 10 06:11:07 web-01 sshd[20150]: Failed password for root from 198.51.100.42 port 54004 ssh2',
  'Jun 10 06:11:09 web-01 sshd[20152]: Failed password for invalid user oracle from 198.51.100.42 port 54005 ssh2',
  'Jun 10 06:11:11 web-01 sshd[20154]: Failed password for invalid user postgres from 198.51.100.42 port 54006 ssh2',
  'Jun 10 06:11:42 web-01 sshd[20160]: Accepted password for alice from 10.0.0.20 port 53999 ssh2',
].join('\n')

// nginx/apache access log — two SQL-injection probes (URL-encoded so spaces
// survive the request line) plus one clean request that raises nothing.
const WEB_SQLI = [
  '198.51.100.23 - - [10/Jun/2026:06:03:48 +0000] "GET /products?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 200 5123 "-" "sqlmap/1.5.2#stable (http://sqlmap.org)"',
  "198.51.100.23 - - [10/Jun/2026:06:03:50 +0000] \"GET /login.php?user=admin%27%20OR%20%271%27=%271 HTTP/1.1\" 403 217 \"-\" \"sqlmap/1.5.2#stable\"",
  '203.0.113.7 - - [10/Jun/2026:06:04:10 +0000] "GET /index.html HTTP/1.1" 200 8742 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
].join('\n')

// Suricata EVE JSON — one source probing 12 distinct destination ports in
// ~12s trips port_scan (>=10 distinct ports / 60s).
const SURICATA_PORT_SCAN = [21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 8080]
  .map((port, i) =>
    JSON.stringify({
      timestamp: `2026-06-10T06:05:${String(1 + i).padStart(2, '0')}.000000+0000`,
      event_type: 'alert',
      src_ip: '203.0.113.88',
      src_port: 44001 + i,
      dest_ip: '10.0.0.10',
      dest_port: port,
      proto: 'TCP',
      alert: { signature: 'ET SCAN Potential Port Scan', severity: 2 },
    }),
  )
  .join('\n')

export const SAMPLE_LOGS: LogSample[] = [
  {
    id: 'ssh-brute-force',
    label: 'SSH brute-force',
    blurb: 'Linux /var/log/auth.log — repeated failed root/admin logins',
    text: SSH_BRUTE_FORCE,
  },
  {
    id: 'web-sqli',
    label: 'SQL injection',
    blurb: 'nginx/apache access log — sqlmap probing a login form',
    text: WEB_SQLI,
  },
  {
    id: 'port-scan',
    label: 'Port scan',
    blurb: 'Suricata EVE JSON — one host sweeping many ports',
    text: SURICATA_PORT_SCAN,
  },
]
