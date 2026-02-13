/**
 * SecComply Vendor Attack Surface Scanner
 * Scans: SSL/TLS, HTTP Headers, DNS, Email (SPF/DMARC/DKIM), Ports
 * Input: { url: "example.com" }
 */
import https from "https";
import tls from "tls";
import dns from "dns";
import net from "net";
import { URL } from "url";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type,Authorization",
  "Access-Control-Allow-Methods": "POST,OPTIONS",
  "Content-Type": "application/json",
};

const extractDomain = (input) => {
  let d = input.trim().toLowerCase();
  try { d = new URL(d.startsWith("http") ? d : `https://${d}`).hostname; } catch {}
  return d.replace(/^www\./, "").replace(/\/+$/, "");
};

const timedPromise = (fn, ms = 12000) =>
  Promise.race([fn(), new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), ms))]);

// ─── 1. SSL/TLS Scanner ───
const scanSSL = (domain) =>
  timedPromise(() => new Promise((resolve) => {
    const findings = [];
    const raw = {};
    const sock = tls.connect(443, domain, { servername: domain, rejectUnauthorized: false }, () => {
      const cert = sock.getPeerCertificate();
      const proto = sock.getProtocol();
      const cipher = sock.getCipher();
      raw.protocol = proto;
      raw.cipher = cipher?.name;
      raw.issuer = cert.issuer;
      raw.subject = cert.subject;
      raw.valid_to = cert.valid_to;
      raw.san = cert.subjectaltname;

      if (cert.valid_to) {
        const expiry = new Date(cert.valid_to);
        const days = Math.floor((expiry - Date.now()) / 86400000);
        raw.days_until_expiry = days;
        if (days < 0) findings.push({ title: "SSL Certificate Expired", description: `Certificate expired ${Math.abs(days)} days ago`, severity: "critical", category: "SSL/TLS", recommendation: "Renew the SSL certificate immediately." });
        else if (days < 30) findings.push({ title: "SSL Certificate Expiring Soon", description: `Expires in ${days} days`, severity: "high", category: "SSL/TLS", recommendation: "Renew before expiration." });
        else if (days < 90) findings.push({ title: "SSL Expiring Within 90 Days", description: `Expires in ${days} days`, severity: "medium", category: "SSL/TLS", recommendation: "Plan certificate renewal." });
      }

      if (["SSLv2", "SSLv3", "TLSv1", "TLSv1.0"].includes(proto))
        findings.push({ title: `Deprecated Protocol: ${proto}`, description: `Server uses deprecated ${proto}`, severity: "high", category: "SSL/TLS", recommendation: "Upgrade to TLS 1.2 or TLS 1.3." });
      else if (proto === "TLSv1.1")
        findings.push({ title: "Deprecated Protocol: TLSv1.1", description: "TLS 1.1 is deprecated", severity: "medium", category: "SSL/TLS", recommendation: "Upgrade to TLS 1.2+." });

      const weakCiphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"];
      const cn = cipher?.name || "";
      for (const w of weakCiphers) {
        if (cn.toUpperCase().includes(w)) {
          findings.push({ title: `Weak Cipher: ${cn}`, description: `Contains ${w}`, severity: "high", category: "SSL/TLS", recommendation: "Use AES-GCM or CHACHA20." });
          break;
        }
      }

      if (cert.issuer && cert.subject && JSON.stringify(cert.issuer) === JSON.stringify(cert.subject))
        findings.push({ title: "Self-Signed Certificate", description: "Not trusted by browsers", severity: "high", category: "SSL/TLS", recommendation: "Use a trusted CA." });

      const subjCN = cert.subject?.CN || "";
      if (subjCN.startsWith("*."))
        findings.push({ title: "Wildcard Certificate", description: `Uses wildcard: ${subjCN}`, severity: "low", category: "SSL/TLS", recommendation: "Consider specific certs for critical services." });

      if (!findings.length)
        findings.push({ title: "SSL/TLS Configuration Looks Good", description: `${proto} with ${cn}`, severity: "info", category: "SSL/TLS" });

      sock.end();
      resolve({ scanner: "SSL/TLS Scanner", findings, raw_data: raw, status: "completed" });
    });
    sock.on("error", (e) => {
      findings.push({ title: "SSL/TLS Connection Failed", description: `Could not connect to ${domain}:443`, severity: "critical", category: "SSL/TLS", evidence: e.message, recommendation: "Ensure HTTPS is enabled." });
      resolve({ scanner: "SSL/TLS Scanner", findings, raw_data: raw, status: "completed" });
    });
    sock.setTimeout(10000, () => { sock.destroy(); });
  }));

// ─── 2. HTTP Headers Scanner ───
const scanHeaders = (domain) =>
  timedPromise(() => new Promise((resolve) => {
    const findings = [];
    const raw = {};
    const SEC_HDRS = {
      "strict-transport-security": { severity: "high", description: "HSTS missing — HTTP downgrade risk.", recommendation: "Add Strict-Transport-Security: max-age=31536000; includeSubDomains" },
      "content-security-policy": { severity: "high", description: "CSP missing — XSS/injection risk.", recommendation: "Implement Content-Security-Policy." },
      "x-frame-options": { severity: "medium", description: "Missing — clickjacking risk.", recommendation: "Add X-Frame-Options: DENY or SAMEORIGIN." },
      "x-content-type-options": { severity: "medium", description: "Missing — MIME-sniff risk.", recommendation: "Add X-Content-Type-Options: nosniff" },
      "referrer-policy": { severity: "medium", description: "Missing — URL leak risk.", recommendation: "Add Referrer-Policy: strict-origin-when-cross-origin" },
      "permissions-policy": { severity: "medium", description: "Missing — browser features unrestricted.", recommendation: "Add Permissions-Policy header." },
    };
    const DISCLOSURE = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"];

    const req = https.get({ hostname: domain, path: "/", headers: { "User-Agent": "SecComply-Scanner/1.0" }, rejectUnauthorized: false, timeout: 8000 }, (res) => {
      const headers = res.headers;
      raw.status = res.statusCode;
      raw.headers = headers;

      for (const [name, config] of Object.entries(SEC_HDRS)) {
        if (!headers[name])
          findings.push({ title: `Missing: ${name}`, description: config.description, severity: config.severity, category: "HTTP Headers", recommendation: config.recommendation });
      }

      const hsts = headers["strict-transport-security"] || "";
      if (hsts) {
        const m = hsts.match(/max-age=(\d+)/);
        if (m && parseInt(m[1]) < 31536000)
          findings.push({ title: "HSTS Max-Age Too Short", description: `max-age=${m[1]}`, severity: "medium", category: "HTTP Headers", recommendation: "Set max-age ≥ 31536000." });
        if (!hsts.toLowerCase().includes("includesubdomains"))
          findings.push({ title: "HSTS Missing includeSubDomains", severity: "low", description: "Subdomains not covered", category: "HTTP Headers", recommendation: "Add includeSubDomains." });
      }

      const csp = headers["content-security-policy"] || "";
      if (csp) {
        if (csp.includes("'unsafe-inline'")) findings.push({ title: "CSP allows unsafe-inline", description: "Weakens XSS protection", severity: "medium", category: "HTTP Headers", recommendation: "Use nonces instead." });
        if (csp.includes("'unsafe-eval'")) findings.push({ title: "CSP allows unsafe-eval", description: "Allows eval()", severity: "medium", category: "HTTP Headers", recommendation: "Remove unsafe-eval." });
      }

      for (const h of DISCLOSURE) {
        if (headers[h])
          findings.push({ title: `Info Disclosure: ${h}`, description: `${h}: ${headers[h]}`, severity: "low", category: "HTTP Headers", recommendation: `Remove ${h} header.` });
      }

      const sc = headers["set-cookie"];
      if (sc) {
        const cs = Array.isArray(sc) ? sc.join("; ") : sc;
        if (!cs.toLowerCase().includes("secure")) findings.push({ title: "Cookie Missing Secure Flag", severity: "medium", category: "HTTP Headers", description: "Cookies lack Secure", recommendation: "Add Secure flag." });
        if (!cs.toLowerCase().includes("httponly")) findings.push({ title: "Cookie Missing HttpOnly", severity: "medium", category: "HTTP Headers", description: "Cookies lack HttpOnly", recommendation: "Add HttpOnly flag." });
        if (!cs.toLowerCase().includes("samesite")) findings.push({ title: "Cookie Missing SameSite", severity: "low", category: "HTTP Headers", description: "No SameSite attribute", recommendation: "Add SameSite=Lax." });
      }

      res.resume();
      resolve({ scanner: "HTTP Security Headers", findings, raw_data: raw, status: "completed" });
    });
    req.on("error", (e) => {
      findings.push({ title: "HTTPS Connection Failed", description: `Could not connect to ${domain}`, severity: "high", category: "HTTP Headers", evidence: e.message });
      resolve({ scanner: "HTTP Security Headers", findings, raw_data: raw, status: "error" });
    });
    req.on("timeout", () => { req.destroy(); });
  }));

// ─── 3. DNS Scanner ───
const scanDNS = (domain) =>
  timedPromise(() => new Promise(async (resolve) => {
    const findings = [];
    const raw = { records: {} };
    const resolver = new dns.promises.Resolver();
    resolver.setServers(["8.8.8.8", "1.1.1.1"]);
    const q = async (t) => { try { return await resolver.resolve(domain, t); } catch { return []; } };

    raw.records.A = await q("A");
    raw.records.AAAA = await q("AAAA");
    raw.records.MX = await q("MX");
    raw.records.NS = await q("NS");
    raw.records.TXT = await q("TXT");
    raw.records.CAA = await q("CAA");

    if (!raw.records.A?.length)
      findings.push({ title: "No A Record Found", description: `${domain} does not resolve`, severity: "high", category: "DNS", recommendation: "Verify DNS configuration." });

    if ((raw.records.NS || []).length < 2)
      findings.push({ title: "Insufficient Nameservers", description: `Only ${(raw.records.NS||[]).length} NS record(s)`, severity: "medium", category: "DNS", recommendation: "Configure at least 2 nameservers." });

    if (!(raw.records.CAA || []).length)
      findings.push({ title: "No CAA Records", description: "No CA Authorization configured", severity: "medium", category: "DNS", recommendation: "Add CAA records." });

    if (!(raw.records.MX || []).length)
      findings.push({ title: "No MX Records", description: "No email MX records", severity: "low", category: "DNS", recommendation: "Configure MX if email is used." });

    if (!findings.length)
      findings.push({ title: "DNS Configuration Looks Good", description: "No critical issues", severity: "info", category: "DNS" });

    resolve({ scanner: "DNS Security Scanner", findings, raw_data: raw, status: "completed" });
  }));

// ─── 4. Email Security (SPF/DMARC/DKIM) ───
const scanEmail = (domain) =>
  timedPromise(() => new Promise(async (resolve) => {
    const findings = [];
    const raw = { spf: {}, dmarc: {}, dkim: {} };
    const resolver = new dns.promises.Resolver();
    resolver.setServers(["8.8.8.8", "1.1.1.1"]);
    const qTXT = async (d) => { try { return (await resolver.resolveTxt(d)).map(t => t.join("")); } catch { return []; } };

    // SPF
    const txts = await qTXT(domain);
    const spfs = txts.filter(t => t.startsWith("v=spf1"));
    if (!spfs.length) {
      findings.push({ title: "No SPF Record", description: "Vulnerable to email spoofing", severity: "high", category: "Email Security", recommendation: "Add SPF record (v=spf1 ... -all)." });
      raw.spf.status = "missing";
    } else if (spfs.length > 1) {
      findings.push({ title: "Multiple SPF Records", description: `${spfs.length} found (only 1 allowed)`, severity: "high", category: "Email Security", recommendation: "Consolidate into one." });
    } else {
      raw.spf = { record: spfs[0], status: "found" };
      if (spfs[0].includes("+all")) findings.push({ title: "SPF Overly Permissive (+all)", description: "Allows any server", severity: "critical", category: "Email Security", recommendation: "Change to -all." });
      else if (spfs[0].endsWith("~all")) findings.push({ title: "SPF Soft Fail (~all)", description: "Consider hard fail", severity: "low", category: "Email Security", recommendation: "Change to -all." });
      else if (spfs[0].includes("?all")) findings.push({ title: "SPF Neutral (?all)", description: "No protection", severity: "medium", category: "Email Security", recommendation: "Change to -all." });
    }

    // DMARC
    const dRecs = await qTXT(`_dmarc.${domain}`);
    const dmarcs = dRecs.filter(t => t.toLowerCase().includes("v=dmarc1"));
    if (!dmarcs.length) {
      findings.push({ title: "No DMARC Record", description: "No email auth enforcement", severity: "high", category: "Email Security", recommendation: "Add DMARC (v=DMARC1; p=reject; rua=mailto:...)." });
      raw.dmarc.status = "missing";
    } else {
      raw.dmarc = { record: dmarcs[0], status: "found" };
      const pM = dmarcs[0].match(/p=(\w+)/);
      const policy = pM ? pM[1].toLowerCase() : "none";
      raw.dmarc.policy = policy;
      if (policy === "none") findings.push({ title: "DMARC Policy: none", description: "Monitoring only", severity: "medium", category: "Email Security", recommendation: "Upgrade to p=quarantine or p=reject." });
      if (!dmarcs[0].includes("rua=")) findings.push({ title: "DMARC Missing Report Address", description: "No aggregate reports", severity: "medium", category: "Email Security", recommendation: "Add rua=mailto:..." });
    }

    // DKIM
    const sels = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim", "s1", "s2"];
    let found = false;
    for (const s of sels) {
      const r = await qTXT(`${s}._domainkey.${domain}`);
      if (r.length) { found = true; raw.dkim = { selector: s, status: "found" }; break; }
    }
    if (!found) {
      findings.push({ title: "No DKIM Record Found", description: "Checked common selectors", severity: "medium", category: "Email Security", recommendation: "Configure DKIM signing." });
      raw.dkim.status = "not_found";
    }

    resolve({ scanner: "Email Security (SPF/DKIM/DMARC)", findings, raw_data: raw, status: "completed" });
  }), 15000);

// ─── 5. Port Scanner ───
const scanPorts = (domain) =>
  timedPromise(() => new Promise(async (resolve) => {
    const findings = [];
    const raw = { open_ports: [] };
    const PORTS = [21, 22, 23, 25, 80, 443, 3306, 3389, 5432, 8080, 8443, 9200];
    const RISKY = { 21: "FTP", 23: "Telnet", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 9200: "Elasticsearch" };

    const check = (port) => new Promise((res) => {
      const s = new net.Socket();
      s.setTimeout(3000);
      s.on("connect", () => { s.destroy(); res(true); });
      s.on("error", () => res(false));
      s.on("timeout", () => { s.destroy(); res(false); });
      s.connect(port, domain);
    });

    await Promise.allSettled(PORTS.map(async (p) => {
      if (await check(p)) raw.open_ports.push(p);
    }));

    raw.open_ports.forEach((p) => {
      if (RISKY[p])
        findings.push({ title: `Risky Port Open: ${p} (${RISKY[p]})`, description: `Port ${p} exposed`, severity: p === 23 ? "critical" : "high", category: "Port Scan", recommendation: `Close port ${p} or restrict via firewall.` });
    });

    if (raw.open_ports.length > 5)
      findings.push({ title: "Many Open Ports", description: `${raw.open_ports.length} ports open`, severity: "medium", category: "Port Scan", recommendation: "Minimize exposed services." });

    if (!findings.length)
      findings.push({ title: "No Risky Ports Detected", description: `Checked ${PORTS.length} common ports`, severity: "info", category: "Port Scan" });

    resolve({ scanner: "Port Scanner", findings, raw_data: raw, status: "completed" });
  }), 20000);

// ─── Risk Calculator ───
const SEV_W = { critical: 10, high: 7, medium: 4, low: 1.5, info: 0 };
const CAT_W = { "SSL/TLS": 1.5, "DNS": 1.3, "Email Security": 1.0, "HTTP Headers": 1.2, "Port Scan": 1.4 };

const calculateRisk = (results) => {
  const all = results.flatMap(r => r.findings || []);
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let penalty = 0;
  const catP = {};

  all.forEach(f => {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
    const p = (SEV_W[f.severity] || 0) * (CAT_W[f.category] || 1);
    penalty += p;
    catP[f.category] = (catP[f.category] || 0) + p;
  });

  let score = Math.max(0, 100 - Math.min(penalty / 200 * 100, 100));
  if (counts.critical > 0) score = Math.min(score, 40);

  const catScores = {};
  for (const cat of Object.keys(CAT_W))
    catScores[cat] = Math.max(0, Math.round(100 - ((catP[cat] || 0) / 30 * 100)));

  let riskLevel, grade;
  if (score >= 85) { riskLevel = "Low Risk"; grade = "A"; }
  else if (score >= 70) { riskLevel = "Moderate Risk"; grade = "B"; }
  else if (score >= 50) { riskLevel = "High Risk"; grade = "C"; }
  else { riskLevel = "Critical Risk"; grade = "F"; }
  if (counts.critical > 0) riskLevel = "Critical Risk";

  const topRisks = all.filter(f => f.severity !== "info")
    .sort((a, b) => (SEV_W[b.severity] || 0) - (SEV_W[a.severity] || 0))
    .slice(0, 10).map(f => ({ title: f.title, severity: f.severity, category: f.category, recommendation: f.recommendation }));

  return { overall_score: Math.round(score), risk_level: riskLevel, letter_grade: grade, findings_summary: { ...counts, total: all.length }, category_scores: catScores, top_risks: topRisks };
};

// ─── Handler ───
export const handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return { statusCode: 200, headers: CORS, body: "" };
  if (event.httpMethod !== "POST") return { statusCode: 405, headers: CORS, body: JSON.stringify({ error: "POST only" }) };

  try {
    const { url } = JSON.parse(event.body || "{}");
    if (!url) return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: "URL required" }) };
    const domain = extractDomain(url);
    if (!domain) return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: "Invalid URL" }) };

    const t0 = Date.now();
    const results = await Promise.allSettled([scanSSL(domain), scanHeaders(domain), scanDNS(domain), scanEmail(domain), scanPorts(domain)]);
    const scanResults = results.map((r, i) => r.status === "fulfilled" ? r.value : { scanner: ["SSL/TLS", "HTTP Headers", "DNS", "Email", "Ports"][i], findings: [{ title: "Scanner Error", description: r.reason?.message || "Unknown", severity: "info", category: "Error" }], status: "error" });

    const report = {
      meta: { domain, scan_date: new Date().toISOString(), scan_duration_seconds: parseFloat(((Date.now() - t0) / 1000).toFixed(1)), scanners_run: scanResults.length, module: "SecComply Attack Surface Scanner v1.0" },
      risk_score: calculateRisk(scanResults),
      scan_results: scanResults.map(r => ({ ...r, findings_count: r.findings?.length || 0, raw_data: undefined })),
    };

    return { statusCode: 200, headers: CORS, body: JSON.stringify(report) };
  } catch (e) {
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: e.message }) };
  }
};
