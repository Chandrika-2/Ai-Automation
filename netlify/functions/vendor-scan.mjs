import https from "https";
import tls from "tls";
import dns from "dns";
import { URL } from "url";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type,Authorization",
  "Access-Control-Allow-Methods": "POST,OPTIONS",
  "Content-Type": "application/json",
};

const extractDomain = (input) => {
  let d = (input || "").trim().toLowerCase().replace(/\/+$/, "");
  try { d = new URL(d.startsWith("http") ? d : `https://${d}`).hostname; } catch (e) {}
  return d.replace(/^www\./, "");
};

const timedPromise = (fn, ms = 8000) =>
  Promise.race([fn(), new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), ms))]);

const scanSSL = (domain) =>
  timedPromise(() => new Promise((resolve) => {
    const findings = [];
    const raw = {};
    const sock = tls.connect(443, domain, { servername: domain, rejectUnauthorized: false }, () => {
      try {
        const cert = sock.getPeerCertificate();
        const proto = sock.getProtocol();
        const cipher = sock.getCipher();
        raw.protocol = proto;
        raw.cipher = cipher?.name;
        raw.valid_to = cert.valid_to;
        if (cert.valid_to) {
          const days = Math.floor((new Date(cert.valid_to) - Date.now()) / 86400000);
          raw.days_until_expiry = days;
          if (days < 0) findings.push({ title: "SSL Certificate Expired", description: `Expired ${Math.abs(days)} days ago`, severity: "critical", category: "SSL/TLS", recommendation: "Renew immediately." });
          else if (days < 30) findings.push({ title: "SSL Expiring Soon", description: `Expires in ${days} days`, severity: "high", category: "SSL/TLS", recommendation: "Renew before expiration." });
          else if (days < 90) findings.push({ title: "SSL Expiring in 90 Days", description: `Expires in ${days} days`, severity: "medium", category: "SSL/TLS", recommendation: "Plan renewal." });
        }
        if (["SSLv2", "SSLv3", "TLSv1", "TLSv1.0"].includes(proto))
          findings.push({ title: `Deprecated: ${proto}`, description: `Uses ${proto}`, severity: "high", category: "SSL/TLS", recommendation: "Upgrade to TLS 1.2+." });
        else if (proto === "TLSv1.1")
          findings.push({ title: "Deprecated: TLSv1.1", severity: "medium", description: "TLS 1.1 is deprecated", category: "SSL/TLS", recommendation: "Upgrade to TLS 1.2+." });
        const cn = (cipher?.name || "").toUpperCase();
        for (const w of ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"]) {
          if (cn.includes(w)) { findings.push({ title: `Weak Cipher: ${cipher.name}`, description: `Contains ${w}`, severity: "high", category: "SSL/TLS", recommendation: "Use AES-GCM or CHACHA20." }); break; }
        }
        try { if (cert.issuer && cert.subject && JSON.stringify(cert.issuer) === JSON.stringify(cert.subject)) findings.push({ title: "Self-Signed Certificate", description: "Not browser-trusted", severity: "high", category: "SSL/TLS", recommendation: "Use a trusted CA." }); } catch (e) {}
        if ((cert.subject?.CN || "").startsWith("*.")) findings.push({ title: "Wildcard Certificate", description: `Uses ${cert.subject.CN}`, severity: "low", category: "SSL/TLS", recommendation: "Consider specific certs." });
        if (!findings.length) findings.push({ title: "SSL/TLS Looks Good", description: `${proto} with ${cipher?.name || "unknown"}`, severity: "info", category: "SSL/TLS" });
      } catch (e) { findings.push({ title: "SSL Parse Error", description: e.message, severity: "info", category: "SSL/TLS" }); }
      sock.end();
      resolve({ scanner: "SSL/TLS Scanner", findings, raw_data: raw, status: "completed" });
    });
    sock.on("error", (e) => {
      findings.push({ title: "SSL Connection Failed", description: e.message, severity: "critical", category: "SSL/TLS", recommendation: "Ensure HTTPS is enabled." });
      resolve({ scanner: "SSL/TLS Scanner", findings, raw_data: {}, status: "completed" });
    });
    sock.setTimeout(6000, () => { sock.destroy(); });
  }), 8000);

const scanHeaders = (domain) =>
  timedPromise(() => new Promise((resolve) => {
    const findings = [];
    const raw = {};
    const SEC = {
      "strict-transport-security": { severity: "high", description: "HSTS missing — HTTP downgrade risk.", recommendation: "Add Strict-Transport-Security: max-age=31536000; includeSubDomains" },
      "content-security-policy": { severity: "high", description: "CSP missing — XSS/injection risk.", recommendation: "Implement Content-Security-Policy." },
      "x-frame-options": { severity: "medium", description: "Missing — clickjacking risk.", recommendation: "Add X-Frame-Options: DENY or SAMEORIGIN." },
      "x-content-type-options": { severity: "medium", description: "Missing — MIME-sniff risk.", recommendation: "Add X-Content-Type-Options: nosniff" },
      "referrer-policy": { severity: "medium", description: "Missing — URL leak risk.", recommendation: "Add Referrer-Policy: strict-origin-when-cross-origin" },
      "permissions-policy": { severity: "medium", description: "Missing — browser features unrestricted.", recommendation: "Add Permissions-Policy header." },
    };
    const req = https.get({ hostname: domain, path: "/", headers: { "User-Agent": "SecComply-Scanner/1.0" }, rejectUnauthorized: false, timeout: 6000 }, (res) => {
      const h = res.headers;
      raw.status = res.statusCode;
      for (const [name, cfg] of Object.entries(SEC)) { if (!h[name]) findings.push({ title: `Missing: ${name}`, description: cfg.description, severity: cfg.severity, category: "HTTP Headers", recommendation: cfg.recommendation }); }
      const hsts = h["strict-transport-security"] || "";
      if (hsts) {
        const m = hsts.match(/max-age=(\d+)/);
        if (m && parseInt(m[1]) < 31536000) findings.push({ title: "HSTS Max-Age Too Short", description: `max-age=${m[1]}`, severity: "medium", category: "HTTP Headers", recommendation: "Set >= 31536000." });
        if (!hsts.toLowerCase().includes("includesubdomains")) findings.push({ title: "HSTS Missing includeSubDomains", description: "Subdomains not covered", severity: "low", category: "HTTP Headers", recommendation: "Add includeSubDomains." });
      }
      const csp = h["content-security-policy"] || "";
      if (csp) {
        if (csp.includes("'unsafe-inline'")) findings.push({ title: "CSP unsafe-inline", description: "Weakens XSS protection", severity: "medium", category: "HTTP Headers", recommendation: "Use nonces." });
        if (csp.includes("'unsafe-eval'")) findings.push({ title: "CSP unsafe-eval", description: "Allows eval()", severity: "medium", category: "HTTP Headers", recommendation: "Remove unsafe-eval." });
      }
      for (const hdr of ["server", "x-powered-by", "x-aspnet-version"]) { if (h[hdr]) findings.push({ title: `Info Disclosure: ${hdr}`, description: `${hdr}: ${h[hdr]}`, severity: "low", category: "HTTP Headers", recommendation: `Remove ${hdr}.` }); }
      const sc = h["set-cookie"];
      if (sc) {
        const cs = Array.isArray(sc) ? sc.join("; ") : sc;
        if (!cs.toLowerCase().includes("secure")) findings.push({ title: "Cookie Missing Secure", description: "No Secure flag", severity: "medium", category: "HTTP Headers", recommendation: "Add Secure." });
        if (!cs.toLowerCase().includes("httponly")) findings.push({ title: "Cookie Missing HttpOnly", description: "No HttpOnly", severity: "medium", category: "HTTP Headers", recommendation: "Add HttpOnly." });
      }
      res.resume();
      resolve({ scanner: "HTTP Security Headers", findings, raw_data: raw, status: "completed" });
    });
    req.on("error", (e) => { findings.push({ title: "HTTPS Failed", description: e.message, severity: "high", category: "HTTP Headers" }); resolve({ scanner: "HTTP Security Headers", findings, raw_data: {}, status: "error" }); });
    req.on("timeout", () => { req.destroy(); });
  }), 8000);

const scanDNS = (domain) =>
  timedPromise(() => new Promise(async (resolve) => {
    const findings = [];
    const raw = { records: {} };
    try {
      const resolver = new dns.promises.Resolver();
      resolver.setServers(["8.8.8.8", "1.1.1.1"]);
      const q = async (t) => { try { return await resolver.resolve(domain, t); } catch { return []; } };
      raw.records.A = await q("A");
      raw.records.AAAA = await q("AAAA");
      raw.records.MX = await q("MX");
      raw.records.NS = await q("NS");
      raw.records.TXT = await q("TXT");
      try { raw.records.CAA = await q("CAA"); } catch { raw.records.CAA = []; }
      if (!raw.records.A?.length && !raw.records.AAAA?.length) findings.push({ title: "No A/AAAA Records", description: `${domain} does not resolve`, severity: "high", category: "DNS", recommendation: "Verify DNS." });
      if ((raw.records.NS || []).length < 2) findings.push({ title: "Insufficient Nameservers", description: `${(raw.records.NS || []).length} NS`, severity: "medium", category: "DNS", recommendation: "Use 2+ NS." });
      if (!(raw.records.CAA || []).length) findings.push({ title: "No CAA Records", description: "No CA Authorization", severity: "medium", category: "DNS", recommendation: "Add CAA." });
      if (!(raw.records.MX || []).length) findings.push({ title: "No MX Records", description: "No email config", severity: "low", category: "DNS", recommendation: "Add MX if needed." });
      if (!findings.length) findings.push({ title: "DNS Looks Good", description: "No issues", severity: "info", category: "DNS" });
    } catch (e) { findings.push({ title: "DNS Error", description: e.message, severity: "info", category: "DNS" }); }
    resolve({ scanner: "DNS Security", findings, raw_data: raw, status: "completed" });
  }), 8000);

const scanEmail = (domain) =>
  timedPromise(() => new Promise(async (resolve) => {
    const findings = [];
    const raw = { spf: {}, dmarc: {}, dkim: {} };
    try {
      const resolver = new dns.promises.Resolver();
      resolver.setServers(["8.8.8.8", "1.1.1.1"]);
      const qTXT = async (d) => { try { return (await resolver.resolveTxt(d)).map(t => t.join("")); } catch { return []; } };
      const txts = await qTXT(domain);
      const spfs = txts.filter(t => t.startsWith("v=spf1"));
      if (!spfs.length) { findings.push({ title: "No SPF Record", description: "Email spoofing risk", severity: "high", category: "Email Security", recommendation: "Add SPF." }); raw.spf.status = "missing"; }
      else if (spfs.length > 1) { findings.push({ title: "Multiple SPF Records", description: `${spfs.length} found`, severity: "high", category: "Email Security", recommendation: "Use only one." }); }
      else {
        raw.spf = { record: spfs[0], status: "found" };
        if (spfs[0].includes("+all")) findings.push({ title: "SPF +all", description: "Allows any sender", severity: "critical", category: "Email Security", recommendation: "Change to -all." });
        else if (spfs[0].endsWith("~all")) findings.push({ title: "SPF ~all", description: "Soft fail", severity: "low", category: "Email Security", recommendation: "Change to -all." });
        else if (spfs[0].includes("?all")) findings.push({ title: "SPF ?all", description: "Neutral", severity: "medium", category: "Email Security", recommendation: "Change to -all." });
      }
      const dRecs = await qTXT(`_dmarc.${domain}`);
      const dmarcs = dRecs.filter(t => t.toLowerCase().includes("v=dmarc1"));
      if (!dmarcs.length) { findings.push({ title: "No DMARC Record", description: "No enforcement", severity: "high", category: "Email Security", recommendation: "Add DMARC." }); raw.dmarc.status = "missing"; }
      else {
        raw.dmarc = { record: dmarcs[0], status: "found" };
        const pM = dmarcs[0].match(/p=(\w+)/);
        const policy = pM ? pM[1].toLowerCase() : "none";
        raw.dmarc.policy = policy;
        if (policy === "none") findings.push({ title: "DMARC p=none", description: "Monitor only", severity: "medium", category: "Email Security", recommendation: "Upgrade to p=reject." });
        if (!dmarcs[0].includes("rua=")) findings.push({ title: "DMARC Missing rua", description: "No reports", severity: "medium", category: "Email Security", recommendation: "Add rua=mailto:..." });
      }
      let dkimFound = false;
      for (const s of ["default", "google", "selector1", "selector2", "k1", "mail", "dkim", "s1", "s2"]) {
        const r = await qTXT(`${s}._domainkey.${domain}`);
        if (r.length) { dkimFound = true; raw.dkim = { selector: s, status: "found" }; break; }
      }
      if (!dkimFound) { findings.push({ title: "No DKIM Found", description: "Common selectors checked", severity: "medium", category: "Email Security", recommendation: "Configure DKIM." }); raw.dkim.status = "not_found"; }
    } catch (e) { findings.push({ title: "Email Scan Error", description: e.message, severity: "info", category: "Email Security" }); }
    resolve({ scanner: "Email Security (SPF/DKIM/DMARC)", findings, raw_data: raw, status: "completed" });
  }), 12000);

const SEV_W = { critical: 10, high: 7, medium: 4, low: 1.5, info: 0 };
const CAT_W = { "SSL/TLS": 1.5, "DNS": 1.3, "Email Security": 1.0, "HTTP Headers": 1.2 };

const calculateRisk = (results) => {
  const all = results.flatMap(r => r.findings || []);
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let penalty = 0;
  const catP = {};
  all.forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1; const p = (SEV_W[f.severity] || 0) * (CAT_W[f.category] || 1); penalty += p; catP[f.category] = (catP[f.category] || 0) + p; });
  let score = Math.max(0, 100 - Math.min(penalty / 150 * 100, 100));
  if (counts.critical > 0) score = Math.min(score, 40);
  const catScores = {};
  for (const cat of Object.keys(CAT_W)) catScores[cat] = Math.max(0, Math.round(100 - ((catP[cat] || 0) / 25 * 100)));
  let riskLevel, grade;
  if (score >= 85) { riskLevel = "Low Risk"; grade = "A"; } else if (score >= 70) { riskLevel = "Moderate Risk"; grade = "B"; } else if (score >= 50) { riskLevel = "High Risk"; grade = "C"; } else { riskLevel = "Critical Risk"; grade = "F"; }
  if (counts.critical > 0) riskLevel = "Critical Risk";
  const topRisks = all.filter(f => f.severity !== "info").sort((a, b) => (SEV_W[b.severity] || 0) - (SEV_W[a.severity] || 0)).slice(0, 10).map(f => ({ title: f.title, severity: f.severity, category: f.category, recommendation: f.recommendation }));
  return { overall_score: Math.round(score), risk_level: riskLevel, letter_grade: grade, findings_summary: { ...counts, total: all.length }, category_scores: catScores, top_risks: topRisks };
};

export const handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return { statusCode: 200, headers: CORS, body: "" };
  if (event.httpMethod !== "POST") return { statusCode: 405, headers: CORS, body: JSON.stringify({ error: "POST only" }) };
  try {
    const body = JSON.parse(event.body || "{}");
    const url = body.url;
    if (!url) return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: "URL required" }) };
    const domain = extractDomain(url);
    if (!domain || domain.length < 3) return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: "Invalid domain" }) };
    console.log(`[vendor-scan] Scanning: ${domain}`);
    const t0 = Date.now();
    const results = await Promise.allSettled([scanSSL(domain), scanHeaders(domain), scanDNS(domain), scanEmail(domain)]);
    const scanResults = results.map((r, i) => {
      if (r.status === "fulfilled") return r.value;
      return { scanner: ["SSL/TLS Scanner", "HTTP Security Headers", "DNS Security", "Email Security"][i], findings: [{ title: "Scanner Error", description: r.reason?.message || "Unknown", severity: "info", category: "Error" }], raw_data: {}, status: "error" };
    });
    const riskScore = calculateRisk(scanResults);
    const duration = ((Date.now() - t0) / 1000).toFixed(1);
    console.log(`[vendor-scan] Done: ${domain} | Score: ${riskScore.overall_score} | ${duration}s`);
    return { statusCode: 200, headers: CORS, body: JSON.stringify({
      meta: { domain, scan_date: new Date().toISOString(), scan_duration_seconds: parseFloat(duration), scanners_run: scanResults.length, module: "SecComply Attack Surface Scanner v1.0" },
      risk_score: riskScore,
      scan_results: scanResults.map(r => ({ scanner: r.scanner, findings: r.findings, findings_count: r.findings?.length || 0, status: r.status })),
    })};
  } catch (e) {
    console.error("[vendor-scan] Error:", e);
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: e.message || "Internal error" }) };
  }
};
