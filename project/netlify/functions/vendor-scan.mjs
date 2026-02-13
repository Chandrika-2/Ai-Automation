/**
 * SecComply Vendor Attack Surface Scanner
 * Node.js translation of attack_surface_module for Netlify Functions
 * Scanners: SSL/TLS, HTTP Headers, DNS, Email (SPF/DKIM/DMARC)
 */
import tls from "tls";
import https from "https";
import http from "http";
import dns from "dns";
import { URL } from "url";

const headers = {
  "Content-Type": "application/json",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

// ============================
// SEVERITY & FINDING HELPERS
// ============================
const SEV = { CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low", INFO: "info" };
const finding = (title, desc, severity, category, evidence = "", recommendation = "") => ({
  title, description: desc, severity, category, evidence, recommendation,
});

// Promise wrapper with timeout
const withTimeout = (promise, ms = 8000) =>
  Promise.race([promise, new Promise((_, reject) => setTimeout(() => reject(new Error("Timeout")), ms))]);

// ============================
// SSL/TLS SCANNER
// ============================
async function scanSSL(domain) {
  const findings = [];
  const rawData = {};

  try {
    const result = await withTimeout(new Promise((resolve, reject) => {
      const socket = tls.connect(443, domain, { servername: domain, rejectUnauthorized: false, timeout: 8000 }, () => {
        const cert = socket.getPeerCertificate(true);
        const proto = socket.getProtocol();
        const cipher = socket.getCipher();
        const authorized = socket.authorized;
        socket.end();
        resolve({ cert, proto, cipher, authorized });
      });
      socket.on("error", reject);
      socket.on("timeout", () => { socket.destroy(); reject(new Error("Connection timeout")); });
    }));

    const { cert, proto, cipher, authorized } = result;
    rawData.protocol = proto;
    rawData.cipher = cipher?.name;
    rawData.authorized = authorized;

    // Certificate verification
    if (!authorized) {
      findings.push(finding(
        "SSL Certificate Not Trusted",
        "The SSL certificate could not be verified by a trusted CA.",
        SEV.HIGH, "SSL/TLS", `Authorized: ${authorized}`,
        "Obtain a valid SSL certificate from a trusted Certificate Authority."
      ));
    }

    // Expiry check
    if (cert?.valid_to) {
      const expiry = new Date(cert.valid_to);
      const daysLeft = Math.floor((expiry - Date.now()) / 86400000);
      rawData.days_until_expiry = daysLeft;
      rawData.expiry_date = cert.valid_to;

      if (daysLeft < 0) {
        findings.push(finding("SSL Certificate Expired",
          `Certificate expired ${Math.abs(daysLeft)} days ago.`,
          SEV.CRITICAL, "SSL/TLS", `Expiry: ${cert.valid_to}`,
          "Renew the SSL certificate immediately."));
      } else if (daysLeft < 30) {
        findings.push(finding("SSL Certificate Expiring Soon",
          `Certificate expires in ${daysLeft} days.`,
          SEV.HIGH, "SSL/TLS", `Expiry: ${cert.valid_to}`,
          "Renew the SSL certificate before expiration."));
      } else if (daysLeft < 90) {
        findings.push(finding("SSL Certificate Expiring Within 90 Days",
          `Certificate expires in ${daysLeft} days.`,
          SEV.MEDIUM, "SSL/TLS", `Expiry: ${cert.valid_to}`,
          "Plan SSL certificate renewal."));
      }
    }

    // Protocol check
    if (proto) {
      rawData.tls_version = proto;
      if (["SSLv2", "SSLv3", "TLSv1", "TLSv1.0"].includes(proto)) {
        findings.push(finding(`Deprecated Protocol: ${proto}`,
          `Server uses deprecated ${proto} with known vulnerabilities.`,
          SEV.HIGH, "SSL/TLS", `Protocol: ${proto}`,
          "Disable SSLv2/v3 and TLSv1.0. Use TLS 1.2 or TLS 1.3."));
      } else if (proto === "TLSv1.1") {
        findings.push(finding("Deprecated Protocol: TLSv1.1",
          "TLS 1.1 is deprecated. Modern browsers no longer support it.",
          SEV.MEDIUM, "SSL/TLS", `Protocol: ${proto}`,
          "Upgrade to TLS 1.2 or TLS 1.3."));
      }
    }

    // Cipher check
    const weakCiphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"];
    if (cipher?.name) {
      rawData.cipher_suite = cipher.name;
      for (const weak of weakCiphers) {
        if (cipher.name.toUpperCase().includes(weak)) {
          findings.push(finding(`Weak Cipher Suite: ${cipher.name}`,
            `Server negotiated a cipher suite containing ${weak}.`,
            SEV.HIGH, "SSL/TLS", `Cipher: ${cipher.name}`,
            "Use strong cipher suites (AES-GCM, CHACHA20)."));
          break;
        }
      }
    }

    // Self-signed check
    if (cert?.issuer && cert?.subject) {
      const issuerCN = cert.issuer?.CN || "";
      const subjectCN = cert.subject?.CN || "";
      rawData.issuer = cert.issuer;
      rawData.subject = cert.subject;
      if (issuerCN && issuerCN === subjectCN) {
        findings.push(finding("Self-Signed Certificate Detected",
          "The certificate is self-signed and won't be trusted by browsers.",
          SEV.HIGH, "SSL/TLS", `Issuer: ${issuerCN}`,
          "Use a certificate from a trusted Certificate Authority."));
      }
    }

    // SAN check
    const san = cert?.subjectaltname;
    rawData.san = san;
    if (!san) {
      findings.push(finding("No Subject Alternative Names",
        "Certificate lacks SAN entries required by modern browsers.",
        SEV.MEDIUM, "SSL/TLS", "",
        "Include SAN entries for all required domains."));
    }

    // Wildcard
    const cn = cert?.subject?.CN || "";
    if (cn.startsWith("*.")) {
      findings.push(finding("Wildcard Certificate In Use",
        `Domain uses wildcard certificate: ${cn}`,
        SEV.LOW, "SSL/TLS", `CN: ${cn}`,
        "Consider specific certificates for critical services."));
    }

    if (findings.length === 0) {
      findings.push(finding("SSL/TLS Configuration Looks Good",
        `Using ${proto} with ${cipher?.name || "unknown"} cipher.`,
        SEV.INFO, "SSL/TLS"));
    }

  } catch (e) {
    findings.push(finding("SSL/TLS Connection Failed",
      `Could not establish SSL connection to ${domain}:443`,
      SEV.CRITICAL, "SSL/TLS", e.message,
      "Ensure HTTPS is enabled on the server."));
  }

  return { scanner: "SSL/TLS Scanner", domain, findings, raw_data: rawData };
}

// ============================
// HTTP HEADERS SCANNER
// ============================
async function scanHeaders(domain) {
  const findings = [];
  const rawData = {};

  const SECURITY_HEADERS = {
    "strict-transport-security": { severity: SEV.HIGH, description: "HSTS missing — browser may allow HTTP downgrade attacks.", recommendation: "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" },
    "content-security-policy": { severity: SEV.HIGH, description: "CSP missing — vulnerable to XSS and data injection attacks.", recommendation: "Implement a Content-Security-Policy header restricting resource origins." },
    "x-frame-options": { severity: SEV.MEDIUM, description: "X-Frame-Options missing — vulnerable to clickjacking.", recommendation: "Add X-Frame-Options: DENY or SAMEORIGIN." },
    "x-content-type-options": { severity: SEV.MEDIUM, description: "X-Content-Type-Options missing — browser may MIME-sniff.", recommendation: "Add X-Content-Type-Options: nosniff" },
    "referrer-policy": { severity: SEV.MEDIUM, description: "Referrer-Policy missing — full URL may leak in Referer.", recommendation: "Add Referrer-Policy: strict-origin-when-cross-origin" },
    "permissions-policy": { severity: SEV.MEDIUM, description: "Permissions-Policy missing — browser features unrestricted.", recommendation: "Add Permissions-Policy to restrict camera, microphone, etc." },
    "x-xss-protection": { severity: SEV.LOW, description: "X-XSS-Protection missing (legacy but useful for older browsers).", recommendation: "Add X-XSS-Protection: 1; mode=block" },
  };

  const DISCLOSURE_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"];

  const fetchHeaders = (url) => withTimeout(new Promise((resolve, reject) => {
    const mod = url.startsWith("https") ? https : http;
    const req = mod.get(url, { timeout: 8000, headers: { "User-Agent": "SecComply-Scanner/1.0" }, rejectUnauthorized: false }, (res) => {
      const hdrs = {};
      for (const [k, v] of Object.entries(res.headers)) hdrs[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : v;
      resolve({ statusCode: res.statusCode, headers: hdrs, location: res.headers.location });
    });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("Timeout")); });
  }));

  try {
    // HTTPS check
    let hdrs;
    try {
      const resp = await fetchHeaders(`https://${domain}`);
      hdrs = resp.headers;
      rawData.https_status = resp.statusCode;
      rawData.response_headers = hdrs;
    } catch {
      // Fallback to HTTP
      try {
        const resp = await fetchHeaders(`http://${domain}`);
        hdrs = resp.headers;
        rawData.http_only = true;
        findings.push(finding("HTTPS Not Available",
          "Website only responds over HTTP (not HTTPS).",
          SEV.CRITICAL, "HTTP Headers", "",
          "Enable HTTPS with a valid SSL certificate."));
      } catch (e2) {
        findings.push(finding("Website Not Reachable",
          `Could not connect to ${domain} on port 80 or 443.`,
          SEV.HIGH, "HTTP Headers", e2.message));
        return { scanner: "HTTP Security Headers Scanner", domain, findings, raw_data: rawData };
      }
    }

    // Check missing security headers
    for (const [header, config] of Object.entries(SECURITY_HEADERS)) {
      if (!hdrs[header]) {
        findings.push(finding(`Missing: ${header}`,
          config.description, config.severity, "HTTP Headers", "",
          config.recommendation));
      }
    }

    // HSTS analysis
    const hsts = hdrs["strict-transport-security"];
    if (hsts) {
      const match = hsts.match(/max-age=(\d+)/);
      if (match && parseInt(match[1]) < 31536000) {
        findings.push(finding("HSTS Max-Age Too Short",
          `HSTS max-age is ${match[1]} seconds (< 1 year).`,
          SEV.MEDIUM, "HTTP Headers", `max-age=${match[1]}`,
          "Set max-age to at least 31536000 (1 year)."));
      }
      if (!hsts.toLowerCase().includes("includesubdomains")) {
        findings.push(finding("HSTS Missing includeSubDomains",
          "HSTS does not include subdomains directive.",
          SEV.LOW, "HTTP Headers", "", "Add includeSubDomains to HSTS header."));
      }
    }

    // CSP analysis
    const csp = hdrs["content-security-policy"];
    if (csp) {
      if (csp.includes("'unsafe-inline'")) {
        findings.push(finding("CSP Allows unsafe-inline",
          "CSP contains 'unsafe-inline' weakening XSS protection.",
          SEV.MEDIUM, "HTTP Headers", "'unsafe-inline' in CSP",
          "Remove 'unsafe-inline' and use nonces or hashes."));
      }
      if (csp.includes("'unsafe-eval'")) {
        findings.push(finding("CSP Allows unsafe-eval",
          "CSP contains 'unsafe-eval' allowing eval().",
          SEV.MEDIUM, "HTTP Headers", "'unsafe-eval' in CSP",
          "Remove 'unsafe-eval' from CSP."));
      }
    }

    // Info disclosure
    for (const h of DISCLOSURE_HEADERS) {
      if (hdrs[h]) {
        findings.push(finding(`Info Disclosure: ${h}`,
          `Server reveals ${h}: ${hdrs[h]}`,
          SEV.LOW, "HTTP Headers", `${h}: ${hdrs[h]}`,
          `Remove or suppress the ${h} header.`));
      }
    }

    // Cookie security
    const setCookie = hdrs["set-cookie"];
    if (setCookie) {
      const lc = setCookie.toLowerCase();
      if (!lc.includes("secure")) findings.push(finding("Cookie Missing Secure Flag", "Set-Cookie lacks Secure flag.", SEV.MEDIUM, "HTTP Headers", "", "Add Secure flag to all cookies."));
      if (!lc.includes("httponly")) findings.push(finding("Cookie Missing HttpOnly Flag", "Set-Cookie lacks HttpOnly flag.", SEV.MEDIUM, "HTTP Headers", "", "Add HttpOnly flag to session cookies."));
      if (!lc.includes("samesite")) findings.push(finding("Cookie Missing SameSite", "Set-Cookie lacks SameSite attribute.", SEV.LOW, "HTTP Headers", "", "Add SameSite=Lax or Strict."));
    }

    // HTTP to HTTPS redirect
    try {
      const httpResp = await fetchHeaders(`http://${domain}`);
      if (httpResp.statusCode >= 300 && httpResp.statusCode < 400) {
        if (httpResp.location && httpResp.location.includes("https://")) {
          rawData.http_to_https_redirect = true;
        } else {
          findings.push(finding("HTTP Redirect Not to HTTPS",
            `HTTP redirects to ${httpResp.location} instead of HTTPS.`,
            SEV.MEDIUM, "HTTP Headers", "", "Redirect HTTP to HTTPS."));
        }
      } else if (httpResp.statusCode === 200) {
        findings.push(finding("HTTP Serves Content Without HTTPS Redirect",
          "Site serves content over HTTP without redirecting.",
          SEV.HIGH, "HTTP Headers", "", "Add 301 redirect from HTTP to HTTPS."));
      }
    } catch { /* HTTP not available, which is fine if HTTPS works */ }

  } catch (e) {
    findings.push(finding("HTTP Header Scan Error", e.message, SEV.MEDIUM, "HTTP Headers"));
  }

  return { scanner: "HTTP Security Headers Scanner", domain, findings, raw_data: rawData };
}

// ============================
// DNS SCANNER
// ============================
async function scanDNS(domain) {
  const findings = [];
  const rawData = { records: {} };

  const resolveDns = (d, type) => withTimeout(new Promise((resolve) => {
    const fn = { A: "resolve4", AAAA: "resolve6", MX: "resolveMx", NS: "resolveNs", TXT: "resolveTxt", SOA: "resolveSoa", CNAME: "resolveCname", CAA: "resolveCaa" }[type];
    if (!fn || !dns[fn]) return resolve([]);
    dns[fn](d, (err, records) => {
      if (err) return resolve([]);
      resolve(records || []);
    });
  }), 5000);

  try {
    // Query all record types
    const [aRecs, aaaaRecs, mxRecs, nsRecs, txtRecs, cnameRecs] = await Promise.all([
      resolveDns(domain, "A"), resolveDns(domain, "AAAA"), resolveDns(domain, "MX"),
      resolveDns(domain, "NS"), resolveDns(domain, "TXT"), resolveDns(domain, "CNAME"),
    ]);

    rawData.records = { A: aRecs, AAAA: aaaaRecs, MX: mxRecs?.map(m => `${m.priority} ${m.exchange}`) || [], NS: nsRecs, TXT: txtRecs?.map(t => t.join("")) || [], CNAME: cnameRecs };

    // No A record
    if (!aRecs.length) {
      findings.push(finding("No A Record Found",
        `No A record for ${domain}.`,
        SEV.HIGH, "DNS", "", "Verify DNS configuration."));
    }

    // NS check
    if (nsRecs.length < 2) {
      findings.push(finding("Insufficient Nameservers",
        `Only ${nsRecs.length} NS record(s) found. At least 2 recommended.`,
        SEV.MEDIUM, "DNS", `NS: ${nsRecs.join(", ")}`,
        "Configure at least 2 nameservers for redundancy."));
    }

    // CAA check
    let caaRecs = [];
    try { caaRecs = await resolveDns(domain, "CAA"); } catch { }
    rawData.records.CAA = caaRecs;
    if (!caaRecs.length) {
      findings.push(finding("No CAA Records",
        "No Certificate Authority Authorization records configured.",
        SEV.MEDIUM, "DNS", "",
        "Add CAA records to restrict which CAs can issue certificates."));
    }

    // MX check
    if (!mxRecs?.length) {
      findings.push(finding("No MX Records",
        "Domain has no MX records for email.",
        SEV.LOW, "DNS", "", "If email is used, configure MX records."));
    }

    // Dangling CNAME check
    for (const cname of (cnameRecs || [])) {
      try {
        await withTimeout(new Promise((resolve, reject) => {
          dns.resolve4(cname, (err) => err ? reject(err) : resolve());
        }), 3000);
      } catch {
        findings.push(finding("Dangling CNAME (Subdomain Takeover Risk)",
          `CNAME ${cname} does not resolve.`,
          SEV.HIGH, "DNS", `CNAME: ${cname}`,
          "Remove the dangling CNAME or point to a valid target."));
      }
    }

    if (findings.length === 0) {
      findings.push(finding("DNS Configuration Looks Good",
        "No critical DNS misconfigurations detected.",
        SEV.INFO, "DNS"));
    }

  } catch (e) {
    findings.push(finding("DNS Scan Error", e.message, SEV.MEDIUM, "DNS"));
  }

  return { scanner: "DNS Security Scanner", domain, findings, raw_data: rawData };
}

// ============================
// EMAIL SECURITY SCANNER (SPF/DKIM/DMARC)
// ============================
async function scanEmail(domain) {
  const findings = [];
  const rawData = { spf: {}, dmarc: {}, dkim: {} };

  const resolveTxt = (d) => withTimeout(new Promise((resolve) => {
    dns.resolveTxt(d, (err, records) => {
      if (err) return resolve([]);
      resolve((records || []).map(r => r.join("")));
    });
  }), 5000);

  try {
    // ===== SPF =====
    const txtRecords = await resolveTxt(domain);
    const spfRecords = txtRecords.filter(r => r.trim().startsWith("v=spf1"));

    if (!spfRecords.length) {
      findings.push(finding("No SPF Record Found",
        "Domain has no SPF record, vulnerable to email spoofing.",
        SEV.HIGH, "Email Security", "",
        "Add an SPF record (e.g., v=spf1 include:_spf.google.com -all)."));
      rawData.spf.status = "missing";
    } else if (spfRecords.length > 1) {
      findings.push(finding("Multiple SPF Records",
        `Found ${spfRecords.length} SPF records. Only one allowed per RFC 7208.`,
        SEV.HIGH, "Email Security", spfRecords.join(" | "),
        "Consolidate into a single SPF record."));
    } else {
      const spf = spfRecords[0];
      rawData.spf = { record: spf, status: "found" };

      if (spf.includes("+all")) {
        findings.push(finding("SPF Overly Permissive (+all)",
          "SPF uses +all allowing any server to send email.",
          SEV.CRITICAL, "Email Security", spf,
          "Change +all to -all or ~all."));
      } else if (spf.endsWith("~all")) {
        findings.push(finding("SPF Soft Fail (~all)",
          "SPF uses soft fail. Consider hard fail (-all).",
          SEV.LOW, "Email Security", spf,
          "Change ~all to -all for stricter enforcement."));
      } else if (spf.includes("?all")) {
        findings.push(finding("SPF Neutral (?all)",
          "SPF uses neutral policy providing no protection.",
          SEV.MEDIUM, "Email Security", spf, "Change ?all to -all."));
      }

      // DNS lookup count
      const lookups = ["include:", "a:", "mx:", "ptr:", "exists:", "redirect="].reduce((c, m) => c + (spf.split(m).length - 1), 0);
      rawData.spf.dns_lookups = lookups;
      if (lookups > 10) {
        findings.push(finding("SPF Exceeds DNS Lookup Limit",
          `SPF requires ${lookups} lookups (max 10).`,
          SEV.HIGH, "Email Security", `Lookups: ${lookups}`,
          "Reduce mechanisms or use SPF flattening."));
      }
    }

    // ===== DMARC =====
    const dmarcRecords = await resolveTxt(`_dmarc.${domain}`);
    const dmarcEntries = dmarcRecords.filter(r => r.toLowerCase().includes("v=dmarc1"));

    if (!dmarcEntries.length) {
      findings.push(finding("No DMARC Record Found",
        "Domain has no DMARC policy, reducing email authentication.",
        SEV.HIGH, "Email Security", "",
        "Add a DMARC record (e.g., v=DMARC1; p=reject; rua=mailto:dmarc@example.com)."));
      rawData.dmarc.status = "missing";
    } else {
      const dmarc = dmarcEntries[0];
      rawData.dmarc = { record: dmarc, status: "found" };

      const pMatch = dmarc.match(/p=(\w+)/);
      const policy = pMatch ? pMatch[1].toLowerCase() : "none";
      rawData.dmarc.policy = policy;

      if (policy === "none") {
        findings.push(finding("DMARC Policy: None (Monitor Only)",
          "DMARC in monitoring mode, no enforcement.",
          SEV.MEDIUM, "Email Security", dmarc,
          "Upgrade to p=quarantine or p=reject."));
      } else if (policy === "quarantine") {
        findings.push(finding("DMARC Policy: Quarantine",
          "Suspicious emails quarantined but not rejected.",
          SEV.LOW, "Email Security", dmarc,
          "Consider upgrading to p=reject."));
      }

      if (!dmarc.includes("rua=")) {
        findings.push(finding("DMARC Missing Report Address",
          "No rua= tag. Reports won't be collected.",
          SEV.MEDIUM, "Email Security", "",
          "Add rua=mailto:reports@yourdomain.com."));
      }
    }

    // ===== DKIM (common selectors) =====
    const selectors = ["default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim", "s1", "s2"];
    let dkimFound = false;
    for (const sel of selectors) {
      const recs = await resolveTxt(`${sel}._domainkey.${domain}`);
      if (recs.length) {
        dkimFound = true;
        rawData.dkim = { selector: sel, status: "found", record: recs[0].substring(0, 200) };
        break;
      }
    }
    if (!dkimFound) {
      findings.push(finding("No DKIM Record Found",
        "Could not find DKIM records using common selectors.",
        SEV.MEDIUM, "Email Security",
        `Checked: ${selectors.slice(0, 6).join(", ")}...`,
        "Configure DKIM signing for your email domain."));
      rawData.dkim.status = "not_found";
    }

  } catch (e) {
    findings.push(finding("Email Security Scan Error", e.message, SEV.MEDIUM, "Email Security"));
  }

  return { scanner: "Email Security Scanner", domain, findings, raw_data: rawData };
}

// ============================
// TECH FINGERPRINTING
// ============================
async function scanTech(domain) {
  const findings = [];
  const rawData = {};

  try {
    const body = await withTimeout(new Promise((resolve, reject) => {
      const req = https.get(`https://${domain}`, {
        timeout: 8000,
        headers: { "User-Agent": "SecComply-Scanner/1.0" },
        rejectUnauthorized: false,
      }, (res) => {
        let data = "";
        res.on("data", chunk => { data += chunk; if (data.length > 50000) res.destroy(); });
        res.on("end", () => resolve({ headers: res.headers, body: data, statusCode: res.statusCode }));
      });
      req.on("error", reject);
      req.on("timeout", () => { req.destroy(); reject(new Error("Timeout")); });
    }));

    const hdrs = body.headers;
    const html = body.body.toLowerCase();
    rawData.technologies = [];

    // Server header
    if (hdrs.server) rawData.technologies.push({ name: hdrs.server, category: "Server" });
    if (hdrs["x-powered-by"]) rawData.technologies.push({ name: hdrs["x-powered-by"], category: "Framework" });

    // HTML-based detection
    const techPatterns = [
      { pattern: "wp-content", name: "WordPress", severity: SEV.LOW, rec: "Keep WordPress and plugins updated." },
      { pattern: "drupal", name: "Drupal", severity: SEV.INFO },
      { pattern: "joomla", name: "Joomla", severity: SEV.INFO },
      { pattern: "react", name: "React", severity: SEV.INFO },
      { pattern: "angular", name: "Angular", severity: SEV.INFO },
      { pattern: "vue.js", name: "Vue.js", severity: SEV.INFO },
      { pattern: "next.js", name: "Next.js", severity: SEV.INFO },
      { pattern: "jquery", name: "jQuery", severity: SEV.LOW, rec: "Ensure jQuery is updated to latest version." },
      { pattern: "bootstrap", name: "Bootstrap", severity: SEV.INFO },
      { pattern: "cloudflare", name: "Cloudflare", severity: SEV.INFO },
      { pattern: "google analytics", name: "Google Analytics", severity: SEV.INFO },
      { pattern: "gtag", name: "Google Tag Manager", severity: SEV.INFO },
      { pattern: "shopify", name: "Shopify", severity: SEV.INFO },
      { pattern: "wix.com", name: "Wix", severity: SEV.INFO },
      { pattern: "squarespace", name: "Squarespace", severity: SEV.INFO },
    ];

    for (const t of techPatterns) {
      if (html.includes(t.pattern) || (hdrs.server || "").toLowerCase().includes(t.pattern)) {
        rawData.technologies.push({ name: t.name, category: "Detected" });
        if (t.severity !== SEV.INFO) {
          findings.push(finding(`Technology Detected: ${t.name}`,
            `The website uses ${t.name}.`,
            t.severity, "Technology", "",
            t.rec || "Keep all software updated."));
        }
      }
    }

    // Version disclosure in HTML
    const versionMatch = html.match(/(?:version|ver|v)[\"':\s]*(\d+\.\d+(?:\.\d+)?)/);
    if (versionMatch) {
      findings.push(finding("Software Version Disclosed",
        `Version information found in page source: ${versionMatch[0]}`,
        SEV.LOW, "Technology", versionMatch[0],
        "Remove version information from public-facing pages."));
    }

    if (findings.length === 0) {
      findings.push(finding("Technology Scan Complete",
        `Detected ${rawData.technologies.length} technologies.`,
        SEV.INFO, "Technology"));
    }

  } catch (e) {
    findings.push(finding("Tech Scan Error", e.message, SEV.INFO, "Technology"));
  }

  return { scanner: "Technology Scanner", domain, findings, raw_data: rawData };
}

// ============================
// RISK ENGINE
// ============================
function calculateRisk(allResults) {
  const SEV_WEIGHTS = { critical: 10, high: 7, medium: 4, low: 1.5, info: 0 };
  const CAT_WEIGHTS = { "SSL/TLS": 1.5, "DNS": 1.3, "Email Security": 1.0, "HTTP Headers": 1.2, "Technology": 0.9 };

  const allFindings = allResults.flatMap(r => r.findings || []);
  let critical = 0, high = 0, medium = 0, low = 0, info = 0;
  let totalPenalty = 0;
  const categoryPenalties = {};

  for (const f of allFindings) {
    if (f.severity === "critical") critical++;
    else if (f.severity === "high") high++;
    else if (f.severity === "medium") medium++;
    else if (f.severity === "low") low++;
    else info++;

    const w = SEV_WEIGHTS[f.severity] || 0;
    const cw = CAT_WEIGHTS[f.category] || 1.0;
    const penalty = w * cw;
    totalPenalty += penalty;
    categoryPenalties[f.category] = (categoryPenalties[f.category] || 0) + penalty;
  }

  let score = Math.max(0, 100 - Math.min(totalPenalty / 200 * 100, 100));

  // Category scores
  const categoryScores = {};
  for (const [cat, maxW] of Object.entries(CAT_WEIGHTS)) {
    const catPen = categoryPenalties[cat] || 0;
    categoryScores[cat] = Math.max(0, Math.round(100 - (catPen / 30 * 100)));
  }

  // Critical findings cap score
  if (critical > 0) { score = Math.min(score, 40); }

  let riskLevel, letterGrade;
  if (score >= 85) { riskLevel = "Low Risk"; }
  else if (score >= 70) { riskLevel = "Moderate Risk"; }
  else if (score >= 50) { riskLevel = "High Risk"; }
  else { riskLevel = "Critical Risk"; }
  if (critical > 0) riskLevel = "Critical Risk";

  if (score >= 90) letterGrade = "A+";
  else if (score >= 80) letterGrade = "A";
  else if (score >= 70) letterGrade = "B";
  else if (score >= 60) letterGrade = "C";
  else if (score >= 50) letterGrade = "D";
  else letterGrade = "F";

  const topRisks = allFindings
    .filter(f => f.severity !== "info")
    .sort((a, b) => SEV_WEIGHTS[b.severity] - SEV_WEIGHTS[a.severity])
    .slice(0, 10)
    .map(f => ({ title: f.title, severity: f.severity, category: f.category, recommendation: f.recommendation }));

  return {
    overall_score: Math.round(score),
    risk_level: riskLevel,
    letter_grade: letterGrade,
    category_scores: categoryScores,
    findings_summary: { critical, high, medium, low, info, total: allFindings.length },
    top_risks: topRisks,
  };
}

// ============================
// HANDLER
// ============================
export const handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return { statusCode: 200, headers, body: "" };
  if (event.httpMethod !== "POST") return { statusCode: 405, headers, body: JSON.stringify({ error: "Method not allowed" }) };

  try {
    const { domain: inputDomain } = JSON.parse(event.body || "{}");
    if (!inputDomain) return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing domain or URL" }) };

    // Extract domain from URL if needed
    let domain = inputDomain.trim().toLowerCase();
    if (domain.startsWith("http")) {
      try { domain = new URL(domain).hostname; } catch { }
    }
    domain = domain.replace(/^www\./, "").replace(/\/+$/, "");
    if (!domain || domain.length < 3) return { statusCode: 400, headers, body: JSON.stringify({ error: "Invalid domain" }) };

    const startTime = Date.now();

    // Run all scanners in parallel
    const [sslResult, headersResult, dnsResult, emailResult, techResult] = await Promise.allSettled([
      scanSSL(domain),
      scanHeaders(domain),
      scanDNS(domain),
      scanEmail(domain),
      scanTech(domain),
    ]);

    const results = [sslResult, headersResult, dnsResult, emailResult, techResult]
      .filter(r => r.status === "fulfilled")
      .map(r => r.value);

    // Add error results for failed scanners
    [sslResult, headersResult, dnsResult, emailResult, techResult].forEach((r, i) => {
      if (r.status === "rejected") {
        const names = ["SSL/TLS", "HTTP Headers", "DNS", "Email Security", "Technology"];
        results.push({
          scanner: `${names[i]} Scanner`,
          domain,
          findings: [finding(`${names[i]} Scan Failed`, r.reason?.message || "Unknown error", SEV.MEDIUM, names[i])],
          raw_data: {},
        });
      }
    });

    const riskScore = calculateRisk(results);
    const duration = ((Date.now() - startTime) / 1000).toFixed(2);

    const report = {
      meta: {
        domain,
        scan_date: new Date().toISOString(),
        scan_duration_seconds: parseFloat(duration),
        scanners_run: results.length,
        module: "SecComply Attack Surface Scanner v1.0",
      },
      risk_score: riskScore,
      scan_results: results.map(r => ({
        scanner: r.scanner,
        domain: r.domain,
        findings_count: r.findings.length,
        findings: r.findings,
      })),
    };

    return { statusCode: 200, headers, body: JSON.stringify(report) };

  } catch (e) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: e.message }) };
  }
};
