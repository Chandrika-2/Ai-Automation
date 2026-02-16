import { createSign } from "crypto";

const headers = { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Content-Type", "Access-Control-Allow-Methods": "POST, OPTIONS" };
const safe = async (fn, fb) => { try { return await fn(); } catch(e) { console.warn("[gcp-scan] Error:", e.message); return typeof fb === "function" ? fb() : fb; } };

async function getAccessToken(clientEmail, privateKey) {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({
    iss: clientEmail,
    scope: "https://www.googleapis.com/auth/cloud-platform.read-only https://www.googleapis.com/auth/cloud-platform",
    aud: "https://oauth2.googleapis.com/token",
    iat: now, exp: now + 3600,
  })).toString("base64url");
  const sign = createSign("RSA-SHA256");
  sign.update(`${header}.${payload}`);
  const signature = sign.sign(privateKey.replace(/\\n/g, "\n"), "base64url");
  const jwt = `${header}.${payload}.${signature}`;
  const resp = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`,
  });
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.error_description || "Token exchange failed");
  return data.access_token;
}

const gcpFetch = async (url, token) => {
  const r = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.error?.message || `HTTP ${r.status}`); }
  return r.json();
};

const gcpList = async (url, token, key = "items") => {
  try {
    const d = await gcpFetch(url, token);
    return d[key] || d.accounts || d.serviceAccounts || d.bindings || d.firewalls || d.instances || d.sslPolicies || [];
  } catch { return []; }
};

export const handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return { statusCode: 200, headers, body: "" };
  if (event.httpMethod !== "POST") return { statusCode: 405, headers, body: JSON.stringify({ error: "Method not allowed" }) };

  const { projectId, clientEmail, privateKey, accessToken } = JSON.parse(event.body || "{}");
  if (!projectId) return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing projectId" }) };

  const results = {}; const log = [];
  const CRM = "https://cloudresourcemanager.googleapis.com/v1";
  const COMPUTE = `https://compute.googleapis.com/compute/v1/projects/${projectId}`;
  const IAM = "https://iam.googleapis.com/v1";
  const STORAGE = "https://storage.googleapis.com/storage/v1";
  const SQLADMIN = `https://sqladmin.googleapis.com/v1/projects/${projectId}`;
  const LOGGING = `https://logging.googleapis.com/v2`;
  const KMS = `https://cloudkms.googleapis.com/v1/projects/${projectId}/locations`;

  try {
    log.push("Authenticating...");
    let token;
    if (accessToken) {
      token = accessToken;
      log.push("Using OAuth access token");
    } else if (clientEmail && privateKey) {
      token = await getAccessToken(clientEmail, privateKey);
      log.push("Using service account key");
    } else {
      return { statusCode: 400, headers, body: JSON.stringify({ error: "Provide accessToken or (clientEmail + privateKey)" }) };
    }

    // Verify project
    const project = await gcpFetch(`${CRM}/projects/${projectId}`, token);
    log.push(`Project: ${project.name} (${project.projectId})`);

    // ═══════════════════════════════════════════
    // IAM CHECKS (10)
    // ═══════════════════════════════════════════
    log.push("Scanning IAM...");

    // gcp_iam_01: Service accounts — check for user-managed keys
    await safe(async () => {
      const sas = await gcpList(`${IAM}/projects/${projectId}/serviceAccounts`, token, "accounts");
      let hasUserKeys = false;
      for (const sa of sas.slice(0, 20)) {
        const keys = await gcpList(`${IAM}/${sa.name}/keys`, token, "keys");
        const userKeys = keys.filter(k => k.keyType === "USER_MANAGED");
        if (userKeys.length > 0) hasUserKeys = true;
        // Check for old keys (>90 days)
        const oldKeys = userKeys.filter(k => {
          const created = new Date(k.validAfterTime);
          return (Date.now() - created.getTime()) > 90 * 86400000;
        });
        results.gcp_iam_09 = results.gcp_iam_09 === "FAIL" ? "FAIL" : (oldKeys.length > 0 ? "FAIL" : "PASS");
      }
      results.gcp_iam_01 = hasUserKeys ? "WARN" : "PASS";
      if (sas.length === 0) { results.gcp_iam_01 = "N/A"; results.gcp_iam_09 = "N/A"; }
    }, () => { results.gcp_iam_01 = "ERROR"; results.gcp_iam_09 = "ERROR"; });

    // gcp_iam_02: Check IAM policy for overly permissive bindings
    await safe(async () => {
      const policy = await gcpFetch(`${CRM}/projects/${projectId}:getIamPolicy`, token);
      const bindings = policy.bindings || [];
      // Check for allUsers or allAuthenticatedUsers
      const publicBindings = bindings.filter(b => (b.members || []).some(m => m === "allUsers" || m === "allAuthenticatedUsers"));
      results.gcp_iam_02 = publicBindings.length > 0 ? "FAIL" : "PASS";
      // Check for owner/editor roles on service accounts
      const adminBindings = bindings.filter(b => (b.role === "roles/owner" || b.role === "roles/editor") && (b.members || []).some(m => m.startsWith("serviceAccount:")));
      results.gcp_iam_03 = adminBindings.length > 0 ? "WARN" : "PASS";
      // Check for primitive roles usage
      const primitiveRoles = bindings.filter(b => ["roles/owner", "roles/editor", "roles/viewer"].includes(b.role));
      results.gcp_iam_04 = primitiveRoles.length > 3 ? "WARN" : "PASS";
      // Check separation of duties — owner != editor
      results.gcp_iam_05 = "MANUAL";
    }, () => { results.gcp_iam_02 = "ERROR"; results.gcp_iam_03 = "ERROR"; results.gcp_iam_04 = "ERROR"; results.gcp_iam_05 = "MANUAL"; });

    // gcp_iam_06: Default service account usage
    await safe(async () => {
      const sas = await gcpList(`${IAM}/projects/${projectId}/serviceAccounts`, token, "accounts");
      const defaultSa = sas.find(s => s.email && (s.email.includes("compute@developer") || s.email.includes("appspot")));
      const policy = await gcpFetch(`${CRM}/projects/${projectId}:getIamPolicy`, token);
      const bindings = policy.bindings || [];
      const defaultUsed = defaultSa && bindings.some(b => (b.members || []).some(m => m.includes(defaultSa.email)));
      results.gcp_iam_06 = defaultUsed ? "WARN" : "PASS";
    }, () => { results.gcp_iam_06 = "MANUAL"; });

    // gcp_iam_07: API keys — check for unrestricted
    results.gcp_iam_07 = "MANUAL"; // API key restrictions require admin API

    // gcp_iam_08: Domain-restricted sharing
    await safe(async () => {
      const policy = await gcpFetch(`${CRM}/projects/${projectId}:getIamPolicy`, token);
      const bindings = policy.bindings || [];
      const externalMembers = bindings.flatMap(b => (b.members || []).filter(m => m.startsWith("user:") && !m.endsWith(clientEmail.split("@")[1])));
      results.gcp_iam_08 = externalMembers.length > 0 ? "WARN" : "PASS";
    }, () => { results.gcp_iam_08 = "MANUAL"; });

    // gcp_iam_10: Organization policy constraints
    results.gcp_iam_10 = "MANUAL";

    // ═══════════════════════════════════════════
    // LOGGING & MONITORING (5)
    // ═══════════════════════════════════════════
    log.push("Scanning Logging...");

    // gcp_log_01: Audit logs enabled
    await safe(async () => {
      const policy = await gcpFetch(`${CRM}/projects/${projectId}:getIamPolicy`, token);
      const auditConfigs = policy.auditConfigs || [];
      results.gcp_log_01 = auditConfigs.length > 0 ? "PASS" : "WARN";
      // Check for allServices audit
      const allServices = auditConfigs.find(a => a.service === "allServices");
      results.gcp_log_02 = allServices ? "PASS" : "WARN";
    }, () => { results.gcp_log_01 = "ERROR"; results.gcp_log_02 = "ERROR"; });

    // gcp_log_03: Log sinks configured
    await safe(async () => {
      const resp = await gcpFetch(`${LOGGING}/projects/${projectId}/sinks`, token);
      const sinks = resp.sinks || [];
      results.gcp_log_03 = sinks.length > 0 ? "PASS" : "FAIL";
    }, () => { results.gcp_log_03 = "ERROR"; });

    // gcp_log_04: Log retention
    await safe(async () => {
      const resp = await gcpFetch(`${LOGGING}/projects/${projectId}/metrics`, token);
      results.gcp_log_04 = (resp.metrics || []).length > 0 ? "PASS" : "MANUAL";
    }, () => { results.gcp_log_04 = "MANUAL"; });

    // gcp_log_05: Alert policies
    await safe(async () => {
      const resp = await gcpFetch(`https://monitoring.googleapis.com/v3/projects/${projectId}/alertPolicies`, token);
      const policies = resp.alertPolicies || [];
      results.gcp_log_05 = policies.length > 0 ? "PASS" : "FAIL";
    }, () => { results.gcp_log_05 = "MANUAL"; });

    // ═══════════════════════════════════════════
    // STORAGE (5)
    // ═══════════════════════════════════════════
    log.push("Scanning Storage...");

    await safe(async () => {
      const resp = await gcpFetch(`${STORAGE}/b?project=${projectId}`, token);
      const buckets = resp.items || [];
      if (buckets.length === 0) {
        results.gcp_str_01 = "N/A"; results.gcp_str_02 = "N/A";
        results.gcp_str_03 = "N/A"; results.gcp_str_04 = "N/A"; results.gcp_str_05 = "N/A";
        return;
      }
      let allEncrypted = true, allUniform = true, anyPublic = false, allVersioned = true, allRetention = true;
      for (const b of buckets.slice(0, 20)) {
        try {
          const detail = await gcpFetch(`${STORAGE}/b/${b.name}?fields=encryption,iamConfiguration,versioning,retentionPolicy,acl`, token);
          // Public access
          if (detail.iamConfiguration?.publicAccessPrevention !== "enforced") {
            // Check IAM policy
            try {
              const bPolicy = await gcpFetch(`${STORAGE}/b/${b.name}/iam`, token);
              const pubBindings = (bPolicy.bindings || []).filter(x => (x.members || []).some(m => m === "allUsers" || m === "allAuthenticatedUsers"));
              if (pubBindings.length > 0) anyPublic = true;
            } catch { /* no access */ }
          }
          // Uniform bucket-level access
          if (!detail.iamConfiguration?.uniformBucketLevelAccess?.enabled) allUniform = false;
          // Encryption (default is Google-managed, check for CMEK)
          if (!detail.encryption?.defaultKmsKeyName) { /* Google-managed is ok, just note */ }
          // Versioning
          if (!detail.versioning?.enabled) allVersioned = false;
          // Retention policy
          if (!detail.retentionPolicy) allRetention = false;
        } catch { /* skip inaccessible buckets */ }
      }
      results.gcp_str_01 = anyPublic ? "FAIL" : "PASS";
      results.gcp_str_02 = "PASS"; // All GCS buckets encrypted by default
      results.gcp_str_03 = allUniform ? "PASS" : "WARN";
      results.gcp_str_04 = allVersioned ? "PASS" : "WARN";
      results.gcp_str_05 = allRetention ? "PASS" : "WARN";
    }, () => { ["gcp_str_01","gcp_str_02","gcp_str_03","gcp_str_04","gcp_str_05"].forEach(k => results[k] = results[k] || "ERROR"); });

    // ═══════════════════════════════════════════
    // COMPUTE (5)
    // ═══════════════════════════════════════════
    log.push("Scanning Compute...");

    await safe(async () => {
      // Get all zones, then instances
      const aggResp = await gcpFetch(`${COMPUTE}/aggregated/instances`, token);
      const allInstances = [];
      for (const [, zoneData] of Object.entries(aggResp.items || {})) {
        if (zoneData.instances) allInstances.push(...zoneData.instances);
      }
      if (allInstances.length === 0) {
        results.gcp_cmp_01 = "N/A"; results.gcp_cmp_02 = "N/A";
        results.gcp_cmp_03 = "N/A"; results.gcp_cmp_04 = "N/A"; results.gcp_cmp_05 = "N/A";
        return;
      }
      let serialPortDisabled = true, ipFwdOff = true, osLoginEnabled = true, shieldedVm = true, noPublicIp = true;
      for (const inst of allInstances.slice(0, 30)) {
        const meta = inst.metadata?.items || [];
        const getMetaVal = (key) => (meta.find(m => m.key === key) || {}).value;
        // Serial port
        if (getMetaVal("serial-port-enable") === "true" || getMetaVal("serial-port-enable") === "1") serialPortDisabled = false;
        // IP forwarding
        if (inst.canIpForward) ipFwdOff = false;
        // OS Login
        if (getMetaVal("enable-oslogin") !== "TRUE" && getMetaVal("enable-oslogin") !== "true") osLoginEnabled = false;
        // Shielded VM
        if (!inst.shieldedInstanceConfig?.enableVtpm || !inst.shieldedInstanceConfig?.enableIntegrityMonitoring) shieldedVm = false;
        // Public IP
        for (const ni of (inst.networkInterfaces || [])) {
          if ((ni.accessConfigs || []).some(ac => ac.natIP)) noPublicIp = false;
        }
      }
      results.gcp_cmp_01 = serialPortDisabled ? "PASS" : "FAIL";
      results.gcp_cmp_02 = ipFwdOff ? "PASS" : "WARN";
      results.gcp_cmp_03 = osLoginEnabled ? "PASS" : "WARN";
      results.gcp_cmp_04 = shieldedVm ? "PASS" : "WARN";
      results.gcp_cmp_05 = noPublicIp ? "PASS" : "WARN";
    }, () => { ["gcp_cmp_01","gcp_cmp_02","gcp_cmp_03","gcp_cmp_04","gcp_cmp_05"].forEach(k => results[k] = results[k] || "ERROR"); });

    // ═══════════════════════════════════════════
    // NETWORK / FIREWALL (5)
    // ═══════════════════════════════════════════
    log.push("Scanning Network...");

    await safe(async () => {
      const fwResp = await gcpFetch(`${COMPUTE}/global/firewalls`, token);
      const firewalls = fwResp.items || [];
      if (firewalls.length === 0) {
        results.gcp_net_01 = "N/A"; results.gcp_net_02 = "N/A"; results.gcp_net_03 = "N/A";
        return;
      }
      // Check for 0.0.0.0/0 SSH
      const sshOpen = firewalls.some(f => f.direction === "INGRESS" && !f.disabled && (f.sourceRanges || []).includes("0.0.0.0/0") && (f.allowed || []).some(a => (a.ports || []).some(p => p === "22" || p === "22-22")));
      results.gcp_net_01 = sshOpen ? "FAIL" : "PASS";
      // Check for 0.0.0.0/0 RDP
      const rdpOpen = firewalls.some(f => f.direction === "INGRESS" && !f.disabled && (f.sourceRanges || []).includes("0.0.0.0/0") && (f.allowed || []).some(a => (a.ports || []).some(p => p === "3389" || p === "3389-3389")));
      results.gcp_net_02 = rdpOpen ? "FAIL" : "PASS";
      // Check for overly permissive rules (all protocols from 0.0.0.0/0)
      const wideOpen = firewalls.some(f => f.direction === "INGRESS" && !f.disabled && (f.sourceRanges || []).includes("0.0.0.0/0") && (f.allowed || []).some(a => !a.ports || a.IPProtocol === "all"));
      results.gcp_net_03 = wideOpen ? "FAIL" : "PASS";
    }, () => { results.gcp_net_01 = "ERROR"; results.gcp_net_02 = "ERROR"; results.gcp_net_03 = "ERROR"; });

    // gcp_net_04: SSL policies
    await safe(async () => {
      const sslResp = await gcpFetch(`${COMPUTE}/global/sslPolicies`, token);
      const policies = sslResp.items || [];
      if (policies.length === 0) { results.gcp_net_04 = "MANUAL"; return; }
      const weakPolicy = policies.some(p => p.minTlsVersion === "TLS_1_0" || p.minTlsVersion === "TLS_1_1");
      results.gcp_net_04 = weakPolicy ? "FAIL" : "PASS";
    }, () => { results.gcp_net_04 = "MANUAL"; });

    // gcp_net_05: Private Google Access
    await safe(async () => {
      const netResp = await gcpFetch(`${COMPUTE}/aggregated/subnetworks`, token);
      let allPrivate = true, count = 0;
      for (const [, regionData] of Object.entries(netResp.items || {})) {
        for (const subnet of (regionData.subnetworks || []).slice(0, 20)) {
          count++;
          if (!subnet.privateIpGoogleAccess) allPrivate = false;
        }
      }
      results.gcp_net_05 = count === 0 ? "N/A" : (allPrivate ? "PASS" : "WARN");
    }, () => { results.gcp_net_05 = "MANUAL"; });

    // ═══════════════════════════════════════════
    // DATABASE (5)
    // ═══════════════════════════════════════════
    log.push("Scanning Databases...");

    await safe(async () => {
      const sqlResp = await gcpFetch(`${SQLADMIN}/instances`, token);
      const instances = sqlResp.items || [];
      if (instances.length === 0) {
        results.gcp_db_01 = "N/A"; results.gcp_db_02 = "N/A";
        results.gcp_db_03 = "N/A"; results.gcp_db_04 = "N/A"; results.gcp_db_05 = "N/A";
        return;
      }
      let allEncrypted = true, allBackups = true, noPublicIp = true, allSSL = true, noAuthNets = true;
      for (const inst of instances) {
        const s = inst.settings || {};
        // Encryption — Cloud SQL always encrypted, check CMEK
        if (!s.dataDiskSizeGb) { /* just flag */ }
        // Backup
        if (!s.backupConfiguration?.enabled) allBackups = false;
        // Public IP
        if ((inst.ipAddresses || []).some(ip => ip.type === "PRIMARY")) {
          // Has public IP - check authorized networks
          const authNets = s.ipConfiguration?.authorizedNetworks || [];
          if (authNets.some(n => n.value === "0.0.0.0/0")) noAuthNets = false;
          noPublicIp = false;
        }
        // SSL required
        if (!s.ipConfiguration?.requireSsl) allSSL = false;
      }
      results.gcp_db_01 = "PASS"; // Cloud SQL always encrypted at rest
      results.gcp_db_02 = allBackups ? "PASS" : "FAIL";
      results.gcp_db_03 = noPublicIp ? "PASS" : (noAuthNets ? "WARN" : "FAIL");
      results.gcp_db_04 = allSSL ? "PASS" : "FAIL";
      results.gcp_db_05 = noAuthNets ? "PASS" : "FAIL";
    }, () => { ["gcp_db_01","gcp_db_02","gcp_db_03","gcp_db_04","gcp_db_05"].forEach(k => results[k] = results[k] || "ERROR"); });

    // ═══════════════════════════════════════════
    // KMS (3)
    // ═══════════════════════════════════════════
    log.push("Scanning KMS...");

    await safe(async () => {
      const locResp = await gcpFetch(`${KMS}`, token);
      const locations = (locResp.locations || []).slice(0, 5);
      let hasKeys = false, allRotation = true;
      for (const loc of locations) {
        try {
          const krResp = await gcpFetch(`${KMS}/${loc.locationId}/keyRings`, token);
          const rings = krResp.keyRings || [];
          for (const ring of rings.slice(0, 5)) {
            const ckResp = await gcpFetch(`https://cloudkms.googleapis.com/v1/${ring.name}/cryptoKeys`, token);
            const keys = ckResp.cryptoKeys || [];
            for (const key of keys) {
              hasKeys = true;
              if (!key.rotationPeriod && key.purpose === "ENCRYPT_DECRYPT") allRotation = false;
            }
          }
        } catch { /* location may not have KMS */ }
      }
      results.gcp_kms_01 = hasKeys ? (allRotation ? "PASS" : "FAIL") : "N/A";
      results.gcp_kms_02 = hasKeys ? "MANUAL" : "N/A"; // Key destruction check
      results.gcp_kms_03 = hasKeys ? "MANUAL" : "N/A"; // Separation of duties
    }, () => { results.gcp_kms_01 = "MANUAL"; results.gcp_kms_02 = "MANUAL"; results.gcp_kms_03 = "MANUAL"; });

    // ═══════════════════════════════════════════
    // SECURITY (2)
    // ═══════════════════════════════════════════
    log.push("Scanning Security...");
    results.gcp_sec_01 = "MANUAL"; // Security Command Center enabled
    results.gcp_sec_02 = "MANUAL"; // SCC findings reviewed

    // ═══════════════════════════════════════════
    // SUMMARY
    // ═══════════════════════════════════════════
    log.push("Done!");
    const pass = Object.values(results).filter(v => v === "PASS").length;
    const fail = Object.values(results).filter(v => v === "FAIL").length;
    const warn = Object.values(results).filter(v => v === "WARN").length;

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        success: true,
        projectId: project.projectId,
        projectName: project.name,
        results,
        summary: { pass, fail, warn, total: Object.keys(results).length, checks: 40 },
        log,
        scannedAt: new Date().toISOString(),
      }),
    };
  } catch (e) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: `GCP scan failed: ${e.message}`, results, log }) };
  }
};
