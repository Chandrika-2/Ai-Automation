import { ClientSecretCredential } from "@azure/identity";
import { SubscriptionClient } from "@azure/arm-subscriptions";
import { StorageManagementClient } from "@azure/arm-storage";
import { NetworkManagementClient } from "@azure/arm-network";
import { ComputeManagementClient } from "@azure/arm-compute";
import { MonitorClient } from "@azure/arm-monitor";
import { SqlManagementClient } from "@azure/arm-sql";
import { KeyVaultManagementClient } from "@azure/arm-keyvault";
import { SecurityCenter } from "@azure/arm-security";
import { PolicyClient } from "@azure/arm-policy";
import { AuthorizationManagementClient } from "@azure/arm-authorization";
import { ResourceManagementClient } from "@azure/arm-resources";

const headers = { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Content-Type", "Access-Control-Allow-Methods": "POST, OPTIONS" };
const safe = async (fn, fb) => { try { return await fn(); } catch { return typeof fb === "function" ? fb() : fb; } };
async function listAll(iter) { const items = []; try { for await (const i of iter) items.push(i); } catch {} return items; }

export const handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return { statusCode: 200, headers, body: "" };
  if (event.httpMethod !== "POST") return { statusCode: 405, headers, body: JSON.stringify({ error: "Method not allowed" }) };

  const { tenantId, clientId, clientSecret, subscriptionId } = JSON.parse(event.body || "{}");
  if (!tenantId || !clientId || !clientSecret || !subscriptionId) return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing credentials" }) };

  const cred = new ClientSecretCredential(tenantId, clientId, clientSecret);
  const results = {}; const log = [];

  try {
    log.push("Validating Azure credentials...");
    const subClient = new SubscriptionClient(cred);
    const sub = await subClient.subscriptions.get(subscriptionId);
    log.push("Connected: " + sub.displayName);

    const storage = new StorageManagementClient(cred, subscriptionId);
    const network = new NetworkManagementClient(cred, subscriptionId);
    const compute = new ComputeManagementClient(cred, subscriptionId);
    const monitor = new MonitorClient(cred, subscriptionId);
    const sqlMgmt = new SqlManagementClient(cred, subscriptionId);
    const kvMgmt = new KeyVaultManagementClient(cred, subscriptionId);
    const security = new SecurityCenter(cred, subscriptionId);
    const policyClient = new PolicyClient(cred, subscriptionId);
    const authClient = new AuthorizationManagementClient(cred, subscriptionId);
    const resMgmt = new ResourceManagementClient(cred, subscriptionId);

    // ===== 1. IDENTITY (7) =====
    log.push("Identity & Access...");
    await safe(async () => { const roles = await listAll(authClient.roleDefinitions.list("subscriptions/" + subscriptionId, { filter: "type eq 'CustomRole'" })); results.az_iam_01 = roles.length <= 5 ? "PASS" : (roles.length <= 15 ? "WARN" : "FAIL"); }, () => { results.az_iam_01 = "MANUAL"; });
    await safe(async () => { const asgn = await listAll(authClient.roleAssignments.listForSubscription()); const ownerSPs = asgn.filter(a => a.roleDefinitionId?.includes("8e3af657-a8ff-443c-a75c-2fe8c4bcb635") && a.principalType === "ServicePrincipal"); results.az_iam_02 = ownerSPs.length === 0 ? "PASS" : "WARN"; }, () => { results.az_iam_02 = "MANUAL"; });
    results.az_iam_03 = "MANUAL"; results.az_iam_04 = "MANUAL"; results.az_iam_05 = "MANUAL"; results.az_iam_06 = "MANUAL"; results.az_iam_07 = "MANUAL";

    // ===== 2. DEFENDER (4) =====
    log.push("Defender for Cloud...");
    await safe(async () => { const pr = await listAll(security.pricings.list()); const sc = pr.filter(p => p.pricingTier === "Standard").length; results.az_def_01 = sc > 0 ? "PASS" : "FAIL"; const srv = pr.find(p => p.name === "VirtualMachines" || p.name === "Servers"); results.az_def_02 = srv?.pricingTier === "Standard" ? "PASS" : "FAIL"; const stP = pr.find(p => p.name === "StorageAccounts"); results.az_def_03 = stP?.pricingTier === "Standard" ? "PASS" : "FAIL"; }, () => { results.az_def_01 = results.az_def_01 || "MANUAL"; results.az_def_02 = results.az_def_02 || "MANUAL"; results.az_def_03 = results.az_def_03 || "MANUAL"; });
    await safe(async () => { const ap = await listAll(security.autoProvisioningSettings.list()); const d = ap.find(s => s.name === "default"); results.az_def_04 = d?.autoProvision === "On" ? "PASS" : "FAIL"; }, () => { results.az_def_04 = "MANUAL"; });

    // ===== 3. STORAGE (6) =====
    log.push("Storage Accounts...");
    await safe(async () => {
      const accts = await listAll(storage.storageAccounts.list());
      if (accts.length === 0) { ["az_stor_01","az_stor_02","az_stor_03","az_stor_04","az_stor_05","az_stor_06"].forEach(k => results[k] = "N/A"); return; }
      results.az_stor_01 = accts.every(a => a.encryption?.services?.blob?.enabled !== false) ? "PASS" : "FAIL";
      results.az_stor_02 = accts.every(a => a.enableHttpsTrafficOnly !== false) ? "PASS" : "FAIL";
      results.az_stor_03 = accts.every(a => a.allowBlobPublicAccess === false) ? "PASS" : "FAIL";
      results.az_stor_05 = accts.every(a => a.minimumTlsVersion === "TLS1_2") ? "PASS" : "FAIL";
      results.az_stor_06 = accts.every(a => a.networkRuleSet?.defaultAction === "Deny") ? "PASS" : "WARN";
      let allSD = true;
      for (const a of accts.slice(0, 10)) { await safe(async () => { const rg = a.id.split("/")[4]; const p = await storage.blobServices.getServiceProperties(rg, a.name); if (!p.deleteRetentionPolicy?.enabled) allSD = false; }, () => { allSD = false; }); }
      results.az_stor_04 = allSD ? "PASS" : "WARN";
    }, () => { ["az_stor_01","az_stor_02","az_stor_03","az_stor_04","az_stor_05","az_stor_06"].forEach(k => { results[k] = results[k] || "ERROR"; }); });

    // ===== 4. NETWORK (6) =====
    log.push("Network Security...");
    await safe(async () => {
      const nsgs = await listAll(network.networkSecurityGroups.listAll());
      results.az_net_01 = nsgs.some(nsg => (nsg.securityRules||[]).some(r => r.direction==="Inbound"&&r.access==="Allow"&&(r.destinationPortRange==="22"||r.destinationPortRange==="*")&&(r.sourceAddressPrefix==="*"||r.sourceAddressPrefix==="0.0.0.0/0"||r.sourceAddressPrefix==="Internet"))) ? "FAIL" : "PASS";
      results.az_net_02 = nsgs.some(nsg => (nsg.securityRules||[]).some(r => r.direction==="Inbound"&&r.access==="Allow"&&(r.destinationPortRange==="3389"||r.destinationPortRange==="*")&&(r.sourceAddressPrefix==="*"||r.sourceAddressPrefix==="0.0.0.0/0"||r.sourceAddressPrefix==="Internet"))) ? "FAIL" : "PASS";
      results.az_net_03 = nsgs.length > 0 ? "PASS" : "WARN";
    }, () => { results.az_net_01 = results.az_net_01 || "ERROR"; results.az_net_02 = results.az_net_02 || "ERROR"; results.az_net_03 = "MANUAL"; });
    await safe(async () => { const w = await listAll(network.networkWatchers.listAll()); results.az_net_04 = w.length > 0 ? "PASS" : "FAIL"; }, () => { results.az_net_04 = "MANUAL"; });
    await safe(async () => { const pips = await listAll(network.publicIPAddresses.listAll()); const att = pips.filter(p => p.ipConfiguration); results.az_net_05 = att.length === 0 ? "PASS" : (att.length <= 3 ? "WARN" : "FAIL"); }, () => { results.az_net_05 = "MANUAL"; });
    await safe(async () => { const w = await listAll(network.networkWatchers.listAll()); if (w.length === 0) { results.az_net_06 = "MANUAL"; return; } const rg = w[0].id.split("/")[4]; let has = false; await safe(async () => { const fl = await listAll(network.flowLogs.list(rg, w[0].name)); has = fl.length > 0; }, null); results.az_net_06 = has ? "PASS" : "WARN"; }, () => { results.az_net_06 = "MANUAL"; });

    // ===== 5. COMPUTE (4) =====
    log.push("Compute...");
    await safe(async () => {
      const vms = await listAll(compute.virtualMachines.listAll());
      if (vms.length === 0) { ["az_vm_01","az_vm_02","az_vm_03","az_vm_04"].forEach(k => results[k] = "N/A"); return; }
      results.az_vm_01 = vms.every(v => v.storageProfile?.osDisk?.managedDisk?.securityProfile?.securityEncryptionType || v.storageProfile?.osDisk?.encryptionSettings?.enabled) ? "PASS" : "WARN";
      results.az_vm_02 = vms.every(v => v.storageProfile?.osDisk?.managedDisk) ? "PASS" : "FAIL";
      results.az_vm_03 = "MANUAL";
      results.az_vm_04 = "MANUAL";
    }, () => { ["az_vm_01","az_vm_02","az_vm_03","az_vm_04"].forEach(k => { results[k] = results[k] || "MANUAL"; }); });

    // ===== 6. DATABASE (4) =====
    log.push("SQL Databases...");
    await safe(async () => {
      const servers = await listAll(sqlMgmt.servers.list());
      if (servers.length === 0) { ["az_db_01","az_db_02","az_db_03","az_db_04"].forEach(k => results[k] = "N/A"); return; }
      let allAudit=true, allTDE=true, noAllow=true, allATP=true;
      for (const srv of servers.slice(0, 10)) {
        const rg = srv.id.split("/")[4];
        await safe(async () => { const a = await sqlMgmt.serverBlobAuditingPolicies.get(rg, srv.name); if (a.state !== "Enabled") allAudit = false; }, () => { allAudit = false; });
        await safe(async () => { const r = await listAll(sqlMgmt.firewallRules.listByServer(rg, srv.name)); if (r.some(x => x.startIpAddress === "0.0.0.0" && x.endIpAddress === "0.0.0.0")) noAllow = false; }, () => {});
        await safe(async () => { const a = await sqlMgmt.serverAdvancedThreatProtectionSettings.get(rg, srv.name); if (a.state !== "Enabled") allATP = false; }, () => { allATP = false; });
        await safe(async () => { const dbs = await listAll(sqlMgmt.databases.listByServer(rg, srv.name)); for (const db of dbs.filter(d => d.name !== "master").slice(0, 10)) { await safe(async () => { const t = await sqlMgmt.transparentDataEncryptions.get(rg, srv.name, db.name); if (t.state !== "Enabled") allTDE = false; }, () => {}); } }, () => { allTDE = false; });
      }
      results.az_db_01 = allAudit ? "PASS" : "FAIL"; results.az_db_02 = allTDE ? "PASS" : "FAIL"; results.az_db_03 = noAllow ? "PASS" : "WARN"; results.az_db_04 = allATP ? "PASS" : "FAIL";
    }, () => { ["az_db_01","az_db_02","az_db_03","az_db_04"].forEach(k => { results[k] = results[k] || "MANUAL"; }); });

    // ===== 7. KEY VAULT (3) =====
    log.push("Key Vaults...");
    await safe(async () => {
      const vaults = await listAll(kvMgmt.vaults.listBySubscription());
      if (vaults.length === 0) { results.az_kv_01 = "N/A"; results.az_kv_02 = "N/A"; results.az_kv_03 = "N/A"; return; }
      results.az_kv_01 = vaults.every(v => v.properties?.enableSoftDelete !== false) ? "PASS" : "FAIL";
      results.az_kv_02 = vaults.every(v => v.properties?.enablePurgeProtection === true) ? "PASS" : "FAIL";
      results.az_kv_03 = vaults.every(v => v.properties?.enableRbacAuthorization === true) ? "PASS" : "WARN";
    }, () => { ["az_kv_01","az_kv_02","az_kv_03"].forEach(k => { results[k] = results[k] || "MANUAL"; }); });

    // ===== 8. MONITORING (4) =====
    log.push("Monitoring...");
    await safe(async () => { const p = await listAll(monitor.logProfiles.list()); results.az_log_01 = p.length === 0 ? "FAIL" : (p.some(x => (x.retentionPolicy?.days||0) >= 365 || x.retentionPolicy?.enabled === false) ? "PASS" : "WARN"); }, () => { results.az_log_01 = "MANUAL"; });
    await safe(async () => { const ds = await listAll(monitor.diagnosticSettings.list("subscriptions/" + subscriptionId)); results.az_log_02 = ds.length > 0 ? "PASS" : "FAIL"; }, () => { results.az_log_02 = "MANUAL"; });
    await safe(async () => { const al = await listAll(monitor.activityLogAlerts.listBySubscriptionId()); results.az_log_03 = al.length > 0 ? "PASS" : "FAIL"; }, () => { results.az_log_03 = "MANUAL"; });
    await safe(async () => {
      const rgs = await listAll(resMgmt.resourceGroups.list()); let locked = 0;
      for (const rg of rgs.slice(0, 10)) { await safe(async () => { const lk = await listAll(resMgmt.managementLocks?.listAtResourceGroupLevel?.(rg.name) || []); if (lk.length > 0) locked++; }, null); }
      results.az_log_04 = rgs.length === 0 ? "N/A" : (locked > 0 ? "PASS" : "WARN");
    }, () => { results.az_log_04 = "MANUAL"; });

    // ===== 9. POLICY (2) =====
    log.push("Policy & Compliance...");
    await safe(async () => { const a = await listAll(policyClient.policyAssignments.list()); results.az_pol_01 = a.length > 0 ? "PASS" : "FAIL"; }, () => { results.az_pol_01 = "MANUAL"; });
    results.az_pol_02 = "MANUAL";

    log.push("Azure scan complete!");
    const pass = Object.values(results).filter(v => v === "PASS").length;
    const fail = Object.values(results).filter(v => v === "FAIL").length;
    return { statusCode: 200, headers, body: JSON.stringify({ success: true, provider: "azure", subscriptionId, subscriptionName: sub.displayName, tenantId, results, summary: { pass, fail, total: Object.keys(results).length, checks: 40 }, log, scannedAt: new Date().toISOString() }) };
  } catch (e) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: `Azure scan failed: ${e.message}`, results, log }) };
  }
};
