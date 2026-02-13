import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import { IAMClient, GetAccountSummaryCommand, GetAccountPasswordPolicyCommand, GenerateCredentialReportCommand, GetCredentialReportCommand, ListUsersCommand, ListUserPoliciesCommand, ListGroupsForUserCommand } from "@aws-sdk/client-iam";
import { CloudTrailClient, DescribeTrailsCommand } from "@aws-sdk/client-cloudtrail";
import { GuardDutyClient, ListDetectorsCommand } from "@aws-sdk/client-guardduty";
import { S3ControlClient, GetPublicAccessBlockCommand } from "@aws-sdk/client-s3-control";
import { S3Client, ListBucketsCommand, GetBucketEncryptionCommand, GetBucketVersioningCommand } from "@aws-sdk/client-s3";
import { EC2Client, DescribeSecurityGroupsCommand, DescribeVolumesCommand, DescribeInstancesCommand } from "@aws-sdk/client-ec2";
import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import { CloudWatchClient, DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";
import { CloudWatchLogsClient, DescribeLogGroupsCommand } from "@aws-sdk/client-cloudwatch-logs";
import { ConfigServiceClient, DescribeConfigurationRecordersCommand, DescribeConfigRulesCommand } from "@aws-sdk/client-config-service";
import { KMSClient, ListKeysCommand, DescribeKeyCommand } from "@aws-sdk/client-kms";

const headers = { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Content-Type", "Access-Control-Allow-Methods": "POST, OPTIONS" };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const safe = async (fn, fb) => { try { return await fn(); } catch { return typeof fb === "function" ? fb() : fb; } };
const mkCfg = (region, creds) => ({ region, credentials: creds });

export const handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return { statusCode: 200, headers, body: "" };
  if (event.httpMethod !== "POST") return { statusCode: 405, headers, body: JSON.stringify({ error: "Method not allowed" }) };

  const { accessKeyId, secretAccessKey, region } = JSON.parse(event.body || "{}");
  if (!accessKeyId || !secretAccessKey) return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing credentials" }) };
  const creds = { accessKeyId, secretAccessKey }; const reg = region || "us-east-1"; const results = {}; const log = [];

  try {
    log.push("Validating..."); const sts = new STSClient(mkCfg(reg, creds)); const identity = await sts.send(new GetCallerIdentityCommand({})); const account = identity.Account;

    // IAM
    log.push("IAM..."); const iam = new IAMClient(mkCfg("us-east-1", creds));
    await safe(async () => { const s = await iam.send(new GetAccountSummaryCommand({})); const m = s.SummaryMap || {}; results.iam_01 = m.AccountMFAEnabled === 1 ? "PASS" : "FAIL"; results.iam_02 = (m.AccountAccessKeysPresent || 0) === 0 ? "PASS" : "FAIL"; }, () => { results.iam_01 = "ERROR"; results.iam_02 = "ERROR"; });
    await safe(async () => { const pp = await iam.send(new GetAccountPasswordPolicyCommand({})); const p = pp.PasswordPolicy || {}; results.iam_04 = (p.MinimumPasswordLength >= 14 && p.RequireUppercaseCharacters && p.RequireLowercaseCharacters && p.RequireNumbers && p.RequireSymbols) ? "PASS" : "WARN"; }, () => { results.iam_04 = "FAIL"; });
    await safe(async () => {
      await safe(() => iam.send(new GenerateCredentialReportCommand({})), null); await sleep(5000);
      const cr = await iam.send(new GetCredentialReportCommand({})); const csv = Buffer.from(cr.Content).toString("utf-8"); const lines = csv.split("\n").filter(l => l.trim()); if (lines.length <= 1) return;
      const h = lines[0].split(","); const idx = (n) => h.indexOf(n); const rootRow = lines.find(l => l.startsWith("<root_account>")); const userRows = lines.slice(1).filter(l => !l.startsWith("<root_account>"));
      if (rootRow) { const c = rootRow.split(","); const ak1 = idx("access_key_1_active"), ak2 = idx("access_key_2_active"); if (ak1 >= 0) results.iam_02 = (c[ak1] === "false" && (ak2 < 0 || c[ak2] === "false")) ? "PASS" : "FAIL"; const pwL = idx("password_last_used"); if (pwL >= 0 && !["no_information","N/A","not_supported"].includes(c[pwL])) results.iam_03 = Math.floor((Date.now() - new Date(c[pwL]).getTime()) / 86400000) > 90 ? "PASS" : "WARN"; else results.iam_03 = "PASS"; }
      const mI = idx("mfa_active"), pE = idx("password_enabled"); if (mI >= 0 && userRows.length > 0) results.iam_05 = userRows.every(l => { const c = l.split(","); return c[mI] === "true" || c[pE] === "false"; }) ? "PASS" : "FAIL";
      let unused = false; const pLI = idx("password_last_used"); userRows.forEach(l => { const c = l.split(","); if (c[pE] === "true" && pLI >= 0 && !["N/A","no_information"].includes(c[pLI]) && Math.floor((Date.now() - new Date(c[pLI]).getTime()) / 86400000) > 90) unused = true; }); results.iam_08 = unused ? "FAIL" : "PASS";
      const a1I = idx("access_key_1_active"), a1L = idx("access_key_1_last_rotated"); let old = false; userRows.forEach(l => { const c = l.split(","); if (a1I >= 0 && c[a1I] === "true" && a1L >= 0 && c[a1L] !== "N/A" && Math.floor((Date.now() - new Date(c[a1L]).getTime()) / 86400000) > 90) old = true; }); results.iam_09 = old ? "FAIL" : "PASS";
    }, () => { if (!results.iam_03) results.iam_03 = "MANUAL"; if (!results.iam_05) results.iam_05 = "MANUAL"; results.iam_08 = results.iam_08 || "MANUAL"; results.iam_09 = results.iam_09 || "MANUAL"; });
    await safe(async () => { const u = await iam.send(new ListUsersCommand({})); let hi = false, ng = false; for (const usr of (u.Users || []).slice(0, 20)) { const ip = await iam.send(new ListUserPoliciesCommand({ UserName: usr.UserName })); if ((ip.PolicyNames || []).length > 0) hi = true; const gp = await iam.send(new ListGroupsForUserCommand({ UserName: usr.UserName })); if ((gp.Groups || []).length === 0) ng = true; } results.iam_06 = hi ? "FAIL" : "PASS"; results.iam_07 = ng ? "FAIL" : "PASS"; }, () => { results.iam_06 = results.iam_06 || "MANUAL"; results.iam_07 = results.iam_07 || "MANUAL"; });
    results.iam_10 = "MANUAL";

    // CloudTrail
    log.push("CloudTrail..."); await safe(async () => { const ct = new CloudTrailClient(mkCfg(reg, creds)); const t = (await ct.send(new DescribeTrailsCommand({}))).trailList || []; results.ct_01 = t.length > 0 && t.some(x => x.IsMultiRegionTrail) ? "PASS" : (t.length > 0 ? "WARN" : "FAIL"); results.ct_02 = t.some(x => x.LogFileValidationEnabled) ? "PASS" : "FAIL"; results.ct_03 = t.some(x => x.KmsKeyId) ? "PASS" : "FAIL"; results.ct_04 = "MANUAL"; results.ct_05 = t.some(x => x.CloudWatchLogsLogGroupArn) ? "PASS" : "FAIL"; }, () => { ["ct_01","ct_02","ct_03","ct_04","ct_05"].forEach(k => { results[k] = results[k] || "ERROR"; }); });

    // GuardDuty
    log.push("GuardDuty..."); await safe(async () => { const gd = new GuardDutyClient(mkCfg(reg, creds)); results.gd_01 = ((await gd.send(new ListDetectorsCommand({}))).DetectorIds || []).length > 0 ? "PASS" : "FAIL"; results.gd_02 = "MANUAL"; }, () => { results.gd_01 = results.gd_01 || "ERROR"; results.gd_02 = "MANUAL"; });

    // S3
    log.push("S3..."); await safe(async () => {
      const s3c = new S3ControlClient(mkCfg(reg, creds)); try { const p = await s3c.send(new GetPublicAccessBlockCommand({ AccountId: account })); const c = p.PublicAccessBlockConfiguration || {}; results.s3_05 = (c.BlockPublicAcls && c.IgnorePublicAcls && c.BlockPublicPolicy && c.RestrictPublicBuckets) ? "PASS" : "WARN"; results.s3_01 = results.s3_05 === "PASS" ? "PASS" : "MANUAL"; } catch { results.s3_05 = "FAIL"; results.s3_01 = "MANUAL"; }
      const s3 = new S3Client(mkCfg("us-east-1", creds)); try { const bk = (await s3.send(new ListBucketsCommand({}))).Buckets || []; if (bk.length === 0) { results.s3_02 = "N/A"; results.s3_03 = "N/A"; results.s3_04 = "N/A"; } else { let ae = true, av = true; for (const b of bk.slice(0, 15)) { try { await s3.send(new GetBucketEncryptionCommand({ Bucket: b.Name })); } catch { ae = false; } try { const v = await s3.send(new GetBucketVersioningCommand({ Bucket: b.Name })); if (v.Status !== "Enabled") av = false; } catch { av = false; } } results.s3_02 = ae ? "PASS" : "FAIL"; results.s3_04 = av ? "PASS" : "WARN"; results.s3_03 = "MANUAL"; } } catch { results.s3_02 = results.s3_02 || "MANUAL"; results.s3_03 = "MANUAL"; results.s3_04 = results.s3_04 || "MANUAL"; }
    }, () => { ["s3_01","s3_02","s3_03","s3_04","s3_05"].forEach(k => { results[k] = results[k] || "ERROR"; }); });

    // Config
    log.push("Config..."); await safe(async () => { const c = new ConfigServiceClient(mkCfg(reg, creds)); results.cfg_01 = ((await c.send(new DescribeConfigurationRecordersCommand({}))).ConfigurationRecorders || []).length > 0 ? "PASS" : "FAIL"; results.cfg_02 = ((await c.send(new DescribeConfigRulesCommand({}))).ConfigRules || []).length > 0 ? "PASS" : "FAIL"; }, () => { results.cfg_01 = results.cfg_01 || "ERROR"; results.cfg_02 = results.cfg_02 || "ERROR"; });

    // EC2
    log.push("EC2..."); await safe(async () => { const ec2 = new EC2Client(mkCfg(reg, creds)); const sgs = (await ec2.send(new DescribeSecurityGroupsCommand({}))).SecurityGroups || []; results.ec2_01 = sgs.some(sg => (sg.IpPermissions||[]).some(r => (r.FromPort||0)<=22&&(r.ToPort||0)>=22&&(r.IpRanges||[]).some(ip=>ip.CidrIp==="0.0.0.0/0"))) ? "FAIL" : "PASS"; results.ec2_02 = sgs.some(sg => (sg.IpPermissions||[]).some(r => (r.FromPort||0)<=3389&&(r.ToPort||0)>=3389&&(r.IpRanges||[]).some(ip=>ip.CidrIp==="0.0.0.0/0"))) ? "FAIL" : "PASS"; const def = sgs.find(sg => sg.GroupName === "default"); results.ec2_04 = def && (def.IpPermissions||[]).length === 0 ? "PASS" : "WARN"; await safe(async () => { results.ec2_03 = ((await ec2.send(new DescribeVolumesCommand({Filters:[{Name:"encrypted",Values:["false"]}]}))).Volumes||[]).length === 0 ? "PASS" : "FAIL"; }, () => { results.ec2_03 = "MANUAL"; }); await safe(async () => { const i = (await ec2.send(new DescribeInstancesCommand({}))).Reservations || []; results.ec2_05 = i.length === 0 ? "N/A" : (i.every(r => (r.Instances||[]).every(x => x.MetadataOptions?.HttpTokens === "required")) ? "PASS" : "FAIL"); }, () => { results.ec2_05 = "MANUAL"; }); }, () => { ["ec2_01","ec2_02","ec2_03","ec2_04","ec2_05"].forEach(k => { results[k] = results[k] || "ERROR"; }); });

    // RDS
    log.push("RDS..."); await safe(async () => { const rds = new RDSClient(mkCfg(reg, creds)); const d = (await rds.send(new DescribeDBInstancesCommand({}))).DBInstances || []; if (d.length === 0) { results.rds_01="N/A"; results.rds_02="N/A"; results.rds_03="N/A"; results.rds_04="N/A"; } else { results.rds_01 = d.every(x=>!x.PubliclyAccessible)?"PASS":"FAIL"; results.rds_02 = d.every(x=>x.StorageEncrypted)?"PASS":"FAIL"; results.rds_03 = d.every(x=>(x.BackupRetentionPeriod||0)>0)?"PASS":"FAIL"; results.rds_04 = d.every(x=>x.MultiAZ)?"PASS":"WARN"; } }, () => { ["rds_01","rds_02","rds_03","rds_04"].forEach(k => { results[k] = results[k] || "ERROR"; }); });

    // CloudWatch
    log.push("CloudWatch..."); await safe(async () => { const cw = new CloudWatchClient(mkCfg(reg, creds)); const al = (await cw.send(new DescribeAlarmsCommand({}))).MetricAlarms || []; const n = al.map(a => `${a.AlarmName} ${a.MetricName||""} ${a.Namespace||""}`.toLowerCase()); results.cw_01 = n.some(x=>x.includes("unauthorized")||x.includes("accessdenied"))?"PASS":"MANUAL"; results.cw_02 = n.some(x=>x.includes("root"))?"PASS":"MANUAL"; results.cw_03 = n.some(x=>x.includes("iam")&&(x.includes("policy")||x.includes("change")))?"PASS":"MANUAL"; results.cw_04 = n.some(x=>x.includes("security")&&x.includes("group"))?"PASS":"MANUAL"; }, () => { ["cw_01","cw_02","cw_03","cw_04"].forEach(k => { results[k] = results[k] || "MANUAL"; }); });
    await safe(async () => { const cwl = new CloudWatchLogsClient(mkCfg(reg, creds)); const l = (await cwl.send(new DescribeLogGroupsCommand({}))).logGroups || []; results.cw_05 = l.length > 0 && l.every(x=>(x.retentionInDays||0)>=365) ? "PASS" : (l.length===0?"MANUAL":"WARN"); }, () => { results.cw_05 = results.cw_05 || "MANUAL"; });

    // KMS
    log.push("KMS..."); await safe(async () => { const kms = new KMSClient(mkCfg(reg, creds)); const k = (await kms.send(new ListKeysCommand({}))).Keys || []; if (k.length === 0) { results.kms_01 = "N/A"; return; } let hc = false; for (const key of k.slice(0, 10)) { await safe(async () => { const d = await kms.send(new DescribeKeyCommand({ KeyId: key.KeyId })); if (d.KeyMetadata?.KeyManager === "CUSTOMER" && d.KeyMetadata?.KeyState === "Enabled") hc = true; }, null); } results.kms_01 = hc ? "MANUAL" : "PASS"; }, () => { results.kms_01 = results.kms_01 || "MANUAL"; });
    results.sso_01 = "MANUAL";

    log.push("Done!"); const pass = Object.values(results).filter(v => v === "PASS").length; const fail = Object.values(results).filter(v => v === "FAIL").length;
    return { statusCode: 200, headers, body: JSON.stringify({ success: true, account, region: reg, results, summary: { pass, fail, total: Object.keys(results).length, checks: 40 }, log, scannedAt: new Date().toISOString() }) };
  } catch (e) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: `AWS scan failed: ${e.message}`, results, log }) };
  }
};
