import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";

const headers = { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Content-Type", "Access-Control-Allow-Methods": "POST, OPTIONS" };

export const handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return { statusCode: 200, headers, body: "" };
  if (event.httpMethod !== "POST") return { statusCode: 405, headers, body: JSON.stringify({ error: "Method not allowed" }) };

  try {
    const { accessKeyId, secretAccessKey, region } = JSON.parse(event.body || "{}");
    if (!accessKeyId || !secretAccessKey) return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing credentials" }) };

    const sts = new STSClient({ region: region || "us-east-1", credentials: { accessKeyId, secretAccessKey } });
    const id = await sts.send(new GetCallerIdentityCommand({}));
    return { statusCode: 200, headers, body: JSON.stringify({ success: true, account: id.Account, arn: id.Arn, userId: id.UserId }) };
  } catch (e) {
    return { statusCode: 401, headers, body: JSON.stringify({ error: `Auth failed: ${e.message}` }) };
  }
};
