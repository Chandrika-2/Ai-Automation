import { ClientSecretCredential } from "@azure/identity";
import { SubscriptionClient } from "@azure/arm-subscriptions";

const headers = { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Content-Type", "Access-Control-Allow-Methods": "POST, OPTIONS" };

export const handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return { statusCode: 200, headers, body: "" };
  if (event.httpMethod !== "POST") return { statusCode: 405, headers, body: JSON.stringify({ error: "Method not allowed" }) };

  try {
    const { tenantId, clientId, clientSecret, subscriptionId } = JSON.parse(event.body || "{}");
    if (!tenantId || !clientId || !clientSecret || !subscriptionId) return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing: tenantId, clientId, clientSecret, subscriptionId" }) };

    const cred = new ClientSecretCredential(tenantId, clientId, clientSecret);
    const subClient = new SubscriptionClient(cred);
    const sub = await subClient.subscriptions.get(subscriptionId);
    return { statusCode: 200, headers, body: JSON.stringify({ success: true, subscriptionId: sub.subscriptionId, displayName: sub.displayName, state: sub.state, tenantId }) };
  } catch (e) {
    return { statusCode: 401, headers, body: JSON.stringify({ error: `Azure auth failed: ${e.message}` }) };
  }
};
