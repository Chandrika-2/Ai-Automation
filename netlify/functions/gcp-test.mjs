import { createSign } from "crypto";

const headers = { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Content-Type", "Access-Control-Allow-Methods": "POST, OPTIONS" };

// Generate OAuth2 token from service account credentials (JWT flow)
async function getAccessToken(clientEmail, privateKey) {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({
    iss: clientEmail,
    scope: "https://www.googleapis.com/auth/cloud-platform.read-only",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
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
  if (!resp.ok) throw new Error(data.error_description || data.error || "Token exchange failed");
  return data.access_token;
}

export const handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return { statusCode: 200, headers, body: "" };
  if (event.httpMethod !== "POST") return { statusCode: 405, headers, body: JSON.stringify({ error: "Method not allowed" }) };

  try {
    const { projectId, clientEmail, privateKey, accessToken } = JSON.parse(event.body || "{}");

    // Get token — either from OAuth access token or service account key
    let token;
    if (accessToken) {
      token = accessToken;
    } else if (clientEmail && privateKey) {
      token = await getAccessToken(clientEmail, privateKey);
    } else {
      return { statusCode: 400, headers, body: JSON.stringify({ error: "Provide accessToken OR (clientEmail + privateKey)" }) };
    }

    // MODE 1: No projectId → list all accessible projects (OAuth flow)
    if (!projectId) {
      const resp = await fetch("https://cloudresourcemanager.googleapis.com/v1/projects?filter=lifecycleState%3AACTIVE&pageSize=50", {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error?.message || "Failed to list projects");
      const projects = (data.projects || []).map(p => ({
        projectId: p.projectId,
        name: p.name,
        projectNumber: p.projectNumber,
        state: p.lifecycleState,
      }));
      return { statusCode: 200, headers, body: JSON.stringify({ success: true, mode: "list", projects }) };
    }

    // MODE 2: projectId provided → test connection to specific project
    const resp = await fetch(`https://cloudresourcemanager.googleapis.com/v1/projects/${projectId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const project = await resp.json();
    if (!resp.ok) throw new Error(project.error?.message || "Project access failed");

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        success: true,
        mode: "test",
        projectId: project.projectId,
        projectName: project.name,
        projectNumber: project.projectNumber,
        state: project.lifecycleState,
        authMethod: accessToken ? "oauth" : "service_account",
        serviceAccount: clientEmail || undefined,
      }),
    };
  } catch (e) {
    return { statusCode: 401, headers, body: JSON.stringify({ error: `GCP auth failed: ${e.message}` }) };
  }
};
