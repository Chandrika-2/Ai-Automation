import { useState, useEffect, useCallback, useMemo, useRef, createContext, useContext, Component } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from "recharts";
import * as XLSX from "xlsx";
import { GAP_CATS, GAP_QUESTIONS, MULTI_SELECT } from "./gapData.js";
import { POLICY_TEMPLATES } from "./policyData.js";
import { SOA_CONTROLS, SOA_THEMES } from "./soaData.js";
import {
  Shield, LayoutDashboard, ClipboardCheck, AlertTriangle, Server, Users,
  Bug, GraduationCap, FileSearch, Upload, ChevronRight, ChevronLeft,
  Plus, X, Download, Eye, EyeOff, Search, CheckCircle, Clock,
  XCircle, AlertCircle, Trash2, Edit3, Save, Link, FileText,
  Monitor, Wifi, Database, ArrowLeft, ArrowRight, FolderOpen,
  Target, ListChecks, Paperclip, File, Image, FileSpreadsheet, LogOut, Mail, Lock, Loader,
  RefreshCw, Calendar, ThumbsUp, ThumbsDown, Activity, Settings, Bell, Cloud, Zap, Copy, Terminal, ExternalLink, HardDrive,
  GitBranch, ShieldCheck, UserPlus, ToggleLeft, Briefcase, Flag
} from "lucide-react";

// Custom GitHub icon (lucide doesn't have one)
const GithubIcon = ({size=18,color="currentColor",...p}) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill={color} {...p}>
    <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/>
  </svg>
);

// Error Boundary to prevent blank pages
class ErrorBoundary extends Component {
  constructor(props) { super(props); this.state = { hasError: false, error: null }; }
  static getDerivedStateFromError(error) { return { hasError: true, error }; }
  componentDidCatch(error, errorInfo) { console.error("ISMS Error:", error, errorInfo); }
  render() {
    if (this.state.hasError) {
      return (<div style={{padding:40,textAlign:"center",fontFamily:"'DM Sans',sans-serif",color:"#F8FAFC",background:"#0B1120",minHeight:"100vh",display:"flex",alignItems:"center",justifyContent:"center"}}>
        <div><div style={{fontSize:48,marginBottom:16}}>⚠️</div><h2 style={{color:"#F97316",marginBottom:8}}>Something went wrong</h2><p style={{color:"#94A3B8",marginBottom:16}}>{this.state.error?.message||"An unexpected error occurred"}</p>
        <button onClick={()=>{this.setState({hasError:false,error:null});}} style={{padding:"10px 24px",background:"#F97316",color:"#fff",border:"none",borderRadius:8,cursor:"pointer",fontWeight:700,fontSize:14,fontFamily:"inherit"}}>Try Again</button>
        <button onClick={()=>{window.location.reload();}} style={{padding:"10px 24px",background:"transparent",color:"#EF4444",border:"1px solid #EF4444",borderRadius:8,cursor:"pointer",fontWeight:700,fontSize:14,fontFamily:"inherit",marginLeft:8}}>Reset & Reload</button>
        </div></div>);
    }
    return this.props.children;
  }
}

// =============================================
// SUPABASE CONFIG — loaded from environment variables [PATCH V3/V10]
// =============================================
const SUPA_URL = (import.meta.env.VITE_SUPABASE_URL || "").replace(/\/+$/, "");
const SUPA_KEY = import.meta.env.VITE_SUPABASE_ANON_KEY || "";
const ENV_READY = !!(SUPA_URL && SUPA_KEY && SUPA_URL.startsWith("https://"));

if (!ENV_READY) {
  console.error(
    "⚠️ Missing or invalid environment variables!\n" +
    "Create a .env file in your project root with:\n\n" +
    "  VITE_SUPABASE_URL=https://your-project.supabase.co\n" +
    "  VITE_SUPABASE_ANON_KEY=your-anon-key\n" +
    "  VITE_SUPER_ADMIN_EMAIL=admin@yourcompany.com\n\n" +
    "Then restart the dev server (npm run dev)."
  );
}

const AuthCtx = createContext(null);
const useAuth = () => useContext(AuthCtx); // returns {user, token, orgId}
const RoleCtx = createContext({role:"client_employee",org:null,can:(mod,action)=>false});

// =============================================
// SUPABASE API HELPERS
// =============================================
const safeFetch = async (url, options = {}) => {
  if (!ENV_READY) throw new Error("Supabase not configured. Create a .env file with VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY, then restart the dev server.");
  try { return await fetch(url, options); }
  catch (e) {
    if (e.message === "Failed to fetch" || e.name === "TypeError") {
      throw new Error("Cannot connect to server. This may be due to:\n• Browser security restrictions (try opening the app in a new tab)\n• Supabase project may be paused (check your Supabase dashboard)\n• Network connectivity issue");
    }
    throw e;
  }
};

// [PATCH V13] Client-side rate limiting for auth
const authRateLimit = { attempts: 0, lastReset: Date.now(), lockUntil: 0 };
const AUTH_MAX_ATTEMPTS = 5;
const AUTH_WINDOW_MS = 60000; // 1 minute
const AUTH_LOCKOUT_MS = 300000; // 5 minute lockout

const checkAuthRateLimit = () => {
  const now = Date.now();
  if (now < authRateLimit.lockUntil) {
    const remaining = Math.ceil((authRateLimit.lockUntil - now) / 1000);
    throw new Error(`Too many login attempts. Please wait ${remaining} seconds.`);
  }
  if (now - authRateLimit.lastReset > AUTH_WINDOW_MS) {
    authRateLimit.attempts = 0;
    authRateLimit.lastReset = now;
  }
  authRateLimit.attempts++;
  if (authRateLimit.attempts > AUTH_MAX_ATTEMPTS) {
    authRateLimit.lockUntil = now + AUTH_LOCKOUT_MS;
    throw new Error("Too many login attempts. Account locked for 5 minutes.");
  }
};

const supaAuth = async (path, body) => {
  checkAuthRateLimit(); // [PATCH V13]
  const r = await safeFetch(`${SUPA_URL}/auth/v1/${path}`, {
    method: "POST", headers: { "Content-Type": "application/json", "apikey": SUPA_KEY }, body: JSON.stringify(body),
  });
  const data = await r.json();
  // [PATCH V14] Sanitize error messages — don't leak internal details
  if (!r.ok && !data.access_token) throw new Error("Invalid email or password. Please try again.");
  return data;
};

const supaDB = async (token, method, query = "", body = null, headers = {}) => {
  const h = { "apikey": SUPA_KEY, "Authorization": `Bearer ${token}`, "Content-Type": "application/json", ...headers };
  const opts = { method, headers: h };
  if (body) opts.body = JSON.stringify(body);
  const r = await safeFetch(`${SUPA_URL}/rest/v1/isms_state${query}`, opts);
  if (r.status === 204 || r.status === 201) return null;
  const data = await r.json();
  if (!r.ok) { console.warn("DB error:", data); return []; } // [PATCH V14] errors logged, not exposed
  return data;
};

// [PATCH V9] File upload validation
const ALLOWED_FILE_TYPES = new Set([
  "pdf","doc","docx","xls","xlsx","csv","ppt","pptx","ppsx",
  "txt","md","json","xml","yaml","yml","log","html","css",
  "png","jpg","jpeg","gif","webp","svg","bmp",
  "mp4","webm","mov","mp3","wav","ogg","aac","m4a",
  "zip","rar","7z"
]);
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50 MB

const validateFile = (file) => {
  const ext = (file.name || "").split(".").pop().toLowerCase();
  if (!ALLOWED_FILE_TYPES.has(ext)) {
    throw new Error(`File type .${ext} is not allowed. Permitted types: ${[...ALLOWED_FILE_TYPES].join(", ")}`);
  }
  if (file.size > MAX_FILE_SIZE) {
    throw new Error(`File too large (${(file.size / 1024 / 1024).toFixed(1)} MB). Maximum: ${MAX_FILE_SIZE / 1024 / 1024} MB.`);
  }
  return true;
};

const uploadToStorage = async (token, scopeId, module, file) => {
  validateFile(file); // [PATCH V9] Validate extension before upload

  // [SEC-4] Verify actual content matches claimed type via magic bytes
  const detectedMime = await detectMimeType(file);
  const ext = (file.name || "").split(".").pop().toLowerCase();
  const dangerousMismatch = (
    (detectedMime.includes("html") && !["html","htm"].includes(ext)) ||
    (detectedMime.includes("javascript") && !["js"].includes(ext))
  );
  if (dangerousMismatch) {
    throw new Error("File content does not match its extension. Upload rejected for security.");
  }

  const safe = file.name.replace(/[^a-zA-Z0-9._-]/g, "_");
  const path = `${scopeId}/${module}/${Date.now()}_${safe}`;
  const r = await safeFetch(`${SUPA_URL}/storage/v1/object/isms-files/${path}`, {
    method: "POST",
    headers: { "apikey": SUPA_KEY, "Authorization": `Bearer ${token}`, "Content-Type": file.type || "application/octet-stream", "x-upsert": "false" },
    body: file,
  });
  if (!r.ok) { throw new Error("File upload failed. Please try again."); }
  const signedUrl = await getSignedUrl(token, path, 86400);

  // [SEC-2] Audit log file upload
  await auditLog(token, "file_upload", { resource_type: "file", resource_id: path, org_id: scopeId, file_name: file.name, file_size: file.size, module }, "info");

  return { name: file.name, url: signedUrl || "", path, type: ext };
};

// [PATCH V5] Generate signed URL for private file access
const getSignedUrl = async (token, filePath, expiresIn = 3600) => {
  const r = await safeFetch(`${SUPA_URL}/storage/v1/object/sign/isms-files/${filePath}`, {
    method: "POST",
    headers: { "apikey": SUPA_KEY, "Authorization": `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ expiresIn }),
  });
  if (!r.ok) return null;
  const data = await r.json();
  return data.signedURL ? `${SUPA_URL}/storage/v1${data.signedURL}` : null;
};


// =============================================
// TRAINING SLIDES
// =============================================
// (Training content is now user-uploaded, no hardcoded slides)

// =============================================
// WORKFLOW CHECK — ISO 27001 Mandatory Clauses
// =============================================
const WORKFLOW_CONTROLS = [
  {id:"mgmt_review",name:"Management Review",isoRef:"Clause 9.3",icon:"👥",desc:"Top management reviews ISMS at planned intervals for suitability, adequacy, and effectiveness.",defaultFreq:"Semi-Annual",weight:20,
    evidenceHints:["Management Review Meeting minutes","Attendance sheet","Action items tracker","Review inputs/outputs document","Continual improvement decisions"]},
  {id:"internal_audit",name:"Internal Audit",isoRef:"Clause 9.2",icon:"🔍",desc:"Planned internal audits to verify ISMS conformity and effective implementation.",defaultFreq:"Annual",weight:20,
    evidenceHints:["Audit plan & schedule","NC report","Audit report","Corrective action log","Auditor competence records"]},
  {id:"awareness",name:"Awareness & Training",isoRef:"Clause 7.2 / 7.3",icon:"🎓",desc:"Ensure personnel are competent and aware of the ISMS policy and their contribution.",defaultFreq:"Quarterly",weight:15,
    evidenceHints:["Training attendance register","Training material / PPT","Competence assessment results","Awareness quiz results","Training calendar"]},
  {id:"vendor_risk",name:"Vendor Risk Assessment",isoRef:"A.5.19–A.5.23",icon:"🤝",desc:"Assess and monitor security risks of third-party suppliers and service providers.",defaultFreq:"Annual",weight:15,
    evidenceHints:["Vendor risk register","Security questionnaire responses","Vendor SOC2 / ISO certificates","Vendor assessment report","Contract security clauses"]},
  {id:"vapt_review",name:"VAPT",isoRef:"A.8.8",icon:"🛡️",desc:"Periodic vulnerability assessments and penetration testing of infrastructure and applications.",defaultFreq:"Semi-Annual",weight:15,
    evidenceHints:["VAPT report","Vulnerability scan results","Remediation tracker","Retest evidence","Scope document"]},
  {id:"policy_review",name:"Policies Review",isoRef:"Clause 7.5 / A.5.1",icon:"📋",desc:"Regular review and update of information security policies to ensure continued relevance.",defaultFreq:"Annual",weight:15,
    evidenceHints:["Policy review minutes","Updated policy documents","Version comparison / changelog","Approval sign-off","Distribution records"]},
];

const FREQ_OPTIONS = ["Monthly","Quarterly","Semi-Annual","Annual"];
const freqDays = {Monthly:30,Quarterly:90,"Semi-Annual":182,Annual:365};

const calcNextDue = (lastDate, freq) => {
  if(!lastDate) return null;
  const d = new Date(lastDate);
  d.setDate(d.getDate() + (freqDays[freq]||365));
  return d.toISOString().slice(0,10);
};

const isOverdue = (dueDate) => {
  if(!dueDate) return true;
  return new Date(dueDate) < new Date();
};

const daysUntilDue = (dueDate) => {
  if(!dueDate) return -999;
  return Math.ceil((new Date(dueDate) - new Date()) / 86400000);
};

// =============================================
// RBAC — Roles, Permissions, Helpers
// =============================================
const ROLES = {
  super_admin:     {label:"Super Admin",     desc:"Full platform access, manage all users & clients",  level:0,badge:"🔑",color:"#ef4444",type:"seccomply"},
  employee:        {label:"Employee",        desc:"Manage clients, approve/reject, full client access", level:1,badge:"👨‍💼",color:"#3b82f6",type:"seccomply"},
  client_admin:    {label:"Client Admin",    desc:"Manage own org, add users & employees, view all",   level:2,badge:"🏢",color:"#f97316",type:"client"},
  client_user:     {label:"Client User",     desc:"Upload evidence, manage risks, add employees",      level:3,badge:"👤",color:"#22c55e",type:"client"},
  client_employee: {label:"Client Employee", desc:"Training access only",                              level:4,badge:"🎓",color:"#8b5cf6",type:"client"},
};

// What each role can DO on each module
const PERMS = {
  admin_panel:{super_admin:["view","create","edit","delete"],employee:["view","create"],client_admin:["view","create"],client_user:["view","create"],client_employee:[]},
  dashboard:  {super_admin:["view"],employee:["view"],client_admin:["view"],client_user:["view"],client_employee:[]},
  soa:        {super_admin:["view","create","edit","delete"],employee:["view","create","edit","delete"],client_admin:["view","create","edit"],client_user:["view","create","edit"],client_employee:[]},
  gap:        {super_admin:["view","create","edit","delete","approve"],employee:["view","create","edit","delete","approve"],client_admin:["view","create","edit"],client_user:["view","create","edit"],client_employee:[]},
  workflow:   {super_admin:["view","edit","approve","upload","delete"],employee:["view","edit","approve","upload","delete"],client_admin:["view","edit","upload"],client_user:["view","edit","upload"],client_employee:[]},
  risk:       {super_admin:["view","create","edit","delete"],employee:["view","create","edit","delete"],client_admin:["view","create","edit"],client_user:["view","create","edit"],client_employee:[]},
  assets:     {super_admin:["view","create","edit","delete"],employee:["view","create","edit","delete"],client_admin:["view","create","edit"],client_user:["view","create","edit"],client_employee:[]},
  policies:   {super_admin:["view","create","edit","delete"],employee:["view","create","edit","delete"],client_admin:["view","create","edit","upload"],client_user:["view","create","edit","upload"],client_employee:[]},
  evidence:   {super_admin:["view","create","edit","delete","approve"],employee:["view","create","edit","delete","approve"],client_admin:["view","create","edit","upload"],client_user:["view","create","edit","upload"],client_employee:[]},
  roles:      {super_admin:["view","create","edit","delete"],employee:["view","create","edit"],client_admin:["view","create","edit"],client_user:["view","create","edit"],client_employee:[]},
  vapt:       {super_admin:["view","create","edit","delete"],employee:["view","create","edit","delete"],client_admin:["view","create","edit"],client_user:["view","create","edit"],client_employee:[]},
  training:   {super_admin:["view","create","edit","delete"],employee:["view","create","edit","delete"],client_admin:["view","create","edit"],client_user:["view","create","edit"],client_employee:["view"]},
  cloud:      {super_admin:["view","create","edit","delete"],employee:["view","create","edit","delete"],client_admin:["view","create","edit"],client_user:["view"],client_employee:[]},
  github:     {super_admin:["view","create","edit","delete"],employee:["view","create","edit","delete"],client_admin:["view","create","edit"],client_user:["view"],client_employee:[]},
  vendors:    {super_admin:["view","create","edit","delete"],employee:["view","create","edit","delete"],client_admin:["view","create","edit"],client_user:["view","create","edit"],client_employee:[]},
};

const hasPerm = (role, mod, action) => (PERMS[mod]?.[role]||[]).includes(action);
const canView = (role, mod) => hasPerm(role, mod, "view");
const canEdit = (role, mod) => hasPerm(role, mod, "edit")||hasPerm(role, mod, "create");
const canApprove = (role, mod) => hasPerm(role, mod, "approve");
const canDelete = (role, mod) => hasPerm(role, mod, "delete");
const isSecComply = (role) => ["super_admin","employee"].includes(role);
const isClientRole = (role) => ["client_admin","client_user","client_employee"].includes(role);

// Who can create which roles
const CAN_CREATE = {
  super_admin: ["super_admin","employee","client_admin"],
  employee:    ["client_admin"],
  client_admin:["client_user","client_employee"],
  client_user: ["client_employee"],
  client_employee:[],
};

const RBAC_KEY = "_rbac_directory_";
const SUPER_ADMIN_EMAIL = (import.meta.env.VITE_SUPER_ADMIN_EMAIL || "").toLowerCase().trim(); // [PATCH V10]

// Generate secure password using crypto API [PATCH V4]
const genPassword = () => {
  const chars = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789!@#$%&*";
  const array = new Uint32Array(14);
  crypto.getRandomValues(array);
  let pw = "";
  for (let i = 0; i < 14; i++) pw += chars[array[i] % chars.length];
  return pw;
};

// Secure ID generation [PATCH V11]
const secureId = (prefix = "") => `${prefix}${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`;

// [PATCH V17] Input sanitization — prevent script injection in stored data
const sanitizeInput = (str) => {
  if (typeof str !== "string") return str;
  return str
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/javascript:/gi, "")
    .replace(/on\w+\s*=/gi, "")
    .trim()
    .slice(0, 5000); // Max input length
};

// =============================================
// NEW SECURITY FEATURES
// =============================================

// [SEC-1] Password complexity validator
const PASSWORD_RULES = {
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumber: true,
  requireSpecial: true,
};

const validatePasswordComplexity = (pw) => {
  const errors = [];
  if (!pw || pw.length < PASSWORD_RULES.minLength) errors.push(`At least ${PASSWORD_RULES.minLength} characters`);
  if (PASSWORD_RULES.requireUppercase && !/[A-Z]/.test(pw)) errors.push("At least one uppercase letter");
  if (PASSWORD_RULES.requireLowercase && !/[a-z]/.test(pw)) errors.push("At least one lowercase letter");
  if (PASSWORD_RULES.requireNumber && !/[0-9]/.test(pw)) errors.push("At least one number");
  if (PASSWORD_RULES.requireSpecial && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(pw)) errors.push("At least one special character");
  // Common password patterns
  if (/^(.)\1+$/.test(pw)) errors.push("Cannot be all the same character");
  if (/^(012|123|234|345|456|567|678|789|abc|bcd|cde|def)/i.test(pw)) errors.push("Cannot be a sequential pattern");
  return { valid: errors.length === 0, errors };
};

// [SEC-2] Audit logger — sends audit events to Supabase
const auditLog = async (token, action, details = {}, severity = "info") => {
  if (!token || !ENV_READY) return;
  try {
    await safeFetch(`${SUPA_URL}/rest/v1/rpc/log_audit_event`, {
      method: "POST",
      headers: { "apikey": SUPA_KEY, "Authorization": `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        p_action: action,
        p_resource_type: details.resource_type || null,
        p_resource_id: details.resource_id || null,
        p_org_id: details.org_id || null,
        p_details: details,
        p_severity: severity,
      }),
    });
  } catch (e) { console.warn("Audit log failed:", e.message); }
};

// [SEC-3] Data integrity — SHA-256 checksum for stored data
const computeChecksum = async (data) => {
  try {
    const text = JSON.stringify(data);
    const buffer = new TextEncoder().encode(text);
    const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
  } catch { return null; }
};

// [SEC-4] Content-type detection via magic bytes (file header)
const MAGIC_BYTES = {
  "25504446": "application/pdf",      // %PDF
  "504b0304": "application/zip",       // PK.. (zip/docx/xlsx/pptx)
  "d0cf11e0": "application/msword",    // OLE compound (doc/xls/ppt)
  "89504e47": "image/png",             // .PNG
  "ffd8ffe0": "image/jpeg",            // JFIF
  "ffd8ffe1": "image/jpeg",            // EXIF
  "47494638": "image/gif",             // GIF8
  "52494646": "audio/wav",             // RIFF (wav)
};

const detectMimeType = async (file) => {
  return new Promise((resolve) => {
    const reader = new FileReader();
    reader.onload = () => {
      const arr = new Uint8Array(reader.result).slice(0, 4);
      const hex = Array.from(arr).map(b => b.toString(16).padStart(2, "0")).join("");
      resolve(MAGIC_BYTES[hex] || file.type || "application/octet-stream");
    };
    reader.onerror = () => resolve(file.type || "application/octet-stream");
    reader.readAsArrayBuffer(file.slice(0, 4));
  });
};

// [SEC-5] Session idle timeout constants
const SESSION_IDLE_TIMEOUT = 30 * 60 * 1000;   // 30 minutes
const SESSION_WARNING_BEFORE = 5 * 60 * 1000;  // Warn 5 min before
const SESSION_MAX_DURATION = 8 * 60 * 60 * 1000; // 8 hour max session

// [SEC-6] Export watermarking — adds user/timestamp to exported data
const addExportWatermark = (rows, userEmail, orgName) => {
  const ts = new Date().toISOString().replace("T", " ").slice(0, 19);
  return [
    { "⚠️ CONFIDENTIAL": `Exported by ${userEmail} on ${ts} | Organization: ${orgName} | SecComply` },
    ...rows,
    { "⚠️ CONFIDENTIAL": `End of export — ${rows.length} records | This document contains sensitive compliance data` },
  ];
};

// [SEC-7] Secure server-side logout
const serverLogout = async (token) => {
  if (!token || !ENV_READY) return;
  try {
    await safeFetch(`${SUPA_URL}/auth/v1/logout`, {
      method: "POST",
      headers: { "apikey": SUPA_KEY, "Authorization": `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
  } catch (e) { console.warn("Server logout failed:", e.message); }
};

// [SEC-8] Session fingerprint (basic — browser + screen)
const getSessionFingerprint = () => {
  try {
    const parts = [
      navigator.userAgent,
      navigator.language,
      screen.width + "x" + screen.height,
      Intl.DateTimeFormat().resolvedOptions().timeZone,
    ];
    return parts.join("|");
  } catch { return "unknown"; }
};

// Create user via Supabase Auth API (no Edge Function needed)
const createAuthUser = async(token, email, password, name, role, orgId) => {
  const pwCheck = validatePasswordComplexity(password);
  if (!pwCheck.valid) throw new Error("Password requirements:\n• " + pwCheck.errors.join("\n• "));
  if (!email || !name || !role) throw new Error("All fields are required");

  const cleanEmail = email.toLowerCase().trim();

  // Step 1: Create auth user via Supabase signup endpoint
  const r = await safeFetch(`${SUPA_URL}/auth/v1/signup`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "apikey": SUPA_KEY,
    },
    body: JSON.stringify({
      email: cleanEmail,
      password,
      data: { name: name.trim(), role },
      gotrue_meta_security: { captcha_token: "" },
    }),
  });
  const d = await r.json().catch(()=>({}));
  if (!r.ok) {
    const msg = d.msg || d.error_description || d.error || "";
    if(msg.includes("already been registered")||msg.includes("already registered")) throw new Error("This email is already registered. Use a different email.");
    throw new Error(msg || `Account creation failed (HTTP ${r.status})`);
  }

  const userId = d.id || d.user?.id;
  if(!userId) throw new Error("Account created but no user ID returned. Check Supabase Auth settings.");

  // Step 2: Insert into user_org_roles
  const roleRes = await safeFetch(`${SUPA_URL}/rest/v1/user_org_roles`, {
    method: "POST",
    headers: {
      "apikey": SUPA_KEY,
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/json",
      "Prefer": "return=minimal",
    },
    body: JSON.stringify({
      user_id: userId,
      email: cleanEmail,
      name: name.trim(),
      role,
      org_id: ["super_admin","employee"].includes(role) ? null : orgId,
      created_by: "platform",
      status: "active",
      must_change_password: true,
    }),
  });
  if(!roleRes.ok) console.warn("Role insert failed — user created but role not assigned. They can still log in.");

  await auditLog(token, "create_user", { resource_type: "user", resource_id: userId, org_id: orgId, email: cleanEmail, role }, "critical");

  return { id: userId, email: cleanEmail };
};

// Create employee via Netlify function (Admin API) — NO email invite sent
const createEmployeeNoEmail = async(token, email, password, name, role, orgId) => {
  const pwCheck = validatePasswordComplexity(password);
  if (!pwCheck.valid) throw new Error("Password requirements:\n• " + pwCheck.errors.join("\n• "));
  if (!email || !name || !role) throw new Error("All fields are required");

  const cleanEmail = email.toLowerCase().trim();

  // Call Netlify function which uses Supabase Admin API (no invite email)
  const res = await safeFetch("/api/create-employee", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: cleanEmail, password, name: name.trim(), role, orgId, callerToken: token }),
  });

  const d = await res.json().catch(()=>({}));
  if (!res.ok) {
    throw new Error(d.error || `Account creation failed (HTTP ${res.status})`);
  }

  const userId = d.id;
  if (!userId) throw new Error("Account created but no user ID returned.");

  await auditLog(token, "create_user", { resource_type: "user", resource_id: userId, org_id: orgId, email: cleanEmail, role }, "critical");

  return { id: userId, email: cleanEmail };
};

const loadRbac = async(token) => {
  try {
    const rows = await supaDB(token,"GET",`?user_id=eq.${RBAC_KEY}&select=state`);
    if(rows&&Array.isArray(rows)&&rows.length>0&&rows[0].state) return rows[0].state;
  } catch(e){ console.warn("RBAC load:",e); }
  return null;
};

const saveRbac = async(token, rbac) => {
  await safeFetch(`${SUPA_URL}/rest/v1/isms_state`,{
    method:"POST",
    headers:{"apikey":SUPA_KEY,"Authorization":`Bearer ${token}`,"Content-Type":"application/json","Prefer":"resolution=merge-duplicates"},
    body:JSON.stringify({user_id:RBAC_KEY,state:rbac,updated_at:new Date().toISOString()}),
  });
};

const loadOrgData = async(token, orgId) => {
  try {
    const rows = await supaDB(token,"GET",`?user_id=eq.org_${orgId}&select=state`);
    if(rows&&Array.isArray(rows)&&rows.length>0&&rows[0].state) return rows[0].state;
  } catch(e){ console.warn("Org data load:",e); }
  return null;
};

const saveOrgData = async(token, orgId, data) => {
  await safeFetch(`${SUPA_URL}/rest/v1/isms_state`,{
    method:"POST",
    headers:{"apikey":SUPA_KEY,"Authorization":`Bearer ${token}`,"Content-Type":"application/json","Prefer":"resolution=merge-duplicates"},
    body:JSON.stringify({user_id:`org_${orgId}`,state:data,updated_at:new Date().toISOString()}),
  });
};

// =============================================
// INITIAL DATA (v7 — with workflow)
// =============================================
const getInitialData = () => ({
  gapResponses: {},
  workflowConfig: Object.fromEntries(WORKFLOW_CONTROLS.map(c=>[c.id,{frequency:c.defaultFreq}])),
  workflowRecords: [],
  risks:[], assets:[], roles:[], raci:[], vapt:[], audits:[], policies:[], policySettings:{companyName:"",logoDataUrl:"",headerRightText:""}, soaApplicability:{}, evidenceList:[], trainings:[], trainingCompletions:[],
  cloudScans:[],
  githubScans:[],
  vendors:[],
  soaSheets:null, soaFileName:"", soaSheetNames:[],
  soaFileRef:null, vaptFileRef:null,
});

// =============================================
// THEME
// =============================================
const C = {
  bg:"#0B1120", sidebar:"#0F172A", card:"#1E293B", cardHover:"#334155",
  border:"#334155", orange:"#F97316", orangeHover:"#FB923C", orangeDark:"#C2410C",
  text:"#F8FAFC", textMuted:"#94A3B8", textDim:"#64748B",
  green:"#22C55E", yellow:"#EAB308", red:"#EF4444", blue:"#3B82F6",
  greenBg:"#052E16", yellowBg:"#422006", redBg:"#450A0A", blueBg:"#172554",
};

// =============================================
// EXCEL PARSE HELPER
// =============================================
const parseExcelToSheets = async (file) => {
  const buf = await new Promise(r => { const rd = new FileReader(); rd.onload = () => r(rd.result); rd.readAsArrayBuffer(file); });
  const wb = XLSX.read(buf, { type: "array" });
  const all = {};
  wb.SheetNames.forEach(n => { all[n] = XLSX.utils.sheet_to_json(wb.Sheets[n], { defval: "" }); });
  return { sheetNames: wb.SheetNames, allSheets: all };
};

// =============================================
// SHARED UI COMPONENTS
// =============================================
const Logo = () => (<div style={{display:"flex",alignItems:"center",gap:8}}><Shield size={28} color={C.orange} fill={C.orange} strokeWidth={1.5}/><span style={{fontSize:20,fontWeight:800,color:"#fff"}}>Sec<span style={{color:C.orange}}>Comply</span></span></div>);

const Btn = ({children,onClick,variant="primary",size="md",disabled,style:s,...p}) => {
  const base = {border:"none",borderRadius:8,cursor:disabled?"not-allowed":"pointer",fontWeight:600,display:"inline-flex",alignItems:"center",gap:6,transition:"all 0.2s",opacity:disabled?0.5:1,fontFamily:"inherit"};
  const sizes = {sm:{padding:"6px 12px",fontSize:12},md:{padding:"8px 16px",fontSize:13},lg:{padding:"12px 24px",fontSize:15}};
  const vars = {primary:{background:C.orange,color:"#fff"},secondary:{background:C.card,color:C.text,border:`1px solid ${C.border}`},danger:{background:C.red,color:"#fff"},ghost:{background:"transparent",color:C.textMuted},success:{background:C.green,color:"#fff"}};
  return <button onClick={onClick} disabled={disabled} style={{...base,...sizes[size],...vars[variant],...s}} {...p}>{children}</button>;
};

const Input = ({label,value,onChange,type="text",placeholder,textarea,style:s,select,options,...p}) => (
  <div style={{marginBottom:12,...s}}>
    {label && <label style={{display:"block",fontSize:12,color:C.textMuted,marginBottom:4,fontWeight:600}}>{label}</label>}
    {select ? <select value={value} onChange={e=>onChange(e.target.value)} style={{width:"100%",padding:"8px 12px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,color:C.text,fontSize:13,fontFamily:"inherit"}} {...p}>{options.map(o=><option key={typeof o==="string"?o:o.value} value={typeof o==="string"?o:o.value}>{typeof o==="string"?o:o.label}</option>)}</select>
    : textarea ? <textarea value={value} onChange={e=>onChange(e.target.value)} placeholder={placeholder} rows={3} style={{width:"100%",padding:"8px 12px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,color:C.text,fontSize:13,resize:"vertical",fontFamily:"inherit"}} {...p}/>
    : <input type={type} value={value} onChange={e=>onChange(e.target.value)} placeholder={placeholder} style={{width:"100%",padding:"8px 12px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,color:C.text,fontSize:13,fontFamily:"inherit"}} {...p}/>}
  </div>
);

const Badge = ({children,color=C.textMuted,bg}) => (<span style={{display:"inline-block",padding:"3px 10px",borderRadius:20,fontSize:11,fontWeight:700,color,background:bg||`${color}22`,whiteSpace:"nowrap"}}>{children}</span>);
const Card = ({children,style:s,title,action,...p}) => (<div style={{background:C.card,borderRadius:12,border:`1px solid ${C.border}`,padding:20,...s}} {...p}>{(title||action)&&<div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:16}}>{title&&<h3 style={{margin:0,fontSize:16,fontWeight:700,color:C.text}}>{title}</h3>}{action}</div>}{children}</div>);
const Modal = ({open,onClose,title,children,wide}) => {
  if(!open) return null;
  return (<div style={{position:"fixed",inset:0,zIndex:1000,display:"flex",alignItems:"center",justifyContent:"center",background:"rgba(0,0,0,0.7)",backdropFilter:"blur(4px)"}} onClick={onClose}><div onClick={e=>e.stopPropagation()} style={{background:C.sidebar,borderRadius:16,border:`1px solid ${C.border}`,padding:24,width:wide?900:500,maxWidth:"95vw",maxHeight:"90vh",overflowY:"auto"}}><div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20}}><h2 style={{margin:0,fontSize:18,fontWeight:700,color:C.text}}>{title}</h2><button onClick={onClose} style={{background:"none",border:"none",cursor:"pointer",color:C.textMuted}}><X size={20}/></button></div>{children}</div></div>);
};
const Stat = ({label,value,icon:Icon,color=C.orange}) => (<div style={{background:C.card,borderRadius:12,border:`1px solid ${C.border}`,padding:20,flex:1,minWidth:180}}><div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}><div><div style={{fontSize:12,color:C.textMuted,fontWeight:600,marginBottom:4}}>{label}</div><div style={{fontSize:28,fontWeight:800,color}}>{value}</div></div>{Icon&&<div style={{padding:10,borderRadius:10,background:`${color}15`}}><Icon size={22} color={color}/></div>}</div></div>);
const Empty = ({msg="No data yet",action,onAction}) => (<div style={{textAlign:"center",padding:40,color:C.textDim}}><FileText size={40} style={{marginBottom:8,opacity:0.3}}/><div style={{marginBottom:action?12:0}}>{msg}</div>{action&&<Btn onClick={onAction} size="sm"><Plus size={14}/> {action}</Btn>}</div>);
const Toast = ({msg,type="success",onClose}) => {
  useEffect(()=>{const t=setTimeout(onClose,3000);return()=>clearTimeout(t);},[]);
  const colors = {success:C.green,error:C.red,info:C.blue};
  return (<div style={{position:"fixed",top:20,right:20,zIndex:2000,background:C.sidebar,border:`1px solid ${colors[type]}`,borderRadius:12,padding:"12px 20px",color:C.text,fontSize:13,fontWeight:600,boxShadow:`0 4px 20px ${colors[type]}33`,display:"flex",alignItems:"center",gap:8}}>{type==="success"?<CheckCircle size={16} color={C.green}/>:type==="error"?<XCircle size={16} color={C.red}/>:<AlertCircle size={16} color={C.blue}/>}{msg}</div>);
};
const FileUploadBtn = ({onFile,accept,label="Upload File",variant="primary",size="md"}) => {
  const ref = useRef();
  return (<><input ref={ref} type="file" accept={accept} style={{display:"none"}} onChange={async(e)=>{const f=e.target.files[0];if(f){await onFile(f);e.target.value="";}}} /><Btn variant={variant} size={size} onClick={()=>ref.current.click()}><Upload size={14}/> {label}</Btn></>);
};
const InlineUpload = ({onUpload,label}) => {
  const ref = useRef();
  return <><input ref={ref} type="file" style={{display:"none"}} onChange={async(e)=>{const f=e.target.files[0];if(f){await onUpload(f);e.target.value="";}}} /><button onClick={()=>ref.current.click()} style={{background:`${C.orange}22`,border:`1px solid ${C.orange}44`,borderRadius:6,cursor:"pointer",padding:"3px 8px",color:C.orange,fontSize:11,fontWeight:600,display:"flex",alignItems:"center",gap:4,fontFamily:"inherit"}}><Upload size={10}/> {label||"Upload"}</button></>;
};
const DataTable = ({rows,maxH=500}) => {
  if(!rows||rows.length===0) return <div style={{padding:20,color:C.textDim,textAlign:"center"}}>No data</div>;
  const cols = Object.keys(rows[0]);
  return (<div style={{overflow:"auto",maxHeight:maxH}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}><thead><tr style={{background:C.bg,position:"sticky",top:0,zIndex:1}}>{cols.map(c=><th key={c} style={{padding:"8px 10px",textAlign:"left",color:C.orange,fontWeight:700,fontSize:11,textTransform:"uppercase",borderBottom:`2px solid ${C.border}`,whiteSpace:"nowrap"}}>{c}</th>)}</tr></thead><tbody>{rows.map((r,i)=><tr key={i} style={{borderBottom:`1px solid ${C.border}22`}}>{cols.map(c=><td key={c} style={{padding:"7px 10px",color:C.text,maxWidth:300,overflow:"hidden",textOverflow:"ellipsis"}}>{String(r[c]??"")}</td>)}</tr>)}</tbody></table></div>);
};
const FilePreviewModal = ({file,onClose}) => {
  if(!file) return null;
  const ext = (file.type||file.name?.split(".").pop()||"").toLowerCase();
  const isImg = ["png","jpg","jpeg","gif","webp","svg","bmp"].includes(ext);
  const isPdf = ext==="pdf";
  const isOffice = ["pptx","ppt","docx","doc","xlsx","xls","ppsx"].includes(ext);
  const isVideo = ["mp4","webm","mov","ogg"].includes(ext);
  const isAudio = ["mp3","wav","ogg","aac","m4a"].includes(ext);
  const isTxt = ["txt","md","csv","json","xml","yaml","yml","log","html","css","js","py","sql","sh"].includes(ext);
  const officeUrl = isOffice && file.url ? `https://view.officeapps.live.com/op/embed.aspx?src=${encodeURIComponent(file.url)}` : null;
  const gDocsUrl = isOffice && file.url ? `https://docs.google.com/gview?url=${encodeURIComponent(file.url)}&embedded=true` : null;
  const [viewerMode,setViewerMode]=useState("ms"); // ms | google | download
  const [txtContent,setTxtContent]=useState(null);
  const [loading,setLoading]=useState(isOffice||isTxt);

  useEffect(()=>{
    if(isTxt && file.url) {
      fetch(file.url).then(r=>r.text()).then(t=>{setTxtContent(t);setLoading(false);}).catch(()=>{setTxtContent(null);setLoading(false);});
    }
  },[file.url]);

  const previewUrl = viewerMode === "google" ? gDocsUrl : officeUrl;

  return (<div style={{position:"fixed",inset:0,zIndex:2000,display:"flex",alignItems:"center",justifyContent:"center",background:"rgba(0,0,0,0.85)",backdropFilter:"blur(6px)"}} onClick={onClose}>
    <div onClick={e=>e.stopPropagation()} style={{background:C.sidebar,borderRadius:16,border:`1px solid ${C.border}`,width:isOffice||isPdf||isVideo?960:800,maxWidth:"96vw",maxHeight:"94vh",display:"flex",flexDirection:"column",overflow:"hidden"}}>
      {/* Header */}
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"14px 20px",borderBottom:`1px solid ${C.border}`,flexShrink:0}}>
        <div style={{display:"flex",alignItems:"center",gap:10,flex:1,minWidth:0}}>
          <div style={{padding:8,borderRadius:8,background:`${C.orange}18`}}>
            {isImg?<Image size={18} color={C.orange}/>:isPdf?<FileText size={18} color={C.red}/>:isOffice?<FileSpreadsheet size={18} color={C.blue}/>:isVideo?<Monitor size={18} color="#A855F7"/>:<File size={18} color={C.orange}/>}
          </div>
          <div style={{minWidth:0}}>
            <div style={{color:C.text,fontSize:14,fontWeight:700,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{file.name}</div>
            <div style={{color:C.textDim,fontSize:11}}>.{ext} file</div>
          </div>
        </div>
        <div style={{display:"flex",gap:6,alignItems:"center",flexShrink:0}}>
          {isOffice&&<>
            <button onClick={()=>{setViewerMode("ms");setLoading(true);}} style={{padding:"5px 10px",borderRadius:6,border:`1px solid ${viewerMode==="ms"?C.blue:C.border}`,background:viewerMode==="ms"?`${C.blue}22`:"transparent",color:viewerMode==="ms"?C.blue:C.textMuted,fontSize:11,fontWeight:600,cursor:"pointer",fontFamily:"inherit"}}>Microsoft</button>
            <button onClick={()=>{setViewerMode("google");setLoading(true);}} style={{padding:"5px 10px",borderRadius:6,border:`1px solid ${viewerMode==="google"?C.green:C.border}`,background:viewerMode==="google"?`${C.green}22`:"transparent",color:viewerMode==="google"?C.green:C.textMuted,fontSize:11,fontWeight:600,cursor:"pointer",fontFamily:"inherit"}}>Google</button>
          </>}
          {file.url&&<a href={file.url} target="_blank" rel="noreferrer" style={{padding:"5px 10px",borderRadius:6,border:`1px solid ${C.orange}`,background:`${C.orange}22`,color:C.orange,fontSize:11,fontWeight:600,textDecoration:"none",display:"flex",alignItems:"center",gap:4}}><Download size={12}/> Download</a>}
          <button onClick={onClose} style={{background:"none",border:"none",cursor:"pointer",color:C.textMuted,padding:4}}><X size={20}/></button>
        </div>
      </div>
      {/* Content */}
      <div style={{flex:1,overflow:"auto",position:"relative"}}>
        {isImg && <div style={{padding:20,display:"flex",justifyContent:"center",alignItems:"center",minHeight:400}}><img src={file.url} alt={file.name} style={{maxWidth:"100%",maxHeight:"75vh",borderRadius:8,objectFit:"contain"}}/></div>}
        {isPdf && <iframe src={file.url} style={{width:"100%",height:"80vh",border:"none"}} title={file.name} sandbox="allow-scripts allow-same-origin" referrerPolicy="no-referrer"/>}
        {isOffice && previewUrl && <>
          {loading&&<div style={{position:"absolute",inset:0,display:"flex",alignItems:"center",justifyContent:"center",background:C.card,zIndex:1}}><div style={{textAlign:"center"}}><Loader size={28} color={C.orange} style={{animation:"spin 1s linear infinite",marginBottom:10}}/><div style={{color:C.textMuted,fontSize:13}}>Loading preview...</div><div style={{color:C.textDim,fontSize:11,marginTop:4}}>via {viewerMode==="ms"?"Microsoft Office":"Google Docs"} Viewer</div></div></div>}
          <iframe src={previewUrl} onLoad={()=>setLoading(false)} style={{width:"100%",height:"80vh",border:"none"}} title={file.name} sandbox="allow-scripts allow-same-origin" referrerPolicy="no-referrer"/>
        </>}
        {isVideo && <div style={{padding:20,display:"flex",justifyContent:"center"}}><video src={file.url} controls style={{maxWidth:"100%",maxHeight:"75vh",borderRadius:8}}/></div>}
        {isAudio && <div style={{padding:40,display:"flex",justifyContent:"center"}}><audio src={file.url} controls style={{width:"100%",maxWidth:500}}/></div>}
        {isTxt && <div style={{padding:20}}>{txtContent!==null?<pre style={{background:C.bg,padding:20,borderRadius:10,border:`1px solid ${C.border}`,color:C.text,fontSize:12,lineHeight:1.6,overflow:"auto",maxHeight:"70vh",whiteSpace:"pre-wrap",wordBreak:"break-word"}}>{txtContent}</pre>:<div style={{color:C.textDim,textAlign:"center",padding:40}}>Could not load file content</div>}</div>}
        {!isImg && !isPdf && !isOffice && !isVideo && !isAudio && !isTxt && (
          <div style={{textAlign:"center",padding:60}}>
            <File size={56} color={C.textDim} style={{marginBottom:12}}/>
            <p style={{color:C.textMuted,fontSize:14,marginBottom:4}}>Preview not available for .{ext} files</p>
            <p style={{color:C.textDim,fontSize:12,marginBottom:20}}>Download to view in your preferred application</p>
            {file.url&&<a href={file.url} target="_blank" rel="noreferrer" style={{padding:"10px 24px",borderRadius:8,background:C.orange,color:"#fff",fontWeight:700,fontSize:13,textDecoration:"none"}}>Download File ↗</a>}
          </div>
        )}
      </div>
    </div>
  </div>);
};

// =============================================
// AUTH PAGE (Sign In Only)
// =============================================
const AuthPage = ({onAuth}) => {
  const [email,setEmail]=useState("");const [password,setPassword]=useState("");const [error,setError]=useState("");const [loading,setLoading]=useState(false);const [showPw,setShowPw]=useState(false);
  const [failedAttempts,setFailedAttempts]=useState(0);
  const [cooldownUntil,setCooldownUntil]=useState(0);

  const handleSubmit = async() => {
    if(!email||!password){setError("Please enter email and password");return;}
    // [SEC-13] Progressive cooldown on failed attempts
    const now = Date.now();
    if(now < cooldownUntil) {
      setError(`Too many failed attempts. Wait ${Math.ceil((cooldownUntil-now)/1000)} seconds.`);
      return;
    }
    setError("");setLoading(true);
    try{
      // [SEC-13] Anti-automation: deliberate 500ms minimum delay
      const start = Date.now();
      const d=await supaAuth("token?grant_type=password",{email,password});
      const elapsed = Date.now() - start;
      if(elapsed < 500) await new Promise(r=>setTimeout(r, 500-elapsed));

      if(d.access_token){
        setFailedAttempts(0);
        onAuth(d.access_token,d.user,d.refresh_token);
      }else{
        setFailedAttempts(f=>f+1);
        if(failedAttempts+1 >= 3) setCooldownUntil(Date.now()+(failedAttempts+1)*10000); // 30s, 40s, 50s...
        setError("Invalid credentials");
      }
    }
    catch(e){
      setFailedAttempts(f=>f+1);
      if(failedAttempts+1 >= 3) setCooldownUntil(Date.now()+(failedAttempts+1)*10000);
      setError(e.message);
    }
    setLoading(false);
  };
  const isCoolingDown = Date.now() < cooldownUntil;
  return (
    <div style={{minHeight:"100vh",background:C.bg,display:"flex",alignItems:"center",justifyContent:"center",fontFamily:"'DM Sans',sans-serif"}}>
      <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800;900&display=swap" rel="stylesheet"/>
      <div style={{width:400,maxWidth:"95vw"}}>
        <div style={{textAlign:"center",marginBottom:32,display:"flex",flexDirection:"column",alignItems:"center"}}><Logo/><p style={{color:C.textMuted,fontSize:14,marginTop:8}}>AI Powered Compliance Platform</p></div>
        <div style={{background:C.sidebar,borderRadius:16,border:`1px solid ${C.border}`,padding:32}}>
          <h3 style={{margin:"0 0 24px",textAlign:"center",color:C.text,fontSize:18,fontWeight:800}}>Sign In</h3>
          {!ENV_READY&&<div style={{padding:"12px 14px",background:"#422006",border:"1px solid #F9731644",borderRadius:8,color:"#F97316",fontSize:12,marginBottom:16,fontWeight:500,lineHeight:1.6}}>
            <strong>⚠️ Configuration Required</strong><br/>
            Create a <code style={{background:"#0B1120",padding:"1px 5px",borderRadius:4}}>.env</code> file in your project root:<br/><br/>
            <code style={{background:"#0B1120",padding:"4px 8px",borderRadius:4,display:"block",fontSize:11,lineHeight:1.8,color:"#94A3B8"}}>
              VITE_SUPABASE_URL=https://your-project.supabase.co<br/>
              VITE_SUPABASE_ANON_KEY=your-anon-key<br/>
              VITE_SUPER_ADMIN_EMAIL=admin@yourcompany.com
            </code><br/>
            Then restart the dev server (<code style={{background:"#0B1120",padding:"1px 5px",borderRadius:4}}>npm run dev</code>).
          </div>}
          {error&&<div style={{padding:"10px 14px",background:C.redBg,border:`1px solid ${C.red}44`,borderRadius:8,color:C.red,fontSize:12,marginBottom:16,fontWeight:500,whiteSpace:"pre-wrap"}}>{error}</div>}
          <div style={{marginBottom:16}}><label style={{display:"block",fontSize:12,color:C.textMuted,marginBottom:6,fontWeight:600}}>Email</label><div style={{position:"relative"}}><Mail size={16} style={{position:"absolute",left:12,top:12,color:C.textDim}}/><input type="email" value={email} onChange={e=>setEmail(e.target.value)} placeholder="you@company.com" onKeyDown={e=>e.key==="Enter"&&handleSubmit()} autoComplete="username" style={{width:"100%",padding:"10px 12px 10px 38px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,color:C.text,fontSize:14,fontFamily:"inherit",boxSizing:"border-box"}}/></div></div>
          <div style={{marginBottom:24}}><label style={{display:"block",fontSize:12,color:C.textMuted,marginBottom:6,fontWeight:600}}>Password</label><div style={{position:"relative"}}><Lock size={16} style={{position:"absolute",left:12,top:12,color:C.textDim}}/><input type={showPw?"text":"password"} value={password} onChange={e=>setPassword(e.target.value)} placeholder="••••••••" onKeyDown={e=>e.key==="Enter"&&handleSubmit()} autoComplete="current-password" style={{width:"100%",padding:"10px 40px 10px 38px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,color:C.text,fontSize:14,fontFamily:"inherit",boxSizing:"border-box"}}/><button onClick={()=>setShowPw(!showPw)} style={{position:"absolute",right:10,top:10,background:"none",border:"none",cursor:"pointer",color:C.textDim}}>{showPw?<EyeOff size={16}/>:<Eye size={16}/>}</button></div></div>
          {failedAttempts>=3&&<div style={{padding:"8px 12px",background:C.yellowBg,border:`1px solid ${C.yellow}44`,borderRadius:8,color:C.yellow,fontSize:11,marginBottom:16}}>⚠️ Multiple failed attempts detected. Account may be temporarily locked.</div>}
          <button onClick={handleSubmit} disabled={loading||!ENV_READY||isCoolingDown} style={{width:"100%",padding:"12px",background:(loading||!ENV_READY||isCoolingDown)?C.cardHover:C.orange,border:"none",borderRadius:10,color:"#fff",fontSize:15,fontWeight:700,cursor:(loading||!ENV_READY||isCoolingDown)?"not-allowed":"pointer",display:"flex",alignItems:"center",justifyContent:"center",gap:8,fontFamily:"inherit"}}>{loading&&<Loader size={16} style={{animation:"spin 1s linear infinite"}}/>}{!ENV_READY?"Configure .env First":isCoolingDown?"Please wait...":"Sign In"}</button>
          <style>{`@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}`}</style>
        </div>
        <p style={{textAlign:"center",color:C.textDim,fontSize:11,marginTop:16}}>Powered by SecComply · Session protected by TLS</p>
      </div>
    </div>
  );
};

// =============================================
// DASHBOARD
// =============================================
const Dashboard = ({data}) => {
  const gapStats = useMemo(()=>{
    const resp=data.gapResponses||{};
    const evalTrig=(trigger)=>{if(!trigger||trigger==="Ask all clients")return true;const m=trigger.match(/^If\s+(\w+)\s*=\s*(.+)$/);if(m){const r=resp[m[1]];if(!r||!r.resp||r.resp==="No")return false;if(m[2].trim()==="Yes")return r.resp==="Yes"||r.resp==="Partial";return(r.sel||[]).some(s=>s.toLowerCase().includes(m[2].trim().toLowerCase()));}return true;};
    const visible=GAP_QUESTIONS.filter(q=>evalTrig(q.trigger));
    let yes=0,no=0,partial=0,na=0,totalW=0,scoreW=0;
    visible.forEach(q=>{const r=resp[q.id];const w=q.sev==="MAJOR"?2:1;if(!r||!r.resp)return;if(r.resp==="Yes"){yes++;const evN=(q.ev||"").split("\n").filter(l=>l.trim().startsWith("•")).length;const evC=(r.evChecked||[]).length;const s=evN>0&&evC>=evN?100:evC>0?70:60;totalW+=w;scoreW+=s*w;}else if(r.resp==="No"){no++;totalW+=w;}else if(r.resp==="Partial"){partial++;const evC=(r.evChecked||[]).length;totalW+=w;scoreW+=(evC>0?50:30)*w;}else if(r.resp==="N/A"){na++;}});
    const pct=totalW>0?Math.round(scoreW/totalW):0;
    return{total:visible.length,yes,no,partial,na,pct};
  },[data.gapResponses]);

  // Workflow score
  const wfStats = useMemo(()=>{
    const config=data.workflowConfig||{};const records=data.workflowRecords||[];
    const getRecords=(cid)=>records.filter(r=>r.controlId===cid).sort((a,b)=>new Date(b.date)-new Date(a.date));
    const scoreCtrl=(cid)=>{
      const freq=config[cid]?.frequency||"Annual";const recs=getRecords(cid);
      const la=recs.find(r=>r.status==="approved");
      if(la){const nd=calcNextDue(la.date,freq);if(nd&&!isOverdue(nd))return 100;const p=recs.find(r=>r.status==="uploaded"||r.status==="pending");if(p)return 60;return 30;}
      const p=recs.find(r=>r.status==="uploaded"||r.status==="pending");if(p)return 60;
      const rj=recs.find(r=>r.status==="rejected");if(rj)return 20;return 0;
    };
    let totalW=0,scoreW=0,compliant=0,pending=0,overdue=0;
    WORKFLOW_CONTROLS.forEach(c=>{
      const sc=scoreCtrl(c.id);totalW+=c.weight;scoreW+=sc*c.weight/100;
      if(sc>=80)compliant++;else if(sc>=40)pending++;else overdue++;
    });
    const pct=totalW>0?Math.round((scoreW/totalW)*100):0;
    return{pct,compliant,pending,overdue};
  },[data.workflowConfig,data.workflowRecords]);

  // SOA stats
  const soaStats = useMemo(()=>{
    const app=data.soaApplicability||{};
    const total=SOA_CONTROLS.length;
    let applicable=0,notApplicable=0,justified=0,pending=0;
    SOA_CONTROLS.forEach(c=>{
      const s=app[c.id];
      if(!s||s.applicable===null||s.applicable===undefined){pending++;return;}
      if(s.applicable){applicable++;}else{notApplicable++;if(s.justification&&s.justification.trim())justified++;}
    });
    const completed=applicable+notApplicable;
    const pct=total>0?Math.round((completed/total)*100):0;
    return{total,applicable,notApplicable,justified,pending,pct};
  },[data.soaApplicability]);

  // Policy stats
  const policyStats = useMemo(()=>{
    const policies=data.policies||[];
    return{total:policies.length,pct:policies.length>0?Math.round((policies.length/40)*100):0};
  },[data.policies]);

  // Vendor/TPRA stats
  const vendorStats = useMemo(()=>{
    const vendors=data.vendors||[];
    const assessed=vendors.filter(v=>(v.answers&&Object.keys(v.answers).length>0)||v.score>0||v.scan_report);
    return{total:vendors.length,assessed:assessed.length,pct:vendors.length>0?Math.round((assessed.length/vendors.length)*100):0};
  },[data.vendors]);

  // Risk stats
  const riskData = useMemo(()=>{const r=(data.risks||[]).filter(x=>!x.disabled);return{total:r.length,high:r.filter(x=>x.impact*x.likelihood>=15).length,med:r.filter(x=>{const l=x.impact*x.likelihood;return l>=8&&l<15;}).length,low:r.filter(x=>x.impact*x.likelihood<8).length};},[data.risks]);

  // Overall: Workflow 30% + Gap 30% + SOA 20% + Policies 10% + Vendors 10%
  const overallPct = Math.round(wfStats.pct * 0.3 + gapStats.pct * 0.3 + soaStats.pct * 0.2 + policyStats.pct * 0.1 + vendorStats.pct * 0.1);
  const overallColor = overallPct >= 70 ? C.green : overallPct >= 40 ? C.yellow : C.red;

  const gapPie=[{name:"Yes",value:gapStats.yes,color:C.green},{name:"Partial",value:gapStats.partial,color:C.yellow},{name:"No (Gap)",value:gapStats.no,color:C.red},{name:"N/A",value:gapStats.na,color:C.textDim}].filter(d=>d.value>0);
  const riskPie=[{name:"High",value:riskData.high,color:C.red},{name:"Medium",value:riskData.med,color:C.yellow},{name:"Low",value:riskData.low,color:C.green}].filter(d=>d.value>0);
  const wfPie=[{name:"Compliant",value:wfStats.compliant,color:C.green},{name:"In Progress",value:wfStats.pending,color:C.yellow},{name:"Non-Compliant",value:wfStats.overdue,color:C.red}].filter(d=>d.value>0);

  return (<div>
    <h2 style={{margin:"0 0 4px",fontSize:22,fontWeight:800,color:C.text}}>Compliance Dashboard</h2>
    <p style={{color:C.textMuted,margin:"0 0 20px",fontSize:14}}>Your information security management at a glance</p>

    {/* Overall Compliance Hero */}
    <div style={{background:`linear-gradient(135deg,${C.card},${overallColor}08)`,borderRadius:14,border:`1px solid ${overallColor}33`,padding:"24px 28px",marginBottom:20,display:"flex",alignItems:"center",gap:24}}>
      <div style={{position:"relative",width:100,height:100,flexShrink:0}}>
        <svg viewBox="0 0 36 36" style={{width:100,height:100,transform:"rotate(-90deg)"}}>
          <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke={C.border} strokeWidth="2.5"/>
          <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke={overallColor} strokeWidth="2.5" strokeDasharray={`${overallPct}, 100`} strokeLinecap="round"/>
        </svg>
        <div style={{position:"absolute",inset:0,display:"flex",alignItems:"center",justifyContent:"center",flexDirection:"column"}}><span style={{fontSize:28,fontWeight:900,color:overallColor}}>{overallPct}%</span></div>
      </div>
      <div style={{flex:1}}>
        <div style={{fontSize:18,fontWeight:800,color:C.text,marginBottom:6}}>Overall ISMS Compliance</div>
        <div style={{display:"flex",gap:16,flexWrap:"wrap",marginBottom:8}}>
          <div><span style={{color:C.textDim,fontSize:11}}>Workflow (30%)</span><div style={{fontSize:15,fontWeight:800,color:wfStats.pct>=70?C.green:wfStats.pct>=40?C.yellow:C.red}}>{wfStats.pct}%</div></div>
          <div><span style={{color:C.textDim,fontSize:11}}>Gap Assessment (30%)</span><div style={{fontSize:15,fontWeight:800,color:gapStats.pct>=70?C.green:gapStats.pct>=40?C.yellow:C.red}}>{gapStats.pct}%</div></div>
          <div><span style={{color:C.textDim,fontSize:11}}>SOA (20%)</span><div style={{fontSize:15,fontWeight:800,color:soaStats.pct>=70?C.green:soaStats.pct>=40?C.yellow:C.red}}>{soaStats.pct}%</div></div>
          <div><span style={{color:C.textDim,fontSize:11}}>Policies (10%)</span><div style={{fontSize:15,fontWeight:800,color:policyStats.pct>=70?C.green:policyStats.pct>=40?C.yellow:C.red}}>{policyStats.pct}%</div></div>
          <div><span style={{color:C.textDim,fontSize:11}}>Vendors (10%)</span><div style={{fontSize:15,fontWeight:800,color:vendorStats.pct>=70?C.green:vendorStats.pct>=40?C.yellow:C.red}}>{vendorStats.pct}%</div></div>
        </div>
        <div style={{height:8,background:C.bg,borderRadius:4,overflow:"hidden",maxWidth:400}}><div style={{height:"100%",width:`${overallPct}%`,background:`linear-gradient(90deg,${overallColor},${C.orange})`,borderRadius:4,transition:"width 0.6s"}}/></div>
      </div>
    </div>

    {/* Stats */}
    <div style={{display:"flex",gap:16,flexWrap:"wrap",marginBottom:24}}>
      <Stat label="Overall Score" value={`${overallPct}%`} icon={Shield} color={overallColor}/>
      <Stat label="Workflow Check" value={`${wfStats.pct}%`} icon={Activity} color={wfStats.pct>=70?C.green:wfStats.pct>=40?C.yellow:C.red}/>
      <Stat label="Gap Assessment" value={`${gapStats.pct}%`} icon={ClipboardCheck} color={gapStats.pct>=70?C.green:gapStats.pct>=40?C.yellow:C.red}/>
      <Stat label="SOA Completion" value={`${soaStats.pct}%`} icon={FileText} color={soaStats.pct>=70?C.green:soaStats.pct>=40?C.yellow:C.red}/>
      <Stat label="Policies" value={`${policyStats.total}/40`} icon={FileText} color={policyStats.pct>=70?C.green:policyStats.pct>=40?C.yellow:C.red}/>
      <Stat label="Active Risks" value={riskData.total} icon={AlertTriangle} color={C.yellow}/>
      <Stat label="Assets" value={(data.assets||[]).length} icon={Server} color={C.blue}/>
      <Stat label="Vendors" value={`${vendorStats.assessed}/${vendorStats.total}`} icon={Users} color={vendorStats.pct>=70?C.green:vendorStats.pct>=40?C.yellow:C.red}/>
    </div>

    {/* Charts */}
    <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:16}}>
      <Card title="Workflow Controls">{wfPie.length>0?<ResponsiveContainer width="100%" height={200}><PieChart><Pie data={wfPie} cx="50%" cy="50%" innerRadius={40} outerRadius={70} dataKey="value" paddingAngle={3}>{wfPie.map((d,i)=><Cell key={i} fill={d.color}/>)}</Pie><Legend formatter={v=><span style={{color:C.textMuted,fontSize:11}}>{v}</span>}/></PieChart></ResponsiveContainer>:<Empty msg="Configure Workflow Check"/>}</Card>
      <Card title="Gap Assessment">{gapPie.length>0?<ResponsiveContainer width="100%" height={200}><PieChart><Pie data={gapPie} cx="50%" cy="50%" innerRadius={40} outerRadius={70} dataKey="value" paddingAngle={2}>{gapPie.map((d,i)=><Cell key={i} fill={d.color}/>)}</Pie><Legend formatter={v=><span style={{color:C.textMuted,fontSize:11}}>{v}</span>}/></PieChart></ResponsiveContainer>:<Empty msg="Start Gap Assessment"/>}</Card>
      <Card title="Risk Heatmap">{riskPie.length>0?<ResponsiveContainer width="100%" height={200}><BarChart data={riskPie}><XAxis dataKey="name" tick={{fill:C.textMuted,fontSize:11}} axisLine={false} tickLine={false}/><YAxis tick={{fill:C.textMuted,fontSize:11}} axisLine={false} tickLine={false}/><Tooltip contentStyle={{background:C.sidebar,border:`1px solid ${C.border}`,borderRadius:8,color:C.text}}/><Bar dataKey="value" radius={[6,6,0,0]}>{riskPie.map((d,i)=><Cell key={i} fill={d.color}/>)}</Bar></BarChart></ResponsiveContainer>:<Empty msg="Add risks"/>}</Card>
    </div>
  </div>);
};

// =============================================
// SOA MODULE (unchanged)
// =============================================
const SOAModule = ({data,setData}) => {
  const [toast,setToast]=useState(null);
  const [activeTheme,setActiveTheme]=useState("all");
  const [search,setSearch]=useState("");
  const [expandedId,setExpandedId]=useState(null);
  const {token,user,orgId} = useAuth();

  const soa=data.soaApplicability||{};
  // {controlId: {applicable: true/false/null, justification:"..."}}

  const setControlState=(controlId,updates)=>{
    setData(d=>({...d,soaApplicability:{...(d.soaApplicability||{}),
      [controlId]:{...((d.soaApplicability||{})[controlId]||{applicable:null,justification:""}), ...updates}
    }}));
  };

  // Mark all in a theme
  const markAllTheme=(theme,applicable)=>{
    const controls=SOA_CONTROLS.filter(c=>theme==="all"||c.theme===theme);
    setData(d=>{
      const newSoa={...(d.soaApplicability||{})};
      controls.forEach(c=>{newSoa[c.id]={...(newSoa[c.id]||{applicable:null,justification:""}),applicable};});
      return{...d,soaApplicability:newSoa};
    });
    setToast({msg:`Marked ${controls.length} controls as ${applicable?"Applicable":"Not Applicable"}`,type:"success"});
  };

  // Stats
  const stats=useMemo(()=>{
    let total=SOA_CONTROLS.length,applicable=0,notApplicable=0,pending=0,justified=0;
    SOA_CONTROLS.forEach(c=>{
      const s=soa[c.id];
      if(!s||s.applicable===null||s.applicable===undefined) pending++;
      else if(s.applicable) applicable++;
      else{notApplicable++;if(s.justification&&s.justification.trim())justified++;}
    });
    return{total,applicable,notApplicable,pending,justified,needsJustification:notApplicable-justified};
  },[soa]);

  // Theme stats
  const themeStats=useMemo(()=>{
    const ts={};
    SOA_THEMES.forEach(t=>{
      const controls=SOA_CONTROLS.filter(c=>c.theme===t.id);
      let app=0,na=0,pend=0;
      controls.forEach(c=>{
        const s=soa[c.id];
        if(!s||s.applicable===null||s.applicable===undefined)pend++;
        else if(s.applicable)app++;else na++;
      });
      ts[t.id]={total:controls.length,applicable:app,notApplicable:na,pending:pend};
    });
    return ts;
  },[soa]);

  // Filtered controls
  const filtered=useMemo(()=>{
    let list=SOA_CONTROLS;
    if(activeTheme!=="all") list=list.filter(c=>c.theme===activeTheme);
    if(search){
      const q=search.toLowerCase();
      list=list.filter(c=>c.id.toLowerCase().includes(q)||c.title.toLowerCase().includes(q)||c.desc.toLowerCase().includes(q));
    }
    return list;
  },[activeTheme,search]);

  // Export to Excel
  const exportSOA=()=>{
    const rows=SOA_CONTROLS.map(c=>{
      const s=soa[c.id]||{};
      return{"Control ID":c.id,"Theme":c.theme,"Control Title":c.title,"Description":c.desc,"Applicable":s.applicable===true?"Yes":s.applicable===false?"No":"Pending","Justification":s.justification||""};
    });
    const wb=XLSX.utils.book_new();
    const ws=XLSX.utils.json_to_sheet(rows);
    ws["!cols"]=[{wch:10},{wch:16},{wch:40},{wch:70},{wch:12},{wch:50}];
    XLSX.utils.book_append_sheet(wb,ws,"SOA");

    // Summary sheet
    const summary=[
      {Metric:"Total Controls",Value:stats.total},
      {Metric:"Applicable",Value:stats.applicable},
      {Metric:"Not Applicable",Value:stats.notApplicable},
      {Metric:"Pending Review",Value:stats.pending},
      {Metric:"Justified (N/A)",Value:stats.justified},
      {Metric:"Needs Justification",Value:stats.needsJustification},
    ];
    const ws2=XLSX.utils.json_to_sheet(summary);
    ws2["!cols"]=[{wch:22},{wch:10}];
    XLSX.utils.book_append_sheet(wb,ws2,"Summary");
    XLSX.writeFile(wb,"SOA_Statement_of_Applicability.xlsx");
    auditLog(token,"data_export",{resource_type:"soa",org_id:orgId},"warning");
    setToast({msg:"SOA exported!",type:"success"});
  };

  const pctComplete=stats.total>0?Math.round(((stats.applicable+stats.notApplicable)/stats.total)*100):0;

  return (<div>
    {toast&&<Toast {...toast} onClose={()=>setToast(null)}/>}

    {/* Header */}
    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20,flexWrap:"wrap",gap:12}}>
      <div>
        <h2 style={{margin:0,fontSize:22,fontWeight:800,color:C.text}}>Statement of Applicability</h2>
        <p style={{color:C.textMuted,margin:"4px 0 0",fontSize:13}}>ISO 27001:2022 — 93 Annex A controls • Review applicability & provide justification</p>
      </div>
      <div style={{display:"flex",gap:8}}>
        <Btn variant="secondary" onClick={exportSOA}><Download size={14}/> Export SOA</Btn>
      </div>
    </div>

    {/* Progress bar */}
    <div style={{background:C.card,borderRadius:12,padding:"16px 20px",border:`1px solid ${C.border}`,marginBottom:20}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
        <span style={{fontSize:13,fontWeight:700,color:C.text}}>Overall Completion</span>
        <span style={{fontSize:13,fontWeight:800,color:pctComplete===100?C.green:C.orange}}>{pctComplete}%</span>
      </div>
      <div style={{height:8,background:C.bg,borderRadius:4,overflow:"hidden"}}>
        <div style={{height:"100%",width:`${pctComplete}%`,background:pctComplete===100?C.green:`linear-gradient(90deg, ${C.orange}, ${C.yellow})`,borderRadius:4,transition:"width 0.3s"}}/>
      </div>
      <div style={{display:"flex",justifyContent:"space-between",marginTop:8,fontSize:11,color:C.textDim}}>
        <span>{stats.applicable+stats.notApplicable} of {stats.total} reviewed</span>
        {stats.needsJustification>0&&<span style={{color:C.red}}>⚠ {stats.needsJustification} N/A controls need justification</span>}
      </div>
    </div>

    {/* Stats cards */}
    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(120px,1fr))",gap:12,marginBottom:20}}>
      {[
        {label:"Total Controls",val:stats.total,col:C.text},
        {label:"Applicable",val:stats.applicable,col:C.green},
        {label:"Not Applicable",val:stats.notApplicable,col:C.red},
        {label:"Pending",val:stats.pending,col:C.yellow},
        {label:"Justified",val:stats.justified,col:C.blue},
      ].map(s=><div key={s.label} style={{background:C.card,borderRadius:10,padding:"12px 14px",border:`1px solid ${s.col}22`}}>
        <div style={{fontSize:11,color:C.textMuted,fontWeight:600}}>{s.label}</div>
        <div style={{fontSize:22,fontWeight:800,color:s.col}}>{s.val}</div>
      </div>)}
    </div>

    {/* Theme tabs */}
    <div style={{display:"flex",gap:4,marginBottom:16,background:C.card,borderRadius:10,padding:4,flexWrap:"wrap"}}>
      <button onClick={()=>setActiveTheme("all")} style={{padding:"8px 16px",border:"none",borderRadius:8,cursor:"pointer",fontWeight:700,fontSize:12,background:activeTheme==="all"?C.orange:"transparent",color:activeTheme==="all"?"#fff":C.textMuted,fontFamily:"inherit"}}>All ({stats.total})</button>
      {SOA_THEMES.map(t=>{
        const ts=themeStats[t.id]||{};
        return(<button key={t.id} onClick={()=>setActiveTheme(t.id)} style={{padding:"8px 16px",border:"none",borderRadius:8,cursor:"pointer",fontWeight:700,fontSize:12,background:activeTheme===t.id?t.color:"transparent",color:activeTheme===t.id?"#fff":C.textMuted,fontFamily:"inherit"}}>
          {t.label} <span style={{opacity:0.7,marginLeft:4}}>({ts.applicable||0}/{t.count})</span>
        </button>);
      })}
    </div>

    {/* Search + bulk actions */}
    <div style={{display:"flex",gap:12,marginBottom:16,alignItems:"center",flexWrap:"wrap"}}>
      <div style={{position:"relative",flex:1,minWidth:200,maxWidth:360}}>
        <Search size={16} style={{position:"absolute",left:12,top:"50%",transform:"translateY(-50%)",color:C.textDim}}/>
        <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search controls by ID, title or description..." style={{width:"100%",padding:"10px 12px 10px 36px",background:C.card,border:`1px solid ${C.border}`,borderRadius:10,color:C.text,fontSize:13,fontFamily:"inherit",boxSizing:"border-box"}}/>
      </div>
      <div style={{display:"flex",gap:6}}>
        <Btn size="sm" variant="secondary" onClick={()=>markAllTheme(activeTheme,true)} style={{fontSize:11}}><CheckCircle size={12}/> Mark All Applicable</Btn>
        <Btn size="sm" variant="secondary" onClick={()=>markAllTheme(activeTheme,false)} style={{fontSize:11}}><XCircle size={12}/> Mark All N/A</Btn>
      </div>
    </div>

    {/* Controls list */}
    <div style={{display:"flex",flexDirection:"column",gap:6}}>
      {filtered.map(c=>{
        const s=soa[c.id]||{applicable:null,justification:""};
        const isExpanded=expandedId===c.id;
        const themeColor=(SOA_THEMES.find(t=>t.id===c.theme)||{}).color||C.textMuted;
        const needsJust=s.applicable===false&&(!s.justification||!s.justification.trim());
        return(<div key={c.id} style={{background:C.card,borderRadius:10,border:`1px solid ${needsJust?`${C.red}66`:s.applicable===true?`${C.green}33`:s.applicable===false?`${C.red}22`:C.border}`,overflow:"hidden",transition:"border-color 0.2s"}}>
          {/* Row */}
          <div style={{display:"flex",alignItems:"center",gap:12,padding:"12px 16px",cursor:"pointer"}} onClick={()=>setExpandedId(isExpanded?null:c.id)}>
            {/* Control ID badge */}
            <div style={{background:`${themeColor}18`,color:themeColor,padding:"4px 10px",borderRadius:6,fontSize:12,fontWeight:800,fontFamily:"monospace",whiteSpace:"nowrap",minWidth:52,textAlign:"center"}}>{c.id}</div>
            {/* Title */}
            <div style={{flex:1,minWidth:0}}>
              <div style={{fontSize:13,fontWeight:600,color:C.text,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{c.title}</div>
              {!isExpanded&&<div style={{fontSize:11,color:C.textDim,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",maxWidth:500}}>{c.desc.substring(0,100)}...</div>}
            </div>
            {/* Applicable / Not Applicable toggle */}
            <div style={{display:"flex",gap:4}} onClick={e=>e.stopPropagation()}>
              <button onClick={()=>setControlState(c.id,{applicable:true})} style={{padding:"6px 14px",borderRadius:8,border:`1.5px solid ${s.applicable===true?C.green:C.border}`,background:s.applicable===true?`${C.green}18`:"transparent",color:s.applicable===true?C.green:C.textDim,fontSize:12,fontWeight:s.applicable===true?700:500,cursor:"pointer",fontFamily:"inherit",transition:"all 0.15s"}}>Applicable</button>
              <button onClick={()=>{setControlState(c.id,{applicable:false});if(!isExpanded)setExpandedId(c.id);}} style={{padding:"6px 14px",borderRadius:8,border:`1.5px solid ${s.applicable===false?C.red:C.border}`,background:s.applicable===false?`${C.red}18`:"transparent",color:s.applicable===false?C.red:C.textDim,fontSize:12,fontWeight:s.applicable===false?700:500,cursor:"pointer",fontFamily:"inherit",transition:"all 0.15s"}}>Not Applicable</button>
            </div>
            {/* Status indicator */}
            <div style={{width:8,height:8,borderRadius:"50%",background:s.applicable===null?C.yellow:s.applicable?C.green:C.red,flexShrink:0}}/>
            <ChevronRight size={14} color={C.textDim} style={{transform:isExpanded?"rotate(90deg)":"none",transition:"transform 0.2s"}}/>
          </div>

          {/* Expanded detail */}
          {isExpanded&&<div style={{padding:"0 16px 16px",borderTop:`1px solid ${C.border}`}}>
            <div style={{padding:"12px 0"}}>
              <div style={{fontSize:12,color:C.textMuted,lineHeight:1.7,marginBottom:14}}>{c.desc}</div>
              <div style={{display:"flex",gap:8,marginBottom:12}}>
                <Badge color={themeColor}>{c.theme}</Badge>
                {s.applicable===true&&<Badge color={C.green}>Applicable</Badge>}
                {s.applicable===false&&<Badge color={C.red}>Not Applicable</Badge>}
                {s.applicable===null&&<Badge color={C.yellow}>Pending Review</Badge>}
              </div>
              {/* Justification field — always shown when expanded, highlighted when N/A */}
              <div>
                <label style={{display:"block",fontSize:12,color:s.applicable===false&&needsJust?C.red:C.textMuted,fontWeight:700,marginBottom:4}}>
                  {s.applicable===false?"Justification for Exclusion *":"Justification / Notes"}
                  {needsJust&&<span style={{color:C.red,marginLeft:6,fontSize:11,fontWeight:500}}>— Required for N/A controls</span>}
                </label>
                <textarea value={s.justification||""} onChange={e=>setControlState(c.id,{justification:e.target.value})} placeholder={s.applicable===false?"Explain why this control is not applicable to your organization...":"Optional notes on implementation status, evidence, or remarks..."} style={{width:"100%",minHeight:70,padding:10,background:C.bg,border:`1px solid ${needsJust?C.red:C.border}`,borderRadius:8,color:C.text,fontSize:12,fontFamily:"inherit",lineHeight:1.6,resize:"vertical",boxSizing:"border-box"}}/>
              </div>
            </div>
          </div>}
        </div>);
      })}
    </div>

    {filtered.length===0&&<Card><Empty msg="No controls match your search"/></Card>}
  </div>);
};


// Conditional trigger evaluator
const evalTrigger = (trigger, resp) => {
  if(!trigger || trigger === "Ask all clients") return {visible:true,reason:""};
  const m = trigger.match(/^If\s+(\w+)\s*=\s*(.+)$/);
  if(m) {
    const pid = m[1], val = m[2].trim();
    const r = resp[pid];
    if(!r || !r.resp || r.resp === "No" || r.resp === "N/A") return {visible:false,reason:`Requires ${pid} = ${val}`};
    if(val === "Yes") return {visible: r.resp === "Yes" || r.resp === "Partial", reason:`Requires ${pid} = Yes`};
    const match = (r.sel||[]).some(s => s.toLowerCase().includes(val.toLowerCase()));
    return {visible:match, reason:`Requires ${pid} includes ${val}`};
  }
  const ctx = {
    "If on-prem or hybrid":  () => (resp.N1?.sel||[]).some(s=>/on.?prem|hybrid/i.test(s)),
    "If multi-site":         () => (resp.N1?.sel||[]).some(s=>/multi/i.test(s)),
    "If hosting web apps":   () => true,
    "If using WiFi":         () => true,
    "If managing critical infra": () => true,
    "If handling sensitive data":  () => true,
    "If using containers":   () => true,
    "If hosting APIs":       () => true,
    "If SOC exists":         () => resp.L5?.resp === "Yes" || resp.L5?.resp === "Partial",
    "If using cloud":        () => resp.C1?.resp === "Yes" || resp.C1?.resp === "Partial",
    "If critical vendors":   () => resp.T1?.resp === "Yes" || resp.T1?.resp === "Partial",
  };
  const fn = ctx[trigger];
  return {visible: fn ? fn() : true, reason: trigger};
};

// Scoring per question
const scoreQ = (r, q) => {
  if(!r || !r.resp || r.resp === "N/A") return null; // excluded
  if(r.resp === "No") return 0;
  const evItems = (q.ev||"").split("\n").filter(l=>l.trim().startsWith("•")).length;
  const evChecked = (r.evChecked||[]).length;
  const evPct = evItems > 0 ? evChecked / evItems : 0;
  if(r.resp === "Yes" && evPct >= 1) return 100;
  if(r.resp === "Yes" && evPct > 0) return 70;
  if(r.resp === "Yes" && evPct === 0) return 60;
  if(r.resp === "Partial" && evPct > 0) return 50;
  if(r.resp === "Partial") return 30;
  return 0;
};

const GapAssessment = ({data,setData,role:userRole}) => {
  const [activeCat,setActiveCat]=useState(0);
  const [view,setView]=useState("assess"); // assess | dashboard | export
  const [detailQ,setDetailQ]=useState(null);
  const [search,setSearch]=useState("");
  const [toast,setToast]=useState(null);
  const [uploading,setUploading]=useState(false);
  const [rejectModal,setRejectModal]=useState(null);
  const [rejectComment,setRejectComment]=useState("");
  const {token,user,orgId} = useAuth();
  const canDoApprove = canApprove(userRole||"client_user","gap");

  const resp = data.gapResponses || {};
  const setResp = (qId, updates) => {
    setData(d => ({...d, gapResponses: {...(d.gapResponses||{}), [qId]: {...((d.gapResponses||{})[qId]||{resp:"",sel:[],evChecked:[],notes:"",driveLink:""}), ...updates}}}));
  };

  // Get visible questions for a category
  const getVisibleQs = (catIdx) => {
    return GAP_QUESTIONS.filter(q => q.catIdx === catIdx).filter(q => {
      const {visible} = evalTrigger(q.trigger, resp);
      return visible;
    });
  };

  // Get ALL visible questions across all categories
  const allVisibleQs = useMemo(() => {
    return GAP_QUESTIONS.filter(q => evalTrigger(q.trigger, resp).visible);
  }, [resp]);

  // Current category questions
  const catQs = useMemo(() => {
    let qs = GAP_QUESTIONS.filter(q => q.catIdx === activeCat);
    if(search) {
      const s = search.toLowerCase();
      qs = qs.filter(q => q.q.toLowerCase().includes(s) || q.id.toLowerCase().includes(s) || q.iso.toLowerCase().includes(s));
    }
    return qs;
  }, [activeCat, search]);

  // Category scores
  const catScores = useMemo(() => {
    return GAP_CATS.map((cat, idx) => {
      const qs = getVisibleQs(idx);
      let totalWeight = 0, weightedScore = 0, answered = 0, total = qs.length;
      qs.forEach(q => {
        const r = resp[q.id];
        const w = q.sev === "MAJOR" ? 2 : 1;
        const s = scoreQ(r, q);
        if(s !== null) { totalWeight += w; weightedScore += s * w; answered++; }
        else { total--; } // N/A excluded from total
      });
      const pct = totalWeight > 0 ? Math.round(weightedScore / totalWeight) : 0;
      return {name: cat.name, icon: cat.icon, total, answered, pct, visible: qs.length, allQs: GAP_QUESTIONS.filter(q=>q.catIdx===idx).length};
    });
  }, [resp]);

  // Overall stats
  const overallStats = useMemo(() => {
    let totalW = 0, scoreW = 0, answered = 0, yesCount = 0, noCount = 0, partialCount = 0, naCount = 0;
    let majorGaps = 0, modGaps = 0;
    allVisibleQs.forEach(q => {
      const r = resp[q.id];
      const w = q.sev === "MAJOR" ? 2 : 1;
      if(r?.resp === "Yes") yesCount++;
      else if(r?.resp === "No") { noCount++; if(q.sev==="MAJOR") majorGaps++; else modGaps++; }
      else if(r?.resp === "Partial") partialCount++;
      else if(r?.resp === "N/A") naCount++;
      const s = scoreQ(r, q);
      if(s !== null) { totalW += w; scoreW += s * w; answered++; }
    });
    const pct = totalW > 0 ? Math.round(scoreW / totalW) : 0;
    return {total: allVisibleQs.length, answered, yesCount, noCount, partialCount, naCount, majorGaps, modGaps, pct};
  }, [resp, allVisibleQs]);

  // Evidence items parser
  const parseEvItems = (ev) => (ev||"").split("\n").filter(l=>l.trim().startsWith("•")).map(l=>l.trim().replace(/^•\s*/,""));

  // Evidence upload
  const handleEvUpload = async(qId) => {
    const input = document.createElement("input");
    input.type = "file";
    input.onchange = async(e) => {
      const file = e.target.files[0];
      if(!file) return;
      try {
        const ref = await uploadToStorage(token,orgId||user.id,"gap-evidence",file);
        const curr = resp[qId] || {};
        const files = [...(curr.evFiles||[]), ref];
        setResp(qId, {evFiles: files, evStatus: "uploaded", evReviewComment:"", evReviewedBy:"", evReviewedAt:""});
        setToast({msg:"Evidence uploaded! Awaiting review.",type:"success"});
      } catch(err) { setToast({msg:err.message.includes("not allowed")||err.message.includes("too large")?"Upload error: "+err.message:"Upload failed. Please try again.",type:"error"}); }
    };
    input.click();
  };

  // Approve evidence for a question
  const approveEvidence = (qId) => {
    setResp(qId, {evStatus:"approved", evReviewedBy:user.email, evReviewedAt:new Date().toISOString(), evReviewComment:""});
    setToast({msg:"Evidence approved!",type:"success"});
  };

  // Reject evidence for a question
  const rejectEvidence = (qId) => {
    setResp(qId, {evStatus:"rejected", evReviewedBy:user.email, evReviewedAt:new Date().toISOString(), evReviewComment:rejectComment});
    setRejectModal(null); setRejectComment("");
    setToast({msg:"Evidence rejected.",type:"warning"});
  };

  // Export assessment to Excel — [SEC-2] with audit log and [SEC-6] watermark
  const exportAssessment = () => {
    const rows = allVisibleQs.map(q => {
      const r = resp[q.id] || {};
      const evItems = parseEvItems(q.ev);
      const evChecked = (r.evChecked||[]).length;
      const s = scoreQ(r, q);
      return {
        "Q#": q.id,
        "Category": GAP_CATS[q.catIdx]?.name || "",
        "Type": q.type,
        "Question": q.q,
        "ISO Ref": q.iso,
        "Severity": q.sev,
        "Response": r.resp || "Not Assessed",
        "Selections": (r.sel||[]).join(", "),
        "Evidence Items": evItems.length,
        "Evidence Collected": evChecked,
        "Evidence %": evItems.length > 0 ? Math.round((evChecked/evItems.length)*100)+"%" : "N/A",
        "Score": s !== null ? s+"%" : "N/A",
        "Drive Link": r.driveLink || "",
        "Notes": r.notes || "",
        "Recommended Action": q.act,
        "Trigger": q.trigger,
      };
    });
    const watermarked = addExportWatermark(rows, user?.email || "unknown", orgId || "unknown");
    const ws = XLSX.utils.json_to_sheet(watermarked);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, "Gap Assessment");
    ws["!cols"] = [{wch:5},{wch:28},{wch:10},{wch:55},{wch:14},{wch:10},{wch:14},{wch:20},{wch:6},{wch:6},{wch:8},{wch:6},{wch:25},{wch:25},{wch:35},{wch:18}];
    XLSX.writeFile(wb, "Gap_Assessment_Report.xlsx");
    // [SEC-2] Audit log export event
    auditLog(token, "data_export", { resource_type: "gap_assessment", org_id: orgId, record_count: rows.length }, "warning");
    setToast({msg:"Assessment exported!",type:"success"});
  };

  // Type badge colors
  const typeBg = {DISCOVERY:"#3B82F622",["DRILL-DOWN"]:"#A855F722",GAP:"#EF444422"};
  const typeColor = {DISCOVERY:C.blue,["DRILL-DOWN"]:"#A855F7",GAP:C.red};
  const sevColor = s => s === "MAJOR" ? C.red : C.orange;
  const respColor = r => ({Yes:C.green,No:C.red,Partial:C.yellow,"N/A":C.textDim}[r]||C.border);

  // Score color
  const scoreBg = (pct) => pct >= 80 ? C.green : pct >= 60 ? C.yellow : pct >= 40 ? C.orange : C.red;

  // ─── DASHBOARD VIEW ───
  if(view === "dashboard") {
    const radarData = catScores.map(c=>({domain:c.icon+" "+c.name.split(" ")[0],score:c.pct,full:100}));
    const sevData = [{name:"MAJOR Gaps",value:overallStats.majorGaps,color:C.red},{name:"MODERATE Gaps",value:overallStats.modGaps,color:C.orange}].filter(d=>d.value>0);
    const respData = [{name:"Yes",value:overallStats.yesCount,color:C.green},{name:"Partial",value:overallStats.partialCount,color:C.yellow},{name:"No",value:overallStats.noCount,color:C.red},{name:"N/A",value:overallStats.naCount,color:C.textDim}].filter(d=>d.value>0);
    return (<div>
      {toast&&<Toast {...toast} onClose={()=>setToast(null)}/>}
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20}}>
        <div><h2 style={{margin:0,fontSize:22,fontWeight:800,color:C.text}}>Gap Assessment Dashboard</h2>
        <p style={{color:C.textMuted,margin:"4px 0 0",fontSize:13}}>Overall Score: <span style={{color:scoreBg(overallStats.pct),fontWeight:800,fontSize:18}}>{overallStats.pct}%</span> • {overallStats.answered}/{overallStats.total} questions assessed</p></div>
        <div style={{display:"flex",gap:8}}>
          <Btn variant="secondary" size="sm" onClick={()=>setView("assess")}><ArrowLeft size={14}/> Back to Assessment</Btn>
          <Btn onClick={exportAssessment}><Download size={14}/> Export Report</Btn>
        </div>
      </div>
      {/* Stats Row */}
      <div style={{display:"flex",gap:16,flexWrap:"wrap",marginBottom:20}}>
        <Stat label="Overall Score" value={`${overallStats.pct}%`} icon={Target} color={scoreBg(overallStats.pct)}/>
        <Stat label="Questions Assessed" value={`${overallStats.answered}/${overallStats.total}`} icon={ClipboardCheck} color={C.blue}/>
        <Stat label="Compliant (Yes)" value={overallStats.yesCount} icon={CheckCircle} color={C.green}/>
        <Stat label="Gaps Found (No)" value={overallStats.noCount} icon={AlertTriangle} color={C.red}/>
      </div>
      {/* Progress bar */}
      <div style={{height:8,background:C.bg,borderRadius:4,marginBottom:24,overflow:"hidden"}}><div style={{height:"100%",width:`${overallStats.pct}%`,background:`linear-gradient(90deg,${scoreBg(overallStats.pct)},${C.orange})`,borderRadius:4,transition:"width 0.6s"}}/></div>
      {/* Charts Row */}
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16,marginBottom:20}}>
        <Card title="Response Distribution">{respData.length>0?<ResponsiveContainer width="100%" height={220}><PieChart><Pie data={respData} cx="50%" cy="50%" innerRadius={45} outerRadius={75} dataKey="value" paddingAngle={3}>{respData.map((d,i)=><Cell key={i} fill={d.color}/>)}</Pie><Legend formatter={v=><span style={{color:C.textMuted,fontSize:12}}>{v}</span>}/></PieChart></ResponsiveContainer>:<Empty msg="No responses yet"/>}</Card>
        <Card title="Gap Severity">{sevData.length>0?<ResponsiveContainer width="100%" height={220}><BarChart data={sevData}><XAxis dataKey="name" tick={{fill:C.textMuted,fontSize:11}} axisLine={false} tickLine={false}/><YAxis tick={{fill:C.textMuted,fontSize:11}} axisLine={false} tickLine={false}/><Tooltip contentStyle={{background:C.sidebar,border:`1px solid ${C.border}`,borderRadius:8,color:C.text}}/><Bar dataKey="value" radius={[6,6,0,0]}>{sevData.map((d,i)=><Cell key={i} fill={d.color}/>)}</Bar></BarChart></ResponsiveContainer>:<Empty msg="No gaps found yet"/>}</Card>
      </div>
      {/* Domain Scores */}
      <Card title="Domain-wise Compliance">
        <div style={{display:"flex",flexDirection:"column",gap:10}}>
          {catScores.map((c,i) => (
            <div key={i} style={{display:"flex",alignItems:"center",gap:12}}>
              <span style={{fontSize:18,width:28}}>{c.icon}</span>
              <span style={{color:C.text,fontSize:13,fontWeight:600,width:220,flexShrink:0}}>{c.name}</span>
              <div style={{flex:1,height:8,background:C.bg,borderRadius:4,overflow:"hidden"}}><div style={{height:"100%",width:`${c.pct}%`,background:scoreBg(c.pct),borderRadius:4,transition:"width 0.4s"}}/></div>
              <span style={{color:scoreBg(c.pct),fontWeight:800,fontSize:14,width:45,textAlign:"right"}}>{c.pct}%</span>
              <span style={{color:C.textDim,fontSize:11,width:60}}>{c.answered}/{c.total}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>);
  }

  // ─── ASSESSMENT VIEW ───
  return (<div>
    {toast&&<Toast {...toast} onClose={()=>setToast(null)}/>}
    {/* Header */}
    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:16}}>
      <div>
        <h2 style={{margin:0,fontSize:22,fontWeight:800,color:C.text}}>Gap Assessment</h2>
        <p style={{color:C.textMuted,margin:"4px 0 0",fontSize:13}}>102 questions across 11 security domains • Smart conditional flow</p>
      </div>
      <div style={{display:"flex",gap:8}}>
        <Btn variant="secondary" size="sm" onClick={()=>setView("dashboard")}><Target size={14}/> Dashboard</Btn>
        <Btn variant="secondary" size="sm" onClick={exportAssessment}><Download size={14}/> Export</Btn>
        <Btn variant="danger" size="sm" onClick={()=>{if(confirm("Clear all responses?"))setData(d=>({...d,gapResponses:{}}));}}><Trash2 size={12}/> Reset</Btn>
      </div>
    </div>

    {/* Overall progress */}
    <div style={{display:"flex",gap:12,marginBottom:16,flexWrap:"wrap"}}>
      <div style={{background:C.card,borderRadius:10,border:`1px solid ${C.border}`,padding:"10px 16px",display:"flex",alignItems:"center",gap:10,flex:1,minWidth:160}}>
        <Target size={18} color={scoreBg(overallStats.pct)}/>
        <div><div style={{fontSize:11,color:C.textMuted,fontWeight:600}}>Overall Score</div><div style={{fontSize:20,fontWeight:800,color:scoreBg(overallStats.pct)}}>{overallStats.pct}%</div></div>
      </div>
      <div style={{background:C.card,borderRadius:10,border:`1px solid ${C.border}`,padding:"10px 16px",display:"flex",alignItems:"center",gap:10,flex:1,minWidth:160}}>
        <ClipboardCheck size={18} color={C.blue}/>
        <div><div style={{fontSize:11,color:C.textMuted,fontWeight:600}}>Assessed</div><div style={{fontSize:20,fontWeight:800,color:C.blue}}>{overallStats.answered}<span style={{fontSize:13,color:C.textDim,fontWeight:500}}>/{overallStats.total}</span></div></div>
      </div>
      <div style={{background:C.card,borderRadius:10,border:`1px solid ${C.border}`,padding:"10px 16px",display:"flex",alignItems:"center",gap:10,flex:1,minWidth:120}}>
        <CheckCircle size={18} color={C.green}/><div><div style={{fontSize:11,color:C.textMuted,fontWeight:600}}>Yes</div><div style={{fontSize:20,fontWeight:800,color:C.green}}>{overallStats.yesCount}</div></div>
      </div>
      <div style={{background:C.card,borderRadius:10,border:`1px solid ${C.border}`,padding:"10px 16px",display:"flex",alignItems:"center",gap:10,flex:1,minWidth:120}}>
        <XCircle size={18} color={C.red}/><div><div style={{fontSize:11,color:C.textMuted,fontWeight:600}}>No</div><div style={{fontSize:20,fontWeight:800,color:C.red}}>{overallStats.noCount}</div></div>
      </div>
      <div style={{background:C.card,borderRadius:10,border:`1px solid ${C.border}`,padding:"10px 16px",display:"flex",alignItems:"center",gap:10,flex:1,minWidth:120}}>
        <AlertCircle size={18} color={C.yellow}/><div><div style={{fontSize:11,color:C.textMuted,fontWeight:600}}>Partial</div><div style={{fontSize:20,fontWeight:800,color:C.yellow}}>{overallStats.partialCount}</div></div>
      </div>
    </div>

    {/* Category tabs */}
    <div style={{display:"flex",gap:4,marginBottom:16,overflowX:"auto",paddingBottom:4,background:C.card,borderRadius:10,padding:4}}>
      {GAP_CATS.map((cat,i) => {
        const sc = catScores[i];
        const active = activeCat === i;
        return <button key={i} onClick={()=>setActiveCat(i)} style={{display:"flex",alignItems:"center",gap:6,padding:"8px 14px",border:"none",borderRadius:8,cursor:"pointer",fontWeight:active?700:500,fontSize:12,whiteSpace:"nowrap",background:active?C.orange:"transparent",color:active?"#fff":C.textMuted,fontFamily:"inherit",transition:"all 0.15s"}}>
          <span style={{fontSize:15}}>{cat.icon}</span>
          <span>{cat.name.split(" ")[0]}</span>
          {sc.answered>0&&<span style={{fontSize:10,padding:"1px 6px",borderRadius:10,background:active?"rgba(255,255,255,0.2)":`${scoreBg(sc.pct)}22`,color:active?"#fff":scoreBg(sc.pct),fontWeight:700}}>{sc.pct}%</span>}
        </button>;
      })}
    </div>

    {/* Category info bar */}
    <div style={{display:"flex",alignItems:"center",gap:12,marginBottom:12,padding:"10px 16px",background:C.card,borderRadius:10,border:`1px solid ${C.border}`}}>
      <span style={{fontSize:24}}>{GAP_CATS[activeCat]?.icon}</span>
      <div style={{flex:1}}>
        <div style={{color:C.text,fontWeight:700,fontSize:15}}>{GAP_CATS[activeCat]?.name}</div>
        <div style={{color:C.textDim,fontSize:12}}>{GAP_CATS[activeCat]?.desc}</div>
      </div>
      <div style={{display:"flex",alignItems:"center",gap:8}}>
        <div style={{width:80,height:6,background:C.bg,borderRadius:3,overflow:"hidden"}}><div style={{height:"100%",width:`${catScores[activeCat]?.pct||0}%`,background:scoreBg(catScores[activeCat]?.pct||0),borderRadius:3}}/></div>
        <span style={{color:scoreBg(catScores[activeCat]?.pct||0),fontWeight:700,fontSize:13}}>{catScores[activeCat]?.pct||0}%</span>
        <Badge color={C.textMuted}>{catScores[activeCat]?.answered||0}/{catScores[activeCat]?.total||0}</Badge>
      </div>
    </div>

    {/* Search */}
    <div style={{position:"relative",marginBottom:16}}>
      <Search size={16} style={{position:"absolute",left:12,top:10,color:C.textDim}}/>
      <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search questions, Q#, ISO ref..." style={{width:"100%",padding:"8px 12px 8px 36px",background:C.card,border:`1px solid ${C.border}`,borderRadius:8,color:C.text,fontSize:13,fontFamily:"inherit"}}/>
    </div>

    {/* Question List */}
    <div style={{display:"flex",flexDirection:"column",gap:8}}>
      {catQs.map(q => {
        const {visible, reason} = evalTrigger(q.trigger, resp);
        const r = resp[q.id] || {};
        const evItems = parseEvItems(q.ev);
        const evCheckedCount = (r.evChecked||[]).length;
        const hasMultiSel = MULTI_SELECT[q.id];
        const qScore = scoreQ(r, q);

        if(!visible) {
          // Show hidden drill-downs as dimmed placeholder
          if(q.type === "DRILL-DOWN") return (
            <div key={q.id} style={{padding:"10px 16px",background:`${C.card}66`,borderRadius:10,border:`1px dashed ${C.border}44`,opacity:0.4,display:"flex",alignItems:"center",gap:10}}>
              <Badge color={typeColor[q.type]} bg={typeBg[q.type]}>{q.id}</Badge>
              <span style={{color:C.textDim,fontSize:12,fontStyle:"italic"}}>{reason} — {q.q.substring(0,60)}...</span>
            </div>
          );
          return null;
        }

        return (
          <div key={q.id} style={{background:C.card,borderRadius:12,border:`1px solid ${r.resp?`${respColor(r.resp)}44`:C.border}`,padding:16,transition:"all 0.2s"}}>
            {/* Question Header */}
            <div style={{display:"flex",alignItems:"flex-start",gap:10,marginBottom:10}}>
              <div style={{display:"flex",flexDirection:"column",gap:4,alignItems:"center",minWidth:44}}>
                <Badge color={typeColor[q.type]} bg={typeBg[q.type]}>{q.id}</Badge>
                <span style={{fontSize:9,color:typeColor[q.type],fontWeight:700}}>{q.type}</span>
              </div>
              <div style={{flex:1}}>
                <div style={{color:C.text,fontSize:14,fontWeight:600,lineHeight:1.5,marginBottom:6}}>{q.q}</div>
                <div style={{display:"flex",gap:6,flexWrap:"wrap",alignItems:"center"}}>
                  <Badge color={sevColor(q.sev)} bg={`${sevColor(q.sev)}18`}>{q.sev}</Badge>
                  <span style={{color:C.textDim,fontSize:11,fontFamily:"monospace"}}>{q.iso}</span>
                  {q.trigger !== "Ask all clients" && <span style={{color:C.textDim,fontSize:10,fontStyle:"italic"}}>⚡ {q.trigger}</span>}
                  {qScore !== null && <span style={{marginLeft:"auto",padding:"2px 8px",borderRadius:6,fontSize:11,fontWeight:700,background:`${scoreBg(qScore)}22`,color:scoreBg(qScore)}}>{qScore}%</span>}
                </div>
              </div>
            </div>

            {/* Response Buttons */}
            <div style={{display:"flex",gap:6,marginBottom:10,flexWrap:"wrap",alignItems:"center"}}>
              <span style={{color:C.textDim,fontSize:11,fontWeight:600,marginRight:4}}>Response:</span>
              {["Yes","No","Partial","N/A"].map(opt => (
                <button key={opt} onClick={()=>setResp(q.id, {resp: r.resp===opt?"":opt})} style={{padding:"5px 14px",borderRadius:8,border:`1px solid ${r.resp===opt?respColor(opt):C.border}`,background:r.resp===opt?`${respColor(opt)}22`:"transparent",color:r.resp===opt?respColor(opt):C.textMuted,fontSize:12,fontWeight:r.resp===opt?700:500,cursor:"pointer",fontFamily:"inherit",transition:"all 0.15s"}}>{opt}</button>
              ))}
            </div>

            {/* Multi-select chips for DISCOVERY questions */}
            {hasMultiSel && r.resp && r.resp !== "No" && r.resp !== "N/A" && (
              <div style={{marginBottom:10}}>
                <span style={{color:C.textDim,fontSize:11,fontWeight:600,display:"block",marginBottom:6}}>Select applicable options:</span>
                <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
                  {hasMultiSel.map(opt => {
                    const selected = (r.sel||[]).includes(opt);
                    return <button key={opt} onClick={()=>{
                      const curr = r.sel||[];
                      const next = selected ? curr.filter(s=>s!==opt) : [...curr, opt];
                      setResp(q.id, {sel: next});
                    }} style={{padding:"5px 12px",borderRadius:20,border:`1px solid ${selected?C.orange:C.border}`,background:selected?`${C.orange}22`:"transparent",color:selected?C.orange:C.textMuted,fontSize:12,fontWeight:selected?700:500,cursor:"pointer",fontFamily:"inherit",transition:"all 0.15s"}}>{selected?"✓ ":""}{opt}</button>;
                  })}
                </div>
              </div>
            )}

            {/* Evidence & Details — expandable on click */}
            {r.resp && r.resp !== "N/A" && (
              <div style={{display:"flex",gap:8,alignItems:"center"}}>
                <button onClick={()=>setDetailQ(detailQ===q.id?null:q.id)} style={{flex:1,display:"flex",alignItems:"center",gap:8,padding:"8px 12px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,cursor:"pointer",color:C.textMuted,fontSize:12,fontFamily:"inherit"}}>
                  <Paperclip size={13}/>
                  <span>Evidence: {evCheckedCount}/{evItems.length} items</span>
                  {evItems.length > 0 && <div style={{width:60,height:4,background:C.border,borderRadius:2,overflow:"hidden"}}><div style={{height:"100%",width:`${evItems.length>0?(evCheckedCount/evItems.length)*100:0}%`,background:evCheckedCount===evItems.length?C.green:C.yellow,borderRadius:2}}/></div>}
                  {(r.evFiles||[]).length > 0 && <Badge color={C.green}>{(r.evFiles||[]).length} files</Badge>}
                  <span style={{marginLeft:"auto",color:C.textDim}}>{detailQ===q.id?"▲":"▼"}</span>
                </button>
                <button onClick={()=>handleEvUpload(q.id)} style={{padding:"8px 12px",background:`${C.orange}22`,border:`1px solid ${C.orange}44`,borderRadius:8,cursor:"pointer",color:C.orange,fontSize:12,fontWeight:600,fontFamily:"inherit",display:"flex",alignItems:"center",gap:4}}><Upload size={12}/> Upload</button>
              </div>
            )}

            {/* Expanded Evidence Panel */}
            {detailQ===q.id && r.resp && r.resp !== "N/A" && (
              <div style={{marginTop:10,padding:14,background:C.bg,borderRadius:10,border:`1px solid ${C.border}`}}>
                {/* Evidence Checklist */}
                <div style={{marginBottom:12}}>
                  <div style={{color:C.textMuted,fontSize:11,fontWeight:700,marginBottom:8,textTransform:"uppercase"}}>Evidence Required</div>
                  {evItems.map((item, idx) => {
                    const checked = (r.evChecked||[]).includes(idx);
                    return <div key={idx} style={{display:"flex",alignItems:"flex-start",gap:8,padding:"6px 0",borderBottom:idx<evItems.length-1?`1px solid ${C.border}22`:"none"}}>
                      <button onClick={()=>{
                        const curr = r.evChecked||[];
                        const next = checked ? curr.filter(i=>i!==idx) : [...curr, idx];
                        setResp(q.id, {evChecked: next});
                      }} style={{width:20,height:20,borderRadius:6,border:`2px solid ${checked?C.green:C.border}`,background:checked?`${C.green}22`:"transparent",cursor:"pointer",display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0,marginTop:1}}>
                        {checked&&<CheckCircle size={12} color={C.green}/>}
                      </button>
                      <span style={{color:checked?C.text:C.textMuted,fontSize:12,lineHeight:1.5,textDecoration:checked?"none":"none"}}>{item}</span>
                    </div>;
                  })}
                </div>
                {/* Uploaded Files */}
                {(r.evFiles||[]).length > 0 && (
                  <div style={{marginBottom:12}}>
                    <div style={{color:C.textMuted,fontSize:11,fontWeight:700,marginBottom:6,textTransform:"uppercase"}}>Uploaded Files</div>
                    {(r.evFiles||[]).map((f,i)=>(
                      <div key={i} style={{display:"flex",alignItems:"center",gap:8,padding:"4px 0"}}>
                        <File size={12} color={C.green}/>
                        <a href={f.url} target="_blank" rel="noreferrer" style={{color:C.orange,fontSize:12,fontWeight:600,textDecoration:"none"}}>{f.name}</a>
                        <button onClick={()=>{const files=(r.evFiles||[]).filter((_,j)=>j!==i);setResp(q.id,{evFiles:files});}} style={{background:"none",border:"none",cursor:"pointer",color:C.red,padding:2}}><X size={10}/></button>
                      </div>
                    ))}
                    {/* Evidence Review Status */}
                    <div style={{marginTop:10,padding:10,borderRadius:8,border:`1px solid ${r.evStatus==="approved"?C.green:r.evStatus==="rejected"?C.red:C.blue}33`,background:r.evStatus==="approved"?`${C.green}11`:r.evStatus==="rejected"?`${C.red}11`:`${C.blue}11`}}>
                      <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",flexWrap:"wrap",gap:8}}>
                        <div style={{display:"flex",alignItems:"center",gap:6}}>
                          {r.evStatus==="approved"&&<><CheckCircle size={14} color={C.green}/><span style={{color:C.green,fontSize:12,fontWeight:700}}>Evidence Approved</span></>}
                          {r.evStatus==="rejected"&&<><AlertCircle size={14} color={C.red}/><span style={{color:C.red,fontSize:12,fontWeight:700}}>Evidence Rejected</span></>}
                          {(!r.evStatus||r.evStatus==="uploaded")&&<><Clock size={14} color={C.blue}/><span style={{color:C.blue,fontSize:12,fontWeight:700}}>Awaiting Review</span></>}
                          {r.evReviewedBy&&<span style={{color:C.textDim,fontSize:10,marginLeft:4}}>by {r.evReviewedBy} on {r.evReviewedAt?.slice(0,10)}</span>}
                        </div>
                        <div style={{display:"flex",gap:4}}>
                          {canDoApprove && (!r.evStatus||r.evStatus==="uploaded"||r.evStatus==="rejected") && (
                            <button onClick={()=>approveEvidence(q.id)} style={{padding:"5px 10px",borderRadius:6,background:`${C.green}22`,border:`1px solid ${C.green}44`,color:C.green,fontSize:11,fontWeight:700,cursor:"pointer",fontFamily:"inherit",display:"flex",alignItems:"center",gap:3}}><ThumbsUp size={11}/> Approve</button>
                          )}
                          {canDoApprove && (!r.evStatus||r.evStatus==="uploaded"||r.evStatus==="approved") && (
                            <button onClick={()=>{setRejectModal(q.id);setRejectComment("");}} style={{padding:"5px 10px",borderRadius:6,background:`${C.red}22`,border:`1px solid ${C.red}44`,color:C.red,fontSize:11,fontWeight:700,cursor:"pointer",fontFamily:"inherit",display:"flex",alignItems:"center",gap:3}}><ThumbsDown size={11}/> Reject</button>
                          )}
                        </div>
                      </div>
                      {r.evStatus==="rejected"&&r.evReviewComment&&<div style={{marginTop:6,color:C.red,fontSize:11}}>❌ Reason: {r.evReviewComment}</div>}
                    </div>
                  </div>
                )}
                {/* Drive Link */}
                <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:10}}>
                  <Link size={13} color={C.textDim}/>
                  <input value={r.driveLink||""} onChange={e=>setResp(q.id,{driveLink:e.target.value})} placeholder="Google Drive / OneDrive link..." style={{flex:1,padding:"6px 10px",background:C.card,border:`1px solid ${C.border}`,borderRadius:6,color:C.text,fontSize:12,fontFamily:"inherit"}}/>
                </div>
                {/* Notes */}
                <textarea value={r.notes||""} onChange={e=>setResp(q.id,{notes:e.target.value})} placeholder="Assessor notes..." rows={2} style={{width:"100%",padding:"8px 10px",background:C.card,border:`1px solid ${C.border}`,borderRadius:6,color:C.text,fontSize:12,fontFamily:"inherit",resize:"vertical"}}/>
                {/* Recommended Action */}
                {r.resp === "No" && q.act && (
                  <div style={{marginTop:10,padding:10,background:`${C.red}11`,borderRadius:8,border:`1px solid ${C.red}33`}}>
                    <div style={{color:C.red,fontSize:11,fontWeight:700,marginBottom:4}}>⚠️ RECOMMENDED ACTION</div>
                    <div style={{color:C.text,fontSize:12,lineHeight:1.5}}>{q.act}</div>
                  </div>
                )}
                {r.resp === "Partial" && q.act && (
                  <div style={{marginTop:10,padding:10,background:`${C.yellow}11`,borderRadius:8,border:`1px solid ${C.yellow}33`}}>
                    <div style={{color:C.yellow,fontSize:11,fontWeight:700,marginBottom:4}}>⚡ RECOMMENDED ACTION</div>
                    <div style={{color:C.text,fontSize:12,lineHeight:1.5}}>{q.act}</div>
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>

    {/* Gap Evidence Reject Modal */}
    <Modal open={!!rejectModal} onClose={()=>setRejectModal(null)} title="Reject Evidence">
      <div>
        <p style={{color:C.textMuted,fontSize:13,marginBottom:12}}>Provide a reason for rejection. This will be visible to the client.</p>
        <textarea value={rejectComment} onChange={e=>setRejectComment(e.target.value)} placeholder="Reason for rejection..." rows={3} style={{width:"100%",padding:"10px 12px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,color:C.text,fontSize:13,fontFamily:"inherit",resize:"vertical"}}/>
        <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:16}}>
          <Btn variant="secondary" onClick={()=>setRejectModal(null)}>Cancel</Btn>
          <Btn variant="danger" onClick={()=>rejectEvidence(rejectModal)}><ThumbsDown size={14}/> Reject</Btn>
        </div>
      </div>
    </Modal>
  </div>);
};
// =============================================
// RISK REGISTER — with Import/Export
// =============================================
const RISK_LIB = [
{rid:"RSK-AC-001",cat:"Access Control",title:"Unauthorized access due to weak password policies",desc:"Inadequate password complexity, length, or rotation requirements may allow attackers to compromise user credentials through brute-force or dictionary attacks.",dl:4,di:4,rating:"Critical",controls:["A.5.15", "A.5.16", "A.5.17", "A.8.5"],treat:"Implement strong password policy with MFA enforcement across all systems."},
{rid:"RSK-AC-002",cat:"Access Control",title:"Excessive user privileges",desc:"Users granted more access rights than required for their role, violating the principle of least privilege, potentially leading to unauthorized data access or modification.",dl:4,di:4,rating:"Critical",controls:["A.5.15", "A.5.18", "A.8.2"],treat:"Implement role-based access control (RBAC) with periodic access reviews."},
{rid:"RSK-AC-003",cat:"Access Control",title:"Orphaned accounts after employee departure",desc:"User accounts not deactivated or removed promptly after employee termination or role change, allowing continued unauthorized access.",dl:3,di:4,rating:"High",controls:["A.5.18", "A.6.1", "A.6.5"],treat:"Automate deprovisioning linked to HR offboarding; conduct monthly orphaned account reviews."},
{rid:"RSK-AC-004",cat:"Access Control",title:"Shared or generic account usage",desc:"Use of shared or generic accounts prevents individual accountability and makes it impossible to trace actions to specific users.",dl:3,di:3,rating:"Medium",controls:["A.5.16", "A.8.5"],treat:"Eliminate shared accounts; enforce unique credentials per user with audit logging."},
{rid:"RSK-AC-005",cat:"Access Control",title:"Lack of multi-factor authentication",desc:"Absence of MFA on critical systems and remote access points increases the risk of credential-based attacks.",dl:4,di:5,rating:"Critical",controls:["A.5.17", "A.8.5"],treat:"Deploy MFA for all external-facing services, privileged accounts, and VPN access."},
{rid:"RSK-AC-006",cat:"Access Control",title:"Unauthorized privileged access escalation",desc:"Users or attackers exploit misconfigurations or vulnerabilities to gain administrative or root-level access without authorization.",dl:3,di:5,rating:"High",controls:["A.8.2", "A.8.18", "A.8.5"],treat:"Implement PAM solutions, monitor privileged sessions, and restrict admin access."},
{rid:"RSK-AC-007",cat:"Access Control",title:"Insecure remote access",desc:"Remote access methods without proper encryption, authentication, or monitoring expose internal resources to external threats.",dl:3,di:4,rating:"High",controls:["A.5.14", "A.6.7", "A.8.5"],treat:"Enforce VPN with MFA for all remote access; implement zero-trust architecture."},
{rid:"RSK-AM-001",cat:"Asset Management",title:"Incomplete or inaccurate IT asset inventory",desc:"Failure to maintain a complete and up-to-date inventory of hardware, software, and information assets, leading to unmanaged and unprotected resources.",dl:4,di:3,rating:"High",controls:["A.5.9", "A.5.10", "A.5.11"],treat:"Deploy automated asset discovery tools; conduct quarterly asset audits."},
{rid:"RSK-AM-002",cat:"Asset Management",title:"Unauthorized use of personal devices (Shadow IT)",desc:"Employees using unapproved personal devices or software to process organizational data, bypassing security controls.",dl:4,di:3,rating:"High",controls:["A.5.9", "A.7.9", "A.8.1"],treat:"Implement BYOD policy with MDM; block unauthorized devices on the network."},
{rid:"RSK-AM-003",cat:"Asset Management",title:"Improper disposal of IT assets",desc:"Storage media or hardware not securely wiped or destroyed before disposal, leading to potential data leakage.",dl:3,di:4,rating:"High",controls:["A.5.10", "A.7.10", "A.7.14", "A.8.10"],treat:"Define media sanitization procedures; maintain certificates of destruction."},
{rid:"RSK-AM-004",cat:"Asset Management",title:"Uncontrolled use of removable media",desc:"USB drives and other removable media used without restriction can introduce malware or enable unauthorized data exfiltration.",dl:3,di:4,rating:"High",controls:["A.7.10", "A.8.12"],treat:"Disable USB ports via GPO; implement DLP for removable media; use encrypted drives only."},
{rid:"RSK-AM-005",cat:"Asset Management",title:"Unauthorized software installation",desc:"Users installing unapproved software that may contain vulnerabilities, backdoors, or licensing violations.",dl:3,di:3,rating:"Medium",controls:["A.5.9", "A.8.19", "A.8.32"],treat:"Implement application whitelisting; restrict local admin rights."},
{rid:"RSK-BC-001",cat:"Business Continuity",title:"Inadequate disaster recovery plan",desc:"Absence or insufficiency of disaster recovery plans leading to prolonged downtime during catastrophic events.",dl:2,di:5,rating:"High",controls:["A.5.29", "A.5.30", "A.8.13", "A.8.14"],treat:"Develop and test DR plan annually; define RTO/RPO for critical systems."},
{rid:"RSK-BC-002",cat:"Business Continuity",title:"Lack of tested backup and recovery procedures",desc:"Backups not regularly tested for integrity and recoverability, risking data loss during restoration events.",dl:3,di:5,rating:"High",controls:["A.8.13"],treat:"Schedule quarterly backup restoration tests; implement 3-2-1 backup strategy."},
{rid:"RSK-BC-003",cat:"Business Continuity",title:"Single point of failure in critical infrastructure",desc:"Critical systems or services dependent on a single component without redundancy, risking complete service disruption.",dl:3,di:5,rating:"High",controls:["A.5.30", "A.8.14"],treat:"Identify SPOFs; implement redundancy for critical network, server, and storage components."},
{rid:"RSK-BC-004",cat:"Business Continuity",title:"Ransomware attack causing operational disruption",desc:"Ransomware encrypting critical business data and systems, causing extended downtime and potential data loss.",dl:4,di:5,rating:"Critical",controls:["A.5.29", "A.8.7", "A.8.13"],treat:"Deploy EDR solutions; maintain immutable backups; develop ransomware response playbook."},
{rid:"RSK-BC-005",cat:"Business Continuity",title:"Absence of business impact analysis",desc:"Without a formal BIA, the organization cannot prioritize recovery of critical processes and allocate resources effectively.",dl:3,di:4,rating:"High",controls:["A.5.29", "A.5.30"],treat:"Conduct annual BIA; map critical business processes to supporting IT services."},
{rid:"RSK-CM-001",cat:"Change Management",title:"Uncontrolled changes to production systems",desc:"Changes deployed to production without formal approval, testing, or documentation, introducing instability or vulnerabilities.",dl:3,di:4,rating:"High",controls:["A.8.32", "A.8.9"],treat:"Implement formal change management process with CAB approval and rollback plans."},
{rid:"RSK-CM-002",cat:"Change Management",title:"Lack of segregation between development and production",desc:"Development, testing, and production environments not adequately separated, risking accidental data exposure or system corruption.",dl:3,di:4,rating:"High",controls:["A.8.31", "A.8.32"],treat:"Enforce environment segregation; restrict developer access to production data."},
{rid:"RSK-CM-003",cat:"Change Management",title:"Configuration drift across environments",desc:"System configurations diverging from approved baselines over time due to ad-hoc changes, creating security gaps.",dl:3,di:3,rating:"Medium",controls:["A.8.9", "A.8.32"],treat:"Use infrastructure-as-code and configuration management tools; conduct periodic baseline audits."},
{rid:"RSK-CS-001",cat:"Cloud Security",title:"Misconfigured cloud storage (public exposure)",desc:"Cloud storage buckets or containers inadvertently configured for public access, exposing sensitive organizational data.",dl:3,di:5,rating:"High",controls:["A.5.23", "A.8.11"],treat:"Enable cloud security posture management (CSPM); enforce private-by-default storage policies."},
{rid:"RSK-CS-002",cat:"Cloud Security",title:"Lack of visibility into cloud infrastructure",desc:"Insufficient monitoring and logging of cloud environment activities, impeding detection of unauthorized access or misconfigurations.",dl:3,di:4,rating:"High",controls:["A.5.23", "A.8.15", "A.8.16"],treat:"Enable cloud-native logging (CloudTrail, Azure Monitor); deploy SIEM integration."},
{rid:"RSK-CS-003",cat:"Cloud Security",title:"Insecure cloud IAM configurations",desc:"Overly permissive IAM roles, policies, or service accounts in cloud environments enabling lateral movement or privilege escalation.",dl:3,di:5,rating:"High",controls:["A.5.15", "A.5.23", "A.8.2"],treat:"Apply least-privilege IAM policies; audit cloud permissions quarterly; eliminate wildcard permissions."},
{rid:"RSK-CS-004",cat:"Cloud Security",title:"Data residency and sovereignty non-compliance",desc:"Cloud data stored in jurisdictions that violate regulatory or contractual requirements regarding data residency.",dl:2,di:4,rating:"Medium",controls:["A.5.23", "A.5.34"],treat:"Configure cloud region restrictions; verify provider compliance with data residency requirements."},
{rid:"RSK-CS-005",cat:"Cloud Security",title:"Shared responsibility model misunderstanding",desc:"Organization fails to implement its security responsibilities in the cloud shared responsibility model, leaving gaps in protection.",dl:3,di:4,rating:"High",controls:["A.5.23", "A.5.21"],treat:"Document shared responsibility matrix per cloud service; train teams on their obligations."},
{rid:"RSK-CO-001",cat:"Communications Security",title:"Unencrypted data in transit",desc:"Sensitive data transmitted over networks without encryption, susceptible to interception and eavesdropping.",dl:3,di:4,rating:"High",controls:["A.5.14", "A.8.24"],treat:"Enforce TLS 1.2+ for all data in transit; disable legacy protocols (SSLv3, TLS 1.0/1.1)."},
{rid:"RSK-CO-002",cat:"Communications Security",title:"Sensitive data leakage via email",desc:"Accidental or intentional transmission of confidential information via unprotected email channels.",dl:4,di:4,rating:"Critical",controls:["A.5.14", "A.8.12"],treat:"Deploy email DLP policies; enforce mandatory encryption for classified data; train users."},
{rid:"RSK-CO-003",cat:"Communications Security",title:"Insecure use of messaging and collaboration platforms",desc:"Confidential data shared over unauthorized or improperly configured messaging platforms (Slack, WhatsApp, etc.).",dl:3,di:3,rating:"Medium",controls:["A.5.14", "A.5.10"],treat:"Define approved communication channels; configure DLP on collaboration tools."},
{rid:"RSK-CO-004",cat:"Communications Security",title:"Information leakage through metadata",desc:"Documents and files containing embedded metadata (author names, revision history, GPS data) inadvertently disclosing sensitive information.",dl:2,di:3,rating:"Medium",controls:["A.5.14", "A.8.12"],treat:"Implement metadata scrubbing tools before external sharing; train staff on metadata risks."},
{rid:"RSK-CL-001",cat:"Compliance & Legal",title:"Non-compliance with regulatory requirements",desc:"Failure to identify and comply with applicable legal, regulatory, and contractual information security requirements.",dl:3,di:5,rating:"High",controls:["A.5.31", "A.5.32", "A.5.34"],treat:"Maintain a legal/regulatory register; conduct annual compliance gap assessments."},
{rid:"RSK-CL-002",cat:"Compliance & Legal",title:"Inadequate management of intellectual property rights",desc:"Failure to protect organizational IP or inadvertent use of third-party IP without appropriate licenses.",dl:2,di:4,rating:"Medium",controls:["A.5.32"],treat:"Maintain software license inventory; include IP clauses in employee and vendor contracts."},
{rid:"RSK-CL-003",cat:"Compliance & Legal",title:"Failure to maintain audit trails for compliance",desc:"Insufficient or tampered audit logs that cannot satisfy regulatory or legal evidence requirements.",dl:3,di:4,rating:"High",controls:["A.5.33", "A.8.15", "A.8.17"],treat:"Implement tamper-proof centralized logging; define log retention per compliance requirements."},
{rid:"RSK-CL-004",cat:"Compliance & Legal",title:"Expired or inadequate contractual security clauses",desc:"Contracts with clients, partners, or vendors lacking appropriate information security, confidentiality, and data protection clauses.",dl:3,di:4,rating:"High",controls:["A.5.31", "A.5.34", "A.5.20"],treat:"Review all contracts for security clauses; develop standard contractual security requirements."},
{rid:"RSK-CR-001",cat:"Cryptography",title:"Use of weak or deprecated encryption algorithms",desc:"Employment of outdated cryptographic algorithms (DES, MD5, SHA-1, RC4) that are vulnerable to known attacks.",dl:3,di:4,rating:"High",controls:["A.8.24"],treat:"Enforce AES-256, SHA-256+ minimum standards; deprecate legacy algorithms; maintain crypto policy."},
{rid:"RSK-CR-002",cat:"Cryptography",title:"Poor cryptographic key management",desc:"Encryption keys stored insecurely, not rotated, or shared inappropriately, compromising the effectiveness of encryption.",dl:3,di:5,rating:"High",controls:["A.8.24"],treat:"Implement KMS/HSM; define key lifecycle (generation, rotation, revocation, destruction)."},
{rid:"RSK-CR-003",cat:"Cryptography",title:"Unencrypted data at rest",desc:"Sensitive data stored on servers, databases, or endpoints without encryption, vulnerable to theft if physical or logical controls fail.",dl:3,di:4,rating:"High",controls:["A.8.24", "A.8.11"],treat:"Enable full-disk encryption on endpoints; encrypt sensitive database fields and backup data."},
{rid:"RSK-CR-004",cat:"Cryptography",title:"Hard-coded secrets and API keys in source code",desc:"Cryptographic keys, passwords, or API tokens embedded directly in application source code or configuration files.",dl:4,di:4,rating:"Critical",controls:["A.8.24", "A.8.4", "A.8.28"],treat:"Use secrets management tools (Vault, AWS Secrets Manager); scan repos for exposed secrets."},
{rid:"RSK-DP-001",cat:"Data Protection & Privacy",title:"Unauthorized processing of personal data",desc:"Personal data processed without lawful basis, appropriate consent, or beyond the stated purpose of collection.",dl:3,di:5,rating:"High",controls:["A.5.34", "A.5.31"],treat:"Maintain data processing register; conduct DPIA for high-risk processing activities."},
{rid:"RSK-DP-002",cat:"Data Protection & Privacy",title:"Excessive data collection and retention",desc:"Collecting more personal or business data than necessary and retaining it beyond defined periods, increasing exposure risk.",dl:3,di:3,rating:"Medium",controls:["A.5.34", "A.5.33"],treat:"Implement data minimization; define and enforce retention schedules; automate data purging."},
{rid:"RSK-DP-003",cat:"Data Protection & Privacy",title:"Unauthorized cross-border data transfer",desc:"Personal or sensitive data transferred to jurisdictions without adequate data protection safeguards.",dl:2,di:5,rating:"High",controls:["A.5.34", "A.5.14"],treat:"Map data flows; implement standard contractual clauses; verify adequacy of destination jurisdictions."},
{rid:"RSK-DP-004",cat:"Data Protection & Privacy",title:"Lack of data masking in non-production environments",desc:"Production data containing PII used in development, testing, or training environments without anonymization.",dl:3,di:4,rating:"High",controls:["A.8.11", "A.8.33", "A.8.31"],treat:"Implement data masking/anonymization for all non-production environments."},
{rid:"RSK-DP-005",cat:"Data Protection & Privacy",title:"Inability to fulfil data subject rights requests",desc:"Lack of processes or technical capability to respond to data access, rectification, erasure, or portability requests within mandated timelines.",dl:3,di:4,rating:"High",controls:["A.5.34", "A.5.31"],treat:"Implement automated DSR workflows; maintain data mapping to locate all data subject records."},
{rid:"RSK-EP-001",cat:"Endpoint Security",title:"Endpoints without anti-malware protection",desc:"Workstations or servers lacking endpoint detection and response (EDR) or anti-malware solutions, vulnerable to malware infections.",dl:3,di:4,rating:"High",controls:["A.8.1", "A.8.7"],treat:"Deploy EDR on all endpoints; ensure real-time signature and behavioral detection is enabled."},
{rid:"RSK-EP-002",cat:"Endpoint Security",title:"Unpatched operating systems and software",desc:"Endpoints running outdated OS or software versions with known vulnerabilities that have not been patched.",dl:4,di:4,rating:"Critical",controls:["A.8.8", "A.8.19"],treat:"Implement automated patch management with SLA-based patching (critical: 72hrs, high: 7 days)."},
{rid:"RSK-EP-003",cat:"Endpoint Security",title:"Loss or theft of mobile devices and laptops",desc:"Portable devices containing organizational data being lost or stolen, leading to potential data exposure.",dl:3,di:4,rating:"High",controls:["A.7.9", "A.8.1", "A.8.24"],treat:"Enforce full-disk encryption; deploy remote wipe capability; train staff on device security."},
{rid:"RSK-EP-004",cat:"Endpoint Security",title:"Disabled or misconfigured endpoint firewalls",desc:"Host-based firewalls disabled or improperly configured on endpoints, allowing unauthorized network connections.",dl:3,di:3,rating:"Medium",controls:["A.8.1", "A.8.20"],treat:"Enforce host firewall via GPO; monitor compliance through endpoint management tools."},
{rid:"RSK-HR-001",cat:"Human Resource Security",title:"Insufficient background verification for new hires",desc:"Employees granted access to sensitive systems without adequate background screening, increasing insider threat risk.",dl:2,di:4,rating:"Medium",controls:["A.6.1"],treat:"Conduct background checks proportional to role sensitivity; include in onboarding process."},
{rid:"RSK-HR-002",cat:"Human Resource Security",title:"Lack of security awareness training",desc:"Employees not trained on information security policies, phishing threats, and safe computing practices.",dl:4,di:4,rating:"Critical",controls:["A.6.3"],treat:"Conduct mandatory quarterly security awareness training; run phishing simulations monthly."},
{rid:"RSK-HR-003",cat:"Human Resource Security",title:"Social engineering and phishing attacks",desc:"Employees manipulated through phishing, vishing, or pretexting to disclose credentials or sensitive information.",dl:4,di:4,rating:"Critical",controls:["A.6.3", "A.5.14"],treat:"Deploy email security gateways; conduct phishing simulations; train staff on social engineering red flags."},
{rid:"RSK-HR-004",cat:"Human Resource Security",title:"Insider threat from disgruntled employees",desc:"Current or departing employees with malicious intent exploiting their access to sabotage systems or exfiltrate data.",dl:2,di:5,rating:"High",controls:["A.6.1", "A.6.2", "A.6.5", "A.5.15"],treat:"Implement UBA/UEBA; monitor high-risk user activity; enforce access revocation on termination."},
{rid:"RSK-HR-005",cat:"Human Resource Security",title:"Absence of confidentiality and NDA agreements",desc:"Employees and contractors not bound by confidentiality agreements, limiting legal recourse in case of information disclosure.",dl:2,di:4,rating:"Medium",controls:["A.6.1", "A.6.2", "A.6.6"],treat:"Include NDA/confidentiality clauses in all employment and contractor contracts."},
{rid:"RSK-HR-006",cat:"Human Resource Security",title:"Inadequate security responsibilities in job descriptions",desc:"Information security responsibilities not clearly defined in job roles and performance criteria.",dl:3,di:2,rating:"Medium",controls:["A.6.1", "A.6.2"],treat:"Include security responsibilities in all JDs; factor security compliance into performance reviews."},
{rid:"RSK-IM-001",cat:"Incident Management",title:"Lack of formal incident response plan",desc:"No documented incident response procedures, leading to delayed and uncoordinated response during security incidents.",dl:3,di:5,rating:"High",controls:["A.5.24", "A.5.25", "A.5.26"],treat:"Develop and maintain IRP with defined roles, escalation paths, and communication templates."},
{rid:"RSK-IM-002",cat:"Incident Management",title:"Delayed incident detection and response",desc:"Security incidents not detected or responded to in a timely manner due to inadequate monitoring or unclear escalation procedures.",dl:3,di:5,rating:"High",controls:["A.5.24", "A.5.25", "A.8.15", "A.8.16"],treat:"Implement SIEM with automated alerting; define SLA-based response times by severity."},
{rid:"RSK-IM-003",cat:"Incident Management",title:"Failure to learn from security incidents",desc:"Post-incident reviews not conducted or lessons learned not incorporated into preventive measures.",dl:3,di:3,rating:"Medium",controls:["A.5.27"],treat:"Mandate post-incident reviews within 2 weeks; track corrective actions to closure."},
{rid:"RSK-IM-004",cat:"Incident Management",title:"Inadequate evidence collection and preservation",desc:"Digital evidence not properly collected or preserved during incidents, compromising forensic investigations and legal proceedings.",dl:3,di:4,rating:"High",controls:["A.5.28"],treat:"Train IR team on evidence preservation; maintain forensic toolkits; document chain of custody."},
{rid:"RSK-IM-005",cat:"Incident Management",title:"Under-reporting of security events",desc:"Security events and near-misses not reported by employees due to fear of blame or unclear reporting channels.",dl:4,di:3,rating:"High",controls:["A.6.8", "A.5.24"],treat:"Establish no-blame reporting culture; simplify reporting channels; incentivize reporting."},
{rid:"RSK-IC-001",cat:"Information Classification",title:"Lack of data classification scheme",desc:"Information not classified by sensitivity level, leading to inconsistent protection and potential over- or under-protection.",dl:3,di:3,rating:"Medium",controls:["A.5.12", "A.5.13"],treat:"Define classification levels (Public, Internal, Confidential, Restricted); label all assets accordingly."},
{rid:"RSK-IC-002",cat:"Information Classification",title:"Mislabeled or unlabeled sensitive information",desc:"Sensitive documents and data not properly labeled, leading to inadvertent sharing or inadequate protection.",dl:3,di:4,rating:"High",controls:["A.5.13", "A.8.12"],treat:"Implement automated classification tools; mandate labeling in document templates."},
{rid:"RSK-IC-003",cat:"Information Classification",title:"Inadequate handling of confidential information",desc:"Confidential information handled without appropriate safeguards during storage, transfer, or printing.",dl:3,di:4,rating:"High",controls:["A.5.10", "A.5.12", "A.5.13"],treat:"Define handling procedures per classification level; implement secure print and transfer mechanisms."},
{rid:"RSK-LM-001",cat:"Logging & Monitoring",title:"Insufficient logging of security events",desc:"Critical security events not logged or log detail insufficient for incident investigation and compliance.",dl:3,di:4,rating:"High",controls:["A.8.15"],treat:"Define logging requirements per system type; capture authentication, access, and change events."},
{rid:"RSK-LM-002",cat:"Logging & Monitoring",title:"Log tampering or deletion",desc:"Audit logs vulnerable to unauthorized modification or deletion, undermining their integrity for investigations.",dl:2,di:5,rating:"High",controls:["A.8.15", "A.8.17"],treat:"Centralize logs to WORM storage; restrict log access to security team; monitor log integrity."},
{rid:"RSK-LM-003",cat:"Logging & Monitoring",title:"Absence of real-time security monitoring",desc:"No active monitoring or alerting system in place to detect security anomalies and potential breaches in real-time.",dl:3,di:5,rating:"High",controls:["A.8.16"],treat:"Deploy SIEM with correlation rules; implement 24/7 monitoring or managed SOC service."},
{rid:"RSK-LM-004",cat:"Logging & Monitoring",title:"Inadequate time synchronization across systems",desc:"Systems not synchronized to a common time source, making event correlation across logs unreliable.",dl:2,di:3,rating:"Medium",controls:["A.8.17"],treat:"Configure NTP across all systems; verify synchronization monthly."},
{rid:"RSK-LM-005",cat:"Logging & Monitoring",title:"Insufficient log retention",desc:"Logs retained for periods shorter than regulatory or organizational requirements, losing critical evidence.",dl:3,di:4,rating:"High",controls:["A.8.15", "A.5.33"],treat:"Define log retention per compliance needs (min 1 year); implement tiered storage for cost efficiency."},
{rid:"RSK-NS-001",cat:"Network Security",title:"Lack of network segmentation",desc:"Flat network architecture without segmentation allowing lateral movement once an attacker gains initial access.",dl:3,di:5,rating:"High",controls:["A.8.20", "A.8.22"],treat:"Implement VLANs and micro-segmentation; isolate critical assets and restrict inter-segment traffic."},
{rid:"RSK-NS-002",cat:"Network Security",title:"Unprotected wireless networks",desc:"Wi-Fi networks using weak encryption (WEP/WPA) or lacking proper authentication, enabling unauthorized access.",dl:3,di:4,rating:"High",controls:["A.8.20", "A.8.21"],treat:"Enforce WPA3-Enterprise with RADIUS; isolate guest Wi-Fi; disable SSID broadcast for internal."},
{rid:"RSK-NS-003",cat:"Network Security",title:"Inadequate firewall rule management",desc:"Firewall rules overly permissive, outdated, or not reviewed regularly, allowing unauthorized traffic flows.",dl:3,di:4,rating:"High",controls:["A.8.20", "A.8.22"],treat:"Conduct quarterly firewall rule reviews; implement deny-by-default; document all rule justifications."},
{rid:"RSK-NS-004",cat:"Network Security",title:"DNS-based attacks (spoofing, tunneling)",desc:"DNS infrastructure exploited for cache poisoning, spoofing, or covert data exfiltration through DNS tunneling.",dl:2,di:4,rating:"Medium",controls:["A.8.20", "A.8.23"],treat:"Implement DNSSEC; deploy DNS monitoring and anomaly detection; use DNS filtering services."},
{rid:"RSK-NS-005",cat:"Network Security",title:"DDoS attack on public-facing services",desc:"Distributed denial-of-service attacks overwhelming network bandwidth or application resources, causing service outage.",dl:3,di:4,rating:"High",controls:["A.8.20", "A.8.6"],treat:"Deploy DDoS mitigation service (CloudFlare, AWS Shield); implement rate limiting and traffic scrubbing."},
{rid:"RSK-NS-006",cat:"Network Security",title:"Exposed management interfaces",desc:"Administrative interfaces of network devices, servers, or applications accessible from untrusted networks.",dl:3,di:5,rating:"High",controls:["A.8.20", "A.8.9"],treat:"Restrict management access to dedicated management VLANs; require VPN + MFA for admin access."},
{rid:"RSK-OS-001",cat:"Operations Security",title:"Lack of documented operating procedures",desc:"IT operational procedures not documented or outdated, leading to inconsistent and error-prone operations.",dl:3,di:3,rating:"Medium",controls:["A.5.37"],treat:"Document all critical operational procedures; review and update annually; train operations staff."},
{rid:"RSK-OS-002",cat:"Operations Security",title:"Insufficient capacity management",desc:"System resources not monitored or planned for growth, risking performance degradation or outages during peak loads.",dl:3,di:3,rating:"Medium",controls:["A.8.6"],treat:"Implement resource monitoring and alerting; conduct annual capacity planning reviews."},
{rid:"RSK-OS-003",cat:"Operations Security",title:"Use of end-of-life software and systems",desc:"Operating systems, applications, or hardware past vendor support end-of-life, no longer receiving security patches.",dl:3,di:4,rating:"High",controls:["A.8.8", "A.5.9"],treat:"Maintain EOL inventory; plan migrations; apply compensating controls for legacy systems."},
{rid:"RSK-PS-001",cat:"Physical Security",title:"Unauthorized physical access to server rooms",desc:"Server rooms or data centers accessible without proper authentication, enabling theft, tampering, or sabotage.",dl:2,di:5,rating:"High",controls:["A.7.1", "A.7.2", "A.7.3", "A.7.4"],treat:"Implement biometric/card access; maintain access logs; install CCTV with 90-day retention."},
{rid:"RSK-PS-002",cat:"Physical Security",title:"Tailgating into secure areas",desc:"Unauthorized individuals following authorized personnel into restricted areas by exploiting door-holding courtesy.",dl:3,di:3,rating:"Medium",controls:["A.7.1", "A.7.2"],treat:"Install anti-tailgating turnstiles or mantraps; train staff on tailgating risks; conduct audits."},
{rid:"RSK-PS-003",cat:"Physical Security",title:"Inadequate environmental controls",desc:"Server rooms lacking proper temperature, humidity, fire suppression, or flood protection, risking hardware failure.",dl:2,di:5,rating:"High",controls:["A.7.5", "A.7.12"],treat:"Install environmental monitoring with alerts; deploy fire suppression and water leak detection."},
{rid:"RSK-PS-004",cat:"Physical Security",title:"Power supply failure or instability",desc:"Electrical power interruptions or fluctuations causing system downtime or hardware damage.",dl:3,di:4,rating:"High",controls:["A.7.11"],treat:"Install UPS for critical systems; deploy generator backup; test power failover quarterly."},
{rid:"RSK-PS-005",cat:"Physical Security",title:"Unsecured cabling infrastructure",desc:"Network and power cabling not physically protected, vulnerable to interception, disconnection, or damage.",dl:2,di:3,rating:"Medium",controls:["A.7.12"],treat:"Route cables through secured conduits; label and document cabling; restrict access to cable rooms."},
{rid:"RSK-PS-006",cat:"Physical Security",title:"Unattended equipment in public areas",desc:"Laptops, documents, or devices left unattended in public or shared spaces, vulnerable to theft or shoulder surfing.",dl:3,di:3,rating:"Medium",controls:["A.7.7", "A.7.9", "A.8.1"],treat:"Enforce clear desk/clear screen policy; deploy cable locks; auto-lock screens after 5 minutes."},
{rid:"RSK-PS-007",cat:"Physical Security",title:"Lack of visitor management controls",desc:"Visitors not properly registered, escorted, or monitored while on premises, posing risk of unauthorized access.",dl:3,di:3,rating:"Medium",controls:["A.7.2", "A.7.6"],treat:"Implement visitor registration system; mandatory escort in restricted areas; visitor badges."},
{rid:"RSK-RG-001",cat:"Risk Management & Governance",title:"Lack of defined information security policy",desc:"No formal information security policy approved by management, leaving security objectives and responsibilities unclear.",dl:2,di:4,rating:"Medium",controls:["A.5.1"],treat:"Develop and publish ISMS policy; obtain top management approval; review annually."},
{rid:"RSK-RG-002",cat:"Risk Management & Governance",title:"Insufficient management commitment to ISMS",desc:"Top management not actively supporting the ISMS through resource allocation, reviews, and visible commitment.",dl:3,di:4,rating:"High",controls:["A.5.1", "A.5.2", "A.5.4"],treat:"Schedule quarterly management reviews; include security KPIs in board reporting."},
{rid:"RSK-RG-003",cat:"Risk Management & Governance",title:"Unclear information security roles and responsibilities",desc:"Security roles not clearly defined or communicated, leading to gaps in accountability and ownership.",dl:3,di:3,rating:"Medium",controls:["A.5.2", "A.5.3"],treat:"Define RACI matrix for security functions; document in policy; communicate organization-wide."},
{rid:"RSK-RG-004",cat:"Risk Management & Governance",title:"Absence of systematic risk assessment process",desc:"No formal methodology for identifying, analyzing, and evaluating information security risks on a regular basis.",dl:3,di:4,rating:"High",controls:["A.5.1"],treat:"Adopt risk assessment methodology (ISO 27005); conduct assessments annually and on major changes."},
{rid:"RSK-RG-005",cat:"Risk Management & Governance",title:"Non-compliance with internal ISMS policies",desc:"Employees and departments not adhering to established ISMS policies and procedures.",dl:3,di:3,rating:"Medium",controls:["A.5.4", "A.5.36"],treat:"Conduct periodic compliance audits; implement disciplinary process for violations; track remediation."},
{rid:"RSK-SD-001",cat:"Software Development Security",title:"Injection vulnerabilities (SQL, XSS, Command)",desc:"Application code vulnerable to injection attacks due to insufficient input validation and parameterization.",dl:4,di:5,rating:"Critical",controls:["A.8.25", "A.8.26", "A.8.28"],treat:"Implement parameterized queries; deploy WAF; conduct SAST/DAST in CI/CD pipeline."},
{rid:"RSK-SD-002",cat:"Software Development Security",title:"Insecure third-party libraries and dependencies",desc:"Applications using open-source or third-party components with known vulnerabilities or compromised supply chains.",dl:4,di:4,rating:"Critical",controls:["A.8.25", "A.8.28"],treat:"Implement SCA tools (Snyk, Dependabot); maintain SBOM; enforce dependency review in CI/CD."},
{rid:"RSK-SD-003",cat:"Software Development Security",title:"Lack of secure coding practices",desc:"Developers not following secure coding standards, introducing vulnerabilities during software development.",dl:3,di:4,rating:"High",controls:["A.8.25", "A.8.28"],treat:"Adopt OWASP secure coding guidelines; provide annual secure coding training; enforce code review."},
{rid:"RSK-SD-004",cat:"Software Development Security",title:"Insecure API design and implementation",desc:"APIs lacking proper authentication, authorization, rate limiting, or input validation, exposing backend systems.",dl:3,di:4,rating:"High",controls:["A.8.25", "A.8.26"],treat:"Follow OWASP API Security Top 10; implement API gateway; enforce OAuth 2.0/JWT authentication."},
{rid:"RSK-SD-005",cat:"Software Development Security",title:"Insufficient security testing before release",desc:"Applications deployed without adequate security testing (penetration testing, code review, DAST/SAST).",dl:3,di:4,rating:"High",controls:["A.8.29", "A.8.33"],treat:"Integrate SAST/DAST into CI/CD; mandate penetration testing for major releases."},
{rid:"RSK-SD-006",cat:"Software Development Security",title:"Insecure session management",desc:"Session tokens not properly generated, validated, or expired, allowing session hijacking or fixation attacks.",dl:3,di:4,rating:"High",controls:["A.8.25", "A.8.5"],treat:"Use cryptographically random session tokens; implement session timeout and secure cookie flags."},
{rid:"RSK-SD-007",cat:"Software Development Security",title:"Unprotected source code repositories",desc:"Source code repositories without proper access controls, allowing unauthorized access, modification, or leakage of proprietary code.",dl:3,di:4,rating:"High",controls:["A.8.4", "A.8.25"],treat:"Enforce RBAC on repos; enable branch protection; audit access regularly; scan for secrets."},
{rid:"RSK-ST-001",cat:"Supplier & Third-Party Management",title:"Insufficient vendor security assessment",desc:"Third-party vendors not assessed for security posture before onboarding, potentially introducing supply chain risks.",dl:3,di:4,rating:"High",controls:["A.5.19", "A.5.20", "A.5.21"],treat:"Implement vendor security assessment questionnaire; require SOC 2/ISO 27001 for critical vendors."},
{rid:"RSK-ST-002",cat:"Supplier & Third-Party Management",title:"Lack of ongoing vendor monitoring",desc:"Third-party risk not monitored post-onboarding, missing emerging threats from vendor security degradation.",dl:3,di:4,rating:"High",controls:["A.5.22"],treat:"Conduct annual vendor re-assessments; monitor vendor security ratings; define vendor SLAs."},
{rid:"RSK-ST-003",cat:"Supplier & Third-Party Management",title:"Supply chain attack on software providers",desc:"Compromise of a software vendor's update or distribution mechanism, delivering malicious code to the organization.",dl:2,di:5,rating:"High",controls:["A.5.21", "A.8.25"],treat:"Verify update integrity (code signing); limit auto-updates; monitor vendor advisories."},
{rid:"RSK-ST-004",cat:"Supplier & Third-Party Management",title:"Excessive data sharing with third parties",desc:"Sharing more data with vendors or partners than necessary for service delivery, expanding the attack surface.",dl:3,di:4,rating:"High",controls:["A.5.19", "A.5.20", "A.5.14"],treat:"Apply data minimization with vendors; define data sharing boundaries in contracts; audit data flows."},
{rid:"RSK-ST-005",cat:"Supplier & Third-Party Management",title:"Vendor lock-in and exit planning deficiency",desc:"Over-dependence on a single vendor without contingency or exit plans, risking continuity if the vendor fails.",dl:2,di:4,rating:"Medium",controls:["A.5.19", "A.5.23"],treat:"Define vendor exit strategies; ensure data portability; maintain alternative vendor shortlists."},
{rid:"RSK-TV-001",cat:"Threat Intelligence & Vulnerability Management",title:"Lack of vulnerability management program",desc:"No systematic process for identifying, evaluating, and remediating vulnerabilities across the IT infrastructure.",dl:3,di:4,rating:"High",controls:["A.8.8"],treat:"Implement regular vulnerability scanning (weekly/monthly); define SLA-based remediation timelines."},
{rid:"RSK-TV-002",cat:"Threat Intelligence & Vulnerability Management",title:"Exploitation of known unpatched vulnerabilities",desc:"Publicly known vulnerabilities remaining unpatched beyond acceptable windows, exploited by attackers using available exploits.",dl:4,di:5,rating:"Critical",controls:["A.8.8", "A.8.19"],treat:"Track CVEs; prioritize patching by CVSS/EPSS; patch critical vulns within 72 hours."},
{rid:"RSK-TV-003",cat:"Threat Intelligence & Vulnerability Management",title:"No threat intelligence integration",desc:"Organization not consuming or acting upon relevant threat intelligence, missing advance warning of targeted attacks.",dl:3,di:3,rating:"Medium",controls:["A.5.7"],treat:"Subscribe to threat intelligence feeds (CERT-In, industry ISACs); integrate IOCs into SIEM."},
{rid:"RSK-TV-004",cat:"Threat Intelligence & Vulnerability Management",title:"Lack of penetration testing",desc:"No regular penetration testing conducted to validate security controls and identify exploitable weaknesses.",dl:3,di:4,rating:"High",controls:["A.8.8", "A.8.34"],treat:"Conduct annual VAPT; perform quarterly web app assessments; retest after remediation."},
{rid:"RSK-TV-005",cat:"Threat Intelligence & Vulnerability Management",title:"Zero-day exploit targeting critical systems",desc:"Previously unknown vulnerabilities exploited before patches are available, bypassing traditional defenses.",dl:2,di:5,rating:"High",controls:["A.5.7", "A.8.7", "A.8.16"],treat:"Deploy behavioral detection (EDR/XDR); implement network microsegmentation; maintain virtual patching."},
{rid:"RSK-TV-006",cat:"Threat Intelligence & Vulnerability Management",title:"Web application vulnerabilities (OWASP Top 10)",desc:"Web applications vulnerable to common attack vectors including broken access control, cryptographic failures, and SSRF.",dl:4,di:4,rating:"Critical",controls:["A.8.25", "A.8.26", "A.8.28"],treat:"Deploy WAF; conduct regular DAST scans; train developers on OWASP Top 10 mitigations."}
];

const RISK_CATS = ["Access Control", "Asset Management", "Business Continuity", "Change Management", "Cloud Security", "Communications Security", "Compliance & Legal", "Cryptography", "Data Protection & Privacy", "Endpoint Security", "Human Resource Security", "Incident Management", "Information Classification", "Logging & Monitoring", "Network Security", "Operations Security", "Physical Security", "Risk Management & Governance", "Software Development Security", "Supplier & Third-Party Management", "Threat Intelligence & Vulnerability Management"];


const RiskRegister = ({data,setData,role:userRole,members:allMembers,orgId}) => {
  const [tab,setTab]=useState("library");
  const [modal,setModal]=useState(null);
  const [toast,setToast]=useState(null);
  const [importing,setImporting]=useState(false);
  const [catFilter,setCatFilter]=useState("All");
  const [search,setSearch]=useState("");
  const [ratingFilter,setRatingFilter]=useState("All");

  const {token,user}=useAuth();
  const isAdmin=["super_admin","employee","client_admin"].includes(userRole);
  const isEmployee=userRole==="client_employee";

  const blank={id:"",risk_name:"",description:"",impact:3,likelihood:3,mitigations:"",owner:"",linked_control:"",remarks:"",disabled:false,treatment:"Mitigate",mitigation_steps:"",transfer_to:"",source:"custom",category:"",annex_a_controls:[],assigned_to:[]};
  const rl=(i,l)=>{const v=i*l;if(v>=16)return{label:"Critical",color:C.red};if(v>=10)return{label:"High",color:C.orange};if(v>=5)return{label:"Medium",color:C.yellow};return{label:"Low",color:C.green};};

  // Check if library is loaded
  const libraryLoaded=(data.risks||[]).some(r=>r.source==="library");
  const libraryCount=(data.risks||[]).filter(r=>r.source==="library").length;

  // Load standard risk library
  const loadLibrary=()=>{
    const existing=new Set((data.risks||[]).filter(r=>r.source==="library").map(r=>r.risk_id));
    const newRisks=RISK_LIB.filter(r=>!existing.has(r.rid)).map(r=>({
      id:secureId('r'),risk_id:r.rid,risk_name:r.title,description:r.desc,category:r.cat,
      impact:r.di,likelihood:r.dl,risk_rating:r.rating,annex_a_controls:r.controls,
      treatment_suggestion:r.treat,mitigations:r.treat,owner:"",
      linked_control:r.controls.join(", "),remarks:"",disabled:false,
      treatment:"Mitigate",mitigation_steps:r.treat,transfer_to:"",
      source:"library",assigned_to:[],
    }));
    setData(d=>({...d,risks:[...d.risks,...newRisks]}));
    setToast({msg:`${newRisks.length} standard risks loaded from ISO 27001 library!`,type:"success"});
  };

  // Core CRUD
  const saveRisk=(r)=>{
    if(r.id){setData(d=>({...d,risks:d.risks.map(x=>x.id===r.id?r:x)}));}
    else{setData(d=>({...d,risks:[...d.risks,{...r,id:secureId('r'),source:r.source||"custom",assigned_to:[]}]}));}
    setToast({msg:"Saved!",type:"success"});setModal(null);
  };
  const toggle=(r)=>{setData(d=>({...d,risks:d.risks.map(x=>x.id===r.id?{...x,disabled:!x.disabled}:x)}));};
  const del=(id)=>{setData(d=>({...d,risks:d.risks.filter(r=>r.id!==id)}));};
  const upd=(id,f,v)=>{setData(d=>({...d,risks:d.risks.map(r=>r.id===id?{...r,[f]:v}:r)}));};

  // Filtered risks for library tab
  const filteredRisks=useMemo(()=>{
    let risks=data.risks||[];
    if(catFilter!=="All") risks=risks.filter(r=>r.category===catFilter);
    if(ratingFilter!=="All") risks=risks.filter(r=>rl(r.impact,r.likelihood).label===ratingFilter);
    if(search) {const s=search.toLowerCase();risks=risks.filter(r=>(r.risk_name||"").toLowerCase().includes(s)||(r.risk_id||"").toLowerCase().includes(s)||(r.description||"").toLowerCase().includes(s));}
    return risks;
  },[data.risks,catFilter,ratingFilter,search]);

  // Active risks
  const activeRisks=useMemo(()=>(data.risks||[]).filter(r=>!r.disabled),[data.risks]);

  // Stats
  const stats=useMemo(()=>{
    const all=data.risks||[];const active=all.filter(r=>!r.disabled);
    return {total:all.length,active:active.length,disabled:all.length-active.length,
      critical:active.filter(r=>r.impact*r.likelihood>=16).length,
      high:active.filter(r=>{const s=r.impact*r.likelihood;return s>=10&&s<16;}).length,
      medium:active.filter(r=>{const s=r.impact*r.likelihood;return s>=5&&s<10;}).length,
      low:active.filter(r=>r.impact*r.likelihood<5).length,
      library:all.filter(r=>r.source==="library").length,
      custom:all.filter(r=>r.source!=="library").length};
  },[data.risks]);

  // Export Risk Register
  const expReg=()=>{const rows=(data.risks||[]).map(r=>({"Risk ID":r.risk_id||"","Risk Name":r.risk_name,Category:r.category||"",Description:r.description,Impact:r.impact,Likelihood:r.likelihood,"Risk Level":rl(r.impact,r.likelihood).label,Score:r.impact*r.likelihood,Owner:r.owner,"ISO Controls":r.linked_control||"",Mitigations:r.mitigations,"Assigned To":(r.assigned_to||[]).join(", "),Status:r.disabled?"Disabled":"Active",Source:r.source||"custom"}));const wm=addExportWatermark(rows,user?.email||"",orgId||"");const ws=XLSX.utils.json_to_sheet(wm);const wb=XLSX.utils.book_new();XLSX.utils.book_append_sheet(wb,ws,"Risk Register");ws["!cols"]=[{wch:12},{wch:30},{wch:18},{wch:40},{wch:7},{wch:10},{wch:10},{wch:6},{wch:15},{wch:15},{wch:30},{wch:25},{wch:10},{wch:8}];XLSX.writeFile(wb,"Risk_Register.xlsx");auditLog(token,"data_export",{resource_type:"risk_register",org_id:orgId,record_count:rows.length},"warning");};

  // Export RTP
  const expRTP=()=>{const rows=(data.risks||[]).filter(r=>!r.disabled).map(r=>({"Risk Name":r.risk_name,"Risk Level":rl(r.impact,r.likelihood).label,Treatment:r.treatment||"Mitigate","Mitigation Steps":r.treatment==="Mitigate"?(r.mitigation_steps||""):"","Transfer To":r.treatment==="Transfer"?(r.transfer_to||""):"",Owner:r.owner,"Assigned To":(r.assigned_to||[]).join(", ")}));const wm=addExportWatermark(rows,user?.email||"",orgId||"");const ws=XLSX.utils.json_to_sheet(wm);const wb=XLSX.utils.book_new();XLSX.utils.book_append_sheet(wb,ws,"Risk Treatment Plan");ws["!cols"]=[{wch:30},{wch:10},{wch:12},{wch:35},{wch:20},{wch:15},{wch:25}];XLSX.writeFile(wb,"Risk_Treatment_Plan.xlsx");auditLog(token,"data_export",{resource_type:"risk_treatment_plan",org_id:orgId,record_count:rows.length},"warning");};

  // Import Risks
  const importRisks=async(file)=>{setImporting(true);try{const{sheetNames,allSheets}=await parseExcelToSheets(file);const rows=allSheets[sheetNames[0]]||[];const imported=rows.map((r,i)=>{const name=r["Risk Name"]||r["Risk"]||r["Name"]||r["risk_name"]||r["Title"]||Object.values(r)[0]||`Risk ${i+1}`;const desc=r["Description"]||r["description"]||r["Details"]||"";const impact=parseInt(r["Impact"]||r["impact"]||3)||3;const likelihood=parseInt(r["Likelihood"]||r["likelihood"]||r["Probability"]||3)||3;const owner=r["Owner"]||r["owner"]||r["Risk Owner"]||"";const linked=r["Linked Control"]||r["linked_control"]||r["ISO Control"]||r["Control"]||"";const mits=r["Mitigations"]||r["mitigations"]||r["Mitigation"]||r["Controls"]||"";const treatment=r["Treatment"]||r["treatment"]||"Mitigate";const mitSteps=r["Mitigation Steps"]||r["mitigation_steps"]||"";const transferTo=r["Transfer To"]||r["transfer_to"]||"";const status=r["Status"]||r["status"]||"Active";const cat=r["Category"]||r["category"]||"";return{id:secureId('r'),risk_name:String(name),description:String(desc),impact:Math.min(5,Math.max(1,impact)),likelihood:Math.min(5,Math.max(1,likelihood)),owner:String(owner),linked_control:String(linked),mitigations:String(mits),treatment:String(treatment),mitigation_steps:String(mitSteps),transfer_to:String(transferTo),disabled:String(status).toLowerCase()==="disabled",remarks:"",source:"custom",category:String(cat),assigned_to:[]};});setData(d=>({...d,risks:[...d.risks,...imported]}));setToast({msg:`${imported.length} risks imported!`,type:"success"});}catch(e){setToast({msg:"Import failed: "+e.message,type:"error"});}setImporting(false);};

  // Import RTP
  const importRTP=async(file)=>{setImporting(true);try{const{sheetNames,allSheets}=await parseExcelToSheets(file);const rows=allSheets[sheetNames[0]]||[];const updates={};rows.forEach(r=>{const name=r["Risk Name"]||r["Risk"]||r["Name"]||"";if(!name)return;updates[String(name).toLowerCase()]={treatment:r["Treatment"]||r["treatment"]||"Mitigate",mitigation_steps:r["Mitigation Steps"]||r["mitigation_steps"]||"",transfer_to:r["Transfer To"]||r["transfer_to"]||"",owner:r["Owner"]||r["owner"]||""};});setData(d=>{const newRisks=d.risks.map(risk=>{const key=risk.risk_name.toLowerCase();if(updates[key])return{...risk,...updates[key]};return risk;});return{...d,risks:newRisks};});setToast({msg:`Treatment plan applied to ${Object.keys(updates).length} risks!`,type:"success"});}catch(e){setToast({msg:"Import failed: "+e.message,type:"error"});}setImporting(false);};

  // Bulk enable/disable by category
  const bulkToggleCat=(cat,enable)=>{setData(d=>({...d,risks:d.risks.map(r=>r.category===cat?{...r,disabled:!enable}:r)}));setToast({msg:`${cat}: all ${enable?"enabled":"disabled"}`,type:"success"});};

  // Available categories from loaded risks
  const loadedCats=useMemo(()=>[...new Set((data.risks||[]).map(r=>r.category).filter(Boolean))].sort(),[data.risks]);

  // Tab pills
  const tabs=[{id:"library",label:"Risk Library",icon:Shield},{id:"register",label:"Risk Register",icon:FileText},{id:"rtp",label:"Treatment Plan",icon:Settings}];

  return (<div>
    {toast&&<Toast {...toast} onClose={()=>setToast(null)}/>}

    {/* Header */}
    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20,flexWrap:"wrap",gap:12}}>
      <div>
        <h2 style={{margin:0,fontSize:22,fontWeight:800,color:C.text}}>Risk Management</h2>
        <p style={{margin:"4px 0 0",fontSize:13,color:C.textMuted}}>ISO 27001:2022 Risk Library — {stats.total} risks ({stats.active} active, {stats.disabled} disabled)</p>
      </div>
      <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
        {!libraryLoaded&&!isEmployee&&<Btn onClick={loadLibrary}><Shield size={14}/> Load Standard Library (104 Risks)</Btn>}
        {libraryLoaded&&!isEmployee&&libraryCount<104&&<Btn variant="secondary" size="sm" onClick={loadLibrary}><Plus size={14}/> Load Missing Risks</Btn>}
        {tab==="register"&&<>
          <FileUploadBtn onFile={importRisks} accept=".xlsx,.xls,.csv" label={importing?"Importing...":"Import Risks"} variant="secondary" size="sm"/>
          {stats.total>0&&<Btn variant="secondary" size="sm" onClick={expReg}><Download size={14}/> Export Register</Btn>}
        </>}
        {tab==="rtp"&&<>
          <FileUploadBtn onFile={importRTP} accept=".xlsx,.xls,.csv" label={importing?"Importing...":"Import RTP"} variant="secondary" size="sm"/>
          {stats.active>0&&<Btn variant="secondary" size="sm" onClick={expRTP}><Download size={14}/> Export RTP</Btn>}
        </>}
        {!isEmployee&&<Btn onClick={()=>setModal({...blank})}><Plus size={14}/> Add Custom Risk</Btn>}
      </div>
    </div>

    {/* Stats bar */}
    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(130px,1fr))",gap:12,marginBottom:20}}>
      <div style={{background:C.card,borderRadius:10,padding:"14px 16px",border:`1px solid ${C.border}`}}>
        <div style={{fontSize:11,color:C.textMuted,fontWeight:600}}>Total Risks</div>
        <div style={{fontSize:24,fontWeight:800,color:C.text}}>{stats.total}</div>
      </div>
      <div style={{background:C.card,borderRadius:10,padding:"14px 16px",border:`1px solid ${C.red}33`}}>
        <div style={{fontSize:11,color:C.textMuted,fontWeight:600}}>Critical</div>
        <div style={{fontSize:24,fontWeight:800,color:C.red}}>{stats.critical}</div>
      </div>
      <div style={{background:C.card,borderRadius:10,padding:"14px 16px",border:`1px solid ${C.orange}33`}}>
        <div style={{fontSize:11,color:C.textMuted,fontWeight:600}}>High</div>
        <div style={{fontSize:24,fontWeight:800,color:C.orange}}>{stats.high}</div>
      </div>
      <div style={{background:C.card,borderRadius:10,padding:"14px 16px",border:`1px solid ${C.yellow}33`}}>
        <div style={{fontSize:11,color:C.textMuted,fontWeight:600}}>Medium</div>
        <div style={{fontSize:24,fontWeight:800,color:C.yellow}}>{stats.medium}</div>
      </div>
      <div style={{background:C.card,borderRadius:10,padding:"14px 16px",border:`1px solid ${C.green}33`}}>
        <div style={{fontSize:11,color:C.textMuted,fontWeight:600}}>Low</div>
        <div style={{fontSize:24,fontWeight:800,color:C.green}}>{stats.low}</div>
      </div>
    </div>

    {/* Tab pills */}
    <div style={{display:"flex",gap:4,marginBottom:16,background:C.card,borderRadius:10,padding:4,width:"fit-content",flexWrap:"wrap"}}>
      {tabs.map(t=><button key={t.id} onClick={()=>setTab(t.id)} style={{padding:"8px 20px",border:"none",borderRadius:8,cursor:"pointer",fontWeight:700,fontSize:13,background:tab===t.id?C.orange:"transparent",color:tab===t.id?"#fff":C.textMuted,fontFamily:"inherit",display:"flex",alignItems:"center",gap:6}}>{t.label}</button>)}
    </div>

    {/* ====== RISK LIBRARY ====== */}
    {tab==="library"&&(<Card>
      {(data.risks||[]).length===0?(<div style={{textAlign:"center",padding:40}}>
        <Shield size={48} color={C.orange} style={{marginBottom:16}}/>
        <h3 style={{color:C.text,margin:"0 0 8px"}}>ISO 27001 Risk Library</h3>
        <p style={{color:C.textMuted,fontSize:14,margin:"0 0 20px"}}>Load 104 pre-defined risks mapped to ISO 27001:2022 Annex A controls across 21 categories.</p>
        {!isEmployee&&<Btn onClick={loadLibrary}><Shield size={14}/> Load Standard Risk Library</Btn>}
      </div>):(<>
        {/* Filters */}
        <div style={{display:"flex",gap:10,marginBottom:16,flexWrap:"wrap",alignItems:"center"}}>
          <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search risks..." style={{padding:"8px 14px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,color:C.text,fontSize:13,flex:"1 1 200px",minWidth:180,fontFamily:"inherit"}}/>
          <select value={catFilter} onChange={e=>setCatFilter(e.target.value)} style={{padding:"8px 12px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,color:C.text,fontSize:13,fontFamily:"inherit"}}>
            <option value="All">All Categories ({stats.total})</option>
            {loadedCats.map(c=><option key={c} value={c}>{c} ({(data.risks||[]).filter(r=>r.category===c).length})</option>)}
          </select>
          <select value={ratingFilter} onChange={e=>setRatingFilter(e.target.value)} style={{padding:"8px 12px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,color:C.text,fontSize:13,fontFamily:"inherit"}}>
            <option value="All">All Ratings</option>
            {["Critical","High","Medium","Low"].map(r=><option key={r} value={r}>{r}</option>)}
          </select>
          {catFilter!=="All"&&!isEmployee&&<div style={{display:"flex",gap:4}}>
            <Btn size="sm" variant="secondary" onClick={()=>bulkToggleCat(catFilter,true)}>Enable All</Btn>
            <Btn size="sm" variant="secondary" onClick={()=>bulkToggleCat(catFilter,false)}>Disable All</Btn>
          </div>}
        </div>
        <div style={{fontSize:12,color:C.textMuted,marginBottom:12}}>Showing {filteredRisks.length} of {stats.total} risks</div>
        <div style={{overflowX:"auto"}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:13}}><thead><tr style={{background:C.bg}}>
          {["ID","Risk","Category","Impact","Likelihood","Level","ISO Controls","Status","Actions"].map(h=><th key={h} style={{padding:"10px 10px",textAlign:"left",color:C.textMuted,fontWeight:700,fontSize:11,textTransform:"uppercase",borderBottom:`1px solid ${C.border}`,whiteSpace:"nowrap"}}>{h}</th>)}
        </tr></thead><tbody>
          {filteredRisks.map(r=>{const rv=rl(r.impact,r.likelihood);return(<tr key={r.id} style={{borderBottom:`1px solid ${C.border}22`,opacity:r.disabled?0.45:1}}>
            <td style={{padding:"8px 10px",color:C.textMuted,fontSize:11,fontFamily:"monospace"}}>{r.risk_id||"—"}</td>
            <td style={{padding:"8px 10px",color:C.text,maxWidth:220}}><div style={{fontWeight:600,fontSize:13}}>{r.risk_name}</div><div style={{fontSize:11,color:C.textMuted,marginTop:2}}>{(r.description||"").substring(0,80)}{(r.description||"").length>80?"...":""}</div></td>
            <td style={{padding:"8px 10px"}}><span style={{fontSize:11,color:C.textMuted,background:C.bg,padding:"2px 8px",borderRadius:4,whiteSpace:"nowrap"}}>{r.category||"—"}</span></td>
            <td style={{padding:"8px 10px",color:C.text,textAlign:"center"}}>{r.impact}</td>
            <td style={{padding:"8px 10px",color:C.text,textAlign:"center"}}>{r.likelihood}</td>
            <td style={{padding:"8px 10px"}}><Badge color={rv.color}>{rv.label} ({r.impact*r.likelihood})</Badge></td>
            <td style={{padding:"8px 10px",fontSize:11,color:C.textMuted,maxWidth:120}}>{(r.annex_a_controls||[]).join(", ")||(r.linked_control||"—")}</td>
            <td style={{padding:"8px 10px"}}><button onClick={()=>toggle(r)} style={{background:r.disabled?`${C.red}22`:`${C.green}22`,border:`1px solid ${r.disabled?C.red:C.green}44`,borderRadius:6,cursor:"pointer",padding:"4px 10px",color:r.disabled?C.red:C.green,fontSize:11,fontWeight:700,fontFamily:"inherit"}}>{r.disabled?"Disabled":"Enabled"}</button></td>
            <td style={{padding:"8px 10px"}}><div style={{display:"flex",gap:4}}>
              <button onClick={()=>setModal({...r})} title="Edit" style={{background:"none",border:"none",cursor:"pointer",color:C.orange}}><Edit3 size={15}/></button>
              {!isEmployee&&<button onClick={()=>del(r.id)} title="Delete" style={{background:"none",border:"none",cursor:"pointer",color:C.red}}><Trash2 size={15}/></button>}
            </div></td>
          </tr>);})}
        </tbody></table></div>
      </>)}
    </Card>)}

    {/* ====== RISK REGISTER (Active Risks) ====== */}
    {tab==="register"&&(<Card title={`Active Risks (${activeRisks.length})`}>
      {activeRisks.length===0?<Empty msg="No active risks. Enable risks from the Library tab or add custom risks." action="Add Risk" onAction={()=>setModal({...blank})}/>:(
        <div style={{overflowX:"auto"}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:13}}><thead><tr style={{background:C.bg}}>
          {["Risk","Category","Impact","Like.","Level","Owner","Actions"].map(h=><th key={h} style={{padding:"10px 12px",textAlign:"left",color:C.textMuted,fontWeight:700,fontSize:11,textTransform:"uppercase",borderBottom:`1px solid ${C.border}`}}>{h}</th>)}
        </tr></thead><tbody>
          {activeRisks.map(r=>{const rv=rl(r.impact,r.likelihood);return(<tr key={r.id} style={{borderBottom:`1px solid ${C.border}22`}}>
            <td style={{padding:"10px 12px",color:C.text,maxWidth:200}}><div style={{fontWeight:600}}>{r.risk_name}</div>{r.risk_id&&<div style={{fontSize:11,color:C.textMuted}}>{r.risk_id}</div>}</td>
            <td style={{padding:"10px 12px"}}><span style={{fontSize:11,color:C.textMuted}}>{r.category||"—"}</span></td>
            <td style={{padding:"10px 12px",color:C.text,textAlign:"center"}}>{r.impact}</td>
            <td style={{padding:"10px 12px",color:C.text,textAlign:"center"}}>{r.likelihood}</td>
            <td style={{padding:"10px 12px"}}><Badge color={rv.color}>{rv.label} ({r.impact*r.likelihood})</Badge></td>
            <td style={{padding:"10px 12px",color:C.textMuted}}>{r.owner||"—"}</td>
            <td style={{padding:"10px 12px"}}><div style={{display:"flex",gap:4}}>
              <button onClick={()=>setModal({...r})} style={{background:"none",border:"none",cursor:"pointer",color:C.orange}}><Edit3 size={15}/></button>
              <button onClick={()=>toggle(r)} style={{background:"none",border:"none",cursor:"pointer",color:C.red}} title="Disable"><ToggleLeft size={15}/></button>
            </div></td>
          </tr>);})}
        </tbody></table></div>
      )}
    </Card>)}

    {/* ====== RISK TREATMENT PLAN ====== */}
    {tab==="rtp"&&(<Card title="Risk Treatment Plan">
      {activeRisks.length===0?<Empty msg="No active risks yet"/>:(
        <div style={{display:"flex",flexDirection:"column",gap:12}}>
          {activeRisks.map(r=>{const rv=rl(r.impact,r.likelihood);return(<div key={r.id} style={{background:C.bg,borderRadius:10,border:`1px solid ${C.border}`,padding:16}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12,flexWrap:"wrap",gap:8}}>
              <div style={{display:"flex",alignItems:"center",gap:10,flexWrap:"wrap"}}><span style={{fontWeight:700,color:C.text}}>{r.risk_name}</span><Badge color={rv.color}>{rv.label}</Badge>{r.risk_id&&<span style={{fontSize:11,color:C.textMuted}}>{r.risk_id}</span>}</div>
              <div style={{display:"flex",gap:6}}><button onClick={()=>toggle(r)} style={{background:"none",border:"none",cursor:"pointer",color:C.red,fontSize:11,fontWeight:600}}>Disable</button></div>
            </div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 2fr",gap:12}}>
              <div><label style={{fontSize:11,color:C.textMuted,fontWeight:600}}>Treatment</label><select value={r.treatment||"Mitigate"} onChange={e=>upd(r.id,"treatment",e.target.value)} style={{width:"100%",padding:"6px 10px",background:C.card,border:`1px solid ${C.border}`,borderRadius:6,color:C.text,fontSize:13,marginTop:4,fontFamily:"inherit"}}>{["Accept","Transfer","Mitigate","Avoid"].map(o=><option key={o} value={o}>{o}</option>)}</select></div>
              <div>
                {r.treatment==="Mitigate"&&<div><label style={{fontSize:11,color:C.textMuted,fontWeight:600}}>Mitigation Steps</label><textarea value={r.mitigation_steps||""} rows={2} onChange={e=>upd(r.id,"mitigation_steps",e.target.value)} style={{width:"100%",padding:"6px 10px",background:C.card,border:`1px solid ${C.border}`,borderRadius:6,color:C.text,fontSize:13,marginTop:4,resize:"vertical",fontFamily:"inherit"}} placeholder="Describe mitigation..."/></div>}
                {r.treatment==="Transfer"&&<div><label style={{fontSize:11,color:C.textMuted,fontWeight:600}}>Transfer To</label><input value={r.transfer_to||""} onChange={e=>upd(r.id,"transfer_to",e.target.value)} style={{width:"100%",padding:"6px 10px",background:C.card,border:`1px solid ${C.border}`,borderRadius:6,color:C.text,fontSize:13,marginTop:4,fontFamily:"inherit"}}/></div>}
                {r.treatment==="Accept"&&<div style={{fontSize:12,color:C.textMuted,marginTop:16}}>Risk accepted — no further action.</div>}
                {r.treatment==="Avoid"&&<div style={{fontSize:12,color:C.textMuted,marginTop:16}}>Risk to be avoided — activity eliminated.</div>}
              </div>
            </div>
          </div>);})}
        </div>
      )}
    </Card>)}

    {/* ====== ADD/EDIT RISK MODAL ====== */}
    <Modal open={!!modal} onClose={()=>setModal(null)} title={modal?.id?"Edit Risk":"Add New Custom Risk"} wide>
      {modal&&(()=>{const u=(f,v)=>setModal(p=>({...p,[f]:v}));return(<div>
        <Input label="Risk Name" value={modal.risk_name} onChange={v=>u("risk_name",v)} placeholder="e.g., Data breach via phishing"/>
        <Input label="Description" value={modal.description} onChange={v=>u("description",v)} textarea/>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
          <Input label="Category" value={modal.category||""} onChange={v=>u("category",v)} select options={[{value:"",label:"Select..."},...RISK_CATS.map(c=>({value:c,label:c}))]}/>
          <Input label="Owner" value={modal.owner} onChange={v=>u("owner",v)}/>
        </div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:12}}>
          <Input label="Impact (1-5)" value={modal.impact} onChange={v=>u("impact",parseInt(v)||1)} select options={[{value:1,label:"1 — Negligible"},{value:2,label:"2 — Minor"},{value:3,label:"3 — Moderate"},{value:4,label:"4 — Major"},{value:5,label:"5 — Severe"}]}/>
          <Input label="Likelihood (1-5)" value={modal.likelihood} onChange={v=>u("likelihood",parseInt(v)||1)} select options={[{value:1,label:"1 — Rare"},{value:2,label:"2 — Unlikely"},{value:3,label:"3 — Possible"},{value:4,label:"4 — Likely"},{value:5,label:"5 — Almost Certain"}]}/>
          <div style={{marginBottom:12}}><label style={{display:"block",fontSize:12,color:C.textMuted,marginBottom:4,fontWeight:600}}>Risk Level</label><div style={{padding:"8px 12px"}}><Badge color={rl(modal.impact,modal.likelihood).color}>{rl(modal.impact,modal.likelihood).label} ({modal.impact*modal.likelihood})</Badge></div></div>
        </div>
        <Input label="Mitigations / Treatment Suggestion" value={modal.mitigations} onChange={v=>u("mitigations",v)} textarea/>
        <Input label="Linked ISO Controls" value={modal.linked_control} onChange={v=>u("linked_control",v)} placeholder="e.g., A.8.7, A.5.15"/>
        <Input label="Remarks" value={modal.remarks} onChange={v=>u("remarks",v)} textarea/>
        <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:16}}><Btn variant="secondary" onClick={()=>setModal(null)}>Cancel</Btn><Btn onClick={()=>saveRisk(modal)}><Save size={14}/> Save Risk</Btn></div>
      </div>);})()}
    </Modal>
  </div>);
};


// =============================================
// ASSET REGISTER — with Import/Export (separate sheets per category)
// =============================================
const AssetRegister = ({data,setData}) => {
  const cats=["Informational","Physical","People","Software","Service"];
  const [tab,setTab]=useState(cats[0]);const [modal,setModal]=useState(null);const [toast,setToast]=useState(null);const [importing,setImporting]=useState(false);
  const {token,user,orgId}=useAuth();
  const blank = {id:"",asset_name:"",description:"",owner:"",custodian:"",c_rating:1,i_rating:1,a_rating:1};
  const save=(a)=>{if(a.id){setData(d=>({...d,assets:d.assets.map(x=>x.id===a.id?{...a,category:tab}:x)}));}else{setData(d=>({...d,assets:[...d.assets,{...a,id:secureId('a'),category:tab}]}));}setToast({msg:"Saved!",type:"success"});setModal(null);};
  
  // Export with separate sheets per category — [SEC-2] audit + [SEC-6] watermark
  const exp=()=>{
    const wb=XLSX.utils.book_new();let totalRows=0;
    cats.forEach(c=>{
      const rows=data.assets.filter(a=>a.category===c).map(a=>({"Asset Name":a.asset_name,Description:a.description,Owner:a.owner,Custodian:a.custodian||"","Confidentiality":a.c_rating,"Integrity":a.i_rating,"Availability":a.a_rating}));
      totalRows+=rows.length;
      const wm=addExportWatermark(rows,user?.email||"",orgId||"");
      const ws=XLSX.utils.json_to_sheet(wm.length>2?wm:[{"Asset Name":"","Description":"","Owner":"","Custodian":"","Confidentiality":"","Integrity":"","Availability":""}]);
      ws["!cols"]=[{wch:25},{wch:35},{wch:15},{wch:15},{wch:14},{wch:10},{wch:12}];
      XLSX.utils.book_append_sheet(wb,ws,c);
    });
    XLSX.writeFile(wb,"Asset_Register.xlsx");
    auditLog(token,"data_export",{resource_type:"asset_register",org_id:orgId,record_count:totalRows},"warning");
  };

  // Import from Excel — detect category from sheet names or Category column
  const importAssets = async(file) => {
    setImporting(true);
    try {
      const {sheetNames,allSheets} = await parseExcelToSheets(file);
      const imported = [];
      
      sheetNames.forEach(sheetName => {
        const rows = allSheets[sheetName]||[];
        // Try to match sheet name to a category
        const matchedCat = cats.find(c => sheetName.toLowerCase().includes(c.toLowerCase())) || null;
        
        rows.forEach((r,i) => {
          const name = r["Asset Name"]||r["asset_name"]||r["Name"]||r["Asset"]||Object.values(r)[0]||"";
          if(!name) return;
          const desc = r["Description"]||r["description"]||r["Details"]||"";
          const owner = r["Owner"]||r["owner"]||r["Asset Owner"]||"";
          const custodian = r["Custodian"]||r["custodian"]||"";
          const cRat = parseInt(r["Confidentiality"]||r["C"]||r["c_rating"]||1)||1;
          const iRat = parseInt(r["Integrity"]||r["I"]||r["i_rating"]||1)||1;
          const aRat = parseInt(r["Availability"]||r["A"]||r["a_rating"]||1)||1;
          // Category from column or sheet name
          const catCol = r["Category"]||r["category"]||r["Type"]||"";
          const category = cats.find(c => c.toLowerCase()===String(catCol).toLowerCase()) || matchedCat || tab;
          
          imported.push({
            id:secureId('a'),
            asset_name:String(name), description:String(desc), owner:String(owner),
            custodian:String(custodian), c_rating:Math.min(5,Math.max(1,cRat)),
            i_rating:Math.min(5,Math.max(1,iRat)), a_rating:Math.min(5,Math.max(1,aRat)),
            category
          });
        });
      });
      
      setData(d=>({...d,assets:[...d.assets,...imported]}));
      setToast({msg:`${imported.length} assets imported from ${sheetNames.length} sheet(s)!`,type:"success"});
    } catch(e) { setToast({msg:"Import failed: "+e.message,type:"error"}); }
    setImporting(false);
  };

  const filtered = data.assets.filter(a=>a.category===tab);
  return (<div>
    {toast&&<Toast {...toast} onClose={()=>setToast(null)}/>}
    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20}}>
      <h2 style={{margin:0,fontSize:22,fontWeight:800,color:C.text}}>Asset Register</h2>
      <div style={{display:"flex",gap:8}}>
        <FileUploadBtn onFile={importAssets} accept=".xlsx,.xls,.csv" label={importing?"Importing...":"Import"} variant="secondary" size="sm"/>
        {data.assets.length>0&&<Btn variant="secondary" size="sm" onClick={exp}><Download size={14}/> Export</Btn>}
        <Btn onClick={()=>setModal({...blank})}><Plus size={14}/> Add Asset</Btn>
      </div>
    </div>
    <div style={{display:"flex",gap:4,marginBottom:16,background:C.card,borderRadius:10,padding:4,overflowX:"auto"}}>{cats.map(c=><button key={c} onClick={()=>setTab(c)} style={{padding:"8px 16px",border:"none",borderRadius:8,cursor:"pointer",fontWeight:700,fontSize:13,whiteSpace:"nowrap",background:tab===c?C.orange:"transparent",color:tab===c?"#fff":C.textMuted,fontFamily:"inherit"}}>{c} <span style={{opacity:0.6}}>({data.assets.filter(a=>a.category===c).length})</span></button>)}</div>
    <Card>
      {filtered.length===0?<Empty msg={`No ${tab} assets`} action="Add Asset" onAction={()=>setModal({...blank})}/>:(
        <div style={{overflowX:"auto"}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:13}}><thead><tr style={{background:C.bg}}>{["Asset Name","Description","Owner","Custodian","C","I","A",""].map(h=><th key={h} style={{padding:"10px 12px",textAlign:"left",color:C.textMuted,fontWeight:700,fontSize:11,textTransform:"uppercase",borderBottom:`1px solid ${C.border}`}}>{h}</th>)}</tr></thead><tbody>{filtered.map(a=><tr key={a.id} style={{borderBottom:`1px solid ${C.border}22`}}>
          <td style={{padding:"10px 12px",color:C.text,fontWeight:600}}>{a.asset_name}</td>
          <td style={{padding:"10px 12px",color:C.textMuted,maxWidth:180,fontSize:12}}>{a.description}</td>
          <td style={{padding:"10px 12px",color:C.textMuted}}>{a.owner}</td>
          <td style={{padding:"10px 12px",color:C.textMuted}}>{a.custodian||"—"}</td>
          {["c_rating","i_rating","a_rating"].map(f=><td key={f} style={{padding:"10px 12px",textAlign:"center"}}><Badge color={a[f]>=4?C.red:a[f]>=3?C.yellow:C.green}>{a[f]}</Badge></td>)}
          <td style={{padding:"10px 12px"}}><div style={{display:"flex",gap:6}}><button onClick={()=>setModal({...a})} style={{background:"none",border:"none",cursor:"pointer",color:C.orange}}><Edit3 size={15}/></button><button onClick={()=>setData(d=>({...d,assets:d.assets.filter(x=>x.id!==a.id)}))} style={{background:"none",border:"none",cursor:"pointer",color:C.red}}><Trash2 size={15}/></button></div></td>
        </tr>)}</tbody></table></div>)}
    </Card>
    <Modal open={!!modal} onClose={()=>setModal(null)} title={modal?.id?"Edit Asset":`Add ${tab} Asset`}>
      {modal&&(()=>{const u=(f,v)=>setModal(p=>({...p,[f]:v}));return(<div>
        <Input label="Asset Name" value={modal.asset_name} onChange={v=>u("asset_name",v)}/>
        <Input label="Description" value={modal.description} onChange={v=>u("description",v)} textarea/>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}><Input label="Owner" value={modal.owner} onChange={v=>u("owner",v)}/><Input label="Custodian" value={modal.custodian||""} onChange={v=>u("custodian",v)}/></div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:12}}>
          <Input label="Confidentiality (1-5)" value={modal.c_rating} onChange={v=>u("c_rating",parseInt(v)||1)} select options={[1,2,3,4,5].map(n=>({value:n,label:`${n}`}))}/>
          <Input label="Integrity (1-5)" value={modal.i_rating} onChange={v=>u("i_rating",parseInt(v)||1)} select options={[1,2,3,4,5].map(n=>({value:n,label:`${n}`}))}/>
          <Input label="Availability (1-5)" value={modal.a_rating} onChange={v=>u("a_rating",parseInt(v)||1)} select options={[1,2,3,4,5].map(n=>({value:n,label:`${n}`}))}/>
        </div>
        <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:16}}><Btn variant="secondary" onClick={()=>setModal(null)}>Cancel</Btn><Btn onClick={()=>save(modal)}><Save size={14}/> Save</Btn></div>
      </div>);})()}
    </Modal>
  </div>);
};

// =============================================
// POLICIES (unchanged)
// =============================================
const PoliciesModule = ({data,setData,role:userRole,members:allMembers,orgId}) => {
  const [tab,setTab]=useState("library"); // library | settings | editor
  const [selPolicyId,setSelPolicyId]=useState(null);
  const [editSection,setEditSection]=useState(null); // {policyIdx, sectionIdx}
  const [editText,setEditText]=useState("");
  const [toast,setToast]=useState(null);
  const [search,setSearch]=useState("");
  const [generating,setGenerating]=useState(false);
  const [previewHtml,setPreviewHtml]=useState("");
  const {token,user}=useAuth();
  const isAdmin=["super_admin","employee","client_admin"].includes(userRole);
  const policies=data.policies||[];
  const ps=data.policySettings||{companyName:"",logoDataUrl:"",headerRightText:""};

  // Update policy settings
  const updateSettings=(k,v)=>setData(d=>({...d,policySettings:{...d.policySettings||{},[k]:v}}));

  // Logo upload as base64 data URL
  const handleLogoUpload=(e)=>{
    const file=e.target.files?.[0];if(!file)return;
    if(!file.type.startsWith("image/")){setToast({msg:"Please upload an image file",type:"error"});return;}
    if(file.size>2*1024*1024){setToast({msg:"Logo must be under 2MB",type:"error"});return;}
    const reader=new FileReader();
    reader.onload=(ev)=>{updateSettings("logoDataUrl",ev.target.result);setToast({msg:"Logo uploaded!",type:"success"});};
    reader.readAsDataURL(file);
  };

  // Load all 40 templates into data.policies (seeding)
  const loadLibrary=()=>{
    if(!ps.companyName){setToast({msg:"Please set Company Name in Settings first",type:"error"});setTab("settings");return;}
    const seeded=POLICY_TEMPLATES.map(t=>({
      id:t.id,
      name:t.name.replace(/\([\d]+\)/g,'').trim(),
      enabled:true,
      source:"library",
      pages:t.pages,
      sections:t.sections.map(s=>({
        heading:s.heading.replace(/\{\{COMPANY_NAME\}\}/g,ps.companyName),
        body:s.body.replace(/\{\{COMPANY_NAME\}\}/g,ps.companyName),
      })),
      generated_at:new Date().toISOString(),
      status:"draft",
    }));
    setData(d=>({...d,policies:seeded}));
    setToast({msg:`${seeded.length} policies generated for ${ps.companyName}!`,type:"success"});
  };

  // Regenerate a single policy with current company name
  const regeneratePolicy=(policyId)=>{
    const template=POLICY_TEMPLATES.find(t=>t.id===policyId);
    if(!template)return;
    setData(d=>({...d,policies:d.policies.map(p=>{
      if(p.id!==policyId)return p;
      return{...p,sections:template.sections.map(s=>({
        heading:s.heading.replace(/\{\{COMPANY_NAME\}\}/g,ps.companyName||"[Company Name]"),
        body:s.body.replace(/\{\{COMPANY_NAME\}\}/g,ps.companyName||"[Company Name]"),
      })),generated_at:new Date().toISOString(),status:"draft"};
    })}));
    setToast({msg:"Policy regenerated!",type:"success"});
  };

  // Toggle enable
  const togglePolicy=(id)=>setData(d=>({...d,policies:d.policies.map(p=>p.id===id?{...p,enabled:!p.enabled}:p)}));

  // Update section text
  const saveSectionEdit=()=>{
    if(!editSection)return;
    const{policyIdx,sectionIdx}=editSection;
    setData(d=>{
      const newPolicies=[...d.policies];
      const p={...newPolicies[policyIdx]};
      const secs=[...p.sections];
      secs[sectionIdx]={...secs[sectionIdx],body:editText};
      p.sections=secs;
      newPolicies[policyIdx]=p;
      return{...d,policies:newPolicies};
    });
    setEditSection(null);setEditText("");
    setToast({msg:"Section updated!",type:"success"});
  };

  // Update policy status
  const setStatus=(id,status)=>setData(d=>({...d,policies:d.policies.map(p=>p.id===id?{...p,status}:p)}));

  // Filtered policies
  const filtered=useMemo(()=>{
    if(!search)return policies;
    const q=search.toLowerCase();
    return policies.filter(p=>p.name.toLowerCase().includes(q));
  },[policies,search]);

  // Stats
  const stats=useMemo(()=>{
    const total=policies.length;
    const enabled=policies.filter(p=>p.enabled).length;
    const approved=policies.filter(p=>p.status==="approved").length;
    const draft=policies.filter(p=>p.status==="draft").length;
    const review=policies.filter(p=>p.status==="review").length;
    return{total,enabled,approved,draft,review};
  },[policies]);

  // Generate Word-compatible HTML with proper headers, footers, page numbers
  const generateDocHTML=(policy,forPreview=false)=>{
    const cn=ps.companyName||"[Company Name]";
    const headerRight=ps.headerRightText||"";
    const genDate=policy.generated_at?new Date(policy.generated_at).toLocaleDateString('en-IN',{day:'numeric',month:'short',year:'numeric'}):'—';
    const statusText=policy.status==='approved'?'Approved':policy.status==='review'?'Under Review':'Draft';

    // Escape HTML in section bodies
    const esc=(t)=>(t||"").replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

    // Logo as img tag (for Word) or placeholder
    const logoImg=ps.logoDataUrl?`<img src="${ps.logoDataUrl}" width="140" height="50" style="width:140px;height:auto;max-height:50px;"/>`:
      `<span style="display:inline-block;width:40px;height:40px;background:#F97316;border-radius:6px;color:#fff;font-weight:800;font-size:20px;text-align:center;line-height:40px;">${esc(cn.charAt(0))}</span>`;

    // Build section HTML
    let sectionsHtml='';
    policy.sections.forEach((s,i)=>{
      // Process body text: convert line breaks to paragraphs, handle bullet-like lines
      const bodyLines=(s.body||"").split('\n');
      let bodyHtml='';
      bodyLines.forEach(line=>{
        const trimmed=line.trim();
        if(!trimmed)return;
        // Check if line starts with bullet-like chars
        if(/^[•\-–]/.test(trimmed)){
          bodyHtml+=`<p class=MsoListBullet style="margin:0 0 4pt 36pt;text-indent:-18pt;line-height:150%"><span style="font-family:Symbol">·</span><span style="font-size:11.0pt;font-family:'Calibri',sans-serif"> ${esc(trimmed.replace(/^[•\-–]\s*/,''))}</span></p>\n`;
        } else {
          bodyHtml+=`<p class=MsoNormal style="margin:0 0 6pt;line-height:150%"><span style="font-size:11.0pt;font-family:'Calibri',sans-serif">${esc(trimmed)}</span></p>\n`;
        }
      });

      sectionsHtml+=`
        <h2 style="margin:18pt 0 8pt;font-size:13.0pt;font-family:'Calibri',sans-serif;color:#1F3864;font-weight:bold;border-bottom:1pt solid #D5D5D5;padding-bottom:4pt;">${i+1}. ${esc(s.heading)}</h2>
        ${bodyHtml}
      `;
    });

    // Table of contents
    let tocHtml=policy.sections.map((s,i)=>`<p style="margin:2pt 0;font-size:11pt;font-family:'Calibri',sans-serif;"><span style="color:#555;">${i+1}.</span> ${esc(s.heading)}</p>`).join('\n');

    // For in-app preview (simple HTML)
    if(forPreview){
      return `<!DOCTYPE html><html><head><meta charset="utf-8">
<style>body{font-family:Calibri,sans-serif;color:#1a1a1a;margin:0;padding:40px;background:#fff;max-width:800px;margin:0 auto;}
.hdr{display:flex;justify-content:space-between;align-items:center;border-bottom:2.5pt solid #F97316;padding-bottom:10px;margin-bottom:30px;}
.hdr-left{display:flex;align-items:center;gap:12px;}
.hdr-co{font-size:14pt;font-weight:700;}
.hdr-right{font-size:9pt;color:#666;text-align:right;}
.title-block{text-align:center;margin:40px 0 30px;}
.title-block h1{font-size:22pt;color:#1F3864;margin:0 0 6px;font-weight:700;}
.title-block .co{font-size:13pt;color:#555;margin:0 0 30px;}
.dc-table{width:70%;margin:20px auto;border-collapse:collapse;}
.dc-table td{padding:8px 14px;border:1px solid #d5d5d5;font-size:10pt;}
.dc-table .lbl{background:#f4f6f8;color:#555;font-weight:600;width:35%;}
.toc{margin:30px 0;padding:20px;background:#fafbfc;border-radius:6px;border:1px solid #eee;}
.toc-title{font-size:14pt;font-weight:700;color:#1F3864;margin:0 0 10px;}
.ftr{margin-top:40px;border-top:1px solid #ddd;padding-top:8px;display:flex;justify-content:space-between;font-size:8pt;color:#999;}
h2{font-size:13pt;color:#1F3864;border-bottom:1pt solid #d5d5d5;padding-bottom:4pt;margin:18pt 0 8pt;}
p{font-size:11pt;line-height:160%;margin:0 0 6pt;}
</style></head><body>
<div class="hdr"><div class="hdr-left">${logoImg}<div class="hdr-co">${esc(cn)}</div></div><div class="hdr-right">${esc(headerRight)}</div></div>
<div class="title-block"><h1>${esc(policy.name)}</h1><p class="co">${esc(cn)}</p>
<table class="dc-table"><tr><td colspan="2" style="text-align:center;font-weight:700;background:#1F3864;color:#fff;font-size:11pt;">Document Control</td></tr>
<tr><td class="lbl">Status</td><td>${statusText}</td></tr>
<tr><td class="lbl">Generated</td><td>${genDate}</td></tr>
<tr><td class="lbl">Organization</td><td>${esc(cn)}</td></tr>
<tr><td class="lbl">Classification</td><td>Company Internal</td></tr></table></div>
<div class="toc"><div class="toc-title">Contents</div>${tocHtml}</div>
${sectionsHtml}
<div class="ftr"><span>Page 1</span><span>Company Internal</span><span>Created by SecComply</span></div>
</body></html>`;
    }

    // Word-compatible HTML with proper headers, footers, page numbers
    return `<html xmlns:v="urn:schemas-microsoft-com:vml"
xmlns:o="urn:schemas-microsoft-com:office:office"
xmlns:w="urn:schemas-microsoft-com:office:word"
xmlns="http://www.w3.org/TR/REC-html40">
<head><meta charset="utf-8"><meta name=ProgId content=Word.Document>
<meta name=Generator content="SecComply">
<!--[if gte mso 9]><xml><o:DocumentProperties>
<o:Author>SecComply</o:Author><o:Company>${esc(cn)}</o:Company>
</o:DocumentProperties></xml><![endif]-->
<!--[if gte mso 9]><xml><w:WordDocument>
<w:View>Print</w:View><w:Zoom>100</w:Zoom>
<w:SpellingState>Clean</w:SpellingState><w:GrammarState>Clean</w:GrammarState>
<w:DoNotOptimizeForBrowser/><w:BrowserLevel>MicrosoftInternetExplorer4</w:BrowserLevel>
</w:WordDocument></xml><![endif]-->
<style>
@page Section1 {
  size:595.3pt 841.9pt; /* A4 */
  margin:72pt 72pt 72pt 72pt;
  mso-header-margin:36pt;
  mso-footer-margin:36pt;
  mso-header: h1;
  mso-footer: f1;
  mso-paper-source:0;
}
div.Section1 { page:Section1; }

/* Header */
@page Section1 { 
  @top-left { content: element(header-left); }
}

p.MsoNormal { margin:0; font-size:11.0pt; font-family:"Calibri",sans-serif; line-height:150%; }
h1 { font-size:22.0pt; font-family:"Calibri",sans-serif; color:#1F3864; font-weight:bold; margin:0 0 6pt; }
h2 { font-size:13.0pt; font-family:"Calibri",sans-serif; color:#1F3864; font-weight:bold; margin:18pt 0 8pt; border-bottom:1.0pt solid #D5D5D5; padding-bottom:4pt; }
p.MsoHeader { margin:0; font-size:10.0pt; font-family:"Calibri",sans-serif; }
p.MsoFooter { margin:0; font-size:8.0pt; font-family:"Calibri",sans-serif; color:#888888; }
table.MsoTable { border-collapse:collapse; font-size:10.0pt; font-family:"Calibri",sans-serif; }
p.MsoListBullet { margin:0 0 4pt 36pt; text-indent:-18pt; font-size:11.0pt; font-family:"Calibri",sans-serif; line-height:150%; }
p.MsoToc { margin:2pt 0; font-size:11.0pt; font-family:"Calibri",sans-serif; }
span.BulletChar { font-family:Symbol; }
</style>
</head>
<body lang=EN-IN style="tab-interval:36.0pt">

<div class=Section1>

<!-- ===== HEADER ===== -->
<div style="mso-element:header" id=h1>
<table width="100%" border=0 cellspacing=0 cellpadding=0 style="border-bottom:2.5pt solid #F97316;padding-bottom:6pt;margin-bottom:12pt;">
<tr>
<td width="60%" valign="middle" style="padding-bottom:8pt;">
<p class=MsoHeader>${logoImg}
<span style="font-size:13.0pt;font-weight:bold;font-family:'Calibri',sans-serif;margin-left:10pt;"> ${esc(cn)}</span></p>
</td>
<td width="40%" valign="middle" align="right" style="padding-bottom:8pt;">
<p class=MsoHeader align=right style="text-align:right;font-size:9.0pt;color:#666666;">${esc(headerRight)}</p>
</td>
</tr>
</table>
</div>

<!-- ===== FOOTER ===== -->
<div style="mso-element:footer" id=f1>
<table width="100%" border=0 cellspacing=0 cellpadding=0 style="border-top:0.5pt solid #CCCCCC;padding-top:6pt;">
<tr>
<td width="33%" align="left"><p class=MsoFooter>Page <span style='mso-field-code:" PAGE "'>1</span> of <span style='mso-field-code:" NUMPAGES "'>1</span></p></td>
<td width="34%" align="center"><p class=MsoFooter align=center style="text-align:center;font-weight:bold;color:#555555;">Company Internal</p></td>
<td width="33%" align="right"><p class=MsoFooter align=right style="text-align:right;">Created by SecComply</p></td>
</tr>
</table>
</div>

<!-- ===== TITLE PAGE ===== -->
<div style="text-align:center;margin-top:120pt;margin-bottom:40pt;">
<h1 style="text-align:center;font-size:24.0pt;color:#1F3864;">${esc(policy.name)}</h1>
<p class=MsoNormal style="text-align:center;font-size:14.0pt;color:#555555;margin-top:8pt;">${esc(cn)}</p>
</div>

<!-- Document Control Table -->
<table class=MsoTable width="420" align="center" border=1 cellspacing=0 cellpadding=0 style="border:1px solid #D5D5D5;margin:20pt auto;">
<tr><td colspan=2 style="background:#1F3864;color:#ffffff;padding:8pt 14pt;font-weight:bold;font-size:11.0pt;text-align:center;">Document Control</td></tr>
<tr><td width="40%" style="background:#F4F6F8;padding:7pt 14pt;font-weight:600;color:#555;border:1px solid #D5D5D5;">Status</td>
<td style="padding:7pt 14pt;border:1px solid #D5D5D5;font-weight:600;color:${policy.status==='approved'?'#16A34A':policy.status==='review'?'#D97706':'#666'};">${statusText}</td></tr>
<tr><td style="background:#F4F6F8;padding:7pt 14pt;font-weight:600;color:#555;border:1px solid #D5D5D5;">Generated</td>
<td style="padding:7pt 14pt;border:1px solid #D5D5D5;">${genDate}</td></tr>
<tr><td style="background:#F4F6F8;padding:7pt 14pt;font-weight:600;color:#555;border:1px solid #D5D5D5;">Organization</td>
<td style="padding:7pt 14pt;border:1px solid #D5D5D5;">${esc(cn)}</td></tr>
<tr><td style="background:#F4F6F8;padding:7pt 14pt;font-weight:600;color:#555;border:1px solid #D5D5D5;">Classification</td>
<td style="padding:7pt 14pt;border:1px solid #D5D5D5;">Company Internal</td></tr>
<tr><td style="background:#F4F6F8;padding:7pt 14pt;font-weight:600;color:#555;border:1px solid #D5D5D5;">Prepared By</td>
<td style="padding:7pt 14pt;border:1px solid #D5D5D5;">SecComply</td></tr>
</table>

<br clear=all style="page-break-before:always;mso-break-type:section-break;">

<!-- ===== TABLE OF CONTENTS ===== -->
<h2 style="font-size:15.0pt;color:#1F3864;border-bottom:2pt solid #F97316;padding-bottom:6pt;margin-bottom:14pt;">Contents</h2>
${tocHtml.replace(/class="[^"]*"/g,'class=MsoToc')}

<br clear=all style="page-break-before:always;mso-break-type:section-break;">

<!-- ===== POLICY CONTENT ===== -->
${sectionsHtml}

</div>
</body></html>`;
  };

  // Preview (uses simpler HTML for iframe)
  const showPreview=(policyId)=>{
    const policy=policies.find(p=>p.id===policyId);
    if(!policy)return;
    setPreviewHtml(generateDocHTML(policy,true));
    setSelPolicyId(policyId);
    setTab("preview");
  };

  // Download as .doc (uses Word-compatible HTML)
  const downloadDoc=(policy)=>{
    const html=generateDocHTML(policy,false);
    const blob=new Blob(['\ufeff',html],{type:'application/msword'});
    const url=URL.createObjectURL(blob);
    const a=document.createElement('a');
    a.href=url;
    a.download=`${policy.name.replace(/[^a-zA-Z0-9 ]/g,'').replace(/\s+/g,'_')}_${(ps.companyName||'Policy').replace(/[^a-zA-Z0-9]/g,'_')}.doc`;
    document.body.appendChild(a);a.click();document.body.removeChild(a);URL.revokeObjectURL(url);
    auditLog(token,"data_export",{resource_type:"policy",policy_name:policy.name,org_id:orgId},"warning");
    setToast({msg:`Downloaded: ${policy.name}`,type:"success"});
  };

  // Download ALL enabled policies
  const downloadAll=()=>{
    const enabled=policies.filter(p=>p.enabled);
    if(enabled.length===0){setToast({msg:"No enabled policies to download",type:"error"});return;}
    setGenerating(true);
    let delay=0;
    enabled.forEach(p=>{setTimeout(()=>downloadDoc(p),delay);delay+=300;});
    setTimeout(()=>{setGenerating(false);setToast({msg:`${enabled.length} policies downloaded!`,type:"success"});},delay+500);
  };

  // Selected policy for editor
  const selPolicy=policies.find(p=>p.id===selPolicyId);
  const selPolicyIdx=policies.findIndex(p=>p.id===selPolicyId);

  const statusColors={draft:C.textMuted,review:C.yellow,approved:C.green};
  const statusLabels={draft:"Draft",review:"Under Review",approved:"Approved"};

  return (<div>
    {toast&&<Toast {...toast} onClose={()=>setToast(null)}/>}

    {/* Header */}
    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20,flexWrap:"wrap",gap:12}}>
      <div>
        <h2 style={{margin:0,fontSize:22,fontWeight:800,color:C.text}}>Policy Automation</h2>
        <p style={{margin:"4px 0 0",fontSize:13,color:C.textMuted}}>40 ISO 27001 policy templates — customize, preview & download</p>
      </div>
      {isAdmin&&policies.length>0&&<div style={{display:"flex",gap:8}}>
        <Btn variant="secondary" onClick={downloadAll} disabled={generating}><Download size={14}/> {generating?"Generating...":"Download All"}</Btn>
      </div>}
    </div>

    {/* Stats */}
    {policies.length>0&&<div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(110px,1fr))",gap:12,marginBottom:20}}>
      <div style={{background:C.card,borderRadius:10,padding:"12px 14px",border:`1px solid ${C.border}`}}><div style={{fontSize:11,color:C.textMuted,fontWeight:600}}>Total</div><div style={{fontSize:22,fontWeight:800,color:C.text}}>{stats.total}</div></div>
      <div style={{background:C.card,borderRadius:10,padding:"12px 14px",border:`1px solid ${C.orange}33`}}><div style={{fontSize:11,color:C.textMuted,fontWeight:600}}>Enabled</div><div style={{fontSize:22,fontWeight:800,color:C.orange}}>{stats.enabled}</div></div>
      <div style={{background:C.card,borderRadius:10,padding:"12px 14px",border:`1px solid ${C.green}33`}}><div style={{fontSize:11,color:C.textMuted,fontWeight:600}}>Approved</div><div style={{fontSize:22,fontWeight:800,color:C.green}}>{stats.approved}</div></div>
      <div style={{background:C.card,borderRadius:10,padding:"12px 14px",border:`1px solid ${C.yellow}33`}}><div style={{fontSize:11,color:C.textMuted,fontWeight:600}}>Review</div><div style={{fontSize:22,fontWeight:800,color:C.yellow}}>{stats.review}</div></div>
      <div style={{background:C.card,borderRadius:10,padding:"12px 14px",border:`1px solid ${C.border}`}}><div style={{fontSize:11,color:C.textMuted,fontWeight:600}}>Draft</div><div style={{fontSize:22,fontWeight:800,color:C.textMuted}}>{stats.draft}</div></div>
    </div>}

    {/* Tab bar */}
    <div style={{display:"flex",gap:4,marginBottom:20,background:C.card,borderRadius:10,padding:4,width:"fit-content",flexWrap:"wrap"}}>
      {[{id:"library",label:"Policy Library"},{id:"settings",label:"Settings"},
        ...(selPolicyId?[{id:"editor",label:"Edit Policy"},{id:"preview",label:"Preview"}]:[])
      ].map(t=><button key={t.id} onClick={()=>setTab(t.id)} style={{padding:"8px 20px",border:"none",borderRadius:8,cursor:"pointer",fontWeight:700,fontSize:13,background:tab===t.id?C.orange:"transparent",color:tab===t.id?"#fff":C.textMuted,fontFamily:"inherit"}}>{t.label}</button>)}
    </div>

    {/* ========== SETTINGS TAB ========== */}
    {tab==="settings"&&<Card title="Policy Document Settings">
      <div style={{maxWidth:600}}>
        <Input label="Company Name *" value={ps.companyName} onChange={v=>updateSettings("companyName",v)} placeholder="e.g., InTime Solutions Pvt. Ltd."/>
        <p style={{fontSize:11,color:C.textDim,margin:"-8px 0 12px"}}>This replaces all "Aistra" references in policies</p>
        
        <Input label="Header Right Text" value={ps.headerRightText} onChange={v=>updateSettings("headerRightText",v)} placeholder="e.g., Document ID: ISP-001 | Confidential"/>
        <p style={{fontSize:11,color:C.textDim,margin:"-8px 0 12px"}}>Appears in the top-right corner of each policy document</p>
        
        <div style={{marginBottom:16}}>
          <label style={{display:"block",fontSize:12,color:C.textMuted,marginBottom:6,fontWeight:600}}>Company Logo</label>
          <div style={{display:"flex",alignItems:"center",gap:16}}>
            {ps.logoDataUrl?
              <div style={{position:"relative"}}>
                <img src={ps.logoDataUrl} alt="Logo" style={{maxHeight:60,maxWidth:200,borderRadius:8,border:`1px solid ${C.border}`}}/>
                <button onClick={()=>updateSettings("logoDataUrl","")} style={{position:"absolute",top:-6,right:-6,background:C.red,border:"none",borderRadius:"50%",width:20,height:20,cursor:"pointer",color:"#fff",fontSize:12,display:"flex",alignItems:"center",justifyContent:"center"}}>×</button>
              </div>:
              <div style={{width:60,height:60,background:C.bg,borderRadius:10,border:`2px dashed ${C.border}`,display:"flex",alignItems:"center",justifyContent:"center",color:C.textDim,fontSize:11}}>No logo</div>
            }
            <label style={{padding:"8px 16px",background:C.orange,color:"#fff",borderRadius:8,cursor:"pointer",fontSize:13,fontWeight:600}}>
              Upload Logo
              <input type="file" accept="image/*" onChange={handleLogoUpload} style={{display:"none"}}/>
            </label>
          </div>
          <p style={{fontSize:11,color:C.textDim,margin:"6px 0 0"}}>Max 2MB. Appears in the header of every policy document.</p>
        </div>

        {/* Footer preview */}
        <div style={{marginTop:20}}>
          <label style={{display:"block",fontSize:12,color:C.textMuted,marginBottom:6,fontWeight:600}}>Footer Layout (fixed)</label>
          <div style={{display:"flex",justifyContent:"space-between",padding:"10px 16px",background:C.bg,borderRadius:8,border:`1px solid ${C.border}`,fontSize:11,color:C.textDim}}>
            <span>Page X of Y</span>
            <span style={{fontWeight:600}}>Company Internal</span>
            <span>Created by SecComply</span>
          </div>
        </div>

        {/* Header preview */}
        <div style={{marginTop:16}}>
          <label style={{display:"block",fontSize:12,color:C.textMuted,marginBottom:6,fontWeight:600}}>Header Preview</label>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"10px 16px",background:"#fff",borderRadius:8,border:`1px solid ${C.border}`}}>
            <div style={{display:"flex",alignItems:"center",gap:10}}>
              {ps.logoDataUrl?<img src={ps.logoDataUrl} alt="Logo" style={{maxHeight:30,maxWidth:100}}/>:
                <div style={{width:30,height:30,background:"#f97316",borderRadius:6,display:"flex",alignItems:"center",justifyContent:"center",color:"#fff",fontWeight:800,fontSize:14}}>{(ps.companyName||"C").charAt(0)}</div>
              }
              <span style={{fontWeight:800,color:"#1a1a1a",fontSize:14}}>{ps.companyName||"[Company Name]"}</span>
            </div>
            <span style={{fontSize:10,color:"#888"}}>{ps.headerRightText||"[Header Right Text]"}</span>
          </div>
        </div>

        {policies.length>0&&<div style={{marginTop:24,padding:14,background:`${C.orange}11`,borderRadius:10,border:`1px solid ${C.orange}33`}}>
          <div style={{fontSize:13,color:C.orange,fontWeight:700,marginBottom:4}}>⚠ Regenerate Policies?</div>
          <p style={{fontSize:12,color:C.textMuted,margin:"0 0 10px"}}>Company name changed? Click below to regenerate all policies with the new name. This will reset any manual edits.</p>
          <Btn size="sm" onClick={loadLibrary}><RefreshCw size={13}/> Regenerate All Policies</Btn>
        </div>}
      </div>
    </Card>}

    {/* ========== LIBRARY TAB ========== */}
    {tab==="library"&&<>
      {policies.length===0?(<Card>
        <div style={{textAlign:"center",padding:30}}>
          <div style={{width:64,height:64,borderRadius:"50%",background:`${C.orange}22`,display:"flex",alignItems:"center",justifyContent:"center",margin:"0 auto 16px"}}><FileText size={32} color={C.orange}/></div>
          <h3 style={{color:C.text,margin:"0 0 8px",fontSize:18,fontWeight:800}}>40 ISO 27001 Policy Templates Ready</h3>
          <p style={{color:C.textMuted,fontSize:13,margin:"0 0 20px",maxWidth:450,marginLeft:"auto",marginRight:"auto"}}>Generate all policy documents customized with your company name, logo, and branding. Set up your company details first in Settings.</p>
          <div style={{display:"flex",gap:8,justifyContent:"center"}}>
            <Btn variant="secondary" onClick={()=>setTab("settings")}><Settings size={14}/> Configure Settings</Btn>
            <Btn onClick={loadLibrary}><Zap size={14}/> Generate All Policies</Btn>
          </div>
        </div>
      </Card>):(<>
        {/* Search */}
        <div style={{marginBottom:16,position:"relative",maxWidth:360}}>
          <Search size={16} style={{position:"absolute",left:12,top:"50%",transform:"translateY(-50%)",color:C.textDim}}/>
          <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search policies..." style={{width:"100%",padding:"10px 12px 10px 36px",background:C.card,border:`1px solid ${C.border}`,borderRadius:10,color:C.text,fontSize:13,fontFamily:"inherit",boxSizing:"border-box"}}/>
        </div>

        {/* Policy list */}
        <div style={{display:"flex",flexDirection:"column",gap:6}}>
          {filtered.map((p,idx)=>{
            const actualIdx=policies.findIndex(x=>x.id===p.id);
            return(<div key={p.id} style={{display:"flex",alignItems:"center",gap:12,padding:"12px 16px",background:C.card,borderRadius:10,border:`1px solid ${p.enabled?C.border:`${C.border}44`}`,opacity:p.enabled?1:0.5,transition:"all 0.2s"}}>
              {/* Enable toggle */}
              <button onClick={()=>togglePolicy(p.id)} style={{background:p.enabled?C.green:`${C.border}`,border:"none",borderRadius:12,width:38,height:22,cursor:"pointer",position:"relative",transition:"background 0.2s",flexShrink:0}}>
                <div style={{width:16,height:16,borderRadius:"50%",background:"#fff",position:"absolute",top:3,left:p.enabled?19:3,transition:"left 0.2s"}}/>
              </button>
              {/* Policy info */}
              <div style={{flex:1,minWidth:0}}>
                <div style={{display:"flex",alignItems:"center",gap:8}}>
                  <FileText size={16} color={C.orange} style={{flexShrink:0}}/>
                  <span style={{fontSize:14,fontWeight:600,color:C.text,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{p.name}</span>
                </div>
                <div style={{fontSize:11,color:C.textDim,marginTop:2}}>{p.sections?.length||0} sections • {p.pages||"—"} pages</div>
              </div>
              {/* Status badge */}
              <Badge color={statusColors[p.status]||C.textMuted}>{statusLabels[p.status]||"Draft"}</Badge>
              {/* Actions */}
              <div style={{display:"flex",gap:4}}>
                {isAdmin&&<select value={p.status||"draft"} onChange={e=>setStatus(p.id,e.target.value)} style={{padding:"4px 6px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:6,color:C.text,fontSize:11,fontFamily:"inherit",cursor:"pointer"}}>
                  <option value="draft">Draft</option><option value="review">Review</option><option value="approved">Approved</option>
                </select>}
                <button onClick={()=>{setSelPolicyId(p.id);setTab("editor");}} title="Edit" style={{background:"none",border:"none",cursor:"pointer",color:C.orange,padding:4}}><Edit3 size={15}/></button>
                <button onClick={()=>showPreview(p.id)} title="Preview" style={{background:"none",border:"none",cursor:"pointer",color:C.blue,padding:4}}><Eye size={15}/></button>
                <button onClick={()=>downloadDoc(p)} title="Download" style={{background:"none",border:"none",cursor:"pointer",color:C.green,padding:4}}><Download size={15}/></button>
              </div>
            </div>);
          })}
        </div>
      </>)}
    </>}

    {/* ========== EDITOR TAB ========== */}
    {tab==="editor"&&selPolicy&&<div>
      <div style={{display:"flex",alignItems:"center",gap:12,marginBottom:16,flexWrap:"wrap"}}>
        <button onClick={()=>{setSelPolicyId(null);setTab("library");}} style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:8,padding:"8px 12px",cursor:"pointer",color:C.text,display:"flex",alignItems:"center",gap:4,fontFamily:"inherit",fontSize:13}}><ArrowLeft size={14}/> Back</button>
        <div style={{flex:1}}>
          <h3 style={{margin:0,fontSize:18,fontWeight:800,color:C.text}}>{selPolicy.name}</h3>
          <span style={{fontSize:12,color:C.textMuted}}>{selPolicy.sections?.length||0} sections — click any section to edit</span>
        </div>
        <Btn size="sm" variant="secondary" onClick={()=>regeneratePolicy(selPolicy.id)}><RefreshCw size={13}/> Reset to Template</Btn>
        <Btn size="sm" variant="secondary" onClick={()=>showPreview(selPolicy.id)}><Eye size={13}/> Preview</Btn>
        <Btn size="sm" onClick={()=>downloadDoc(selPolicy)}><Download size={13}/> Download</Btn>
      </div>

      {/* Sections editor */}
      <div style={{display:"flex",flexDirection:"column",gap:12}}>
        {(selPolicy.sections||[]).map((s,si)=>(
          <Card key={si}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:8}}>
              <h4 style={{margin:0,fontSize:14,fontWeight:700,color:C.orange}}>{si+1}. {s.heading}</h4>
              {editSection?.policyIdx===selPolicyIdx&&editSection?.sectionIdx===si?
                <div style={{display:"flex",gap:6}}>
                  <Btn size="sm" onClick={saveSectionEdit}><Save size={12}/> Save</Btn>
                  <Btn size="sm" variant="secondary" onClick={()=>setEditSection(null)}>Cancel</Btn>
                </div>:
                <button onClick={()=>{setEditSection({policyIdx:selPolicyIdx,sectionIdx:si});setEditText(s.body);}} style={{background:"none",border:"none",cursor:"pointer",color:C.orange,padding:4}}><Edit3 size={14}/></button>
              }
            </div>
            {editSection?.policyIdx===selPolicyIdx&&editSection?.sectionIdx===si?
              <textarea value={editText} onChange={e=>setEditText(e.target.value)} style={{width:"100%",minHeight:200,padding:12,background:C.bg,border:`1px solid ${C.orange}`,borderRadius:8,color:C.text,fontSize:13,fontFamily:"inherit",lineHeight:1.7,resize:"vertical",boxSizing:"border-box"}}/>:
              <div style={{fontSize:13,color:C.textMuted,lineHeight:1.7,whiteSpace:"pre-wrap",maxHeight:200,overflow:"auto",padding:"8px 0"}}>{s.body}</div>
            }
          </Card>
        ))}
      </div>
    </div>}

    {/* ========== PREVIEW TAB ========== */}
    {tab==="preview"&&selPolicy&&<div>
      <div style={{display:"flex",alignItems:"center",gap:12,marginBottom:16,flexWrap:"wrap"}}>
        <button onClick={()=>setTab("editor")} style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:8,padding:"8px 12px",cursor:"pointer",color:C.text,display:"flex",alignItems:"center",gap:4,fontFamily:"inherit",fontSize:13}}><ArrowLeft size={14}/> Back to Editor</button>
        <div style={{flex:1}}>
          <h3 style={{margin:0,fontSize:16,fontWeight:700,color:C.text}}>Preview: {selPolicy.name}</h3>
        </div>
        <Btn size="sm" onClick={()=>downloadDoc(selPolicy)}><Download size={13}/> Download .doc</Btn>
        <Btn size="sm" variant="secondary" onClick={()=>{
          const w=window.open('','_blank');
          if(w){w.document.write(previewHtml);w.document.close();}
        }}><ExternalLink size={13}/> Open in New Tab</Btn>
      </div>
      {/* Embedded preview */}
      <div style={{background:"#fff",borderRadius:12,border:`1px solid ${C.border}`,overflow:"hidden",boxShadow:"0 4px 24px rgba(0,0,0,0.3)"}}>
        <iframe srcDoc={previewHtml} style={{width:"100%",minHeight:"80vh",border:"none",borderRadius:12}} title="Policy Preview"/>
      </div>
    </div>}
  </div>);
};


// =============================================
// EVIDENCE (unchanged)
// =============================================
const EV_FREQ_OPTIONS = ["Monthly","Quarterly","Semi-Annual","Annual"];
const EV_STATUS_OPTIONS = [
  {value:"not_started",label:"Not Started",color:C.textDim,icon:"⬜"},
  {value:"in_progress",label:"In Progress",color:C.yellow,icon:"🔄"},
  {value:"uploaded",label:"Uploaded",color:C.blue,icon:"📤"},
  {value:"under_review",label:"Under Review",color:"#a855f7",icon:"🔍"},
  {value:"approved",label:"Approved",color:C.green,icon:"✅"},
  {value:"rejected",label:"Rejected",color:C.red,icon:"❌"},
  {value:"not_applicable",label:"N/A",color:C.textDim,icon:"➖"},
];
const evStatusMap = Object.fromEntries(EV_STATUS_OPTIONS.map(s=>[s.value,s]));

const EvidenceModule = ({data,setData,role:userRole}) => {
  const [toast,setToast]=useState(null);const [preview,setPreview]=useState(null);
  const [rejectModal,setRejectModal]=useState(null);const [rejectComment,setRejectComment]=useState("");
  const {token,user,orgId}=useAuth();
  const canDoApprove = canApprove(userRole||"client_user","evidence");
  const canChange = userRole !== "client_employee";
  const evList = data.evidenceList||[];

  const handleUploadList = async(file)=>{
    try{const{sheetNames,allSheets}=await parseExcelToSheets(file);const rows=allSheets[sheetNames[0]]||[];const items=rows.map((r,i)=>({...r,_id:secureId('ev'),_evidenceFile:null,_evStatus:"not_started",_evFrequency:"Annual",_evReviewedBy:"",_evReviewedAt:"",_evReviewComment:""}));setData(d=>({...d,evidenceList:items}));setToast({msg:`${items.length} evidence items loaded!`,type:"success"});}catch{setToast({msg:"Error reading file",type:"error"});}
  };

  const handleEvUpload = async(id,file)=>{
    try{const ref=await uploadToStorage(token,orgId||user.id,"evidence",file);setData(d=>({...d,evidenceList:d.evidenceList.map(e=>e._id===id?{...e,_evidenceFile:ref,_evStatus:e._evStatus==="not_started"?"uploaded":e._evStatus}:e)}));setToast({msg:"Evidence uploaded!",type:"success"});}catch(e){setToast({msg:"Upload failed",type:"error"});}
  };

  const updateField = (id,field,value)=>{
    const updates = {[field]:value};
    if(field==="_evStatus" && (value==="approved"||value==="rejected")) {
      updates._evReviewedBy = user.email;
      updates._evReviewedAt = new Date().toISOString();
      if(value==="approved") updates._evReviewComment = "";
    }
    setData(d=>({...d,evidenceList:d.evidenceList.map(e=>e._id===id?{...e,...updates}:e)}));
  };

  const rejectEv = (id)=>{
    setData(d=>({...d,evidenceList:d.evidenceList.map(e=>e._id===id?{...e,_evStatus:"rejected",_evReviewedBy:user.email,_evReviewedAt:new Date().toISOString(),_evReviewComment:rejectComment}:e)}));
    setRejectModal(null);setRejectComment("");setToast({msg:"Evidence rejected.",type:"warning"});
  };

  const cols = evList.length>0?Object.keys(evList[0]).filter(k=>!k.startsWith("_")):[];

  // Stats
  const uploaded = evList.filter(e=>e._evidenceFile).length;
  const approved = evList.filter(e=>e._evStatus==="approved").length;
  const rejected = evList.filter(e=>e._evStatus==="rejected").length;
  const inProgress = evList.filter(e=>e._evStatus==="in_progress"||e._evStatus==="uploaded"||e._evStatus==="under_review").length;

  return (<div>
    {toast&&<Toast {...toast} onClose={()=>setToast(null)}/>}
    {preview&&<FilePreviewModal file={preview} onClose={()=>setPreview(null)}/>}
    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20}}>
      <div><h2 style={{margin:0,fontSize:22,fontWeight:800,color:C.text}}>Evidence</h2><p style={{color:C.textMuted,margin:"4px 0 0",fontSize:13}}>Upload evidence list, set frequency & status for each item</p></div>
      <FileUploadBtn onFile={handleUploadList} accept=".xlsx,.xls,.csv" label="Upload Evidence List"/>
    </div>
    {evList.length>0&&<div style={{display:"flex",gap:12,flexWrap:"wrap",marginBottom:16}}>
      <Stat label="Total Items" value={evList.length} icon={FileText} color={C.textMuted}/>
      <Stat label="With Files" value={uploaded} icon={Upload} color={C.blue}/>
      <Stat label="Approved" value={approved} icon={CheckCircle} color={C.green}/>
      <Stat label="Rejected" value={rejected} icon={AlertCircle} color={C.red}/>
      <Stat label="In Progress" value={inProgress} icon={Clock} color={C.yellow}/>
    </div>}
    {evList.length>0?(<Card><div style={{overflow:"auto",maxHeight:600}}>
      <table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}><thead><tr style={{background:C.bg,position:"sticky",top:0,zIndex:1}}>
        {cols.map(c=><th key={c} style={{padding:"8px 10px",textAlign:"left",color:C.orange,fontWeight:700,fontSize:11,textTransform:"uppercase",borderBottom:`2px solid ${C.border}`,whiteSpace:"nowrap"}}>{c}</th>)}
        <th style={{padding:"8px 10px",textAlign:"left",color:C.orange,fontWeight:700,fontSize:11,textTransform:"uppercase",borderBottom:`2px solid ${C.border}`}}>Evidence</th>
        <th style={{padding:"8px 10px",textAlign:"center",color:C.orange,fontWeight:700,fontSize:11,textTransform:"uppercase",borderBottom:`2px solid ${C.border}`}}>Frequency</th>
        <th style={{padding:"8px 10px",textAlign:"center",color:C.orange,fontWeight:700,fontSize:11,textTransform:"uppercase",borderBottom:`2px solid ${C.border}`}}>Status</th>
        {canDoApprove&&<th style={{padding:"8px 10px",textAlign:"center",color:C.orange,fontWeight:700,fontSize:11,textTransform:"uppercase",borderBottom:`2px solid ${C.border}`}}>Review</th>}
      </tr></thead><tbody>{evList.map(e=>{
        const st = evStatusMap[e._evStatus]||evStatusMap.not_started;
        return <tr key={e._id} style={{borderBottom:`1px solid ${C.border}22`}}>
        {cols.map(c=><td key={c} style={{padding:"7px 10px",color:C.text,maxWidth:250,overflow:"hidden",textOverflow:"ellipsis"}}>{String(e[c]??"")}</td>)}
        {/* Evidence file */}
        <td style={{padding:"7px 10px"}}>{e._evidenceFile?<button onClick={()=>setPreview(e._evidenceFile)} style={{background:`${C.green}22`,border:`1px solid ${C.green}44`,borderRadius:6,cursor:"pointer",padding:"3px 8px",color:C.green,fontSize:11,fontWeight:700,display:"flex",alignItems:"center",gap:4,fontFamily:"inherit"}}><CheckCircle size={10}/> {e._evidenceFile.name}</button>:<InlineUpload onUpload={(f)=>handleEvUpload(e._id,f)}/>}</td>
        {/* Frequency dropdown */}
        <td style={{padding:"7px 6px",textAlign:"center"}}>{canChange?(
          <select value={e._evFrequency||"Annual"} onChange={ev=>updateField(e._id,"_evFrequency",ev.target.value)} style={{padding:"4px 6px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:6,color:C.text,fontSize:11,fontFamily:"inherit",cursor:"pointer",width:"100%",maxWidth:110}}>
            {EV_FREQ_OPTIONS.map(f=><option key={f} value={f} style={{background:C.bg,color:C.text}}>{f}</option>)}
          </select>
        ):(
          <span style={{color:C.textMuted,fontSize:11}}>{e._evFrequency||"Annual"}</span>
        )}</td>
        {/* Status dropdown */}
        <td style={{padding:"7px 6px",textAlign:"center"}}>{canChange?(
          <select value={e._evStatus||"not_started"} onChange={ev=>{
            const v=ev.target.value;
            if((v==="approved"||v==="rejected")&&!canDoApprove){setToast({msg:"Only SecComply can set Approved/Rejected",type:"error"});return;}
            if(v==="rejected"&&canDoApprove){setRejectModal(e._id);setRejectComment("");return;}
            updateField(e._id,"_evStatus",v);
          }} style={{padding:"4px 6px",background:`${st.color}11`,border:`1px solid ${st.color}44`,borderRadius:6,color:st.color,fontSize:11,fontWeight:700,fontFamily:"inherit",cursor:"pointer",width:"100%",maxWidth:130}}>
            {EV_STATUS_OPTIONS.filter(s=>{
              if((s.value==="approved"||s.value==="rejected")&&!canDoApprove) return false;
              return true;
            }).map(s=><option key={s.value} value={s.value} style={{background:C.bg,color:C.text}}>{s.icon} {s.label}</option>)}
          </select>
        ):(
          <div style={{display:"inline-flex",alignItems:"center",gap:4,padding:"4px 8px",borderRadius:6,background:`${st.color}11`,border:`1px solid ${st.color}44`}}>
            <span style={{fontSize:11}}>{st.icon}</span>
            <span style={{color:st.color,fontSize:11,fontWeight:700}}>{st.label}</span>
          </div>
        )}</td>
        {/* Review column — SecComply only */}
        {canDoApprove&&<td style={{padding:"7px 6px",textAlign:"center"}}>
          {e._evidenceFile?(
            <div style={{display:"flex",gap:3,justifyContent:"center"}}>
              <button onClick={()=>{updateField(e._id,"_evStatus","approved");setToast({msg:"Approved!",type:"success"});}} title="Approve" style={{padding:"4px 7px",borderRadius:5,background:`${C.green}22`,border:`1px solid ${C.green}44`,color:C.green,fontSize:10,fontWeight:700,cursor:"pointer",fontFamily:"inherit"}}><ThumbsUp size={10}/></button>
              <button onClick={()=>{setRejectModal(e._id);setRejectComment("");}} title="Reject" style={{padding:"4px 7px",borderRadius:5,background:`${C.red}22`,border:`1px solid ${C.red}44`,color:C.red,fontSize:10,fontWeight:700,cursor:"pointer",fontFamily:"inherit"}}><ThumbsDown size={10}/></button>
            </div>
          ):<span style={{color:C.textDim,fontSize:11}}>—</span>}
          {e._evReviewedBy&&<div style={{fontSize:9,color:C.textDim,marginTop:2}}>{e._evReviewedBy.split("@")[0]} · {e._evReviewedAt?.slice(0,10)}</div>}
          {e._evStatus==="rejected"&&e._evReviewComment&&<div style={{fontSize:9,color:C.red,marginTop:1}} title={e._evReviewComment}>❌ {e._evReviewComment.slice(0,20)}{e._evReviewComment.length>20?"...":""}</div>}
        </td>}
      </tr>})}</tbody></table>
    </div></Card>):<Card><Empty msg="Upload an Excel file with your evidence list"/></Card>}

    {/* Evidence Reject Modal */}
    <Modal open={!!rejectModal} onClose={()=>setRejectModal(null)} title="Reject Evidence">
      <div>
        <p style={{color:C.textMuted,fontSize:13,marginBottom:12}}>Provide a reason for rejection. This will be visible to the client.</p>
        <textarea value={rejectComment} onChange={e=>setRejectComment(e.target.value)} placeholder="Reason for rejection..." rows={3} style={{width:"100%",padding:"10px 12px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,color:C.text,fontSize:13,fontFamily:"inherit",resize:"vertical"}}/>
        <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:16}}>
          <Btn variant="secondary" onClick={()=>setRejectModal(null)}>Cancel</Btn>
          <Btn variant="danger" onClick={()=>rejectEv(rejectModal)}><ThumbsDown size={14}/> Reject</Btn>
        </div>
      </div>
    </Modal>
  </div>);
};

// =============================================
// ROLES & RACI — with Export
// =============================================
const RolesRaci = ({data,setData}) => {
  const [tab,setTab]=useState("roles");const [modal,setModal]=useState(null);const [deptInput,setDeptInput]=useState("");const [selectedDept,setSelectedDept]=useState(null);const [toast,setToast]=useState(null);
  const {token,user,orgId}=useAuth();
  const depts=[...new Set(data.roles.map(r=>r.department))];
  const saveRole=(r)=>{if(r.id){setData(d=>({...d,roles:d.roles.map(x=>x.id===r.id?{...r,department:selectedDept}:x)}));}else{setData(d=>({...d,roles:[...d.roles,{...r,id:secureId('ro'),department:selectedDept}]}));}setToast({msg:"Saved!",type:"success"});setModal(null);};
  const saveRaci=(item)=>{if(item.id){setData(d=>({...d,raci:d.raci.map(r=>r.id===item.id?item:r)}));}else{setData(d=>({...d,raci:[...d.raci,{...item,id:secureId('rc')}]}));}setToast({msg:"Saved!",type:"success"});setModal(null);};
  const expRoles=()=>{const wb=XLSX.utils.book_new();let totalRows=0;depts.forEach(d=>{const rows=data.roles.filter(r=>r.department===d).map(r=>({Role:r.role_name,KRA:r.kra,KPI:r.kpi}));totalRows+=rows.length;if(rows.length>0){const wm=addExportWatermark(rows,user?.email||"",orgId||"");const ws=XLSX.utils.json_to_sheet(wm);ws["!cols"]=[{wch:25},{wch:40},{wch:40}];XLSX.utils.book_append_sheet(wb,ws,d.substring(0,31));}});if(wb.SheetNames.length===0)XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet([{Role:"",KRA:"",KPI:""}]),"Empty");XLSX.writeFile(wb,"Roles.xlsx");auditLog(token,"data_export",{resource_type:"roles",org_id:orgId,record_count:totalRows},"warning");};
  const expRaci=()=>{const rows=data.raci.map(r=>({Process:r.process_name,Responsible:r.responsible,Accountable:r.accountable,Consulted:r.consulted,Informed:r.informed}));const wm=addExportWatermark(rows.length>0?rows:[{Process:"",Responsible:"",Accountable:"",Consulted:"",Informed:""}],user?.email||"",orgId||"");const ws=XLSX.utils.json_to_sheet(wm);const wb=XLSX.utils.book_new();ws["!cols"]=[{wch:30},{wch:20},{wch:20},{wch:20},{wch:20}];XLSX.utils.book_append_sheet(wb,ws,"RACI Matrix");XLSX.writeFile(wb,"RACI_Matrix.xlsx");auditLog(token,"data_export",{resource_type:"raci_matrix",org_id:orgId,record_count:rows.length},"warning");};
  return (<div>
    {toast&&<Toast {...toast} onClose={()=>setToast(null)}/>}
    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20}}>
      <h2 style={{margin:0,fontSize:22,fontWeight:800,color:C.text}}>Roles & RACI</h2>
      <div style={{display:"flex",gap:8}}>
        {tab==="roles"&&data.roles.length>0&&<Btn variant="secondary" size="sm" onClick={expRoles}><Download size={14}/> Export Roles</Btn>}
        {tab==="raci"&&data.raci.length>0&&<Btn variant="secondary" size="sm" onClick={expRaci}><Download size={14}/> Export RACI</Btn>}
        <Btn onClick={()=>setModal(tab==="roles"?{role_name:"",kra:"",kpi:""}:{process_name:"",responsible:"",accountable:"",consulted:"",informed:"",_type:"raci"})}><Plus size={14}/> Add {tab==="roles"?"Role":"RACI"}</Btn>
      </div>
    </div>
    <div style={{display:"flex",gap:4,marginBottom:16,background:C.card,borderRadius:10,padding:4,width:"fit-content"}}>
      {["roles","raci"].map(t=><button key={t} onClick={()=>{setTab(t);setSelectedDept(null);}} style={{padding:"8px 20px",border:"none",borderRadius:8,cursor:"pointer",fontWeight:700,fontSize:13,background:tab===t?C.orange:"transparent",color:tab===t?"#fff":C.textMuted,fontFamily:"inherit"}}>{t==="roles"?"Roles & KRA/KPI":"RACI Matrix"}</button>)}
    </div>
    {tab==="roles"?(!selectedDept?(<Card title="Select or Create Department">
      <div style={{display:"flex",gap:8,marginBottom:16}}><input value={deptInput} onChange={e=>setDeptInput(e.target.value)} placeholder="New department name..." style={{flex:1,padding:"8px 12px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,color:C.text,fontSize:13,fontFamily:"inherit"}}/><Btn onClick={()=>{if(deptInput.trim()){setSelectedDept(deptInput.trim());setDeptInput("");}}}>Create</Btn></div>
      {depts.length>0?<div style={{display:"flex",gap:8,flexWrap:"wrap"}}>{depts.map(d=><button key={d} onClick={()=>setSelectedDept(d)} style={{padding:"10px 18px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:10,color:C.text,cursor:"pointer",fontWeight:600,fontSize:13,fontFamily:"inherit"}}>{d} <span style={{color:C.textDim,marginLeft:6}}>({data.roles.filter(r=>r.department===d).length})</span></button>)}</div>:<Empty msg="No departments yet"/>}
    </Card>):(<div>
      <Btn variant="ghost" onClick={()=>setSelectedDept(null)} style={{marginBottom:12}}><ArrowLeft size={14}/> Back</Btn>
      <Card title={`${selectedDept} — Roles`}>
        {data.roles.filter(r=>r.department===selectedDept).length===0?<Empty msg="No roles yet" action="Add Role" onAction={()=>setModal({role_name:"",kra:"",kpi:""})}/>:(
          <div style={{overflowX:"auto"}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:13}}><thead><tr style={{background:C.bg}}>{["Role","KRA","KPI",""].map(h=><th key={h} style={{padding:"10px 12px",textAlign:"left",color:C.textMuted,fontWeight:700,fontSize:11,borderBottom:`1px solid ${C.border}`}}>{h}</th>)}</tr></thead><tbody>{data.roles.filter(r=>r.department===selectedDept).map(r=><tr key={r.id} style={{borderBottom:`1px solid ${C.border}22`}}>
            <td style={{padding:"10px 12px",color:C.text,fontWeight:600}}>{r.role_name}</td>
            <td style={{padding:"10px 12px",color:C.textMuted,fontSize:12}}>{r.kra}</td>
            <td style={{padding:"10px 12px",color:C.textMuted,fontSize:12}}>{r.kpi}</td>
            <td style={{padding:"10px 12px"}}><div style={{display:"flex",gap:6}}><button onClick={()=>setModal({...r})} style={{background:"none",border:"none",cursor:"pointer",color:C.orange}}><Edit3 size={15}/></button><button onClick={()=>setData(d=>({...d,roles:d.roles.filter(x=>x.id!==r.id)}))} style={{background:"none",border:"none",cursor:"pointer",color:C.red}}><Trash2 size={15}/></button></div></td>
          </tr>)}</tbody></table></div>)}
      </Card>
    </div>)):(
      <Card>{data.raci.length===0?<Empty msg="No RACI entries" action="Add RACI" onAction={()=>setModal({process_name:"",responsible:"",accountable:"",consulted:"",informed:"",_type:"raci"})}/>:(
        <div style={{overflowX:"auto"}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:13}}><thead><tr style={{background:C.bg}}>{["Process","R","A","C","I",""].map(h=><th key={h} style={{padding:"10px 12px",textAlign:"left",color:C.textMuted,fontWeight:700,fontSize:11,borderBottom:`1px solid ${C.border}`}}>{h}</th>)}</tr></thead><tbody>{data.raci.map(r=><tr key={r.id} style={{borderBottom:`1px solid ${C.border}22`}}>
          <td style={{padding:"10px 12px",color:C.text,fontWeight:600}}>{r.process_name}</td>
          {["responsible","accountable","consulted","informed"].map(f=><td key={f} style={{padding:"10px 12px",color:C.textMuted,fontSize:12}}>{r[f]||"—"}</td>)}
          <td style={{padding:"10px 12px"}}><div style={{display:"flex",gap:6}}><button onClick={()=>setModal({...r,_type:"raci"})} style={{background:"none",border:"none",cursor:"pointer",color:C.orange}}><Edit3 size={15}/></button><button onClick={()=>setData(d=>({...d,raci:d.raci.filter(x=>x.id!==r.id)}))} style={{background:"none",border:"none",cursor:"pointer",color:C.red}}><Trash2 size={15}/></button></div></td>
        </tr>)}</tbody></table></div>)}</Card>
    )}
    <Modal open={!!modal} onClose={()=>setModal(null)} title={modal?._type==="raci"?"RACI Entry":"Role"}>
      {modal&&(modal._type==="raci"?(<div>
        <Input label="Process" value={modal.process_name||""} onChange={v=>setModal(p=>({...p,process_name:v}))}/>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}><Input label="Responsible" value={modal.responsible||""} onChange={v=>setModal(p=>({...p,responsible:v}))}/><Input label="Accountable" value={modal.accountable||""} onChange={v=>setModal(p=>({...p,accountable:v}))}/><Input label="Consulted" value={modal.consulted||""} onChange={v=>setModal(p=>({...p,consulted:v}))}/><Input label="Informed" value={modal.informed||""} onChange={v=>setModal(p=>({...p,informed:v}))}/></div>
        <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:16}}><Btn variant="secondary" onClick={()=>setModal(null)}>Cancel</Btn><Btn onClick={()=>saveRaci(modal)}><Save size={14}/> Save</Btn></div>
      </div>):(<div>
        <Input label="Role Name" value={modal.role_name||""} onChange={v=>setModal(p=>({...p,role_name:v}))}/>
        <Input label="KRA" value={modal.kra||""} onChange={v=>setModal(p=>({...p,kra:v}))} textarea/>
        <Input label="KPI" value={modal.kpi||""} onChange={v=>setModal(p=>({...p,kpi:v}))} textarea/>
        <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:16}}><Btn variant="secondary" onClick={()=>setModal(null)}>Cancel</Btn><Btn onClick={()=>saveRole(modal)}><Save size={14}/> Save</Btn></div>
      </div>))}
    </Modal>
  </div>);
};

// =============================================
// VAPT (unchanged)
// =============================================
const VAPTManagement = ({data,setData}) => {
  const [toast,setToast]=useState(null);const [modal,setModal]=useState(null);const [preview,setPreview]=useState(null);
  const {token,user,orgId}=useAuth();
  const vapt = data.vapt||[];
  const handleUpload = async(file)=>{
    try {
      const {sheetNames,allSheets}=await parseExcelToSheets(file);const rows=allSheets[sheetNames[0]]||[];
      const findings = rows.map((r,i)=>{
        const name=r["Finding"]||r["Vulnerability"]||r["finding_name"]||r["Name"]||r["Title"]||r["Issue"]||Object.values(r)[0]||`Finding ${i+1}`;
        const sev=r["Severity"]||r["Risk"]||r["severity"]||r["Priority"]||"Medium";
        const desc=r["Description"]||r["description"]||r["Details"]||"";
        const rem=r["Remediation"]||r["remediation"]||r["Fix"]||r["Recommendation"]||"";
        return {id:secureId('v'),finding_name:String(name),severity:String(sev),description:String(desc),remediation:String(rem),status:"Open"};
      });
      let fileRef=null;
      try{fileRef=await uploadToStorage(token,orgId||user.id,"vapt",file);}catch(e){}
      setData(d=>({...d,vapt:findings,vaptFileRef:fileRef,vaptFileName:file.name}));
      setToast({msg:`${findings.length} vulnerabilities identified!`,type:"success"});
    } catch{setToast({msg:"Error reading file",type:"error"});}
  };
  const sevCol={Critical:C.red,High:C.orange,Medium:C.yellow,Low:C.green,Info:C.blue};
  const statCol={Open:C.red,Patched:C.yellow,Closed:C.green};
  const saveFinding=(f)=>{if(f.id&&vapt.find(v=>v.id===f.id)){setData(d=>({...d,vapt:d.vapt.map(v=>v.id===f.id?f:v)}));}else{setData(d=>({...d,vapt:[...(d.vapt||[]),{...f,id:secureId('v')}]}));}setToast({msg:"Saved!",type:"success"});setModal(null);};
  return (<div>
    {toast&&<Toast {...toast} onClose={()=>setToast(null)}/>}
    {preview&&<FilePreviewModal file={preview} onClose={()=>setPreview(null)}/>}
    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20}}>
      <div><h2 style={{margin:0,fontSize:22,fontWeight:800,color:C.text}}>VAPT</h2><p style={{color:C.textMuted,margin:"4px 0 0",fontSize:13}}>Upload report to auto-identify vulnerabilities</p></div>
      <div style={{display:"flex",gap:8}}><FileUploadBtn onFile={handleUpload} accept=".xlsx,.xls,.csv" label="Upload Report"/><Btn variant="secondary" onClick={()=>setModal({id:"",finding_name:"",severity:"Medium",description:"",status:"Open",remediation:""})}><Plus size={14}/> Add Manual</Btn></div>
    </div>
    {data.vaptFileName&&<div style={{marginBottom:12,padding:"8px 14px",background:C.bg,borderRadius:8,border:`1px solid ${C.border}`,display:"flex",alignItems:"center",gap:8}}><FileSpreadsheet size={14} color={C.green}/><span style={{color:C.text,fontSize:13}}>{data.vaptFileName}</span><Badge color={C.green}>{vapt.length} findings</Badge>{data.vaptFileRef?.url&&<a href={data.vaptFileRef.url} target="_blank" rel="noreferrer" style={{color:C.orange,fontSize:12,fontWeight:600,textDecoration:"none",marginLeft:"auto"}}>Download ↗</a>}</div>}
    <Card>
      {vapt.length===0?<Empty msg="Upload a VAPT report to identify vulnerabilities"/>:(
        <div style={{overflowX:"auto"}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:13}}><thead><tr style={{background:C.bg}}>{["Finding","Severity","Status",""].map(h=><th key={h} style={{padding:"10px 12px",textAlign:"left",color:C.textMuted,fontWeight:700,fontSize:11,borderBottom:`1px solid ${C.border}`}}>{h}</th>)}</tr></thead><tbody>{vapt.map(f=><tr key={f.id} style={{borderBottom:`1px solid ${C.border}22`}}>
          <td style={{padding:"10px 12px"}}><div style={{color:C.text,fontWeight:600}}>{f.finding_name}</div>{f.description&&<div style={{fontSize:11,color:C.textMuted,marginTop:2}}>{f.description.substring(0,80)}</div>}</td>
          <td style={{padding:"10px 12px"}}><Badge color={sevCol[f.severity]||C.textMuted}>{f.severity}</Badge></td>
          <td style={{padding:"10px 12px"}}><select value={f.status} onChange={e=>setData(d=>({...d,vapt:d.vapt.map(v=>v.id===f.id?{...v,status:e.target.value}:v)}))} style={{padding:"4px 8px",background:"transparent",border:`1px solid ${(statCol[f.status]||C.textMuted)}44`,borderRadius:6,color:statCol[f.status]||C.textMuted,fontSize:12,fontWeight:600,fontFamily:"inherit"}}>{["Open","Patched","Closed"].map(s=><option key={s} value={s} style={{background:C.bg,color:C.text}}>{s}</option>)}</select></td>
          <td style={{padding:"10px 12px"}}><div style={{display:"flex",gap:6}}><button onClick={()=>setModal({...f})} style={{background:"none",border:"none",cursor:"pointer",color:C.orange}}><Edit3 size={15}/></button><button onClick={()=>setData(d=>({...d,vapt:d.vapt.filter(v=>v.id!==f.id)}))} style={{background:"none",border:"none",cursor:"pointer",color:C.red}}><Trash2 size={15}/></button></div></td>
        </tr>)}</tbody></table></div>)}
    </Card>
    <Modal open={!!modal} onClose={()=>setModal(null)} title="Finding" wide>
      {modal&&<div>
        <Input label="Finding Name" value={modal.finding_name} onChange={v=>setModal(m=>({...m,finding_name:v}))}/>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}><Input label="Severity" value={modal.severity} onChange={v=>setModal(m=>({...m,severity:v}))} select options={["Critical","High","Medium","Low","Info"]}/><Input label="Status" value={modal.status} onChange={v=>setModal(m=>({...m,status:v}))} select options={["Open","Patched","Closed"]}/></div>
        <Input label="Description" value={modal.description} onChange={v=>setModal(m=>({...m,description:v}))} textarea/><Input label="Remediation" value={modal.remediation} onChange={v=>setModal(m=>({...m,remediation:v}))} textarea/>
        <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:16}}><Btn variant="secondary" onClick={()=>setModal(null)}>Cancel</Btn><Btn onClick={()=>saveFinding(modal)}><Save size={14}/> Save</Btn></div>
      </div>}
    </Modal>
  </div>);
};

// =============================================
// TRAINING — Upload & Preview
// =============================================
const TrainingModule = ({data,setData,role:userRole,members:allMembers,orgId}) => {
  const [toast,setToast]=useState(null);const [preview,setPreview]=useState(null);const [uploading,setUploading]=useState(false);
  const [editId,setEditId]=useState(null);const [editName,setEditName]=useState("");const [editDesc,setEditDesc]=useState("");
  const [expandTracker,setExpandTracker]=useState(null);
  const {token,user}=useAuth();
  const trainings = data.trainings||[];
  const completions = data.trainingCompletions||[];
  const isEmployee = userRole==="client_employee";
  const canManage = !isEmployee; // everyone except client_employee can upload/edit/delete

  // Get org employees (client_employee role) for tracking
  const orgEmployees = useMemo(()=>(allMembers||[]).filter(m=>m.orgId===orgId&&m.role==="client_employee"&&m.status==="active"),[allMembers,orgId]);

  // Completion helpers
  const getCompletions = (tId)=>completions.filter(c=>c.trainingId===tId);
  const isCompletedBy = (tId,email)=>completions.some(c=>c.trainingId===tId&&c.email===email);
  const completedCount = (tId)=>orgEmployees.filter(e=>isCompletedBy(tId,e.email)).length;
  const remaining = (tId)=>orgEmployees.filter(e=>!isCompletedBy(tId,e.email));

  const markComplete = (tId) => {
    if(isCompletedBy(tId,user.email)) return;
    setData(d=>({...d,trainingCompletions:[...(d.trainingCompletions||[]),{trainingId:tId,email:user.email,name:user.email.split("@")[0],completedAt:new Date().toISOString()}]}));
    setToast({msg:"Marked as completed!",type:"success"});
  };

  const unmarkComplete = (tId,email) => {
    setData(d=>({...d,trainingCompletions:(d.trainingCompletions||[]).filter(c=>!(c.trainingId===tId&&c.email===email))}));
  };

  const handleUpload = async(file) => {
    setUploading(true);
    try {
      const ref = await uploadToStorage(token,orgId||user.id,"training",file);
      const ext = file.name.split(".").pop().toLowerCase();
      const typeLabel = {pptx:"Presentation",ppt:"Presentation",pdf:"PDF Document",docx:"Word Document",doc:"Word Document",xlsx:"Spreadsheet",mp4:"Video",png:"Image",jpg:"Image",jpeg:"Image"}[ext]||"File";
      const item = {id:secureId('tr'),name:file.name.replace(/\.[^.]+$/,""),description:"",file:ref,typeLabel,date:new Date().toISOString().slice(0,10),status:"Active"};
      setData(d=>({...d,trainings:[...(d.trainings||[]),item]}));
      setToast({msg:`Training "${item.name}" uploaded!`,type:"success"});
    } catch(e) { setToast({msg:e.message.includes("not allowed")||e.message.includes("too large")?"Upload error: "+e.message:"Upload failed. Please try again.",type:"error"}); }
    setUploading(false);
  };

  const remove = (id) => { setData(d=>({...d,trainings:(d.trainings||[]).filter(t=>t.id!==id),trainingCompletions:(d.trainingCompletions||[]).filter(c=>c.trainingId!==id)})); setToast({msg:"Removed",type:"success"}); };

  const saveEdit = () => {
    setData(d=>({...d,trainings:(d.trainings||[]).map(t=>t.id===editId?{...t,name:editName,description:editDesc}:t)}));
    setEditId(null); setToast({msg:"Updated!",type:"success"});
  };

  const iconForExt = (ext) => {
    if(["pptx","ppt","ppsx"].includes(ext)) return {icon:Monitor,color:"#A855F7"};
    if(["pdf"].includes(ext)) return {icon:FileText,color:C.red};
    if(["docx","doc"].includes(ext)) return {icon:FileText,color:C.blue};
    if(["xlsx","xls","csv"].includes(ext)) return {icon:FileSpreadsheet,color:C.green};
    if(["mp4","webm","mov"].includes(ext)) return {icon:Monitor,color:C.yellow};
    if(["png","jpg","jpeg","gif","svg"].includes(ext)) return {icon:Image,color:C.orange};
    return {icon:File,color:C.textMuted};
  };

  // Overall stats
  const totalPairs = trainings.length * orgEmployees.length;
  const totalCompleted = trainings.reduce((s,t)=>s+completedCount(t.id),0);
  const overallPct = totalPairs>0?Math.round((totalCompleted/totalPairs)*100):0;

  return (<div>
    {toast&&<Toast {...toast} onClose={()=>setToast(null)}/>}
    {preview&&<FilePreviewModal file={preview} onClose={()=>setPreview(null)}/>}
    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20}}>
      <div>
        <h2 style={{margin:0,fontSize:22,fontWeight:800,color:C.text}}>Training</h2>
        <p style={{color:C.textMuted,margin:"4px 0 0",fontSize:13}}>{isEmployee?"View and complete assigned training materials":"Upload training materials and track employee completion"}</p>
      </div>
      {canManage&&<FileUploadBtn onFile={handleUpload} accept="*" label={uploading?"Uploading...":"Upload Material"}/>}
    </div>

    {/* Completion overview stats — visible to managers */}
    {canManage&&trainings.length>0&&orgEmployees.length>0&&(
      <div style={{display:"flex",gap:12,flexWrap:"wrap",marginBottom:16}}>
        <Stat label="Trainings" value={trainings.length} icon={Monitor} color="#A855F7"/>
        <Stat label="Employees" value={orgEmployees.length} icon={Users} color={C.blue}/>
        <Stat label="Completed" value={totalCompleted} icon={CheckCircle} color={C.green}/>
        <Stat label="Remaining" value={totalPairs-totalCompleted} icon={Clock} color={C.yellow}/>
        <div style={{background:C.card,borderRadius:12,border:`1px solid ${C.border}`,padding:"12px 20px",display:"flex",alignItems:"center",gap:10,minWidth:140}}>
          <div style={{width:40,height:40,borderRadius:"50%",background:`conic-gradient(${C.green} ${overallPct*3.6}deg, ${C.border} 0deg)`,display:"flex",alignItems:"center",justifyContent:"center"}}>
            <div style={{width:30,height:30,borderRadius:"50%",background:C.card,display:"flex",alignItems:"center",justifyContent:"center",fontSize:11,fontWeight:800,color:C.green}}>{overallPct}%</div>
          </div>
          <div><div style={{fontSize:10,color:C.textDim,fontWeight:700,textTransform:"uppercase"}}>Overall</div><div style={{fontSize:14,fontWeight:800,color:C.text}}>{totalCompleted}/{totalPairs}</div></div>
        </div>
      </div>
    )}

    {trainings.length===0 ? (
      <Card>
        <Empty msg={isEmployee?"No training materials assigned yet":"No training materials yet — upload PPT, PDF, DOCX, or video files"}/>
        {canManage&&<div style={{textAlign:"center",marginTop:8,fontSize:12,color:C.textDim}}>
          Supported: PPTX, PDF, DOCX, XLSX, MP4, images, and more. All files can be previewed in-app.
        </div>}
      </Card>
    ) : (
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(320px,1fr))",gap:14}}>
        {trainings.map(t => {
          const ext = (t.file?.type||t.file?.name?.split(".").pop()||"").toLowerCase();
          const {icon:Icon,color} = iconForExt(ext);
          const done = completedCount(t.id);
          const total = orgEmployees.length;
          const pct = total>0?Math.round((done/total)*100):0;
          const left = remaining(t.id);
          const myDone = isCompletedBy(t.id,user.email);
          const isExpanded = expandTracker===t.id;
          const comps = getCompletions(t.id);
          return (
            <div key={t.id} style={{background:C.card,borderRadius:12,border:`1px solid ${C.border}`,overflow:"hidden",transition:"all 0.2s"}}>
              {/* Preview thumbnail area */}
              <div style={{height:130,background:`linear-gradient(135deg,${color}15,${C.bg})`,display:"flex",alignItems:"center",justifyContent:"center",borderBottom:`1px solid ${C.border}`,position:"relative",cursor:"pointer"}} onClick={()=>t.file&&setPreview(t.file)}>
                <Icon size={44} color={color} strokeWidth={1.5}/>
                <div style={{position:"absolute",top:10,right:10}}><Badge color={color} bg={`${color}22`}>{ext.toUpperCase()}</Badge></div>
                {t.file?.url&&<div style={{position:"absolute",bottom:10,right:10,padding:"4px 10px",borderRadius:6,background:`${C.orange}cc`,color:"#fff",fontSize:11,fontWeight:700,display:"flex",alignItems:"center",gap:4}}><Eye size={11}/> Preview</div>}
              </div>
              {/* Info */}
              <div style={{padding:14}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:6}}>
                  <div style={{color:C.text,fontSize:14,fontWeight:700,flex:1,lineHeight:1.3}}>{t.name}</div>
                  {canManage&&<div style={{display:"flex",gap:4,flexShrink:0,marginLeft:8}}>
                    <button onClick={()=>{setEditId(t.id);setEditName(t.name);setEditDesc(t.description||"");}} style={{background:"none",border:"none",cursor:"pointer",color:C.orange,padding:2}}><Edit3 size={13}/></button>
                    <button onClick={()=>remove(t.id)} style={{background:"none",border:"none",cursor:"pointer",color:C.red,padding:2}}><Trash2 size={13}/></button>
                  </div>}
                </div>
                {t.description&&<div style={{color:C.textMuted,fontSize:12,lineHeight:1.4,marginBottom:6}}>{t.description}</div>}
                <div style={{display:"flex",gap:6,alignItems:"center",marginBottom:10}}>
                  <span style={{color:C.textDim,fontSize:11}}>{t.date}</span>
                  <span style={{color:C.textDim,fontSize:11}}>•</span>
                  <span style={{color,fontSize:11,fontWeight:600}}>{t.typeLabel||ext.toUpperCase()}</span>
                </div>

                {/* Action buttons */}
                <div style={{display:"flex",gap:6,marginBottom:10}}>
                  <button onClick={()=>t.file&&setPreview(t.file)} style={{flex:1,padding:"6px 0",borderRadius:6,border:`1px solid ${C.orange}44`,background:`${C.orange}11`,color:C.orange,fontSize:12,fontWeight:600,cursor:"pointer",fontFamily:"inherit",display:"flex",alignItems:"center",justifyContent:"center",gap:4}}><Eye size={12}/> View</button>
                  {t.file?.url&&<a href={t.file.url} target="_blank" rel="noreferrer" style={{flex:1,padding:"6px 0",borderRadius:6,border:`1px solid ${C.blue}44`,background:`${C.blue}11`,color:C.blue,fontSize:12,fontWeight:600,cursor:"pointer",fontFamily:"inherit",display:"flex",alignItems:"center",justifyContent:"center",gap:4,textDecoration:"none"}}><Download size={12}/> Download</a>}
                  {isEmployee&&(
                    myDone?<div style={{flex:1,padding:"6px 0",borderRadius:6,background:`${C.green}22`,border:`1px solid ${C.green}44`,color:C.green,fontSize:12,fontWeight:700,display:"flex",alignItems:"center",justifyContent:"center",gap:4}}><CheckCircle size={12}/> Completed</div>
                    :<button onClick={()=>markComplete(t.id)} style={{flex:1,padding:"6px 0",borderRadius:6,border:`1px solid ${C.green}44`,background:`${C.green}11`,color:C.green,fontSize:12,fontWeight:600,cursor:"pointer",fontFamily:"inherit",display:"flex",alignItems:"center",justifyContent:"center",gap:4}}><CheckCircle size={12}/> Mark Complete</button>
                  )}
                </div>

                {/* Completion Tracker — managers only */}
                {canManage&&total>0&&(<>
                  <div onClick={()=>setExpandTracker(isExpanded?null:t.id)} style={{cursor:"pointer",padding:"8px 10px",borderRadius:8,background:C.bg,border:`1px solid ${C.border}`,marginBottom:isExpanded?0:0}}>
                    <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:6}}>
                      <div style={{display:"flex",alignItems:"center",gap:6}}>
                        <Users size={13} color={C.textMuted}/>
                        <span style={{fontSize:12,fontWeight:700,color:C.text}}>Completion: {done}/{total}</span>
                        {left.length>0&&<Badge color={C.yellow}>{left.length} remaining</Badge>}
                        {left.length===0&&<Badge color={C.green}>All done ✓</Badge>}
                      </div>
                      <span style={{color:C.textDim,fontSize:11}}>{isExpanded?"▲":"▼"}</span>
                    </div>
                    <div style={{height:5,background:C.border,borderRadius:3,overflow:"hidden"}}>
                      <div style={{height:"100%",width:`${pct}%`,background:pct===100?C.green:pct>=50?C.yellow:C.red,borderRadius:3,transition:"width 0.3s"}}/>
                    </div>
                  </div>
                  {isExpanded&&(
                    <div style={{border:`1px solid ${C.border}`,borderTop:"none",borderRadius:"0 0 8px 8px",background:C.bg,maxHeight:220,overflow:"auto"}}>
                      {/* Completed list */}
                      {comps.length>0&&<div style={{padding:"8px 10px"}}>
                        <div style={{fontSize:10,fontWeight:700,color:C.green,textTransform:"uppercase",marginBottom:4}}>✅ Completed ({comps.length})</div>
                        {comps.map(c=>(
                          <div key={c.email} style={{display:"flex",alignItems:"center",justifyContent:"space-between",padding:"4px 0",borderBottom:`1px solid ${C.border}22`}}>
                            <div style={{display:"flex",alignItems:"center",gap:6}}>
                              <div style={{width:22,height:22,borderRadius:"50%",background:`${C.green}22`,display:"flex",alignItems:"center",justifyContent:"center"}}><CheckCircle size={11} color={C.green}/></div>
                              <div>
                                <div style={{fontSize:11,fontWeight:600,color:C.text}}>{c.name||c.email.split("@")[0]}</div>
                                <div style={{fontSize:10,color:C.textDim}}>{c.email}</div>
                              </div>
                            </div>
                            <div style={{display:"flex",alignItems:"center",gap:6}}>
                              <span style={{fontSize:10,color:C.textDim}}>{c.completedAt?.slice(0,10)}</span>
                              {canManage&&<button onClick={(ev)=>{ev.stopPropagation();unmarkComplete(t.id,c.email);}} title="Unmark" style={{background:"none",border:"none",cursor:"pointer",color:C.red,padding:1}}><X size={10}/></button>}
                            </div>
                          </div>
                        ))}
                      </div>}
                      {/* Remaining list */}
                      {left.length>0&&<div style={{padding:"8px 10px"}}>
                        <div style={{fontSize:10,fontWeight:700,color:C.yellow,textTransform:"uppercase",marginBottom:4}}>⏳ Pending ({left.length})</div>
                        {left.map(m=>(
                          <div key={m.id} style={{display:"flex",alignItems:"center",justifyContent:"space-between",padding:"4px 0",borderBottom:`1px solid ${C.border}22`}}>
                            <div style={{display:"flex",alignItems:"center",gap:6}}>
                              <div style={{width:22,height:22,borderRadius:"50%",background:`${C.yellow}22`,display:"flex",alignItems:"center",justifyContent:"center"}}><Clock size={11} color={C.yellow}/></div>
                              <div>
                                <div style={{fontSize:11,fontWeight:600,color:C.text}}>{m.name}</div>
                                <div style={{fontSize:10,color:C.textDim}}>{m.email}</div>
                              </div>
                            </div>
                            <span style={{color:C.textDim,fontSize:10}}>Not completed</span>
                          </div>
                        ))}
                      </div>}
                      {total===0&&<div style={{padding:12,textAlign:"center",color:C.textDim,fontSize:12}}>No employees added yet</div>}
                    </div>
                  )}
                </>)}
                {canManage&&total===0&&(
                  <div style={{padding:"6px 10px",borderRadius:8,background:`${C.yellow}11`,border:`1px solid ${C.yellow}33`,fontSize:11,color:C.yellow,display:"flex",alignItems:"center",gap:4}}>
                    <AlertCircle size={12}/> No client employees added — add via Admin Panel to track completion
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    )}

    {/* Edit Name/Description Modal */}
    <Modal open={!!editId} onClose={()=>setEditId(null)} title="Edit Training Material">
      {editId&&<div>
        <Input label="Name" value={editName} onChange={v=>setEditName(v)} placeholder="Training name..."/>
        <Input label="Description" value={editDesc} onChange={v=>setEditDesc(v)} textarea placeholder="Brief description..."/>
        <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:16}}><Btn variant="secondary" onClick={()=>setEditId(null)}>Cancel</Btn><Btn onClick={saveEdit}><Save size={14}/> Save</Btn></div>
      </div>}
    </Modal>
  </div>);
};

// =============================================
// =============================================
// WORKFLOW CHECK — ISO 27001 Mandatory Controls
// =============================================
const WorkflowCheck = ({data,setData,role:userRole}) => {
  const [view,setView]=useState("dashboard"); // dashboard | controls
  const [activeCtrl,setActiveCtrl]=useState(null);
  const [toast,setToast]=useState(null);
  const [preview,setPreview]=useState(null);
  const [rejectModal,setRejectModal]=useState(null);
  const [rejectComment,setRejectComment]=useState("");
  const [freqEdit,setFreqEdit]=useState(null);
  const {token,user,orgId}=useAuth();
  const canDoApprove = canApprove(userRole||"client_user","workflow");
  const canDoDelete = canDelete(userRole||"client_user","workflow");

  const config = data.workflowConfig || {};
  const records = data.workflowRecords || [];

  // Get records for a control, sorted newest first
  const getRecords = (ctrlId) => records.filter(r=>r.controlId===ctrlId).sort((a,b)=>new Date(b.date)-new Date(a.date));

  // Get latest approved record for a control
  const getLatest = (ctrlId) => {
    const recs = getRecords(ctrlId);
    return recs.find(r=>r.status==="approved") || recs[0] || null;
  };

  // Score per control: approved=100, uploaded/pending=60, rejected=20, overdue/none=0
  const scoreCtrl = (ctrlId) => {
    const freq = config[ctrlId]?.frequency || "Annual";
    const recs = getRecords(ctrlId);
    const latestApproved = recs.find(r=>r.status==="approved");
    if(latestApproved) {
      const nextDue = calcNextDue(latestApproved.date, freq);
      if(nextDue && !isOverdue(nextDue)) return 100;
      // Approved but overdue for next cycle
      const pending = recs.find(r=>r.status==="uploaded"||r.status==="pending");
      if(pending) return 60;
      return 30; // had approval but now overdue
    }
    const pending = recs.find(r=>r.status==="uploaded"||r.status==="pending");
    if(pending) return 60;
    const rejected = recs.find(r=>r.status==="rejected");
    if(rejected) return 20;
    return 0;
  };

  // Overall workflow score (weighted)
  const wfScore = useMemo(()=>{
    let totalW=0,scoreW=0;
    WORKFLOW_CONTROLS.forEach(c=>{
      totalW+=c.weight;
      scoreW+=scoreCtrl(c.id)*c.weight/100;
    });
    return totalW>0?Math.round((scoreW/totalW)*100):0;
  },[records,config]);

  // Pending tasks
  const pendingTasks = useMemo(()=>{
    const tasks=[];
    WORKFLOW_CONTROLS.forEach(c=>{
      const freq = config[c.id]?.frequency || c.defaultFreq;
      const recs = getRecords(c.id);
      const latestApproved = recs.find(r=>r.status==="approved");
      const hasPending = recs.find(r=>r.status==="uploaded"||r.status==="pending");
      const hasRejected = recs.find(r=>r.status==="rejected"&&!recs.find(r2=>r2.status==="approved"&&new Date(r2.date)>new Date(r.date)));

      if(!latestApproved && !hasPending) {
        tasks.push({ctrl:c,type:"missing",msg:"No evidence submitted yet",urgent:true});
      } else if(latestApproved) {
        const nextDue = calcNextDue(latestApproved.date, freq);
        const days = daysUntilDue(nextDue);
        if(days < 0 && !hasPending) tasks.push({ctrl:c,type:"overdue",msg:`Overdue by ${Math.abs(days)} days`,urgent:true,dueDate:nextDue});
        else if(days >= 0 && days <= 30 && !hasPending) tasks.push({ctrl:c,type:"upcoming",msg:`Due in ${days} days`,urgent:false,dueDate:nextDue});
      }
      if(hasPending) tasks.push({ctrl:c,type:"review",msg:"Evidence awaiting review",urgent:false});
      if(hasRejected) tasks.push({ctrl:c,type:"rejected",msg:`Rejected: ${hasRejected.reviewComment||"No comment"}`,urgent:true});
    });
    return tasks;
  },[records,config]);

  // Evidence upload
  const handleUpload = async(ctrlId) => {
    const input = document.createElement("input"); input.type="file";
    input.onchange = async(e) => {
      const file = e.target.files[0]; if(!file) return;
      try {
        const ref = await uploadToStorage(token,orgId||user.id,"workflow",file);
        const freq = config[ctrlId]?.frequency || "Annual";
        const rec = {
          id:secureId('wr'),controlId:ctrlId,date:new Date().toISOString().slice(0,10),
          dueDate:calcNextDue(new Date().toISOString().slice(0,10),freq),
          status:"uploaded",evidenceFile:ref,uploadedBy:user.email,
          uploadedAt:new Date().toISOString(),reviewComment:"",reviewedBy:"",reviewedAt:""
        };
        setData(d=>({...d,workflowRecords:[...(d.workflowRecords||[]),rec]}));
        setToast({msg:"Evidence uploaded! Awaiting review.",type:"success"});
      } catch(err){ setToast({msg:err.message.includes("not allowed")||err.message.includes("too large")?"Upload error: "+err.message:"Upload failed. Please try again.",type:"error"}); }
    };
    input.click();
  };

  // Approve evidence
  const approve = (recId) => {
    setData(d=>({...d,workflowRecords:(d.workflowRecords||[]).map(r=>r.id===recId?{...r,status:"approved",reviewedBy:user.email,reviewedAt:new Date().toISOString()}:r)}));
    setToast({msg:"Evidence approved ✓",type:"success"});
  };

  // Reject evidence
  const reject = (recId) => {
    setData(d=>({...d,workflowRecords:(d.workflowRecords||[]).map(r=>r.id===recId?{...r,status:"rejected",reviewComment:rejectComment,reviewedBy:user.email,reviewedAt:new Date().toISOString()}:r)}));
    setRejectModal(null); setRejectComment("");
    setToast({msg:"Evidence rejected",type:"error"});
  };

  // Update frequency
  const updateFreq = (ctrlId, freq) => {
    setData(d=>({...d,workflowConfig:{...(d.workflowConfig||{}), [ctrlId]:{...(d.workflowConfig||{})[ctrlId],frequency:freq}}}));
    setFreqEdit(null); setToast({msg:"Frequency updated",type:"success"});
  };

  // Delete record
  const deleteRec = (recId) => {
    setData(d=>({...d,workflowRecords:(d.workflowRecords||[]).filter(r=>r.id!==recId)}));
    setToast({msg:"Record removed",type:"success"});
  };

  const scoreBg = (pct) => pct >= 80 ? C.green : pct >= 60 ? C.yellow : pct >= 40 ? C.orange : C.red;
  const statusColor = {approved:C.green,uploaded:C.blue,pending:C.yellow,rejected:C.red};
  const statusLabel = {approved:"Approved ✓",uploaded:"Awaiting Review",pending:"Pending",rejected:"Rejected ✗"};

  // ─── DASHBOARD VIEW ───
  if(view==="dashboard") {
    const ctrlData = WORKFLOW_CONTROLS.map(c=>{
      const sc = scoreCtrl(c.id);
      const freq = config[c.id]?.frequency || c.defaultFreq;
      const recs = getRecords(c.id);
      const latest = recs[0];
      const latestApproved = recs.find(r=>r.status==="approved");
      const nextDue = latestApproved ? calcNextDue(latestApproved.date,freq) : null;
      const days = nextDue ? daysUntilDue(nextDue) : -999;
      return {ctrl:c,score:sc,freq,latest,latestApproved,nextDue,days,recs};
    });
    const statusPie = [
      {name:"Compliant",value:ctrlData.filter(d=>d.score>=80).length,color:C.green},
      {name:"In Progress",value:ctrlData.filter(d=>d.score>=40&&d.score<80).length,color:C.yellow},
      {name:"Non-Compliant",value:ctrlData.filter(d=>d.score<40).length,color:C.red},
    ].filter(d=>d.value>0);

    return (<div>
      {toast&&<Toast {...toast} onClose={()=>setToast(null)}/>}
      {preview&&<FilePreviewModal file={preview} onClose={()=>setPreview(null)}/>}
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20}}>
        <div><h2 style={{margin:0,fontSize:22,fontWeight:800,color:C.text}}>Workflow Check</h2>
        <p style={{color:C.textMuted,margin:"4px 0 0",fontSize:13}}>ISO 27001 mandatory controls — compliance score: <span style={{color:scoreBg(wfScore),fontWeight:800,fontSize:16}}>{wfScore}%</span></p></div>
        <Btn onClick={()=>setView("controls")}><Settings size={14}/> Manage Controls</Btn>
      </div>

      {/* Stats */}
      <div style={{display:"flex",gap:16,flexWrap:"wrap",marginBottom:20}}>
        <Stat label="Workflow Score" value={`${wfScore}%`} icon={Activity} color={scoreBg(wfScore)}/>
        <Stat label="Controls Compliant" value={`${ctrlData.filter(d=>d.score>=80).length}/6`} icon={CheckCircle} color={C.green}/>
        <Stat label="Pending Reviews" value={pendingTasks.filter(t=>t.type==="review").length} icon={Clock} color={C.blue}/>
        <Stat label="Overdue Tasks" value={pendingTasks.filter(t=>t.type==="overdue"||t.type==="missing").length} icon={AlertTriangle} color={C.red}/>
      </div>

      {/* Progress bar */}
      <div style={{height:10,background:C.bg,borderRadius:5,marginBottom:24,overflow:"hidden"}}><div style={{height:"100%",width:`${wfScore}%`,background:`linear-gradient(90deg,${scoreBg(wfScore)},${C.orange})`,borderRadius:5,transition:"width 0.6s"}}/></div>

      {/* Charts + Pending */}
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16,marginBottom:20}}>
        <Card title="Control Status">{statusPie.length>0?<ResponsiveContainer width="100%" height={200}><PieChart><Pie data={statusPie} cx="50%" cy="50%" innerRadius={40} outerRadius={70} dataKey="value" paddingAngle={3}>{statusPie.map((d,i)=><Cell key={i} fill={d.color}/>)}</Pie><Legend formatter={v=><span style={{color:C.textMuted,fontSize:12}}>{v}</span>}/></PieChart></ResponsiveContainer>:<Empty msg="No data yet"/>}</Card>
        <Card title="Pending Tasks">
          {pendingTasks.length===0?<div style={{padding:20,textAlign:"center"}}><CheckCircle size={32} color={C.green} style={{marginBottom:8}}/><div style={{color:C.green,fontWeight:700}}>All tasks up to date!</div></div>:(
            <div style={{display:"flex",flexDirection:"column",gap:8,maxHeight:200,overflowY:"auto"}}>
              {pendingTasks.map((t,i)=>(
                <div key={i} style={{display:"flex",alignItems:"center",gap:10,padding:"8px 12px",background:t.urgent?`${C.red}11`:C.bg,borderRadius:8,border:`1px solid ${t.urgent?`${C.red}33`:C.border}`}}>
                  <span style={{fontSize:16}}>{t.ctrl.icon}</span>
                  <div style={{flex:1}}>
                    <div style={{color:C.text,fontSize:12,fontWeight:600}}>{t.ctrl.name}</div>
                    <div style={{color:t.urgent?C.red:C.textMuted,fontSize:11}}>{t.msg}</div>
                  </div>
                  {(t.type==="overdue"||t.type==="missing")&&<button onClick={()=>{setView("controls");setActiveCtrl(t.ctrl.id);}} style={{padding:"4px 10px",borderRadius:6,background:`${C.orange}22`,border:`1px solid ${C.orange}44`,color:C.orange,fontSize:11,fontWeight:700,cursor:"pointer",fontFamily:"inherit"}}>Upload</button>}
                  {t.type==="review"&&<Badge color={C.blue}>Review</Badge>}
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      {/* Control Details Grid */}
      <Card title="Control-wise Compliance">
        <div style={{display:"flex",flexDirection:"column",gap:10}}>
          {ctrlData.map(d=>(
            <div key={d.ctrl.id} style={{display:"flex",alignItems:"center",gap:12,padding:"10px 0",borderBottom:`1px solid ${C.border}22`}}>
              <span style={{fontSize:20,width:30}}>{d.ctrl.icon}</span>
              <div style={{flex:1,minWidth:0}}>
                <div style={{display:"flex",alignItems:"center",gap:8}}>
                  <span style={{color:C.text,fontSize:13,fontWeight:700}}>{d.ctrl.name}</span>
                  <span style={{color:C.textDim,fontSize:10,fontFamily:"monospace"}}>{d.ctrl.isoRef}</span>
                </div>
                <div style={{display:"flex",alignItems:"center",gap:8,marginTop:4}}>
                  <Badge color={C.textMuted}>{d.freq}</Badge>
                  {d.latestApproved&&<span style={{color:C.textDim,fontSize:10}}>Last: {d.latestApproved.date}</span>}
                  {d.nextDue&&<span style={{color:d.days<0?C.red:d.days<=30?C.yellow:C.textDim,fontSize:10,fontWeight:d.days<0?700:400}}>{d.days<0?`Overdue ${Math.abs(d.days)}d`:`Due in ${d.days}d`}</span>}
                </div>
              </div>
              <div style={{width:80,height:6,background:C.bg,borderRadius:3,overflow:"hidden"}}><div style={{height:"100%",width:`${d.score}%`,background:scoreBg(d.score),borderRadius:3}}/></div>
              <span style={{color:scoreBg(d.score),fontWeight:800,fontSize:14,width:42,textAlign:"right"}}>{d.score}%</span>
              <button onClick={()=>{setView("controls");setActiveCtrl(d.ctrl.id);}} style={{padding:"5px 10px",borderRadius:6,border:`1px solid ${C.border}`,background:"transparent",color:C.orange,fontSize:11,fontWeight:600,cursor:"pointer",fontFamily:"inherit"}}>View</button>
            </div>
          ))}
        </div>
      </Card>
    </div>);
  }

  // ─── CONTROLS LIST VIEW ───
  return (<div>
    {toast&&<Toast {...toast} onClose={()=>setToast(null)}/>}
    {preview&&<FilePreviewModal file={preview} onClose={()=>setPreview(null)}/>}

    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:16}}>
      <div><h2 style={{margin:0,fontSize:22,fontWeight:800,color:C.text}}>Workflow Controls</h2>
      <p style={{color:C.textMuted,margin:"4px 0 0",fontSize:13}}>Manage evidence for 6 mandatory ISO 27001 clauses</p></div>
      <div style={{display:"flex",gap:8}}>
        <Btn variant="secondary" size="sm" onClick={()=>setView("dashboard")}><ArrowLeft size={14}/> Dashboard</Btn>
      </div>
    </div>

    {/* Overall bar */}
    <div style={{display:"flex",gap:12,marginBottom:16,flexWrap:"wrap"}}>
      <div style={{background:C.card,borderRadius:10,border:`1px solid ${C.border}`,padding:"10px 16px",display:"flex",alignItems:"center",gap:10,flex:1,minWidth:160}}>
        <Activity size={18} color={scoreBg(wfScore)}/><div><div style={{fontSize:11,color:C.textMuted,fontWeight:600}}>Workflow Score</div><div style={{fontSize:20,fontWeight:800,color:scoreBg(wfScore)}}>{wfScore}%</div></div>
      </div>
      <div style={{background:C.card,borderRadius:10,border:`1px solid ${C.border}`,padding:"10px 16px",display:"flex",alignItems:"center",gap:10,flex:1,minWidth:120}}>
        <AlertTriangle size={18} color={C.red}/><div><div style={{fontSize:11,color:C.textMuted,fontWeight:600}}>Overdue</div><div style={{fontSize:20,fontWeight:800,color:C.red}}>{pendingTasks.filter(t=>t.type==="overdue"||t.type==="missing").length}</div></div>
      </div>
    </div>

    {/* Control cards */}
    <div style={{display:"flex",flexDirection:"column",gap:12}}>
      {WORKFLOW_CONTROLS.map(ctrl => {
        const sc = scoreCtrl(ctrl.id);
        const freq = config[ctrl.id]?.frequency || ctrl.defaultFreq;
        const recs = getRecords(ctrl.id);
        const isExpanded = activeCtrl === ctrl.id;
        const latestApproved = recs.find(r=>r.status==="approved");
        const nextDue = latestApproved ? calcNextDue(latestApproved.date,freq) : null;
        const days = nextDue ? daysUntilDue(nextDue) : -999;

        return (
          <div key={ctrl.id} style={{background:C.card,borderRadius:12,border:`1px solid ${isExpanded?`${C.orange}44`:C.border}`,overflow:"hidden",transition:"all 0.2s"}}>
            {/* Header */}
            <div onClick={()=>setActiveCtrl(isExpanded?null:ctrl.id)} style={{display:"flex",alignItems:"center",gap:12,padding:16,cursor:"pointer"}}>
              <span style={{fontSize:24}}>{ctrl.icon}</span>
              <div style={{flex:1}}>
                <div style={{display:"flex",alignItems:"center",gap:8}}>
                  <span style={{color:C.text,fontSize:15,fontWeight:700}}>{ctrl.name}</span>
                  <span style={{color:C.textDim,fontSize:10,fontFamily:"monospace"}}>{ctrl.isoRef}</span>
                  <Badge color={C.textMuted} bg={`${C.textMuted}15`}>Weight: {ctrl.weight}%</Badge>
                </div>
                <div style={{color:C.textDim,fontSize:12,marginTop:2}}>{ctrl.desc}</div>
              </div>
              <div style={{display:"flex",alignItems:"center",gap:8}}>
                {/* Frequency badge */}
                {freqEdit===ctrl.id && canDoApprove ? (
                  <select value={freq} onChange={e=>updateFreq(ctrl.id,e.target.value)} onBlur={()=>setFreqEdit(null)} autoFocus style={{padding:"4px 8px",background:C.bg,border:`1px solid ${C.orange}`,borderRadius:6,color:C.text,fontSize:11,fontFamily:"inherit"}}>
                    {FREQ_OPTIONS.map(f=><option key={f} value={f} style={{background:C.bg,color:C.text}}>{f}</option>)}
                  </select>
                ) : canDoApprove ? (
                  <button onClick={(e)=>{e.stopPropagation();setFreqEdit(ctrl.id);}} style={{padding:"4px 10px",borderRadius:6,border:`1px solid ${C.border}`,background:"transparent",color:C.textMuted,fontSize:11,fontWeight:600,cursor:"pointer",fontFamily:"inherit",display:"flex",alignItems:"center",gap:4}}>
                    <Calendar size={10}/> {freq}
                  </button>
                ) : (
                  <span style={{padding:"4px 10px",borderRadius:6,border:`1px solid ${C.border}`,color:C.textDim,fontSize:11,fontWeight:600,display:"flex",alignItems:"center",gap:4}}>
                    <Calendar size={10}/> {freq}
                  </span>
                )}
                <div style={{width:60,height:6,background:C.bg,borderRadius:3,overflow:"hidden"}}><div style={{height:"100%",width:`${sc}%`,background:scoreBg(sc),borderRadius:3}}/></div>
                <span style={{color:scoreBg(sc),fontWeight:800,fontSize:14,width:40,textAlign:"right"}}>{sc}%</span>
                <span style={{color:C.textDim,fontSize:14}}>{isExpanded?"▲":"▼"}</span>
              </div>
            </div>

            {/* Expanded Panel */}
            {isExpanded && (
              <div style={{borderTop:`1px solid ${C.border}`,padding:16,background:C.bg}}>
                {/* Status bar */}
                <div style={{display:"flex",gap:12,marginBottom:14,alignItems:"center",flexWrap:"wrap"}}>
                  {nextDue && <div style={{display:"flex",alignItems:"center",gap:4,fontSize:12}}>
                    <Clock size={12} color={days<0?C.red:days<=30?C.yellow:C.textDim}/>
                    <span style={{color:days<0?C.red:days<=30?C.yellow:C.textDim,fontWeight:600}}>
                      {days<0?`Overdue by ${Math.abs(days)} days`:days===0?"Due today":`Due in ${days} days`} ({nextDue})
                    </span>
                  </div>}
                  {!nextDue && !latestApproved && <span style={{color:C.red,fontSize:12,fontWeight:600}}>⚠️ No approved evidence yet</span>}
                  <div style={{marginLeft:"auto"}}><button onClick={()=>handleUpload(ctrl.id)} style={{padding:"6px 14px",borderRadius:8,background:C.orange,border:"none",color:"#fff",fontSize:12,fontWeight:700,cursor:"pointer",fontFamily:"inherit",display:"flex",alignItems:"center",gap:4}}><Upload size={12}/> Upload Evidence</button></div>
                </div>

                {/* Evidence hints */}
                <div style={{padding:10,background:C.card,borderRadius:8,border:`1px solid ${C.border}`,marginBottom:14}}>
                  <div style={{color:C.textDim,fontSize:10,fontWeight:700,textTransform:"uppercase",marginBottom:6}}>Expected Evidence</div>
                  <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
                    {ctrl.evidenceHints.map((h,i)=><span key={i} style={{padding:"3px 8px",borderRadius:12,background:`${C.blue}15`,border:`1px solid ${C.blue}33`,color:C.blue,fontSize:11}}>📎 {h}</span>)}
                  </div>
                </div>

                {/* Records list */}
                {recs.length===0 ? (
                  <div style={{textAlign:"center",padding:20}}><Empty msg="No evidence uploaded yet for this control"/></div>
                ) : (
                  <div style={{display:"flex",flexDirection:"column",gap:8}}>
                    <div style={{color:C.textDim,fontSize:11,fontWeight:700,textTransform:"uppercase"}}>Evidence History ({recs.length} records)</div>
                    {recs.map(rec=>(
                      <div key={rec.id} style={{display:"flex",alignItems:"center",gap:10,padding:12,background:C.card,borderRadius:10,border:`1px solid ${(statusColor[rec.status]||C.border)}33`}}>
                        <div style={{width:8,height:8,borderRadius:"50%",background:statusColor[rec.status]||C.textDim,flexShrink:0}}/>
                        <div style={{flex:1,minWidth:0}}>
                          <div style={{display:"flex",alignItems:"center",gap:8}}>
                            {rec.evidenceFile && <button onClick={()=>setPreview(rec.evidenceFile)} style={{background:"none",border:"none",cursor:"pointer",color:C.orange,fontSize:12,fontWeight:600,padding:0,display:"flex",alignItems:"center",gap:4}}><Eye size={11}/> {rec.evidenceFile.name}</button>}
                          </div>
                          <div style={{display:"flex",gap:8,marginTop:2,flexWrap:"wrap"}}>
                            <span style={{color:C.textDim,fontSize:10}}>📅 {rec.date}</span>
                            <span style={{color:C.textDim,fontSize:10}}>👤 {rec.uploadedBy}</span>
                            <Badge color={statusColor[rec.status]} bg={`${statusColor[rec.status]}15`}>{statusLabel[rec.status]||rec.status}</Badge>
                          </div>
                          {rec.status==="rejected" && rec.reviewComment && (
                            <div style={{marginTop:6,padding:"6px 10px",background:`${C.red}11`,borderRadius:6,border:`1px solid ${C.red}22`}}>
                              <span style={{color:C.red,fontSize:11}}>❌ Rejection reason: {rec.reviewComment}</span>
                            </div>
                          )}
                          {rec.status==="approved" && rec.reviewedBy && (
                            <div style={{marginTop:4,fontSize:10,color:C.green}}>✓ Approved by {rec.reviewedBy} on {rec.reviewedAt?.slice(0,10)}</div>
                          )}
                        </div>
                        {/* Actions */}
                        <div style={{display:"flex",gap:4,flexShrink:0}}>
                          {rec.status==="uploaded" && canDoApprove && <>
                            <button onClick={()=>approve(rec.id)} title="Approve" style={{padding:"6px 10px",borderRadius:6,background:`${C.green}22`,border:`1px solid ${C.green}44`,color:C.green,fontSize:11,fontWeight:700,cursor:"pointer",fontFamily:"inherit",display:"flex",alignItems:"center",gap:3}}><ThumbsUp size={12}/> Approve</button>
                            <button onClick={()=>{setRejectModal(rec.id);setRejectComment("");}} title="Reject" style={{padding:"6px 10px",borderRadius:6,background:`${C.red}22`,border:`1px solid ${C.red}44`,color:C.red,fontSize:11,fontWeight:700,cursor:"pointer",fontFamily:"inherit",display:"flex",alignItems:"center",gap:3}}><ThumbsDown size={12}/> Reject</button>
                          </>}
                          {rec.status==="uploaded" && !canDoApprove && (
                            <Badge color={C.blue}>⏳ Pending SecComply Review</Badge>
                          )}
                          {canDoDelete&&<button onClick={()=>deleteRec(rec.id)} title="Delete" style={{padding:"6px",borderRadius:6,background:"transparent",border:`1px solid ${C.border}`,color:C.textDim,cursor:"pointer"}}><Trash2 size={11}/></button>}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>

    {/* Reject Modal */}
    <Modal open={!!rejectModal} onClose={()=>setRejectModal(null)} title="Reject Evidence">
      <div>
        <p style={{color:C.textMuted,fontSize:13,marginBottom:12}}>Please provide a reason for rejection. This will be shown to the uploader.</p>
        <textarea value={rejectComment} onChange={e=>setRejectComment(e.target.value)} placeholder="Reason for rejection..." rows={3} style={{width:"100%",padding:"10px 12px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,color:C.text,fontSize:13,fontFamily:"inherit",resize:"vertical"}}/>
        <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:16}}>
          <Btn variant="secondary" onClick={()=>setRejectModal(null)}>Cancel</Btn>
          <Btn variant="danger" onClick={()=>reject(rejectModal)}><ThumbsDown size={14}/> Reject</Btn>
        </div>
      </div>
    </Modal>
  </div>);
};
// INTERNAL AUDIT (unchanged)
// =============================================
const InternalAudit = ({data,setData}) => {
  const [modal,setModal]=useState(null);const [toast,setToast]=useState(null);const [preview,setPreview]=useState(null);const [uploading,setUploading]=useState("");
  const {token,user,orgId}=useAuth();
  const blank = {id:"",audit_name:"",start_date:"",end_date:"",nc_report_file:null,final_report_file:null,status:"Open",remarks:""};
  const save=(a)=>{if(a.id){setData(d=>({...d,audits:d.audits.map(x=>x.id===a.id?a:x)}));}else{setData(d=>({...d,audits:[...d.audits,{...a,id:secureId('au')}]}));}setToast({msg:"Saved!",type:"success"});setModal(null);};
  const handleFile=async(field,file)=>{
    setUploading(field);
    try{const ref=await uploadToStorage(token,orgId||user.id,"audit",file);setModal(m=>({...m,[field]:ref}));}catch(e){setToast({msg:"Upload failed",type:"error"});}
    setUploading("");
  };
  return (<div>
    {toast&&<Toast {...toast} onClose={()=>setToast(null)}/>}
    {preview&&<FilePreviewModal file={preview} onClose={()=>setPreview(null)}/>}
    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20}}>
      <h2 style={{margin:0,fontSize:22,fontWeight:800,color:C.text}}>Internal Audit</h2>
      <Btn onClick={()=>setModal({...blank})}><Plus size={14}/> New Audit</Btn>
    </div>
    {data.audits.length===0?<Card><Empty msg="No audits yet" action="New Audit" onAction={()=>setModal({...blank})}/></Card>:(
      <div style={{display:"flex",flexDirection:"column",gap:12}}>
        {data.audits.map(a=><Card key={a.id}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}>
            <div><div style={{fontSize:16,fontWeight:700,color:C.text,marginBottom:4}}>{a.audit_name||"Untitled"}</div><div style={{fontSize:12,color:C.textMuted}}>{a.start_date&&`${a.start_date} → ${a.end_date||"Ongoing"}`}</div></div>
            <div style={{display:"flex",gap:8,alignItems:"center"}}><Badge color={a.status==="Closed"?C.green:a.status==="In Progress"?C.yellow:C.blue}>{a.status}</Badge><button onClick={()=>setModal({...a})} style={{background:"none",border:"none",cursor:"pointer",color:C.orange}}><Edit3 size={16}/></button></div>
          </div>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginTop:12}}>
            <div style={{padding:12,background:C.bg,borderRadius:8,border:`1px solid ${C.border}`}}><div style={{fontSize:11,color:C.textDim,fontWeight:600,marginBottom:6}}>NC Report</div>{a.nc_report_file?<button onClick={()=>setPreview(a.nc_report_file)} style={{background:"none",border:"none",cursor:"pointer",color:C.orange,fontSize:12,display:"flex",alignItems:"center",gap:4}}><Eye size={12}/> {a.nc_report_file.name}</button>:<span style={{color:C.textDim,fontSize:12}}>Not uploaded</span>}</div>
            <div style={{padding:12,background:C.bg,borderRadius:8,border:`1px solid ${C.border}`}}><div style={{fontSize:11,color:C.textDim,fontWeight:600,marginBottom:6}}>Final Report</div>{a.final_report_file?<button onClick={()=>setPreview(a.final_report_file)} style={{background:"none",border:"none",cursor:"pointer",color:C.orange,fontSize:12,display:"flex",alignItems:"center",gap:4}}><Eye size={12}/> {a.final_report_file.name}</button>:<span style={{color:C.textDim,fontSize:12}}>Not uploaded</span>}</div>
          </div>
        </Card>)}
      </div>)}
    <Modal open={!!modal} onClose={()=>setModal(null)} title={modal?.id?"Edit Audit":"New Audit"} wide>
      {modal&&<div>
        <Input label="Audit Name" value={modal.audit_name} onChange={v=>setModal(m=>({...m,audit_name:v}))}/>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:12}}>
          <Input label="Start Date" type="date" value={modal.start_date} onChange={v=>setModal(m=>({...m,start_date:v}))}/>
          <Input label="End Date" type="date" value={modal.end_date} onChange={v=>setModal(m=>({...m,end_date:v}))}/>
          <Input label="Status" value={modal.status} onChange={v=>setModal(m=>({...m,status:v}))} select options={["Open","In Progress","Closed"]}/>
        </div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginTop:8}}>
          <div><label style={{display:"block",fontSize:12,color:C.textMuted,marginBottom:6,fontWeight:600}}>NC Report</label>{modal.nc_report_file?<div style={{display:"flex",alignItems:"center",gap:6}}><CheckCircle size={14} color={C.green}/><span style={{color:C.text,fontSize:12}}>{modal.nc_report_file.name}</span><button onClick={()=>setModal(m=>({...m,nc_report_file:null}))} style={{background:"none",border:"none",cursor:"pointer",color:C.red}}><X size={12}/></button></div>:<FileUploadBtn onFile={f=>handleFile("nc_report_file",f)} accept="*" label={uploading==="nc_report_file"?"Uploading...":"Upload NC Report"} size="sm" variant="secondary"/>}</div>
          <div><label style={{display:"block",fontSize:12,color:C.textMuted,marginBottom:6,fontWeight:600}}>Final Report</label>{modal.final_report_file?<div style={{display:"flex",alignItems:"center",gap:6}}><CheckCircle size={14} color={C.green}/><span style={{color:C.text,fontSize:12}}>{modal.final_report_file.name}</span><button onClick={()=>setModal(m=>({...m,final_report_file:null}))} style={{background:"none",border:"none",cursor:"pointer",color:C.red}}><X size={12}/></button></div>:<FileUploadBtn onFile={f=>handleFile("final_report_file",f)} accept="*" label={uploading==="final_report_file"?"Uploading...":"Upload Final Report"} size="sm" variant="secondary"/>}</div>
        </div>
        <Input label="Remarks" value={modal.remarks} onChange={v=>setModal(m=>({...m,remarks:v}))} textarea style={{marginTop:12}}/>
        <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:16}}><Btn variant="secondary" onClick={()=>setModal(null)}>Cancel</Btn>{modal.id&&modal.status!=="Closed"&&<Btn variant="success" onClick={()=>save({...modal,status:"Closed"})}><CheckCircle size={14}/> Close</Btn>}<Btn onClick={()=>save(modal)}><Save size={14}/> Save</Btn></div>
      </div>}
    </Modal>
  </div>);
};



// =============================================
// CLOUD SECURITY — AWS / Azure / GCP Integration
// =============================================

const AWS_CHECKS = [
  // IAM
  {id:"iam_01",cat:"IAM",name:"Root account MFA enabled",iso:"A.8.5",sev:"CRITICAL",gapQ:"C7"},
  {id:"iam_02",cat:"IAM",name:"No root access keys exist",iso:"A.5.15",sev:"CRITICAL",gapQ:"C7"},
  {id:"iam_03",cat:"IAM",name:"Root not used in 90 days",iso:"A.5.18",sev:"HIGH",gapQ:"C7"},
  {id:"iam_04",cat:"IAM",name:"Password policy enforces complexity",iso:"A.5.17",sev:"HIGH",gapQ:"C7"},
  {id:"iam_05",cat:"IAM",name:"All users have MFA enabled",iso:"A.8.5",sev:"HIGH",gapQ:"C7"},
  {id:"iam_06",cat:"IAM",name:"No inline policies on users",iso:"A.5.15",sev:"MEDIUM",gapQ:"C7"},
  {id:"iam_07",cat:"IAM",name:"Users belong to groups",iso:"A.5.15",sev:"MEDIUM",gapQ:"C7"},
  {id:"iam_08",cat:"IAM",name:"Unused credentials disabled (>90d)",iso:"A.5.18",sev:"HIGH",gapQ:"C7"},
  {id:"iam_09",cat:"IAM",name:"Access keys rotated every 90 days",iso:"A.5.17",sev:"HIGH",gapQ:"C7"},
  {id:"iam_10",cat:"IAM",name:"No full admin (*:*) policies",iso:"A.8.3",sev:"CRITICAL",gapQ:"C7"},
  // CloudTrail
  {id:"ct_01",cat:"CloudTrail",name:"CloudTrail enabled in all regions",iso:"A.8.15",sev:"CRITICAL",gapQ:"C3"},
  {id:"ct_02",cat:"CloudTrail",name:"Log file validation enabled",iso:"A.8.15",sev:"HIGH",gapQ:"C3"},
  {id:"ct_03",cat:"CloudTrail",name:"Logs encrypted with KMS",iso:"A.8.24",sev:"HIGH",gapQ:"C3"},
  {id:"ct_04",cat:"CloudTrail",name:"Trail S3 bucket not public",iso:"A.8.3",sev:"CRITICAL",gapQ:"C3"},
  {id:"ct_05",cat:"CloudTrail",name:"Integrated with CloudWatch Logs",iso:"A.8.16",sev:"MEDIUM",gapQ:"C3"},
  // GuardDuty
  {id:"gd_01",cat:"GuardDuty",name:"GuardDuty enabled",iso:"A.8.16",sev:"CRITICAL",gapQ:"C4"},
  {id:"gd_02",cat:"GuardDuty",name:"No unarchived HIGH findings",iso:"A.8.16",sev:"HIGH",gapQ:"C4"},
  // S3
  {id:"s3_01",cat:"S3",name:"No public buckets",iso:"A.8.3",sev:"CRITICAL",gapQ:"C5"},
  {id:"s3_02",cat:"S3",name:"Default encryption on all buckets",iso:"A.8.24",sev:"HIGH",gapQ:"C5"},
  {id:"s3_03",cat:"S3",name:"Access logging enabled",iso:"A.8.15",sev:"MEDIUM",gapQ:"C5"},
  {id:"s3_04",cat:"S3",name:"Versioning enabled",iso:"A.8.13",sev:"MEDIUM",gapQ:"C5"},
  {id:"s3_05",cat:"S3",name:"Block Public Access at account level",iso:"A.8.3",sev:"CRITICAL",gapQ:"C5"},
  // AWS Config
  {id:"cfg_01",cat:"Config",name:"AWS Config recorder enabled",iso:"A.8.9",sev:"HIGH",gapQ:"C6"},
  {id:"cfg_02",cat:"Config",name:"Config rules active",iso:"A.8.9",sev:"MEDIUM",gapQ:"C6"},
  // EC2 / Network
  {id:"ec2_01",cat:"Compute",name:"No SG allows 0.0.0.0/0 to SSH (22)",iso:"A.8.20",sev:"CRITICAL",gapQ:null},
  {id:"ec2_02",cat:"Compute",name:"No SG allows 0.0.0.0/0 to RDP (3389)",iso:"A.8.20",sev:"CRITICAL",gapQ:null},
  {id:"ec2_03",cat:"Compute",name:"EBS volumes encrypted",iso:"A.8.24",sev:"HIGH",gapQ:null},
  {id:"ec2_04",cat:"Compute",name:"Default SG restricts all traffic",iso:"A.8.20",sev:"MEDIUM",gapQ:null},
  {id:"ec2_05",cat:"Compute",name:"Instances use IMDSv2",iso:"A.8.9",sev:"HIGH",gapQ:null},
  // RDS
  {id:"rds_01",cat:"Database",name:"RDS not publicly accessible",iso:"A.8.20",sev:"CRITICAL",gapQ:null},
  {id:"rds_02",cat:"Database",name:"RDS encryption at rest enabled",iso:"A.8.24",sev:"HIGH",gapQ:null},
  {id:"rds_03",cat:"Database",name:"RDS automated backups enabled",iso:"A.8.13",sev:"HIGH",gapQ:null},
  {id:"rds_04",cat:"Database",name:"RDS Multi-AZ for production",iso:"A.8.13",sev:"MEDIUM",gapQ:null},
  // CloudWatch
  {id:"cw_01",cat:"CloudWatch",name:"Alarm for unauthorized API calls",iso:"A.8.16",sev:"HIGH",gapQ:"C3"},
  {id:"cw_02",cat:"CloudWatch",name:"Alarm for root account usage",iso:"A.8.16",sev:"CRITICAL",gapQ:"C3"},
  {id:"cw_03",cat:"CloudWatch",name:"Alarm for IAM policy changes",iso:"A.8.16",sev:"HIGH",gapQ:"C3"},
  {id:"cw_04",cat:"CloudWatch",name:"Alarm for SG changes",iso:"A.8.16",sev:"HIGH",gapQ:null},
  {id:"cw_05",cat:"CloudWatch",name:"Log retention >= 365 days",iso:"A.8.15",sev:"MEDIUM",gapQ:"C3"},
  // SSO
  {id:"sso_01",cat:"SSO",name:"AWS SSO / IAM Identity Center enabled",iso:"A.5.16",sev:"HIGH",gapQ:"C7"},
  // KMS
  {id:"kms_01",cat:"KMS",name:"KMS key rotation enabled",iso:"A.8.24",sev:"HIGH",gapQ:null},
];

const AWS_CATS = [...new Set(AWS_CHECKS.map(c=>c.cat))];

// =============================================
// AZURE SECURITY CHECKS (40 checks)
// =============================================
const AZURE_CHECKS = [
  // Identity & Access (10 checks)
  {id:"az_iam_01",cat:"Identity",name:"MFA enforced for all users",iso:"A.8.5",sev:"CRITICAL",gapQ:"C7"},
  {id:"az_iam_02",cat:"Identity",name:"Conditional Access policies active",iso:"A.5.15",sev:"CRITICAL",gapQ:"C7"},
  {id:"az_iam_03",cat:"Identity",name:"No excessive Owner role assignments",iso:"A.5.15",sev:"HIGH",gapQ:"C7"},
  {id:"az_iam_04",cat:"Identity",name:"Custom RBAC roles reviewed",iso:"A.5.18",sev:"MEDIUM",gapQ:"C7"},
  {id:"az_iam_05",cat:"Identity",name:"Guest user access restricted",iso:"A.5.16",sev:"HIGH",gapQ:"C7"},
  {id:"az_iam_06",cat:"Identity",name:"Resource locks on critical resources",iso:"A.8.3",sev:"MEDIUM",gapQ:"C7"},
  {id:"az_iam_07",cat:"Identity",name:"No classic administrators",iso:"A.5.15",sev:"HIGH",gapQ:"C7"},
  {id:"az_iam_08",cat:"Identity",name:"JIT VM access enabled",iso:"A.8.20",sev:"HIGH",gapQ:"C7"},
  {id:"az_iam_09",cat:"Identity",name:"RBAC properly scoped (no wildcard actions)",iso:"A.8.3",sev:"CRITICAL",gapQ:"C7"},
  {id:"az_iam_10",cat:"Identity",name:"Azure AD SSO configured",iso:"A.5.16",sev:"HIGH",gapQ:"C7"},
  // Activity Log (5 checks)
  {id:"az_log_01",cat:"Activity Log",name:"Activity Log alerts for admin operations",iso:"A.8.15",sev:"HIGH",gapQ:"C3"},
  {id:"az_log_02",cat:"Activity Log",name:"Diagnostic settings on subscription",iso:"A.8.15",sev:"HIGH",gapQ:"C3"},
  {id:"az_log_03",cat:"Activity Log",name:"Log Analytics workspace exists",iso:"A.8.16",sev:"HIGH",gapQ:"C3"},
  {id:"az_log_04",cat:"Activity Log",name:"Activity log retained >= 365 days",iso:"A.8.15",sev:"MEDIUM",gapQ:"C3"},
  {id:"az_log_05",cat:"Activity Log",name:"Alert rules for security events",iso:"A.8.16",sev:"HIGH",gapQ:"C3"},
  // Defender for Cloud (2 checks)
  {id:"az_def_01",cat:"Defender",name:"Microsoft Defender for Cloud enabled",iso:"A.8.16",sev:"CRITICAL",gapQ:"C4"},
  {id:"az_def_02",cat:"Defender",name:"Security contacts configured",iso:"A.8.16",sev:"HIGH",gapQ:"C4"},
  // Storage (5 checks)
  {id:"az_str_01",cat:"Storage",name:"Storage accounts deny public blob access",iso:"A.8.3",sev:"CRITICAL",gapQ:"C5"},
  {id:"az_str_02",cat:"Storage",name:"Storage account encryption enabled (SSE)",iso:"A.8.24",sev:"HIGH",gapQ:"C5"},
  {id:"az_str_03",cat:"Storage",name:"HTTPS-only traffic enforced",iso:"A.8.24",sev:"HIGH",gapQ:"C5"},
  {id:"az_str_04",cat:"Storage",name:"Blob soft delete enabled",iso:"A.8.13",sev:"MEDIUM",gapQ:"C5"},
  {id:"az_str_05",cat:"Storage",name:"Minimum TLS 1.2 enforced",iso:"A.8.24",sev:"HIGH",gapQ:"C5"},
  // Azure Policy (2 checks)
  {id:"az_pol_01",cat:"Policy",name:"Azure Policy assignments active",iso:"A.8.9",sev:"HIGH",gapQ:"C6"},
  {id:"az_pol_02",cat:"Policy",name:"Policy compliance evaluated",iso:"A.8.9",sev:"MEDIUM",gapQ:"C6"},
  // Network Security (5 checks)
  {id:"az_net_01",cat:"Network",name:"No NSG allows 0.0.0.0/0 to SSH (22)",iso:"A.8.20",sev:"CRITICAL",gapQ:null},
  {id:"az_net_02",cat:"Network",name:"No NSG allows 0.0.0.0/0 to RDP (3389)",iso:"A.8.20",sev:"CRITICAL",gapQ:null},
  {id:"az_net_03",cat:"Network",name:"Network Watcher enabled",iso:"A.8.16",sev:"HIGH",gapQ:null},
  {id:"az_net_04",cat:"Network",name:"No VMs with direct public IPs",iso:"A.8.20",sev:"HIGH",gapQ:null},
  {id:"az_net_05",cat:"Network",name:"NSG flow logs enabled",iso:"A.8.15",sev:"MEDIUM",gapQ:null},
  // Database (4 checks)
  {id:"az_db_01",cat:"Database",name:"SQL firewall doesn't allow 0.0.0.0",iso:"A.8.20",sev:"CRITICAL",gapQ:null},
  {id:"az_db_02",cat:"Database",name:"SQL TDE (Transparent Data Encryption) on",iso:"A.8.24",sev:"HIGH",gapQ:null},
  {id:"az_db_03",cat:"Database",name:"SQL auditing enabled",iso:"A.8.15",sev:"HIGH",gapQ:null},
  {id:"az_db_04",cat:"Database",name:"SQL Advanced Threat Protection on",iso:"A.8.16",sev:"HIGH",gapQ:null},
  // Monitor (5 checks)
  {id:"az_mon_01",cat:"Monitor",name:"Azure Monitor alerts configured",iso:"A.8.16",sev:"HIGH",gapQ:"C3"},
  {id:"az_mon_02",cat:"Monitor",name:"Action groups for alert notifications",iso:"A.8.16",sev:"HIGH",gapQ:"C3"},
  {id:"az_mon_03",cat:"Monitor",name:"Diagnostic settings on key resources",iso:"A.8.15",sev:"MEDIUM",gapQ:"C3"},
  {id:"az_mon_04",cat:"Monitor",name:"Service Health alerts configured",iso:"A.8.16",sev:"MEDIUM",gapQ:null},
  {id:"az_mon_05",cat:"Monitor",name:"Log retention >= 365 days",iso:"A.8.15",sev:"MEDIUM",gapQ:"C3"},
  // Key Vault (1 check)
  {id:"az_kv_01",cat:"Key Vault",name:"Soft delete & purge protection enabled",iso:"A.8.24",sev:"HIGH",gapQ:null},
  // SSO (1 check)
  {id:"az_sso_01",cat:"SSO",name:"Azure AD SSO / Entra ID configured",iso:"A.5.16",sev:"HIGH",gapQ:"C7"},
];
const AZURE_CATS = [...new Set(AZURE_CHECKS.map(c=>c.cat))];

// Azure setup commands
const AZ_SETUP_COMMANDS = {
  createApp: `az ad app create --display-name "SecComply-Scanner" --query appId -o tsv`,
  createSecret: `az ad app credential reset --id <APP_ID> --query password -o tsv`,
  createSP: `az ad sp create --id <APP_ID>`,
  assignRole: `az role assignment create --assignee <APP_ID> --role "Reader" --scope /subscriptions/<SUB_ID>`,
  getInfo: `echo "Tenant ID:" && az account show --query tenantId -o tsv && echo "Subscription ID:" && az account show --query id -o tsv`,
  cleanup: `az ad app delete --id <APP_ID>`,
};

const CF_TEMPLATE_YAML = `AWSTemplateFormatVersion: '2010-09-09'
Description: 'SecComply ISMS - Read-only IAM user for AWS security posture scanning'

Resources:
  SecComplyScanner:
    Type: AWS::IAM::User
    Properties:
      UserName: SecComplyScanner
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/SecurityAudit
        - arn:aws:iam::aws:policy/job-function/ViewOnlyAccess

  SecComplyAccessKey:
    Type: AWS::IAM::AccessKey
    Properties:
      UserName: !Ref SecComplyScanner

Outputs:
  AccessKeyId:
    Description: 'Access Key ID - enter this in SecComply'
    Value: !Ref SecComplyAccessKey
  SecretAccessKey:
    Description: 'Secret Access Key - enter this in SecComply'
    Value: !GetAtt SecComplyAccessKey.SecretAccessKey
  UserARN:
    Description: 'ARN of the scanner user'
    Value: !GetAtt SecComplyScanner.Arn`;

const CF_JSON_TEMPLATE = JSON.stringify({
  AWSTemplateFormatVersion:"2010-09-09",
  Description:"SecComply ISMS - Read-only IAM user for AWS security scanning",
  Resources:{
    SecComplyScanner:{Type:"AWS::IAM::User",Properties:{UserName:"SecComplyScanner",ManagedPolicyArns:["arn:aws:iam::aws:policy/SecurityAudit","arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"]}},
    SecComplyAccessKey:{Type:"AWS::IAM::AccessKey",Properties:{UserName:{Ref:"SecComplyScanner"}}}
  },
  Outputs:{
    AccessKeyId:{Description:"Access Key ID",Value:{Ref:"SecComplyAccessKey"}},
    SecretAccessKey:{Description:"Secret Access Key",Value:{"Fn::GetAtt":["SecComplyAccessKey","SecretAccessKey"]}},
    UserARN:{Description:"User ARN",Value:{"Fn::GetAtt":["SecComplyScanner","Arn"]}}
  }
});

const CF_ONE_LINER = `aws cloudformation create-stack --stack-name seccomply-scanner --capabilities CAPABILITY_NAMED_IAM --template-body '${CF_JSON_TEMPLATE}'`;

const CF_GET_KEYS = `aws cloudformation describe-stacks --stack-name seccomply-scanner --query "Stacks[0].Outputs" --output table`;

const CF_CLEANUP = `aws cloudformation delete-stack --stack-name seccomply-scanner`;

const AWS_REGIONS = ["us-east-1","us-east-2","us-west-1","us-west-2","ap-south-1","ap-southeast-1","ap-southeast-2","ap-northeast-1","ap-northeast-2","eu-west-1","eu-west-2","eu-central-1","sa-east-1","ca-central-1","me-south-1","af-south-1"];

const AWS_SCAN_SCRIPT = `#!/bin/bash
# ============================================
# SecComply AWS Security Scanner v2
# Run this in AWS CloudShell
# ============================================
OUT="/tmp/sc_scan.json"

# Safe command runner — never exits on failure
run_cmd() {
  local result
  result=$(eval "$1" 2>/dev/null) && echo "$result" >> $OUT || echo "$2" >> $OUT
}

echo ""
echo "  SecComply AWS Security Scanner"
echo "  =============================="
echo ""

ACCT=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "unknown")
REG=$(aws configure get region 2>/dev/null || echo "us-east-1")
echo "  Account: $ACCT"
echo "  Region:  $REG"
echo ""

# Start JSON
echo '{"_meta":{"tool":"SecComply","v":"2.0","scannedAt":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'","account":"'$ACCT'","region":"'$REG'"},' > $OUT

# 1. IAM
echo "  [1/10] Scanning IAM..."
echo '"iam":{"account_summary":' >> $OUT
run_cmd "aws iam get-account-summary" '{}'
echo ',"password_policy":' >> $OUT
run_cmd "aws iam get-account-password-policy" '{"error":"no policy"}'
echo ',"users":' >> $OUT
run_cmd "aws iam list-users --query Users[].{UserName:UserName,CreateDate:CreateDate}" '[]'
echo ',"credential_report":"' >> $OUT
aws iam generate-credential-report >/dev/null 2>&1 || true
sleep 5
aws iam get-credential-report --query Content --output text 2>/dev/null >> $OUT || echo -n "" >> $OUT
echo '"},' >> $OUT

# 2. CloudTrail
echo "  [2/10] Scanning CloudTrail..."
echo '"cloudtrail":{"trails":' >> $OUT
run_cmd "aws cloudtrail describe-trails" '{"trailList":[]}'
echo '},' >> $OUT

# 3. GuardDuty
echo "  [3/10] Scanning GuardDuty..."
echo '"guardduty":{"detectors":' >> $OUT
run_cmd "aws guardduty list-detectors" '{"DetectorIds":[]}'
echo '},' >> $OUT

# 4. S3
echo "  [4/10] Scanning S3..."
echo '"s3":{"public_access_block":' >> $OUT
if [ "$ACCT" != "unknown" ]; then
  run_cmd "aws s3control get-public-access-block --account-id $ACCT" '{"error":"not set"}'
else
  echo '{"error":"not set"}' >> $OUT
fi
echo ',"buckets":' >> $OUT
run_cmd "aws s3api list-buckets --query Buckets[].Name" '[]'
echo '},' >> $OUT

# 5. EC2
echo "  [5/10] Scanning EC2 & Security Groups..."
echo '"ec2":{"security_groups":' >> $OUT
run_cmd "aws ec2 describe-security-groups --query SecurityGroups[].{Id:GroupId,Name:GroupName,Rules:IpPermissions}" '[]'
echo ',"unencrypted_volumes":' >> $OUT
run_cmd "aws ec2 describe-volumes --filters Name=encrypted,Values=false --query Volumes[].VolumeId" '[]'
echo ',"instances":' >> $OUT
run_cmd "aws ec2 describe-instances --query Reservations[].Instances[].{Id:InstanceId,IMDS:MetadataOptions.HttpTokens}" '[]'
echo '},' >> $OUT

# 6. RDS
echo "  [6/10] Scanning RDS..."
echo '"rds":{"instances":' >> $OUT
run_cmd "aws rds describe-db-instances --query DBInstances[].{Id:DBInstanceIdentifier,Public:PubliclyAccessible,Encrypted:StorageEncrypted,MultiAZ:MultiAZ,Backup:BackupRetentionPeriod}" '[]'
echo '},' >> $OUT

# 7. CloudWatch
echo "  [7/10] Scanning CloudWatch..."
echo '"cloudwatch":{"alarms":' >> $OUT
run_cmd "aws cloudwatch describe-alarms --query MetricAlarms[].{Name:AlarmName,Metric:MetricName,NS:Namespace}" '[]'
echo ',"log_groups":' >> $OUT
run_cmd "aws logs describe-log-groups --query logGroups[].{Name:logGroupName,Retention:retentionInDays}" '[]'
echo '},' >> $OUT

# 8. Config
echo "  [8/10] Scanning AWS Config..."
echo '"config":{"recorders":' >> $OUT
run_cmd "aws configservice describe-configuration-recorders" '{"ConfigurationRecorders":[]}'
echo ',"rules":' >> $OUT
run_cmd "aws configservice describe-config-rules --query ConfigRules[].{Name:ConfigRuleName,State:ConfigRuleState}" '[]'
echo '},' >> $OUT

# 9. KMS
echo "  [9/10] Scanning KMS..."
echo '"kms":{"keys":' >> $OUT
run_cmd "aws kms list-keys --query Keys[].KeyId" '[]'
echo '},' >> $OUT

# 10. SSO
echo "  [10/10] Checking SSO..."
echo '"sso":{"instances":' >> $OUT
run_cmd "aws sso-admin list-instances" '{"Instances":[]}'
echo '}}' >> $OUT

# Format JSON (optional, non-fatal)
python3 -m json.tool $OUT > /tmp/sc_fmt.json 2>/dev/null && mv /tmp/sc_fmt.json $OUT || true

echo ""
echo "  ========================================="
echo "  ✅ SCAN COMPLETE!"
echo "  📄 File: $OUT"
echo "  📦 Size: $(wc -c < $OUT) bytes"
echo "  ========================================="
echo ""
echo "  NEXT STEPS:"
echo "  1. Click 'Actions' (top-right corner)"
echo "  2. Click 'Download file'"
echo "  3. Enter path: /tmp/sc_scan.json"
echo "  4. Upload to SecComply > Cloud Security"
echo ""
`;

// Gap question IDs that map to cloud checks
const CLOUD_GAP_MAP = {
  aws: {
    C3:{name:"CloudTrail & Monitoring",checks:["ct_01","ct_02","ct_03","ct_04","ct_05","cw_01","cw_02","cw_03","cw_05"]},
    C4:{name:"GuardDuty",checks:["gd_01","gd_02"]},
    C5:{name:"S3 Security",checks:["s3_01","s3_02","s3_03","s3_04","s3_05"]},
    C6:{name:"AWS Config",checks:["cfg_01","cfg_02"]},
    C7:{name:"IAM Policies",checks:["iam_01","iam_02","iam_03","iam_04","iam_05","iam_06","iam_07","iam_08","iam_09","iam_10","sso_01"]},
  },
  azure: {
    C3:{name:"Monitoring & Logging",checks:["az_log_01","az_log_02","az_log_03","az_log_04"]},
    C4:{name:"Defender for Cloud",checks:["az_def_01","az_def_02"]},
    C5:{name:"Storage Security",checks:["az_str_01","az_str_02","az_str_03","az_str_04","az_str_05"]},
    C6:{name:"Azure Policy",checks:["az_pol_01","az_pol_02"]},
    C7:{name:"Identity & Access",checks:["az_iam_01","az_iam_02","az_iam_03","az_iam_04","az_iam_05","az_iam_06","az_iam_07","az_iam_08","az_iam_09","az_iam_10","az_sso_01"]},
  },
};

const parseAwsScan = (raw) => {
  const results = {};
  try {
    const d = typeof raw === "string" ? JSON.parse(raw) : raw;
    const meta = d._meta || {};

    // IAM checks
    const iam = d.iam || {};
    const summary = iam.account_summary?.SummaryMap || {};
    results.iam_01 = summary.AccountMFAEnabled === 1 ? "PASS" : "FAIL";
    results.iam_02 = (summary.AccountAccessKeysPresent || 0) === 0 ? "PASS" : "FAIL";
    const pwPolicy = iam.password_policy?.PasswordPolicy || iam.password_policy || {};
    results.iam_04 = (pwPolicy.MinimumPasswordLength >= 14 && pwPolicy.RequireUppercaseCharacters && pwPolicy.RequireLowercaseCharacters && pwPolicy.RequireNumbers && pwPolicy.RequireSymbols) ? "PASS" : (pwPolicy.error ? "FAIL" : "WARN");
    results.iam_06 = "MANUAL"; results.iam_07 = "MANUAL"; results.iam_03 = "MANUAL";
    results.iam_05 = "MANUAL"; results.iam_08 = "MANUAL"; results.iam_09 = "MANUAL"; results.iam_10 = "MANUAL";

    // Parse credential report if available
    if (iam.credential_report && iam.credential_report.length > 10) {
      try {
        const csv = atob(iam.credential_report);
        const lines = csv.split("\\n").filter(l => l.trim());
        if (lines.length > 1) {
          const headers = lines[0].split(",");
          const mfaIdx = headers.indexOf("mfa_active");
          const rootRow = lines.find(l => l.startsWith("<root_account>"));
          if (rootRow) {
            const cols = rootRow.split(",");
            const ak1Idx = headers.indexOf("access_key_1_active");
            const ak2Idx = headers.indexOf("access_key_2_active");
            if (ak1Idx >= 0) results.iam_02 = (cols[ak1Idx] === "false" && (ak2Idx < 0 || cols[ak2Idx] === "false")) ? "PASS" : "FAIL";
            const lastUsedIdx = headers.indexOf("password_last_used");
            if (lastUsedIdx >= 0 && cols[lastUsedIdx] !== "no_information" && cols[lastUsedIdx] !== "N/A") {
              const daysSince = Math.floor((Date.now() - new Date(cols[lastUsedIdx]).getTime()) / 86400000);
              results.iam_03 = daysSince > 90 ? "PASS" : "WARN";
            }
          }
          const userRows = lines.slice(1).filter(l => !l.startsWith("<root_account>"));
          if (mfaIdx >= 0 && userRows.length > 0) {
            const allMfa = userRows.every(l => {const c = l.split(","); return c[mfaIdx] === "true" || c[headers.indexOf("password_enabled")] === "false";});
            results.iam_05 = allMfa ? "PASS" : "FAIL";
          }
        }
      } catch(e) { /* credential report parse error */ }
    }

    // CloudTrail
    const trails = d.cloudtrail?.trails?.trailList || d.cloudtrail?.trails?.TrailList || [];
    results.ct_01 = trails.length > 0 && trails.some(t => t.IsMultiRegionTrail) ? "PASS" : (trails.length > 0 ? "WARN" : "FAIL");
    results.ct_02 = trails.some(t => t.LogFileValidationEnabled) ? "PASS" : "FAIL";
    results.ct_03 = trails.some(t => t.KmsKeyId) ? "PASS" : "FAIL";
    results.ct_05 = trails.some(t => t.CloudWatchLogsLogGroupArn) ? "PASS" : "FAIL";
    results.ct_04 = "MANUAL";

    // GuardDuty
    const detectors = d.guardduty?.detectors?.DetectorIds || [];
    results.gd_01 = detectors.length > 0 ? "PASS" : "FAIL";
    results.gd_02 = "MANUAL";

    // S3
    const pub = d.s3?.public_access_block?.PublicAccessBlockConfiguration || d.s3?.public_access_block || {};
    results.s3_05 = (pub.BlockPublicAcls && pub.IgnorePublicAcls && pub.BlockPublicPolicy && pub.RestrictPublicBuckets) ? "PASS" : (pub.error ? "FAIL" : "WARN");
    results.s3_01 = results.s3_05 === "PASS" ? "PASS" : "MANUAL";
    results.s3_02 = "MANUAL"; results.s3_03 = "MANUAL"; results.s3_04 = "MANUAL";

    // Config
    const recorders = d.config?.recorders?.ConfigurationRecorders || [];
    results.cfg_01 = recorders.length > 0 ? "PASS" : "FAIL";
    const rules = d.config?.rules || [];
    results.cfg_02 = rules.length > 0 ? "PASS" : "FAIL";

    // EC2
    const sgs = d.ec2?.security_groups || [];
    const sshOpen = sgs.some(sg => (sg.Rules || []).some(r => r.FromPort <= 22 && r.ToPort >= 22 && (r.IpRanges || []).some(ip => ip.CidrIp === "0.0.0.0/0")));
    const rdpOpen = sgs.some(sg => (sg.Rules || []).some(r => r.FromPort <= 3389 && r.ToPort >= 3389 && (r.IpRanges || []).some(ip => ip.CidrIp === "0.0.0.0/0")));
    results.ec2_01 = sshOpen ? "FAIL" : "PASS";
    results.ec2_02 = rdpOpen ? "FAIL" : "PASS";
    const unencVols = d.ec2?.unencrypted_volumes || [];
    results.ec2_03 = unencVols.length === 0 ? "PASS" : "FAIL";
    results.ec2_04 = "MANUAL"; results.ec2_05 = "MANUAL";

    // RDS
    const rdsList = d.rds?.instances || [];
    if (rdsList.length === 0) { results.rds_01 = "N/A"; results.rds_02 = "N/A"; results.rds_03 = "N/A"; results.rds_04 = "N/A"; }
    else {
      results.rds_01 = rdsList.every(r => !r.Public) ? "PASS" : "FAIL";
      results.rds_02 = rdsList.every(r => r.Encrypted) ? "PASS" : "FAIL";
      results.rds_03 = rdsList.every(r => (r.Backup || 0) > 0) ? "PASS" : "FAIL";
      results.rds_04 = rdsList.every(r => r.MultiAZ) ? "PASS" : "WARN";
    }

    // CloudWatch
    const alarms = d.cloudwatch?.alarms || [];
    const alarmNames = alarms.map(a => (a.Name + " " + (a.Metric||"") + " " + (a.NS||"")).toLowerCase());
    results.cw_01 = alarmNames.some(n => n.includes("unauthorized") || n.includes("accessdenied")) ? "PASS" : "MANUAL";
    results.cw_02 = alarmNames.some(n => n.includes("root") || n.includes("rootaccount")) ? "PASS" : "MANUAL";
    results.cw_03 = alarmNames.some(n => n.includes("iam") && n.includes("policy")) ? "PASS" : "MANUAL";
    results.cw_04 = alarmNames.some(n => n.includes("security") && n.includes("group")) ? "PASS" : "MANUAL";
    const logGroups = d.cloudwatch?.log_groups || [];
    results.cw_05 = logGroups.length > 0 && logGroups.every(lg => (lg.Retention || 0) >= 365) ? "PASS" : (logGroups.length === 0 ? "MANUAL" : "WARN");

    // KMS
    const keys = d.kms?.keys || [];
    results.kms_01 = keys.length > 0 ? "MANUAL" : "N/A";

    // SSO
    results.sso_01 = "MANUAL";

    return { results, meta, raw: d };
  } catch (e) {
    console.error("Parse error:", e);
    return { results, meta: {}, raw: null, error: e.message };
  }
};

const CloudIntegration = ({data, setData, role: userRole}) => {
  const [toast, setToast] = useState(null);
  const [tab, setTab] = useState("dashboard");
  const [provider, setProvider] = useState("aws"); // "aws" | "azure"
  const [expandCat, setExpandCat] = useState(null);
  const [copied, setCopied] = useState({});
  const [filterSev, setFilterSev] = useState("ALL");
  const [filterStatus, setFilterStatus] = useState("ALL");
  const [awsCreds, setAwsCreds] = useState({accessKeyId:"", secretAccessKey:"", region:"ap-south-1"});
  const [azureCreds, setAzureCreds] = useState({tenantId:"", clientId:"", clientSecret:"", subscriptionId:""});
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState({pct:0, msg:""});
  const [connected, setConnected] = useState({aws:false, azure:false});
  const [connectedAccount, setConnectedAccount] = useState({aws:"", azure:""});
  const canManage = canEdit(userRole || "client_user", "cloud");
  const {user} = useAuth();

  // Provider-aware computed values
  const CHECKS = provider === "aws" ? AWS_CHECKS : AZURE_CHECKS;
  const CATS = provider === "aws" ? AWS_CATS : AZURE_CATS;
  const GAP_MAP = CLOUD_GAP_MAP[provider] || {};

  const scans = (data.cloudScans || []).filter(s => s.provider === provider);
  const latestScan = scans.length > 0 ? scans[scans.length - 1] : null;
  const checkResults = latestScan?.results || {};
  const overrides = latestScan?.overrides || {};

  const getStatus = (id) => overrides[id] || checkResults[id] || "NOT_RUN";

  // ---- AWS Test Connection ----
  const testAwsConnection = async () => {
    if (!awsCreds.accessKeyId || !awsCreds.secretAccessKey) { setToast({msg:"Enter both Access Key ID and Secret Access Key",type:"error"}); return; }
    try {
      setScanning(true); setScanProgress({pct:10,msg:"Testing AWS connection..."});
      const resp = await fetch("/api/test", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({accessKeyId:awsCreds.accessKeyId,secretAccessKey:awsCreds.secretAccessKey,region:awsCreds.region})});
      const d = await resp.json();
      if (!resp.ok) throw new Error(d.error || "Connection failed");
      setConnected(c => ({...c,aws:true})); setConnectedAccount(a => ({...a,aws:d.account}));
      setToast({msg:`Connected to AWS account ${d.account}`,type:"success"});
    } catch(e) {
      setConnected(c => ({...c,aws:false})); setConnectedAccount(a => ({...a,aws:""}));
      setToast({msg:`AWS connection failed: ${e.message}`,type:"error"});
    } finally { setScanning(false); }
  };

  // ---- AWS Full Scan ----
  const handleAwsScan = async () => {
    if (!awsCreds.accessKeyId || !awsCreds.secretAccessKey) { setToast({msg:"Enter AWS credentials first",type:"error"}); return; }
    try {
      setScanning(true); setScanProgress({pct:5,msg:"Starting AWS scan — this takes 30-60 seconds..."});
      const progressTimer = setInterval(() => {
        setScanProgress(p => ({pct: Math.min(p.pct + 3, 90), msg: p.pct < 20 ? "Scanning IAM..." : p.pct < 40 ? "Scanning CloudTrail, GuardDuty, S3..." : p.pct < 60 ? "Scanning EC2, RDS, Config..." : p.pct < 80 ? "Scanning CloudWatch, KMS..." : "Finalizing..."}));
      }, 2000);
      const resp = await fetch("/api/scan", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({accessKeyId:awsCreds.accessKeyId,secretAccessKey:awsCreds.secretAccessKey,region:awsCreds.region})});
      clearInterval(progressTimer);
      const result = await resp.json();
      if (!resp.ok) throw new Error(result.error || "Scan failed");
      setScanProgress({pct:100,msg:"Scan complete!"});
      const scan = {id:`scan_${Date.now()}`,provider:"aws",date:result.scannedAt||new Date().toISOString(),account:result.account||"Unknown",region:result.region||awsCreds.region,results:result.results,overrides:{},scannedBy:user?.email||"unknown",scanType:"live"};
      setData(d => ({...d, cloudScans: [...(d.cloudScans || []), scan]}));
      setConnected(c => ({...c,aws:true})); setConnectedAccount(a => ({...a,aws:result.account}));
      setToast({msg:`AWS scan complete! ${result.summary?.pass||0} passed, ${result.summary?.fail||0} failed.`,type:"success"});
      setTab("checks");
    } catch(e) { setToast({msg:`AWS scan failed: ${e.message}`,type:"error"}); } finally { setScanning(false); }
  };

  // ---- Azure Test Connection ----
  const testAzureConnection = async () => {
    const {tenantId,clientId,clientSecret,subscriptionId} = azureCreds;
    if (!tenantId||!clientId||!clientSecret||!subscriptionId) { setToast({msg:"Enter all 4 Azure fields",type:"error"}); return; }
    try {
      setScanning(true); setScanProgress({pct:10,msg:"Testing Azure connection..."});
      const resp = await fetch("/api/azure/test", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(azureCreds)});
      const d = await resp.json();
      if (!resp.ok) throw new Error(d.error || "Connection failed");
      setConnected(c => ({...c,azure:true})); setConnectedAccount(a => ({...a,azure:d.subscriptionName||d.subscriptionId}));
      setToast({msg:`Connected to Azure subscription: ${d.subscriptionName||d.subscriptionId}`,type:"success"});
    } catch(e) {
      setConnected(c => ({...c,azure:false})); setConnectedAccount(a => ({...a,azure:""}));
      setToast({msg:`Azure connection failed: ${e.message}`,type:"error"});
    } finally { setScanning(false); }
  };

  // ---- Azure Full Scan ----
  const handleAzureScan = async () => {
    const {tenantId,clientId,clientSecret,subscriptionId} = azureCreds;
    if (!tenantId||!clientId||!clientSecret||!subscriptionId) { setToast({msg:"Enter all 4 Azure fields",type:"error"}); return; }
    try {
      setScanning(true); setScanProgress({pct:5,msg:"Starting Azure scan — this takes 30-60 seconds..."});
      const progressTimer = setInterval(() => {
        setScanProgress(p => ({pct: Math.min(p.pct + 3, 90), msg: p.pct < 20 ? "Scanning Identity & RBAC..." : p.pct < 40 ? "Scanning Storage, Network, Policy..." : p.pct < 60 ? "Scanning Defender, SQL, Monitor..." : p.pct < 80 ? "Scanning Key Vault, Logs..." : "Finalizing..."}));
      }, 2000);
      const resp = await fetch("/api/azure/scan", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(azureCreds)});
      clearInterval(progressTimer);
      const result = await resp.json();
      if (!resp.ok) throw new Error(result.error || "Scan failed");
      setScanProgress({pct:100,msg:"Scan complete!"});
      const scan = {id:`scan_${Date.now()}`,provider:"azure",date:result.scannedAt||new Date().toISOString(),account:result.subscriptionName||result.subscriptionId||"Unknown",region:"Global",results:result.results,overrides:{},scannedBy:user?.email||"unknown",scanType:"live"};
      setData(d => ({...d, cloudScans: [...(d.cloudScans || []), scan]}));
      setConnected(c => ({...c,azure:true})); setConnectedAccount(a => ({...a,azure:result.subscriptionName||result.subscriptionId}));
      setToast({msg:`Azure scan complete! ${result.summary?.pass||0} passed, ${result.summary?.fail||0} failed.`,type:"success"});
      setTab("checks");
    } catch(e) { setToast({msg:`Azure scan failed: ${e.message}`,type:"error"}); } finally { setScanning(false); }
  };

  // Convenience wrappers
  const testConnection = () => provider === "aws" ? testAwsConnection() : testAzureConnection();
  const handleLiveScan = () => provider === "aws" ? handleAwsScan() : handleAzureScan();

  const handleUpload = (file) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const parsed = parseAwsScan(e.target.result);
        if (parsed.error) { setToast({msg: "Parse error: " + parsed.error, type: "error"}); return; }
        const scan = {
          id: `scan_${Date.now()}`, provider: provider, date: new Date().toISOString(),
          account: parsed.meta?.account || "Unknown", region: parsed.meta?.region || "Unknown",
          results: parsed.results, overrides: {}, scannedBy: user?.email || "unknown", scanType: "upload",
        };
        setData(d => ({...d, cloudScans: [...(d.cloudScans || []), scan]}));
        setToast({msg: `Scan imported! ${Object.values(parsed.results).filter(v=>v==="PASS").length} passed, ${Object.values(parsed.results).filter(v=>v==="FAIL").length} failed.`, type: "success"});
        setTab("checks");
      } catch (err) { setToast({msg: "Invalid JSON file: " + err.message, type: "error"}); }
    };
    reader.readAsText(file);
  };

  const copyText = (text, key) => {
    navigator.clipboard.writeText(text).then(() => { setCopied(c => ({...c,[key]:true})); setTimeout(() => setCopied(c => ({...c,[key]:false})), 2000); });
  };

  const downloadScript = () => {
    const blob = new Blob([AWS_SCAN_SCRIPT], {type:"text/x-shellscript"});
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = "seccomply_scan.sh"; a.click(); URL.revokeObjectURL(url);
  };

  const downloadTemplate = () => {
    const blob = new Blob([CF_TEMPLATE_YAML], {type:"text/yaml"});
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = "seccomply_scanner.yaml"; a.click(); URL.revokeObjectURL(url);
  };

  const setOverride = (checkId, status) => {
    if (!latestScan) return;
    const scanIdx = (data.cloudScans||[]).findIndex(s => s.id === latestScan.id);
    if (scanIdx < 0) return;
    setData(d => ({...d, cloudScans: d.cloudScans.map((s, i) => i === scanIdx ? {...s, overrides: {...(s.overrides || {}), [checkId]: status}} : s)}));
  };

  const clearOverride = (checkId) => {
    if (!latestScan) return;
    const scanIdx = (data.cloudScans||[]).findIndex(s => s.id === latestScan.id);
    if (scanIdx < 0) return;
    setData(d => ({...d, cloudScans: d.cloudScans.map((s, i) => {
      if (i !== scanIdx) return s;
      const ov = {...(s.overrides || {})}; delete ov[checkId]; return {...s, overrides: ov};
    })}));
  };

  // Push evidence to gap assessment (provider-aware)
  const pushToGap = () => {
    const updates = {};
    const provLabel = provider === "aws" ? "AWS" : "Azure";
    Object.entries(GAP_MAP).forEach(([qId, {name, checks: checkIds}]) => {
      const statuses = checkIds.map(id => ({id, name: (CHECKS.find(c => c.id === id)||{}).name, status: getStatus(id)}));
      const pass = statuses.filter(s => s.status === "PASS").length;
      const fail = statuses.filter(s => s.status === "FAIL").length;
      const total = statuses.length;
      const pct = Math.round((pass / total) * 100);

      const summary = `[${provLabel} Scan ${new Date().toLocaleDateString()}] ${name}: ${pass}/${total} passed (${pct}%)\n` +
        statuses.map(s => `${s.status === "PASS" ? "✅" : s.status === "FAIL" ? "❌" : s.status === "WARN" ? "⚠️" : "⬜"} ${s.name}`).join("\n");

      const existing = (data.gapResponses || {})[qId] || {};
      const autoResp = fail === 0 && pass === total ? "Yes" : pass === 0 ? "No" : "Partial";
      updates[qId] = {
        ...existing,
        resp: existing.resp || autoResp,
        notes: (existing.notes ? existing.notes + "\n\n" : "") + summary,
        driveLink: existing.driveLink || "",
        cloudScanLinked: true,
        cloudScanDate: new Date().toISOString(),
      };
    });
    setData(d => ({...d, gapResponses: {...(d.gapResponses || {}), ...updates}}));
    setToast({msg: `${provLabel} evidence pushed to Gap Assessment (C3–C7)!`, type: "success"});
  };

  // Stats (provider-aware via CHECKS/CATS)
  const pass = CHECKS.filter(c => getStatus(c.id) === "PASS").length;
  const fail = CHECKS.filter(c => getStatus(c.id) === "FAIL").length;
  const warn = CHECKS.filter(c => getStatus(c.id) === "WARN").length;
  const manual = CHECKS.filter(c => getStatus(c.id) === "MANUAL").length;
  const na = CHECKS.filter(c => getStatus(c.id) === "N/A").length;
  const notRun = CHECKS.filter(c => getStatus(c.id) === "NOT_RUN").length;
  const scorePct = latestScan ? Math.round((pass / (CHECKS.length - na)) * 100) || 0 : 0;

  const catStats = CATS.map(cat => {
    const checks = CHECKS.filter(c => c.cat === cat);
    return {cat, total: checks.length, pass: checks.filter(c => getStatus(c.id) === "PASS").length, fail: checks.filter(c => getStatus(c.id) === "FAIL").length, warn: checks.filter(c => getStatus(c.id) === "WARN" || getStatus(c.id) === "MANUAL").length};
  });

  const filteredChecks = CHECKS.filter(c => {
    if (filterSev !== "ALL" && c.sev !== filterSev) return false;
    if (filterStatus !== "ALL" && getStatus(c.id) !== filterStatus) return false;
    return true;
  });

  const statusStyle = (st) => {
    const map = {PASS:{bg:`${C.green}15`,border:`${C.green}44`,color:C.green,label:"PASS",icon:"✅"},FAIL:{bg:`${C.red}15`,border:`${C.red}44`,color:C.red,label:"FAIL",icon:"❌"},WARN:{bg:`${C.yellow}15`,border:`${C.yellow}44`,color:C.yellow,label:"WARN",icon:"⚠️"},MANUAL:{bg:`${C.blue}15`,border:`${C.blue}44`,color:C.blue,label:"MANUAL",icon:"🔍"},"N/A":{bg:`${C.textDim}15`,border:`${C.textDim}44`,color:C.textDim,label:"N/A",icon:"➖"},NOT_RUN:{bg:`${C.textDim}10`,border:`${C.border}`,color:C.textDim,label:"—",icon:"⬜"}};
    return map[st] || map.NOT_RUN;
  };

  const isConn = connected[provider];
  const connAcct = connectedAccount[provider];
  const providerLabel = provider === "aws" ? "AWS" : "Azure";
  const providerColor = provider === "aws" ? C.orange : "#0078D4";
  const TABS = [{id:"dashboard",label:"Dashboard",icon:LayoutDashboard},{id:"checks",label:"Security Checks",icon:Shield},{id:"connect",label:`Connect ${providerLabel}`,icon:Cloud},{id:"evidence",label:"Gap Evidence",icon:ClipboardCheck}];

  return (<div>
    {toast && <Toast {...toast} onClose={() => setToast(null)}/>}

    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20}}>
      <div>
        <h2 style={{margin:0,fontSize:22,fontWeight:800,color:C.text,display:"flex",alignItems:"center",gap:8}}><Cloud size={24} color={C.blue}/> Cloud Security</h2>
        <p style={{color:C.textMuted,margin:"4px 0 0",fontSize:13}}>{providerLabel} security posture assessment mapped to ISO 27001 controls</p>
      </div>
      <div style={{display:"flex",gap:8,alignItems:"center"}}>
        {isConn && <span style={{fontSize:11,color:C.green,fontWeight:700,display:"flex",alignItems:"center",gap:4,background:`${C.green}15`,padding:"4px 10px",borderRadius:6,border:`1px solid ${C.green}33`}}><CheckCircle size={12}/> {providerLabel} {connAcct}</span>}
        {!isConn && latestScan && <span style={{fontSize:11,color:C.green,fontWeight:700,display:"flex",alignItems:"center",gap:4,background:`${C.green}15`,padding:"4px 10px",borderRadius:6,border:`1px solid ${C.green}33`}}><CheckCircle size={12}/> {providerLabel} {latestScan.account}</span>}
        {canManage && isConn && <Btn onClick={handleLiveScan} disabled={scanning}>{scanning ? <><Loader size={14} style={{animation:"spin 1s linear infinite"}}/> Scanning...</> : <><Zap size={14}/> Re-Scan</>}</Btn>}
        {canManage && !isConn && <Btn onClick={() => setTab("connect")}><Cloud size={14}/> Connect {providerLabel}</Btn>}
      </div>
    </div>

    {/* Provider Switcher */}
    <div style={{display:"flex",gap:6,marginBottom:12}}>
      {[{id:"aws",label:"AWS",color:C.orange,icon:"🔶"},{id:"azure",label:"Azure",color:"#0078D4",icon:"🔷"}].map(p => (
        <button key={p.id} onClick={() => { setProvider(p.id); setTab("dashboard"); }} style={{padding:"8px 18px",borderRadius:8,border: provider===p.id ? `2px solid ${p.color}` : `1px solid ${C.border}`,cursor:"pointer",fontFamily:"inherit",fontSize:13,fontWeight: provider===p.id ? 800 : 500,background: provider===p.id ? `${p.color}15` : C.card,color: provider===p.id ? p.color : C.textMuted,display:"flex",alignItems:"center",gap:6,transition:"all 0.2s"}}>{p.icon} {p.label} {connected[p.id] && <CheckCircle size={12} color={C.green}/>}</button>
      ))}
    </div>

    {/* Tabs */}
    <div style={{display:"flex",gap:4,marginBottom:16,background:C.card,borderRadius:10,padding:4,width:"fit-content"}}>
      {TABS.map(t => <button key={t.id} onClick={() => setTab(t.id)} style={{padding:"8px 16px",borderRadius:8,border:"none",cursor:"pointer",fontFamily:"inherit",fontSize:12,fontWeight:tab===t.id?700:500,background:tab===t.id?providerColor:"transparent",color:tab===t.id?"#fff":C.textMuted,display:"flex",alignItems:"center",gap:6,transition:"all 0.2s"}}><t.icon size={13}/> {t.label}</button>)}
    </div>

    {/* DASHBOARD TAB */}
    {tab === "dashboard" && (<>
      {!latestScan ? (
        <Card>
          <div style={{textAlign:"center",padding:40}}>
            <Cloud size={56} color={providerColor} style={{marginBottom:16,opacity:0.3}}/>
            <h3 style={{color:C.text,margin:"0 0 8px",fontSize:18,fontWeight:700}}>No {providerLabel} Scan Yet</h3>
            <p style={{color:C.textMuted,fontSize:13,marginBottom:16}}>Connect your {providerLabel} account to automatically scan your security posture, or manually mark checks in the Security Checks tab.</p>
            <div style={{display:"flex",gap:8,justifyContent:"center"}}>
              <Btn onClick={() => setTab("connect")}><Cloud size={14}/> Connect {providerLabel}</Btn>
              <Btn variant="secondary" onClick={() => setTab("checks")}><Shield size={14}/> Manual Assessment</Btn>
            </div>
          </div>
        </Card>
      ) : (<>
        {/* Score + Meta */}
        <div style={{display:"flex",gap:12,flexWrap:"wrap",marginBottom:16}}>
          <div style={{background:C.card,borderRadius:12,border:`1px solid ${C.border}`,padding:"16px 24px",display:"flex",alignItems:"center",gap:14,minWidth:160}}>
            <div style={{width:52,height:52,borderRadius:"50%",background:`conic-gradient(${scorePct >= 80 ? C.green : scorePct >= 50 ? C.yellow : C.red} ${scorePct * 3.6}deg, ${C.border} 0deg)`,display:"flex",alignItems:"center",justifyContent:"center"}}>
              <div style={{width:40,height:40,borderRadius:"50%",background:C.card,display:"flex",alignItems:"center",justifyContent:"center",fontSize:14,fontWeight:800,color:scorePct >= 80 ? C.green : scorePct >= 50 ? C.yellow : C.red}}>{scorePct}%</div>
            </div>
            <div><div style={{fontSize:10,color:C.textDim,fontWeight:700,textTransform:"uppercase"}}>Security Score</div><div style={{fontSize:18,fontWeight:800,color:C.text}}>{pass}/{CHECKS.length - na}</div></div>
          </div>
          <Stat label="Passed" value={pass} icon={CheckCircle} color={C.green}/>
          <Stat label="Failed" value={fail} icon={XCircle} color={C.red}/>
          <Stat label="Warning" value={warn} icon={AlertCircle} color={C.yellow}/>
          <Stat label="Manual" value={manual} icon={Search} color={C.blue}/>
          {notRun > 0 && <Stat label="Not Run" value={notRun} icon={Clock} color={C.textDim}/>}
        </div>

        {/* Scan info */}
        <div style={{background:C.card,borderRadius:10,border:`1px solid ${C.border}`,padding:"10px 16px",marginBottom:16,display:"flex",gap:20,alignItems:"center",fontSize:12,flexWrap:"wrap"}}>
          <span style={{color:C.textMuted}}>{provider === "aws" ? "🔶" : "🔷"} <strong style={{color:C.text}}>{providerLabel}</strong> {provider === "aws" ? "Account" : "Subscription"}: <strong style={{color:providerColor}}>{latestScan.account}</strong></span>
          <span style={{color:C.textMuted}}>{provider === "aws" ? "Region" : "Scope"}: <strong style={{color:C.text}}>{latestScan.region}</strong></span>
          <span style={{color:C.textMuted}}>Scanned: <strong style={{color:C.text}}>{new Date(latestScan.date).toLocaleString()}</strong></span>
          <span style={{color:C.textMuted}}>By: <strong style={{color:C.text}}>{latestScan.scannedBy}</strong></span>
          <span style={{color:C.textMuted}}>Scans: <strong style={{color:C.text}}>{scans.length}</strong></span>
        </div>

        {/* Category breakdown */}
        <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(200px,1fr))",gap:10}}>
          {catStats.map(cs => {
            const pct = cs.total > 0 ? Math.round((cs.pass / cs.total) * 100) : 0;
            return (<div key={cs.cat} onClick={() => {setExpandCat(expandCat === cs.cat ? null : cs.cat); setTab("checks");}} style={{background:C.card,borderRadius:10,border:`1px solid ${pct === 100 ? C.green : cs.fail > 0 ? C.red : C.border}44`,padding:14,cursor:"pointer",transition:"all 0.2s"}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
                <span style={{fontSize:13,fontWeight:700,color:C.text}}>{cs.cat}</span>
                <span style={{fontSize:12,fontWeight:800,color:pct === 100 ? C.green : pct >= 50 ? C.yellow : C.red}}>{pct}%</span>
              </div>
              <div style={{height:5,background:C.border,borderRadius:3,overflow:"hidden",marginBottom:6}}>
                <div style={{height:"100%",width:`${pct}%`,background:pct === 100 ? C.green : pct >= 50 ? C.yellow : C.red,borderRadius:3,transition:"width 0.3s"}}/>
              </div>
              <div style={{display:"flex",gap:8,fontSize:10,color:C.textDim}}>
                {cs.pass > 0 && <span style={{color:C.green}}>✅ {cs.pass}</span>}
                {cs.fail > 0 && <span style={{color:C.red}}>❌ {cs.fail}</span>}
                {cs.warn > 0 && <span style={{color:C.yellow}}>⚠️ {cs.warn}</span>}
              </div>
            </div>);
          })}
        </div>
      </>)}
    </>)}

    {/* CHECKS TAB */}
    {tab === "checks" && (
      <Card>
        <div style={{display:"flex",gap:8,marginBottom:14,flexWrap:"wrap",alignItems:"center"}}>
          <span style={{fontSize:11,color:C.textDim,fontWeight:700}}>FILTER:</span>
          <select value={filterSev} onChange={e => setFilterSev(e.target.value)} style={{padding:"4px 8px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:6,color:C.text,fontSize:11,fontFamily:"inherit"}}>
            <option value="ALL">All Severity</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option>
          </select>
          <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)} style={{padding:"4px 8px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:6,color:C.text,fontSize:11,fontFamily:"inherit"}}>
            <option value="ALL">All Status</option><option value="PASS">Pass</option><option value="FAIL">Fail</option><option value="WARN">Warn</option><option value="MANUAL">Manual</option><option value="NOT_RUN">Not Run</option>
          </select>
          <span style={{fontSize:11,color:C.textMuted,marginLeft:8}}>{filteredChecks.length} checks</span>
        </div>
        <div style={{overflow:"auto",maxHeight:550}}>
          <table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}>
            <thead><tr style={{background:C.bg,position:"sticky",top:0,zIndex:1}}>
              <th style={{padding:"8px 10px",textAlign:"left",color:C.orange,fontWeight:700,fontSize:11,borderBottom:`2px solid ${C.border}`,width:60}}>STATUS</th>
              <th style={{padding:"8px 10px",textAlign:"left",color:C.orange,fontWeight:700,fontSize:11,borderBottom:`2px solid ${C.border}`}}>CHECK</th>
              <th style={{padding:"8px 10px",textAlign:"center",color:C.orange,fontWeight:700,fontSize:11,borderBottom:`2px solid ${C.border}`,width:70}}>SEVERITY</th>
              <th style={{padding:"8px 10px",textAlign:"center",color:C.orange,fontWeight:700,fontSize:11,borderBottom:`2px solid ${C.border}`,width:65}}>ISO</th>
              <th style={{padding:"8px 10px",textAlign:"center",color:C.orange,fontWeight:700,fontSize:11,borderBottom:`2px solid ${C.border}`,width:50}}>GAP</th>
              {canManage && <th style={{padding:"8px 10px",textAlign:"center",color:C.orange,fontWeight:700,fontSize:11,borderBottom:`2px solid ${C.border}`,width:110}}>OVERRIDE</th>}
            </tr></thead>
            <tbody>
              {CATS.map(cat => {
                const catChecks = filteredChecks.filter(c => c.cat === cat);
                if (catChecks.length === 0) return null;
                return (<>
                  <tr key={`cat_${cat}`}><td colSpan={canManage ? 6 : 5} style={{padding:"10px 10px 4px",fontWeight:800,fontSize:12,color:C.blue,borderBottom:`1px solid ${C.border}33`}}>{cat} <span style={{fontWeight:500,color:C.textDim}}>({catChecks.length})</span></td></tr>
                  {catChecks.map(c => {
                    const st = getStatus(c.id);
                    const ss = statusStyle(st);
                    const isOverridden = !!overrides[c.id];
                    const sevColor = {CRITICAL:C.red,HIGH:C.yellow,MEDIUM:C.blue}[c.sev] || C.textDim;
                    return (<tr key={c.id} style={{borderBottom:`1px solid ${C.border}22`}}>
                      <td style={{padding:"6px 10px"}}>
                        <div style={{display:"inline-flex",alignItems:"center",gap:4,padding:"3px 8px",borderRadius:6,background:ss.bg,border:`1px solid ${ss.border}`,minWidth:55,justifyContent:"center"}}>
                          <span style={{fontSize:10}}>{ss.icon}</span>
                          <span style={{fontSize:10,fontWeight:700,color:ss.color}}>{ss.label}</span>
                        </div>
                      </td>
                      <td style={{padding:"6px 10px",color:C.text,fontSize:12}}>
                        {c.name}
                        {isOverridden && <span style={{marginLeft:6,fontSize:9,color:C.orange,fontWeight:700,background:`${C.orange}22`,padding:"1px 5px",borderRadius:4}}>OVERRIDDEN</span>}
                      </td>
                      <td style={{padding:"6px 10px",textAlign:"center"}}>
                        <span style={{fontSize:10,fontWeight:700,color:sevColor,padding:"2px 6px",borderRadius:4,background:`${sevColor}18`}}>{c.sev}</span>
                      </td>
                      <td style={{padding:"6px 10px",textAlign:"center",fontSize:10,color:C.textMuted,fontWeight:600}}>{c.iso}</td>
                      <td style={{padding:"6px 10px",textAlign:"center"}}>{c.gapQ ? <span style={{fontSize:10,fontWeight:700,color:C.orange,background:`${C.orange}22`,padding:"2px 6px",borderRadius:4}}>{c.gapQ}</span> : <span style={{color:C.textDim,fontSize:10}}>—</span>}</td>
                      {canManage && <td style={{padding:"6px 6px",textAlign:"center"}}>
                        <select value={overrides[c.id] || ""} onChange={e => {const v = e.target.value; if (v) setOverride(c.id, v); else clearOverride(c.id);}} style={{padding:"3px 5px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:5,color:C.text,fontSize:10,fontFamily:"inherit",width:80}}>
                          <option value="">Auto</option><option value="PASS">✅ Pass</option><option value="FAIL">❌ Fail</option><option value="WARN">⚠️ Warn</option><option value="N/A">➖ N/A</option>
                        </select>
                      </td>}
                    </tr>);
                  })}
                </>);
              })}
            </tbody>
          </table>
        </div>
      </Card>
    )}

    {/* CONNECT TAB */}
    {tab === "connect" && (
      <div>
        {/* ===== AWS CONNECT ===== */}
        {provider === "aws" && (<>
          {/* Step 1: CloudFormation Setup */}
          <Card>
            <div style={{marginBottom:16}}>
              <h3 style={{margin:"0 0 8px",fontSize:16,fontWeight:800,color:C.text,display:"flex",alignItems:"center",gap:6}}>
                <span style={{background:C.orange,color:"#fff",width:24,height:24,borderRadius:"50%",display:"inline-flex",alignItems:"center",justifyContent:"center",fontSize:12,fontWeight:800}}>1</span>
                Create Scanner IAM User
              </h3>
              <p style={{color:C.textMuted,fontSize:12,margin:0,lineHeight:1.6}}>Open <strong style={{color:C.text}}>AWS CloudShell</strong> (click the <code style={{background:`${C.orange}22`,padding:"1px 4px",borderRadius:3,color:C.orange,fontSize:11}}>&gt;_</code> icon in AWS Console) and run this command. It creates a read-only IAM user with <strong style={{color:C.orange}}>SecurityAudit</strong> + <strong style={{color:C.orange}}>ViewOnlyAccess</strong> policies.</p>
            </div>
            <div style={{background:"#0a0e17",borderRadius:10,border:`1px solid ${C.border}`,padding:14,marginBottom:12,position:"relative"}}>
              <pre style={{margin:0,fontSize:11,color:C.green,lineHeight:1.5,whiteSpace:"pre-wrap",wordBreak:"break-all",fontFamily:"'Courier New',monospace"}}>{CF_ONE_LINER}</pre>
              <button onClick={() => copyText(CF_ONE_LINER,"cf")} style={{position:"absolute",top:8,right:8,padding:"4px 10px",background:copied.cf?C.green:C.orange,color:"#fff",border:"none",borderRadius:6,fontSize:10,fontWeight:700,cursor:"pointer",fontFamily:"inherit"}}>{copied.cf ? "✓ Copied" : "Copy"}</button>
            </div>
            <Btn variant="secondary" size="sm" onClick={downloadTemplate}><Download size={12}/> Download YAML Template</Btn>
          </Card>

          {/* Step 2: Get Access Keys */}
          <Card style={{marginTop:12}}>
            <div style={{marginBottom:16}}>
              <h3 style={{margin:"0 0 8px",fontSize:16,fontWeight:800,color:C.text,display:"flex",alignItems:"center",gap:6}}>
                <span style={{background:C.orange,color:"#fff",width:24,height:24,borderRadius:"50%",display:"inline-flex",alignItems:"center",justifyContent:"center",fontSize:12,fontWeight:800}}>2</span>
                Get Access Keys
              </h3>
              <p style={{color:C.textMuted,fontSize:12,margin:0}}>Wait ~30 seconds for Step 1 to finish. Then run this command to get the access keys:</p>
            </div>
            <div style={{background:"#0a0e17",borderRadius:10,border:`1px solid ${C.border}`,padding:14,position:"relative"}}>
              <pre style={{margin:0,fontSize:11,color:C.green,fontFamily:"'Courier New',monospace"}}>{CF_GET_KEYS}</pre>
              <button onClick={() => copyText(CF_GET_KEYS,"keys")} style={{position:"absolute",top:8,right:8,padding:"4px 10px",background:copied.keys?C.green:C.orange,color:"#fff",border:"none",borderRadius:6,fontSize:10,fontWeight:700,cursor:"pointer",fontFamily:"inherit"}}>{copied.keys ? "✓ Copied" : "Copy"}</button>
            </div>
          </Card>

          {/* Step 3: Enter Credentials & Scan */}
          <Card style={{marginTop:12}}>
            <div style={{marginBottom:16}}>
              <h3 style={{margin:"0 0 8px",fontSize:16,fontWeight:800,color:C.text,display:"flex",alignItems:"center",gap:6}}>
                <span style={{background:C.orange,color:"#fff",width:24,height:24,borderRadius:"50%",display:"inline-flex",alignItems:"center",justifyContent:"center",fontSize:12,fontWeight:800}}>3</span>
                Enter Credentials & Scan
              </h3>
              <p style={{color:C.textMuted,fontSize:12,margin:0}}>Paste the keys from Step 2 below. Credentials are sent to your backend server (same origin) — <strong style={{color:C.green}}>never stored anywhere</strong>.</p>
            </div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:12}}>
              <div>
                <label style={{fontSize:11,fontWeight:700,color:C.textMuted,marginBottom:4,display:"block"}}>Access Key ID</label>
                <input value={awsCreds.accessKeyId} onChange={e => setAwsCreds(c => ({...c, accessKeyId: e.target.value.trim()}))} placeholder="AKIA..." style={{width:"100%",padding:"10px 12px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,color:C.text,fontSize:13,fontFamily:"'Courier New',monospace",boxSizing:"border-box"}}/>
              </div>
              <div>
                <label style={{fontSize:11,fontWeight:700,color:C.textMuted,marginBottom:4,display:"block"}}>Secret Access Key</label>
                <input type="password" value={awsCreds.secretAccessKey} onChange={e => setAwsCreds(c => ({...c, secretAccessKey: e.target.value.trim()}))} placeholder="wJalr..." style={{width:"100%",padding:"10px 12px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,color:C.text,fontSize:13,fontFamily:"'Courier New',monospace",boxSizing:"border-box"}}/>
              </div>
            </div>
            <div style={{marginBottom:16}}>
              <label style={{fontSize:11,fontWeight:700,color:C.textMuted,marginBottom:4,display:"block"}}>AWS Region</label>
              <select value={awsCreds.region} onChange={e => setAwsCreds(c => ({...c, region: e.target.value}))} style={{padding:"10px 12px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,color:C.text,fontSize:13,fontFamily:"inherit",minWidth:200}}>
                {AWS_REGIONS.map(r => <option key={r} value={r}>{r}</option>)}
              </select>
            </div>
            {scanning && <div style={{marginBottom:16}}><div style={{display:"flex",justifyContent:"space-between",marginBottom:4}}><span style={{fontSize:11,color:C.textMuted}}>{scanProgress.msg}</span><span style={{fontSize:11,fontWeight:700,color:C.orange}}>{scanProgress.pct}%</span></div><div style={{height:6,background:C.border,borderRadius:3,overflow:"hidden"}}><div style={{height:"100%",width:`${scanProgress.pct}%`,background:C.orange,borderRadius:3,transition:"width 0.3s"}}/></div></div>}
            <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
              <Btn variant="secondary" onClick={testConnection} disabled={scanning || !awsCreds.accessKeyId}>{connected.aws ? <><CheckCircle size={14} color={C.green}/> Connected ({connectedAccount.aws})</> : "Test Connection"}</Btn>
              <Btn onClick={handleLiveScan} disabled={scanning || !awsCreds.accessKeyId || !awsCreds.secretAccessKey}>{scanning ? `Scanning (${scanProgress.pct}%)...` : <><Zap size={14}/> Run Full Scan (40 checks)</>}</Btn>
            </div>
            {connected.aws && !scanning && <div style={{marginTop:12,padding:10,background:`${C.green}10`,borderRadius:8,border:`1px solid ${C.green}33`,fontSize:12,color:C.green,display:"flex",alignItems:"center",gap:6}}><CheckCircle size={14}/> <strong>Connected</strong> to AWS account {connectedAccount.aws} ({awsCreds.region})</div>}
          </Card>

          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginTop:12}}>
            <Card>
              <h4 style={{margin:"0 0 6px",fontSize:13,fontWeight:700,color:C.text}}>🧹 Cleanup (After Scanning)</h4>
              <p style={{color:C.textDim,fontSize:11,margin:"0 0 8px"}}>Remove the IAM user when done:</p>
              <div style={{background:"#0a0e17",borderRadius:8,border:`1px solid ${C.border}`,padding:10,position:"relative"}}>
                <pre style={{margin:0,fontSize:10,color:C.red,fontFamily:"'Courier New',monospace"}}>{CF_CLEANUP}</pre>
                <button onClick={() => copyText(CF_CLEANUP,"cleanup")} style={{position:"absolute",top:6,right:6,padding:"3px 8px",background:copied.cleanup?C.green:C.orange,color:"#fff",border:"none",borderRadius:5,fontSize:9,fontWeight:700,cursor:"pointer",fontFamily:"inherit"}}>{copied.cleanup ? "✓" : "Copy"}</button>
              </div>
            </Card>
            <Card>
              <h4 style={{margin:"0 0 6px",fontSize:13,fontWeight:700,color:C.text}}>📤 Upload JSON (Alternative)</h4>
              <p style={{color:C.textDim,fontSize:11,margin:"0 0 8px"}}>Or upload a JSON scan file from the CLI script:</p>
              <FileUploadBtn onFile={handleUpload} accept=".json" label="Upload sc_scan.json"/>
              {latestScan && <span style={{display:"block",marginTop:6,fontSize:11,color:C.green}}>✅ Last scan: {new Date(latestScan.date).toLocaleDateString()}</span>}
            </Card>
          </div>

          <Card style={{marginTop:12}}>
            <h4 style={{margin:"0 0 8px",fontSize:13,fontWeight:700,color:C.text}}>🔒 Security & Permissions</h4>
            <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(200px,1fr))",gap:8}}>
              {[{name:"SecurityAudit",desc:"Read-only security checks across all AWS services",icon:"🛡️"},{name:"ViewOnlyAccess",desc:"Read-only access to most AWS resources",icon:"👁️"},{name:"Server-Side Scan",desc:"Credentials sent to your backend API — never stored",icon:"🔐"},{name:"CloudFormation",desc:"One-click setup and cleanup via CloudFormation stack",icon:"📦"}].map(p => (
                <div key={p.name} style={{background:C.bg,borderRadius:8,border:`1px solid ${C.border}`,padding:10}}>
                  <div style={{fontSize:11,fontWeight:700,color:C.orange}}>{p.icon} {p.name}</div>
                  <div style={{fontSize:10,color:C.textDim,marginTop:2}}>{p.desc}</div>
                </div>
              ))}
            </div>
          </Card>
        </>)}

        {/* ===== AZURE CONNECT ===== */}
        {provider === "azure" && (<>
          {/* Step 1: Create App Registration */}
          <Card>
            <div style={{marginBottom:16}}>
              <h3 style={{margin:"0 0 8px",fontSize:16,fontWeight:800,color:C.text,display:"flex",alignItems:"center",gap:6}}>
                <span style={{background:"#0078D4",color:"#fff",width:24,height:24,borderRadius:"50%",display:"inline-flex",alignItems:"center",justifyContent:"center",fontSize:12,fontWeight:800}}>1</span>
                Create Service Principal (App Registration)
              </h3>
              <p style={{color:C.textMuted,fontSize:12,margin:0,lineHeight:1.6}}>Open <strong style={{color:C.text}}>Azure Cloud Shell</strong> (Bash) and run these commands. This creates a read-only App Registration with <strong style={{color:"#0078D4"}}>Reader</strong> role on your subscription.</p>
            </div>
            {[
              {label:"Step 1a: Get your Tenant & Subscription ID",cmd:AZ_SETUP_COMMANDS.getInfo,key:"azInfo"},
              {label:"Step 1b: Create App Registration",cmd:AZ_SETUP_COMMANDS.createApp,key:"azApp"},
              {label:"Step 1c: Create Client Secret",cmd:"az ad app credential reset --id <APP_ID_FROM_STEP_1b> --query password -o tsv",key:"azSecret"},
              {label:"Step 1d: Create Service Principal",cmd:"az ad sp create --id <APP_ID_FROM_STEP_1b>",key:"azSP"},
              {label:"Step 1e: Assign Reader Role",cmd:"az role assignment create --assignee <APP_ID_FROM_STEP_1b> --role \"Reader\" --scope /subscriptions/<SUBSCRIPTION_ID>",key:"azRole"},
            ].map(step => (
              <div key={step.key} style={{marginBottom:10}}>
                <div style={{fontSize:11,fontWeight:700,color:"#0078D4",marginBottom:4}}>{step.label}</div>
                <div style={{background:"#0a0e17",borderRadius:8,border:`1px solid ${C.border}`,padding:10,position:"relative"}}>
                  <pre style={{margin:0,fontSize:10,color:C.green,fontFamily:"'Courier New',monospace",whiteSpace:"pre-wrap",wordBreak:"break-all"}}>{step.cmd}</pre>
                  <button onClick={() => copyText(step.cmd, step.key)} style={{position:"absolute",top:6,right:6,padding:"3px 8px",background:copied[step.key]?C.green:"#0078D4",color:"#fff",border:"none",borderRadius:5,fontSize:9,fontWeight:700,cursor:"pointer",fontFamily:"inherit"}}>{copied[step.key] ? "✓" : "Copy"}</button>
                </div>
              </div>
            ))}
          </Card>

          {/* Step 2: Enter Credentials & Scan */}
          <Card style={{marginTop:12}}>
            <div style={{marginBottom:16}}>
              <h3 style={{margin:"0 0 8px",fontSize:16,fontWeight:800,color:C.text,display:"flex",alignItems:"center",gap:6}}>
                <span style={{background:"#0078D4",color:"#fff",width:24,height:24,borderRadius:"50%",display:"inline-flex",alignItems:"center",justifyContent:"center",fontSize:12,fontWeight:800}}>2</span>
                Enter Credentials & Scan
              </h3>
              <p style={{color:C.textMuted,fontSize:12,margin:0}}>Enter your Azure Service Principal credentials below. Credentials are sent to your backend server — <strong style={{color:C.green}}>never stored anywhere</strong>.</p>
            </div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:12}}>
              <div>
                <label style={{fontSize:11,fontWeight:700,color:C.textMuted,marginBottom:4,display:"block"}}>Tenant ID (Directory ID)</label>
                <input value={azureCreds.tenantId} onChange={e => setAzureCreds(c => ({...c, tenantId: e.target.value.trim()}))} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" style={{width:"100%",padding:"10px 12px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,color:C.text,fontSize:12,fontFamily:"'Courier New',monospace",boxSizing:"border-box"}}/>
              </div>
              <div>
                <label style={{fontSize:11,fontWeight:700,color:C.textMuted,marginBottom:4,display:"block"}}>Client ID (Application ID)</label>
                <input value={azureCreds.clientId} onChange={e => setAzureCreds(c => ({...c, clientId: e.target.value.trim()}))} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" style={{width:"100%",padding:"10px 12px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,color:C.text,fontSize:12,fontFamily:"'Courier New',monospace",boxSizing:"border-box"}}/>
              </div>
            </div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:16}}>
              <div>
                <label style={{fontSize:11,fontWeight:700,color:C.textMuted,marginBottom:4,display:"block"}}>Client Secret</label>
                <input type="password" value={azureCreds.clientSecret} onChange={e => setAzureCreds(c => ({...c, clientSecret: e.target.value.trim()}))} placeholder="Enter client secret..." style={{width:"100%",padding:"10px 12px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,color:C.text,fontSize:12,fontFamily:"'Courier New',monospace",boxSizing:"border-box"}}/>
              </div>
              <div>
                <label style={{fontSize:11,fontWeight:700,color:C.textMuted,marginBottom:4,display:"block"}}>Subscription ID</label>
                <input value={azureCreds.subscriptionId} onChange={e => setAzureCreds(c => ({...c, subscriptionId: e.target.value.trim()}))} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" style={{width:"100%",padding:"10px 12px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,color:C.text,fontSize:12,fontFamily:"'Courier New',monospace",boxSizing:"border-box"}}/>
              </div>
            </div>
            {scanning && <div style={{marginBottom:16}}><div style={{display:"flex",justifyContent:"space-between",marginBottom:4}}><span style={{fontSize:11,color:C.textMuted}}>{scanProgress.msg}</span><span style={{fontSize:11,fontWeight:700,color:"#0078D4"}}>{scanProgress.pct}%</span></div><div style={{height:6,background:C.border,borderRadius:3,overflow:"hidden"}}><div style={{height:"100%",width:`${scanProgress.pct}%`,background:"#0078D4",borderRadius:3,transition:"width 0.3s"}}/></div></div>}
            <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
              <Btn variant="secondary" onClick={testConnection} disabled={scanning || !azureCreds.tenantId}>{connected.azure ? <><CheckCircle size={14} color={C.green}/> Connected ({connectedAccount.azure})</> : "Test Connection"}</Btn>
              <Btn onClick={handleLiveScan} disabled={scanning || !azureCreds.tenantId || !azureCreds.clientId || !azureCreds.clientSecret || !azureCreds.subscriptionId}>{scanning ? `Scanning (${scanProgress.pct}%)...` : <><Zap size={14}/> Run Full Scan (40 checks)</>}</Btn>
            </div>
            {connected.azure && !scanning && <div style={{marginTop:12,padding:10,background:`${C.green}10`,borderRadius:8,border:`1px solid ${C.green}33`,fontSize:12,color:C.green,display:"flex",alignItems:"center",gap:6}}><CheckCircle size={14}/> <strong>Connected</strong> to Azure subscription: {connectedAccount.azure}</div>}
          </Card>

          {/* Cleanup + Security Info */}
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginTop:12}}>
            <Card>
              <h4 style={{margin:"0 0 6px",fontSize:13,fontWeight:700,color:C.text}}>🧹 Cleanup (After Scanning)</h4>
              <p style={{color:C.textDim,fontSize:11,margin:"0 0 8px"}}>Remove the App Registration when done:</p>
              <div style={{background:"#0a0e17",borderRadius:8,border:`1px solid ${C.border}`,padding:10,position:"relative"}}>
                <pre style={{margin:0,fontSize:10,color:C.red,fontFamily:"'Courier New',monospace"}}>az ad app delete --id {"<APP_ID>"}</pre>
                <button onClick={() => copyText(AZ_SETUP_COMMANDS.cleanup,"azCleanup")} style={{position:"absolute",top:6,right:6,padding:"3px 8px",background:copied.azCleanup?C.green:"#0078D4",color:"#fff",border:"none",borderRadius:5,fontSize:9,fontWeight:700,cursor:"pointer",fontFamily:"inherit"}}>{copied.azCleanup ? "✓" : "Copy"}</button>
              </div>
            </Card>
            <Card>
              <h4 style={{margin:"0 0 6px",fontSize:13,fontWeight:700,color:C.text}}>📤 Upload JSON (Alternative)</h4>
              <p style={{color:C.textDim,fontSize:11,margin:"0 0 8px"}}>Or upload a JSON scan file:</p>
              <FileUploadBtn onFile={handleUpload} accept=".json" label="Upload scan.json"/>
              {latestScan && <span style={{display:"block",marginTop:6,fontSize:11,color:C.green}}>✅ Last scan: {new Date(latestScan.date).toLocaleDateString()}</span>}
            </Card>
          </div>

          <Card style={{marginTop:12}}>
            <h4 style={{margin:"0 0 8px",fontSize:13,fontWeight:700,color:C.text}}>🔒 Security & Permissions</h4>
            <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(200px,1fr))",gap:8}}>
              {[{name:"Reader Role",desc:"Read-only access to Azure subscription resources",icon:"🛡️"},{name:"Service Principal",desc:"App Registration with scoped Reader access only",icon:"👁️"},{name:"Server-Side Scan",desc:"Credentials sent to your backend API — never stored",icon:"🔐"},{name:"Azure CLI Setup",desc:"One-command setup and cleanup via Azure CLI",icon:"📦"}].map(p => (
                <div key={p.name} style={{background:C.bg,borderRadius:8,border:`1px solid ${C.border}`,padding:10}}>
                  <div style={{fontSize:11,fontWeight:700,color:"#0078D4"}}>{p.icon} {p.name}</div>
                  <div style={{fontSize:10,color:C.textDim,marginTop:2}}>{p.desc}</div>
                </div>
              ))}
            </div>
          </Card>
        </>)}
      </div>
    )}

    {/* EVIDENCE TAB */}
    {tab === "evidence" && (
      <div>
        <Card>
          <div style={{marginBottom:16}}>
            <h3 style={{margin:"0 0 8px",fontSize:16,fontWeight:800,color:C.text,display:"flex",alignItems:"center",gap:6}}><Zap size={18} color={C.orange}/> Push Evidence to Gap Assessment</h3>
            <p style={{color:C.textMuted,fontSize:12,margin:0}}>Cloud scan results will be pushed as evidence notes to the relevant Gap Assessment questions (C3–C7). This auto-fills responses and adds detailed check results.</p>
          </div>

          {!latestScan ? (
            <div style={{textAlign:"center",padding:24,color:C.textDim,fontSize:13}}>Run a scan first to push evidence to Gap Assessment.</div>
          ) : (<>
            <div style={{display:"grid",gap:10,marginBottom:16}}>
              {Object.entries(GAP_MAP).map(([qId, {name, checks: checkIds}]) => {
                const statuses = checkIds.map(id => ({id, name: (CHECKS.find(c => c.id === id)||{}).name, status: getStatus(id)}));
                const passCount = statuses.filter(s => s.status === "PASS").length;
                const failCount = statuses.filter(s => s.status === "FAIL").length;
                const pct = Math.round((passCount / statuses.length) * 100);
                const gapResp = (data.gapResponses || {})[qId] || {};
                const isLinked = gapResp.cloudScanLinked;
                return (
                  <div key={qId} style={{background:C.bg,borderRadius:10,border:`1px solid ${isLinked ? C.green : C.border}44`,padding:14}}>
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
                      <div>
                        <span style={{fontSize:13,fontWeight:800,color:C.orange,marginRight:8}}>{qId}</span>
                        <span style={{fontSize:13,fontWeight:600,color:C.text}}>{name}</span>
                        {isLinked && <span style={{marginLeft:8,fontSize:10,color:C.green,fontWeight:700,background:`${C.green}22`,padding:"2px 6px",borderRadius:4}}>✅ Linked</span>}
                      </div>
                      <span style={{fontSize:14,fontWeight:800,color:pct === 100 ? C.green : pct >= 50 ? C.yellow : C.red}}>{pct}%</span>
                    </div>
                    <div style={{height:4,background:C.border,borderRadius:2,overflow:"hidden",marginBottom:8}}>
                      <div style={{height:"100%",width:`${pct}%`,background:pct === 100 ? C.green : pct >= 50 ? C.yellow : C.red,borderRadius:2}}/>
                    </div>
                    <div style={{display:"flex",flexWrap:"wrap",gap:4}}>
                      {statuses.map(s => {
                        const ss = statusStyle(s.status);
                        return <span key={s.id} title={s.name} style={{fontSize:9,padding:"2px 6px",borderRadius:4,background:ss.bg,color:ss.color,fontWeight:600,border:`1px solid ${ss.border}`}}>{ss.icon} {s.name?.slice(0,25)}</span>;
                      })}
                    </div>
                  </div>
                );
              })}
            </div>

            {canManage && <Btn onClick={pushToGap} style={{width:"100%"}}><Zap size={14}/> Push All Evidence to Gap Assessment (C3–C7)</Btn>}
            {!canManage && <p style={{color:C.textDim,fontSize:12,textAlign:"center"}}>Only SecComply staff or Client Admins can push evidence.</p>}
          </>)}
        </Card>

        {latestScan && <Card style={{marginTop:12}}>
          <h4 style={{margin:"0 0 10px",fontSize:13,fontWeight:700,color:C.text}}>Scan History</h4>
          <div style={{overflow:"auto",maxHeight:200}}>
            <table style={{width:"100%",borderCollapse:"collapse",fontSize:11}}>
              <thead><tr style={{borderBottom:`1px solid ${C.border}`}}>
                <th style={{padding:"6px 10px",textAlign:"left",color:C.textDim}}>Date</th>
                <th style={{padding:"6px 10px",textAlign:"left",color:C.textDim}}>Provider</th>
                <th style={{padding:"6px 10px",textAlign:"left",color:C.textDim}}>Account</th>
                <th style={{padding:"6px 10px",textAlign:"left",color:C.textDim}}>Scanned By</th>
                <th style={{padding:"6px 10px",textAlign:"center",color:C.textDim}}>Pass</th>
                <th style={{padding:"6px 10px",textAlign:"center",color:C.textDim}}>Fail</th>
              </tr></thead>
              <tbody>{scans.slice().reverse().map(s => {
                const p = Object.values(s.results || {}).filter(v => v === "PASS").length;
                const f = Object.values(s.results || {}).filter(v => v === "FAIL").length;
                return (<tr key={s.id} style={{borderBottom:`1px solid ${C.border}22`}}>
                  <td style={{padding:"5px 10px",color:C.text}}>{new Date(s.date).toLocaleDateString()}</td>
                  <td style={{padding:"5px 10px",color:C.text}}>🔶 AWS</td>
                  <td style={{padding:"5px 10px",color:C.orange,fontWeight:600}}>{s.account}</td>
                  <td style={{padding:"5px 10px",color:C.textMuted}}>{s.scannedBy}</td>
                  <td style={{padding:"5px 10px",textAlign:"center",color:C.green,fontWeight:700}}>{p}</td>
                  <td style={{padding:"5px 10px",textAlign:"center",color:C.red,fontWeight:700}}>{f}</td>
                </tr>);
              })}</tbody>
            </table>
          </div>
        </Card>}
      </div>
    )}
  </div>);
};

// =============================================
// GITHUB SECURITY CHECKS (40+ checks mapped to ISO 27001)
// =============================================
const GITHUB_CHECKS = [
  // Repository Security
  {id:"gh_repo_01",cat:"Repository",name:"Branch protection enabled on default branch",iso:"A.8.9",sev:"CRITICAL",gapQ:"C8"},
  {id:"gh_repo_02",cat:"Repository",name:"Require pull request reviews before merging",iso:"A.8.25",sev:"CRITICAL",gapQ:"C8"},
  {id:"gh_repo_03",cat:"Repository",name:"Dismiss stale PR reviews on new commits",iso:"A.8.25",sev:"HIGH",gapQ:"C8"},
  {id:"gh_repo_04",cat:"Repository",name:"Require status checks before merging",iso:"A.8.25",sev:"HIGH",gapQ:"C8"},
  {id:"gh_repo_05",cat:"Repository",name:"Require signed commits",iso:"A.8.26",sev:"MEDIUM",gapQ:"C8"},
  {id:"gh_repo_06",cat:"Repository",name:"Force push disabled on protected branches",iso:"A.8.9",sev:"HIGH",gapQ:"C8"},
  {id:"gh_repo_07",cat:"Repository",name:"Branch deletion disabled on protected branches",iso:"A.8.9",sev:"MEDIUM",gapQ:"C8"},
  {id:"gh_repo_08",cat:"Repository",name:"CODEOWNERS file present",iso:"A.5.2",sev:"MEDIUM",gapQ:"C8"},
  {id:"gh_repo_09",cat:"Repository",name:"Default branch is not directly pushable by admins",iso:"A.8.25",sev:"MEDIUM",gapQ:"C8"},
  {id:"gh_repo_10",cat:"Repository",name:"Require conversation resolution before merging",iso:"A.8.25",sev:"LOW",gapQ:"C8"},
  // Access Management
  {id:"gh_access_01",cat:"Access",name:"Two-factor authentication required for org",iso:"A.8.5",sev:"CRITICAL",gapQ:"C7"},
  {id:"gh_access_02",cat:"Access",name:"SSO enforced for organization",iso:"A.5.16",sev:"HIGH",gapQ:"C7"},
  {id:"gh_access_03",cat:"Access",name:"No outside collaborators with admin access",iso:"A.5.15",sev:"HIGH",gapQ:"C7"},
  {id:"gh_access_04",cat:"Access",name:"Team-based permissions (least privilege)",iso:"A.8.3",sev:"HIGH",gapQ:"C7"},
  {id:"gh_access_05",cat:"Access",name:"Deploy keys audited and minimal",iso:"A.5.17",sev:"MEDIUM",gapQ:"C7"},
  {id:"gh_access_06",cat:"Access",name:"Personal access tokens scoped and rotated",iso:"A.5.17",sev:"HIGH",gapQ:"C7"},
  {id:"gh_access_07",cat:"Access",name:"No stale member accounts (inactive >90d)",iso:"A.5.18",sev:"MEDIUM",gapQ:"C7"},
  {id:"gh_access_08",cat:"Access",name:"Repository creation restricted to admins",iso:"A.8.3",sev:"MEDIUM",gapQ:"C7"},
  // Code Security
  {id:"gh_code_01",cat:"Code Security",name:"Dependabot alerts enabled",iso:"A.8.8",sev:"CRITICAL",gapQ:"C9"},
  {id:"gh_code_02",cat:"Code Security",name:"Dependabot security updates enabled",iso:"A.8.8",sev:"HIGH",gapQ:"C9"},
  {id:"gh_code_03",cat:"Code Security",name:"Secret scanning enabled",iso:"A.5.33",sev:"CRITICAL",gapQ:"C9"},
  {id:"gh_code_04",cat:"Code Security",name:"Push protection for secrets enabled",iso:"A.5.33",sev:"CRITICAL",gapQ:"C9"},
  {id:"gh_code_05",cat:"Code Security",name:"Code scanning (CodeQL) enabled",iso:"A.8.28",sev:"HIGH",gapQ:"C9"},
  {id:"gh_code_06",cat:"Code Security",name:"No critical/high Dependabot alerts open >30d",iso:"A.8.8",sev:"HIGH",gapQ:"C9"},
  {id:"gh_code_07",cat:"Code Security",name:"No exposed secrets detected in repos",iso:"A.5.33",sev:"CRITICAL",gapQ:"C9"},
  {id:"gh_code_08",cat:"Code Security",name:"Security policy (SECURITY.md) present",iso:"A.5.1",sev:"MEDIUM",gapQ:"C9"},
  // Supply Chain
  {id:"gh_supply_01",cat:"Supply Chain",name:"Dependency review enabled on PRs",iso:"A.5.19",sev:"HIGH",gapQ:"C10"},
  {id:"gh_supply_02",cat:"Supply Chain",name:"GitHub Actions permissions restricted",iso:"A.8.9",sev:"HIGH",gapQ:"C10"},
  {id:"gh_supply_03",cat:"Supply Chain",name:"Third-party actions pinned to SHA",iso:"A.5.19",sev:"HIGH",gapQ:"C10"},
  {id:"gh_supply_04",cat:"Supply Chain",name:"Workflow approvals required for external contributors",iso:"A.5.20",sev:"MEDIUM",gapQ:"C10"},
  {id:"gh_supply_05",cat:"Supply Chain",name:"GITHUB_TOKEN permissions set to read-only default",iso:"A.8.3",sev:"HIGH",gapQ:"C10"},
  {id:"gh_supply_06",cat:"Supply Chain",name:"Artifact attestation / provenance enabled",iso:"A.5.20",sev:"MEDIUM",gapQ:"C10"},
  // Audit & Compliance
  {id:"gh_audit_01",cat:"Audit",name:"Audit log enabled and accessible",iso:"A.8.15",sev:"HIGH",gapQ:"C3"},
  {id:"gh_audit_02",cat:"Audit",name:"Audit log streaming configured",iso:"A.8.15",sev:"MEDIUM",gapQ:"C3"},
  {id:"gh_audit_03",cat:"Audit",name:"IP allow list configured",iso:"A.8.20",sev:"MEDIUM",gapQ:"C3"},
  {id:"gh_audit_04",cat:"Audit",name:"Webhook secrets configured",iso:"A.8.24",sev:"HIGH",gapQ:"C3"},
  {id:"gh_audit_05",cat:"Audit",name:"Repository visibility controls enforced",iso:"A.5.12",sev:"HIGH",gapQ:"C3"},
  // Secrets & Environment
  {id:"gh_env_01",cat:"Environments",name:"Environment protection rules configured",iso:"A.8.31",sev:"HIGH",gapQ:"C10"},
  {id:"gh_env_02",cat:"Environments",name:"Required reviewers for production deployments",iso:"A.8.25",sev:"HIGH",gapQ:"C10"},
  {id:"gh_env_03",cat:"Environments",name:"Encrypted secrets used (no hardcoded credentials)",iso:"A.8.24",sev:"CRITICAL",gapQ:"C10"},
  {id:"gh_env_04",cat:"Environments",name:"Environment-scoped secrets (not repo-wide)",iso:"A.8.31",sev:"MEDIUM",gapQ:"C10"},
];

const GITHUB_CATS = [...new Set(GITHUB_CHECKS.map(c => c.cat))];

const GITHUB_GAP_MAP = {
  C3:{name:"Audit & Logging",checks:["gh_audit_01","gh_audit_02","gh_audit_03","gh_audit_04","gh_audit_05"]},
  C7:{name:"Access Management",checks:["gh_access_01","gh_access_02","gh_access_03","gh_access_04","gh_access_05","gh_access_06","gh_access_07","gh_access_08"]},
  C8:{name:"Repository Security",checks:["gh_repo_01","gh_repo_02","gh_repo_03","gh_repo_04","gh_repo_05","gh_repo_06","gh_repo_07","gh_repo_08","gh_repo_09","gh_repo_10"]},
  C9:{name:"Code Security",checks:["gh_code_01","gh_code_02","gh_code_03","gh_code_04","gh_code_05","gh_code_06","gh_code_07","gh_code_08"]},
  C10:{name:"Supply Chain & Environments",checks:["gh_supply_01","gh_supply_02","gh_supply_03","gh_supply_04","gh_supply_05","gh_supply_06","gh_env_01","gh_env_02","gh_env_03","gh_env_04"]},
};

// Parse GitHub API scan results into check statuses
const parseGithubScan = (raw) => {
  const results = {};
  try {
    const d = typeof raw === "string" ? JSON.parse(raw) : raw;
    const meta = d._meta || {};
    const org = d.org || {};
    const repos = d.repos || [];
    const hasRepos = repos.length > 0;

    // Access Management checks
    results.gh_access_01 = org.two_factor_requirement_enabled ? "PASS" : "FAIL";
    results.gh_access_02 = org.sso_enabled ? "PASS" : (org.plan?.name === "enterprise" ? "FAIL" : "N/A");
    results.gh_access_03 = "MANUAL";
    results.gh_access_04 = "MANUAL";
    results.gh_access_05 = "MANUAL";
    results.gh_access_06 = "MANUAL";
    results.gh_access_07 = "MANUAL";
    results.gh_access_08 = org.members_can_create_repositories === false ? "PASS" : (org.members_can_create_repositories === true ? "WARN" : "MANUAL");

    // Repository Security (check across all repos)
    if (hasRepos) {
      const branchProtection = repos.map(r => r.branch_protection || {});
      const allProtected = branchProtection.every(bp => bp.enabled);
      const anyProtected = branchProtection.some(bp => bp.enabled);
      results.gh_repo_01 = allProtected ? "PASS" : anyProtected ? "WARN" : "FAIL";
      results.gh_repo_02 = branchProtection.every(bp => bp.required_pull_request_reviews?.enabled) ? "PASS" :
        branchProtection.some(bp => bp.required_pull_request_reviews?.enabled) ? "WARN" : "FAIL";
      results.gh_repo_03 = branchProtection.every(bp => bp.required_pull_request_reviews?.dismiss_stale_reviews) ? "PASS" : "WARN";
      results.gh_repo_04 = branchProtection.every(bp => bp.required_status_checks?.strict) ? "PASS" :
        branchProtection.some(bp => bp.required_status_checks?.enabled) ? "WARN" : "FAIL";
      results.gh_repo_05 = branchProtection.every(bp => bp.required_signatures) ? "PASS" : "WARN";
      results.gh_repo_06 = branchProtection.every(bp => !bp.allow_force_pushes) ? "PASS" : "FAIL";
      results.gh_repo_07 = branchProtection.every(bp => !bp.allow_deletions) ? "PASS" : "WARN";
      results.gh_repo_08 = repos.every(r => r.has_codeowners) ? "PASS" : repos.some(r => r.has_codeowners) ? "WARN" : "FAIL";
      results.gh_repo_09 = branchProtection.every(bp => !bp.enforce_admins?.enabled === false) ? "WARN" :
        branchProtection.every(bp => bp.enforce_admins?.enabled) ? "PASS" : "WARN";
      results.gh_repo_10 = branchProtection.every(bp => bp.required_conversation_resolution) ? "PASS" : "MANUAL";

      // Code Security
      results.gh_code_01 = repos.every(r => r.security?.dependabot_alerts) ? "PASS" : repos.some(r => r.security?.dependabot_alerts) ? "WARN" : "FAIL";
      results.gh_code_02 = repos.every(r => r.security?.dependabot_updates) ? "PASS" : repos.some(r => r.security?.dependabot_updates) ? "WARN" : "FAIL";
      results.gh_code_03 = repos.every(r => r.security?.secret_scanning) ? "PASS" : repos.some(r => r.security?.secret_scanning) ? "WARN" : "FAIL";
      results.gh_code_04 = repos.every(r => r.security?.secret_push_protection) ? "PASS" : repos.some(r => r.security?.secret_push_protection) ? "WARN" : "FAIL";
      results.gh_code_05 = repos.every(r => r.security?.code_scanning) ? "PASS" : repos.some(r => r.security?.code_scanning) ? "WARN" : "FAIL";
      results.gh_code_06 = d.alerts?.critical_high_open_30d === 0 ? "PASS" : d.alerts?.critical_high_open_30d > 0 ? "FAIL" : "MANUAL";
      results.gh_code_07 = d.alerts?.exposed_secrets === 0 ? "PASS" : d.alerts?.exposed_secrets > 0 ? "FAIL" : "MANUAL";
      results.gh_code_08 = repos.every(r => r.has_security_md) ? "PASS" : repos.some(r => r.has_security_md) ? "WARN" : "FAIL";

      // Supply Chain
      results.gh_supply_01 = repos.every(r => r.security?.dependency_review) ? "PASS" : "MANUAL";
      results.gh_supply_02 = org.actions_permissions === "selected" || org.actions_permissions === "local_only" ? "PASS" : org.actions_permissions === "all" ? "WARN" : "MANUAL";
      results.gh_supply_03 = "MANUAL";
      results.gh_supply_04 = org.actions_workflow_approvals ? "PASS" : "MANUAL";
      results.gh_supply_05 = org.default_workflow_permissions === "read" ? "PASS" : "FAIL";
      results.gh_supply_06 = "MANUAL";

      // Environments
      results.gh_env_01 = repos.some(r => r.environments?.some(e => e.protection_rules?.length > 0)) ? "PASS" : "MANUAL";
      results.gh_env_02 = repos.some(r => r.environments?.some(e => e.reviewers?.length > 0)) ? "PASS" : "MANUAL";
      results.gh_env_03 = d.hardcoded_secrets_found === false ? "PASS" : d.hardcoded_secrets_found === true ? "FAIL" : "MANUAL";
      results.gh_env_04 = "MANUAL";
    } else {
      // No repos scanned – all MANUAL
      GITHUB_CHECKS.filter(c => c.cat !== "Access" && c.cat !== "Audit").forEach(c => { results[c.id] = "MANUAL"; });
    }

    // Audit checks
    results.gh_audit_01 = org.plan?.name === "enterprise" || org.plan?.name === "team" ? "PASS" : "WARN";
    results.gh_audit_02 = d.audit_log_streaming ? "PASS" : "MANUAL";
    results.gh_audit_03 = org.ip_allow_list_enabled ? "PASS" : "MANUAL";
    results.gh_audit_04 = "MANUAL";
    results.gh_audit_05 = org.members_can_create_public_repositories === false ? "PASS" : "WARN";

    return { results, meta, raw: d };
  } catch (e) {
    console.error("GitHub parse error:", e);
    return { results, meta: {}, raw: null, error: e.message };
  }
};

// =============================================
// GITHUB INTEGRATION MODULE
// =============================================
const GitHubIntegration = ({data, setData, role: userRole}) => {
  const [toast, setToast] = useState(null);
  const [tab, setTab] = useState("dashboard");
  const [expandCat, setExpandCat] = useState(null);
  const [filterSev, setFilterSev] = useState("ALL");
  const [filterStatus, setFilterStatus] = useState("ALL");
  const [ghToken, setGhToken] = useState("");
  const [ghOrg, setGhOrg] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState({pct:0, msg:""});
  const [connected, setConnected] = useState(false);
  const [connectedOrg, setConnectedOrg] = useState("");
  const [showToken, setShowToken] = useState(false);
  const [selectedRepos, setSelectedRepos] = useState([]);
  const [availableRepos, setAvailableRepos] = useState([]);
  const [repoSearch, setRepoSearch] = useState("");
  const [showManualModal, setShowManualModal] = useState(null);
  const canManage = canEdit(userRole || "client_user", "github");
  const {user} = useAuth();

  const CHECKS = GITHUB_CHECKS;
  const CATS = GITHUB_CATS;
  const GAP_MAP = GITHUB_GAP_MAP;

  const scans = (data.githubScans || []);
  const latestScan = scans.length > 0 ? scans[scans.length - 1] : null;
  const checkResults = latestScan?.results || {};
  const overrides = latestScan?.overrides || {};

  const getStatus = (id) => overrides[id] || checkResults[id] || "NOT_RUN";

  // ---- Test GitHub Connection ----
  // GitHub API helper — GitHub fully supports CORS for authenticated requests
  const ghFetch = async (url) => {
    const r = await fetch(url, { headers: { "Authorization": `token ${ghToken}`, "Accept": "application/vnd.github.v3+json" } });
    return { ok: r.ok, status: r.status, data: r.ok ? await r.json().catch(() => null) : null };
  };

  const testGithubConnection = async () => {
    if (!ghToken) { setToast({msg:"Enter a GitHub Personal Access Token",type:"error"}); return; }
    try {
      setScanning(true); setScanProgress({pct:10,msg:"Testing GitHub connection..."});

      // 1. Verify token
      const userResp = await ghFetch("https://api.github.com/user");
      if (!userResp.ok) throw new Error("Invalid token or insufficient permissions. Check scopes: repo, read:org");
      const ghUser = userResp.data;
      setScanProgress({pct:30,msg:"Token verified..."});

      // 2. Check org if provided
      let orgLogin = ghUser.login;
      if (ghOrg) {
        const orgResp = await ghFetch(`https://api.github.com/orgs/${encodeURIComponent(ghOrg)}`);
        if (!orgResp.ok) throw new Error(`Cannot access organization "${ghOrg}" — check org name and token permissions`);
        orgLogin = orgResp.data.login;
      }
      setConnectedOrg(orgLogin);
      setScanProgress({pct:50,msg:"Fetching repositories..."});

      // 3. Fetch repos
      const repoUrl = ghOrg
        ? `https://api.github.com/orgs/${encodeURIComponent(ghOrg)}/repos?per_page=100&sort=updated`
        : "https://api.github.com/user/repos?per_page=100&sort=updated&affiliation=owner,organization_member";
      const repoResp = await ghFetch(repoUrl);
      const repos = (repoResp.ok && Array.isArray(repoResp.data)) ? repoResp.data : [];
      setAvailableRepos(repos.map(r => ({name: r.full_name, private: r.private, default_branch: r.default_branch, language: r.language, archived: r.archived})));
      setSelectedRepos(repos.filter(r => !r.archived).slice(0, 10).map(r => r.full_name));

      setConnected(true);
      setToast({msg:`Connected as ${ghUser.login}${ghOrg ? ` to org ${ghOrg}` : ""} — ${repos.length} repos found`,type:"success"});
    } catch(e) {
      setConnected(false); setConnectedOrg("");
      setToast({msg:`GitHub connection failed: ${e.message}`,type:"error"});
    } finally { setScanning(false); }
  };

  // ---- Full GitHub Scan (direct API) ----
  const handleGithubScan = async () => {
    if (!ghToken) { setToast({msg:"Enter a GitHub token first",type:"error"}); return; }
    const reposToScan = selectedRepos.length > 0 ? selectedRepos : [];
    if (reposToScan.length === 0) { setToast({msg:"Select at least one repository to scan",type:"error"}); return; }

    try {
      setScanning(true);
      const scanData = {org: {}, repos: [], alerts: {exposed_secrets:0, critical_high_open_30d:0}, _meta: {scannedAt: new Date().toISOString()}};
      const totalRepos = reposToScan.length;

      // ---- Org settings ----
      setScanProgress({pct:5,msg:"Scanning organization settings..."});
      if (ghOrg) {
        const orgResp = await ghFetch(`https://api.github.com/orgs/${encodeURIComponent(ghOrg)}`);
        if (orgResp.ok && orgResp.data) {
          const o = orgResp.data;
          scanData.org = { login:o.login, name:o.name, two_factor_requirement_enabled:o.two_factor_requirement_enabled||false, members_can_create_repositories:o.members_can_create_repositories, members_can_create_public_repositories:o.members_can_create_public_repositories, plan:o.plan };
          const actResp = await ghFetch(`https://api.github.com/orgs/${encodeURIComponent(ghOrg)}/actions/permissions`);
          if (actResp.ok && actResp.data) {
            scanData.org.actions_permissions = actResp.data.enabled_repositories;
            scanData.org.default_workflow_permissions = actResp.data.default_workflow_permissions;
            scanData.org.actions_workflow_approvals = actResp.data.can_approve_pull_request_reviews;
          }
        }
      }

      // ---- Scan each repo ----
      for (let i = 0; i < totalRepos; i++) {
        const repoName = reposToScan[i];
        const pct = 10 + Math.round((i / totalRepos) * 80);
        setScanProgress({pct, msg:`Scanning ${repoName.split("/").pop()} (${i+1}/${totalRepos})...`});

        const rd = {name:repoName, branch_protection:{enabled:false}, security:{}, has_codeowners:false, has_security_md:false, environments:[]};

        try {
          const repo = await ghFetch(`https://api.github.com/repos/${repoName}`);
          if (!repo.ok || !repo.data) { scanData.repos.push(rd); continue; }
          rd.default_branch = repo.data.default_branch;
          rd.private = repo.data.private;
          rd.visibility = repo.data.visibility;

          // Branch protection
          const bp = await ghFetch(`https://api.github.com/repos/${repoName}/branches/${encodeURIComponent(repo.data.default_branch)}/protection`);
          if (bp.ok && bp.data && !bp.data.message) {
            const b = bp.data;
            rd.branch_protection = {
              enabled: true,
              required_pull_request_reviews: b.required_pull_request_reviews ? {enabled:true, dismiss_stale_reviews:b.required_pull_request_reviews.dismiss_stale_reviews||false} : {enabled:false},
              required_status_checks: b.required_status_checks ? {enabled:true, strict:b.required_status_checks.strict||false} : {enabled:false},
              required_signatures: b.required_signatures?.enabled || false,
              enforce_admins: b.enforce_admins || {enabled:false},
              allow_force_pushes: b.allow_force_pushes?.enabled || false,
              allow_deletions: b.allow_deletions?.enabled || false,
              required_conversation_resolution: b.required_conversation_resolution?.enabled || false,
            };
          }

          // CODEOWNERS
          let coResp = await ghFetch(`https://api.github.com/repos/${repoName}/contents/CODEOWNERS`);
          if (!coResp.ok) coResp = await ghFetch(`https://api.github.com/repos/${repoName}/contents/.github/CODEOWNERS`);
          rd.has_codeowners = coResp.ok;

          // SECURITY.md
          let secResp = await ghFetch(`https://api.github.com/repos/${repoName}/contents/SECURITY.md`);
          if (!secResp.ok) secResp = await ghFetch(`https://api.github.com/repos/${repoName}/contents/.github/SECURITY.md`);
          rd.has_security_md = secResp.ok;

          // Dependabot vulnerability alerts
          const vulnResp = await fetch(`https://api.github.com/repos/${repoName}/vulnerability-alerts`, {
            headers: {"Authorization":`token ${ghToken}`,"Accept":"application/vnd.github.dorian-preview+json"},
          });
          rd.security.dependabot_alerts = vulnResp.status === 204;

          // Secret scanning alerts
          const ssResp = await ghFetch(`https://api.github.com/repos/${repoName}/secret-scanning/alerts?per_page=5&state=open`);
          if (ssResp.status === 404) { rd.security.secret_scanning = false; rd.security.secret_push_protection = false; }
          else { rd.security.secret_scanning = true; rd.security.secret_push_protection = true; if (Array.isArray(ssResp.data)) scanData.alerts.exposed_secrets += ssResp.data.length; }

          // Code scanning
          const csResp = await ghFetch(`https://api.github.com/repos/${repoName}/code-scanning/alerts?per_page=1`);
          rd.security.code_scanning = csResp.status !== 404;

          // Dependabot alerts (critical/high > 30 days)
          const daResp = await ghFetch(`https://api.github.com/repos/${repoName}/dependabot/alerts?state=open&severity=critical,high&per_page=20`);
          if (daResp.ok && Array.isArray(daResp.data)) {
            const cutoff = new Date(Date.now() - 30*86400000).toISOString();
            scanData.alerts.critical_high_open_30d += daResp.data.filter(a => a.created_at < cutoff).length;
          }

          // Environments
          const envResp = await ghFetch(`https://api.github.com/repos/${repoName}/environments`);
          if (envResp.ok && envResp.data?.environments) {
            rd.environments = envResp.data.environments.map(e => ({name:e.name, protection_rules:e.protection_rules||[], reviewers:(e.protection_rules||[]).filter(r=>r.type==="required_reviewers")}));
          }
        } catch(repoErr) { /* skip */ }

        scanData.repos.push(rd);
      }

      // Parse results
      setScanProgress({pct:95,msg:"Analyzing results..."});
      const parsed = parseGithubScan(scanData);
      setScanProgress({pct:100,msg:"Scan complete!"});

      const scan = {
        id:`ghscan_${Date.now()}`, date:new Date().toISOString(),
        org: connectedOrg || ghOrg || "personal", repoCount:totalRepos,
        results:parsed.results, overrides:{}, scannedBy:user?.email||"unknown",
        scanType:"live", rawData:scanData,
      };
      setData(d => ({...d, githubScans: [...(d.githubScans || []), scan]}));

      const passCount = Object.values(parsed.results).filter(v => v === "PASS").length;
      const failCount = Object.values(parsed.results).filter(v => v === "FAIL").length;
      setToast({msg:`GitHub scan complete! ${passCount} passed, ${failCount} failed across ${totalRepos} repos.`,type:"success"});
      setTab("checks");
    } catch(e) {
      setToast({msg:`GitHub scan failed: ${e.message}`,type:"error"});
    } finally { setScanning(false); }
  };

  // Manual upload of scan results (JSON)
  const handleUpload = (file) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const parsed = parseGithubScan(e.target.result);
        if (parsed.error) { setToast({msg:"Parse error: " + parsed.error,type:"error"}); return; }
        const scan = {
          id:`ghscan_${Date.now()}`, date: new Date().toISOString(),
          org: parsed.raw?.org?.login || "Unknown", repoCount: parsed.raw?.repos?.length || 0,
          results: parsed.results, overrides: {}, scannedBy: user?.email || "unknown", scanType: "upload",
        };
        setData(d => ({...d, githubScans: [...(d.githubScans || []), scan]}));
        setToast({msg:`GitHub scan imported!`,type:"success"});
        setTab("checks");
      } catch(err) { setToast({msg:"Invalid JSON file: " + err.message,type:"error"}); }
    };
    reader.readAsText(file);
  };

  // Override check status
  const setOverride = (checkId, status) => {
    if (!latestScan) return;
    const scanIdx = (data.githubScans||[]).findIndex(s => s.id === latestScan.id);
    if (scanIdx < 0) return;
    setData(d => ({...d, githubScans: d.githubScans.map((s, i) => i === scanIdx ? {...s, overrides: {...(s.overrides || {}), [checkId]: status}} : s)}));
  };

  const clearOverride = (checkId) => {
    if (!latestScan) return;
    const scanIdx = (data.githubScans||[]).findIndex(s => s.id === latestScan.id);
    if (scanIdx < 0) return;
    setData(d => ({...d, githubScans: d.githubScans.map((s, i) => {
      if (i !== scanIdx) return s;
      const ov = {...(s.overrides || {})}; delete ov[checkId]; return {...s, overrides: ov};
    })}));
  };

  // Push evidence to gap assessment
  const pushToGap = () => {
    const updates = {};
    Object.entries(GAP_MAP).forEach(([qId, {name, checks: checkIds}]) => {
      const statuses = checkIds.map(id => ({id, name: (CHECKS.find(c => c.id === id)||{}).name, status: getStatus(id)}));
      const pass = statuses.filter(s => s.status === "PASS").length;
      const fail = statuses.filter(s => s.status === "FAIL").length;
      const total = statuses.length;
      const pct = Math.round((pass / total) * 100);
      const summary = `[GitHub Scan ${new Date().toLocaleDateString()}] ${name}: ${pass}/${total} passed (${pct}%)\n` +
        statuses.map(s => `${s.status === "PASS" ? "✅" : s.status === "FAIL" ? "❌" : s.status === "WARN" ? "⚠️" : "⬜"} ${s.name}`).join("\n");
      const existing = (data.gapResponses || {})[qId] || {};
      const autoResp = fail === 0 && pass === total ? "Yes" : pass === 0 ? "No" : "Partial";
      updates[qId] = {
        ...existing,
        resp: existing.resp || autoResp,
        notes: (existing.notes ? existing.notes + "\n\n" : "") + summary,
        driveLink: existing.driveLink || "",
        githubScanLinked: true,
        githubScanDate: new Date().toISOString(),
      };
    });
    setData(d => ({...d, gapResponses: {...(d.gapResponses || {}), ...updates}}));
    setToast({msg:"GitHub evidence pushed to Gap Assessment!",type:"success"});
  };

  // Stats
  const pass = CHECKS.filter(c => getStatus(c.id) === "PASS").length;
  const fail = CHECKS.filter(c => getStatus(c.id) === "FAIL").length;
  const warn = CHECKS.filter(c => getStatus(c.id) === "WARN").length;
  const manual = CHECKS.filter(c => getStatus(c.id) === "MANUAL").length;
  const na = CHECKS.filter(c => getStatus(c.id) === "N/A").length;
  const notRun = CHECKS.filter(c => getStatus(c.id) === "NOT_RUN").length;
  const scorePct = latestScan ? Math.round((pass / (CHECKS.length - na)) * 100) || 0 : 0;

  const catStats = CATS.map(cat => {
    const checks = CHECKS.filter(c => c.cat === cat);
    return {cat, total: checks.length, pass: checks.filter(c => getStatus(c.id) === "PASS").length, fail: checks.filter(c => getStatus(c.id) === "FAIL").length, warn: checks.filter(c => getStatus(c.id) === "WARN" || getStatus(c.id) === "MANUAL").length};
  });

  const filteredChecks = CHECKS.filter(c => {
    if (filterSev !== "ALL" && c.sev !== filterSev) return false;
    if (filterStatus !== "ALL" && getStatus(c.id) !== filterStatus) return false;
    return true;
  });

  const statusStyle = (st) => {
    const map = {PASS:{bg:`${C.green}15`,border:`${C.green}44`,color:C.green,label:"PASS",icon:"✅"},FAIL:{bg:`${C.red}15`,border:`${C.red}44`,color:C.red,label:"FAIL",icon:"❌"},WARN:{bg:`${C.yellow}15`,border:`${C.yellow}44`,color:C.yellow,label:"WARN",icon:"⚠️"},MANUAL:{bg:`${C.blue}15`,border:`${C.blue}44`,color:C.blue,label:"MANUAL",icon:"🔍"},"N/A":{bg:`${C.textDim}15`,border:`${C.textDim}44`,color:C.textDim,label:"N/A",icon:"➖"},NOT_RUN:{bg:`${C.textDim}10`,border:`${C.border}`,color:C.textDim,label:"—",icon:"⬜"},LOW:{bg:`${C.textDim}15`,border:`${C.textDim}44`,color:C.textDim,label:"LOW",icon:"ℹ️"}};
    return map[st] || map.NOT_RUN;
  };

  const ghColor = "#8B5CF6";
  const TABS = [{id:"dashboard",label:"Dashboard",icon:LayoutDashboard},{id:"checks",label:"Security Checks",icon:ShieldCheck},{id:"connect",label:"Connect GitHub",icon:({size})=><GithubIcon size={size}/>},{id:"evidence",label:"Gap Evidence",icon:ClipboardCheck}];

  const filteredRepos = availableRepos.filter(r => !r.archived && r.name.toLowerCase().includes(repoSearch.toLowerCase()));

  return (<div>
    {toast && <Toast {...toast} onClose={() => setToast(null)}/>}

    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20}}>
      <div>
        <h2 style={{margin:0,fontSize:22,fontWeight:800,color:C.text,display:"flex",alignItems:"center",gap:10}}><GithubIcon size={24} color={ghColor}/> GitHub Security</h2>
        <p style={{color:C.textMuted,margin:"4px 0 0",fontSize:13}}>Repository & organization security posture mapped to ISO 27001 controls</p>
      </div>
      <div style={{display:"flex",gap:8,alignItems:"center"}}>
        {connected && <span style={{fontSize:11,color:C.green,fontWeight:700,display:"flex",alignItems:"center",gap:4,background:`${C.green}15`,padding:"4px 10px",borderRadius:6,border:`1px solid ${C.green}33`}}><CheckCircle size={12}/> {connectedOrg}</span>}
        {!connected && latestScan && <span style={{fontSize:11,color:C.green,fontWeight:700,display:"flex",alignItems:"center",gap:4,background:`${C.green}15`,padding:"4px 10px",borderRadius:6,border:`1px solid ${C.green}33`}}><CheckCircle size={12}/> {latestScan.org}</span>}
        {canManage && connected && <Btn onClick={handleGithubScan} disabled={scanning}>{scanning ? <><Loader size={14} style={{animation:"spin 1s linear infinite"}}/> Scanning...</> : <><Zap size={14}/> Scan</>}</Btn>}
        {canManage && !connected && <Btn onClick={() => setTab("connect")}><GithubIcon size={14} color="#fff"/> Connect GitHub</Btn>}
      </div>
    </div>

    {/* Tabs */}
    <div style={{display:"flex",gap:4,marginBottom:16,background:C.card,borderRadius:10,padding:4,width:"fit-content"}}>
      {TABS.map(t => <button key={t.id} onClick={() => setTab(t.id)} style={{padding:"8px 16px",borderRadius:8,border:"none",cursor:"pointer",fontFamily:"inherit",fontSize:12,fontWeight:tab===t.id?700:500,background:tab===t.id?ghColor:"transparent",color:tab===t.id?"#fff":C.textMuted,display:"flex",alignItems:"center",gap:6,transition:"all 0.2s"}}><t.icon size={13}/> {t.label}</button>)}
    </div>

    {/* -------- DASHBOARD TAB -------- */}
    {tab === "dashboard" && (<>
      {!latestScan ? (
        <Card>
          <div style={{textAlign:"center",padding:40}}>
            <GithubIcon size={56} color={ghColor} style={{marginBottom:16,opacity:0.3}}/>
            <h3 style={{color:C.text,margin:"0 0 8px",fontSize:18,fontWeight:700}}>No GitHub Scan Yet</h3>
            <p style={{color:C.textMuted,fontSize:13,marginBottom:16}}>Connect your GitHub account to scan repository security, branch protection, code scanning, secret detection, and more — all mapped to ISO 27001.</p>
            <div style={{display:"flex",gap:8,justifyContent:"center"}}>
              <Btn onClick={() => setTab("connect")}><GithubIcon size={14} color="#fff"/> Connect GitHub</Btn>
              <Btn variant="secondary" onClick={() => setTab("checks")}><ShieldCheck size={14}/> Manual Assessment</Btn>
            </div>
          </div>
        </Card>
      ) : (<>
        {/* Score + stats */}
        <div style={{display:"flex",gap:12,flexWrap:"wrap",marginBottom:16}}>
          <div style={{background:C.card,borderRadius:12,border:`1px solid ${C.border}`,padding:"16px 24px",display:"flex",alignItems:"center",gap:14,minWidth:160}}>
            <div style={{width:52,height:52,borderRadius:"50%",background:`conic-gradient(${scorePct >= 80 ? C.green : scorePct >= 50 ? C.yellow : C.red} ${scorePct * 3.6}deg, ${C.border} 0deg)`,display:"flex",alignItems:"center",justifyContent:"center"}}>
              <div style={{width:40,height:40,borderRadius:"50%",background:C.card,display:"flex",alignItems:"center",justifyContent:"center",fontSize:14,fontWeight:800,color:scorePct >= 80 ? C.green : scorePct >= 50 ? C.yellow : C.red}}>{scorePct}%</div>
            </div>
            <div><div style={{fontSize:10,color:C.textDim,fontWeight:700,textTransform:"uppercase"}}>Security Score</div><div style={{fontSize:18,fontWeight:800,color:C.text}}>{pass}/{CHECKS.length - na}</div></div>
          </div>
          <Stat label="Passed" value={pass} icon={CheckCircle} color={C.green}/>
          <Stat label="Failed" value={fail} icon={XCircle} color={C.red}/>
          <Stat label="Warning" value={warn} icon={AlertCircle} color={C.yellow}/>
          <Stat label="Manual" value={manual} icon={Search} color={C.blue}/>
          {notRun > 0 && <Stat label="Not Run" value={notRun} icon={Clock} color={C.textDim}/>}
        </div>

        {/* Scan info */}
        <div style={{background:C.card,borderRadius:10,border:`1px solid ${C.border}`,padding:"10px 16px",marginBottom:16,display:"flex",gap:20,alignItems:"center",fontSize:12,flexWrap:"wrap"}}>
          <span style={{color:C.textMuted,display:"flex",alignItems:"center",gap:4}}><GithubIcon size={12} color={ghColor}/> <strong style={{color:C.text}}>Org:</strong> <strong style={{color:ghColor}}>{latestScan.org}</strong></span>
          <span style={{color:C.textMuted}}>Repos: <strong style={{color:C.text}}>{latestScan.repoCount}</strong></span>
          <span style={{color:C.textMuted}}>Scanned: <strong style={{color:C.text}}>{new Date(latestScan.date).toLocaleString()}</strong></span>
          <span style={{color:C.textMuted}}>By: <strong style={{color:C.text}}>{latestScan.scannedBy}</strong></span>
          <span style={{color:C.textMuted}}>Total scans: <strong style={{color:C.text}}>{scans.length}</strong></span>
        </div>

        {/* Category breakdown */}
        <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(200px,1fr))",gap:10}}>
          {catStats.map(cs => {
            const pct = cs.total > 0 ? Math.round((cs.pass / cs.total) * 100) : 0;
            return (<div key={cs.cat} onClick={() => {setExpandCat(expandCat === cs.cat ? null : cs.cat); setTab("checks");}} style={{background:C.card,borderRadius:10,border:`1px solid ${pct === 100 ? C.green : cs.fail > 0 ? C.red : C.border}44`,padding:14,cursor:"pointer",transition:"all 0.2s"}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
                <span style={{fontSize:13,fontWeight:700,color:C.text}}>{cs.cat}</span>
                <span style={{fontSize:12,fontWeight:800,color:pct === 100 ? C.green : pct >= 50 ? C.yellow : C.red}}>{pct}%</span>
              </div>
              <div style={{height:5,background:C.border,borderRadius:3,overflow:"hidden",marginBottom:6}}>
                <div style={{height:"100%",width:`${pct}%`,background:pct === 100 ? C.green : pct >= 50 ? C.yellow : C.red,borderRadius:3,transition:"width 0.3s"}}/>
              </div>
              <div style={{display:"flex",gap:8,fontSize:10,color:C.textDim}}>
                {cs.pass > 0 && <span style={{color:C.green}}>✅ {cs.pass}</span>}
                {cs.fail > 0 && <span style={{color:C.red}}>❌ {cs.fail}</span>}
                {cs.warn > 0 && <span style={{color:C.yellow}}>⚠️ {cs.warn}</span>}
              </div>
            </div>);
          })}
        </div>
      </>)}
    </>)}

    {/* -------- SECURITY CHECKS TAB -------- */}
    {tab === "checks" && (
      <Card>
        <div style={{display:"flex",gap:8,marginBottom:14,flexWrap:"wrap",alignItems:"center"}}>
          <span style={{fontSize:11,color:C.textDim,fontWeight:700}}>FILTER:</span>
          <select value={filterSev} onChange={e => setFilterSev(e.target.value)} style={{padding:"4px 8px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:6,color:C.text,fontSize:11,fontFamily:"inherit"}}>
            <option value="ALL">All Severity</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option>
          </select>
          <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)} style={{padding:"4px 8px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:6,color:C.text,fontSize:11,fontFamily:"inherit"}}>
            <option value="ALL">All Status</option><option value="PASS">Pass</option><option value="FAIL">Fail</option><option value="WARN">Warn</option><option value="MANUAL">Manual</option><option value="NOT_RUN">Not Run</option>
          </select>
          <span style={{fontSize:11,color:C.textMuted,marginLeft:8}}>{filteredChecks.length} checks</span>
        </div>
        <div style={{overflow:"auto",maxHeight:550}}>
          <table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}>
            <thead><tr style={{background:C.bg,position:"sticky",top:0,zIndex:1}}>
              <th style={{padding:"8px 10px",textAlign:"left",color:ghColor,fontWeight:700,fontSize:11,borderBottom:`2px solid ${C.border}`,width:60}}>STATUS</th>
              <th style={{padding:"8px 10px",textAlign:"left",color:ghColor,fontWeight:700,fontSize:11,borderBottom:`2px solid ${C.border}`}}>CHECK</th>
              <th style={{padding:"8px 10px",textAlign:"center",color:ghColor,fontWeight:700,fontSize:11,borderBottom:`2px solid ${C.border}`,width:70}}>SEVERITY</th>
              <th style={{padding:"8px 10px",textAlign:"center",color:ghColor,fontWeight:700,fontSize:11,borderBottom:`2px solid ${C.border}`,width:65}}>ISO</th>
              <th style={{padding:"8px 10px",textAlign:"center",color:ghColor,fontWeight:700,fontSize:11,borderBottom:`2px solid ${C.border}`,width:50}}>GAP</th>
              {canManage && <th style={{padding:"8px 10px",textAlign:"center",color:ghColor,fontWeight:700,fontSize:11,borderBottom:`2px solid ${C.border}`,width:110}}>OVERRIDE</th>}
            </tr></thead>
            <tbody>
              {CATS.map(cat => {
                const catChecks = filteredChecks.filter(c => c.cat === cat);
                if (catChecks.length === 0) return null;
                return (<>
                  <tr key={`ghcat_${cat}`}><td colSpan={canManage ? 6 : 5} style={{padding:"10px 10px 4px",fontWeight:800,fontSize:12,color:ghColor,borderBottom:`1px solid ${C.border}33`}}>{cat} <span style={{fontWeight:500,color:C.textDim}}>({catChecks.length})</span></td></tr>
                  {catChecks.map(c => {
                    const st = getStatus(c.id);
                    const ss = statusStyle(st);
                    const isOverridden = !!overrides[c.id];
                    const sevColor = {CRITICAL:C.red,HIGH:C.yellow,MEDIUM:C.blue,LOW:C.textDim}[c.sev] || C.textDim;
                    return (<tr key={c.id} style={{borderBottom:`1px solid ${C.border}22`}}>
                      <td style={{padding:"6px 10px"}}>
                        <div style={{display:"inline-flex",alignItems:"center",gap:4,padding:"3px 8px",borderRadius:6,background:ss.bg,border:`1px solid ${ss.border}`,minWidth:55,justifyContent:"center"}}>
                          <span style={{fontSize:10}}>{ss.icon}</span>
                          <span style={{fontSize:10,fontWeight:700,color:ss.color}}>{ss.label}</span>
                        </div>
                      </td>
                      <td style={{padding:"6px 10px",color:C.text,fontSize:12}}>
                        {c.name}
                        {isOverridden && <span style={{marginLeft:6,fontSize:9,color:ghColor,fontWeight:700,background:`${ghColor}22`,padding:"1px 5px",borderRadius:4}}>OVERRIDDEN</span>}
                      </td>
                      <td style={{padding:"6px 10px",textAlign:"center"}}><span style={{fontSize:10,fontWeight:700,color:sevColor,background:`${sevColor}15`,padding:"2px 6px",borderRadius:4}}>{c.sev}</span></td>
                      <td style={{padding:"6px 10px",textAlign:"center",color:C.textMuted,fontSize:11}}>{c.iso}</td>
                      <td style={{padding:"6px 10px",textAlign:"center",color:c.gapQ?ghColor:C.textDim,fontSize:11,fontWeight:c.gapQ?700:400}}>{c.gapQ||"—"}</td>
                      {canManage && <td style={{padding:"6px 10px",textAlign:"center"}}>
                        <div style={{display:"flex",gap:2,justifyContent:"center"}}>
                          {["PASS","FAIL","WARN","N/A"].map(s => {
                            const active = st === s && isOverridden;
                            return <button key={s} onClick={() => setOverride(c.id, s)} title={s} style={{width:22,height:22,border:`1px solid ${active?statusStyle(s).color:C.border}`,borderRadius:4,cursor:"pointer",background:active?statusStyle(s).bg:"transparent",fontSize:8,fontWeight:700,color:active?statusStyle(s).color:C.textDim,display:"flex",alignItems:"center",justifyContent:"center"}}>{s[0]}</button>;
                          })}
                          {isOverridden && <button onClick={() => clearOverride(c.id)} title="Clear override" style={{width:22,height:22,border:`1px solid ${C.border}`,borderRadius:4,cursor:"pointer",background:"transparent",fontSize:10,color:C.textDim,display:"flex",alignItems:"center",justifyContent:"center"}}>✕</button>}
                        </div>
                      </td>}
                    </tr>);
                  })}
                </>);
              })}</tbody>
          </table>
        </div>
      </Card>
    )}

    {/* -------- CONNECT GITHUB TAB -------- */}
    {tab === "connect" && (
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}>
        {/* Left: Connection */}
        <Card title="Connect to GitHub">
          <p style={{color:C.textMuted,fontSize:12,marginBottom:16}}>
            Enter a GitHub <strong style={{color:C.text}}>Personal Access Token (classic)</strong> with the following scopes: <code style={{background:C.bg,padding:"1px 5px",borderRadius:4,fontSize:11,color:ghColor}}>repo</code>, <code style={{background:C.bg,padding:"1px 5px",borderRadius:4,fontSize:11,color:ghColor}}>read:org</code>, <code style={{background:C.bg,padding:"1px 5px",borderRadius:4,fontSize:11,color:ghColor}}>admin:repo_hook</code>, <code style={{background:C.bg,padding:"1px 5px",borderRadius:4,fontSize:11,color:ghColor}}>security_events</code>
          </p>

          <div style={{marginBottom:12}}>
            <label style={{display:"block",fontSize:11,fontWeight:700,color:C.textMuted,marginBottom:4}}>Personal Access Token *</label>
            <div style={{display:"flex",gap:4}}>
              <input type={showToken?"text":"password"} value={ghToken} onChange={e=>setGhToken(e.target.value)} placeholder="ghp_xxxxxxxxxxxx" style={{flex:1,padding:"8px 12px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,color:C.text,fontSize:12,fontFamily:"'DM Sans',monospace"}}/>
              <button onClick={()=>setShowToken(!showToken)} style={{padding:"6px 10px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,cursor:"pointer",color:C.textMuted}}>
                {showToken?<EyeOff size={14}/>:<Eye size={14}/>}
              </button>
            </div>
          </div>

          <div style={{marginBottom:16}}>
            <label style={{display:"block",fontSize:11,fontWeight:700,color:C.textMuted,marginBottom:4}}>Organization (optional — leave blank for personal repos)</label>
            <input type="text" value={ghOrg} onChange={e=>setGhOrg(e.target.value)} placeholder="your-org-name" style={{width:"100%",padding:"8px 12px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,color:C.text,fontSize:12,fontFamily:"inherit",boxSizing:"border-box"}}/>
          </div>

          <div style={{display:"flex",gap:8}}>
            <Btn onClick={testGithubConnection} disabled={scanning || !ghToken}>{scanning ? <><Loader size={14} style={{animation:"spin 1s linear infinite"}}/> Testing...</> : <><GithubIcon size={14} color="#fff"/> Test Connection</>}</Btn>
            {connected && <Btn onClick={handleGithubScan} disabled={scanning}><Zap size={14}/> Run Full Scan</Btn>}
          </div>

          {connected && <div style={{marginTop:12,padding:"8px 12px",background:`${C.green}12`,border:`1px solid ${C.green}33`,borderRadius:8,display:"flex",alignItems:"center",gap:6}}>
            <CheckCircle size={14} color={C.green}/>
            <span style={{color:C.green,fontSize:12,fontWeight:600}}>Connected to {connectedOrg}</span>
          </div>}

          {scanning && <div style={{marginTop:12}}>
            <div style={{display:"flex",justifyContent:"space-between",marginBottom:4}}>
              <span style={{fontSize:11,color:C.textMuted}}>{scanProgress.msg}</span>
              <span style={{fontSize:11,color:ghColor,fontWeight:700}}>{scanProgress.pct}%</span>
            </div>
            <div style={{height:6,background:C.border,borderRadius:3,overflow:"hidden"}}>
              <div style={{height:"100%",width:`${scanProgress.pct}%`,background:ghColor,borderRadius:3,transition:"width 0.3s"}}/>
            </div>
          </div>}
        </Card>

        {/* Right: Repo selection & alternate methods */}
        <div style={{display:"flex",flexDirection:"column",gap:16}}>
          {/* Repo Selector */}
          <Card title={`Select Repositories (${selectedRepos.length})`}>
            {availableRepos.length > 0 ? (<>
              <div style={{marginBottom:8}}>
                <input type="text" value={repoSearch} onChange={e=>setRepoSearch(e.target.value)} placeholder="Search repos..." style={{width:"100%",padding:"6px 10px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:6,color:C.text,fontSize:11,fontFamily:"inherit",boxSizing:"border-box"}}/>
              </div>
              <div style={{display:"flex",gap:4,marginBottom:8}}>
                <button onClick={()=>setSelectedRepos(filteredRepos.map(r=>r.name))} style={{padding:"3px 8px",fontSize:10,background:`${ghColor}15`,border:`1px solid ${ghColor}33`,borderRadius:4,color:ghColor,cursor:"pointer",fontWeight:600,fontFamily:"inherit"}}>Select All</button>
                <button onClick={()=>setSelectedRepos([])} style={{padding:"3px 8px",fontSize:10,background:C.bg,border:`1px solid ${C.border}`,borderRadius:4,color:C.textMuted,cursor:"pointer",fontWeight:600,fontFamily:"inherit"}}>Clear</button>
              </div>
              <div style={{maxHeight:200,overflowY:"auto"}}>
                {filteredRepos.map(r => (
                  <label key={r.name} style={{display:"flex",alignItems:"center",gap:6,padding:"4px 6px",borderRadius:4,cursor:"pointer",fontSize:11,color:selectedRepos.includes(r.name)?C.text:C.textMuted,background:selectedRepos.includes(r.name)?`${ghColor}08`:"transparent"}}>
                    <input type="checkbox" checked={selectedRepos.includes(r.name)} onChange={e=>{
                      if(e.target.checked) setSelectedRepos(s=>[...s,r.name]);
                      else setSelectedRepos(s=>s.filter(x=>x!==r.name));
                    }}/>
                    <GitBranch size={10} color={ghColor}/>
                    <span style={{flex:1,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{r.name}</span>
                    {r.private && <Lock size={10} color={C.textDim}/>}
                    {r.language && <span style={{fontSize:9,color:C.textDim,background:C.bg,padding:"1px 4px",borderRadius:3}}>{r.language}</span>}
                  </label>
                ))}
              </div>
            </>) : (
              <div style={{textAlign:"center",padding:20,color:C.textDim,fontSize:12}}>
                <GithubIcon size={24} color={C.textDim} style={{marginBottom:6,opacity:0.3}}/><br/>
                Connect to GitHub first to see repositories
              </div>
            )}
          </Card>

          {/* Manual Upload */}
          <Card title="Alternative Methods">
            <div style={{display:"flex",flexDirection:"column",gap:10}}>
              <div style={{padding:12,background:C.bg,borderRadius:8,border:`1px solid ${C.border}`}}>
                <div style={{fontSize:12,fontWeight:700,color:C.text,marginBottom:4,display:"flex",alignItems:"center",gap:6}}><Upload size={13} color={ghColor}/> Upload Scan JSON</div>
                <p style={{fontSize:11,color:C.textMuted,margin:"0 0 8px"}}>Upload a previously exported GitHub security scan in JSON format.</p>
                <FileUploadBtn onFile={handleUpload} accept=".json" label="Upload JSON" variant="secondary" size="sm"/>
              </div>
              <div style={{padding:12,background:C.bg,borderRadius:8,border:`1px solid ${C.border}`}}>
                <div style={{fontSize:12,fontWeight:700,color:C.text,marginBottom:4,display:"flex",alignItems:"center",gap:6}}><ShieldCheck size={13} color={ghColor}/> Manual Assessment</div>
                <p style={{fontSize:11,color:C.textMuted,margin:"0 0 8px"}}>Manually mark each security check as pass/fail/warn without connecting.</p>
                <Btn variant="secondary" size="sm" onClick={() => {
                  if(!latestScan) {
                    const emptyResults = {};
                    GITHUB_CHECKS.forEach(c => { emptyResults[c.id] = "NOT_RUN"; });
                    setData(d => ({...d, githubScans: [...(d.githubScans || []), {id:`ghscan_${Date.now()}`,date:new Date().toISOString(),org:"Manual",repoCount:0,results:emptyResults,overrides:{},scannedBy:user?.email||"unknown",scanType:"manual"}]}));
                  }
                  setTab("checks");
                }}><ClipboardCheck size={13}/> Start Manual Assessment</Btn>
              </div>
            </div>
          </Card>
        </div>
      </div>
    )}

    {/* -------- GAP EVIDENCE TAB -------- */}
    {tab === "evidence" && (
      <div>
        {latestScan ? (<>
          <Card title="Push GitHub Evidence to Gap Assessment" action={<Btn onClick={pushToGap} size="sm"><Zap size={13}/> Push to Gap Assessment</Btn>}>
            <p style={{color:C.textMuted,fontSize:12,marginBottom:16}}>Link GitHub scan results directly to your ISO 27001 Gap Assessment. This will update questions C3, C7, C8, C9, C10 with your current scan data.</p>
            <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(250px,1fr))",gap:10}}>
              {Object.entries(GAP_MAP).map(([qId, {name, checks: checkIds}]) => {
                const statuses = checkIds.map(id => ({id, name: (CHECKS.find(c => c.id === id)||{}).name, status: getStatus(id)}));
                const passCount = statuses.filter(s => s.status === "PASS").length;
                const failCount = statuses.filter(s => s.status === "FAIL").length;
                const pct = Math.round((passCount / statuses.length) * 100);
                return (<div key={qId} style={{background:C.bg,borderRadius:10,border:`1px solid ${pct === 100 ? C.green : failCount > 0 ? C.red : C.border}44`,padding:14}}>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
                    <div>
                      <span style={{fontSize:10,fontWeight:800,color:ghColor}}>{qId}</span>
                      <span style={{fontSize:12,fontWeight:700,color:C.text,marginLeft:6}}>{name}</span>
                    </div>
                    <span style={{fontSize:12,fontWeight:800,color:pct === 100 ? C.green : pct >= 50 ? C.yellow : C.red}}>{pct}%</span>
                  </div>
                  <div style={{height:4,background:C.border,borderRadius:2,overflow:"hidden",marginBottom:8}}>
                    <div style={{height:"100%",width:`${pct}%`,background:pct === 100 ? C.green : pct >= 50 ? C.yellow : C.red,borderRadius:2}}/>
                  </div>
                  <div style={{fontSize:10,color:C.textDim}}>
                    {statuses.map(s => (
                      <div key={s.id} style={{display:"flex",gap:4,padding:"1px 0"}}>
                        <span>{statusStyle(s.status).icon}</span>
                        <span style={{color: s.status === "FAIL" ? C.red : s.status === "PASS" ? C.green : C.textMuted}}>{s.name}</span>
                      </div>
                    ))}
                  </div>
                </div>);
              })}
            </div>
          </Card>
          {/* Scan History */}
          {scans.length > 1 && <Card title="Scan History" style={{marginTop:16}}>
            <table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}>
              <thead><tr>
                <th style={{padding:6,textAlign:"left",color:C.textDim,fontSize:10,fontWeight:700}}>DATE</th>
                <th style={{padding:6,textAlign:"left",color:C.textDim,fontSize:10,fontWeight:700}}>ORG</th>
                <th style={{padding:6,textAlign:"center",color:C.textDim,fontSize:10,fontWeight:700}}>REPOS</th>
                <th style={{padding:6,textAlign:"center",color:C.textDim,fontSize:10,fontWeight:700}}>TYPE</th>
                <th style={{padding:6,textAlign:"left",color:C.textDim,fontSize:10,fontWeight:700}}>BY</th>
              </tr></thead>
              <tbody>{scans.map((s,i) => {
                const p = Object.values(s.results||{}).filter(v=>v==="PASS").length;
                const f = Object.values(s.results||{}).filter(v=>v==="FAIL").length;
                return (<tr key={s.id} style={{borderBottom:`1px solid ${C.border}22`,background:i===scans.length-1?`${ghColor}08`:"transparent"}}>
                  <td style={{padding:6,color:C.text}}>{new Date(s.date).toLocaleString()}</td>
                  <td style={{padding:6,color:ghColor,fontWeight:600}}>{s.org}</td>
                  <td style={{padding:6,color:C.textMuted,textAlign:"center"}}>{s.repoCount}</td>
                  <td style={{padding:6,textAlign:"center"}}><Badge color={s.scanType==="live"?C.green:C.blue}>{s.scanType}</Badge></td>
                  <td style={{padding:6,color:C.textMuted}}>{s.scannedBy}</td>
                </tr>);
              })}</tbody>
            </table>
          </Card>}
        </>) : (
          <Card>
            <div style={{textAlign:"center",padding:40}}>
              <ClipboardCheck size={48} color={C.textDim} style={{marginBottom:12,opacity:0.3}}/>
              <h3 style={{color:C.text,margin:"0 0 8px"}}>No GitHub Scan Data</h3>
              <p style={{color:C.textMuted,fontSize:13}}>Run a scan first to generate evidence for your Gap Assessment.</p>
              <Btn onClick={() => setTab("connect")} style={{marginTop:12}}><GithubIcon size={14} color="#fff"/> Connect & Scan</Btn>
            </div>
          </Card>
        )}
      </div>
    )}
  </div>);
};

// =============================================
// ACCESS DENIED / READ-ONLY
// =============================================
const AccessDenied = () => (
  <div style={{textAlign:"center",padding:60}}>
    <Lock size={48} color={C.red} style={{marginBottom:16,opacity:0.5}}/>
    <h3 style={{color:C.text,margin:"0 0 8px",fontSize:18,fontWeight:700}}>Access Restricted</h3>
    <p style={{color:C.textMuted,fontSize:13}}>Your role does not have permission to access this module. Contact your administrator.</p>
  </div>
);

const ReadOnlyBanner = ({role}) => (
  <div style={{padding:"8px 16px",background:`${C.yellow}15`,border:`1px solid ${C.yellow}33`,borderRadius:8,marginBottom:16,display:"flex",alignItems:"center",gap:8}}>
    <Eye size={14} color={C.yellow}/>
    <span style={{color:C.yellow,fontSize:12,fontWeight:600}}>Read-only mode — {ROLES[role]?.label||role} cannot edit this module</span>
  </div>
);

const NotRegistered = ({email,onLogout,onRetry}) => (
  <div style={{minHeight:"100vh",background:C.bg,display:"flex",alignItems:"center",justifyContent:"center",fontFamily:"'DM Sans',sans-serif"}}>
    <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800;900&display=swap" rel="stylesheet"/>
    <div style={{width:420,maxWidth:"95vw",textAlign:"center"}}>
      <Logo/>
      <div style={{background:C.sidebar,borderRadius:16,border:`1px solid ${C.border}`,padding:32,marginTop:24}}>
        <AlertCircle size={48} color={C.red} style={{marginBottom:12}}/>
        <h3 style={{color:C.text,margin:"0 0 8px",fontSize:18,fontWeight:700}}>Access Not Granted</h3>
        <p style={{color:C.textMuted,fontSize:13,marginBottom:8}}>The account <strong style={{color:C.text}}>{email}</strong> is not registered in the SecComply platform.</p>
        <p style={{color:C.textDim,fontSize:12,marginBottom:20}}>Please contact your SecComply administrator to get access.</p>
        <div style={{display:"flex",gap:8,justifyContent:"center"}}>
          {onRetry&&<Btn variant="secondary" onClick={onRetry}><RefreshCw size={14}/> Retry</Btn>}
          <Btn onClick={onLogout}>Sign Out</Btn>
        </div>
      </div>
    </div>
  </div>
);

// =============================================
// SETUP WIZARD (first Super Admin)
// =============================================

const SetupWizard = ({user,token,onComplete}) => {
  const [loading,setLoading]=useState(false);
  const [error,setError]=useState("");
  const [adminName, setAdminName] = useState("");
  const allowed = SUPER_ADMIN_EMAIL && user.email.toLowerCase() === SUPER_ADMIN_EMAIL;

  const finish = async() => {
    if(!allowed || !adminName.trim()) return;
    setLoading(true); setError("");
    try {
      const rbac = {
        orgs:[],
        members:[{id:secureId('m_'),userId:user.id,email:user.email,role:"super_admin",name:adminName.trim(),type:"seccomply",orgId:null,createdBy:"system",createdAt:new Date().toISOString(),status:"active"}],
      };
      await saveRbac(token, rbac);
      // Bootstrap super admin into user_org_roles table (required for Edge Functions)
      try {
        const bRes = await safeFetch(`${SUPA_URL}/rest/v1/rpc/bootstrap_super_admin`,{
          method:"POST",
          headers:{"apikey":SUPA_KEY,"Authorization":`Bearer ${token}`,"Content-Type":"application/json"},
          body:JSON.stringify({admin_email:user.email,admin_name:adminName.trim()}),
        });
        const bData = await bRes.json();
        if(bData?.error) console.warn("Bootstrap warning:",bData.error);
        else console.log("Super admin bootstrapped into user_org_roles:",bData);
      } catch(bErr) { console.warn("Bootstrap RPC not available (run updated SQL setup):",bErr.message); }
      onComplete(rbac);
    } catch(e) { setError(e.message); }
    setLoading(false);
  };

  return (
    <div style={{minHeight:"100vh",background:C.bg,display:"flex",alignItems:"center",justifyContent:"center",fontFamily:"'DM Sans',sans-serif"}}>
      <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800;900&display=swap" rel="stylesheet"/>
      <div style={{width:480,maxWidth:"95vw"}}>
        <div style={{textAlign:"center",marginBottom:32,display:"flex",flexDirection:"column",alignItems:"center"}}><Logo/><p style={{color:C.textMuted,fontSize:14,marginTop:8}}>First-Time Platform Setup</p></div>
        <Card>
          {allowed?<>
            <div style={{textAlign:"center",marginBottom:24}}>
              <div style={{width:56,height:56,borderRadius:"50%",background:`${C.orange}22`,display:"flex",alignItems:"center",justifyContent:"center",margin:"0 auto 12px"}}><span style={{fontSize:28}}>🔑</span></div>
              <h3 style={{margin:"0 0 4px",color:C.text,fontSize:18,fontWeight:800}}>Welcome!</h3>
              <p style={{color:C.textMuted,fontSize:13,margin:0}}>Setting up <strong style={{color:C.orange}}>{user.email}</strong> as Super Admin</p>
            </div>
            {error&&<div style={{padding:"8px 12px",background:C.redBg,border:`1px solid ${C.red}44`,borderRadius:8,color:C.red,fontSize:12,marginBottom:16}}>{error}</div>}
            <Input label="Your Name *" value={adminName} onChange={setAdminName} placeholder="Enter your full name"/>
            <div style={{padding:12,background:C.bg,borderRadius:8,border:`1px solid ${C.border}`,marginBottom:16}}>
              <div style={{fontSize:11,color:C.textDim,fontWeight:700,marginBottom:6}}>WHAT THIS SETS UP:</div>
              <div style={{fontSize:12,color:C.textMuted,lineHeight:1.6}}>
                • You'll be the <strong style={{color:"#ef4444"}}>Super Admin</strong> of the platform<br/>
                • You can add SecComply employees, create client organizations<br/>
                • All other users will be created through the Admin Panel
              </div>
            </div>
            <Btn onClick={finish} disabled={loading||!adminName.trim()} style={{width:"100%"}}>{loading?<><Loader size={14} style={{animation:"spin 1s linear infinite"}}/> Setting up...</>:<><CheckCircle size={14}/> Initialize Platform</>}</Btn>
          </>:<>
            <div style={{textAlign:"center",padding:20}}>
              <AlertCircle size={48} color={C.red} style={{marginBottom:12}}/>
              <h3 style={{color:C.text,margin:"0 0 8px",fontSize:18,fontWeight:700}}>Unauthorized Setup</h3>
              <p style={{color:C.textMuted,fontSize:13}}>Platform setup can only be done by <strong style={{color:C.orange}}>{SUPER_ADMIN_EMAIL}</strong></p>
              <p style={{color:C.textDim,fontSize:12,marginBottom:16}}>Logged in as: {user.email}</p>
              <p style={{color:C.textDim,fontSize:12}}>Please contact your SecComply administrator.</p>
            </div>
          </>}
          <style>{`@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}`}</style>
        </Card>
      </div>
    </div>
  );
};

// =============================================
// ADMIN PANEL — User & Client Management
// =============================================
const AdminPanel = ({rbac,setRbac,token,currentRole,onEnterClient,user,currentOrgId}) => {
  const [toast,setToast]=useState(null);
  const [tab,setTab]=useState("clients"); // clients | seccomply_users | create_user
  const [userModal,setUserModal]=useState(null);
  const [orgModal,setOrgModal]=useState(null);
  const [bulkModal,setBulkModal]=useState(null);
  const [bulkResults,setBulkResults]=useState(null);
  const [creating,setCreating]=useState(false);
  const [error,setError]=useState("");

  const allOrgs = rbac?.orgs||[];
  const allMembers = rbac?.members||[];
  const myRole = currentRole;
  const canCreateRoles = CAN_CREATE[myRole]||[];
  const isClient = isClientRole(myRole);

  // Client roles: scope to their org only
  const orgs = isClient ? allOrgs.filter(o=>o.id===currentOrgId) : allOrgs;
  const members = isClient ? allMembers.filter(m=>m.orgId===currentOrgId) : allMembers;

  const s = async(newRbac) => {
    setRbac(newRbac);
    try { await saveRbac(token, newRbac); setToast({msg:"Saved!",type:"success"}); }
    catch(e) { setToast({msg:"Save failed: "+e.message,type:"error"}); }
  };

  // Create single user
  const createUser = async(form) => {
    if(!form.email||!form.password||!form.name||!form.role) { setError("All fields required"); return; }
    if(!canCreateRoles.includes(form.role)) { setError("You cannot create this role"); return; }
    if(isClientRole(form.role) && !form.orgId) { setError("Select a client organization"); return; }
    setCreating(true); setError("");
    try {
      const authUser = await createAuthUser(token, form.email, form.password, form.name, form.role, isSecComply(form.role)?null:form.orgId);
      const mem = {
        id:secureId('m_'),userId:authUser.id,email:sanitizeInput(form.email.toLowerCase().trim()),name:sanitizeInput(form.name),role:form.role,
        type:isSecComply(form.role)?"seccomply":"client",
        orgId:isSecComply(form.role)?null:form.orgId,
        createdBy:user.email,createdAt:new Date().toISOString(),status:"active",
      };
      const newRbac = {...rbac, members:[...members,mem]};
      await s(newRbac);
      setUserModal(null); setToast({msg:`User ${form.name} created!`,type:"success"});
    } catch(e) { setError(e.message); }
    setCreating(false);
  };

  // Create org (client)
  const createOrg = async(form) => {
    if(!form.name) { setError("Organization name required"); return; }
    setCreating(true); setError("");
    try {
      const org = {id:secureId('org_'),name:sanitizeInput(form.name),domain:sanitizeInput(form.domain||""),createdBy:user.email,createdAt:new Date().toISOString(),status:"active"};
      await saveOrgData(token, org.id, getInitialData());
      // If client admin info provided, create their account too
      let newMembers = [...members];
      if(form.adminEmail && form.adminPassword && form.adminName) {
        const authUser = await createAuthUser(token, form.adminEmail, form.adminPassword, form.adminName, "client_admin", org.id);
        newMembers.push({id:secureId('m_'),userId:authUser.id,email:form.adminEmail,name:form.adminName,role:"client_admin",type:"client",orgId:org.id,createdBy:user.email,createdAt:new Date().toISOString(),status:"active"});
      }
      const newRbac = {...rbac, orgs:[...orgs,org], members:newMembers};
      await s(newRbac);
      setOrgModal(null); setToast({msg:`Client "${form.name}" created!`,type:"success"});
    } catch(e) { setError(e.message); }
    setCreating(false);
  };

  // Bulk employee upload from Excel
  const handleBulkUpload = async(file, orgId) => {
    if(!file||!orgId) return;
    setCreating(true); setError(""); setBulkResults(null);
    try {
      const data = await file.arrayBuffer();
      const wb = XLSX.read(data);
      const ws = wb.Sheets[wb.SheetNames[0]];
      const rows = XLSX.utils.sheet_to_json(ws);
      if(!rows.length) { setError("No data found in Excel"); setCreating(false); return; }
      const results = [];
      let newMembers = [...members];
      const org = orgs.find(o=>o.id===orgId);
      const domain = org?.domain || "seccomply.net";
      for(const row of rows) {
        const name = row["Name"]||row["name"]||row["Employee Name"]||row["employee_name"]||"";
        if(!name.trim()) continue;
        const slug = name.trim().toLowerCase().replace(/[^a-z0-9]/g,".");
        const email = row["Email"]||row["email"]|| `${slug}@${domain}`;
        const pw = genPassword();
        try {
          const authUser = await createEmployeeNoEmail(token, email, pw, name.trim(), "client_employee", orgId);
          newMembers.push({id:secureId('m_'),userId:authUser.id,email:sanitizeInput(email),name:sanitizeInput(name.trim()),role:"client_employee",type:"client",orgId,createdBy:user.email,createdAt:new Date().toISOString(),status:"active"});
          results.push({name:name.trim(),email,password:pw,status:"✅ Created"});
        } catch(e) {
          results.push({name:name.trim(),email,password:"-",status:`❌ ${e.message}`});
        }
      }
      const newRbac = {...rbac, members:newMembers};
      await s(newRbac);
      setBulkResults(results);
    } catch(e) { setError(e.message); }
    setCreating(false);
  };

  // Export credentials — passwords included since no email invite is sent
  const exportCredentials = (results) => {
    const ws = XLSX.utils.json_to_sheet(results.map(r=>({Name:r.name,Email:r.email,Password:r.password||"-",Status:r.status})));
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb,ws,"Credentials");
    XLSX.writeFile(wb,"employee_accounts.xlsx");
    auditLog(token,"data_export",{resource_type:"credentials",org_id:currentOrgId,record_count:results.length},"critical");
  };

  // Delete member — [SEC-2] audit + double confirmation for admins
  const removeMember = async(memId) => {
    const mem = members.find(m=>m.id===memId);
    const isAdmin = mem && (mem.role === "super_admin" || mem.role === "client_admin");
    const confirmMsg = isAdmin
      ? `⚠️ CRITICAL: Remove ${mem.role} "${mem.name || mem.email}"? This cannot be undone.`
      : "Remove this user?";
    if(!window.confirm(confirmMsg)) return;
    if(isAdmin && !window.confirm("This is an admin account. Are you absolutely sure?")) return;
    await s({...rbac,members:members.filter(m=>m.id!==memId)});
    auditLog(token,"delete_user",{resource_type:"user",resource_id:memId,email:mem?.email,role:mem?.role,org_id:mem?.orgId},"critical");
  };

  // Delete org — [SEC-2] audit + type-to-confirm
  const deleteOrg = async(orgId) => {
    const org = orgs.find(o=>o.id===orgId);
    const orgMembers = members.filter(m=>m.orgId===orgId);
    const confirmMsg = `⚠️ DELETE "${org?.name || orgId}"?\nThis will remove ${orgMembers.length} member(s) and ALL associated data.\nThis action CANNOT be undone.`;
    if(!window.confirm(confirmMsg)) return;
    const typedName = window.prompt(`Type the organization name "${org?.name}" to confirm deletion:`);
    if(typedName !== org?.name) { return; }
    await s({...rbac,orgs:orgs.filter(o=>o.id!==orgId),members:members.filter(m=>m.orgId!==orgId)});
    auditLog(token,"delete_org",{resource_type:"org",resource_id:orgId,org_name:org?.name,members_removed:orgMembers.length},"critical");
  };

  const scTeam = allMembers.filter(m=>m.type==="seccomply");

  return (<div>
    {toast&&<Toast {...toast} onClose={()=>setToast(null)}/>}
    <h2 style={{margin:"0 0 4px",fontSize:22,fontWeight:800,color:C.text}}>{isClient?"👥 Team Management":"🔑 Admin Panel"}</h2>
    <p style={{color:C.textMuted,margin:"0 0 20px",fontSize:13}}>{isClient?"Manage your organization's users and employees":"Manage clients, users, and access control"}</p>

    {/* Stats */}
    <div style={{display:"flex",gap:16,flexWrap:"wrap",marginBottom:20}}>
      {!isClient&&<Stat label="Client Organizations" value={orgs.length} icon={Server} color={C.orange}/>}
      {!isClient&&<Stat label="SecComply Team" value={scTeam.length} icon={Shield} color={C.blue}/>}
      <Stat label={isClient?"Team Members":"Total Client Users"} value={isClient?members.length:allMembers.filter(m=>m.type==="client").length} icon={Users} color={C.green}/>
      {!isClient&&<Stat label="Total Users" value={allMembers.length} icon={Users} color={C.yellow}/>}
      {isClient&&<Stat label="Client Users" value={members.filter(m=>m.role==="client_user").length} icon={Users} color={C.orange}/>}
      {isClient&&<Stat label="Employees" value={members.filter(m=>m.role==="client_employee").length} icon={GraduationCap} color={C.blue}/>}
    </div>

    {/* Tabs — only show for SecComply roles */}
    {!isClient&&<div style={{display:"flex",gap:4,marginBottom:16,background:C.bg,borderRadius:10,padding:4,width:"fit-content"}}>
      {[{id:"clients",label:"Client Organizations"},{id:"seccomply_users",label:"SecComply Team"}].filter(t=>t.id!=="seccomply_users"||myRole==="super_admin").map(t=>(
        <button key={t.id} onClick={()=>setTab(t.id)} style={{padding:"8px 16px",border:"none",borderRadius:8,cursor:"pointer",fontWeight:700,fontSize:12,background:tab===t.id?C.orange:"transparent",color:tab===t.id?"#fff":C.textMuted,fontFamily:"inherit"}}>{t.label}</button>
      ))}
    </div>}

    {/* Client Team Management (for client_admin / client_user) */}
    {isClient&&(<Card title="Team Members" action={<div style={{display:"flex",gap:6}}>
      {canCreateRoles.length>0&&<Btn size="sm" onClick={()=>{setError("");setUserModal({name:"",email:"",password:"",role:canCreateRoles[0],orgId:currentOrgId});}}><Plus size={12}/> Add User</Btn>}
      {canCreateRoles.includes("client_employee")&&<Btn size="sm" variant="secondary" onClick={()=>{setError("");setBulkModal({orgId:currentOrgId,file:null});}}><Upload size={12}/> Bulk Employees</Btn>}
    </div>}>
      {members.length===0?<Empty msg="No team members yet"/>:(
        <div style={{display:"flex",flexDirection:"column",gap:6}}>
          {members.map(mem=>{const R=ROLES[mem.role]||ROLES.client_employee; return (
            <div key={mem.id} style={{padding:"10px 14px",borderRadius:8,border:`1px solid ${C.border}`,display:"flex",alignItems:"center",gap:10}}>
              <div style={{width:36,height:36,borderRadius:"50%",background:`${R.color}22`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:18}}>{R.badge}</div>
              <div style={{flex:1}}>
                <div style={{fontSize:13,fontWeight:600,color:C.text}}>{mem.name}</div>
                <div style={{fontSize:11,color:C.textDim}}>{mem.email}</div>
              </div>
              <Badge color={R.color}>{R.label}</Badge>
              {mem.email!==user.email&&canCreateRoles.includes(mem.role)&&<button onClick={()=>removeMember(mem.id)} style={{background:"none",border:"none",cursor:"pointer",color:C.red,padding:4}}><Trash2 size={12}/></button>}
            </div>
          );})}
        </div>
      )}
    </Card>)}

    {/* SecComply Team Tab (Super Admin only) */}
    {tab==="seccomply_users"&&myRole==="super_admin"&&(
      <Card title="SecComply Team" action={<Btn size="sm" onClick={()=>{setError("");setUserModal({name:"",email:"",password:"",role:"employee",orgId:null});}}><Plus size={12}/> Add User</Btn>}>
        {scTeam.length===0?<Empty msg="No team members yet"/>:(
          <div style={{display:"flex",flexDirection:"column",gap:6}}>
            {scTeam.map(mem=>{const R=ROLES[mem.role]||ROLES.employee; return (
              <div key={mem.id} style={{padding:"10px 14px",borderRadius:8,border:`1px solid ${C.border}`,display:"flex",alignItems:"center",gap:10}}>
                <div style={{width:32,height:32,borderRadius:"50%",background:`${R.color}22`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:16}}>{R.badge}</div>
                <div style={{flex:1}}><div style={{fontSize:13,fontWeight:600,color:C.text}}>{mem.name}</div><div style={{fontSize:11,color:C.textDim}}>{mem.email}</div></div>
                <Badge color={R.color}>{R.label}</Badge>
                {mem.userId!==user.id&&<button onClick={()=>removeMember(mem.id)} style={{background:"none",border:"none",cursor:"pointer",color:C.red,padding:4}}><Trash2 size={12}/></button>}
              </div>
            );})}
          </div>
        )}
      </Card>
    )}

    {/* Clients Tab (SecComply roles only) */}
    {!isClient&&tab==="clients"&&(<>
      <div style={{display:"flex",gap:8,marginBottom:16}}>
        <Btn size="sm" onClick={()=>{setError("");setOrgModal({name:"",domain:"",adminName:"",adminEmail:"",adminPassword:""});}}><Plus size={12}/> Create Client</Btn>
      </div>
      {orgs.length===0?<Card><Empty msg="No client organizations yet. Create one to get started."/></Card>:(
        <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(320px,1fr))",gap:12}}>
          {orgs.map(org=>{
            const orgMems = members.filter(m=>m.orgId===org.id);
            const admins = orgMems.filter(m=>m.role==="client_admin");
            const users = orgMems.filter(m=>m.role==="client_user");
            const employees = orgMems.filter(m=>m.role==="client_employee");
            return (
              <div key={org.id} style={{background:C.card,borderRadius:12,border:`1px solid ${C.border}`,overflow:"hidden"}}>
                <div style={{padding:"16px 16px 12px",borderBottom:`1px solid ${C.border}22`}}>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}>
                    <div>
                      <div style={{fontSize:16,fontWeight:800,color:C.text}}>{org.name}</div>
                      <div style={{fontSize:11,color:C.textDim,marginTop:2}}>{org.domain||"No domain"} · Created {new Date(org.createdAt).toLocaleDateString()}</div>
                    </div>
                    <div style={{display:"flex",gap:4}}>
                      <button onClick={()=>deleteOrg(org.id)} style={{background:"none",border:"none",cursor:"pointer",color:C.red,padding:4}}><Trash2 size={14}/></button>
                    </div>
                  </div>
                </div>
                <div style={{padding:"12px 16px",display:"flex",gap:16,fontSize:11,color:C.textMuted}}>
                  <span><strong style={{color:C.orange}}>{admins.length}</strong> Admins</span>
                  <span><strong style={{color:C.green}}>{users.length}</strong> Users</span>
                  <span><strong style={{color:"#8b5cf6"}}>{employees.length}</strong> Employees</span>
                </div>
                <div style={{padding:"8px 16px 12px",display:"flex",gap:6,flexWrap:"wrap"}}>
                  <Btn size="sm" onClick={()=>onEnterClient(org.id)}><Eye size={12}/> Enter Client</Btn>
                  <Btn size="sm" variant="secondary" onClick={()=>{setError("");setUserModal({name:"",email:"",password:"",role:"client_admin",orgId:org.id});}}><Plus size={12}/> Add User</Btn>
                  <Btn size="sm" variant="secondary" onClick={()=>{setError("");setBulkModal({orgId:org.id,file:null});}}><Upload size={12}/> Bulk Employees</Btn>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </>)}

    {/* Create/Edit User Modal */}
    <Modal open={!!userModal} onClose={()=>{setUserModal(null);setError("");}}>
      {userModal&&<div>
        <h3 style={{margin:"0 0 16px",color:C.text,fontSize:16,fontWeight:800}}>Create User Account</h3>
        {error&&<div style={{padding:"8px 12px",background:C.redBg,border:`1px solid ${C.red}44`,borderRadius:8,color:C.red,fontSize:12,marginBottom:12}}>{error}</div>}
        <Input label="Full Name *" value={userModal.name} onChange={v=>setUserModal(m=>({...m,name:v}))} placeholder="John Doe"/>
        <Input label="Email (username) *" value={userModal.email} onChange={v=>setUserModal(m=>({...m,email:v}))} placeholder="john@company.com"/>
        <Input label="Password * (min 12 chars)" value={userModal.password} onChange={v=>setUserModal(m=>({...m,password:v}))} placeholder="Min 12 characters" type="password"/>
        <div style={{marginBottom:8}}><label style={{display:"block",fontSize:12,color:C.textMuted,marginBottom:6,fontWeight:600}}>Role *</label>
          <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
            {canCreateRoles.map(r=>{const R=ROLES[r]; return (
              <button key={r} onClick={()=>setUserModal(m=>({...m,role:r}))} style={{padding:"6px 12px",borderRadius:8,border:`1px solid ${userModal.role===r?R.color:C.border}`,background:userModal.role===r?`${R.color}18`:"transparent",color:userModal.role===r?R.color:C.textMuted,fontSize:12,fontWeight:600,cursor:"pointer",fontFamily:"inherit"}}>{R.badge} {R.label}</button>
            );})}
          </div>
        </div>
        {isClientRole(userModal.role)&&<Input label="Client Organization *" value={userModal.orgId||""} onChange={v=>setUserModal(m=>({...m,orgId:v}))} select options={[{value:"",label:"Select organization..."},...orgs.map(o=>({value:o.id,label:o.name}))]} />}
        {isClientRole(userModal.role)&&userModal.orgId&&<div style={{fontSize:11,color:C.textDim,marginBottom:8}}>Org: {orgs.find(o=>o.id===userModal.orgId)?.name}</div>}
        <div style={{padding:10,background:C.bg,borderRadius:8,border:`1px solid ${C.border}`,marginBottom:12}}>
          <div style={{fontSize:12,fontWeight:700,color:ROLES[userModal.role]?.color||C.text}}>{ROLES[userModal.role]?.badge} {ROLES[userModal.role]?.label}</div>
          <div style={{fontSize:11,color:C.textDim,marginTop:2}}>{ROLES[userModal.role]?.desc}</div>
        </div>
        <div style={{display:"flex",justifyContent:"flex-end",gap:8}}>
          <Btn variant="secondary" onClick={()=>{setUserModal(null);setError("");}}>Cancel</Btn>
          <Btn onClick={()=>createUser(userModal)} disabled={creating}>{creating?<><Loader size={12} style={{animation:"spin 1s linear infinite"}}/> Creating...</>:<><Plus size={14}/> Create Account</>}</Btn>
        </div>
      </div>}
    </Modal>

    {/* Create Client Modal */}
    <Modal open={!!orgModal} onClose={()=>{setOrgModal(null);setError("");}}>
      {orgModal&&<div>
        <h3 style={{margin:"0 0 16px",color:C.text,fontSize:16,fontWeight:800}}>Create Client Organization</h3>
        {error&&<div style={{padding:"8px 12px",background:C.redBg,border:`1px solid ${C.red}44`,borderRadius:8,color:C.red,fontSize:12,marginBottom:12}}>{error}</div>}
        <Input label="Organization Name *" value={orgModal.name} onChange={v=>setOrgModal(m=>({...m,name:v}))} placeholder="e.g. Cummins India"/>
        <Input label="Domain" value={orgModal.domain} onChange={v=>setOrgModal(m=>({...m,domain:v}))} placeholder="cummins.com"/>
        <div style={{padding:10,background:`${C.orange}08`,borderRadius:8,border:`1px solid ${C.orange}22`,margin:"12px 0"}}>
          <div style={{fontSize:12,fontWeight:700,color:C.orange,marginBottom:4}}>Client Admin (optional)</div>
          <div style={{fontSize:11,color:C.textDim,marginBottom:8}}>Create a Client Admin account for this organization</div>
          <Input label="Admin Name" value={orgModal.adminName} onChange={v=>setOrgModal(m=>({...m,adminName:v}))} placeholder="Admin name"/>
          <Input label="Admin Email" value={orgModal.adminEmail} onChange={v=>setOrgModal(m=>({...m,adminEmail:v}))} placeholder="admin@client.com"/>
          <Input label="Admin Password" value={orgModal.adminPassword} onChange={v=>setOrgModal(m=>({...m,adminPassword:v}))} placeholder="Min 12 characters" type="password"/>
        </div>
        <div style={{display:"flex",justifyContent:"flex-end",gap:8}}>
          <Btn variant="secondary" onClick={()=>{setOrgModal(null);setError("");}}>Cancel</Btn>
          <Btn onClick={()=>createOrg(orgModal)} disabled={creating}>{creating?"Creating...":"Create Client"}</Btn>
        </div>
      </div>}
    </Modal>

    {/* Bulk Employee Upload Modal */}
    <Modal open={!!bulkModal} onClose={()=>{setBulkModal(null);setBulkResults(null);setError("");}}>
      {bulkModal&&<div>
        <h3 style={{margin:"0 0 8px",color:C.text,fontSize:16,fontWeight:800}}>Bulk Employee Upload</h3>
        <p style={{color:C.textMuted,fontSize:12,marginBottom:12}}>Upload Excel with employee names. Accounts will be auto-created with credentials (no invite email sent).</p>
        {error&&<div style={{padding:"8px 12px",background:C.redBg,border:`1px solid ${C.red}44`,borderRadius:8,color:C.red,fontSize:12,marginBottom:12}}>{error}</div>}
        <div style={{padding:12,background:C.bg,borderRadius:8,border:`1px solid ${C.border}`,marginBottom:12}}>
          <div style={{fontSize:11,color:C.textDim,marginBottom:6,fontWeight:700}}>EXCEL FORMAT:</div>
          <div style={{fontSize:12,color:C.textMuted}}>Column: <strong style={{color:C.text}}>Name</strong> (required), <strong style={{color:C.text}}>Email</strong> (optional — auto-generated if missing)</div>
          <div style={{fontSize:11,color:C.textDim,marginTop:4}}>Role: Client Employee (training access only)</div>
        </div>
        {!bulkResults&&<>
          <FileUploadBtn label="Upload Excel File" accept=".xlsx,.xls,.csv" onFile={(f)=>setBulkModal(m=>({...m,file:f}))}/>
          {bulkModal.file&&<div style={{fontSize:12,color:C.green,marginTop:4}}>📄 {bulkModal.file.name}</div>}
          <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}>
            <Btn variant="secondary" onClick={()=>{setBulkModal(null);setError("");}}>Cancel</Btn>
            <Btn onClick={()=>handleBulkUpload(bulkModal.file,bulkModal.orgId)} disabled={!bulkModal.file||creating}>{creating?"Processing...":"Create Accounts"}</Btn>
          </div>
        </>}
        {bulkResults&&<>
          <div style={{marginBottom:12}}>
            <div style={{fontSize:13,fontWeight:700,color:C.green,marginBottom:4}}>✅ {bulkResults.filter(r=>r.status.includes("✅")).length} created, ❌ {bulkResults.filter(r=>r.status.includes("❌")).length} failed</div>
          </div>
          <div style={{maxHeight:300,overflowY:"auto",border:`1px solid ${C.border}`,borderRadius:8}}>
            <table style={{width:"100%",borderCollapse:"collapse",fontSize:11}}>
              <thead><tr style={{background:C.bg}}><th style={{padding:"6px 8px",textAlign:"left",color:C.textDim}}>Name</th><th style={{padding:"6px 8px",textAlign:"left",color:C.textDim}}>Email</th><th style={{padding:"6px 8px",textAlign:"left",color:C.textDim}}>Temp Password</th><th style={{padding:"6px 8px",textAlign:"left",color:C.textDim}}>Status</th></tr></thead>
              <tbody>{bulkResults.map((r,i)=>(
                <tr key={i} style={{borderBottom:`1px solid ${C.border}22`}}><td style={{padding:"5px 8px",color:C.text}}>{r.name}</td><td style={{padding:"5px 8px",color:C.textMuted}}>{r.email}</td><td style={{padding:"5px 8px",color:C.orange,fontFamily:"monospace"}}>{r.password || "-"}</td><td style={{padding:"5px 8px"}}>{r.status}</td></tr>
              ))}</tbody>
            </table>
          </div>
          <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}>
            <Btn variant="secondary" onClick={()=>exportCredentials(bulkResults)}><Download size={12}/> Export Credentials (with Passwords)</Btn>
            <Btn onClick={()=>{setBulkModal(null);setBulkResults(null);}}>Done</Btn>
          </div>
        </>}
      </div>}
    </Modal>

    {/* Role Reference */}
    <Card title="Role Permissions" style={{marginTop:16}}>
      <div style={{overflowX:"auto"}}>
        <table style={{width:"100%",borderCollapse:"collapse",fontSize:11}}>
          <thead><tr style={{borderBottom:`1px solid ${C.border}`}}>
            <th style={{textAlign:"left",padding:"8px 6px",color:C.textDim}}>Role</th><th style={{padding:"8px 6px",color:C.textDim}}>Type</th><th style={{padding:"8px 6px",color:C.textDim}}>Dashboard</th><th style={{padding:"8px 6px",color:C.textDim}}>ISMS Modules</th><th style={{padding:"8px 6px",color:C.textDim}}>Workflow</th><th style={{padding:"8px 6px",color:C.textDim}}>Training</th><th style={{padding:"8px 6px",color:C.textDim}}>Admin</th>
          </tr></thead>
          <tbody>{Object.entries(ROLES).map(([k,R])=>(
            <tr key={k} style={{borderBottom:`1px solid ${C.border}22`}}>
              <td style={{padding:"6px",color:R.color,fontWeight:700}}>{R.badge} {R.label}</td>
              <td style={{padding:"6px",color:C.textMuted,textAlign:"center"}}>{R.type}</td>
              <td style={{padding:"6px",color:C.textMuted,textAlign:"center"}}>{canView(k,"dashboard")?"✓":"—"}</td>
              <td style={{padding:"6px",color:C.textMuted,textAlign:"center"}}>{canEdit(k,"risk")?"Edit":canView(k,"risk")?"View":"—"}</td>
              <td style={{padding:"6px",color:C.textMuted,textAlign:"center"}}>{canApprove(k,"workflow")?"Approve":hasPerm(k,"workflow","upload")?"Upload":"—"}</td>
              <td style={{padding:"6px",color:C.textMuted,textAlign:"center"}}>{canEdit(k,"training")?"Edit":canView(k,"training")?"View":"—"}</td>
              <td style={{padding:"6px",color:C.textMuted,textAlign:"center"}}>{canView(k,"admin_panel")?"✓":"—"}</td>
            </tr>
          ))}</tbody>
        </table>
      </div>
    </Card>
    <style>{`@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}`}</style>
  </div>);
};

// =============================================
// CLIENT ADMIN DASHBOARD
// =============================================
const ClientAdminDashboard = ({data,rbac,orgId,members}) => {
  const orgMems = members.filter(m=>m.orgId===orgId);
  const employees = orgMems.filter(m=>m.role==="client_employee");
  const trainings = data?.trainings||[];
  const completedTrainings = trainings.filter(t=>t.status==="Completed");

  // Count employees who attended training
  const attendedSet = new Set();
  completedTrainings.forEach(t=>{if(t.attendees) t.attendees.forEach(a=>attendedSet.add(a));});
  const attended = employees.filter(e=>attendedSet.has(e.email)||attendedSet.has(e.name)).length;
  const notAttended = employees.length - attended;

  // Gap stats
  const resp = data?.gapResponses||{};
  let totalQ=0,answered=0;
  GAP_QUESTIONS.forEach(q=>{totalQ++;if(resp[q.id]?.resp)answered++;});
  const gapPct = totalQ>0?Math.round(answered/totalQ*100):0;

  // Workflow stats
  const wfCfg = data?.workflowConfig||{};
  const wfRecs = data?.workflowRecords||[];
  let wfDone=0;
  WORKFLOW_CONTROLS.forEach(c=>{
    const recs=wfRecs.filter(r=>r.controlId===c.id);
    const approved = recs.find(r=>r.status==="approved");
    if(approved) wfDone++;
  });
  const wfPct = Math.round(wfDone/WORKFLOW_CONTROLS.length*100);

  const pendingEvidence = wfRecs.filter(r=>r.status==="uploaded").length;
  const overdue = WORKFLOW_CONTROLS.filter(c=>{
    const recs=wfRecs.filter(r=>r.controlId===c.id);
    const last=recs.find(r=>r.status==="approved");
    if(!last) return true;
    const freq=wfCfg[c.id]?.frequency||c.defaultFreq;
    return daysUntilDue(calcNextDue(last.date,freq))<0;
  }).length;

  return (<div>
    <h2 style={{margin:"0 0 16px",fontSize:22,fontWeight:800,color:C.text}}>Client Dashboard</h2>
    <div style={{display:"flex",gap:16,flexWrap:"wrap",marginBottom:20}}>
      <Stat label="Overall Compliance" value={`${Math.round(wfPct*0.6+gapPct*0.4)}%`} icon={Shield} color={C.orange}/>
      <Stat label="Workflow Controls" value={`${wfDone}/${WORKFLOW_CONTROLS.length}`} icon={Activity} color={C.blue}/>
      <Stat label="Pending Reviews" value={pendingEvidence} icon={Clock} color={C.yellow}/>
      <Stat label="Overdue Items" value={overdue} icon={AlertCircle} color={C.red}/>
    </div>
    <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16,marginBottom:16}}>
      <Card title="Training Attendance">
        <div style={{display:"flex",gap:20,alignItems:"center",padding:"12px 0"}}>
          <div style={{textAlign:"center"}}><div style={{fontSize:32,fontWeight:800,color:C.green}}>{attended}</div><div style={{fontSize:11,color:C.textMuted}}>Attended</div></div>
          <div style={{textAlign:"center"}}><div style={{fontSize:32,fontWeight:800,color:C.red}}>{notAttended}</div><div style={{fontSize:11,color:C.textMuted}}>Not Attended</div></div>
          <div style={{textAlign:"center"}}><div style={{fontSize:32,fontWeight:800,color:C.text}}>{employees.length}</div><div style={{fontSize:11,color:C.textMuted}}>Total Employees</div></div>
        </div>
      </Card>
      <Card title="Team Members">
        <div style={{display:"flex",flexDirection:"column",gap:4,maxHeight:200,overflowY:"auto"}}>
          {orgMems.map(m=>{const R=ROLES[m.role]; return (
            <div key={m.id} style={{display:"flex",alignItems:"center",gap:8,padding:"4px 0"}}>
              <span style={{fontSize:12}}>{R?.badge}</span>
              <span style={{fontSize:12,color:C.text,fontWeight:600}}>{m.name}</span>
              <span style={{fontSize:10,color:C.textDim}}>{m.email}</span>
              <Badge color={R?.color}>{R?.label}</Badge>
            </div>
          );})}
          {orgMems.length===0&&<div style={{color:C.textDim,fontSize:12}}>No team members</div>}
        </div>
      </Card>
    </div>
  </div>);
};

// =============================================
// NAVIGATION
// =============================================



// =============================================
// THIRD PARTY RISK ASSESSMENT (TPRA)
// =============================================

// Vendor Security Questionnaire (15 questions across key domains)
const VENDOR_QUESTIONS = [
  {id:"q1", domain:"Data Protection", q:"Does the vendor encrypt data at rest and in transit?", weight:3},
  {id:"q2", domain:"Data Protection", q:"Does the vendor have a documented data classification policy?", weight:2},
  {id:"q3", domain:"Data Protection", q:"Does the vendor have data retention and disposal procedures?", weight:2},
  {id:"q4", domain:"Access Control", q:"Does the vendor implement role-based access control (RBAC)?", weight:3},
  {id:"q5", domain:"Access Control", q:"Does the vendor enforce multi-factor authentication (MFA)?", weight:3},
  {id:"q6", domain:"Incident Management", q:"Does the vendor have a documented incident response plan?", weight:3},
  {id:"q7", domain:"Incident Management", q:"Will the vendor notify you of security breaches within 72 hours?", weight:3},
  {id:"q8", domain:"Business Continuity", q:"Does the vendor have a business continuity/disaster recovery plan?", weight:2},
  {id:"q9", domain:"Business Continuity", q:"Does the vendor perform regular backups with tested recovery?", weight:2},
  {id:"q10", domain:"Compliance", q:"Does the vendor hold ISO 27001 or SOC 2 certification?", weight:3},
  {id:"q11", domain:"Compliance", q:"Does the vendor comply with applicable data protection laws (DPDP/GDPR)?", weight:3},
  {id:"q12", domain:"Network Security", q:"Does the vendor perform regular vulnerability assessments and penetration testing?", weight:2},
  {id:"q13", domain:"Network Security", q:"Does the vendor have firewall and intrusion detection/prevention systems?", weight:2},
  {id:"q14", domain:"HR & Physical", q:"Does the vendor conduct background checks on employees with data access?", weight:2},
  {id:"q15", domain:"HR & Physical", q:"Does the vendor have physical security controls for data centers/offices?", weight:1},
];

const VENDOR_ANSWER_OPTIONS = [
  {value:"yes", label:"Yes", score:1, color:"#16a34a"},
  {value:"partial", label:"Partially", score:0.5, color:"#f59e0b"},
  {value:"no", label:"No", score:0, color:"#ef4444"},
  {value:"na", label:"N/A", score:null, color:"#94a3b8"},
  {value:"unknown", label:"Unknown", score:0, color:"#64748b"},
];

const VENDOR_CATEGORIES = ["Cloud/SaaS","IT Services","Consulting","Payroll/HR","Legal","Financial","Marketing","Logistics","Telecom","Other"];
const CRITICALITY_OPTIONS = [{value:"critical",label:"Critical",color:"#ef4444"},{value:"high",label:"High",color:"#f97316"},{value:"medium",label:"Medium",color:"#f59e0b"},{value:"low",label:"Low",color:"#16a34a"}];
const DATA_TYPES = ["Personal Data","Financial Data","Health Data","IP/Trade Secrets","Customer Data","Employee Data","Public Data Only","No Data Access"];

const COMPLIANCE_DOCS = [
  {id:"iso27001", name:"ISO 27001 Certificate", icon:"🛡️"},
  {id:"soc2", name:"SOC 2 Report", icon:"📋"},
  {id:"nda", name:"NDA (Non-Disclosure Agreement)", icon:"🔒"},
  {id:"dpa", name:"DPA (Data Processing Agreement)", icon:"📝"},
  {id:"sla", name:"SLA (Service Level Agreement)", icon:"📊"},
  {id:"insurance", name:"Cyber Insurance", icon:"🛡️"},
  {id:"gdpr", name:"GDPR/DPDP Compliance Declaration", icon:"🏛️"},
  {id:"pentest", name:"Latest Pen Test Report", icon:"🔍"},
];

const VendorRiskModule = ({data,setData,role:userRole}) => {
  const [tab,setTab]=useState("dashboard"); // dashboard|registry|assess|detail
  const [selVendorId,setSelVendorId]=useState(null);
  const [modal,setModal]=useState(null); // {type:"vendor"|"doc", data:{...}}
  const [toast,setToast]=useState(null);
  const [search,setSearch]=useState("");
  const [scanning,setScanning]=useState(false);
  const [scanError,setScanError]=useState(null);
  const {token,user,orgId}=useAuth();
  const isAdmin=["super_admin","employee","client_admin"].includes(userRole);
  const vendors=data.vendors||[];

  // ===== VENDOR CRUD =====
  const saveVendor=(v)=>{
    if(v.id){
      setData(d=>({...d,vendors:d.vendors.map(x=>x.id===v.id?v:x)}));
    } else {
      const nv={...v,id:secureId('vnd'),answers:{},docs:{},created_at:new Date().toISOString(),created_by:user?.email};
      setData(d=>({...d,vendors:[...d.vendors,nv]}));
      setSelVendorId(nv.id);
    }
    setModal(null);setToast({msg:"Vendor saved!",type:"success"});
  };
  const delVendor=(id)=>{setData(d=>({...d,vendors:d.vendors.filter(v=>v.id!==id)}));if(selVendorId===id)setSelVendorId(null);setToast({msg:"Vendor removed",type:"success"});};

  // ===== QUESTIONNAIRE =====
  const setAnswer=(vendorId,qId,answer)=>{
    setData(d=>({...d,vendors:d.vendors.map(v=>{
      if(v.id!==vendorId)return v;
      const answers={...(v.answers||{}), [qId]:answer};
      return{...v, answers, assessed_at:new Date().toISOString()};
    })}));
  };

  // ===== COMPLIANCE DOCS =====
  const setDocStatus=(vendorId,docId,status)=>{
    setData(d=>({...d,vendors:d.vendors.map(v=>{
      if(v.id!==vendorId)return v;
      const docs={...(v.docs||{}), [docId]:{...((v.docs||{})[docId]||{}), ...status, updated_at:new Date().toISOString()}};
      return{...v,docs};
    })}));
  };

  // ===== RISK SCORING (scan results OR questionnaire fallback) =====
  const calcRiskScore=(vendor)=>{
    const scan=vendor.scan_report;
    if(scan&&scan.risk_score){
      const rs=scan.risk_score;
      return{score:rs.overall_score,pct:rs.overall_score,rating:rs.risk_level,
        color:rs.overall_score>=80?C.green:rs.overall_score>=60?C.yellow:rs.overall_score>=40?C.orange:C.red,
        answeredCount:rs.findings_summary?.total||0,grade:rs.letter_grade,fromScan:true};
    }
    const answers=vendor.answers||{};
    let totalWeight=0, totalScore=0, answeredCount=0;
    VENDOR_QUESTIONS.forEach(q=>{
      const a=answers[q.id];
      if(!a||a==="na") return;
      answeredCount++;
      const opt=VENDOR_ANSWER_OPTIONS.find(o=>o.value===a);
      if(opt&&opt.score!==null){totalWeight+=q.weight;totalScore+=opt.score*q.weight;}
    });
    if(totalWeight===0) return{score:0,pct:0,rating:"Not Assessed",color:C.textDim,answeredCount,fromScan:false};
    const pct=Math.round((totalScore/totalWeight)*100);
    let rating,color;
    if(pct>=80){rating="Low Risk";color=C.green;}
    else if(pct>=60){rating="Medium Risk";color=C.yellow;}
    else if(pct>=40){rating="High Risk";color=C.orange;}
    else{rating="Critical Risk";color=C.red;}
    if(vendor.criticality==="critical"&&pct<80){rating="Critical Risk";color=C.red;}
    if(vendor.criticality==="high"&&pct<60){rating="High Risk";color=C.orange;}
    return{score:totalScore,pct,rating,color,answeredCount,fromScan:false};
  };

  // ===== STATS =====
  const stats=useMemo(()=>{
    let total=vendors.length, assessed=0, critical=0, high=0, medium=0, low=0, docsComplete=0;
    vendors.forEach(v=>{
      const r=calcRiskScore(v);
      if(r.answeredCount>0||v.scan_report) assessed++;
      if(r.rating==="Critical Risk") critical++;
      else if(r.rating==="High Risk") high++;
      else if(r.rating==="Medium Risk") medium++;
      else if(r.rating==="Low Risk") low++;
      // Docs completeness
      const docCount=COMPLIANCE_DOCS.filter(d=>(v.docs||{})[d.id]?.status==="received").length;
      if(docCount>=4) docsComplete++;
    });
    return{total,assessed,critical,high,medium,low,docsComplete};
  },[vendors]);

  // ===== FILTERED =====
  const filtered=useMemo(()=>{
    if(!search) return vendors;
    const q=search.toLowerCase();
    return vendors.filter(v=>(v.name||"").toLowerCase().includes(q)||(v.category||"").toLowerCase().includes(q));
  },[vendors,search]);

  const selVendor=vendors.find(v=>v.id===selVendorId);

  // ===== VENDOR FORM MODAL =====
  const VendorFormModal=({v,onSave})=>{
    const [f,setF]=useState({name:"",category:"Cloud/SaaS",service_description:"",criticality:"medium",data_types:[],contact_name:"",contact_email:"",contract_start:"",contract_end:"",notes:"",...v});
    const u=(k,val)=>setF(x=>({...x,[k]:val}));
    const toggleDataType=(dt)=>{
      setF(x=>({...x,data_types:(x.data_types||[]).includes(dt)?(x.data_types||[]).filter(d=>d!==dt):[...(x.data_types||[]),dt]}));
    };
    return(<div>
      <Input label="Vendor Name *" value={f.name} onChange={v=>u("name",v)} placeholder="e.g., Amazon Web Services"/>
      <Input label="Website URL *" value={f.website_url||""} onChange={v=>u("website_url",v)} placeholder="e.g., https://aws.amazon.com"/>
      <Input label="Service Description" value={f.service_description} onChange={v=>u("service_description",v)} placeholder="e.g., Cloud hosting for production infrastructure"/>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
        <Input label="Category" value={f.category} onChange={v=>u("category",v)} select options={VENDOR_CATEGORIES.map(c=>({value:c,label:c}))}/>
        <Input label="Business Criticality" value={f.criticality} onChange={v=>u("criticality",v)} select options={CRITICALITY_OPTIONS.map(c=>({value:c.value,label:c.label}))}/>
      </div>
      <div style={{marginBottom:14}}>
        <label style={{display:"block",fontSize:12,color:C.textMuted,marginBottom:6,fontWeight:600}}>Data Types Accessed</label>
        <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
          {DATA_TYPES.map(dt=>{
            const sel=(f.data_types||[]).includes(dt);
            return(<button key={dt} onClick={()=>toggleDataType(dt)} style={{padding:"5px 12px",borderRadius:16,border:`1px solid ${sel?C.orange:C.border}`,background:sel?`${C.orange}22`:"transparent",color:sel?C.orange:C.textMuted,fontSize:11,fontWeight:600,cursor:"pointer",fontFamily:"inherit"}}>{dt}</button>);
          })}
        </div>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
        <Input label="Contact Person" value={f.contact_name} onChange={v=>u("contact_name",v)} placeholder="Vendor contact name"/>
        <Input label="Contact Email" value={f.contact_email} onChange={v=>u("contact_email",v)} placeholder="vendor@example.com"/>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
        <div style={{marginBottom:12}}><label style={{display:"block",fontSize:12,color:C.textMuted,marginBottom:4,fontWeight:600}}>Contract Start</label><input type="date" value={f.contract_start||""} onChange={e=>u("contract_start",e.target.value)} style={{width:"100%",padding:"8px 12px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,color:C.text,fontSize:13,fontFamily:"inherit",boxSizing:"border-box"}}/></div>
        <div style={{marginBottom:12}}><label style={{display:"block",fontSize:12,color:C.textMuted,marginBottom:4,fontWeight:600}}>Contract End</label><input type="date" value={f.contract_end||""} onChange={e=>u("contract_end",e.target.value)} style={{width:"100%",padding:"8px 12px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:8,color:C.text,fontSize:13,fontFamily:"inherit",boxSizing:"border-box"}}/></div>
      </div>
      <Input label="Notes" value={f.notes} onChange={v=>u("notes",v)} textarea placeholder="Any additional notes..."/>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:16}}>
        <Btn variant="secondary" onClick={()=>setModal(null)}>Cancel</Btn>
        <Btn onClick={()=>{if(!f.name)return setToast({msg:"Vendor name required",type:"error"});onSave(f);}}><Save size={14}/> Save</Btn>
      </div>
    </div>);
  };

  // ===== EXPORT =====
  const exportVendors=()=>{
    const rows=vendors.map(v=>{
      const r=calcRiskScore(v);
      const docStatus=COMPLIANCE_DOCS.map(d=>`${d.name}: ${(v.docs||{})[d.id]?.status||'pending'}`).join('; ');
      return{"Vendor":v.name,"Website":v.website_url||"","Category":v.category,"Criticality":v.criticality,"Data Types":(v.data_types||[]).join(', '),"Risk Score":r.pct+"%","Risk Rating":r.rating,"Source":r.fromScan?"Scan":"Questionnaire","Questions Answered":r.answeredCount+"/"+VENDOR_QUESTIONS.length,"Contract Start":v.contract_start||"","Contract End":v.contract_end||"","Documents":docStatus,"Contact":v.contact_name||"","Email":v.contact_email||""};
    });
    const wb=XLSX.utils.book_new();
    const ws=XLSX.utils.json_to_sheet(rows);
    ws["!cols"]=[{wch:25},{wch:12},{wch:10},{wch:30},{wch:10},{wch:14},{wch:16},{wch:12},{wch:12},{wch:50},{wch:20},{wch:25}];
    XLSX.utils.book_append_sheet(wb,ws,"Vendor Risk");
    XLSX.writeFile(wb,"Vendor_Risk_Assessment.xlsx");
    auditLog(token,"data_export",{resource_type:"vendor_risk",org_id:orgId},"warning");
  };

  const fmtDate=(d)=>d?new Date(d).toLocaleDateString("en-IN",{day:"numeric",month:"short",year:"numeric"}):"—";
  const critColor=(c)=>(CRITICALITY_OPTIONS.find(o=>o.value===c)||{}).color||C.textMuted;

  return (<div>
    {toast&&<Toast {...toast} onClose={()=>setToast(null)}/>}

    {/* Header */}
    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20,flexWrap:"wrap",gap:12}}>
      <div>
        <h2 style={{margin:0,fontSize:22,fontWeight:800,color:C.text}}>Third Party Risk Assessment</h2>
        <p style={{margin:"4px 0 0",fontSize:13,color:C.textMuted}}>Vendor registry, security assessment & compliance tracking</p>
      </div>
      <div style={{display:"flex",gap:8}}>
        {vendors.length>0&&<Btn variant="secondary" onClick={exportVendors}><Download size={14}/> Export</Btn>}
        {isAdmin&&<Btn onClick={()=>setModal({type:"vendor",data:{}})}><Plus size={14}/> Add Vendor</Btn>}
      </div>
    </div>

    {/* Stats */}
    {vendors.length>0&&<div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(110px,1fr))",gap:12,marginBottom:20}}>
      {[
        {label:"Total Vendors",val:stats.total,col:C.text},
        {label:"Assessed",val:stats.assessed,col:C.blue},
        {label:"Critical",val:stats.critical,col:C.red},
        {label:"High Risk",val:stats.high,col:C.orange},
        {label:"Medium Risk",val:stats.medium,col:C.yellow},
        {label:"Low Risk",val:stats.low,col:C.green},
      ].map(s=><div key={s.label} style={{background:C.card,borderRadius:10,padding:"12px 14px",border:`1px solid ${s.col}22`}}>
        <div style={{fontSize:11,color:C.textMuted,fontWeight:600}}>{s.label}</div>
        <div style={{fontSize:22,fontWeight:800,color:s.col}}>{s.val}</div>
      </div>)}
    </div>}

    {/* Tabs */}
    <div style={{display:"flex",gap:4,marginBottom:20,background:C.card,borderRadius:10,padding:4,width:"fit-content",flexWrap:"wrap"}}>
      {[{id:"dashboard",label:"Dashboard"},{id:"registry",label:"Vendor Registry"},
        ...(selVendorId?[{id:"assess",label:"Assessment"},{id:"detail",label:"Details"}]:[])
      ].map(t=><button key={t.id} onClick={()=>setTab(t.id)} style={{padding:"8px 20px",border:"none",borderRadius:8,cursor:"pointer",fontWeight:700,fontSize:13,background:tab===t.id?C.orange:"transparent",color:tab===t.id?"#fff":C.textMuted,fontFamily:"inherit"}}>{t.label}</button>)}
    </div>

    {/* ===== DASHBOARD ===== */}
    {tab==="dashboard"&&(<>
      {vendors.length===0?(<Card>
        <div style={{textAlign:"center",padding:30}}>
          <div style={{width:64,height:64,borderRadius:"50%",background:`${C.orange}22`,display:"flex",alignItems:"center",justifyContent:"center",margin:"0 auto 16px"}}><Flag size={32} color={C.orange}/></div>
          <h3 style={{color:C.text,margin:"0 0 8px",fontSize:18,fontWeight:800}}>Third Party Risk Assessment</h3>
          <p style={{color:C.textMuted,fontSize:13,margin:"0 0 20px",maxWidth:450,marginLeft:"auto",marginRight:"auto"}}>Add your vendors and assess their security posture with a standardized questionnaire. Track compliance documents and monitor risk levels.</p>
          {isAdmin&&<Btn onClick={()=>setModal({type:"vendor",data:{}})}><Plus size={14}/> Add Your First Vendor</Btn>}
        </div>
      </Card>):(<>
        {/* Risk distribution chart */}
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16,marginBottom:20}}>
          <Card title="Risk Distribution">
            <div style={{height:200}}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={[
                    {name:"Critical",value:stats.critical,fill:C.red},
                    {name:"High",value:stats.high,fill:C.orange},
                    {name:"Medium",value:stats.medium,fill:C.yellow},
                    {name:"Low",value:stats.low,fill:C.green},
                    {name:"Not Assessed",value:stats.total-stats.assessed,fill:C.textDim},
                  ].filter(d=>d.value>0)} cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={3} dataKey="value">
                    {[C.red,C.orange,C.yellow,C.green,C.textDim].map((c,i)=><Cell key={i} fill={c}/>)}
                  </Pie>
                  <Tooltip/>
                  <Legend/>
                </PieChart>
              </ResponsiveContainer>
            </div>
          </Card>
          <Card title="Vendors Needing Attention">
            <div style={{maxHeight:200,overflowY:"auto"}}>
              {vendors.filter(v=>{const r=calcRiskScore(v);return r.rating==="Critical Risk"||r.rating==="High Risk"||(r.answeredCount===0&&!v.scan_report);}).length===0?
                <div style={{textAlign:"center",padding:20,color:C.textMuted,fontSize:13}}>{"\u2705"} All vendors look good!</div>:
                vendors.filter(v=>{const r=calcRiskScore(v);return r.rating==="Critical Risk"||r.rating==="High Risk"||(r.answeredCount===0&&!v.scan_report);}).map(v=>{
                  const r=calcRiskScore(v);
                  return(<div key={v.id} onClick={()=>{setSelVendorId(v.id);setTab("assess");}} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"8px 12px",borderRadius:8,cursor:"pointer",background:C.bg,marginBottom:4,border:`1px solid ${C.border}`}}>
                    <div><div style={{fontSize:13,fontWeight:600,color:C.text}}>{v.name}</div><div style={{fontSize:11,color:C.textDim}}>{r.answeredCount===0&&!v.scan_report?"Not scanned yet":r.rating}</div></div>
                    <Badge color={r.color}>{r.answeredCount===0&&!v.scan_report?"Pending":r.pct+"%"}</Badge>
                  </div>);
                })
              }
            </div>
          </Card>
        </div>

        {/* All vendors quick list */}
        <Card title="All Vendors">
          <div style={{overflowX:"auto"}}><table style={{width:"100%",borderCollapse:"collapse",fontSize:13}}><thead><tr style={{background:C.bg}}>
            {["Vendor","Category","Criticality","Data Access","Risk Score","Status",""].map(h=><th key={h} style={{padding:"10px 12px",textAlign:"left",color:C.textMuted,fontWeight:700,fontSize:11,textTransform:"uppercase",borderBottom:`1px solid ${C.border}`}}>{h}</th>)}
          </tr></thead><tbody>
            {vendors.map(v=>{
              const r=calcRiskScore(v);
              return(<tr key={v.id} style={{borderBottom:`1px solid ${C.border}22`,cursor:"pointer"}} onClick={()=>{setSelVendorId(v.id);setTab("assess");}}>
                <td style={{padding:"10px 12px"}}><div style={{fontWeight:600,color:C.text}}>{v.name}</div>{v.service_description&&<div style={{fontSize:11,color:C.textDim}}>{v.service_description.substring(0,40)}</div>}</td>
                <td style={{padding:"10px 12px",color:C.textMuted,fontSize:12}}>{v.category}</td>
                <td style={{padding:"10px 12px"}}><Badge color={critColor(v.criticality)}>{v.criticality}</Badge></td>
                <td style={{padding:"10px 12px",fontSize:11,color:C.textMuted}}>{(v.data_types||[]).slice(0,2).join(", ")}{(v.data_types||[]).length>2?` +${(v.data_types||[]).length-2}`:""}</td>
                <td style={{padding:"10px 12px"}}>
                  <div style={{display:"flex",alignItems:"center",gap:8}}>
                    <div style={{width:50,height:6,background:C.bg,borderRadius:3,overflow:"hidden"}}><div style={{height:"100%",width:`${r.pct}%`,background:r.color,borderRadius:3}}/></div>
                    <span style={{fontSize:12,fontWeight:700,color:r.color}}>{r.answeredCount>0?r.pct+"%":"—"}</span>
                  </div>
                </td>
                <td style={{padding:"10px 12px"}}><Badge color={r.color}>{r.rating}</Badge></td>
                <td style={{padding:"10px 12px"}}><ChevronRight size={14} color={C.textDim}/></td>
              </tr>);
            })}
          </tbody></table></div>
        </Card>
      </>)}
    </>)}

    {/* ===== VENDOR REGISTRY ===== */}
    {tab==="registry"&&(<>
      <div style={{marginBottom:16,position:"relative",maxWidth:360}}>
        <Search size={16} style={{position:"absolute",left:12,top:"50%",transform:"translateY(-50%)",color:C.textDim}}/>
        <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search vendors..." style={{width:"100%",padding:"10px 12px 10px 36px",background:C.card,border:`1px solid ${C.border}`,borderRadius:10,color:C.text,fontSize:13,fontFamily:"inherit",boxSizing:"border-box"}}/>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(320px,1fr))",gap:14}}>
        {filtered.map(v=>{
          const r=calcRiskScore(v);
          const docsReceived=COMPLIANCE_DOCS.filter(d=>(v.docs||{})[d.id]?.status==="received").length;
          const contractExpiring=v.contract_end&&new Date(v.contract_end)<new Date(Date.now()+30*86400000);
          return(<div key={v.id} style={{background:C.card,borderRadius:12,border:`1px solid ${C.border}`,padding:18,cursor:"pointer",transition:"border-color 0.2s"}} onClick={()=>{setSelVendorId(v.id);setTab("assess");}} onMouseEnter={e=>e.currentTarget.style.borderColor=C.orange} onMouseLeave={e=>e.currentTarget.style.borderColor=C.border}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:10}}>
              <div>
                <h3 style={{margin:0,fontSize:15,fontWeight:700,color:C.text}}>{v.name}</h3>
                <div style={{fontSize:11,color:C.textDim,marginTop:2}}>{v.category} • {v.service_description||"No description"}</div>
              </div>
              <Badge color={critColor(v.criticality)}>{v.criticality}</Badge>
            </div>
            {/* Risk bar */}
            <div style={{marginBottom:10}}>
              <div style={{display:"flex",justifyContent:"space-between",fontSize:11,color:C.textMuted,marginBottom:4}}><span>Risk Score</span><span style={{fontWeight:700,color:r.color}}>{r.answeredCount>0?r.pct+"%":"Not assessed"}</span></div>
              <div style={{height:6,background:C.bg,borderRadius:3,overflow:"hidden"}}><div style={{height:"100%",width:`${r.pct}%`,background:r.color,borderRadius:3,transition:"width 0.3s"}}/></div>
            </div>
            <div style={{display:"flex",gap:10,fontSize:11,color:C.textMuted,flexWrap:"wrap"}}>
              <span>{v.scan_report?"\uD83D\uDD0D Scanned":`\uD83D\uDCCB ${r.answeredCount}/${VENDOR_QUESTIONS.length} assessed`}</span>
              <span>📎 {docsReceived}/{COMPLIANCE_DOCS.length} docs</span>
              {contractExpiring&&<span style={{color:C.red}}>⚠ Contract expiring</span>}
              {v.contract_end&&<span>🗓 Ends {fmtDate(v.contract_end)}</span>}
            </div>
            {isAdmin&&<div style={{display:"flex",gap:4,marginTop:10,justifyContent:"flex-end"}} onClick={e=>e.stopPropagation()}>
              <button onClick={()=>setModal({type:"vendor",data:{...v}})} style={{background:"none",border:"none",cursor:"pointer",color:C.orange,padding:4}}><Edit3 size={14}/></button>
              <button onClick={()=>delVendor(v.id)} style={{background:"none",border:"none",cursor:"pointer",color:C.red,padding:4}}><Trash2 size={14}/></button>
            </div>}
          </div>);
        })}
      </div>
    </>)}

    {/* ===== ASSESSMENT TAB (ATTACK SURFACE SCAN) ===== */}
    {tab==="assess"&&selVendor&&(<div>
      <div style={{display:"flex",alignItems:"center",gap:12,marginBottom:16,flexWrap:"wrap"}}>
        <button onClick={()=>{setSelVendorId(null);setTab("dashboard");}} style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:8,padding:"8px 12px",cursor:"pointer",color:C.text,display:"flex",alignItems:"center",gap:4,fontFamily:"inherit",fontSize:13}}><ArrowLeft size={14}/> Back</button>
        <div style={{flex:1}}>
          <h3 style={{margin:0,fontSize:18,fontWeight:800,color:C.text}}>{selVendor.name}</h3>
          <span style={{fontSize:12,color:C.textMuted}}>{selVendor.category} • {selVendor.criticality} criticality{selVendor.website_url?` • ${selVendor.website_url}`:""}</span>
        </div>
        {isAdmin&&<Btn size="sm" variant="secondary" onClick={()=>setModal({type:"vendor",data:{...selVendor}})}><Edit3 size={13}/> Edit</Btn>}
        <Btn size="sm" variant="secondary" onClick={()=>setTab("detail")}><Eye size={13}/> Details & Docs</Btn>
      </div>

      {/* Scan UI */}
      {(()=>{
        const r=calcRiskScore(selVendor);
        const scan=selVendor.scan_report;

        const runScan=async()=>{
          const url=selVendor.website_url;
          if(!url){setToast({msg:"Add a website URL first (Edit → Website URL)",type:"error"});return;}
          setScanning(true);setScanError(null);
          try{
            const resp=await fetch("/api/vendor-scan",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url})});
            if(!resp.ok)throw new Error((await resp.json()).error||"Scan failed");
            const report=await resp.json();
            setData(d=>({...d,vendors:d.vendors.map(v=>v.id===selVendor.id?{...v,scan_report:report,scanned_at:new Date().toISOString()}:v)}));
            setToast({msg:`Scan complete! Score: ${report.risk_score.overall_score}/100 (${report.risk_score.risk_level})`,type:"success"});
          }catch(e){setScanError(e.message);setToast({msg:"Scan failed: "+e.message,type:"error"});}
          setScanning(false);
        };

        const downloadReport=()=>{
          if(!scan)return;
          const sev_colors={critical:"#dc2626",high:"#ea580c",medium:"#d97706",low:"#2563eb",info:"#6b7280"};
          const rs=scan.risk_score;
          const sc_color=rs.overall_score>=80?"#22c55e":rs.overall_score>=60?"#f59e0b":rs.overall_score>=40?"#f97316":"#ef4444";
          let fHtml="";
          (scan.scan_results||[]).forEach(sr=>{
            fHtml+=`<div style="background:#1e293b;border-radius:12px;padding:18px;margin-bottom:14px;">`;
            fHtml+=`<h3 style="margin:0 0 12px;color:#e2e8f0;font-size:15px;">${sr.scanner} (${sr.findings_count} findings)</h3>`;
            (sr.findings||[]).forEach(f=>{
              const sc=sev_colors[f.severity]||"#6b7280";
              fHtml+=`<div style="border-left:4px solid ${sc};background:#0f172a;border-radius:8px;padding:10px 14px;margin-bottom:8px;">
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;"><span style="background:${sc};color:#fff;padding:2px 10px;border-radius:12px;font-size:11px;font-weight:700;text-transform:uppercase;">${f.severity}</span><strong style="color:#e2e8f0;font-size:13px;">${f.title}</strong></div>
                <p style="color:#94a3b8;font-size:12px;margin:4px 0;">${f.description||""}</p>
                ${f.recommendation?`<p style="color:#22d3ee;font-size:12px;margin:4px 0;">Fix: ${f.recommendation}</p>`:""}
              </div>`;
            });
            fHtml+=`</div>`;
          });
          const html=`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Attack Surface Report - ${scan.meta.domain}</title>
            <style>*{margin:0;padding:0;box-sizing:border-box;}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;padding:40px;}</style></head>
            <body><div style="max-width:900px;margin:0 auto;">
              <div style="text-align:center;padding:30px 0;border-bottom:1px solid #1e293b;">
                <h1 style="font-size:24px;margin-bottom:8px;">Attack Surface Report</h1>
                <div style="color:#38bdf8;font-size:18px;">${scan.meta.domain}</div>
                <div style="width:120px;height:120px;border-radius:50%;border:6px solid ${sc_color};display:flex;flex-direction:column;align-items:center;justify-content:center;margin:20px auto;">
                  <div style="font-size:36px;font-weight:bold;color:${sc_color};">${rs.overall_score}</div>
                  <div style="font-size:14px;color:${sc_color};">${rs.letter_grade}</div>
                </div>
                <div style="font-size:16px;color:${sc_color};font-weight:600;">${rs.risk_level}</div>
              </div>
              <div style="display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:20px 0;">
                ${["critical","high","medium","low","info"].map(s=>`<div style="background:#1e293b;padding:14px;border-radius:10px;text-align:center;"><div style="font-size:24px;font-weight:bold;color:${sev_colors[s]};">${rs.findings_summary[s]||0}</div><div style="font-size:11px;color:#94a3b8;margin-top:4px;">${s[0].toUpperCase()+s.slice(1)}</div></div>`).join("")}
              </div>
              <h2 style="font-size:18px;color:#94a3b8;margin:24px 0 14px;">Detailed Findings</h2>
              ${fHtml}
              <div style="text-align:center;color:#64748b;font-size:12px;margin-top:30px;padding-top:20px;border-top:1px solid #1e293b;">
                <p>Scanned ${scan.meta.scan_date?.substring(0,19)} UTC | Duration: ${scan.meta.scan_duration_seconds}s</p>
                <p>SecComply Attack Surface Scanner v1.0</p>
              </div>
            </div></body></html>`;
          const blob=new Blob([html],{type:"text/html"});
          const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download=`AttackSurface_${scan.meta.domain}_${new Date().toISOString().slice(0,10)}.html`;a.click();
        };

        return(<>
          {/* Score Cards */}
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:14,marginBottom:20}}>
            <div style={{background:C.card,borderRadius:12,padding:18,border:`1px solid ${r.color}33`,textAlign:"center"}}>
              <div style={{fontSize:11,color:C.textMuted,fontWeight:600,marginBottom:4}}>Security Score</div>
              <div style={{fontSize:36,fontWeight:800,color:r.color}}>{scan?r.pct:"\u2014"}</div>
              <Badge color={r.color}>{scan?r.rating:"Not Scanned"}</Badge>
              {scan&&<div style={{fontSize:11,color:C.textDim,marginTop:6}}>Grade: {scan.risk_score.letter_grade}</div>}
            </div>
            <div style={{background:C.card,borderRadius:12,padding:18,border:`1px solid ${C.border}`,textAlign:"center"}}>
              <div style={{fontSize:11,color:C.textMuted,fontWeight:600,marginBottom:4}}>Total Findings</div>
              <div style={{fontSize:36,fontWeight:800,color:C.text}}>{scan?scan.risk_score.findings_summary.total:"\u2014"}</div>
              {scan&&<div style={{display:"flex",justifyContent:"center",gap:8,marginTop:6,fontSize:11}}>
                {scan.risk_score.findings_summary.critical>0&&<span style={{color:C.red}}>{"\u25CF"}{scan.risk_score.findings_summary.critical} Crit</span>}
                {scan.risk_score.findings_summary.high>0&&<span style={{color:C.orange}}>{"\u25CF"}{scan.risk_score.findings_summary.high} High</span>}
                {scan.risk_score.findings_summary.medium>0&&<span style={{color:C.yellow}}>{"\u25CF"}{scan.risk_score.findings_summary.medium} Med</span>}
              </div>}
            </div>
            <div style={{background:C.card,borderRadius:12,padding:18,border:`1px solid ${C.border}`,textAlign:"center"}}>
              <div style={{fontSize:11,color:C.textMuted,fontWeight:600,marginBottom:4}}>Scanners Run</div>
              <div style={{fontSize:36,fontWeight:800,color:C.text}}>{scan?scan.meta.scanners_run:"\u2014"}</div>
              {scan&&<div style={{fontSize:11,color:C.textDim,marginTop:6}}>in {scan.meta.scan_duration_seconds}s</div>}
            </div>
          </div>

          {/* Action Buttons */}
          <div style={{display:"flex",gap:10,marginBottom:20,flexWrap:"wrap"}}>
            <Btn onClick={runScan} disabled={scanning}>
              {scanning?<><Activity size={14}/> Scanning...</>:<><RefreshCw size={14}/> {scan?"Re-scan":"Run Attack Surface Scan"}</>}
            </Btn>
            {scan&&<Btn variant="secondary" onClick={downloadReport}><Download size={14}/> Download Report</Btn>}
            {!selVendor.website_url&&<span style={{fontSize:12,color:C.yellow,alignSelf:"center"}}>{"\u26A0"} Add a website URL to enable scanning</span>}
          </div>
          {scanError&&<div style={{padding:"10px 14px",background:C.redBg,border:`1px solid ${C.red}44`,borderRadius:8,color:C.red,fontSize:12,marginBottom:16}}>{scanError}</div>}

          {/* Category Breakdown */}
          {scan&&<Card title="Category Breakdown" style={{marginBottom:16}}>
            <div style={{display:"grid",gap:10}}>
              {Object.entries(scan.risk_score.category_scores||{}).map(([cat,score])=>{
                const col=score>=80?C.green:score>=60?C.yellow:score>=40?C.orange:C.red;
                return(<div key={cat} style={{display:"flex",alignItems:"center",gap:12,padding:"8px 0"}}>
                  <div style={{width:130,fontSize:12,fontWeight:600,color:C.text}}>{cat}</div>
                  <div style={{flex:1,height:8,background:C.bg,borderRadius:4,overflow:"hidden"}}><div style={{height:"100%",width:`${score}%`,background:col,borderRadius:4,transition:"width 0.3s"}}/></div>
                  <div style={{width:50,textAlign:"right",fontSize:13,fontWeight:700,color:col}}>{score}%</div>
                </div>);
              })}
            </div>
          </Card>}

          {/* Top Risks */}
          {scan&&scan.risk_score.top_risks?.length>0&&<Card title="Top Risks & Recommendations" style={{marginBottom:16}}>
            <div style={{display:"flex",flexDirection:"column",gap:8}}>
              {scan.risk_score.top_risks.map((risk,i)=>{
                const sevC={critical:C.red,high:C.orange,medium:C.yellow,low:C.blue};
                const col=sevC[risk.severity]||C.textDim;
                return(<div key={i} style={{padding:"12px 16px",background:C.bg,borderRadius:8,borderLeft:`4px solid ${col}`}}>
                  <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4}}>
                    <span style={{background:`${col}22`,color:col,padding:"2px 10px",borderRadius:12,fontSize:10,fontWeight:700,textTransform:"uppercase"}}>{risk.severity}</span>
                    <span style={{fontSize:13,fontWeight:600,color:C.text}}>{risk.title}</span>
                    <span style={{fontSize:10,color:C.textDim,marginLeft:"auto"}}>{risk.category}</span>
                  </div>
                  {risk.recommendation&&<div style={{fontSize:12,color:C.textMuted,marginTop:4}}>{"\uD83D\uDCA1"} {risk.recommendation}</div>}
                </div>);
              })}
            </div>
          </Card>}

          {/* Detailed Findings */}
          {scan&&<Card title="Detailed Scanner Findings">
            {(scan.scan_results||[]).map((sr,si)=>(
              <div key={si} style={{marginBottom:16}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"10px 0",borderBottom:`1px solid ${C.border}`,marginBottom:8}}>
                  <h4 style={{margin:0,fontSize:14,fontWeight:700,color:C.orange}}>{sr.scanner}</h4>
                  <Badge color={C.blue}>{sr.findings_count} findings</Badge>
                </div>
                {(sr.findings||[]).map((f,fi)=>{
                  const sevC2={critical:C.red,high:C.orange,medium:C.yellow,low:C.blue,info:C.textDim};
                  const col2=sevC2[f.severity]||C.textDim;
                  return(<div key={fi} style={{padding:"10px 14px",background:C.bg,borderRadius:8,marginBottom:6,borderLeft:`3px solid ${col2}`}}>
                    <div style={{display:"flex",alignItems:"center",gap:8}}>
                      <span style={{background:`${col2}22`,color:col2,padding:"1px 8px",borderRadius:10,fontSize:10,fontWeight:700,textTransform:"uppercase"}}>{f.severity}</span>
                      <span style={{fontSize:12,fontWeight:600,color:C.text}}>{f.title}</span>
                    </div>
                    {f.description&&<div style={{fontSize:11,color:C.textMuted,marginTop:4}}>{f.description}</div>}
                    {f.recommendation&&<div style={{fontSize:11,color:"#22d3ee",marginTop:3}}>{"\u2192"} {f.recommendation}</div>}
                  </div>);
                })}
              </div>
            ))}
          </Card>}

          {/* Empty state */}
          {!scan&&!scanning&&<Card>
            <div style={{textAlign:"center",padding:40}}>
              <div style={{width:64,height:64,borderRadius:"50%",background:`${C.orange}22`,display:"flex",alignItems:"center",justifyContent:"center",margin:"0 auto 16px"}}><Shield size={32} color={C.orange}/></div>
              <h3 style={{color:C.text,margin:"0 0 8px",fontSize:18,fontWeight:800}}>Attack Surface Scan</h3>
              <p style={{color:C.textMuted,fontSize:13,margin:"0 0 6px",maxWidth:500,marginLeft:"auto",marginRight:"auto"}}>Automatically scan this vendor's website for SSL/TLS, HTTP headers, DNS, email auth (SPF/DKIM/DMARC), and open ports.</p>
              {selVendor.website_url?
                <p style={{color:C.textDim,fontSize:12,margin:"0 0 20px"}}>Target: <strong style={{color:C.blue}}>{selVendor.website_url}</strong></p>:
                <p style={{color:C.yellow,fontSize:12,margin:"0 0 20px"}}>{"\u26A0"} Add a website URL first (click Edit above)</p>}
              {selVendor.website_url&&<Btn onClick={runScan}><RefreshCw size={14}/> Run Scan Now</Btn>}
            </div>
          </Card>}
        </>);
      })()}
    </div>)}

    {/* ===== DETAIL TAB (Docs + Info) ===== */}
    {tab==="detail"&&selVendor&&(<div>
      <div style={{display:"flex",alignItems:"center",gap:12,marginBottom:16}}>
        <button onClick={()=>setTab("assess")} style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:8,padding:"8px 12px",cursor:"pointer",color:C.text,display:"flex",alignItems:"center",gap:4,fontFamily:"inherit",fontSize:13}}><ArrowLeft size={14}/> Back to Assessment</button>
        <h3 style={{margin:0,fontSize:18,fontWeight:800,color:C.text}}>{selVendor.name} — Details & Documents</h3>
      </div>

      {/* Vendor Info */}
      <Card title="Vendor Information" style={{marginBottom:16}}>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:14}}>
          {[
            {l:"Category",v:selVendor.category},{l:"Criticality",v:selVendor.criticality},
            {l:"Service",v:selVendor.service_description||"—"},
            {l:"Data Types",v:(selVendor.data_types||[]).join(", ")||"—"},
            {l:"Contact",v:selVendor.contact_name||"—"},{l:"Email",v:selVendor.contact_email||"—"},
            {l:"Contract Start",v:fmtDate(selVendor.contract_start)},{l:"Contract End",v:fmtDate(selVendor.contract_end)},
            {l:"Last Assessed",v:fmtDate(selVendor.assessed_at)},
          ].map(item=>(
            <div key={item.l} style={{padding:10,background:C.bg,borderRadius:8}}>
              <div style={{fontSize:10,color:C.textDim,fontWeight:700,textTransform:"uppercase",marginBottom:2}}>{item.l}</div>
              <div style={{fontSize:13,color:C.text,fontWeight:500}}>{item.v}</div>
            </div>
          ))}
        </div>
      </Card>

      {/* Compliance Documents */}
      <Card title="Compliance Documents">
        <p style={{fontSize:12,color:C.textDim,margin:"-4px 0 16px"}}>Track required compliance documents from this vendor.</p>
        <div style={{display:"flex",flexDirection:"column",gap:8}}>
          {COMPLIANCE_DOCS.map(doc=>{
            const ds=(selVendor.docs||{})[doc.id]||{};
            const status=ds.status||"pending";
            const statusColors2={pending:C.textDim,requested:C.yellow,received:C.green,expired:C.red,not_applicable:C.textDim};
            const statusLabels2={pending:"Pending",requested:"Requested",received:"Received",expired:"Expired",not_applicable:"N/A"};
            return(<div key={doc.id} style={{display:"flex",alignItems:"center",gap:12,padding:"12px 16px",background:C.bg,borderRadius:8,border:`1px solid ${statusColors2[status]}22`}}>
              <span style={{fontSize:18}}>{doc.icon}</span>
              <div style={{flex:1}}>
                <div style={{fontSize:13,fontWeight:600,color:C.text}}>{doc.name}</div>
                {ds.expiry_date&&<div style={{fontSize:11,color:new Date(ds.expiry_date)<new Date()?C.red:C.textDim}}>Expires: {fmtDate(ds.expiry_date)}{new Date(ds.expiry_date)<new Date()?" (EXPIRED)":""}</div>}
                {ds.notes&&<div style={{fontSize:11,color:C.textDim,marginTop:2}}>{ds.notes}</div>}
              </div>
              {isAdmin?<div style={{display:"flex",gap:6,alignItems:"center"}}>
                <select value={status} onChange={e=>setDocStatus(selVendor.id,doc.id,{status:e.target.value})} style={{padding:"5px 8px",background:`${statusColors2[status]}22`,border:`1px solid ${statusColors2[status]}44`,borderRadius:6,color:statusColors2[status],fontSize:11,fontWeight:700,fontFamily:"inherit",cursor:"pointer"}}>
                  <option value="pending">Pending</option><option value="requested">Requested</option><option value="received">Received</option><option value="expired">Expired</option><option value="not_applicable">N/A</option>
                </select>
                <input type="date" value={ds.expiry_date||""} onChange={e=>setDocStatus(selVendor.id,doc.id,{expiry_date:e.target.value})} style={{padding:"4px 8px",background:C.bg,border:`1px solid ${C.border}`,borderRadius:6,color:C.text,fontSize:11,fontFamily:"inherit",width:120}} title="Expiry date"/>
              </div>:
              <Badge color={statusColors2[status]}>{statusLabels2[status]}</Badge>}
            </div>);
          })}
        </div>
      </Card>

      {/* Notes */}
      {selVendor.notes&&<Card title="Notes" style={{marginTop:16}}>
        <p style={{fontSize:13,color:C.textMuted,lineHeight:1.6,margin:0,whiteSpace:"pre-wrap"}}>{selVendor.notes}</p>
      </Card>}
    </div>)}

    {/* MODAL */}
    <Modal open={modal?.type==="vendor"} onClose={()=>setModal(null)} title={modal?.data?.id?"Edit Vendor":"Add Vendor"} wide>
      {modal?.type==="vendor"&&<VendorFormModal v={modal.data} onSave={saveVendor}/>}
    </Modal>
  </div>);
};

const NAV_ALL = [
  {id:"dashboard",label:"Dashboard",icon:LayoutDashboard,module:"dashboard"},
  {id:"admin",label:"Admin Panel",icon:Settings,module:"admin_panel"},
  {id:"soa",label:"SOA",icon:ListChecks,module:"soa"},
  {id:"gap",label:"Gap Assessment",icon:ClipboardCheck,module:"gap"},
  {id:"workflow",label:"Workflow Check",icon:Activity,module:"workflow"},
  {id:"risk",label:"Risk Register",icon:AlertTriangle,module:"risk"},
  {id:"assets",label:"Asset Register",icon:Server,module:"assets"},
  {id:"policies",label:"Policies",icon:FileText,module:"policies"},
  {id:"evidence",label:"Evidence",icon:FolderOpen,module:"evidence"},
  {id:"roles",label:"Roles & RACI",icon:Users,module:"roles"},
  {id:"vapt",label:"VAPT",icon:Bug,module:"vapt"},
  {id:"training",label:"Training",icon:GraduationCap,module:"training"},
  {id:"cloud",label:"Cloud Security",icon:Cloud,module:"cloud"},
  {id:"github",label:"GitHub Security",icon:({size})=><GithubIcon size={size}/>,module:"github"},
  {id:"vendors",label:"Vendor Risk",icon:Flag,module:"vendors"},
];

// =============================================
// MAIN APP
// =============================================

// [SEC-5] Session idle timeout hook
const useIdleTimeout = (timeout, warningBefore, onTimeout, onWarning) => {
  const lastActivity = useRef(Date.now());
  const warningShown = useRef(false);

  useEffect(() => {
    const updateActivity = () => { lastActivity.current = Date.now(); warningShown.current = false; };
    const events = ["mousedown", "keydown", "touchstart", "scroll", "mousemove"];
    events.forEach(e => window.addEventListener(e, updateActivity, { passive: true }));

    const checker = setInterval(() => {
      const idle = Date.now() - lastActivity.current;
      if (idle >= timeout) { onTimeout(); }
      else if (idle >= timeout - warningBefore && !warningShown.current) {
        warningShown.current = true;
        onWarning(Math.ceil((timeout - idle) / 1000));
      }
    }, 15000); // Check every 15s

    return () => {
      events.forEach(e => window.removeEventListener(e, updateActivity));
      clearInterval(checker);
    };
  }, [timeout, warningBefore, onTimeout, onWarning]);
};

// [SEC-9] Force Password Change screen
const ForcePasswordChange = ({ user, token, onComplete, onLogout }) => {
  const [currentPw, setCurrentPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [showPw, setShowPw] = useState(false);

  const pwCheck = validatePasswordComplexity(newPw);
  const pwMatch = newPw && confirmPw && newPw === confirmPw;

  const handleSubmit = async () => {
    if (!currentPw) { setError("Enter your current password"); return; }
    if (!pwCheck.valid) { setError("Password does not meet requirements:\n• " + pwCheck.errors.join("\n• ")); return; }
    if (!pwMatch) { setError("New passwords do not match"); return; }
    if (newPw === currentPw) { setError("New password must be different from current password"); return; }

    setLoading(true); setError("");
    try {
      // Verify current password by re-authenticating
      const verifyR = await safeFetch(`${SUPA_URL}/auth/v1/token?grant_type=password`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "apikey": SUPA_KEY },
        body: JSON.stringify({ email: user.email, password: currentPw }),
      });
      if (!verifyR.ok) { setError("Current password is incorrect"); setLoading(false); return; }

      // Update password
      const updateR = await safeFetch(`${SUPA_URL}/auth/v1/user`, {
        method: "PUT",
        headers: { "apikey": SUPA_KEY, "Authorization": `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ password: newPw }),
      });
      if (!updateR.ok) { setError("Failed to update password. Try again."); setLoading(false); return; }

      // Clear the must_change_password flag
      await safeFetch(`${SUPA_URL}/rest/v1/user_org_roles?user_id=eq.${user.id}`, {
        method: "PATCH",
        headers: { "apikey": SUPA_KEY, "Authorization": `Bearer ${token}`, "Content-Type": "application/json", "Prefer": "return=minimal" },
        body: JSON.stringify({ must_change_password: false, last_password_change: new Date().toISOString() }),
      });

      await auditLog(token, "password_change", { resource_type: "user", resource_id: user.id }, "critical");
      onComplete();
    } catch (e) { setError(e.message); }
    setLoading(false);
  };

  return (
    <div style={{minHeight:"100vh",background:C.bg,display:"flex",alignItems:"center",justifyContent:"center",fontFamily:"'DM Sans',sans-serif"}}>
      <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800;900&display=swap" rel="stylesheet"/>
      <div style={{width:440,maxWidth:"95vw"}}>
        <div style={{textAlign:"center",marginBottom:24,display:"flex",justifyContent:"center"}}><Logo/></div>
        <div style={{background:C.sidebar,borderRadius:16,border:`1px solid ${C.border}`,padding:32}}>
          <div style={{textAlign:"center",marginBottom:20}}>
            <div style={{width:48,height:48,borderRadius:"50%",background:`${C.orange}22`,display:"flex",alignItems:"center",justifyContent:"center",margin:"0 auto 12px"}}><Lock size={24} color={C.orange}/></div>
            <h3 style={{margin:"0 0 4px",color:C.text,fontSize:18,fontWeight:800}}>Password Change Required</h3>
            <p style={{color:C.textMuted,fontSize:12,margin:0}}>For security, you must change your password before continuing.</p>
          </div>
          {error&&<div style={{padding:"10px 14px",background:C.redBg,border:`1px solid ${C.red}44`,borderRadius:8,color:C.red,fontSize:12,marginBottom:16,fontWeight:500,whiteSpace:"pre-wrap"}}>{error}</div>}
          <Input label="Current Password" type={showPw?"text":"password"} value={currentPw} onChange={setCurrentPw} placeholder="Enter current password"/>
          <Input label="New Password" type={showPw?"text":"password"} value={newPw} onChange={setNewPw} placeholder="Min 12 chars, mixed case, number, special"/>
          <Input label="Confirm New Password" type={showPw?"text":"password"} value={confirmPw} onChange={setConfirmPw} placeholder="Re-enter new password"/>
          <div style={{marginBottom:16}}>
            <label style={{display:"flex",alignItems:"center",gap:6,cursor:"pointer",color:C.textDim,fontSize:11}}>
              <input type="checkbox" checked={showPw} onChange={e=>setShowPw(e.target.checked)}/> Show passwords
            </label>
          </div>
          {newPw && <div style={{padding:10,background:C.bg,borderRadius:8,border:`1px solid ${C.border}`,marginBottom:16,fontSize:11}}>
            <div style={{fontWeight:700,color:C.textDim,marginBottom:4}}>PASSWORD REQUIREMENTS:</div>
            {[
              { label: `At least ${PASSWORD_RULES.minLength} characters`, ok: newPw.length >= PASSWORD_RULES.minLength },
              { label: "Uppercase letter", ok: /[A-Z]/.test(newPw) },
              { label: "Lowercase letter", ok: /[a-z]/.test(newPw) },
              { label: "Number", ok: /[0-9]/.test(newPw) },
              { label: "Special character", ok: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(newPw) },
              { label: "Passwords match", ok: pwMatch },
            ].map((r, i) => <div key={i} style={{color: r.ok ? C.green : C.textDim, display: "flex", alignItems: "center", gap: 4}}>
              {r.ok ? <CheckCircle size={10}/> : <XCircle size={10}/>} {r.label}
            </div>)}
          </div>}
          <div style={{display:"flex",gap:8}}>
            <Btn variant="secondary" onClick={onLogout} style={{flex:1}}>Sign Out</Btn>
            <Btn onClick={handleSubmit} disabled={loading||!pwCheck.valid||!pwMatch} style={{flex:2}}>{loading?"Changing...":"Change Password & Continue"}</Btn>
          </div>
        </div>
      </div>
    </div>
  );
};

// [SEC-10] Confidential watermark overlay
const SecurityWatermark = ({ email }) => (
  <div style={{
    position:"fixed", inset:0, pointerEvents:"none", zIndex:99999,
    backgroundImage: `repeating-linear-gradient(135deg, transparent, transparent 200px, rgba(249,115,22,0.015) 200px, rgba(249,115,22,0.015) 201px)`,
  }}>
    <div style={{
      position:"fixed", bottom:4, right:8, fontSize:9, color:"rgba(148,163,184,0.2)",
      fontFamily:"monospace", pointerEvents:"none", userSelect:"none",
    }}>
      {email} • SecComply ISMS
    </div>
  </div>
);

// [SEC-11] Session timeout warning banner
const SessionWarningBanner = ({ seconds, onExtend }) => (
  <div style={{
    position:"fixed", top:0, left:0, right:0, zIndex:10000,
    background:"linear-gradient(90deg,#422006,#7C2D12)", padding:"10px 24px",
    display:"flex", justifyContent:"center", alignItems:"center", gap:12,
    borderBottom:"2px solid #F97316",
  }}>
    <AlertTriangle size={16} color="#F97316"/>
    <span style={{color:"#F97316",fontSize:13,fontWeight:600}}>
      Session expiring in {seconds}s due to inactivity
    </span>
    <button onClick={onExtend} style={{
      padding:"4px 16px", borderRadius:6, background:"#F97316", color:"#fff",
      border:"none", cursor:"pointer", fontWeight:700, fontSize:12, fontFamily:"inherit",
    }}>Stay Signed In</button>
  </div>
);
export default function App() {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [data, setData] = useState(null);
  const [page, setPageRaw] = useState(() => {
    try { return sessionStorage.getItem("sc_page") || "dashboard"; } catch { return "dashboard"; }
  });
  const setPage = (p) => { setPageRaw(p); try { sessionStorage.setItem("sc_page", p); } catch {} };
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [loading, setLoading] = useState(false);
  const [saveStatus, setSaveStatus] = useState("");
  const saveRef = useRef(null);
  const isInitialLoad = useRef(true);
  const [notifOpen, setNotifOpen] = useState(false);
  const [notifDismissed, setNotifDismissed] = useState([]);

  // [SEC-5] Session timeout state
  const [sessionWarning, setSessionWarning] = useState(null);
  const sessionStartTime = useRef(null);

  // [SEC-9] Force password change state
  const [mustChangePassword, setMustChangePassword] = useState(false);

  // Session restore flag
  const sessionRestoreAttempted = useRef(false);

  // ─── Session Persistence Helpers ───
  const SESSION_KEY = "sc_session";
  const persistSession = (tok, usr, refreshTok) => {
    try {
      sessionStorage.setItem(SESSION_KEY, JSON.stringify({
        token: tok,
        user: usr,
        refreshToken: refreshTok || null,
        timestamp: Date.now(),
      }));
    } catch (e) { console.warn("Session persist failed:", e.message); }
  };
  const clearPersistedSession = () => {
    try { sessionStorage.removeItem(SESSION_KEY); } catch (e) {}
  };
  const getPersistedSession = () => {
    try {
      const raw = sessionStorage.getItem(SESSION_KEY);
      if (!raw) return null;
      const s = JSON.parse(raw);
      // Reject sessions older than 8 hours
      if (Date.now() - s.timestamp > SESSION_MAX_DURATION) { clearPersistedSession(); return null; }
      return s;
    } catch (e) { return null; }
  };

  // ─── Restore session on mount ───
  useEffect(() => {
    if (sessionRestoreAttempted.current || user) return;
    sessionRestoreAttempted.current = true;
    const saved = getPersistedSession();
    if (!saved || !saved.token || !saved.user) return;

    // Try refreshing the token first to ensure it's still valid
    const restoreSession = async () => {
      setLoading(true);
      try {
        if (saved.refreshToken) {
          const r = await safeFetch(`${SUPA_URL}/auth/v1/token?grant_type=refresh_token`, {
            method: "POST",
            headers: { "Content-Type": "application/json", "apikey": SUPA_KEY },
            body: JSON.stringify({ refresh_token: saved.refreshToken }),
          });
          if (r.ok) {
            const d = await r.json();
            if (d.access_token && d.user) {
              handleAuth(d.access_token, d.user, d.refresh_token);
              return;
            }
          }
        }
        // If refresh fails, try using existing token (might still be valid)
        const verifyR = await safeFetch(`${SUPA_URL}/auth/v1/user`, {
          headers: { "apikey": SUPA_KEY, "Authorization": `Bearer ${saved.token}` },
        });
        if (verifyR.ok) {
          const userData = await verifyR.json();
          if (userData?.id) {
            handleAuth(saved.token, userData, saved.refreshToken);
            return;
          }
        }
        // Token invalid — clear and show login
        clearPersistedSession();
        setLoading(false);
      } catch (e) {
        console.warn("Session restore failed:", e.message);
        clearPersistedSession();
        setLoading(false);
      }
    };
    restoreSession();
  }, []);

  // [PATCH V7] Token refresh mechanism
  const tokenRefreshRef = useRef(null);
  useEffect(() => {
    if (!token) return;
    // Parse JWT to get expiry
    const parseJwtExp = (t) => {
      try {
        const payload = JSON.parse(atob(t.split('.')[1]));
        return payload.exp ? payload.exp * 1000 : 0;
      } catch { return 0; }
    };
    const refreshToken = async () => {
      try {
        const r = await safeFetch(`${SUPA_URL}/auth/v1/token?grant_type=refresh_token`, {
          method: "POST",
          headers: { "Content-Type": "application/json", "apikey": SUPA_KEY },
          body: JSON.stringify({ refresh_token: tokenRefreshRef.current }),
        });
        if (r.ok) {
          const d = await r.json();
          if (d.access_token) {
            setToken(d.access_token);
            tokenRefreshRef.current = d.refresh_token;
            persistSession(d.access_token, user, d.refresh_token);
          }
        }
      } catch (e) { console.warn("Token refresh failed:", e.message); }
    };
    const expiry = parseJwtExp(token);
    if (expiry > 0) {
      // Refresh 5 minutes before expiry
      const refreshIn = Math.max(expiry - Date.now() - 300000, 60000);
      const timer = setTimeout(refreshToken, refreshIn);
      return () => clearTimeout(timer);
    }
  }, [token]);

  // [SEC-5] Idle timeout — auto-logout after 30 min inactivity
  const handleIdleTimeout = useCallback(() => {
    if (user && token) {
      auditLog(token, "session_timeout", { resource_type: "session" }, "warning");
      clearPersistedSession();
      handleLogout();
    }
  }, [user, token]);

  const handleIdleWarning = useCallback((seconds) => {
    setSessionWarning(seconds);
  }, []);

  useIdleTimeout(
    SESSION_IDLE_TIMEOUT,
    SESSION_WARNING_BEFORE,
    handleIdleTimeout,
    handleIdleWarning
  );

  // [SEC-5] Max session duration check
  useEffect(() => {
    if (!sessionStartTime.current || !user) return;
    const check = setInterval(() => {
      if (Date.now() - sessionStartTime.current > SESSION_MAX_DURATION) {
        auditLog(token, "session_max_duration", { resource_type: "session" }, "warning");
        clearPersistedSession();
        handleLogout();
      }
    }, 60000);
    return () => clearInterval(check);
  }, [user, token]);

  // [SEC-5] Clear session warning on activity
  useEffect(() => {
    if (!sessionWarning) return;
    const clear = () => setSessionWarning(null);
    const events = ["mousedown", "keydown", "touchstart"];
    events.forEach(e => window.addEventListener(e, clear, { once: true }));
    return () => events.forEach(e => window.removeEventListener(e, clear));
  }, [sessionWarning]);

  // [SEC-12] Lock screen on visibility change (optional — warns on tab switch)
  useEffect(() => {
    const handleVisibility = () => {
      if (document.hidden && user && token) {
        // Don't log out, but do log the event for suspicious activity monitoring
        auditLog(token, "tab_hidden", { resource_type: "session" }, "info");
      }
    };
    document.addEventListener("visibilitychange", handleVisibility);
    return () => document.removeEventListener("visibilitychange", handleVisibility);
  }, [user, token]);

  // RBAC State
  const [rbac, setRbac] = useState(null);
  const [currentOrg, setCurrentOrg] = useState(null);
  const [currentRole, setCurrentRole] = useState(null);
  const [appMode, setAppMode] = useState("loading"); // loading|setup|denied|select_client|isms

  // ─── Notification Engine ───
  const notifications = useMemo(() => {
    if(!data) return [];
    const cfg = data.workflowConfig || {};
    const recs = data.workflowRecords || [];
    const getRecs = (cid) => recs.filter(r=>r.controlId===cid).sort((a,b)=>new Date(b.date)-new Date(a.date));
    const notifs = [];
    WORKFLOW_CONTROLS.forEach(ctrl => {
      const freq = cfg[ctrl.id]?.frequency || ctrl.defaultFreq;
      const cRecs = getRecs(ctrl.id);
      const latestApproved = cRecs.find(r=>r.status==="approved");
      const hasPending = cRecs.some(r=>r.status==="uploaded");
      const hasRejected = cRecs.find(r=>r.status==="rejected"&&!cRecs.find(r2=>r2.status==="approved"&&new Date(r2.date)>new Date(r.date)));
      if(!latestApproved && !hasPending) notifs.push({id:`miss_${ctrl.id}`,ctrl,type:"missing",urgency:"critical",title:`${ctrl.name} — No Evidence`,msg:"Required for ISO compliance.",color:C.red,actionLabel:"Upload Now"});
      else if(latestApproved) {
        const nextDue = calcNextDue(latestApproved.date, freq); const days = daysUntilDue(nextDue);
        if(days<0&&!hasPending) notifs.push({id:`over_${ctrl.id}`,ctrl,type:"overdue",urgency:"critical",title:`${ctrl.name} — Overdue`,msg:`Overdue by ${Math.abs(days)} days.`,dueDate:nextDue,color:C.red,actionLabel:"Upload Now"});
        else if(days>=0&&days<=2&&!hasPending) notifs.push({id:`due2_${ctrl.id}`,ctrl,type:"due_soon",urgency:"warning",title:`${ctrl.name} — Due in ${days}d`,msg:`Due on ${nextDue}.`,dueDate:nextDue,color:C.yellow,actionLabel:"Upload"});
        else if(days>2&&days<=7&&!hasPending) notifs.push({id:`due7_${ctrl.id}`,ctrl,type:"upcoming",urgency:"info",title:`${ctrl.name} — Due in ${days}d`,msg:`Deadline ${nextDue}.`,dueDate:nextDue,color:C.blue,actionLabel:"View"});
      }
      if(hasPending) notifs.push({id:`rev_${ctrl.id}`,ctrl,type:"review",urgency:"info",title:`${ctrl.name} — Awaiting Review`,msg:"Pending review.",color:C.blue});
      if(hasRejected) notifs.push({id:`rej_${ctrl.id}`,ctrl,type:"rejected",urgency:"warning",title:`${ctrl.name} — Rejected`,msg:`${hasRejected.reviewComment||"Re-upload needed."}`,color:C.red,actionLabel:"Re-upload"});
    });
    return notifs;
  }, [data]);

  const activeNotifs = notifications.filter(n=>!notifDismissed.includes(n.id));
  const criticalCount = activeNotifs.filter(n=>n.urgency==="critical").length;
  const bellCount = activeNotifs.length;

  // ─── Notification Bell ───
  const NotificationBell = () => (
    <div style={{position:"relative"}}>
      <button onClick={()=>setNotifOpen(!notifOpen)} style={{background:"none",border:"none",cursor:"pointer",color:bellCount>0?C.orange:C.textDim,padding:4,position:"relative"}}>
        <Bell size={18} fill={criticalCount>0?C.orange:"none"}/>
        {bellCount>0&&<span style={{position:"absolute",top:-2,right:-4,width:16,height:16,borderRadius:"50%",background:criticalCount>0?C.red:C.orange,color:"#fff",fontSize:9,fontWeight:800,display:"flex",alignItems:"center",justifyContent:"center"}}>{bellCount>9?"9+":bellCount}</span>}
      </button>
      {notifOpen&&<><div onClick={()=>setNotifOpen(false)} style={{position:"fixed",inset:0,zIndex:9998}}/><div style={{position:"absolute",right:0,top:32,width:380,maxHeight:480,background:C.card,borderRadius:12,border:`1px solid ${C.border}`,boxShadow:"0 12px 40px rgba(0,0,0,0.5)",zIndex:9999,overflow:"hidden"}} onClick={e=>e.stopPropagation()}>
        <div style={{padding:"14px 16px",borderBottom:`1px solid ${C.border}`,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
          <div style={{fontSize:14,fontWeight:700,color:C.text}}>Notifications</div>
          <div style={{display:"flex",gap:6}}>
            {activeNotifs.length>0&&<button onClick={()=>setNotifDismissed(notifications.map(n=>n.id))} style={{background:"none",border:"none",cursor:"pointer",color:C.textDim,fontSize:11,fontWeight:600,fontFamily:"inherit"}}>Clear all</button>}
            <button onClick={()=>setNotifOpen(false)} style={{background:"none",border:"none",cursor:"pointer",color:C.textDim}}><X size={14}/></button>
          </div>
        </div>
        <div style={{overflowY:"auto",maxHeight:400}}>
          {activeNotifs.length===0?<div style={{padding:32,textAlign:"center"}}><CheckCircle size={28} color={C.green} style={{marginBottom:8}}/><div style={{color:C.green,fontSize:13,fontWeight:600}}>All clear!</div></div>:(
            activeNotifs.map(n=>(
              <div key={n.id} style={{padding:"12px 16px",borderBottom:`1px solid ${C.border}22`,display:"flex",gap:10,alignItems:"flex-start",background:n.urgency==="critical"?`${C.red}08`:"transparent"}}>
                <div style={{width:8,height:8,borderRadius:"50%",background:n.color,marginTop:5,flexShrink:0}}/>
                <div style={{flex:1,minWidth:0}}>
                  <div style={{fontSize:12,fontWeight:700,color:C.text,marginBottom:2}}>{n.ctrl.icon} {n.title}</div>
                  <div style={{fontSize:11,color:C.textMuted}}>{n.msg}</div>
                  <div style={{display:"flex",gap:6,marginTop:6}}>
                    {n.actionLabel&&<button onClick={()=>{setPage("workflow");setNotifOpen(false);}} style={{padding:"3px 10px",borderRadius:5,background:`${C.orange}22`,border:`1px solid ${C.orange}44`,color:C.orange,fontSize:10,fontWeight:700,cursor:"pointer",fontFamily:"inherit"}}>{n.actionLabel}</button>}
                    <button onClick={()=>setNotifDismissed(d=>[...d,n.id])} style={{padding:"3px 8px",borderRadius:5,background:"transparent",border:`1px solid ${C.border}`,color:C.textDim,fontSize:10,cursor:"pointer",fontFamily:"inherit"}}>Dismiss</button>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div></>}
    </div>
  );

  // ─── Sanitize data ───
  const sanitizeData = (saved) => {
    const merged = { ...getInitialData(), ...saved };
    ["risks","assets","roles","raci","vapt","audits","policies","evidenceList","soaSheetNames","trainings","workflowRecords","cloudScans","githubScans","vendors"].forEach(k=>{if(!Array.isArray(merged[k]))merged[k]=[];});
    ["soaFileName"].forEach(k=>{if(typeof merged[k]!=="string") merged[k]="";});
    if(!merged.gapResponses||typeof merged.gapResponses!=="object"||Array.isArray(merged.gapResponses)) merged.gapResponses={};
    if(!merged.workflowConfig||typeof merged.workflowConfig!=="object"||Array.isArray(merged.workflowConfig)) merged.workflowConfig=Object.fromEntries(WORKFLOW_CONTROLS.map(c=>[c.id,{frequency:c.defaultFreq}]));
    else WORKFLOW_CONTROLS.forEach(c=>{if(!merged.workflowConfig[c.id]) merged.workflowConfig[c.id]={frequency:c.defaultFreq};});
    delete merged.gaps; delete merged.gapFileName; delete merged.gapSections;
    return merged;
  };

  // ─── Auth Flow ───
  const handleAuth = async (tok, usr, refreshTok) => {
    setToken(tok); setUser(usr); setLoading(true);
    sessionStartTime.current = Date.now(); // [SEC-5] Track session start
    if (refreshTok) tokenRefreshRef.current = refreshTok;
    persistSession(tok, usr, refreshTok || tokenRefreshRef.current);
    const userEmail = (usr.email||"").toLowerCase().trim();

    // [SEC-2] Audit log: login event
    await auditLog(tok, "login", { resource_type: "session", fingerprint: getSessionFingerprint() }, "info");

    try {
      // [SEC-9] Check if user must change password
      const roleRows = await safeFetch(`${SUPA_URL}/rest/v1/user_org_roles?user_id=eq.${usr.id}&select=must_change_password,status,locked_until`, {
        method: "GET",
        headers: { "apikey": SUPA_KEY, "Authorization": `Bearer ${tok}` },
      });
      if (roleRows.ok) {
        const roles = await roleRows.json();
        const myRole = roles?.[0];
        if (myRole?.must_change_password === true) {
          setMustChangePassword(true);
          setLoading(false);
          return;
        }
        // Check if account is locked
        if (myRole?.locked_until && new Date(myRole.locked_until) > new Date()) {
          setLoading(false);
          setUser(null); setToken(null);
          return;
        }
      }

      const dir = await loadRbac(tok);
      if(!dir) {
        // First time — only super admin email can initialize
        if(userEmail === SUPER_ADMIN_EMAIL) {
          setAppMode("setup"); setLoading(false); return;
        } else {
          setAppMode("denied"); setLoading(false); return;
        }
      }
      setRbac(dir);
      // Case-insensitive email match + userId match
      let me = (dir.members||[]).find(m=>m.userId===usr.id||(m.email||"").toLowerCase().trim()===userEmail);

      // [PATCH V6] Removed auto-recovery backdoor — super admin must be re-added via database.
      // If super admin is not found, deny access like any other unregistered user.

      // If member found but userId is stale, update it
      if(me && me.userId!==usr.id) {
        console.log("Updating stale userId"); // [PATCH V14] Don't log email
        const updatedMembers = (dir.members||[]).map(m=>(m.email||"").toLowerCase().trim()===userEmail?{...m,userId:usr.id}:m);
        const updatedRbac = {...dir, members:updatedMembers};
        await saveRbac(tok, updatedRbac);
        setRbac(updatedRbac);
        me = {...me, userId:usr.id};
      }

      if(!me) {
        console.warn("User not found in RBAC directory"); // [PATCH V14] Don't log emails
        setAppMode("denied"); setLoading(false); return;
      }
      setCurrentRole(me.role);
      // Auto-bootstrap: ensure ALL users exist in user_org_roles (required for Edge Functions)
      try {
        const checkRole = await safeFetch(`${SUPA_URL}/rest/v1/user_org_roles?user_id=eq.${usr.id}&status=eq.active&select=role`,{
          headers:{"apikey":SUPA_KEY,"Authorization":`Bearer ${tok}`},
        });
        const existingRoles = await checkRole.json();
        if(!existingRoles||!Array.isArray(existingRoles)||existingRoles.length===0) {
          if(isSecComply(me.role)) {
            // Use bootstrap RPC for super_admin (bypasses RLS)
            await safeFetch(`${SUPA_URL}/rest/v1/rpc/bootstrap_super_admin`,{
              method:"POST",
              headers:{"apikey":SUPA_KEY,"Authorization":`Bearer ${tok}`,"Content-Type":"application/json"},
              body:JSON.stringify({admin_email:usr.email,admin_name:me.name||usr.email}),
            }).catch(()=>{});
            console.log("Auto-bootstrapped user_org_roles for super admin");
          } else {
            // For client roles, try direct insert (service role handles via RLS)
            await safeFetch(`${SUPA_URL}/rest/v1/user_org_roles`,{
              method:"POST",
              headers:{"apikey":SUPA_KEY,"Authorization":`Bearer ${tok}`,"Content-Type":"application/json","Prefer":"return=minimal"},
              body:JSON.stringify({user_id:usr.id,email:usr.email,name:me.name||usr.email,role:me.role,org_id:me.orgId||null,created_by:"auto_bootstrap",status:"active"}),
            }).catch(()=>{});
            console.log("Auto-bootstrapped user_org_roles for",me.role);
          }
        }
      } catch(e) { console.warn("user_org_roles check skipped:",e.message); }
      if(isSecComply(me.role)) {
        // Super Admin / Employee → Admin dashboard (select client mode)
        setAppMode("select_client"); setData(null); setLoading(false);
        const savedPage = sessionStorage.getItem("sc_page");
        if(!savedPage) setPage("admin");
        // Auto-restore last selected org on session restore
        const savedOrg = sessionStorage.getItem("sc_org");
        if(savedOrg) { setTimeout(()=>enterClient(savedOrg), 0); }
      } else {
        // Client role → load their org data
        setCurrentOrg(me.orgId);
        const saved = await loadOrgData(tok, me.orgId);
        setData(saved ? sanitizeData(saved) : getInitialData());
        setAppMode("isms");
        const savedPage2 = sessionStorage.getItem("sc_page");
        if(!savedPage2) {
          if(me.role==="client_employee") setPage("training");
          else setPage("dashboard");
        }
        setLoading(false);
        isInitialLoad.current = true;
      }
    } catch(e) {
      console.error("Auth flow error:", e);
      setAppMode("denied"); setLoading(false);
    }
  };

  // Enter a specific client org (for SecComply staff)
  const enterClient = async(orgId) => {
    setLoading(true); setCurrentOrg(orgId);
    try { sessionStorage.setItem("sc_org", orgId); } catch {}
    try {
      const saved = await loadOrgData(token, orgId);
      setData(saved ? sanitizeData(saved) : getInitialData());
    } catch(e) { setData(getInitialData()); }
    setAppMode("isms");
    const savedPage3 = sessionStorage.getItem("sc_page");
    if(!savedPage3 || savedPage3==="admin") setPage("dashboard");
    setLoading(false); isInitialLoad.current = true;
  };

  // Back to client list (SecComply staff)
  const backToClients = () => {
    setCurrentOrg(null); setData(null); setAppMode("select_client"); setPage("admin");
    try { sessionStorage.removeItem("sc_org"); } catch {}
  };

  // Setup complete
  const handleSetupComplete = (newRbac) => {
    setRbac(newRbac); setCurrentRole("super_admin"); setAppMode("select_client"); setPage("admin");
  };

  // ─── Auto-save (org-scoped) with integrity checksum [SEC-3] ───
  useEffect(() => {
    if(!user||!token||!data||!currentOrg) return;
    if(isInitialLoad.current) { isInitialLoad.current = false; return; }
    clearTimeout(saveRef.current);
    setSaveStatus("saving");
    saveRef.current = setTimeout(async () => {
      try {
        // [SEC-3] Compute checksum before saving
        const checksum = await computeChecksum(data);
        await safeFetch(`${SUPA_URL}/rest/v1/isms_state`,{
          method:"POST",
          headers:{"apikey":SUPA_KEY,"Authorization":`Bearer ${token}`,"Content-Type":"application/json","Prefer":"resolution=merge-duplicates"},
          body:JSON.stringify({
            user_id:`org_${currentOrg}`,
            state:data,
            updated_at:new Date().toISOString(),
            updated_by:user.id,
            checksum,
          }),
        });
        setSaveStatus("saved"); setTimeout(()=>setSaveStatus(""),2000);
      } catch(e) { console.error("Save failed:",e); setSaveStatus("error"); setTimeout(()=>setSaveStatus(""),3000); }
    }, 2000);
  }, [data]);

  const handleLogout = async () => {
    // [SEC-2] Audit log: logout event
    if (token) await auditLog(token, "logout", { resource_type: "session" }, "info");
    // [SEC-7] Server-side session invalidation
    if (token) await serverLogout(token);
    // Clear persisted session
    clearPersistedSession();
    try { sessionStorage.removeItem("sc_page"); } catch {}
    try { sessionStorage.removeItem("sc_org"); } catch {}
    // Clear all sensitive state
    setUser(null); setToken(null); setData(null); setRbac(null);
    setCurrentOrg(null); setCurrentRole(null); setPage("dashboard");
    setAppMode("loading"); setMustChangePassword(false); setSessionWarning(null);
    tokenRefreshRef.current = null;
    sessionStartTime.current = null;
  };

  // ─── Pre-auth screens ───
  // Show loading during session restore attempt
  if(!user && !sessionRestoreAttempted.current && getPersistedSession()) return (
    <div style={{minHeight:"100vh",background:C.bg,display:"flex",alignItems:"center",justifyContent:"center",fontFamily:"'DM Sans',sans-serif"}}>
      <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800;900&display=swap" rel="stylesheet"/>
      <div style={{textAlign:"center"}}><Loader size={32} color={C.orange} style={{animation:"spin 1s linear infinite",marginBottom:16}}/><div style={{color:C.textMuted,fontSize:14}}>Restoring session...</div><style>{`@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}`}</style></div>
    </div>
  );
  if(!user) return <AuthPage onAuth={handleAuth}/>;
  // [SEC-9] Force password change — must complete before any access
  if(mustChangePassword) return <ForcePasswordChange user={user} token={token} onComplete={()=>{setMustChangePassword(false);handleAuth(token,user,tokenRefreshRef.current);}} onLogout={handleLogout}/>;
  if(appMode==="setup") return <SetupWizard user={user} token={token} onComplete={handleSetupComplete}/>;
  if(appMode==="denied") return <NotRegistered email={user.email} onLogout={handleLogout} onRetry={()=>handleAuth(token,user)}/>;
  if(loading) return (
    <div style={{minHeight:"100vh",background:C.bg,display:"flex",alignItems:"center",justifyContent:"center",fontFamily:"'DM Sans',sans-serif"}}>
      <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800;900&display=swap" rel="stylesheet"/>
      <div style={{textAlign:"center"}}><Loader size={32} color={C.orange} style={{animation:"spin 1s linear infinite",marginBottom:16}}/><div style={{color:C.textMuted,fontSize:14}}>Loading...</div><style>{`@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}`}</style></div>
    </div>
  );

  // ─── SecComply Staff: Admin/Client Selection Mode ───
  if(appMode==="select_client"&&isSecComply(currentRole)) {
    const R = ROLES[currentRole];
    return (
      <AuthCtx.Provider value={{user,token,orgId:currentOrg}}>
      <SecurityWatermark email={user.email}/>
      {sessionWarning && <SessionWarningBanner seconds={sessionWarning} onExtend={()=>setSessionWarning(null)}/>}
      <div style={{display:"flex",minHeight:"100vh",background:C.bg,fontFamily:"'DM Sans',sans-serif",color:C.text}}>
        <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800;900&display=swap" rel="stylesheet"/>
        <style>{`@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}`}</style>
        <div style={{width:220,minHeight:"100vh",background:C.sidebar,borderRight:`1px solid ${C.border}`,display:"flex",flexDirection:"column",flexShrink:0}}>
          <div style={{padding:"20px 16px",borderBottom:`1px solid ${C.border}`}}><Logo/></div>
          <div style={{padding:"12px 16px",borderTop:`1px solid ${C.border}`,marginTop:"auto"}}>
            <div style={{padding:"6px 10px",background:`${R.color}12`,borderRadius:8,marginBottom:8,display:"flex",alignItems:"center",gap:6}}>
              <span style={{fontSize:14}}>{R.badge}</span>
              <span style={{fontSize:11,fontWeight:700,color:R.color}}>{R.label}</span>
            </div>
            <div style={{fontSize:11,color:C.textDim,marginBottom:8,overflow:"hidden",textOverflow:"ellipsis"}}>{user.email}</div>
            <button onClick={handleLogout} style={{width:"100%",display:"flex",alignItems:"center",gap:8,padding:"8px 12px",background:`${C.red}15`,border:`1px solid ${C.red}33`,borderRadius:8,cursor:"pointer",color:C.red,fontSize:12,fontWeight:600,fontFamily:"inherit"}}><LogOut size={14}/> Sign Out</button>
          </div>
        </div>
        <div style={{flex:1,padding:24,overflowY:"auto"}}>
          <ErrorBoundary>
            <AdminPanel rbac={rbac} setRbac={setRbac} token={token} currentRole={currentRole} onEnterClient={enterClient} user={user} currentOrgId={currentOrg}/>
          </ErrorBoundary>
        </div>
      </div>
      </AuthCtx.Provider>
    );
  }

  // ─── ISMS Mode (inside a client org) ───
  const role = currentRole || "client_employee";
  const R = ROLES[role] || ROLES.client_employee;
  const orgName = rbac?.orgs?.find(o=>o.id===currentOrg)?.name || "Organization";
  const allMembers = rbac?.members||[];

  // Filter nav based on role
  const NAV = NAV_ALL.filter(item => {
    if(item.id==="admin") return canView(role,"admin_panel");
    return canView(role, item.module);
  }).map(item => {
    if(item.id==="admin" && isClientRole(role)) return {...item, label:"Team", icon:Users};
    return item;
  });

  const renderPage = () => {
    const navItem = NAV_ALL.find(n=>n.id===page);
    const mod = navItem?.module || "dashboard";
    if(mod!=="dashboard" && !canView(role, mod)) return <AccessDenied/>;

    switch(page) {
      case "dashboard":
        if(role==="client_admin") return <ClientAdminDashboard data={data} rbac={rbac} orgId={currentOrg} members={allMembers}/>;
        return <Dashboard data={data}/>;
      case "admin": return canView(role,"admin_panel")?<AdminPanel rbac={rbac} setRbac={setRbac} token={token} currentRole={role} onEnterClient={enterClient} user={user} currentOrgId={currentOrg}/>:<AccessDenied/>;
      case "soa": return <SOAModule data={data} setData={setData}/>;
      case "gap": return <GapAssessment data={data} setData={setData} role={role}/>;
      case "risk": return <RiskRegister data={data} setData={setData} role={role} members={allMembers} orgId={currentOrg}/>;
      case "assets": return <AssetRegister data={data} setData={setData}/>;
      case "policies": return <PoliciesModule data={data} setData={setData} role={role} members={allMembers} orgId={currentOrg}/>;
      case "evidence": return <EvidenceModule data={data} setData={setData} role={role}/>;
      case "roles": return <RolesRaci data={data} setData={setData}/>;
      case "vapt": return <VAPTManagement data={data} setData={setData}/>;
      case "training": return <TrainingModule data={data} setData={setData} role={role} members={allMembers} orgId={currentOrg}/>;
      case "cloud": return <CloudIntegration data={data} setData={setData} role={role}/>;
      case "github": return <GitHubIntegration data={data} setData={setData} role={role}/>;
      case "vendors": return <VendorRiskModule data={data} setData={setData} role={role}/>;
      case "workflow": return <WorkflowCheck data={data} setData={setData} role={role}/>;
      default: return <Dashboard data={data}/>;
    }
  };

  return (
    <AuthCtx.Provider value={{user,token,orgId:currentOrg}}>
      {/* [SEC-10] Confidential watermark overlay */}
      <SecurityWatermark email={user.email}/>
      {/* [SEC-5] Session timeout warning */}
      {sessionWarning && <SessionWarningBanner seconds={sessionWarning} onExtend={()=>setSessionWarning(null)}/>}
      <div style={{display:"flex",minHeight:"100vh",background:C.bg,fontFamily:"'DM Sans',sans-serif",color:C.text}}>
        <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800;900&display=swap" rel="stylesheet"/>
        <style>{`@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}`}</style>
        {/* Sidebar */}
        <div style={{width:sidebarOpen?220:68,minHeight:"100vh",background:C.sidebar,borderRight:`1px solid ${C.border}`,transition:"width 0.2s",display:"flex",flexDirection:"column",flexShrink:0}}>
          <div style={{padding:sidebarOpen?"20px 16px":"20px 12px",borderBottom:`1px solid ${C.border}`,display:"flex",alignItems:"center",justifyContent:"space-between"}}>
            {sidebarOpen?<Logo/>:<Shield size={24} color={C.orange} fill={C.orange}/>}
            <button onClick={()=>setSidebarOpen(!sidebarOpen)} style={{background:"none",border:"none",cursor:"pointer",color:C.textMuted,padding:4}}>{sidebarOpen?<ChevronLeft size={18}/>:<ChevronRight size={18}/>}</button>
          </div>
          {/* Org badge */}
          {sidebarOpen&&<div style={{padding:"10px 16px",borderBottom:`1px solid ${C.border}22`}}>
            <div style={{fontSize:10,color:C.textDim,fontWeight:700}}>ORGANIZATION</div>
            <div style={{fontSize:13,color:C.text,fontWeight:700,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{orgName}</div>
            {isSecComply(role)&&<button onClick={backToClients} style={{background:"none",border:"none",color:C.orange,fontSize:10,fontWeight:600,cursor:"pointer",padding:"2px 0",fontFamily:"inherit"}}>← Back to clients</button>}
          </div>}
          <nav style={{flex:1,padding:"12px 8px",display:"flex",flexDirection:"column",gap:2,overflowY:"auto"}}>
            {NAV.map(item=>{const active=page===item.id;const Icon=item.icon;return<button key={item.id} onClick={()=>setPage(item.id)} style={{display:"flex",alignItems:"center",gap:12,padding:sidebarOpen?"10px 14px":"10px 14px",border:"none",borderRadius:10,cursor:"pointer",width:"100%",textAlign:"left",background:active?`${C.orange}18`:"transparent",color:active?C.orange:C.textMuted,fontWeight:active?700:500,fontSize:13,fontFamily:"inherit"}}><Icon size={18}/>{sidebarOpen&&<span>{item.label}</span>}</button>;})}
          </nav>
          <div style={{padding:"12px 16px",borderTop:`1px solid ${C.border}`}}>
            {sidebarOpen&&<div style={{padding:"6px 10px",background:`${R.color}12`,borderRadius:8,marginBottom:8,display:"flex",alignItems:"center",gap:6}}>
              <span style={{fontSize:14}}>{R.badge}</span>
              <span style={{fontSize:11,fontWeight:700,color:R.color}}>{R.label}</span>
            </div>}
            {sidebarOpen&&<button onClick={handleLogout} style={{width:"100%",display:"flex",alignItems:"center",gap:8,padding:"8px 12px",background:`${C.red}15`,border:`1px solid ${C.red}33`,borderRadius:8,cursor:"pointer",color:C.red,fontSize:12,fontWeight:600,fontFamily:"inherit"}}><LogOut size={14}/> Sign Out</button>}
          </div>
        </div>
        {/* Main */}
        <div style={{flex:1,display:"flex",flexDirection:"column",minWidth:0}}>
          <div style={{padding:"14px 24px",borderBottom:`1px solid ${C.border}`,display:"flex",justifyContent:"space-between",alignItems:"center",background:C.sidebar}}>
            <div style={{fontSize:13,color:C.textMuted}}>SecComply <span style={{color:C.textDim,fontSize:11}}>v8</span> · <span style={{color:C.orange,fontWeight:600}}>{orgName}</span></div>
            <div style={{display:"flex",alignItems:"center",gap:12}}>
              {saveStatus==="saving"&&<div style={{display:"flex",alignItems:"center",gap:6,fontSize:12,color:C.yellow}}><Loader size={12} style={{animation:"spin 1s linear infinite"}}/> Saving...</div>}
              {saveStatus==="saved"&&<div style={{display:"flex",alignItems:"center",gap:6,fontSize:12,color:C.green}}><CheckCircle size={12}/> Saved</div>}
              {saveStatus==="error"&&<div style={{display:"flex",alignItems:"center",gap:6,fontSize:12,color:C.red}}><AlertCircle size={12}/> Save failed</div>}
              <NotificationBell/>
              <Badge color={R.color}>{R.badge} {R.label}</Badge>
              <Badge color={C.textMuted}>{user.email}</Badge>
            </div>
          </div>
          <div style={{flex:1,padding:24,overflowY:"auto"}}><ErrorBoundary>{renderPage()}</ErrorBoundary></div>
        </div>
      </div>
    </AuthCtx.Provider>
  );
}
