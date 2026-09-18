// AI Website Builder — Backend (single-file version)
// Everything (auth, AI generation, site storage, live hosting) lives in this one file
// so it's easy to upload from a phone without dealing with subfolders.

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { nanoid } = require("nanoid");
const Anthropic = require("@anthropic-ai/sdk");

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-this-in-production";
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

if (!process.env.ANTHROPIC_API_KEY) {
  console.warn("⚠️  ANTHROPIC_API_KEY is not set. /api/generate will fail until you set it.");
}

// ---------- simple file-based storage ----------
const DATA_DIR = path.join(__dirname, "data");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

const USERS_FILE = path.join(DATA_DIR, "users.json");
const SITES_FILE = path.join(DATA_DIR, "sites.json");

function readJSON(file) {
  if (!fs.existsSync(file)) return {};
  try {
    return JSON.parse(fs.readFileSync(file, "utf-8"));
  } catch {
    return {};
  }
}
function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

function getUserByEmail(email) {
  const all = readJSON(USERS_FILE);
  return all[email.toLowerCase()] || null;
}
function createUser({ id, email, passwordHash }) {
  const all = readJSON(USERS_FILE);
  const key = email.toLowerCase();
  all[key] = { id, email, passwordHash, createdAt: new Date().toISOString() };
  writeJSON(USERS_FILE, all);
  return all[key];
}

function getSite(slug) {
  const all = readJSON(SITES_FILE);
  return all[slug] || null;
}
function saveSite(slug, siteRecord) {
  const all = readJSON(SITES_FILE);
  all[slug] = { ...siteRecord, updatedAt: new Date().toISOString() };
  writeJSON(SITES_FILE, all);
  return all[slug];
}
function listSitesForOwner(ownerId) {
  const all = readJSON(SITES_FILE);
  return Object.entries(all)
    .map(([slug, data]) => ({ slug, ...data }))
    .filter((s) => s.ownerId === ownerId);
}

function slugify(name) {
  return (
    name.toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "") ||
    nanoid(8)
  );
}

// ---------- auth middleware ----------
function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Not logged in" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired session" });
  }
}

// ---------- AUTH ROUTES ----------
app.post("/api/auth/signup", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "email and password are required" });
  if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });
  if (getUserByEmail(email)) return res.status(409).json({ error: "An account with this email already exists" });

  const passwordHash = await bcrypt.hash(password, 10);
  const user = createUser({ id: nanoid(12), email, passwordHash });
  const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
  res.status(201).json({ token, user: { id: user.id, email: user.email } });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "email and password are required" });

  const user = getUserByEmail(email);
  if (!user) return res.status(401).json({ error: "Invalid email or password" });

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(401).json({ error: "Invalid email or password" });

  const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, user: { id: user.id, email: user.email } });
});

app.get("/api/auth/me", requireAuth, (req, res) => {
  res.json({ userId: req.userId });
});

// ---------- AI GENERATION ----------
app.post("/api/generate", requireAuth, async (req, res) => {
  const { businessName, businessType, description } = req.body;
  if (!businessName || !businessType) {
    return res.status(400).json({ error: "businessName and businessType are required" });
  }

  const prompt = `You are generating website copy for a small business. Return ONLY raw JSON, no markdown fences, no preamble.

Business name: ${businessName}
Business type: ${businessType}
Extra details from owner: ${description || "none provided"}

Generate 3 DIFFERENT design directions for this business's website. Each should feel distinct in tone/mood while staying true to the business. Vary the tagline style, the about tone, and the accent_mood across the three.

Return JSON with this exact shape (an array of exactly 3 items):
[
  {
    "style_label": "short 2-3 word label describing this direction",
    "tagline": "short punchy tagline, under 8 words",
    "hero_description": "1-2 sentence welcoming description of the business",
    "services": [
      {"name": "service or product name", "desc": "one short sentence"},
      {"name": "...", "desc": "..."},
      {"name": "...", "desc": "..."}
    ],
    "about": "2-3 sentence about section written warmly, in first person plural (we/our)",
    "cta": "short call to action button text, 2-4 words",
    "contact_line": "one short inviting sentence encouraging visitors to reach out",
    "accent_mood": "one of: warm, fresh, elegant, bold, earthy"
  }
]`;

  try {
    const message = await anthropic.messages.create({
      model: "claude-sonnet-4-6",
      max_tokens: 2000,
      messages: [{ role: "user", content: prompt }],
    });
    const textBlock = message.content.find((b) => b.type === "text");
    if (!textBlock) throw new Error("No text response from model");
    const cleaned = textBlock.text.replace(/```json|```/g, "").trim();
    const variants = JSON.parse(cleaned);
    res.json({ variants });
  } catch (err) {
    console.error("Generation error:", err.message);
    res.status(500).json({ error: "Failed to generate website content" });
  }
});

// ---------- SITE CRUD (owner-scoped) ----------
app.post("/api/sites", requireAuth, (req, res) => {
  const { businessName, siteData } = req.body;
  if (!businessName || !siteData) {
    return res.status(400).json({ error: "businessName and siteData are required" });
  }

  let slug = slugify(businessName);
  const existing = getSite(slug);
  if (existing && existing.ownerId !== req.userId) {
    slug = `${slug}-${nanoid(5)}`;
  }

  const saved = saveSite(slug, { businessName, siteData, ownerId: req.userId });
  res.json({ slug, site: saved });
});

app.put("/api/sites/:slug", requireAuth, (req, res) => {
  const existing = getSite(req.params.slug);
  if (!existing) return res.status(404).json({ error: "Site not found" });
  if (existing.ownerId !== req.userId) return res.status(403).json({ error: "Not your site" });

  const updated = saveSite(req.params.slug, {
    ...existing,
    siteData: { ...existing.siteData, ...req.body.siteData },
  });
  res.json({ slug: req.params.slug, site: updated });
});

app.get("/api/sites", requireAuth, (req, res) => {
  res.json(listSitesForOwner(req.userId));
});

app.delete("/api/sites/:slug", requireAuth, (req, res) => {
  const existing = getSite(req.params.slug);
  if (!existing) return res.status(404).json({ error: "Site not found" });
  if (existing.ownerId !== req.userId) return res.status(403).json({ error: "Not your site" });

  const all = readJSON(SITES_FILE);
  delete all[req.params.slug];
  writeJSON(SITES_FILE, all);
  res.json({ ok: true });
});

// ---------- PUBLIC LIVE HOSTING (no auth — this is the actual "hosting") ----------
const moodColors = {
  warm: { bg: "#FBF4EC", accent: "#C9A24B", dark: "#4A3A20" },
  fresh: { bg: "#F2F7F1", accent: "#4B7A5A", dark: "#1F3A2E" },
  elegant: { bg: "#F6F5F8", accent: "#6B5B95", dark: "#2E2640" },
  bold: { bg: "#FFF3F0", accent: "#C9532F", dark: "#3A1F14" },
  earthy: { bg: "#F5F1E8", accent: "#8A6B4E", dark: "#3A2E1F" },
};

function renderSiteHTML(businessName, site) {
  const mood = moodColors[site.accent_mood] || moodColors.warm;
  const servicesHTML = (site.services || [])
    .map(
      (s) => `<div style="text-align:center;flex:1;min-width:150px;">
        <h3 style="font-family:Georgia,serif;font-size:16px;margin-bottom:4px;color:${mood.dark}">${s.name}</h3>
        <p style="font-size:13px;opacity:0.7;color:${mood.dark}">${s.desc}</p>
      </div>`
    )
    .join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>${businessName}</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
</head>
<body style="margin:0;font-family:-apple-system,sans-serif;background:${mood.bg}">
  <div style="padding:80px 40px;text-align:center;color:${mood.dark}">
    <p style="font-size:13px;letter-spacing:0.5px;font-weight:500;color:${mood.accent};margin-bottom:12px">${businessName}</p>
    <h1 style="font-family:Georgia,serif;font-size:36px;font-weight:400;margin-bottom:16px">${site.tagline}</h1>
    <p style="font-size:15px;max-width:500px;margin:0 auto 24px;opacity:0.8">${site.hero_description}</p>
    <button style="padding:10px 22px;border-radius:6px;border:none;background:${mood.accent};color:white;font-size:14px;font-weight:500;cursor:pointer">${site.cta}</button>
  </div>
  <div style="padding:40px;background:rgba(255,255,255,0.5)">
    <div style="display:flex;gap:24px;flex-wrap:wrap;justify-content:center;max-width:800px;margin:0 auto">
      ${servicesHTML}
    </div>
  </div>
  <div style="padding:40px;text-align:center;color:${mood.dark}">
    <h2 style="font-family:Georgia,serif;font-size:22px;margin-bottom:12px">About us</h2>
    <p style="font-size:14px;max-width:600px;margin:0 auto;opacity:0.8">${site.about}</p>
  </div>
  <div style="padding:32px;text-align:center;background:${mood.dark};color:${mood.bg}">
    <p style="font-size:14px">${site.contact_line}</p>
  </div>
</body>
</html>`;
}

app.get("/site/:slug", (req, res) => {
  const record = getSite(req.params.slug);
  if (!record) return res.status(404).send("<h1>Site not found</h1>");
  res.send(renderSiteHTML(record.businessName, record.siteData));
});

app.get("/health", (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`AI website builder backend running on http://localhost:${PORT}`);
});
