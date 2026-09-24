// AI Website Builder — Backend (single-file version)
// Everything (auth, AI generation, site storage, live hosting) lives in this one file
// so it's easy to upload from a phone without dealing with subfolders.

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { nanoid } = require("nanoid");
const Anthropic = require("@anthropic-ai/sdk");
const { MongoClient } = require("mongodb");
const QRCode = require("qrcode");

const app = express();
app.use(cors());
app.use(express.json({ limit: "6mb" }));

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-this-in-production";
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

if (!process.env.ANTHROPIC_API_KEY) {
  console.warn("⚠️  ANTHROPIC_API_KEY is not set. /api/generate will fail until you set it.");
}

// ---------- MongoDB storage ----------
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  console.error("❌ MONGODB_URI is not set. The server cannot start without a database connection.");
  process.exit(1);
}

const client = new MongoClient(MONGODB_URI);
let usersCol, sitesCol, messagesCol;

async function connectDB() {
  await client.connect();
  const db = client.db("cofounder");
  usersCol = db.collection("users");
  sitesCol = db.collection("sites");
  messagesCol = db.collection("messages");
  await usersCol.createIndex({ email: 1 }, { unique: true });
  await sitesCol.createIndex({ slug: 1 }, { unique: true });
  await messagesCol.createIndex({ slug: 1 });
  console.log("✅ Connected to MongoDB");
}

async function getUserByEmail(email) {
  return usersCol.findOne({ email: email.toLowerCase() });
}
async function createUser({ id, email, passwordHash, securityQuestion, securityAnswerHash }) {
  const user = {
    id,
    email: email.toLowerCase(),
    passwordHash,
    securityQuestion: securityQuestion || null,
    securityAnswerHash: securityAnswerHash || null,
    createdAt: new Date().toISOString(),
  };
  await usersCol.insertOne(user);
  return user;
}
async function updateUserPassword(email, passwordHash) {
  await usersCol.updateOne({ email: email.toLowerCase() }, { $set: { passwordHash } });
}

async function getSite(slug) {
  return sitesCol.findOne({ slug });
}
async function saveSite(slug, siteRecord) {
  const record = { ...siteRecord, slug, updatedAt: new Date().toISOString() };
  await sitesCol.updateOne({ slug }, { $set: record }, { upsert: true });
  return record;
}
async function deleteSiteBySlug(slug) {
  await sitesCol.deleteOne({ slug });
}
async function listSitesForOwner(ownerId) {
  return sitesCol.find({ ownerId }).toArray();
}

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
function isValidEmail(email) {
  return typeof email === "string" && EMAIL_REGEX.test(email.trim());
}
function isValidPassword(password) {
  return typeof password === "string" && password.length >= 8 && /[0-9]/.test(password) && /[a-zA-Z]/.test(password);
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
  const { email, password, securityQuestion, securityAnswer } = req.body;
  if (!email || !password) return res.status(400).json({ error: "email and password are required" });
  if (!isValidEmail(email)) return res.status(400).json({ error: "Please enter a valid email address" });
  if (!isValidPassword(password)) {
    return res.status(400).json({ error: "Password must be at least 8 characters and include a letter and a number" });
  }
  if ((await getUserByEmail(email))) return res.status(409).json({ error: "An account with this email already exists" });
  if (!securityQuestion || !securityAnswer || !securityAnswer.trim()) {
    return res.status(400).json({ error: "Please choose a security question and answer (used for password reset)" });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const securityAnswerHash = await bcrypt.hash(securityAnswer.trim().toLowerCase(), 10);
  const user = await createUser({ id: nanoid(12), email, passwordHash, securityQuestion, securityAnswerHash });
  const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
  res.status(201).json({ token, user: { id: user.id, email: user.email } });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "email and password are required" });

  const user = await getUserByEmail(email);
  if (!user) return res.status(401).json({ error: "Invalid email or password" });

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(401).json({ error: "Invalid email or password" });

  const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, user: { id: user.id, email: user.email } });
});

app.get("/api/auth/security-question", async (req, res) => {
  const email = req.query.email;
  if (!email || !isValidEmail(email)) return res.status(400).json({ error: "Valid email required" });
  const user = await getUserByEmail(email);
  if (!user || !user.securityQuestion) {
    return res.status(404).json({ error: "No account with a security question found for this email" });
  }
  res.json({ securityQuestion: user.securityQuestion });
});

app.post("/api/auth/reset-password", async (req, res) => {
  const { email, securityAnswer, newPassword } = req.body;
  if (!email || !securityAnswer || !newPassword) {
    return res.status(400).json({ error: "email, securityAnswer and newPassword are required" });
  }
  if (!isValidPassword(newPassword)) {
    return res.status(400).json({ error: "Password must be at least 8 characters and include a letter and a number" });
  }
  const user = await getUserByEmail(email);
  if (!user || !user.securityAnswerHash) {
    return res.status(404).json({ error: "No account found for this email" });
  }
  const valid = await bcrypt.compare(securityAnswer.trim().toLowerCase(), user.securityAnswerHash);
  if (!valid) return res.status(401).json({ error: "That answer doesn't match our records" });

  const passwordHash = await bcrypt.hash(newPassword, 10);
  await updateUserPassword(email, passwordHash);
  res.json({ ok: true });
});

app.get("/api/auth/me", requireAuth, (req, res) => {
  res.json({ userId: req.userId });
});

// ---------- AI GENERATION ----------
app.post("/api/generate", requireAuth, async (req, res) => {
  const { businessName, businessType, description, language } = req.body;
  if (!businessName || !businessType) {
    return res.status(400).json({ error: "businessName and businessType are required" });
  }
  const lang = language === "hindi" ? "Hindi (written in Devanagari script)" : "English";

  const prompt = `You are generating website copy for a small business. Return ONLY raw JSON, no markdown fences, no preamble.

Business name: ${businessName}
Business type: ${businessType}
Extra details from owner: ${description || "none provided"}
Write all copy (tagline, descriptions, services, about, cta, contact_line) in: ${lang}. Keep business name and style_label in English regardless.

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
    "accent_mood": "one of: warm, fresh, elegant, bold, earthy, ocean, sunset, mono, blush"
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
app.post("/api/sites", requireAuth, async (req, res) => {
  const { businessName, siteData } = req.body;
  if (!businessName || !siteData) {
    return res.status(400).json({ error: "businessName and siteData are required" });
  }

  let slug = slugify(businessName);
  const existing = await getSite(slug);
  if (existing && existing.ownerId !== req.userId) {
    slug = `${slug}-${nanoid(5)}`;
  }

  const saved = await saveSite(slug, { businessName, siteData, ownerId: req.userId });
  res.json({ slug, site: saved });
});

app.put("/api/sites/:slug", requireAuth, async (req, res) => {
  const existing = await getSite(req.params.slug);
  if (!existing) return res.status(404).json({ error: "Site not found" });
  if (existing.ownerId !== req.userId) return res.status(403).json({ error: "Not your site" });

  const updated = await saveSite(req.params.slug, {
    ...existing,
    siteData: { ...existing.siteData, ...req.body.siteData },
  });
  res.json({ slug: req.params.slug, site: updated });
});

app.get("/api/sites", requireAuth, async (req, res) => {
  res.json(await listSitesForOwner(req.userId));
});

app.delete("/api/sites/:slug", requireAuth, async (req, res) => {
  const existing = await getSite(req.params.slug);
  if (!existing) return res.status(404).json({ error: "Site not found" });
  if (existing.ownerId !== req.userId) return res.status(403).json({ error: "Not your site" });

  await deleteSiteBySlug(req.params.slug);
  res.json({ ok: true });
});

// ---------- CONTACT MESSAGES ----------
app.post("/site/:slug/contact", async (req, res) => {
  const { name, email, message } = req.body;
  if (!name || !message) return res.status(400).json({ error: "name and message are required" });
  const record = await getSite(req.params.slug);
  if (!record) return res.status(404).json({ error: "Site not found" });

  await messagesCol.insertOne({
    slug: req.params.slug,
    name: name.slice(0, 200),
    email: (email || "").slice(0, 200),
    message: message.slice(0, 2000),
    createdAt: new Date().toISOString(),
  });
  res.json({ ok: true });
});

app.get("/api/sites/:slug/messages", requireAuth, async (req, res) => {
  const record = await getSite(req.params.slug);
  if (!record) return res.status(404).json({ error: "Site not found" });
  if (record.ownerId !== req.userId) return res.status(403).json({ error: "Not your site" });

  const messages = await messagesCol.find({ slug: req.params.slug }).sort({ createdAt: -1 }).toArray();
  res.json(messages);
});

// ---------- PUBLIC LIVE HOSTING (no auth — this is the actual "hosting") ----------
const moodColors = {
  warm: { bg: "#FBF4EC", accent: "#C9A24B", dark: "#4A3A20" },
  fresh: { bg: "#F2F7F1", accent: "#4B7A5A", dark: "#1F3A2E" },
  elegant: { bg: "#F6F5F8", accent: "#6B5B95", dark: "#2E2640" },
  bold: { bg: "#FFF3F0", accent: "#C9532F", dark: "#3A1F14" },
  earthy: { bg: "#F5F1E8", accent: "#8A6B4E", dark: "#3A2E1F" },
  ocean: { bg: "#EEF6F8", accent: "#2E7D9E", dark: "#123240" },
  sunset: { bg: "#FFF2E5", accent: "#E0793C", dark: "#5C2E12" },
  mono: { bg: "#F4F4F4", accent: "#333333", dark: "#111111" },
  blush: { bg: "#FDF1F4", accent: "#D4537E", dark: "#4A1F2C" },
};

function renderSiteHTML(businessName, site, slug) {
  const mood = moodColors[site.accent_mood] || moodColors.warm;
  const servicesHTML = (site.services || [])
    .map(
      (s) => `<div style="text-align:center;flex:1;min-width:150px;">
        <h3 style="font-family:Georgia,serif;font-size:16px;margin-bottom:4px;color:${mood.dark}">${s.name}</h3>
        <p style="font-size:13px;opacity:0.7;color:${mood.dark}">${s.desc}</p>
      </div>`
    )
    .join("");

  const heroImageHTML = site.heroImage
    ? `<img src="${site.heroImage}" alt="${businessName}" style="max-width:100%;height:auto;border-radius:10px;margin:0 auto 20px;display:block;max-height:280px;object-fit:cover" />`
    : "";

  // #1 WhatsApp floating button
  const waNumber = (site.whatsappNumber || "").replace(/[^0-9]/g, "");
  const whatsappHTML = waNumber
    ? `<a href="https://wa.me/${waNumber}?text=${encodeURIComponent("Hi " + businessName + ", I found you online!")}" target="_blank" rel="noreferrer"
        style="position:fixed;bottom:20px;right:20px;width:56px;height:56px;border-radius:50%;background:#25D366;display:flex;align-items:center;justify-content:center;box-shadow:0 4px 12px rgba(0,0,0,0.25);z-index:50;text-decoration:none">
        <svg width="28" height="28" viewBox="0 0 24 24" fill="white"><path d="M12.04 2C6.58 2 2.13 6.45 2.13 11.91c0 1.75.46 3.46 1.32 4.96L2 22l5.25-1.38c1.44.79 3.08 1.2 4.79 1.2 5.46 0 9.91-4.45 9.91-9.91C21.95 6.45 17.5 2 12.04 2zm0 18.06c-1.5 0-2.98-.4-4.27-1.16l-.3-.18-3.12.82.83-3.04-.2-.31a8.06 8.06 0 0 1-1.24-4.28c0-4.47 3.63-8.1 8.1-8.1 4.47 0 8.1 3.63 8.1 8.1 0 4.47-3.63 8.15-8.1 8.15z"/></svg>
      </a>`
    : "";

  // #3 Google Maps embed
  const mapHTML = site.address
    ? `<div style="padding:0 40px 40px;text-align:center">
        <h2 style="font-family:Georgia,serif;font-size:20px;margin-bottom:12px;color:${mood.dark}">Find us</h2>
        <p style="font-size:13px;margin-bottom:12px;opacity:0.8;color:${mood.dark}">${site.address}</p>
        <iframe
          src="https://maps.google.com/maps?q=${encodeURIComponent(site.address)}&output=embed"
          style="border:0;width:100%;max-width:600px;height:220px;border-radius:8px" loading="lazy"></iframe>
      </div>`
    : "";

  // #6 Business hours
  const DAY_LABELS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  const hoursHTML = site.hours && site.hours.open && site.hours.close
    ? `<div style="padding:0 40px 40px;text-align:center;color:${mood.dark}">
        <p id="hoursStatus" style="font-size:14px;font-weight:600;margin-bottom:4px"></p>
        <p style="font-size:13px;opacity:0.75">${site.hours.open} – ${site.hours.close}${
        site.hours.closedDays && site.hours.closedDays.length
          ? " · Closed: " + site.hours.closedDays.join(", ")
          : ""
      }</p>
      </div>
      <script>
        (function() {
          var open = "${site.hours.open}", close = "${site.hours.close}";
          var closedDays = ${JSON.stringify(site.hours.closedDays || [])};
          var dayLabels = ${JSON.stringify(DAY_LABELS)};
          var now = new Date();
          var today = dayLabels[now.getDay()];
          var mins = now.getHours() * 60 + now.getMinutes();
          function toMins(t) { var p = t.split(":").map(Number); return p[0]*60+(p[1]||0); }
          var isOpen = closedDays.indexOf(today) === -1 && mins >= toMins(open) && mins < toMins(close);
          var el = document.getElementById("hoursStatus");
          if (el) {
            el.textContent = isOpen ? "● Open now" : "● Closed now";
            el.style.color = isOpen ? "#2F7A3E" : "#B23B3B";
          }
        })();
      </script>`
    : "";

  // #8 Social links
  const socialLinks = [];
  if (site.socialInstagram) socialLinks.push(`<a href="${site.socialInstagram}" target="_blank" rel="noreferrer" style="color:${mood.dark};text-decoration:underline;font-size:13px;margin:0 8px">Instagram</a>`);
  if (site.socialFacebook) socialLinks.push(`<a href="${site.socialFacebook}" target="_blank" rel="noreferrer" style="color:${mood.dark};text-decoration:underline;font-size:13px;margin:0 8px">Facebook</a>`);
  const socialHTML = socialLinks.length
    ? `<div style="text-align:center;padding-bottom:24px">${socialLinks.join("")}</div>`
    : "";

  // #9 Reviews
  const reviewsHTML = site.reviews && site.reviews.length
    ? `<div style="padding:0 40px 40px;text-align:center">
        <h2 style="font-family:Georgia,serif;font-size:20px;margin-bottom:16px;color:${mood.dark}">What people say</h2>
        <div style="display:flex;gap:16px;flex-wrap:wrap;justify-content:center;max-width:800px;margin:0 auto">
          ${site.reviews
            .map(
              (r) => `<div style="background:rgba(255,255,255,0.6);border-radius:8px;padding:16px;max-width:240px;text-align:left">
                <p style="font-size:13px;font-style:italic;color:${mood.dark};margin-bottom:8px">"${r.text}"</p>
                <p style="font-size:12px;font-weight:600;color:${mood.accent}">— ${r.name}</p>
              </div>`
            )
            .join("")}
        </div>
      </div>`
    : "";

  // #2 Contact form
  const contactFormHTML = `
    <div style="padding:40px;background:rgba(255,255,255,0.5)" id="contactSection">
      <h2 style="font-family:Georgia,serif;font-size:20px;margin-bottom:16px;text-align:center;color:${mood.dark}">Get in touch</h2>
      <form id="contactForm" style="max-width:420px;margin:0 auto;display:flex;flex-direction:column;gap:10px">
        <input required name="name" placeholder="Your name" style="padding:10px 12px;border-radius:6px;border:1px solid rgba(0,0,0,0.15);font-size:14px" />
        <input name="email" type="email" placeholder="Your email (optional)" style="padding:10px 12px;border-radius:6px;border:1px solid rgba(0,0,0,0.15);font-size:14px" />
        <textarea required name="message" placeholder="Message" rows="3" style="padding:10px 12px;border-radius:6px;border:1px solid rgba(0,0,0,0.15);font-size:14px"></textarea>
        <button type="submit" style="padding:10px;border-radius:6px;border:none;background:${mood.accent};color:white;font-weight:600;font-size:14px;cursor:pointer">Send message</button>
        <p id="contactStatus" style="font-size:12px;text-align:center;color:${mood.dark}"></p>
      </form>
    </div>
    <script>
      var f = document.getElementById('contactForm');
      if (f) {
        f.addEventListener('submit', function(e) {
          e.preventDefault();
          var status = document.getElementById('contactStatus');
          var data = { name: f.name.value, email: f.email.value, message: f.message.value };
          status.textContent = 'Sending...';
          fetch('/site/${slug}/contact', {
            method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(data)
          }).then(function(r){ return r.json(); }).then(function(d){
            if (d.ok) { status.textContent = 'Message sent!'; f.reset(); }
            else { status.textContent = 'Something went wrong. Try again.'; }
          }).catch(function(){ status.textContent = 'Something went wrong. Try again.'; });
        });
      }
    </script>`;

  // #7 Share button
  const shareHTML = `
    <div style="text-align:center;padding-bottom:24px">
      <button id="shareBtn" style="padding:8px 16px;border-radius:20px;border:1px solid ${mood.dark};background:transparent;color:${mood.dark};font-size:13px;cursor:pointer">Share this page</button>
    </div>
    <script>
      var sb = document.getElementById('shareBtn');
      if (sb) {
        sb.addEventListener('click', function() {
          var url = window.location.href;
          if (navigator.share) {
            navigator.share({ title: document.title, url: url }).catch(function(){});
          } else {
            window.open('https://wa.me/?text=' + encodeURIComponent(document.title + ' ' + url), '_blank');
          }
        });
      }
    </script>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>${businessName}</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover" />
<meta name="theme-color" content="${mood.dark}" />
<meta name="mobile-web-app-capable" content="yes" />
<meta name="apple-mobile-web-app-capable" content="yes" />
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent" />
<meta name="apple-mobile-web-app-title" content="${businessName}" />
<link rel="manifest" href="/site/${slug}/manifest.json" />
<link rel="apple-touch-icon" href="/site/${slug}/icon.svg" />
<link rel="icon" href="/site/${slug}/icon.svg" type="image/svg+xml" />
</head>
<body style="margin:0;font-family:-apple-system,sans-serif;background:${mood.bg}">
  ${whatsappHTML}
  <div style="padding:80px 40px 40px;text-align:center;color:${mood.dark}">
    ${heroImageHTML}
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
  ${hoursHTML}
  ${mapHTML}
  ${reviewsHTML}
  ${contactFormHTML}
  <div style="padding:32px;text-align:center;background:${mood.dark};color:${mood.bg}">
    <p style="font-size:14px;margin-bottom:16px">${site.contact_line}</p>
  </div>
  ${socialHTML}
  ${shareHTML}
  <script>
    if ('serviceWorker' in navigator) {
      window.addEventListener('load', () => {
        navigator.serviceWorker.register('/site/${slug}/sw.js').catch(() => {});
      });
    }
  </script>
</body>
</html>`;
}

function renderIconSVG(businessName, site) {
  const mood = moodColors[site.accent_mood] || moodColors.warm;
  const letter = (businessName || "?").trim().charAt(0).toUpperCase() || "?";
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 192 192" width="192" height="192">
  <rect width="192" height="192" rx="28" fill="${mood.dark}" />
  <text x="96" y="128" font-family="Georgia, serif" font-size="96" fill="${mood.accent}" text-anchor="middle">${letter}</text>
</svg>`;
}

app.get("/site/:slug", async (req, res) => {
  const record = await getSite(req.params.slug);
  if (!record) return res.status(404).send("<h1>Site not found</h1>");
  res.send(renderSiteHTML(record.businessName, record.siteData, req.params.slug));
});

app.get("/site/:slug/manifest.json", async (req, res) => {
  const record = await getSite(req.params.slug);
  if (!record) return res.status(404).json({ error: "Site not found" });
  const mood = moodColors[record.siteData.accent_mood] || moodColors.warm;
  res.json({
    name: record.businessName,
    short_name: record.businessName.slice(0, 12),
    start_url: `/site/${req.params.slug}`,
    scope: `/site/${req.params.slug}`,
    display: "standalone",
    background_color: mood.bg,
    theme_color: mood.dark,
    icons: [
      { src: `/site/${req.params.slug}/icon.svg`, sizes: "192x192", type: "image/svg+xml" },
      { src: `/site/${req.params.slug}/icon.svg`, sizes: "512x512", type: "image/svg+xml" },
    ],
  });
});

app.get("/site/:slug/icon.svg", async (req, res) => {
  const record = await getSite(req.params.slug);
  if (!record) return res.status(404).send("");
  res.set("Content-Type", "image/svg+xml");
  res.send(renderIconSVG(record.businessName, record.siteData));
});

app.get("/site/:slug/sw.js", (req, res) => {
  res.set("Content-Type", "application/javascript");
  res.send(`
    const CACHE_NAME = 'site-${req.params.slug}-v1';
    self.addEventListener('install', (e) => { self.skipWaiting(); });
    self.addEventListener('activate', (e) => { self.clients.claim(); });
    self.addEventListener('fetch', (e) => {
      e.respondWith(
        caches.open(CACHE_NAME).then((cache) =>
          fetch(e.request)
            .then((res) => { cache.put(e.request, res.clone()); return res; })
            .catch(() => cache.match(e.request))
        )
      );
    });
  `);
});

app.get("/site/:slug/qr.png", async (req, res) => {
  const record = await getSite(req.params.slug);
  if (!record) return res.status(404).send("Site not found");
  const siteUrl = `${req.protocol}://${req.get("host")}/site/${req.params.slug}`;
  try {
    res.set("Content-Type", "image/png");
    const buffer = await QRCode.toBuffer(siteUrl, { width: 500, margin: 2 });
    res.send(buffer);
  } catch (e) {
    res.status(500).send("Could not generate QR code");
  }
});

app.get("/health", (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3001;
connectDB()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`AI website builder backend running on http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error("❌ Failed to connect to MongoDB:", err.message);
    process.exit(1);
  });
