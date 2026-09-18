# AI Website Builder — Backend (flat, single-file version)

Only 4 files — easy to upload from a phone, no subfolders needed:

```
server.js         ← everything: auth, AI generation, site storage, live hosting
package.json      ← dependencies list
.env.example      ← copy this to .env and fill in your keys
.gitignore
```

## Upload to GitHub (from phone)

1. Create a new repository on github.com
2. Tap "uploading an existing file"
3. Select all 4 files above and upload them
4. Commit changes

## Deploy on Render

1. render.com → New + → Web Service → connect this repo
2. Build Command: `npm install`
3. Start Command: `npm start`
4. Instance Type: Free
5. Add Environment Variables:
   - `ANTHROPIC_API_KEY` = your key from console.anthropic.com
   - `JWT_SECRET` = any long random string
6. Create Web Service — wait for deploy, copy the URL it gives you
   (looks like `https://your-app-name.onrender.com`)

## Endpoints

```
POST /api/auth/signup   { email, password }        → { token, user }
POST /api/auth/login    { email, password }        → { token, user }
POST /api/generate      { businessName, businessType, description }  [needs auth header]
POST /api/sites         { businessName, siteData }                   [needs auth header]
GET  /api/sites                                                       [needs auth header]
PUT  /api/sites/:slug   { siteData }                                  [needs auth header]
GET  /site/:slug        → the live rendered website (public, no auth)
```

Auth header format: `Authorization: Bearer <token>`

## Notes

- Storage is a flat JSON file in `data/` — fine for testing, but on Render's
  free tier this resets whenever the service restarts/redeploys. Swap in a
  real database (Postgres) once this is validated and you want data to persist.
- Free tier sleeps after 15 min of inactivity; first request after that takes
  30-60 seconds to wake up.
