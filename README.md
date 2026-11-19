# Project Hayati (Node + Express + SQLite)

## Run it on your computer
1. Install Node.js 20 or newer.
2. In this folder: `npm install`
3. `npm start`, then open http://localhost:3000

## Deploy (example: Render)
1. Push this folder to a GitHub repo (`.gitignore` already skips node_modules, data and .env).
2. Render > New > Web Service > pick the repo.
   - Build command: `npm install`
   - Start command: `npm start`
3. Environment variables:
   - `NODE_ENV` = `production`
   - `JWT_SECRET` = a long random string (e.g. run `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`)
   - `DB_PATH` = `/var/data/hayati.db` (a path on a persistent disk, see below)
4. Add a persistent disk mounted at `/var/data`. SQLite is a file, so without a disk it is wiped on every redeploy. (Render disks are a paid feature. Railway and Fly.io volumes work the same way.)

## Files
- `server.js` - API, login (bcrypt + JWT cookie) and SQLite tables
- `public/` - the front-end (index.html, style.css, script.js)
