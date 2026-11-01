# CampusLift: local and campus deployment

## Current prototype

CampusLift has PBKDF2 password hashing, HTTP-only server sessions, role checks, verified-driver availability gating, capped server-side fare quotes, ride PINs, rider-to-driver ratings, incident reports, a shared SQLite ride lifecycle and ride-scoped live driver location sharing. Riders can view recent driver coordinates on OpenStreetMap and open a route in Google Maps. Google Places/Routes/Embed services remain optional and require the project's own Google Maps Platform credentials. No research dataset is used.

See README.md for run commands, same-Wi-Fi laptop walkthrough, optional Maps setup, demo pricing configuration and database migration notes.

## API

- `POST /api/auth/register`, `/api/auth/login`, `/api/auth/logout`; `GET /api/auth/me`
- `GET /api/config`, `/api/rides`, `/api/rides/{id}`, `/api/rides/{id}/location`, `/api/driver/summary`
- `POST /api/rides`, `/api/driver/availability`, `/api/rides/{id}/location`, `/api/rides/{id}/location-stop`
- `POST /api/rides/{id}/accept`, `/decline`, `/start`, `/complete`, `/cancel`, `/rating`, `/report`
- Admin-only: `GET /api/admin/overview`, `POST /api/admin/drivers/{id}/verification`, `POST /api/admin/users/{id}/college-verification`, `POST /api/admin/reports/{id}/resolve`
- Optional Maps endpoints: `GET /api/maps/autocomplete`, `GET /api/maps/place`, `POST /api/maps/route`

Sensitive routes check the authenticated role and ride ownership. New requests are available to online drivers; one driver may hold only one active ride; a decline hides a request only for that driver so another driver can receive it. Live driver coordinates are accepted only from the assigned driver during an active ride, readable only by that ride's participants, explicitly opt-in, and cleared on stop or completion. Stale coordinates older than 60 seconds are not returned. Route estimates are recomputed on the server when Google Maps is configured. With no valid key, manual booking, the OpenStreetMap live view and key-free Google Maps directions links remain available.

Browser GPS requires a secure context. Localhost works for a same-computer demo, but a phone or second laptop on the LAN needs HTTPS trusted by its browser. Plain `http://<host-ip>:8765` does not provide cross-device GPS. For public/campus deployment, terminate TLS at an approved HTTPS host/proxy and serve the app from that origin; do not expose the classroom HTTP server publicly.

Driver approval is controlled by the existing driver verification status. The Admin Driver Verification desk can review uploaded licence/selfie documents and approve, reject, suspend or restore drivers. Licence and selfie files are stored as blobs in SQLite and can be downloaded through admin-only document routes; the current Admin dashboard does not expose a college-account review list or vehicle/insurance checklist. Define approved access, retention and deletion rules before handling real identity documents. Riders see the Ride PIN; the assigned driver must enter it before starting. Basic incident reports appear in the admin desk, and the `tel:112` control does not contact CampusLift staff.

Create an admin locally with `python server.py --create-admin` and visit `/#admin`. Set `CAMPUS_EMAIL_DOMAINS` to a comma-separated domain allowlist for pending campus review; a matching email domain is not itself proof of identity.

## Public deployment boundary

Do not expose the classroom server directly to the public internet. Before a college pilot, use HTTPS and secure cookies, add login-abuse controls, secure document verification and retention, approved support/safety/payment workflows, privacy policies, and institutional approval. Restrict Google keys by API and application origin/IP as described in README.md.

## Controlled private beta on Render

For a small, access-restricted beta, deploy one Render Web Service from the reviewed GitHub source. The server uses Render's `PORT` when set and binds to `0.0.0.0`; local development still defaults to `127.0.0.1:8765`. Set the Render start command to:

```sh
python server.py --host 0.0.0.0 --port "$PORT" --db-path /var/data/quickride.db
```

Attach a persistent disk mounted at `/var/data`. The database filename remains `quickride.db`; the app creates its parent directory if needed. Do not copy the local production database into the cloud automatically. Decide separately whether the beta should start with an intentionally prepared database or an empty one. Keep this SQLite deployment to one running service instance.

Set these environment variables in Render, not in a committed `.env` file:

- `CAMPUSLIFT_PIN_SECRET`: a strong, random deployment-only secret.
- `QUICKRIDE_COOKIE_SECURE=true`: enables Secure on user and admin session cookies over HTTPS.
- `GOOGLE_MAPS_API_KEY` and `GOOGLE_MAPS_EMBED_API_KEY`: optional; configure only if the related Maps features are enabled, with the restrictions described above.
- `CAMPUS_UTC_OFFSET_MINUTES` and `CAMPUS_EMAIL_DOMAINS`: optional campus configuration.

Render supplies `PORT`. Restrict beta access using the hosting platform or an approved access layer before sharing the URL. The app's static handler serves only `index.html`, `app.js`, `styles.css`, `quickride-colors.css` and `product-config.js`; API and authorized admin document routes remain handled by the application. `/api/health` is a liveness check and does not verify database readiness.
