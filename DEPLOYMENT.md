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
