# CampusLift College Ride Prototype

A campus ride-booking service with server-side accounts, rider and driver dashboards, upfront route quotes, manual driver verification, ratings, ride PINs and shared multi-device ride state. No research dataset is used. Drivers can opt in to share their live position during an assigned ride; the rider sees recent coordinates on an OpenStreetMap view. A key-free Google Maps directions link is also available. Google Places suggestions, calculated route estimates and embedded Google Maps still require Google Maps Platform keys.

## Local laptop demo (PowerShell)

Python 3.9+ is required; the backend uses only Python's standard library. Stop any old CampusLift server with Ctrl+C before restarting so it loads the updated authentication/database code.

```powershell
Set-Location "$HOME\QuickRideCollegePortal"
python server.py
```

Open `http://127.0.0.1:8765`. Register a Rider and a Driver account with different emails. Passwords must be at least 10 characters. Driver sign-up collects a vehicle type, driving licence and selfie; a new driver remains offline until a campus administrator verifies the profile. Accounts are stored on this server, not tied to a browser/device. Passwords are PBKDF2-SHA256 salted hashes; session cookies are HTTP-only and each device gets its own session. Driver licence and selfie uploads are stored as blobs in the shared SQLite database for admin review. Use fictional documents and demo data only.

Optional one-time generated demo accounts (random passwords are printed to PowerShell once and are never embedded in frontend files):

```powershell
python server.py --create-demo-accounts
python server.py
```

If the demo accounts already exist, use their current password or register accounts in the UI; this command will not reset credentials.

## Campus administrator setup

Create the first administrator from a local PowerShell window (stop the running server first):

```powershell
python server.py --create-admin
python server.py
```

Open `http://127.0.0.1:8765/#admin` and sign in. The Driver Verification desk lets an administrator review the uploaded licence and selfie, then approve, reject, suspend or restore a driver. A driver must also have a supported vehicle type and both documents present to become eligible. The backend has a separate college-verification endpoint, but the current Admin dashboard does not display a college-account review list or vehicle/insurance document checklist. Set `CAMPUS_EMAIL_DOMAINS` to a comma-separated list of campus email domains to mark matching accounts as pending campus review. Matching a domain does not automatically verify an account.

## Two laptops on the same Wi-Fi

1. On the host laptop, run `python server.py --host 0.0.0.0 --port 8765` from this folder. Keep the terminal and laptop awake.
2. Run `ipconfig` on the host and note its Wi-Fi IPv4 address, for example `192.168.1.10`.
3. Both laptops visit `http://192.168.1.10:8765` (replace with the actual host address). If Windows prompts, allow Python on Private networks. Do not expose this demo to public Wi-Fi or the internet.
4. Laptop A registers/signs in as Rider, enters pickup/destination, selects a vehicle and confirms. The request is saved in shared `quickride.db` on the host.
5. Laptop B registers/signs in as Driver, turns Online, accepts the request, then starts and completes it. Laptop A polls the shared server and shows each status change.

The API uses relative URLs, so both browsers talk to the laptop that served the page. There are no device-specific databases.

## Optional Google Maps setup

Without a Maps key, manual booking still works and no route/fare data is invented. For Google location suggestions and route distance/time/fare estimates, create a Google Cloud project, enable billing, and enable **Places API (New)** and **Routes API**. To display the embedded route map, enable **Maps Embed API** too. Places/Routes can incur usage-based charges; review quotas and billing before use. The app sends session tokens for autocomplete/place selection. See [Places Autocomplete](https://developers.google.com/maps/documentation/places/web-service/place-autocomplete), [Routes API](https://developers.google.com/maps/documentation/routes/compute_route_directions), and [Maps Embed API](https://developers.google.com/maps/documentation/embed/embedding-map).

The **Open route in Google Maps** button uses official key-free Google Maps URLs for directions. This opens Google Maps in a new tab/app; it is not an embedded Google map, does not geocode free-text locations inside CampusLift, and does not provide a route estimate to CampusLift. Google Maps Platform features require valid project credentials and billing configuration; no key is included in this project. See [Google Maps URLs](https://developers.google.com/maps/documentation/urls/get-started) and [Maps JavaScript API setup](https://developers.google.com/maps/documentation/javascript/get-api-key).

Configure separate keys:

- `GOOGLE_MAPS_API_KEY`: server-only key for Places API (New) and Routes API. Restrict it to those APIs and the server's IP where practical. It is never sent to JavaScript.
- `GOOGLE_MAPS_EMBED_API_KEY`: browser-visible key for the Embed API. It is not secret; restrict it to Maps Embed API and website referrers. For LAN demo add the exact host origin, e.g. `http://192.168.1.10:8765/*`.

Set keys in the PowerShell window that launches the server (replace placeholders; never commit real keys to Git):

```powershell
$env:GOOGLE_MAPS_API_KEY = "YOUR_SERVER_RESTRICTED_KEY"
$env:GOOGLE_MAPS_EMBED_API_KEY = "YOUR_EMBED_RESTRICTED_KEY"
python server.py --host 0.0.0.0 --port 8765
```

Vehicle fare rules, demand thresholds and campus fare caps are centralized in `VEHICLES` and `PRICING` in `server.py`. Route quotes include distance and estimated travel time when Google Routes is configured. The server recalculates fares when booking and ignores client-supplied fare values. Manual booking still works without a route quote; no fare or route is invented in that fallback.

## Live driver location

After a driver accepts a ride, the driver taps **Share live location** and allows the browser's location prompt. CampusLift sends the latest latitude, longitude and accuracy to the shared server database; only that ride's rider and assigned driver can read it. The rider dashboard polls the location and refreshes a map view. The driver can stop sharing at any time. Completed/cancelled rides do not expose a live position; positions older than 60 seconds are treated as stale. This is not a GPS history or background-tracking service.

The live map uses OpenStreetMap tiles when no Google map key is configured; attribution is shown in the embedded map. The current coordinates are included in the OpenStreetMap map request to draw the marker. Google Maps URLs open the route in Google Maps when requested by the user.

Browser location is available only in a secure context: `http://localhost`/`127.0.0.1` is suitable for testing on the same computer, but another laptop/phone visiting `http://192.168...` will generally need a trusted **HTTPS** URL before Chrome or Safari offers GPS. Use an approved HTTPS host or a certificate trusted on every demo device. The current plain-HTTP LAN server remains suitable for ride API demos, but not cross-device browser GPS.

## Database migration

The existing `quickride.db` is extended in place at next server startup. Existing drivers are marked pending review and taken offline until an administrator verifies them; active rides and ride history remain in place. Before migrating the old rides table, the server creates `quickride-pre-auth-backup.sqlite3` once. The CampusLift Iteration 1 migration also creates `quickride-pre-campuslift-iteration1.sqlite3` before adding verification, rating, PIN and fare fields. Existing ride records are retained; older trips without an owner stay in the database but cannot be assigned to a new account. Users, sessions, driver availability, declines and all new rides share the same database.

## Safety and deployment limits

This is for a trusted classroom LAN, not public deployment. LAN mode uses HTTP, so passwords/session cookies are not encrypted in transit. There is no email challenge, password reset, MFA, payment settlement, 24/7 emergency response or production login-abuse protection. Driver licence and selfie uploads are stored in the SQLite database; there is no document retention/deletion workflow, so use fictional documents and establish approved access, retention and deletion rules before any real pilot. Driver verification is an admin-recorded state. The emergency button starts a phone call to 112 where supported; incident reports are stored for an administrator and do not alert emergency services. Public college use needs HTTPS with secure cookies, operational security/privacy review, and college approval. Set a strong `CAMPUSLIFT_PIN_SECRET` outside source control for any shared demo or deployment; the built-in fallback is only for local prototype use. Use fictional names, locations and vehicle numbers in presentations.
