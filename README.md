# FrostAuth-JS-Example SDK

FrostAuth JavaScript example SDK for https://www.frostauth.cc license key API auth.

This is the **reference implementation** every other SDK port mirrors this
wire behavior. Zero dependencies, Node 18+ (`node:crypto`, `fetch`).

## Bugs

If you're running this example with no significant changes and something's broken,
open an issue with your FrostAuth version, Node version (`node -v`), and the
exact error text.

We do **NOT** provide support for wiring FrostAuth into your project. If the
usage below doesn't make sense yet, learn some JavaScript first (MDN/YouTube),
then come back.

## Security practices

* Ship desktop apps through a protector/packer (pkg/nexe bundle + VMProtect on
the launcher) and put license checks behind their markers, a plain `.js`
next to your exe defeats the point.
* Run frequent integrity checks so patched memory kills the session instead of
granting access.
* Never write a downloaded file to disk if you don't want the user to have it.
Execute in memory and wipe the buffer the moment you're done.
* Treat every client answer as advisory. The server re-checks the license on
each call and don't add a local `isValid` boolean that bypasses it. Match on
`errorCode`, never message text.

FrostAuth signs every response and pins the server key, but no API survives a
client that trusts itself. Obfuscation + integrity checks stop tampering; the
API stops key sharing.

## Copyright License

Copyright (c) 2026 FrostAuth. All rights reserved.

* You may not offer this SDK (or a modified copy of it) to third parties as a
hosted or managed service that reproduces any substantial part of FrostAuth.
* You may not move, change, disable, or circumvent the license-key
functionality in the SDK, and you may not remove or obscure any license-key
enforcement it performs.
* You may not remove or obscure any licensing, copyright, or attribution
notices in the SDK files.

Thank you for your compliance. This SDK is a large body of work, and keeping
the notices intact is what keeps it free.

## What is FrostAuth?

FrostAuth is a cloud licensing platform that protects your software from piracy
and unauthorized access. Hardware-locked licenses, secure auth, real-time
analytics, and a dashboard your customers never see. Client SDKs for JavaScript
(this repo, the reference), C++, C#, Python, Go, Rust, and Java. Come ask
questions on Discord: https://www.frostauth.cc/discord

## Requirements

* Node 18+

## Run

```bash
cd FrostAuth-JS-Example
node example.mjs
```

Or import it (`package.json` publishes `@frostauth/sdk`):

```js
import { FrostAuth } from "./frostauth.js";
// after publish: import { FrostAuth } from "@frostauth/sdk";
```

## `FrostAuth` instance definition

Open your FrostAuth dashboard, pick your product, and copy the three values
into [`example.mjs`](example.mjs):

```js
const app = new FrostAuth({
    owner: "YOUR-OWNER-ID",    // dashboard → owner id
    product: "YOUR-PRODUCT-ID",// dashboard → product → product id
    version: "1.0.0",          // must match the version you ship
});
```

## Initialize application

You must call this before anything else. It fetches the public catalog and
pins the server's signing key (TOFU) — every later response is Ed25519-checked
against it, so a MITM serving a fake key aborts here instead of later.

```js
await app.init();
```

## Display application information

```js
const appData = await app.appData();
console.log("App Version:", appData.product?.version);
console.log("Customer panel:", appData.product ? "enabled" : "unknown");
```

## Check session validation

Re-checks the license/session with the server. Falls back from a stale session
token to the stored license key once.

```js
await app.validate(); // throws FrostAuthError when dead — exit, don't continue
```

## Check blacklist status

Whether this device/IP/key is blacklisted. Optional: the server already
refuses blacklisted callers on login/register, so this is just an early exit
for clients that want to close before showing UI.

```js
await app.checkBlacklist(); // throws on block — exit
```

## Login with username/password

```js
const snap = await app.login(username, password);
// + extras: app.login(user, pw, { twofa: "123456", hash, label: "Alex's desktop" })
```

## Register with username/password/key

```js
const snap = await app.register(key, username, password);
```

## Upgrade user with key

Attaches a license key to an existing app user (adds time). Unlike login and
register this opens **no session** — sign the user in after a successful
upgrade.

```js
await app.upgrade(username, password, key);
console.log("Upgraded. Sign in to use the new licence.");
const snap = await app.login(username, password);
```

## Login with just license key

For key-only products. Binds the key to this machine and opens a session —
no username needed.

```js
const snap = await app.activate(key);
// + extras: app.activate(key, { hash, label })
```

## User Data

Everything about the current session lives in the snapshot:

```js
const snap = app.snapshot();
console.log("Username:", snap.user);
console.log("IP:", snap.account?.lastIp);
console.log("Device Id:", snap.device?.id);
for (const sub of snap.subscriptions ?? [])
    console.log("Subscription:", sub.tier || sub.status);
```

## Check subscription of user

Gate features by tier. Compare against the tier name you configured on the
dashboard — exact match, case-insensitive on the server side.

```js
const pro = (snap.subscriptions ?? []).some(s => (s.tier ?? "").toLowerCase() === "pro");
if (!pro) { console.log("This feature needs a Pro subscription."); process.exit(1); }
```

## Application variables

Server-side strings, global for all users (feature flags, MOTD, config).
Read-only from the client; edit them on the dashboard. Tier- and
version-gated server-side.

```js
console.log("MOTD:", await app.variable("maintenance_message"));
```

## User Variables

Per-user key/value pairs. Read and write them unless the operator marked one
read-only (balances, ranks — server-writable only).

```js
console.log(await app.listVars());       // every variable on this user
console.log(await app.getVar("theme"));  // one variable's value
await app.setVar("theme", "dark");       // write it back
```

## Application Logs

Ship an event to the operator log. Good for anti-debug alerts and crash
breadcrumbs. If the operator set a Discord webhook, it lands there instead of
the dashboard (dashboard logs rotate after 30 days).

```js
await app.log("client started, integrity check passed");
```

## Ban the user

Blacklists the HWID + IP. Call it when your integrity checks catch tampering.
Only works after login. Ends the local session either way.

```js
await app.ban("debugger detected"); // reason shows on next login + dashboard
```

## Server-sided webhooks

Fire an operator-configured webhook by id. The destination URL lives on the
server — the client only supplies params/body, so secrets never ship in your
binary. Tier-gated like files/variables.

```js
const res = await app.webhook("discord", "", '{"content":"Hello from FrostAuth"}');
console.log("upstream:", res.status, "ok:", res.ok);
```

## Heartbeat & offline

`validate()` on a timer keeps the session fresh. The SDK caches a signed
offline assertion when the network drops, `checkOffline()` verifies it
locally so the app keeps working inside the grace window. Events: `init`,
`activated`, `registered`, `loggedIn`, `validated`, `updateAvailable`,
`offline`, `invalid`, `needsActivation`, `closed`.

```js
app.on("offline", ({ secondsOffline, verified }) => console.log("offline:", secondsOffline, verified));
app.startHeartbeat(); // server cadence until stop/close
// ...
const { ok, reason } = app.checkOffline();
if (!ok) console.log("offline:", reason);
// ...
app.stopHeartbeat();
await app.close();
```

## SDK layout

* `frostauth.js` — the whole SDK (reference implementation, zero deps).
* `main.mjs` — the interactive demo this README walks through.