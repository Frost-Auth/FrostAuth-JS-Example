import { createHash, createPublicKey, randomBytes, randomInt, verify as edVerify } from "node:crypto";
import { exec } from "node:child_process";
import { EventEmitter } from "node:events";
import { promisify } from "node:util";
import { lookup as dnsLookup } from "node:dns/promises";
import { networkInterfaces } from "node:os";
import { arch, cpus, hostname, platform, totalmem, userInfo } from "node:os";

const run = promisify(exec);

export const SDK_VERSION = "1.0.0";
export const DEFAULT_BASE_URL = "https://api.frostauth.cc";

export const PUBLIC_KEYS = Object.freeze({ k2: "MCowBQYDK2VwAyEA7xdiHZqo4DmS4O1C8FavYq9Yqk5QbBkJiicb1MTTFzo" });

export const CLIENT_CODES = Object.freeze({
    CONFIG: "CONFIG",
    NETWORK: "NETWORK",
    TIMEOUT: "TIMEOUT",
    NOT_INITIALIZED: "NOT_INITIALIZED",
    NOT_ACTIVATED: "NOT_ACTIVATED",
    SERVER_ERROR: "SERVER_ERROR",
    SIGNATURE: "SIGNATURE",
});

export class FrostAuthError extends Error {
    constructor(message, { code = CLIENT_CODES.SERVER_ERROR, status = 0, retryable = false, cause, requestId = null } = {}) {
        super(message);
        this.name = "FrostAuthError";
        this.code = code;
        this.status = status;
        this.retryable = retryable;
        this.requestId = requestId;

        if (cause) this.cause = cause;
    }

    get needsActivation() {
        return this.status === 404 && !this.retryable;
    }

    get terminal() {
        return !this.retryable && !this.needsActivation && this.status >= 400 && this.status < 500;
    }
}

const MACHINE_ID_COMMANDS = {
    win32: {
        cmd: 'reg query "HKLM\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid',
        pattern: /MachineGuid\s+REG_SZ\s+([\w-]+)/i,
    },
    darwin: {
        cmd: "ioreg -rd1 -c IOPlatformExpertDevice",
        pattern: /"IOPlatformUUID"\s*=\s*"([^"]+)"/,
    },
    linux: {
        cmd: "cat /etc/machine-id 2>/dev/null || cat /var/lib/dbus/machine-id 2>/dev/null",
        pattern: /([0-9a-f]{8,})/i,
    },
};

let machineIdCache = null;

async function rawMachineId() {
    if (machineIdCache) return machineIdCache;

    const probe = MACHINE_ID_COMMANDS[platform()];

    if (probe) {
        try {

            const { stdout } = await run(probe.cmd, { timeout: 5000, windowsHide: true });
            const found = probe.pattern.exec(stdout);
            if (found?.[1]) {
                machineIdCache = found[1].trim();
                return machineIdCache;
            }
        } catch {  }
    }

    machineIdCache = `fallback:${hostname()}:${safeUser()}:${platform()}`;
    return machineIdCache;
}

function safeUser() {
    try {
        return userInfo().username;
    } catch {
        return "unknown";
    }
}

export async function hardwareId(scope = "frostauth") {
    const raw = await rawMachineId();
    return createHash("sha256").update(`${scope}|${raw}`).digest("hex");
}

const facet = (value) => createHash("sha256").update(String(value)).digest("hex").slice(0, 32);

const VM_MAC_PREFIXES = [
    "00:05:69", 
    "00:0c:29", 
    "00:1c:14", 
    "00:50:56",
    "08:00:27", 
    "0a:00:27",
    "00:15:5d",
    "00:1c:42",
    "52:54:00",
    "00:16:3e",
];

const VM_NAME_PATTERN = /vmware|virtualbox|vbox|qemu|kvm|xen|hyper-?v|parallels|bhyve|virtual machine|innotek/i;

const VM_PROBES = {
    win32: 'reg query "HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS" /v SystemManufacturer',
    darwin: "ioreg -l -d 2 -c IOPlatformExpertDevice",
    linux: "cat /sys/class/dmi/id/product_name /sys/class/dmi/id/sys_vendor 2>/dev/null",
};

function macAddresses() {
    const found = [];

    for (const list of Object.values(networkInterfaces() ?? {})) {
        for (const nic of list ?? []) {
            if (nic.internal || !nic.mac || nic.mac === "00:00:00:00:00:00") continue;
            found.push(nic.mac.toLowerCase());
        }
    }

    return [...new Set(found)].sort();
}

let hardwareCache = null;

export async function hardwareProfile() {
    if (hardwareCache) return hardwareCache;

    const macs = macAddresses();
    const cpu = cpus()?.[0]?.model ?? "unknown";

    const components = [
        { n: "cpu", v: facet(`${cpu}|${cpus()?.length ?? 0}`) },
        { n: "ram", v: facet(Math.round(totalmem() / 1024 ** 3)) },
        { n: "arch", v: facet(arch()) },
        { n: "platform", v: facet(platform()) },
        { n: "host", v: facet(hostname()) },
        ...(macs.length ? [{ n: "mac", v: facet(macs.join(",")) }] : []),
    ];

    const hypervisorMacs = macs.filter((mac) => VM_MAC_PREFIXES.includes(mac.slice(0, 8)));
    const allNicsVirtual = macs.length > 0 && hypervisorMacs.length === macs.length;

    let firmwareSaysVm = false;
    if (VM_PROBES[platform()]) {
        try {
            const { stdout } = await run(VM_PROBES[platform()], { timeout: 5000, windowsHide: true });
            firmwareSaysVm = VM_NAME_PATTERN.test(stdout);
        } catch {  }
    }

    const virtual = firmwareSaysVm || allNicsVirtual || VM_NAME_PATTERN.test(cpu);

    hardwareCache = { components, virtual };
    return hardwareCache;
}

const SIGNING_INPUT = (timestamp, nonce, method, path, status, body) => `${timestamp}\n${nonce}\n${method}\n${path}\n${status}\n${body}`;

const MAX_SIGNATURE_SKEW_MS = 60_000;

const ASSERTION_PREFIX = "frostauth:assertion:v1";

const assertionClaimString = (c) => [
    ASSERTION_PREFIX, 1, c.lic, c.pid, c.dev, c.hwid, c.status, c.tier,
    c.exp ?? "", c.iat, c.nbf, c.naf,
].join("\n");

const parseTime = (value) => {
    if (typeof value === "number" && Number.isFinite(value)) return value;
    if (typeof value === "string" && value.trim()) {
        const t = Date.parse(value);
        if (Number.isFinite(t)) return t;
    }
    return null;
};

export function verifyAssertion(assertion, pinned, { hwid = null, at = Date.now() } = {}) {
    const ring = pinned instanceof KeyRing ? pinned : keyRing(pinned);
    if (!ring.size) return { ok: false, reason: "no pinned public key" };

    const parts = String(assertion ?? "").split(".");
    if (parts.length !== 3) return { ok: false, reason: "malformed" };

    const candidates = ring.select(parts[2]);
    if (!candidates.length) return { ok: false, reason: `signed with key "${parts[2]}", which this build does not trust` };

    let claims;
    try {
        claims = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    } catch {
        return { ok: false, reason: "unreadable" };
    }

    const material = Buffer.from(assertionClaimString(claims), "utf8");
    const signature = Buffer.from(parts[1], "base64url");

    let ok = false;
    for (const key of candidates) {
        try {
            if (edVerify(null, material, key, signature)) {
                ok = true;
                break;
            }
        } catch {  }
    }

    if (!ok) return { ok: false, reason: "signature does not verify" };
    if (hwid && claims.hwid !== hwid) return { ok: false, reason: "issued for a different machine" };

    const nbf = parseTime(claims.nbf);
    const naf = parseTime(claims.naf);

    if (nbf === null || naf === null || naf <= nbf) return { ok: false, reason: "offline window is missing or unreadable" };

    if (at < nbf) return { ok: false, reason: "not yet valid" };
    if (at > naf) return { ok: false, reason: "offline period has run out" };

    if (claims.exp) {
        const exp = parseTime(claims.exp);
        if (exp === null || at > exp) return { ok: false, reason: "licence expired" };
    }

    return { ok: true, claims };
}

const isKeyObject = (v) => Boolean(v) && typeof v === "object" && typeof v.export === "function" && typeof v.asymmetricKeyType === "string";

function loadOneKey(value, label) {
    if (isKeyObject(value)) {
        if (value.asymmetricKeyType !== "ed25519") {
            throw new FrostAuthError(`${label} is ${value.asymmetricKeyType}, not an Ed25519 public key`, {
                code: CLIENT_CODES.CONFIG,
            });
        }
        return value;
    }

    try {

        const key = String(value).includes("-----BEGIN") ? createPublicKey(String(value)) : createPublicKey({ key: Buffer.from(String(value), "base64url"), format: "der", type: "spki" });
        if (key.asymmetricKeyType !== "ed25519") throw new FrostAuthError(`${label} is ${key.asymmetricKeyType}, not an Ed25519 public key`, { code: CLIENT_CODES.CONFIG });

        return key;
    } catch (cause) {
        if (cause instanceof FrostAuthError) throw cause;

        throw new FrostAuthError(`${label} is not a usable Ed25519 public key`, { code: CLIENT_CODES.CONFIG, cause });
    }
}

class KeyRing {

    #entries = [];

    constructor(entries) {
        this.#entries = entries;
    }

    get size() {
        return this.#entries.length;
    }

    get ids() {
        return this.#entries.map((e) => e.id).filter(Boolean);
    }

    get primary() {
        return this.#entries[0]?.key ?? null;
    }

    select(keyId) {
        const id = String(keyId ?? "").trim();

        if (!id) return this.#entries.map((e) => e.key);

        const named = this.#entries.filter((e) => e.id === id);
        if (named.length) return named.map((e) => e.key);

        if (this.#entries.every((e) => e.id === null)) return this.#entries.map((e) => e.key);

        return [];
    }
}

function keyRing(value) {
    if (value === null || value === undefined || value === "") return new KeyRing([]);
    if (value instanceof KeyRing) return value;

    if (Array.isArray(value)) {
        return new KeyRing(value.map((v, i) => ({ id: null, key: loadOneKey(v, `publicKey[${i}]`) })));
    }

    if (!isKeyObject(value) && typeof value === "object") {
        const entries = Object.entries(value)
            .filter(([, v]) => v !== null && v !== undefined && v !== "")
            .map(([id, v]) => ({ id: String(id), key: loadOneKey(v, `publicKey["${id}"]`) }));

        if (!entries.length) {
            throw new FrostAuthError("publicKey was given as an empty set of keys", { code: CLIENT_CODES.CONFIG });
        }

        return new KeyRing(entries);
    }

    return new KeyRing([{ id: null, key: loadOneKey(value, "publicKey") }]);
}

function isPrivateAddress(ip) {
    return (
        ip === "::1" || ip === "::" || ip === "0.0.0.0" ||
        ip.startsWith("127.") || ip.startsWith("10.") ||
        ip.startsWith("192.168.") || ip.startsWith("169.254.") ||
        ip.startsWith("fc") || ip.startsWith("fd") || ip.startsWith("fe80") ||
        /^172\.(1[6-9]|2\d|3[01])\./.test(ip)
    );
}

function makeLogger(debug) {
    if (!debug) return () => {};
    const sink = typeof debug === "function" ? debug : (line, data) => console.debug(`[frostauth] ${line}`, data ?? "");

    return (line, data) => {
        try {
            sink(line, data);
        } catch {  }
    };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const backoff = (attempt, base) => randomInt(0, Math.min(base * 2 ** attempt, 15_000) + 1);
const isPlainObject = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
const MAX_RETRY_AFTER_SECONDS = 10;

function requireString(value, field) {
    if (typeof value !== "string" || !value.trim()) throw new FrostAuthError(`${field} is required`, { code: CLIENT_CODES.CONFIG });
    return value.trim();
}

export class FrostAuth extends EventEmitter {
    #key = null;
    #session = null;
    #timer = null;
    #offlineSince = null;
    #assertion = null;
    #keys = null;

    #machineId = null;
    #closed = false;
    #hardwareId = null;
    #allowPrivateDns = false;
    #dnsChecked = false;

    constructor(options = {}) {
        super();

        if (!isPlainObject(options)) {
            throw new FrostAuthError("FrostAuth expects an options object", { code: CLIENT_CODES.CONFIG });
        }

        this.owner = requireString(options.owner, "owner");
        this.product = requireString(options.product, "product");
        this.version = requireString(options.version, "version");

        this.baseUrl = DEFAULT_BASE_URL;
        this.timeout = Number(options.timeout ?? 10_000);
        this.retries = Math.max(0, Number(options.retries ?? 2));
        this.offlineGraceSeconds = Number(options.offlineGraceSeconds ?? 900);

        this.#hardwareId = options.hardwareId ?? null;
        this.#allowPrivateDns = options.allowPrivateDns === true;
        this.#keys = keyRing(options.publicKey);
        this.publicKey = this.#keys.primary;
        this.pinnedKeyIds = this.#keys.ids;
        this.collectHardware = options.collectHardware !== false;
        this.debug = options.debug ?? false;
        this.trace = makeLogger(this.debug);

        const url = new URL(this.baseUrl);
        const loopback = ["localhost", "127.0.0.1", "::1"].includes(url.hostname);

        if (url.protocol !== "https:" && !loopback && !options.allowInsecure) throw new FrostAuthError("Refusing to send a licence key over plain http. Use https, or pass allowInsecure: true if you know what you are doing.", { code: CLIENT_CODES.CONFIG });

        this.initialized = false;
        this.activated = false;
        this.app = null;
        this.license = null;
        this.user = null;
        this.device = null;

        this.account = null;

        this.subscriptions = [];

        this.offlineUntil = null;
    }

    get valid() {
        return this.activated && !this.#closed;
    }

    get offlineFor() {
        return this.#offlineSince ? Math.floor((Date.now() - this.#offlineSince) / 1000) : 0;
    }

    async init() {
        await this.#assertRealHost();

        const path = `/api/v1/settings/catalog/${encodeURIComponent(this.owner)}/${encodeURIComponent(this.product)}`;
        const body = await this.#request("GET", path, null, { envelope: false });

        if (!body?.success) {
            throw new FrostAuthError(body?.message ?? "Application not found", {
                code: body?.error ?? "APP_NOT_FOUND",
                status: 404,
            });
        }

        const keyId = String(body.key_id ?? "");
        const served = String(body.public_key ?? "");
        const pinned = PUBLIC_KEYS[keyId];
        if (!keyId || !pinned || served !== pinned) {
            throw new FrostAuthError("Server identity check failed — refusing to continue", {
                code: CLIENT_CODES.SIGNATURE,
                status: 401,
            });
        }

        this.#keys = keyRing({ [keyId]: pinned });
        this.publicKey = this.#keys.primary;
        this.pinnedKeyIds = this.#keys.ids;

        this.app = { name: body.app_name, ownerId: body.owner_id, messages: body.errors ?? {} };
        this.initialized = true;

        this.emit("init", this.app);
        return this.app;
    }

    async activate(key, extra = {}) {
        this.#assertInitialized();

        const licenseKey = requireString(key, "licence key");
        const hwid = await this.#machine();

        const data = await this.#request("POST", "/api/v1/activate", {
            key: licenseKey,
            hwid,
            os: platform(),
            appVersion: this.version,
            ...(await this.#hardware()),
            ...(extra.hash ? { hash: extra.hash } : {}),
            ...(extra.label ? { label: String(extra.label).slice(0, 64) } : {}),
        });

        this.#key = licenseKey;
        this.#adopt(data);
        this.activated = true;
        this.#offlineSince = null;

        this.emit("activated", this.snapshot());
        return this.snapshot();
    }

    async register(key, username, password, extra = {}) {
        this.#assertInitialized();

        const licenseKey = requireString(key, "licence key");
        const hwid = await this.#machine();

        const data = await this.#request("POST", "/api/v1/sdk/register", {
            key: licenseKey,
            username: requireString(username, "username"),
            password: requireString(password, "password"),
            hwid,
            os: platform(),
            appVersion: this.version,
            ...(await this.#hardware()),
            ...(extra.hash ? { hash: extra.hash } : {}),
            ...(extra.label ? { label: String(extra.label).slice(0, 64) } : {}),
        });

        this.#key = licenseKey;
        this.#adopt(data);
        this.activated = true;
        this.#offlineSince = null;

        this.emit("registered", this.snapshot());
        this.emit("activated", this.snapshot());
        return this.snapshot();
    }

    async login(username, password, extra = {}) {
        this.#assertInitialized();

        const hwid = await this.#machine();

        const data = await this.#request("POST", "/api/v1/sdk/login", {
            owner: this.owner,
            product: this.product,
            username: requireString(username, "username"),
            password: requireString(password, "password"),
            hwid,
            os: platform(),
            appVersion: this.version,
            ...(await this.#hardware()),
            ...(extra.twofa ? { twofa: String(extra.twofa) } : {}),
            ...(extra.hash ? { hash: extra.hash } : {}),
            ...(extra.label ? { label: String(extra.label).slice(0, 64) } : {}),
        });

        this.#adopt(data);
        this.activated = true;
        this.#offlineSince = null;

        this.emit("loggedIn", this.snapshot());
        this.emit("activated", this.snapshot());
        return this.snapshot();
    }

    async upgrade(username, password, key) {
        this.#assertInitialized();

        return this.#request("POST", "/api/v1/sdk/upgrade", {
            owner: this.owner,
            product: this.product,
            username: requireString(username, "username"),
            password: requireString(password, "password"),
            key: requireString(key, "licence key"),
        });
    }

    async logout() {
        if (!this.#session?.token) {
            this.close();
            return { signedOut: true };
        }

        try {
            return await this.#authed("POST", "/api/v1/sdk/logout");
        } finally {
            this.close();
        }
    }

    async changeUsername(username, password) {
        const data = await this.#authed("PATCH", "/api/v1/sdk/username", {
            username: requireString(username, "username"),
            password: requireString(password, "password"),
        });

        if (this.account) this.account.username = data.username;
        this.user = data.username;

        return data;
    }

    async session() {
        const data = await this.#authed("GET", "/api/v1/sdk/session");
        this.#adopt(data);

        return this.snapshot();
    }

    async variable(key) {
        const data = await this.#authed("GET", `/api/v1/sdk/vars/app/${encodeURIComponent(key)}`);
        return data.value;
    }

    async listVars() {
        const data = await this.#authed("GET", "/api/v1/sdk/vars/user");
        return data.variables;
    }

    async getVar(key) {
        const data = await this.#authed("GET", `/api/v1/sdk/vars/user/${encodeURIComponent(key)}`);
        return data.value;
    }

    async setVar(key, value) {
        return this.#authed("PUT", `/api/v1/sdk/vars/user/${encodeURIComponent(key)}`, { value: String(value ?? "") });
    }

    async log(message) {
        return this.#authed("POST", "/api/v1/sdk/log", { message: String(message ?? "").slice(0, 256) });
    }

    async ban(reason = "") {
        try {
            return await this.#authed("POST", "/api/v1/sdk/ban", { reason: String(reason).slice(0, 200) });
        } finally {
            this.stopHeartbeat();
            this.activated = false;
            this.#assertion = null;
            this.offlineUntil = null;
        }
    }

    async fetchOnline() {
        return this.#authed("GET", "/api/v1/sdk/online");
    }

    async checkBlacklist() {
        return this.#authed("GET", "/api/v1/sdk/checkblacklist");
    }

    async file(id) {
        void id;
        throw new FrostAuthError("File downloads are disabled on this server", {
            code: CLIENT_CODES.SERVER_ERROR,
        });
    }

    async webhook(id, params = "", body = "", conttype = "") {
        const webId = requireString(id, "webhook id");
        return this.#authed("POST", `/api/v1/sdk/webhook/${encodeURIComponent(webId)}`, {
            ...(params ? { params: String(params).slice(0, 2048) } : {}),
            ...(body ? { body: String(body).slice(0, 8192) } : {}),
            ...(conttype ? { conttype: String(conttype).slice(0, 128) } : {}),
        });
    }

    async appData() {
        return this.#authed("GET", "/api/v1/sdk/app");
    }

    async validate() {
        this.#assertInitialized();

        if (!this.#session?.token && !this.#key) {
            throw new FrostAuthError("Activate before validating", { code: CLIENT_CODES.NOT_ACTIVATED });
        }

        try {
            const data = await this.#sendValidate();
            this.#adopt(data);
            this.activated = true;
            this.#offlineSince = null;

            this.emit("validated", this.snapshot());
            return this.snapshot();
        } catch (err) {
            const staleSession = err.code === "INVALID_TOKEN" || err.code === "INVALID_SESSION";

            if (staleSession && this.#key) {
                this.#session = null;

                const data = await this.#sendValidate();
                this.#adopt(data);
                this.#offlineSince = null;

                this.emit("validated", this.snapshot());
                return this.snapshot();
            }

            throw err;
        }
    }

    startHeartbeat({ intervalSeconds } = {}) {

        if (!this.#session?.token && !this.#key) {
            throw new FrostAuthError(
                "Nothing to heartbeat with: activate with a licence key, or sign in on a plan that issues session tokens.",
                { code: CLIENT_CODES.NOT_ACTIVATED },
            );
        }

        this.stopHeartbeat();
        this.#closed = false;

        const explicit = Number.isFinite(intervalSeconds);

        const period = () => {
            const base = explicit ? intervalSeconds : (this.#session?.heartbeatSeconds ?? 180);
            const floor = explicit ? 1 : 15;

            return Math.max(floor, base) * 1000 + randomInt(0, explicit ? 250 : 5000);
        };

        const tick = async () => {
            if (this.#closed) return;

            try {
                await this.validate();
            } catch (err) {

                if (err.needsActivation) {
                    this.activated = false;
                    this.stopHeartbeat();
                    this.emit("needsActivation", err);
                    return;
                }

                if (err.terminal) {

                    this.activated = false;
                    this.stopHeartbeat();
                    this.emit("invalid", err);
                    return;
                }

                this.#offlineSince ??= Date.now();

                const offline = this.checkOffline();

                this.emit("offline", {
                    error: err,
                    seconds: this.offlineFor,
                    verified: offline.ok,
                    until: this.offlineUntil,
                    reason: offline.ok ? null : offline.reason,
                });

                if (offline.ok) return;

                if (this.offlineFor > this.offlineGraceSeconds) {
                    this.activated = false;
                    this.stopHeartbeat();
                    this.emit("invalid", new FrostAuthError(
                        `Could not reach the licence server for ${this.offlineFor}s`,
                        { code: CLIENT_CODES.NETWORK, cause: err },
                    ));
                    return;
                }
            }

            if (!this.#closed) this.#schedule(tick, period());
        };

        this.#schedule(tick, period());
        return this;
    }

    stopHeartbeat() {
        if (this.#timer) clearTimeout(this.#timer);
        this.#timer = null;
        return this;
    }

    close() {
        this.#closed = true;
        this.stopHeartbeat();
        this.#key = null;
        this.#session = null;
        this.activated = false;

        this.#assertion = null;
        this.offlineUntil = null;
        this.#offlineSince = null;

        this.account = null;
        this.subscriptions = [];

        this.emit("closed");
        return this;
    }

    checkOffline({ at = Date.now() } = {}) {
        if (!this.#assertion) return { ok: false, reason: "no assertion issued yet" };
        if (!this.#keys?.size) return { ok: false, reason: "no pinned publicKey to verify against" };

        return verifyAssertion(this.#assertion, this.#keys, { hwid: this.#machineId, at });
    }

    snapshot() {
        return {
            app: this.app,
            license: this.license,
            product: this.productInfo ?? null,
            device: this.device,
            user: this.user,
            account: this.account,
            subscriptions: this.subscriptions,
            valid: this.valid,
        };
    }

    #assertInitialized() {
        if (!this.initialized) {
            throw new FrostAuthError("Call init() before anything else", { code: CLIENT_CODES.NOT_INITIALIZED });
        }
    }

    #schedule(fn, ms) {
        const timer = setTimeout(fn, ms);
        timer.unref?.();
        this.#timer = timer;
    }

    #verify({ response, raw, nonce, method, path }) {
        if (!this.#keys?.size) return;

        const reject = (why) => {
            throw new FrostAuthError(`Refusing an unverified answer from the licence server: ${why}`, {
                code: CLIENT_CODES.SIGNATURE, status: response.status,
            });
        };

        const signature = response.headers.get("x-frost-signature");
        const timestamp = response.headers.get("x-frost-timestamp");

        if (!signature || !timestamp) reject("it was not signed");
        if (response.headers.get("x-frost-nonce") !== nonce) reject("it answered a different request");

        const skew = Math.abs(Date.now() - Number(timestamp));
        if (!Number.isFinite(skew) || skew > MAX_SIGNATURE_SKEW_MS) reject("it was signed too long ago");

        const keyId = response.headers.get("x-frost-key-id");
        const candidates = this.#keys.select(keyId);

        if (!candidates.length) reject(`it was signed with key "${keyId}", which this build does not trust`);

        const material = Buffer.from(SIGNING_INPUT(timestamp, nonce, method, path, String(response.status), raw), "utf8");
        const supplied = Buffer.from(signature, "base64url");

        let ok = false;
        for (const key of candidates) {
            try {
                if (edVerify(null, material, key, supplied)) {
                    ok = true;
                    break;
                }
            } catch {  }
        }

        if (!ok) reject("the signature did not match");
    }

    async #hardware() {
        if (!this.collectHardware) return {};

        try {
            const { components, virtual } = await hardwareProfile();
            return { components, virtual };
        } catch {

            return {};
        }
    }

    async #machine() {

        if (this.#machineId) return this.#machineId;

        if (typeof this.#hardwareId === "function") this.#machineId = String(await this.#hardwareId());
        else if (typeof this.#hardwareId === "string" && this.#hardwareId) this.#machineId = this.#hardwareId;
        else this.#machineId = await hardwareId(this.app?.ownerId ?? this.owner);

        return this.#machineId;
    }

    async #assertRealHost() {
        if (this.#dnsChecked) return;

        let host = "";
        try {
            host = new URL(this.baseUrl).hostname;
        } catch {
            return;
        }

        const bare = host.replace(/^\[|\]$/g, "");
        const loopback = ["localhost", "127.0.0.1", "::1"].includes(bare);
        const ipLiteral = /^[\d.]+$/.test(bare) || bare.includes(":");

        if (loopback || ipLiteral || this.#allowPrivateDns) {
            this.#dnsChecked = true;
            return;
        }

        let addrs;
        try {
            addrs = await dnsLookup(bare, { all: true, verbatim: true });
        } catch (cause) {
            throw new FrostAuthError(`Cannot resolve the licence server host "${bare}" — refusing to continue`, {
                code: CLIENT_CODES.NETWORK, cause,
            });
        }
        
        if (addrs.some((a) => isPrivateAddress(a.address))) {
            throw new FrostAuthError(
                `"${bare}" resolves to loopback or private space (${addrs.map((a) => a.address).join(", ")}) — this is what a hosts-file hijack or licence emulator looks like. Refusing to continue. Pass allowPrivateDns: true if this is intentional.`,
                { code: CLIENT_CODES.NETWORK },
            );
        }

        this.#dnsChecked = true;
    }

    async #sendValidate() {
        const hwid = await this.#machine();
        const payload = this.#session?.token ? { token: this.#session.token, hwid, appVersion: this.version, os: platform() } : { key: this.#key, hwid, appVersion: this.version, os: platform() };

        return this.#request("POST", "/api/v1/validate", payload);
    }

    async #authed(method, path, body) {
        if (!this.#session?.token) {
            throw new FrostAuthError("This call needs a session — activate or sign in first", { code: CLIENT_CODES.NOT_ACTIVATED });
        }

        return this.#request(method, path, body, { token: this.#session.token });
    }

    #adopt(data) {
        if (data.session?.token) this.#session = data.session;

        this.license = data.license ?? this.license;
        this.productInfo = data.product ?? this.productInfo;
        this.device = data.device ?? this.device;
        this.user = data.user ?? this.user;

        this.account = data.account ?? this.account;
        this.subscriptions = data.subscriptions ?? this.subscriptions;

        if (data.offline?.assertion) {
            this.#assertion = data.offline.assertion;
            this.offlineUntil = data.offline.notAfter ?? null;
        }

        if (data.product?.updateAvailable) {
            this.emit("updateAvailable", { current: this.version, latest: data.product.latest ?? data.product.version, ...(data.product.downloadUrl ? { downloadUrl: data.product.downloadUrl } : {}) });
        }
    }

    async #request(method, path, body, { envelope = true, token = null } = {}) {
        let lastError;
        let requestId;

        for (let attempt = 0; attempt <= this.retries; attempt++) {
            if (attempt > 0) await sleep(backoff(attempt - 1, 300));

            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), this.timeout);

            const nonce = randomBytes(16).toString("base64url");
            const sentAt = Date.now();

            requestId ??= randomBytes(6).toString("hex");

            this.trace(`→ ${method} ${path}`, { requestId, attempt: attempt + 1, body });

            let response;
            try {
                response = await fetch(`${this.baseUrl}${path}`, {
                    method,
                    headers: {
                        "Content-Type": "application/json",
                        Accept: "application/json",
                        "User-Agent": `frostauth-sdk/${SDK_VERSION} (${platform()})`,
                        "X-Frost-Nonce": nonce,
                        "X-Frost-Timestamp": String(sentAt),
                        "X-Frost-Request-Id": requestId,
                        ...(token ? { Authorization: `Bearer ${token}` } : {}),
                    },
                    body: body ? JSON.stringify(body) : undefined,
                    signal: controller.signal,
                });
            } catch (err) {
                clearTimeout(timer);

                const aborted = err?.name === "AbortError";
                lastError = new FrostAuthError(
                    aborted ? `Request timed out after ${this.timeout}ms` : "Could not reach the licence server",
                    { code: aborted ? CLIENT_CODES.TIMEOUT : CLIENT_CODES.NETWORK, retryable: true, cause: err },
                );
                continue;
            } finally {
                clearTimeout(timer);
            }

            const raw = await response.text();

            this.trace(`← ${response.status} ${path}`, { requestId, ms: Date.now() - sentAt, bytes: raw.length });

            if (response.status !== 429 || response.headers.get("x-frost-signature")) {
                this.#verify({ response, raw, nonce, method, path });
            }

            if (response.status === 429) {
                const retryAfter = Number(response.headers.get("retry-after"));
                const waitSeconds = Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter : 2;

                lastError = new FrostAuthError("Rate limited by the licence server", { code: "RATE_LIMITED", status: 429, retryable: true, requestId });
                lastError.retryAfterSeconds = waitSeconds;

                if (attempt < this.retries && waitSeconds <= MAX_RETRY_AFTER_SECONDS) {
                    await sleep(waitSeconds * 1000);
                    continue;
                }
                throw lastError;
            }

            let payload = null;
            try {
                payload = raw ? JSON.parse(raw) : null;
            } catch {  }

            if (response.status >= 500) {

                const typed = payload?.response?.errorCode;
                if (typeof typed === "string" && typed) {
                    throw new FrostAuthError(payload?.response?.message ?? `Request failed (${response.status})`, {
                        code: typed,
                        status: response.status,
                        requestId,
                    });
                }
                lastError = new FrostAuthError(payload?.response?.message ?? "The licence server is having trouble", {
                    code: CLIENT_CODES.SERVER_ERROR, status: response.status, retryable: true, requestId,
                });
                continue;
            }

            if (!envelope) return payload;

            if (payload?.error || !response.ok) {

                const reason = payload?.response?.errorCode;
                throw new FrostAuthError(payload?.response?.message ?? `Request failed (${response.status})`, {
                    code: typeof reason === "string" && reason ? reason : CLIENT_CODES.SERVER_ERROR,
                    status: response.status,
                    requestId,
                });
            }

            return payload?.response?.data ?? {};
        }

        throw lastError ?? new FrostAuthError("Request failed", { code: CLIENT_CODES.NETWORK, retryable: true });
    }
}

export default FrostAuth;
