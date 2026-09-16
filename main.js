import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { FrostAuth, FrostAuthError } from "./frostauth.js";

const readline = createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false,
});

const ask = (q) => readline.question(q);

/**
 * Fill these in from your dashboard:
 *  - owner:   your account (user) id
 *  - product: the product id
 *  - version: the latest version of your product
 */
const FrostAuthApp = new FrostAuth({
    owner: "0809wkVP",
    product: "33abf48a-8e33-4df5-a4bd-d79195704d52",
    version: "2.0.1"
});

function fail(err) {
    if (err instanceof FrostAuthError) {
        console.error(`An error occurred: ${err.message}`);
    } else if (err instanceof Error) {
        console.error("An error occurred:", err.message);
    } else {
        console.error("An unknown error occurred:", err);
    }
}

async function answer() {
    try {
        await FrostAuthApp.init();

        console.log("[1] Login\n[2] Register\n[3] License\n[4] Upgrade");

        const option = parseInt(await ask("Select an option: "), 10);

        let username = "";
        let password = "";
        let license = "";

        switch (option) {
            case 1:
                username = await ask("Username: ");
                password = await ask("Password: ");
                await FrostAuthApp.login(username, password);
                await dashboard();
                break;

            case 2:
                license = await ask("License: ");
                username = await ask("Username: ");
                password = await ask("Password: ");
                await FrostAuthApp.register(license, username, password);
                await dashboard();
                break;

            case 3:
                license = await ask("License: ");
                await FrostAuthApp.activate(license);
                await dashboard();
                break;

            case 4:
                username = await ask("Username: ");
                password = await ask("Password: ");
                license = await ask("License: ");

                await FrostAuthApp.upgrade(username, password, license);
                console.log("Upgraded. Sign in to use the new licence.");
                await FrostAuthApp.login(username, password);
                await dashboard();
                break;

            default:
                console.log("Invalid option selected.");
                break;
        }
    } catch (error) {
        fail(error);
    }
}

async function dashboard() {
    try {
        const appData = await FrostAuthApp.appData().catch(() => null);
        const snap = FrostAuthApp.snapshot();

        console.log(appData)

        console.log("Application data:");
        console.log("  App Version: ", appData?.product?.version ?? snap.product?.version);
        console.log("  Customer panel: ", appData?.product ? "enabled" : "unknown");
        console.log("  Number of Keys: ", appData?.numKeys ?? "unknown");
        console.log("  Number of Users: ", appData?.numUsers ?? "unknown");

        const online = await FrostAuthApp.fetchOnline().catch(() => null);
        console.log("  Online Users: ", online?.online ?? "unknown");

        console.log("\nUser data:");
        console.log("  Username: ", snap.user);
        console.log("  IP Address: ", snap.account?.lastIp ?? "unknown");

        const subs = snap.subscriptions ?? [];
        for (let i = 0; i < subs.length; i++) {
            const sub = subs[i];
            const expiry = sub.expiresAt ? new Date(sub.expiresAt) : null;
            console.log(
                `[${i + 1}/${subs.length}] | Subscription: ${sub.tier || sub.status} - Expiry: ${expiry ? expiry.toLocaleString() : "never"}`,
            );
        }

        console.log(`Created at: ${snap.account?.createdAt ? new Date(snap.account.createdAt).toLocaleString() : "unknown"}`);
        console.log(`Last Login: ${snap.account?.lastLoginAt ? new Date(snap.account.lastLoginAt).toLocaleString() : "unknown"}`);
        const firstExpiry = subs.find((s) => s.expiresAt)?.expiresAt ?? null;
        console.log(`Expires: ${firstExpiry ? new Date(firstExpiry).toLocaleString() : "never"}`);

        try {
            const res = await FrostAuthApp.webhook("discord", "", JSON.stringify({ content: "Hello from FrostAuth" }));
            console.log(`\nWebhook test: upstream ${res.status} (ok: ${res.ok})`);
        } catch (error) {
            console.log(`\nWebhook test failed: ${error.code ?? ""} ${error.message}`);
        }

        try {
            const motd = await FrostAuthApp.variable("motd").catch(() => null);
            console.log(`\nApp var motd: ${motd ?? "not set"}`);
            const vars = await FrostAuthApp.listVars().catch(() => null);
            console.log(`Variables: ${vars ? `${vars.length} user var(s)` : "unavailable"}`);
            for (const v of vars ?? []) {
                console.log(`  ${v.key} = ${v.value}${v.readonly ? " (readonly)" : ""}`);
            }
        } catch (error) {
            console.log(`\nVariables test failed: ${error.code ?? ""} ${error.message}`);
        }

        const selfHash = process.argv[1] ? createHash("sha256").update(readFileSync(process.argv[1])).digest("hex") : "unavailable";
        console.log("\nBuild hash (this file):");
        console.log(`  ${selfHash}`);
        console.log("  Pass it as { hash: selfHash } to activate/register/login when the product requires it.");

        console.log("\nClosing app in 10 seconds...");
        await new Promise((resolve) => setTimeout(resolve, 10000));
        readline.close();
        await FrostAuthApp.logout().catch(() => {});
        process.exit(0);
    } catch (error) {
        fail(error);
    }
}

answer();
