/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { copyWithToast } from "@utils/discord";
import { saveFile } from "@utils/web";
import type { RenderModalProps } from "@vencord/discord-types";
import { Modal, openModal, UserStore, useEffect, useState } from "@webpack/common";

import { CipherError, safeMessage } from "../core/errors";
import { formatFingerprint, inspectKey, KEY_PROBLEM_TEXT, type KeyInfo, keyLabel, type KeyType } from "../core/keys";
import { DEFAULT_SERVER_URL, normalizeServerUrl } from "../core/serverApi";
import { lockCipher } from "../autoLock";
import { type DirectoryKey, getSession, type KeyChange, lookupKeys, OldKeyNeeded, publishKey, serverOrigin, signIn, signOut, unexpectedKeyChanges, unpublishKey } from "../server";
import { settings } from "../settings";
import { pgpEngine } from "../core/pgpCipher";
import type { GpgKey, KeyProtection, PgpAvailability } from "../core/pgpEngine";
import { contactName, state, useCipher } from "../state";
import { Badge, Button, cl, confirmDanger, Fingerprint, Notice, promptPassphrase, requestUnlock, TextBox, TextField, toastError, toastOk, TypeBadge, VerifiedBadge, withPassphrase } from "./common";
import { openContactDialog } from "./ContactDialog";
import { GroupList } from "./GroupEditor";

function useOwnKeyInfo(type: KeyType): KeyInfo | undefined {
    const pub = state.identity.publicIdentity;
    const material = type === "age" ? pub.age?.recipient : pub.pgp?.publicKey;
    const [info, setInfo] = useState<KeyInfo>();
    useEffect(() => {
        setInfo(undefined);
        if (material) inspectKey(type, material).then(setInfo, () => setInfo(undefined));
    }, [material]);
    return info;
}

function KeyDetails({ info }: { info?: KeyInfo; }) {
    if (!info) return <div className={cl("hint")}>Checking…</div>;
    return (
        <>
            <Fingerprint fingerprint={info.fingerprint} code={info.code} />
            {info.userIds.length > 0 && <div className={cl("hint")}>User ID: {info.userIds.join(", ")}</div>}
            {info.problems.map(p => <Notice key={p} tone="bad">{KEY_PROBLEM_TEXT[p]} Messages can't be encrypted to it or signed with it. Set up a new key.</Notice>)}
            <div className={cl("hint")}>Others should see this same code for your key. Read it to each other over a call or in person.</div>
        </>
    );
}

/* ---------- age: stored by Cipher, sealed with the Cipher passphrase ---------- */

function AgeKey() {
    const info = useOwnKeyInfo("age");
    const has = state.identity.has("age");
    const created = state.identity.publicIdentity.age?.createdAt;

    const generate = (postQuantum: boolean) => withPassphrase("add your new age key", async p => {
        await state.identity.generateAge(p, { postQuantum });
        toastOk(postQuantum ? "Post-quantum age key generated" : "age key generated");
    });

    const exportKey = async () => {
        if (!await requestUnlock("Unlock to export your age key.")) return;
        await promptPassphrase({
            title: "Export age secret key",
            subtitle: "Choose a passphrase to protect the exported file. You'll need it to import the key again, or to open it with `age -d`.",
            confirm: true,
            submitText: "Export",
            onSubmit: async p => {
                const data = await state.identity.exportAge(p);
                saveFile(new File([data], "cipher-age-key.age", { type: "text/plain" }));
            }
        });
    };

    const remove = async () => {
        const ok = await confirmDanger(
            "Delete your age key?",
            "You will no longer be able to read messages encrypted to this key, including old ones, unless you exported it. Contacts will keep encrypting to it until you share a new key.",
            "Delete key"
        );
        if (ok) await withPassphrase("delete your age key", async p => {
            await state.identity.removeAge(p);
            toastOk("age key deleted");
        });
    };

    if (!has) {
        return (
            <div className={cl("card")}>
                <div className={cl("row")}><b>age</b> <Badge tone="muted">none</Badge></div>
                <div className={cl("hint")}>Small modern keys (X25519), stored by Cipher and protected by your Cipher passphrase. No signatures: recipients can't cryptographically confirm who wrote an age message.</div>
                <div className={cl("hint")}>Post-quantum keys (ML-KEM-768 + X25519) also hold up against future quantum computers, which matters because encrypted messages stay on Discord. Each post-quantum reader adds about 2 KB to a message, so messages split into more parts. Everyone you write to needs a post-quantum key too, or gets a separate copy.</div>
                <div className={cl("row", "wrap")}>
                    <Button size="small" onClick={() => generate(true)}>Generate post-quantum age key</Button>
                    <Button size="small" variant="secondary" onClick={() => generate(false)}>Generate normal age key</Button>
                    <Button size="small" variant="secondary" onClick={() => openModal(modal => <AgeImportDialog modal={modal} />)}>Import existing</Button>
                </div>
            </div>
        );
    }

    return (
        <div className={cl("card")}>
            <div className={cl("row")}><b>age</b> <TypeBadge type="age" material={state.identity.publicIdentity.age?.recipient} />{created && <span className={cl("hint")}>since {new Date(created).toLocaleDateString()}</span>}</div>
            <KeyDetails info={info} />
            <div className={cl("row", "wrap")}>
                <Button size="small" variant="secondary" onClick={() => info && copyWithToast(info.material, "Public key copied")}>Copy public key</Button>
                <Button size="small" variant="secondary" onClick={exportKey}>Export secret key…</Button>
                <Button size="small" variant="dangerSecondary" onClick={remove}>Delete</Button>
            </div>
        </div>
    );
}

function AgeImportDialog({ modal }: { modal: RenderModalProps; }) {
    const [text, setText] = useState("");
    const [filePass, setFilePass] = useState("");
    const protectedFile = text.includes("BEGIN AGE ENCRYPTED FILE");

    const run = async () => {
        const ok = await withPassphrase("store the imported age key", p => state.identity.importAge(text, p, filePass || undefined));
        if (ok) {
            toastOk("age key imported");
            modal.onClose();
        }
    };

    return (
        <Modal
            {...modal}
            size="md"
            title="Import age secret key"
            subtitle="Paste an AGE-SECRET-KEY-1… line, an identity file, or a key exported from Cipher."
            actions={[
                { text: "Import", variant: "primary", onClick: run, disabled: !text.trim() },
                { text: "Cancel", variant: "secondary", onClick: modal.onClose }
            ]}
        >
            <div className={cl("stack")}>
                <TextBox value={text} onChange={setText} rows={6} placeholder="AGE-SECRET-KEY-1…" />
                {protectedFile && (
                    <>
                        <div className={cl("label")}>Passphrase of the exported file</div>
                        <TextField password value={filePass} onChange={setFilePass} />
                    </>
                )}
                <div className={cl("hint")}>The key is then stored encrypted with your Cipher passphrase. Clear your clipboard afterwards.</div>
            </div>
        </Modal>
    );
}

/* ---------- PGP: a key in the user's GnuPG keyring ---------- */

function useGnupg() {
    const [avail, setAvail] = useState<PgpAvailability>();
    const [keys, setKeys] = useState<(GpgKey & { usable: boolean; })[]>();
    const [error, setError] = useState<string>();
    const refresh = () => {
        setError(undefined);
        pgpEngine().available().then(a => {
            setAvail(a);
            if (a.ok) state.identity.gnupgKeys().then(setKeys, e => setError(safeMessage(e)));
        }, () => setAvail({ ok: false, reason: "GnuPG isn't available." }));
    };
    useEffect(refresh, []);
    return { avail, keys, error, refresh };
}

/** Asks gpg-agent whether the key has a passphrase (KEYINFO; the key itself is never read). */
function useKeyProtection(fingerprint?: string): KeyProtection | undefined {
    const [p, setP] = useState<KeyProtection>();
    useEffect(() => {
        setP(undefined);
        if (!fingerprint) return;
        try {
            pgpEngine().keyProtection(fingerprint).then(setP, () => setP(undefined));
        } catch {
            // GnuPG isn't available.
        }
    }, [fingerprint]);
    return p;
}

function PgpKey() {
    const info = useOwnKeyInfo("pgp");
    const selected = state.identity.publicIdentity.pgp;
    const gnupg = useGnupg();
    const protection = useKeyProtection(selected?.fingerprint);
    const [busy, setBusy] = useState(false);

    const act = async (fn: () => Promise<unknown>, done: string) => {
        setBusy(true);
        try {
            await fn();
            toastOk(done);
            gnupg.refresh();
        } catch (e) {
            toastError(e);
        } finally {
            setBusy(false);
        }
    };

    const exportKey = () => act(async () => {
        const data = await state.identity.exportPgp();
        saveFile(new File([data], "pgp-secret-key.asc", { type: "text/plain" }));
    }, "Exported (still protected by your GnuPG passphrase)");

    const stopUsing = async () => {
        const ok = await confirmDanger(
            "Stop using this PGP key in Cipher?",
            "The key stays in GnuPG/Kleopatra. Cipher just won't use it for new messages; contacts keep encrypting to it until you share a new key.",
            "Stop using"
        );
        if (ok) await act(() => state.identity.forgetPgp(), "Cipher no longer uses this key");
    };

    const header = <div className={cl("row")}><b>PGP</b> <Badge tone="info">via GnuPG{gnupg.avail?.ok ? ` ${gnupg.avail.version}` : ""}</Badge></div>;

    if (gnupg.avail && !gnupg.avail.ok) {
        return (
            <div className={cl("card")}>
                {header}
                <Notice tone="warn">{gnupg.avail.reason} Cipher uses your installed GnuPG for PGP. On Windows, install Gpg4win from gpg4win.org (it includes Kleopatra), then restart Discord.</Notice>
            </div>
        );
    }

    if (selected) {
        return (
            <div className={cl("card")}>
                {header}
                <KeyDetails info={info} />
                {protection?.state === "unprotected" && (
                    <Notice tone="bad">
                        <b>⚠ This GnuPG key has no passphrase.</b> Any program running on your Windows account can use it to read your PGP messages, even while Cipher is locked,
                        and anyone who copies your GnuPG folder gets a working key. Add a passphrase in Kleopatra (right-click the key → Change Passphrase),
                        or run <code>gpg --change-passphrase {selected.fingerprint}</code>.
                    </Notice>
                )}
                {protection?.state === "card" && <div className={cl("hint")}>Your secret key is on a smartcard; its PIN protects it.</div>}
                <div className={cl("hint")}>Your secret key stays in GnuPG. GnuPG asks for its passphrase when Cipher signs or decrypts, and forgets it when Cipher locks.</div>
                <div className={cl("row", "wrap")}>
                    <Button size="small" variant="secondary" onClick={() => info && copyWithToast(info.material, "Public key copied")}>Copy public key</Button>
                    <Button size="small" variant="secondary" disabled={busy} onClick={exportKey}>Export secret key…</Button>
                    <Button size="small" variant="dangerSecondary" disabled={busy} onClick={stopUsing}>Stop using</Button>
                </div>
            </div>
        );
    }

    const usable = gnupg.keys?.filter(k => k.usable) ?? [];
    const unusable = gnupg.keys?.filter(k => !k.usable) ?? [];
    return (
        <div className={cl("card")}>
            {header}
            <div className={cl("hint")}>Pick one of your GnuPG keys (the ones you see in Kleopatra), or make a new one. Cipher never sees your secret key: GnuPG keeps it and asks for its passphrase itself.</div>
            {!gnupg.keys && !gnupg.error && <div className={cl("hint")}>Looking for your GnuPG keys…</div>}
            {gnupg.error && <Notice tone="bad">{gnupg.error}</Notice>}
            {usable.map(k => (
                <div key={k.fingerprint} className={cl("list-row")}>
                    <span className={cl("name")}>{k.userIds[0] ?? "(no user ID)"}</span>
                    <code className={cl("hint")}>{formatFingerprint(k.fingerprint).slice(-19)}</code>
                    <Button size="min" disabled={busy} onClick={() => act(() => state.identity.usePgpKey(k.fingerprint), "Using this GnuPG key")}>Use this key</Button>
                </div>
            ))}
            {unusable.length > 0 && <div className={cl("hint")}>{unusable.length} other key{unusable.length > 1 ? "s" : ""} can't be used (expired, revoked, no secret part, or can't both sign and encrypt).</div>}
            {gnupg.keys && usable.length === 0 && <div className={cl("hint")}>No usable GnuPG keys found.</div>}
            <div className={cl("row", "wrap")}>
                <Button size="small" disabled={busy} onClick={() => act(() => state.identity.createPgpKey(UserStore.getCurrentUser()?.username ?? ""), "New GnuPG key created")}>Create a new key in GnuPG</Button>
                <Button size="small" variant="secondary" disabled={busy} onClick={() => openModal(modal => <PgpImportDialog modal={modal} onDone={gnupg.refresh} />)}>Import a key file…</Button>
            </div>
            <div className={cl("hint")}>New keys are Curve25519 (not RSA). GnuPG will ask you to choose the key's passphrase.</div>
        </div>
    );
}

function PgpImportDialog({ modal, onDone }: { modal: RenderModalProps; onDone(): void; }) {
    const [text, setText] = useState("");
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string>();

    const run = async () => {
        setBusy(true);
        setError(undefined);
        try {
            await state.identity.importPgpKey(text);
            toastOk("Imported into GnuPG and selected");
            onDone();
            modal.onClose();
        } catch (e) {
            setError(safeMessage(e));
        } finally {
            setBusy(false);
        }
    };

    return (
        <Modal
            {...modal}
            size="md"
            title="Import PGP secret key into GnuPG"
            subtitle="Paste an armored secret key (-----BEGIN PGP PRIVATE KEY BLOCK-----). It's added to your GnuPG keyring, so it also shows up in Kleopatra. GnuPG may ask for its passphrase."
            actions={[
                { text: "Import", variant: "primary", onClick: run, disabled: !text.trim() || busy, loading: busy },
                { text: "Cancel", variant: "secondary", onClick: modal.onClose }
            ]}
        >
            <div className={cl("stack")}>
                <TextBox value={text} onChange={setText} rows={8} placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----" />
                <div className={cl("hint")}>Clear your clipboard afterwards.</div>
                {error && <Notice tone="bad">{error}</Notice>}
            </div>
        </Modal>
    );
}

function ServerCard() {
    const { serverUrl } = settings.use(["serverUrl"]);
    const [draft, setDraft] = useState(serverUrl ?? "");
    const origin = serverOrigin();
    const [session, setSession] = useState<{ userId: string; expiresAt: number; } | null>();
    const [published, setPublished] = useState<DirectoryKey[]>();
    const [unexpected, setUnexpected] = useState<Set<KeyType>>(new Set());
    const [busy, setBusy] = useState(false);
    const pub = state.identity.publicIdentity;
    const ageInfo = useOwnKeyInfo("age");

    const refresh = () => {
        setSession(undefined);
        setPublished(undefined);
        if (!origin) return;
        getSession().then(s => {
            setSession(s ?? null);
            if (!s) return;
            lookupKeys(s.userId, { fresh: true })
                .then(keys => {
                    setPublished(keys);
                    // Uses the lookup just made instead of asking the server again.
                    return unexpectedKeyChanges({ fresh: false }).then(list => setUnexpected(new Set(list.map(k => k.type))));
                })
                .catch(() => setPublished(p => p ?? []));
        }, () => setSession(null));
    };
    useEffect(refresh, [origin]);

    const act = async (fn: () => Promise<string | undefined>) => {
        setBusy(true);
        try {
            const done = await fn();
            if (done) toastOk(done);
            refresh();
        } catch (e) {
            if (!(e instanceof CipherError && e.code === "cancelled")) toastError(e);
        } finally {
            setBusy(false);
        }
    };

    const describe = (r: KeyChange, now: string) => "pending" in r ? `Takes effect on ${new Date(r.effectiveAt).toLocaleString()}` : now;

    const publish = (type: KeyType, material: string) => act(async () => {
        try {
            return describe(await publishKey(type, material), "Key published");
        } catch (e) {
            if (!(e instanceof OldKeyNeeded)) throw e;
            const ok = await confirmDanger(
                "Replace your published key without the old one?",
                <>The server has a different {keyLabel(type, material)} key for you, and this computer doesn't have its private key to approve the change.
                    If you still have that key (another computer, a backup), publish from there instead: that's instant.<br /><br />
                    Otherwise the new key takes effect in <b>7 days</b>. Until then, the old key stays, everyone who looks you up sees that a change is waiting,
                    and the old key can cancel it. This delay is what stops someone with your Discord account from swapping your key.</>,
                "Replace in 7 days");
            if (!ok) throw new CipherError("cancelled");
            return describe(await publishKey(type, material, { reset: true }), "Key published");
        }
    });

    const remove = (type: KeyType) => act(async () => {
        try {
            return describe(await unpublishKey(type), "Key removed from the server");
        } catch (e) {
            if (!(e instanceof OldKeyNeeded)) throw e;
            const ok = await confirmDanger(
                "Remove the published key without its private key?",
                <>This computer doesn't have the private key for the {type === "age" ? "age" : "PGP"} key on the server, so it can't approve removing it.
                    It will be removed in <b>7 days</b> instead, and lookups show that until then.</>,
                "Remove in 7 days");
            if (!ok) throw new CipherError("cancelled");
            return describe(await unpublishKey(type, { reset: true }), "Key removed from the server");
        }
    });

    const status = (type: KeyType, material?: string, fingerprint?: string) => {
        if (!material) return null;
        const onServer = published?.find(k => k.type === type);
        const same = !!onServer && (onServer.key.trim() === material.trim() || (!!fingerprint && onServer.fingerprint === fingerprint));
        const pending = onServer?.pending;
        const alarming = !!pending && unexpected.has(type);
        return (
            <div className={cl("stack")} key={type}>
                <div className={cl("list-row")}>
                    <span className={cl("name")}>Your {keyLabel(type, material)} key</span>
                    {published && (same ? <Badge tone="good">published</Badge> : onServer ? <Badge tone="warn">a different key is published</Badge> : <Badge tone="muted">not published</Badge>)}
                    {!same && <Button size="min" disabled={busy || !session} onClick={() => publish(type, material)}>Publish</Button>}
                    {onServer && !pending?.removal && <Button size="min" variant="dangerSecondary" disabled={busy} onClick={() => remove(type)}>Remove</Button>}
                </div>
                {pending && alarming && (
                    <Notice tone="bad">
                        <b>⚠ Someone asked to {pending.removal ? "remove" : "replace"} this key</b>, without proof from it. It happens on {new Date(pending.effectiveAt).toLocaleString()} unless it's cancelled.
                        If this wasn't you, someone may have access to your Discord account: change your Discord password and log out other devices.
                        {same
                            ? <div><Button size="small" disabled={busy} onClick={() => publish(type, material)}>Cancel this change</Button></div>
                            : <div>Cancelling needs the key that's published now: open Cipher where you have it.</div>}
                    </Notice>
                )}
                {pending && !alarming && (
                    <Notice tone="warn">
                        Your request to {pending.removal ? "remove" : "replace"} this key takes effect on {new Date(pending.effectiveAt).toLocaleString()}.
                    </Notice>
                )}
            </div>
        );
    };

    const save = () => {
        const v = draft.trim();
        if (v && !normalizeServerUrl(v)) return toastError(new CipherError("invalid-input", "Use an https:// address with nothing after the host name."));
        settings.store.serverUrl = v ? normalizeServerUrl(v)! : "";
        toastOk(v ? "Server saved" : "Server removed: everything stays in Discord");
    };
    const useDefault = () => {
        setDraft(DEFAULT_SERVER_URL);
        settings.store.serverUrl = DEFAULT_SERVER_URL;
        toastOk("Using the Cipher project's server");
    };

    return (
        <div className={cl("card")}>
            <div className={cl("hint")}>Optional. A Cipher server lets people find your public key by your Discord account, and holds disappearing messages (deleted after 1–7 days). It only ever gets public keys and encrypted text, never plaintext. Publishing or changing a key needs proof from the key itself, so your Discord login alone can't change it.</div>
            <div className={cl("hint")}>{origin === DEFAULT_SERVER_URL
                ? "This is the Cipher project's server (free, run by the maintainer). It's only contacted when you sign in, publish or look up a key, send a disappearing message, or open one from you or a contact; it can see your IP address then. Clear the address to keep everything in Discord, or run your own (see server/README.md)."
                : !origin ? "No server: everything stays in Discord. The key directory and disappearing messages are off." : "Your own server: Cipher contacts no other."}</div>
            <div className={cl("row")}>
                <TextField value={draft} onChange={setDraft} placeholder="https://cipher.example.com" onEnter={save} />
                <Button size="small" variant="secondary" onClick={save}>Save</Button>
                {origin !== DEFAULT_SERVER_URL && <Button size="small" variant="secondary" onClick={useDefault}>Use the default server</Button>}
            </div>
            {origin && session === null && <div><Button size="small" disabled={busy} onClick={() => act(async () => { await signIn(); return "Signed in to the Cipher server"; })}>Sign in with Discord</Button></div>}
            {origin && session && (
                <>
                    <div className={cl("row")}>
                        <Badge tone="good">signed in</Badge>
                        <span className={cl("hint")}>until {new Date(session.expiresAt).toLocaleDateString()}</span>
                        <Button size="min" variant="secondary" onClick={() => act(async () => { await signOut(); return "Signed out"; })}>Sign out</Button>
                    </div>
                    {status("age", pub.age?.recipient, ageInfo?.fingerprint)}
                    {status("pgp", pub.pgp?.publicKey, pub.pgp?.fingerprint)}
                    {pub.age && !state.identity.isUnlocked && <div className={cl("hint")}>Publishing your age key needs Cipher unlocked: it proves the key is yours by opening a challenge from the server.</div>}
                </>
            )}
        </div>
    );
}

function Contacts() {
    const contacts = state.contacts.list();
    return (
        <div className={cl("stack")}>
            {contacts.length === 0 && <div className={cl("hint")}>No contacts yet. When someone shares their key in chat, Cipher offers to trust it. You can also add a key from a user's right-click menu.</div>}
            {contacts.map(c => (
                <div key={c.userId} className={cl("list-row")}>
                    <span className={cl("name")}>{contactName(c)}</span>
                    <TypeBadge type={c.key.type} material={c.key.material} />
                    <VerifiedBadge verified={c.verified} />
                    {c.pendingKey && <Badge tone="bad">⚠ key changed</Badge>}
                    <Button size="min" variant="secondary" onClick={() => openContactDialog(c.userId)}>Open</Button>
                </div>
            ))}
            <div><Button size="small" variant="secondary" onClick={() => openContactDialog()}>Add contact</Button></div>
        </div>
    );
}

export function KeyManager() {
    const ready = useCipher();
    if (!ready) return <div className={cl("hint")}>Loading Cipher…</div>;
    const { identity } = state;

    return (
        <div className={cl("manager", "stack")}>
            <div className={cl("row", "row-between")}>
                <h3 className={cl("h")}>Your keys</h3>
                {identity.hasAnyKey && (identity.isUnlocked
                    ? <Button size="small" variant="secondary" onClick={() => void lockCipher()}>🔓 Unlocked · Lock now</Button>
                    : <Button size="small" variant="secondary" onClick={() => requestUnlock()}>🔒 Locked · Unlock</Button>)}
            </div>
            <div className={cl("hint")}>You can have an age key and a PGP key at the same time. Your age key is encrypted with your Cipher passphrase and stays unlocked until Cipher locks (when you're away, per the auto-lock setting); your PGP key stays in GnuPG.</div>
            <AgeKey />
            <PgpKey />

            <h3 className={cl("h")}>Cipher server</h3>
            <ServerCard />

            <h3 className={cl("h")}>Contacts</h3>
            <Contacts />

            <h3 className={cl("h")}>Recipient groups</h3>
            <GroupList />

            <h3 className={cl("h")}>Good to know</h3>
            <ul className={cl("notes")}>
                <li>Discord still sees who messaged whom, when, and how long the message was. Everyone in the channel sees the ciphertext.</li>
                <li>age messages are not signed: the badge tells you which account posted it, not who wrote it. PGP messages can be signed.</li>
                <li>Neither age nor PGP gives forward secrecy: if a private key leaks later, old messages encrypted to it can be read.</li>
                <li>Removing someone from your readers doesn't take back messages they could already read.</li>
                <li>A compromised computer defeats all of this, and recipients can always copy what you send.</li>
                <li>Client mods like Vencord break Discord's Terms of Service.</li>
            </ul>
        </div>
    );
}

export function openKeyManager() {
    openModal((modal: RenderModalProps) => (
        <Modal {...modal} size="lg" title="Cipher: keys & contacts" actions={[{ text: "Done", variant: "primary", onClick: modal.onClose }]}>
            <KeyManager />
        </Modal>
    ));
}
