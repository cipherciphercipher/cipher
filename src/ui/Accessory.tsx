/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { copyWithToast } from "@utils/discord";
import type { Message } from "@vencord/discord-types";
import { MessageStore, Parser, useEffect, useMemo, useState, useStateFromStores } from "@webpack/common";

import type { DecryptedMessage } from "../core/compose";
import { isPureCipherContent, type MessageLink, parseAttachmentName, parseContent, type ParsedContent } from "../core/envelope";
import { safeMessage } from "../core/errors";
import { inspectKey, KEY_PROBLEM_TEXT, KEY_TYPE_LABEL, type KeyInfo, keyLabel, type KeyType } from "../core/keys";
import { cipherAttachments, collectParts, decryptCached, type DecryptOutcome, fetchAttachmentText, isPgpPaused, onPgpPauseChange, partsSignature, precheck, setPgpPaused, siblingTypes } from "../receive";
import { fetchMessage, serverOrigin } from "../server";
import { settings } from "../settings";
import { selfId, state, useCipher, userName } from "../state";
import { Badge, Button, cl, LockIcon, Notice, requestUnlock, type Tone, toastError, toastOk } from "./common";
import { openContactDialog, openKeyChangeDialog } from "./ContactDialog";
import { useHiddenContent } from "./hideContent";

export function CipherAccessory({ message }: { message: Message; }) {
    const parsed = useMemo(() => parseContent(message.content), [message.content]);
    const hasFile = message.attachments?.some(a => parseAttachmentName(a.filename));
    const { hideCiphertext } = settings.use(["hideCiphertext"]);
    const [revealed, setRevealed] = useState(false);

    const hideable = hideCiphertext && isPureCipherContent(message.content, parsed);
    const hidden = hideable && !revealed;
    useHiddenContent(message.id, hidden);

    let body: React.ReactNode = null;
    if (parsed?.kind === "key") body = <KeyShare message={message} parsed={parsed} />;
    // A lone 1/1 message has no ref and nothing to collect: decrypt its own body.
    else if (parsed?.kind === "part" && !parsed.ref) body = <Decrypt message={message} type={parsed.type} armored={parsed.body + "\n"} />;
    else if (parsed?.kind === "part") body = <SplitMessage message={message} parsed={parsed} ref_={parsed.ref!} hidden={hidden} />;
    else if (parsed?.kind === "raw") body = <Decrypt message={message} type={parsed.type} armored={parsed.armored} />;
    else if (parsed?.kind === "link") body = <LinkMessage message={message} parsed={parsed} />;
    else if (parsed?.kind === "attachment" || (hasFile && parsed?.kind !== "file-notice")) body = <AttachmentMessage message={message} set={parsed?.kind === "attachment" ? parsed.set : undefined} ref_={parsed?.kind === "attachment" ? parsed.ref : undefined} />;
    else if (parsed?.kind === "file-notice" && hidden) body = <Shell tone="muted">Encrypted message, sent as the attachment just above.</Shell>;

    if (!body) return null;
    if (!hideable) return body;
    return (
        <>
            {body}
            <Button size="min" variant="none" className={cl("link", "reveal")} onClick={() => setRevealed(r => !r)}>
                {revealed ? "Hide encrypted text" : "Show encrypted text"}
            </Button>
        </>
    );
}

function Shell({ children, tone = "info" }: { children: React.ReactNode; tone?: Tone; }) {
    return (
        <div className={cl("accessory", `accessory-${tone}`)}>
            <LockIcon size={16} className={cl("accessory-icon")} />
            <div className={cl("accessory-body")}>{children}</div>
        </div>
    );
}

/* ---------- encrypted messages ---------- */

function SplitMessage({ message, parsed, ref_, hidden }: { message: Message; parsed: Extract<ParsedContent, { kind: "part"; }>; ref_: string; hidden: boolean; }) {
    const sig = useStateFromStores([MessageStore], () => partsSignature(message.channel_id, message.author.id, ref_));
    const group = useMemo(() => collectParts(message.channel_id, message.author.id, ref_), [sig]);
    if (!group) return null;
    if (group.displayMessageId !== message.id) {
        // The text is shown once, on the last part; earlier parts just say what they are.
        return hidden ? <Shell tone="muted">Part {parsed.part} of {parsed.total} of an encrypted message (shown on the last part).</Shell> : null;
    }

    if ("missing" in group.result) {
        return (
            <Shell tone="muted">
                Encrypted message in {group.total} parts. Waiting for part{group.result.missing.length > 1 ? "s" : ""} {group.result.missing.join(", ")}
                {" "}(scroll up if they were sent earlier).
            </Shell>
        );
    }
    if ("error" in group.result) return <Shell tone="bad">The parts of this encrypted message don't fit together. It may have been tampered with.</Shell>;
    return <Decrypt message={message} type={group.type} armored={group.result.armored} set={group.set} ref_={group.ref} />;
}

function AttachmentMessage({ message, set, ref_ }: { message: Message; set?: string; ref_?: string; }) {
    const ready = useCipher();
    if (!ready) return null;
    const files = cipherAttachments(message).filter(f => !ref_ || parseAttachmentName(f.name)?.ref === ref_);
    if (files.length === 0) return null;
    const readable = files.filter(f => state.identity.has(f.type));
    if (readable.length === 0) {
        const types = [...new Set(files.map(f => KEY_TYPE_LABEL[f.type]))].join(" / ");
        return <Shell tone="muted">Encrypted {types} attachment. You don't have a {types} key, so it can't be for you.</Shell>;
    }
    return <>{readable.map(f => <AttachmentFile key={f.url} message={message} file={f} set={set} ref_={ref_} />)}</>;
}

function AttachmentFile({ message, file, set, ref_ }: { message: Message; file: ReturnType<typeof cipherAttachments>[number]; set?: string; ref_?: string; }) {
    const [armored, setArmored] = useState<string>();
    const [error, setError] = useState<string>();

    useEffect(() => {
        let live = true;
        fetchAttachmentText(file.url, file.size).then(t => live && setArmored(t), e => live && setError(safeMessage(e)));
        return () => void (live = false);
    }, [file.url]);

    if (error) return <Shell tone="bad">{error}</Shell>;
    if (!armored) return <Shell tone="muted">Downloading encrypted attachment…</Shell>;
    return <Decrypt message={message} type={file.type} armored={armored} set={set} ref_={ref_} />;
}

function usePgpPaused() {
    const [paused, setPaused] = useState(isPgpPaused());
    useEffect(() => onPgpPauseChange(() => setPaused(isPgpPaused())), []);
    return paused;
}

function useOutcome(type: KeyType, armored: string, tryHidden: boolean) {
    const ready = useCipher();
    const [outcome, setOutcome] = useState<DecryptOutcome | "locked" | "loading" | "paused">("loading");
    const unlocked = ready && state.identity.isUnlocked;
    const hasKey = ready && state.identity.has(type);
    const paused = usePgpPaused() && type === "pgp";

    useEffect(() => {
        if (!ready) return;
        let live = true;
        (async () => {
            if (!unlocked || paused) {
                // Answer what we can without the passphrase.
                const pre = await precheck(type, armored, { tryHidden });
                if (live) setOutcome(pre ?? (paused ? "paused" : "locked"));
                return;
            }
            setOutcome("loading");
            const r = await decryptCached(type, armored, { tryHidden });
            if (live) setOutcome(r);
        })();
        return () => void (live = false);
    }, [ready, unlocked, paused, tryHidden, hasKey, armored, type, state.contacts?.list().length]);

    return outcome;
}

/* ---------- disappearing messages (links to a Cipher server) ---------- */

const fetched = new Map<string, Promise<{ armored: string; } | { gone: true; }>>();

function fetchOnce(link: MessageLink) {
    const key = `${link.origin}/${link.id}#${link.hash}`;
    let p = fetched.get(key);
    if (!p) {
        if (fetched.size > 500) fetched.clear();
        p = fetchMessage(link.origin, link.id, link.hash);
        p.catch(() => fetched.delete(key));
        fetched.set(key, p);
    }
    return p;
}

export function clearFetchedLinks() {
    fetched.clear();
}

function relativeTime(at: number): string {
    const ms = at - Date.now();
    if (ms <= 0) return "now";
    const h = Math.round(ms / 3_600_000);
    if (h < 1) return "in less than an hour";
    if (h < 48) return `in ${h} hour${h > 1 ? "s" : ""}`;
    return `in ${Math.round(h / 24)} days`;
}

function LinkMessage({ message, parsed }: { message: Message; parsed: Extract<ParsedContent, { kind: "link"; }>; }) {
    const ready = useCipher();
    if (!ready) return null;
    const mine = parsed.links.filter(l => state.identity.has(l.type));
    if (mine.length === 0) {
        const types = [...new Set(parsed.links.map(l => KEY_TYPE_LABEL[l.type]))].join(" / ");
        return <Shell tone="muted">Disappearing {types} message. You don't have a {types} key, so it can't be for you.</Shell>;
    }
    const allTypes = parsed.links.map(l => l.type);
    return <>{mine.map(l => <LinkCopy key={l.id} message={message} link={l} expiresAt={parsed.expiresAt} siblings={allTypes.length > 1 ? allTypes : []} />)}</>;
}

function LinkCopy({ message, link, expiresAt, siblings }: { message: Message; link: MessageLink; expiresAt: number; siblings: KeyType[]; }) {
    // With your own server set, it's the only one Cipher ever contacts. Without
    // one, another server is only contacted after a click: loading a link tells
    // its server your IP address and when you read the message.
    const own = serverOrigin();
    const auto = own === link.origin;
    const [allowed, setAllowed] = useState(auto);
    const [result, setResult] = useState<{ armored: string; } | { gone: true; } | { error: string; }>();

    useEffect(() => {
        if (!allowed) return;
        if (expiresAt <= Date.now()) return void setResult({ gone: true });
        let live = true;
        fetchOnce(link).then(r => live && setResult(r), e => live && setResult({ error: safeMessage(e) }));
        return () => void (live = false);
    }, [allowed, link.id]);

    const host = new URL(link.origin).host;
    if (own && !auto) {
        return (
            <Shell tone="muted">
                Disappearing message stored on {host}, a different Cipher server. Cipher only contacts your own server, so it wasn't loaded. Ask the sender to send it again without the disappearing option, or through your server.
            </Shell>
        );
    }
    if (!allowed) {
        return (
            <Shell tone="muted">
                <span>Disappearing message stored on {host}, which isn't your Cipher server. Loading it tells that server your IP address. </span>
                <Button size="min" variant="secondary" onClick={() => setAllowed(true)}>Load it</Button>
            </Shell>
        );
    }
    if (!result) return <Shell tone="muted">Loading disappearing message…</Shell>;
    if ("gone" in result) return <Shell tone="muted">This disappearing message has expired or was deleted.</Shell>;
    if ("error" in result) return <Shell tone="bad">{result.error}</Shell>;
    return (
        <>
            <Decrypt message={message} type={link.type} armored={result.armored} siblings={siblings} />
            <div className={cl("hint", "expiry")}>Disappears {relativeTime(expiresAt)} (stored on {host})</div>
        </>
    );
}

function Decrypt({ message, type, armored, set, ref_, siblings: siblingOverride }: { message: Message; type: KeyType; armored: string; set?: string; ref_?: string; siblings?: KeyType[]; }) {
    const [tryHidden, setTryHidden] = useState(false);
    const outcome = useOutcome(type, armored, tryHidden);

    if (outcome === "loading") return <Shell tone="muted">Decrypting…</Shell>;
    if (outcome === "locked") {
        return (
            <Shell tone="muted">
                <span>Encrypted {KEY_TYPE_LABEL[type]} message. </span>
                <Button size="min" variant="secondary" onClick={() => requestUnlock()}>Unlock to read</Button>
            </Shell>
        );
    }
    if (outcome === "paused") {
        return (
            <Shell tone="muted">
                <span>Encrypted PGP message. </span>
                <Button size="min" variant="secondary" onClick={() => setPgpPaused(false)}>Decrypt</Button>
                <div className={cl("hint")}>The GnuPG passphrase prompt was closed, so Cipher stopped opening it by itself.</div>
            </Shell>
        );
    }
    if (!outcome.ok && outcome.code === "hidden-recipients") {
        return (
            <Shell tone="muted">
                <span>{outcome.message} </span>
                <Button size="min" variant="secondary" onClick={() => setTryHidden(true)}>Try to decrypt</Button>
            </Shell>
        );
    }
    if (!outcome.ok) {
        // One of several copies (age / post-quantum age / PGP) of the same message.
        const siblings = siblingOverride ?? (set && ref_ ? siblingTypes(message.channel_id, message.author.id, set, ref_) : []);
        if ((outcome.code === "not-recipient" || outcome.code === "missing-key") && siblings.some(t => state.identity.has(t)))
            return <Shell tone="muted">This is one of several encrypted copies of the same message, for readers with other kinds of keys. Your copy is shown there.</Shell>;
        const tone: Tone = outcome.code === "not-recipient" || outcome.code === "missing-key" ? "muted" : "bad";
        return <Shell tone={tone}>{outcome.message}</Shell>;
    }
    return (
        <Shell tone="good">
            <div className={cl("plaintext")}>{Parser.parse(outcome.text, true, { channelId: message.channel_id, messageId: message.id, allowLinks: true })}</div>
            <SenderBadges message={message} type={type} result={outcome} />
            {/* Discord's own "Copy Text" copies the ciphertext, so offer the decrypted text here. */}
            <Button size="min" variant="none" className={cl("link", "reveal")} onClick={() => copyWithToast(outcome.text, "Decrypted text copied")}>Copy decrypted text</Button>
        </Shell>
    );
}

function SenderBadges({ message, type, result }: { message: Message; type: KeyType; result: DecryptedMessage; }) {
    const authorId = message.author.id;
    const isSelf = authorId === selfId();
    const contact = state.contacts.get(authorId);
    const name = userName(authorId);
    const badges: React.ReactNode[] = [<Badge key="t" tone="info">{KEY_TYPE_LABEL[type]}</Badge>];

    const sig = result.signature;
    if (sig.status === "not-supported") {
        badges.push(<Badge key="s" tone="muted" title="age has no signatures. Anyone who has your public key could have written this; the badge below only tells you about the Discord account that posted it.">unsigned (age)</Badge>);
    } else if (sig.status === "unsigned") {
        badges.push(<Badge key="s" tone="warn" title="The sender didn't sign this message, so it can't be confirmed who wrote it.">not signed</Badge>);
    } else if (sig.status === "invalid") {
        badges.push(<Badge key="s" tone="bad" title="The signature doesn't match the message. It may have been forged or altered.">✗ INVALID SIGNATURE</Badge>);
    } else if (sig.status === "unknown-signer") {
        badges.push(<Badge key="s" tone="warn" title={`Signed by key ID ${sig.signerKeyId.toUpperCase()}, which isn't in your contacts.`}>signed by unknown key</Badge>);
    } else {
        const fp = sig.signerFingerprint;
        const ownFp = state.identity.publicIdentity.pgp?.fingerprint;
        const signer = state.contacts.list().find(c => c.key.type === "pgp" && c.key.fingerprint === fp);
        const pendingSigner = state.contacts.list().find(c => c.pendingKey?.fingerprint === fp);
        if (isSelf && fp === ownFp) badges.push(<Badge key="s" tone="good">✓ signed by you</Badge>);
        else if (signer?.userId === authorId) badges.push(<Badge key="s" tone={signer.verified ? "good" : "warn"}>✓ signed by {name}{signer.verified ? "" : " (key unverified)"}</Badge>);
        else if (pendingSigner?.userId === authorId) badges.push(<Badge key="s" tone="bad" title="Signed with a new key this person posted that you haven't accepted.">signed with {name}'s NEW key</Badge>);
        else if (signer) badges.push(<Badge key="s" tone="bad" title="The signature is valid, but the key belongs to someone other than the account that posted it.">⚠ signed by {userName(signer.userId)}, posted by {name}</Badge>);
        else if (fp === ownFp) badges.push(<Badge key="s" tone="bad">⚠ signed with YOUR key, posted by {name}</Badge>);
        else badges.push(<Badge key="s" tone="warn">signed by unknown key</Badge>);
    }

    if (isSelf) badges.push(<Badge key="a" tone="muted">sent by you</Badge>);
    else if (!contact) badges.push(<Badge key="a" tone="warn" title="You have no key saved for this person.">sender not in contacts</Badge>);
    else if (contact.pendingKey) badges.push(<Badge key="a" tone="bad" title="This person posted a different key. Review it in their contact.">⚠ sender's key changed</Badge>);
    else badges.push(contact.verified ? <Badge key="a" tone="good">sender key verified</Badge> : <Badge key="a" tone="warn">sender key unverified</Badge>);

    return <div className={cl("badges")}>{badges}</div>;
}

/* ---------- shared public keys ---------- */

function KeyShare({ message, parsed }: { message: Message; parsed: Extract<ParsedContent, { kind: "key"; }>; }) {
    const ready = useCipher();
    const [info, setInfo] = useState<KeyInfo>();
    const [error, setError] = useState<string>();
    const [check, setCheck] = useState(false);

    const authorId = message.author.id;
    // A PGP key from someone who isn't a contact is only handed to GnuPG after
    // a click, so a stranger posting a key can't make GnuPG parse it unasked.
    // age keys are checked in JavaScript; contacts' keys are checked at once
    // so a key change is noticed.
    const auto = parsed.type === "age" || (ready && (authorId === selfId() || !!state.contacts.get(authorId)));
    const go = auto || check;

    useEffect(() => {
        if (!go) return;
        inspectKey(parsed.type, parsed.material).then(setInfo, e => setError(safeMessage(e)));
    }, [parsed.material, go]);

    const sentAt = new Date(message.timestamp as any).getTime();
    const contact = ready ? state.contacts.get(authorId) : undefined;
    const status = ready && info ? state.contacts.checkKey(authorId, info.type, info.fingerprint) : undefined;
    // Only a key posted after the one we trust counts as a change; old shares are history.
    const isNewer = !!contact && sentAt > contact.key.addedAt;

    useEffect(() => {
        if (ready && info && status === "changed" && isNewer && authorId !== selfId())
            state.contacts.observeSharedKey(authorId, info, message.id).catch(() => { });
    }, [ready, info?.fingerprint, status, isNewer]);

    if (!ready) return null;
    if (error) return <Shell tone="bad">Shared key can't be used: {error}</Shell>;
    if (!go) {
        return (
            <Shell tone="info">
                <span>{userName(authorId)} shared a PGP public key. </span>
                <Button size="min" variant="secondary" onClick={() => setCheck(true)}>Check key</Button>
            </Shell>
        );
    }
    if (!info) return <Shell tone="muted">Checking shared key…</Shell>;

    const name = userName(authorId);
    const problems = info.problems.map(p => <Notice key={p} tone="bad">{KEY_PROBLEM_TEXT[p]}</Notice>);
    const header = <div><b>{keyLabel(info.type, info.material)} public key</b> · code <code className={cl("code")}>{info.code}</code></div>;

    if (authorId === selfId()) {
        const mine = state.identity.publicIdentity[info.type];
        const same = info.type === "age" ? state.identity.publicIdentity.age?.recipient === info.material : state.identity.publicIdentity.pgp?.fingerprint === info.fingerprint;
        return <Shell tone={same ? "muted" : "warn"}>{header}{same ? "This is your current key." : mine ? "This is not your current key." : "You no longer have this key."}</Shell>;
    }

    if (status === "unknown") {
        return (
            <Shell tone="info">
                {header}
                {problems}
                <div className={cl("row")}>
                    <Button size="small" onClick={() => openContactDialog(authorId, { prefill: info.material })}>Trust this key for {name}</Button>
                </div>
                <div className={cl("hint")}>Before trusting, compare the code with {name} over a call or in person.</div>
            </Shell>
        );
    }

    if (status === "same") {
        return <Shell tone="good">{header}You already trust this key for {name}{contact?.verified ? " (verified)." : " (not verified yet)."}</Shell>;
    }

    if (!isNewer) {
        const old = contact?.history.some(h => h.fingerprint === info.fingerprint);
        return (
            <Shell tone="muted">
                {header}
                {old
                    ? `A previous key of ${name}. You now use a newer one.`
                    : `${name} posted this before you saved the key you trust for them, and it's different. If you're not sure which is current, ask them.`}
            </Shell>
        );
    }

    if (state.contacts.isDismissed(authorId, info.fingerprint)) {
        return (
            <Shell tone="warn">
                {header}
                <div>{name} posted this key, but you chose to keep the key you already trust.</div>
                <div className={cl("row")}>
                    <Button size="small" variant="secondary" onClick={() => openContactDialog(authorId, { prefill: info.material })}>Review again</Button>
                </div>
            </Shell>
        );
    }

    return (
        <Shell tone="bad">
            <div className={cl("loud")}>⚠ {name} posted a DIFFERENT key from the one you trust</div>
            {header}
            {problems}
            <div>This can mean they got a new device or reset their key, or that someone is trying to read your messages. Cipher keeps encrypting to the old key until you decide.</div>
            <div className={cl("row")}>
                <Button size="small" variant="dangerPrimary" onClick={() => openKeyChangeDialog(authorId)}>Review key change</Button>
                <Button size="small" variant="secondary" onClick={() => state.contacts.dismissPendingKey(authorId).then(() => toastOk("Kept the old key"), toastError)}>Keep old key</Button>
            </div>
        </Shell>
    );
}
