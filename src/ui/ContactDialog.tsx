/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import type { RenderModalProps } from "@vencord/discord-types";
import { Modal, openModal, UserStore, useEffect, useMemo, useState } from "@webpack/common";

import { safeMessage } from "../core/errors";
import { inspectPasted, KEY_PROBLEM_TEXT, KEY_TYPE_LABEL, type KeyInfo, keyLabel } from "../core/keys";
import { type DirectoryKey, lookupKeys, serverOrigin } from "../server";
import { selfId, state, useCipher, userName } from "../state";
import { Badge, Button, Checkbox, cl, confirmDanger, Fingerprint, Notice, TextBox, TextField, toastError, toastOk, TypeBadge, VerifiedBadge } from "./common";
import { discordPeople, matchesPerson } from "./discordPeople";

const USER_ID_RE = /^\d{17,20}$/;

function ContactDialog({ modal, initialUserId, prefill }: { modal: RenderModalProps; initialUserId?: string; prefill?: string; }) {
    useCipher();
    const [userIdInput, setUserIdInput] = useState(initialUserId ?? "");
    const userId = initialUserId ?? userIdInput.trim();
    const validId = USER_ID_RE.test(userId) && userId !== selfId();
    const contact = validId ? state.contacts?.get(userId) : undefined;

    const [pasted, setPasted] = useState(prefill ?? "");
    const [info, setInfo] = useState<KeyInfo>();
    const [pasteError, setPasteError] = useState<string>();
    const [verified, setVerified] = useState(false);
    const [understood, setUnderstood] = useState(false);
    const [busy, setBusy] = useState(false);

    useEffect(() => {
        setInfo(undefined);
        setPasteError(undefined);
        setUnderstood(false);
        if (!pasted.trim()) return;
        let live = true;
        inspectPasted(pasted).then(i => live && setInfo(i), e => live && setPasteError(safeMessage(e)));
        return () => void (live = false);
    }, [pasted]);

    const name = validId ? userName(userId) : "this user";
    const isChange = !!contact && !!info && (contact.key.fingerprint !== info.fingerprint || contact.key.type !== info.type);
    const isSame = !!contact && !!info && !isChange;

    const save = async () => {
        if (!validId || !info || busy) return;
        setBusy(true);
        try {
            if (!contact) {
                await state.contacts.add(userId, userName(userId), info);
                if (verified) await state.contacts.setVerified(userId, true);
                toastOk(`Saved ${KEY_TYPE_LABEL[info.type]} key for ${name}`);
            } else if (isChange) {
                await state.contacts.replaceKey(userId, info, { verified });
                toastOk(`Replaced ${name}'s key`);
            } else {
                return modal.onClose();
            }
            modal.onClose();
        } catch (e) {
            toastError(e);
        } finally {
            setBusy(false);
        }
    };

    const remove = async () => {
        if (!contact) return;
        const ok = await confirmDanger(`Remove ${name}?`, `You won't be able to encrypt to ${name} until you add their key again. Messages they could already read stay readable to them.`, "Remove");
        if (!ok) return;
        await state.contacts.remove(userId).catch(toastError);
        modal.onClose();
    };

    const canSave = validId && !!info && !isSame && (!isChange || understood) && !busy;

    return (
        <Modal
            {...modal}
            size="md"
            title={contact ? `${name}'s key` : "Add a contact key"}
            subtitle={contact ? undefined : "Paste their age or PGP public key. The type is detected automatically."}
            actions={[
                ...(info && !isSame ? [{ text: isChange ? "Replace key" : "Save", variant: isChange ? "critical-primary" : "primary", onClick: save, disabled: !canSave, loading: busy }] : []),
                { text: "Close", variant: "secondary", onClick: modal.onClose }
            ]}
        >
            <div className={cl("stack")}>
                {!initialUserId && (validId
                    ? (
                        <div className={cl("row")}>
                            <span>For <b>{name}</b>{UserStore.getUser(userId)?.username ? ` (@${UserStore.getUser(userId).username})` : ""}</span>
                            <Button size="min" variant="none" className={cl("link")} onClick={() => setUserIdInput("")}>change</Button>
                        </div>
                    )
                    : <PersonPicker onPick={setUserIdInput} />
                )}

                {contact && (
                    <div className={cl("card")}>
                        <div className={cl("row")}>
                            <b>Current key</b> <TypeBadge type={contact.key.type} material={contact.key.material} /> <VerifiedBadge verified={contact.verified} />
                        </div>
                        <Fingerprint fingerprint={contact.key.fingerprint} />
                        <CodeFor type={contact.key.type} material={contact.key.material} />
                        <Checkbox checked={contact.verified} onChange={v => state.contacts.setVerified(userId, v).catch(toastError)}>
                            I compared this code with {name} over a call or in person and it matches
                        </Checkbox>
                        {contact.history.length > 0 && <div className={cl("hint")}>Key changed {contact.history.length} time{contact.history.length > 1 ? "s" : ""} before (last on {new Date(contact.history[contact.history.length - 1].replacedAt).toLocaleDateString()}).</div>}
                        {contact.pendingKey && <Notice tone="bad">⚠ {name} posted a different key on {new Date(contact.pendingKey.seenAt).toLocaleString()}. You're still encrypting to the key above.</Notice>}
                    </div>
                )}

                {validId && serverOrigin() && <ServerLookup userId={userId} onFound={setPasted} />}

                <div className={cl("label")}>{contact ? "Paste a new key to replace it" : "Public key"}</div>
                <TextBox value={pasted} onChange={setPasted} rows={5} placeholder="age1…  or  -----BEGIN PGP PUBLIC KEY BLOCK-----" />
                {pasteError && <Notice tone="bad">{pasteError}</Notice>}

                {info && (
                    <div className={cl("card", isChange && "card-danger")}>
                        {isChange && <div className={cl("loud")}>⚠ This is a DIFFERENT key from the one you trust for {name}</div>}
                        <div className={cl("row")}><b>{isChange ? "New key" : "Detected"}</b> <TypeBadge type={info.type} material={info.material} /></div>
                        <Fingerprint fingerprint={info.fingerprint} code={info.code} />
                        {info.userIds.length > 0 && <div className={cl("hint")}>User IDs: {info.userIds.join(", ")}</div>}
                        {info.problems.map(p => <Notice key={p} tone="bad">{KEY_PROBLEM_TEXT[p]} You won't be able to encrypt to it.</Notice>)}
                        {isSame && <Notice tone="good">This is the key you already trust.</Notice>}
                        {!isSame && (
                            <Checkbox checked={verified} onChange={setVerified}>
                                I compared this code with {name} over a call or in person and it matches
                            </Checkbox>
                        )}
                        {isChange && (
                            <>
                                <div>Only replace the key if {name} told you, outside this chat, that they have a new key. Someone with access to their account could post a key to read your future messages.</div>
                                <Checkbox checked={understood} onChange={setUnderstood}>
                                    I understand: future messages to {name} will be encrypted to this new key
                                </Checkbox>
                            </>
                        )}
                    </div>
                )}

                {contact && (
                    <div className={cl("row")}>
                        {contact.pendingKey && !prefill && <Button size="small" variant="secondary" onClick={() => setPasted(contact.pendingKey!.material)}>Show the new key they posted</Button>}
                        {contact.pendingKey && <Button size="small" variant="secondary" onClick={() => state.contacts.dismissPendingKey(userId).then(() => toastOk("Kept the current key"), toastError)}>Keep current key</Button>}
                        <Button size="small" variant="dangerSecondary" onClick={remove}>Remove contact</Button>
                    </div>
                )}
            </div>
        </Modal>
    );
}

/** Fetches the user's published keys from the Cipher server into the paste box; trusting still needs the usual checks. */
function ServerLookup({ userId, onFound }: { userId: string; onFound(key: string): void; }) {
    const [keys, setKeys] = useState<DirectoryKey[]>();
    const [busy, setBusy] = useState(false);
    const find = async () => {
        setBusy(true);
        try {
            const found = await lookupKeys(userId, { fresh: true });
            setKeys(found);
            if (found.length === 1) onFound(found[0].key);
        } catch (e) {
            toastError(e);
        } finally {
            setBusy(false);
        }
    };
    return (
        <div className={cl("row", "wrap")}>
            <Button size="small" variant="secondary" disabled={busy} onClick={find}>Find their key on the Cipher server</Button>
            {keys?.length === 0 && <span className={cl("hint")}>They haven't published a key there.</span>}
            {keys && keys.length > 1 && keys.map(k => <Button key={k.type} size="min" variant="secondary" onClick={() => onFound(k.key)}>Use their {keyLabel(k.type, k.key)} key</Button>)}
            {keys && keys.length > 0 && <span className={cl("hint")}>A key from the server is only as trustworthy as the server: still compare the code with them.</span>}
            {keys?.map(k => <DirectoryNotes key={k.type} k={k} />)}
        </div>
    );
}

const RECENT_MS = 30 * 86_400_000;

/** Warnings about a looked-up key's history: a waiting change or a recent reset can mean a taken-over account. */
function DirectoryNotes({ k }: { k: DirectoryKey; }) {
    const label = k.type === "age" ? "age" : "PGP";
    const when = (t: number) => new Date(t).toLocaleDateString();
    if (k.pending) {
        return (
            <Notice tone="bad">
                ⚠ Someone asked to {k.pending.removal ? "remove" : "replace"} their {label} key on the server without proof from it (takes effect {when(k.pending.effectiveAt)}).
                They may have lost it, or someone may have taken over their Discord account. Ask them outside Discord before trusting either key.
            </Notice>
        );
    }
    if (k.how === "reset" && k.changedAt && Date.now() - k.changedAt < RECENT_MS) {
        return (
            <Notice tone="bad">
                ⚠ Their {label} key replaced their previous one on {when(k.changedAt)} without the old key's approval.
                Only trust it after comparing the code with them outside Discord.
            </Notice>
        );
    }
    if (k.how === "proven" && k.changedAt && Date.now() - k.changedAt < RECENT_MS)
        return <span className={cl("hint")}>Their {label} key changed on {when(k.changedAt)}; their previous key approved the change.</span>;
    return null;
}

/** Picks who a key is for from your Discord friends and group DMs, or by pasted user ID. */
function PersonPicker({ onPick }: { onPick(userId: string): void; }) {
    const [query, setQuery] = useState("");
    const people = useMemo(discordPeople, []);
    const id = query.trim();
    const byId = USER_ID_RE.test(id) && id !== selfId() && !people.some(p => p.userId === id);
    const shown = people.filter(p => matchesPerson(p, query));
    const LIMIT = 100;
    return (
        <>
            <div className={cl("label")}>Who is this key for?</div>
            <TextField value={query} onChange={setQuery} placeholder="Search your friends and group DMs, or paste a user ID" autoFocus />
            <div className={cl("list")}>
                {byId && (
                    <button type="button" className={cl("list-row", "person")} onClick={() => onPick(id)}>
                        <span className={cl("name")}>{userName(id)}</span>
                        <span className={cl("hint")}>user ID {id}</span>
                    </button>
                )}
                {shown.slice(0, LIMIT).map(p => (
                    <button type="button" key={p.userId} className={cl("list-row", "person")} onClick={() => onPick(p.userId)}>
                        <span className={cl("name")}>{p.name}</span>
                        {/* Always show the unique username: display names can be copied. */}
                        {p.username && <span className={cl("hint")}>@{p.username}</span>}
                        {p.friend && <Badge tone="muted">friend</Badge>}
                        {p.groups.length > 0 && <span className={cl("hint")} title={p.groups.join(", ")}>in {p.groups.length === 1 ? p.groups[0] : `${p.groups.length} group DMs`}</span>}
                        {state.contacts?.get(p.userId) && <Badge tone="good">key saved</Badge>}
                    </button>
                ))}
                {shown.length > LIMIT && <div className={cl("hint")}>{shown.length - LIMIT} more; type to narrow it down.</div>}
                {!byId && shown.length === 0 && (
                    <div className={cl("hint")}>
                        {people.length === 0 ? "No friends or group DMs found. " : "Nobody matches. "}
                        For anyone else, paste their user ID (right-click them → Copy User ID, with Developer Mode on).
                    </div>
                )}
            </div>
        </>
    );
}

/** Shows the comparison code for a stored key (computed on demand). */
function CodeFor({ type, material }: { type: KeyInfo["type"]; material: string; }) {
    const [code, setCode] = useState<string>();
    useEffect(() => {
        inspectPasted(material).then(i => setCode(i.code), () => setCode(undefined));
    }, [material, type]);
    return code ? <div><span className={cl("fp-label")}>Code</span> <code className={cl("code")}>{code}</code></div> : null;
}

export function openContactDialog(userId?: string, opts: { prefill?: string; } = {}) {
    openModal(modal => <ContactDialog modal={modal} initialUserId={userId} prefill={opts.prefill} />);
}

export function openKeyChangeDialog(userId: string) {
    const pending = state.contacts.get(userId)?.pendingKey;
    openContactDialog(userId, { prefill: pending?.material });
}
