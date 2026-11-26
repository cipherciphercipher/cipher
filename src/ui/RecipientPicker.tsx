/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { sendMessage } from "@utils/discord";
import type { Channel, RenderModalProps } from "@vencord/discord-types";
import { Modal, openModal, useEffect, useMemo, useState } from "@webpack/common";

import { formatKeyShare } from "../core/envelope";
import { inspectKey, KEY_PROBLEM_TEXT, KEY_TYPE_LABEL, type KeyType } from "../core/keys";
import { type Candidate, describePlanError, MAX_RECIPIENTS, planEncryption, restrictToType } from "../core/recipients";
import { loadCandidates, selfId, state, useCipher, userName } from "../state";
import { Badge, Button, Checkbox, cl, confirmDanger, Notice, TextField, toastError, toastOk, TypeBadge, VerifiedBadge } from "./common";
import { openContactDialog } from "./ContactDialog";
import { describeExposure, exposureFor } from "./exposure";
import { openGroupEditor } from "./GroupEditor";
import { openKeyManager } from "./KeyManager";
import { LINK_TTL_DAYS, type LinkTtl } from "../core/serverApi";
import { getSession, serverOrigin } from "../server";

function Picker({ modal, channel }: { modal: RenderModalProps; channel: Channel; }) {
    useCipher();
    const prefs = state.channels.get(channel.id);
    // Nobody but you is selected unless this chat already has encryption on.
    const [selected, setSelected] = useState<string[]>(prefs.mode === "off" ? [] : prefs.recipients);
    const [allowSplit, setAllowSplit] = useState(prefs.mode === "off" ? false : prefs.allowSplit);
    const [candidates, setCandidates] = useState<Map<string, Candidate>>();
    const [query, setQuery] = useState("");
    const [linkDays, setLinkDays] = useState<LinkTtl | undefined>(prefs.mode === "off" ? undefined : prefs.linkDays);
    const server = serverOrigin();
    const [signedIn, setSignedIn] = useState<boolean>();
    useEffect(() => {
        if (server) getSession().then(s => setSignedIn(!!s), () => setSignedIn(false));
    }, [server]);

    const contactCount = state.contacts.list().length;
    useEffect(() => {
        loadCandidates().then(setCandidates, toastError);
    }, [contactCount, state.contacts.list().map(c => c.key.fingerprint + c.verified + !!c.pendingKey).join()]);

    const lookup = (id: string) => candidates?.get(id);
    const plan = useMemo(() => candidates && planEncryption({
        self: state.identity.selfKeys(selfId()), selectedIds: selected, lookup, allowSplit
    }), [candidates, selected, allowSplit, state.identity.publicIdentity]);

    const memberIds = new Set(channel.isPrivate() ? channel.recipients ?? [] : []);
    // DMs and group DMs only: a server channel's member list isn't fully known.
    const chatMembers = [...memberIds].filter(id => id !== selfId());
    const noKeyHere = chatMembers.filter(id => !state.contacts.get(id));
    const list = [...candidates?.values() ?? []]
        .filter(c => !query || c.name.toLowerCase().includes(query.toLowerCase()))
        .sort((a, b) => Number(memberIds.has(b.userId)) - Number(memberIds.has(a.userId)) || a.name.localeCompare(b.name));

    const count = selected.length + 1;
    const atCap = count >= MAX_RECIPIENTS;

    const toggle = (id: string, on: boolean) => {
        if (on && atCap) return;
        setSelected(s => on ? [...s, id] : s.filter(x => x !== id));
    };

    const addGroup = (memberIds: string[]) => {
        const withKey = memberIds.filter(id => candidates?.has(id));
        const missing = memberIds.filter(id => !candidates?.has(id));
        const next = [...new Set([...selected, ...withKey])];
        if (next.length + 1 > MAX_RECIPIENTS) {
            return void openModalNotice(`That group would make ${next.length + 1} readers; the limit is ${MAX_RECIPIENTS} including you.`);
        }
        setSelected(next);
        if (missing.length) openModalNotice(`Not added (no key saved): ${missing.map(userName).join(", ")}.`);
    };

    const apply = async (mode: "once" | "sticky" | "off") => {
        try {
            if (mode === "off") await state.channels.turnOff(channel.id);
            else await state.channels.set(channel.id, { mode, recipients: selected, allowSplit, ...server && linkDays ? { linkDays } : {} });
            modal.onClose();
        } catch (e) {
            toastError(e);
        }
    };

    const shareKey = async (type: KeyType) => {
        const pub = state.identity.publicIdentity;
        const material = type === "age" ? pub.age?.recipient : pub.pgp?.publicKey;
        if (!material) return;
        const ok = await confirmDanger(`Post your ${KEY_TYPE_LABEL[type]} public key here?`, "Your public key is safe to share. Anyone in this chat will see it, and Cipher users can choose to trust it for you.", "Post key");
        if (!ok) return;
        try {
            const info = await inspectKey(type, material);
            await sendMessage(channel.id, { content: formatKeyShare(type, info.material, info.code) });
            toastOk("Public key posted");
        } catch (e) {
            toastError(e);
        }
    };

    const ok = plan?.ok === true;
    const readerIds = [selfId(), ...selected];
    const exposure = describeExposure(exposureFor(channel, readerIds));

    return (
        <Modal
            {...modal}
            size="md"
            title="Who can read your messages here?"
            subtitle="Only people you have a key for are listed. You're always a reader."
            actions={[
                { text: "Encrypt next message", variant: "primary", onClick: () => apply("once"), disabled: !ok },
                { text: "Keep on in this chat", variant: "primary", onClick: () => apply("sticky"), disabled: !ok },
                ...(prefs.mode !== "off" ? [{ text: "Turn encryption off", variant: "secondary", onClick: () => apply("off") }] : [])
            ]}
        >
            <div className={cl("stack")}>
                <div className={cl("row", "row-between")}>
                    <b>Readers: {count} / {MAX_RECIPIENTS}</b>
                    <span className={cl("hint")}>Currently: {prefs.mode === "off" ? "off (messages are NOT encrypted)" : prefs.mode === "once" ? "next message only" : "on in this chat"}</span>
                </div>

                <SelfRow />
                {!state.identity.has("age") && !state.identity.has("pgp") && (
                    <Notice tone="warn">
                        You need a key of your own first.{" "}
                        <Button size="min" variant="secondary" onClick={() => openKeyManager()}>Set up my key</Button>
                    </Notice>
                )}
                {noKeyHere.length > 0 && (
                    <Notice tone="info">
                        No key saved for {noKeyHere.map(userName).join(", ")}. Ask them to click "Share my key here" in Cipher, then click "Trust this key" under it, or add it yourself:
                        <div className={cl("row", "wrap")}>
                            {noKeyHere.slice(0, 5).map(id => <Button key={id} size="min" variant="secondary" onClick={() => openContactDialog(id)}>Add {userName(id)}'s key</Button>)}
                        </div>
                    </Notice>
                )}

                {(state.groups.list().length > 0 || chatMembers.length > 0) && (
                    <div className={cl("row", "wrap")}>
                        {chatMembers.length > 0 && <Button size="min" variant="secondary" onClick={() => addGroup(chatMembers)}>+ Everyone in this chat ({chatMembers.length})</Button>}
                        {state.groups.list().map(g => (
                            <Button key={g.id} size="min" variant="secondary" onClick={() => addGroup(g.memberIds)}>+ {g.name} ({g.memberIds.length})</Button>
                        ))}
                    </div>
                )}

                {server && (
                    <div className={cl("stack-tight")}>
                        <div className={cl("row", "wrap")}>
                            <b>Delivery:</b>
                            <Button size="min" variant={linkDays ? "secondary" : "primary"} onClick={() => setLinkDays(undefined)}>Kept in Discord</Button>
                            {LINK_TTL_DAYS.map(d => (
                                <Button key={d} size="min" variant={linkDays === d ? "primary" : "secondary"} onClick={() => setLinkDays(d)}>Disappears after {d} day{d > 1 ? "s" : ""}</Button>
                            ))}
                        </div>
                        {linkDays && <div className={cl("hint")}>The encrypted text goes to {new URL(server).host} and is deleted there after {linkDays} day{linkDays > 1 ? "s" : ""}. Discord only gets a link. Readers need Cipher set to the same server to read it automatically.</div>}
                        {linkDays && signedIn === false && <Notice tone="warn">Sign in to the Cipher server first (Keys &amp; contacts → Cipher server).</Notice>}
                    </div>
                )}

                <TextField value={query} onChange={setQuery} placeholder="Search contacts" />

                <div className={cl("list")}>
                    {!candidates && <div className={cl("hint")}>Checking keys…</div>}
                    {candidates && list.length === 0 && (
                        <div className={cl("hint")}>No contacts{query ? " match" : " yet"}. Add someone's key from their profile menu or when they share it in chat.</div>
                    )}
                    {list.map(c => (
                        <div key={c.userId} className={cl("list-row")}>
                            <Checkbox checked={selected.includes(c.userId)} disabled={!selected.includes(c.userId) && atCap} onChange={v => toggle(c.userId, v)}>
                                <span className={cl("name")}>{c.name}</span>
                            </Checkbox>
                            <TypeBadge type={c.type} material={c.material} />
                            <VerifiedBadge verified={c.verified} />
                            {c.pendingKeyChange && <Badge tone="bad" title="They posted a different key. Review it before relying on this contact.">key changed</Badge>}
                            {c.problems.map(p => <Badge key={p} tone="bad" title={KEY_PROBLEM_TEXT[p]}>{p.replace(/-/g, " ")}</Badge>)}
                            {channel.isPrivate() && !memberIds.has(c.userId) && <Badge tone="muted">not in this chat</Badge>}
                            <Button size="min" variant="none" className={cl("link")} onClick={() => openContactDialog(c.userId)}>details</Button>
                        </div>
                    ))}
                </div>
                {atCap && <Notice tone="warn">Limit reached: at most {MAX_RECIPIENTS} readers including you.</Notice>}

                {plan && !plan.ok && plan.error.code === "mixed-types" && (
                    <MixedChoice selected={selected} lookup={lookup} onRestrict={kept => { setSelected(kept); setAllowSplit(false); }} onSplit={() => setAllowSplit(true)} />
                )}
                {plan && !plan.ok && plan.error.code === "mixed-age" && (
                    <Notice tone="warn">
                        {describePlanError(plan.error, userName)}
                        <div><Button size="small" onClick={() => setAllowSplit(true)}>Send one copy per kind</Button></div>
                    </Notice>
                )}
                {plan && !plan.ok && plan.error.code !== "mixed-types" && plan.error.code !== "mixed-age" && plan.error.code !== "no-recipients" && <Notice tone="bad">{describePlanError(plan.error, userName)}</Notice>}
                {plan && !plan.ok && plan.error.code === "no-recipients" && <Notice tone="muted">Pick at least one person. A message only you can read isn't sent.</Notice>}

                {plan?.ok && plan.ciphertexts.length > 1 && (
                    <Notice tone="info">
                        Will send {plan.ciphertexts.length} encrypted copies, one per key kind. Each person reads the copy for their key.
                        {" "}<Button size="min" variant="none" className={cl("link")} onClick={() => setAllowSplit(false)}>undo</Button>
                    </Notice>
                )}
                {plan?.ok && plan.warnings.map(w => (
                    <Notice key={w.code} tone="warn">
                        {w.code === "self-not-post-quantum" && "Your own age key isn't post-quantum, so it's left out of the post-quantum copy (it would undo the protection). You won't be able to read that copy later."}
                        {w.code === "self-cannot-read" && `You don't have a ${KEY_TYPE_LABEL[w.type]} key, so you won't be able to read the ${KEY_TYPE_LABEL[w.type]} copy of your own message later.`}
                        {w.code === "unverified" && `Not verified yet: ${w.userIds.map(userName).join(", ")}. Compare codes to be sure the keys really belong to them.`}
                        {w.code === "pending-key-change" && `${w.userIds.map(userName).join(", ")} posted a new key that you haven't reviewed. Cipher still encrypts to their old key.`}
                    </Notice>
                ))}

                {exposure.map(t => <Notice key={t} tone="warn">{t}</Notice>)}

                <div className={cl("row", "wrap")}>
                    {state.identity.has("age") && <Button size="small" variant="secondary" onClick={() => shareKey("age")}>Share my age key here</Button>}
                    {state.identity.has("pgp") && <Button size="small" variant="secondary" onClick={() => shareKey("pgp")}>Share my PGP key here</Button>}
                    <Button size="small" variant="secondary" onClick={() => openGroupEditor()}>Groups…</Button>
                    <Button size="small" variant="secondary" onClick={() => openKeyManager()}>Keys & contacts…</Button>
                </div>
            </div>
        </Modal>
    );
}

function SelfRow() {
    const pub = state.identity.publicIdentity;
    return (
        <div className={cl("list-row", "self-row")}>
            <Checkbox checked disabled onChange={() => { }}><span className={cl("name")}>You</span></Checkbox>
            {pub.age && <TypeBadge type="age" material={pub.age.recipient} />}
            {pub.pgp && <TypeBadge type="pgp" />}
            {!pub.age && !pub.pgp && <Badge tone="warn">no keys: you can't read your own messages</Badge>}
            <span className={cl("hint")}>always included</span>
        </div>
    );
}

function MixedChoice({ selected, lookup, onRestrict, onSplit }: { selected: string[]; lookup: (id: string) => Candidate | undefined; onRestrict(kept: string[]): void; onSplit(): void; }) {
    const age = restrictToType(selected, lookup, "age");
    const pgp = restrictToType(selected, lookup, "pgp");
    return (
        <Notice tone="warn">
            <div>Your readers use different key types, and one encrypted message can only be age or PGP. Choose:</div>
            <div className={cl("stack-tight")}>
                <Button size="small" variant="secondary" onClick={() => onRestrict(age.kept)}>Only age (removes {age.removed.map(userName).join(", ")})</Button>
                <Button size="small" variant="secondary" onClick={() => onRestrict(pgp.kept)}>Only PGP (removes {pgp.removed.map(userName).join(", ")})</Button>
                <Button size="small" onClick={onSplit}>Send two encrypted copies, one per type</Button>
            </div>
        </Notice>
    );
}

function openModalNotice(text: string) {
    openModal(modal => <Modal {...modal} title="Cipher" actions={[{ text: "OK", variant: "primary", onClick: modal.onClose }]}><div>{text}</div></Modal>);
}

export function openPicker(channel: Channel) {
    state.ensure().then(() => openModal(modal => <Picker modal={modal} channel={channel} />), toastError);
}
