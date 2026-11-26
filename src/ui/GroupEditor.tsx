/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import type { RenderModalProps } from "@vencord/discord-types";
import { Modal, openModal, useState } from "@webpack/common";

import { MAX_GROUP_MEMBERS, type RecipientGroup } from "../core/groups";
import { contactName, state, useCipher, userName } from "../state";
import { Button, Checkbox, cl, confirmDanger, Notice, TextField, toastError, toastOk, TypeBadge } from "./common";
import { openContactDialog } from "./ContactDialog";
import { type DiscordGroup, discordGroups } from "./discordPeople";

function GroupForm({ group, from, onDone }: { group?: RecipientGroup; from?: DiscordGroup; onDone(): void; }) {
    useCipher();
    const [name, setName] = useState(group?.name ?? from?.name ?? "");
    const [members, setMembers] = useState<string[]>(group?.memberIds ?? from?.memberIds.slice(0, MAX_GROUP_MEMBERS) ?? []);
    const contacts = state.contacts.list();
    const full = members.length >= MAX_GROUP_MEMBERS;
    // Members without a saved key (contact deleted, or imported from a group DM)
    // stay visible so they aren't dropped silently.
    const orphans = members.filter(id => !state.contacts.get(id));

    const save = async () => {
        try {
            if (group) await state.groups.update(group.id, name, members);
            else await state.groups.create(name, members);
            toastOk("Group saved");
            onDone();
        } catch (e) {
            toastError(e);
        }
    };

    return (
        <div className={cl("card")}>
            <TextField value={name} onChange={setName} placeholder="Group name, e.g. Close friends" />
            {from && from.memberIds.length > MAX_GROUP_MEMBERS && <Notice tone="warn">{from.name} has {from.memberIds.length} other people; a group holds {MAX_GROUP_MEMBERS}, so the rest weren't added.</Notice>}
            {orphans.length > 0 && <Notice tone="info">People without a saved key are skipped when you use the group, until you add their key.</Notice>}
            <div className={cl("list")}>
                {contacts.map(c => (
                    <div key={c.userId} className={cl("list-row")}>
                        <Checkbox
                            checked={members.includes(c.userId)}
                            disabled={!members.includes(c.userId) && full}
                            onChange={v => setMembers(m => v ? [...m, c.userId] : m.filter(x => x !== c.userId))}
                        >
                            <span className={cl("name")}>{contactName(c)}</span>
                        </Checkbox>
                        <TypeBadge type={c.key.type} material={c.key.material} />
                    </div>
                ))}
                {orphans.map(id => (
                    <div key={id} className={cl("list-row")}>
                        <Checkbox checked onChange={() => setMembers(m => m.filter(x => x !== id))}>
                            <span className={cl("name")}>{userName(id)}</span>
                        </Checkbox>
                        <span className={cl("hint")}>no key saved</span>
                        <Button size="min" variant="none" className={cl("link")} onClick={() => openContactDialog(id)}>add key</Button>
                    </div>
                ))}
            </div>
            {full && <Notice tone="warn">A group can hold {MAX_GROUP_MEMBERS} people; with you that's the limit of {MAX_GROUP_MEMBERS + 1} readers.</Notice>}
            <div className={cl("row")}>
                <Button size="small" onClick={save} disabled={!name.trim()}>Save group</Button>
                <Button size="small" variant="secondary" onClick={onDone}>Cancel</Button>
            </div>
        </div>
    );
}

export function GroupList() {
    useCipher();
    const [editing, setEditing] = useState<string | "new" | "pick-dm" | null>(null);
    const [from, setFrom] = useState<DiscordGroup>();
    if (!state.ready) return null;
    const groups = state.groups.list();
    const done = () => { setEditing(null); setFrom(undefined); };

    const remove = async (g: RecipientGroup) => {
        if (await confirmDanger(`Delete "${g.name}"?`, "This only deletes the group, not the contacts in it.", "Delete"))
            await state.groups.remove(g.id).catch(toastError);
    };

    return (
        <div className={cl("stack")}>
            {groups.length === 0 && editing !== "new" && <div className={cl("hint")}>No groups yet. A group lets you pick several readers in one click.</div>}
            {groups.map(g => editing === g.id
                ? <GroupForm key={g.id} group={g} onDone={() => setEditing(null)} />
                : (
                    <div key={g.id} className={cl("list-row")}>
                        <span className={cl("name")}>{g.name}</span>
                        <span className={cl("hint")}>{g.memberIds.map(userName).join(", ") || "empty"}</span>
                        <Button size="min" variant="secondary" onClick={() => setEditing(g.id)}>Edit</Button>
                        <Button size="min" variant="dangerSecondary" onClick={() => remove(g)}>Delete</Button>
                    </div>
                ))}
            {editing === "new" && <GroupForm key={from?.channelId ?? "new"} from={from} onDone={done} />}
            {editing === "pick-dm" && <GroupDmPicker onPick={g => { setFrom(g); setEditing("new"); }} onCancel={done} />}
            {editing !== "new" && editing !== "pick-dm" && (
                <div className={cl("row")}>
                    <Button size="small" variant="secondary" onClick={() => setEditing("new")}>New group</Button>
                    <Button size="small" variant="secondary" onClick={() => setEditing("pick-dm")}>New group from a group DM</Button>
                </div>
            )}
        </div>
    );
}

function GroupDmPicker({ onPick, onCancel }: { onPick(g: DiscordGroup): void; onCancel(): void; }) {
    const dms = discordGroups();
    return (
        <div className={cl("card")}>
            <b>Pick a group DM</b>
            <div className={cl("list")}>
                {dms.length === 0 && <div className={cl("hint")}>You aren't in any group DMs.</div>}
                {dms.map(g => {
                    const withKey = g.memberIds.filter(id => state.contacts.get(id)).length;
                    return (
                        <button type="button" key={g.channelId} className={cl("list-row", "person")} onClick={() => onPick(g)}>
                            <span className={cl("name")}>{g.name}</span>
                            <span className={cl("hint")}>{g.memberIds.length} {g.memberIds.length === 1 ? "person" : "people"}, {withKey} with a key</span>
                        </button>
                    );
                })}
            </div>
            <div><Button size="small" variant="secondary" onClick={onCancel}>Cancel</Button></div>
        </div>
    );
}

export function openGroupEditor() {
    openModal((modal: RenderModalProps) => (
        <Modal {...modal} size="md" title="Recipient groups" actions={[{ text: "Done", variant: "primary", onClick: modal.onClose }]}>
            <GroupList />
        </Modal>
    ));
}
