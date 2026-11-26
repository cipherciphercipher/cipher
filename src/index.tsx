/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import "./styles.css";

import type { NavContextMenuPatchCallback } from "@api/ContextMenu";
import definePlugin from "@utils/types";
import type { Message, User } from "@vencord/discord-types";
import { Alerts, Menu, MessageActions } from "@webpack/common";

import { parseContent } from "./core/envelope";
import { CipherError } from "./core/errors";
import { canDeleteLink, deleteLink, serverOrigin, unexpectedKeyChanges } from "./server";

import { lockCipher, startAutoLock, stopAutoLock } from "./autoLock";
import { setPgpEngine } from "./core/pgpCipher";
import { gnupgBridge } from "./gnupgBridge";
import { clearDecryptCache } from "./receive";
import { onBeforeEdit, onBeforeSend } from "./send";
import { settings } from "./settings";
import { selfId, state } from "./state";
import { CipherAccessory, clearFetchedLinks } from "./ui/Accessory";
import { CipherChatBarButton } from "./ui/ChatBar";
import { confirmDanger, LockIcon, toastError } from "./ui/common";
import { ContactBadge, contactProfileBadge } from "./ui/ContactBadge";
import { openContactDialog } from "./ui/ContactDialog";
import { clearHiddenContent } from "./ui/hideContent";
import { openKeyManager } from "./ui/KeyManager";

const userContextPatch: NavContextMenuPatchCallback = (children, { user }: { user?: User; }) => {
    if (!user || user.bot || !state.ready || user.id === selfId()) return;
    const has = !!state.contacts.get(user.id);
    children.push(
        <Menu.MenuItem
            id="vc-cipher-contact"
            label={has ? "Cipher key…" : "Add Cipher key…"}
            action={() => openContactDialog(user.id)}
        />
    );
};

const messageContextPatch: NavContextMenuPatchCallback = (children, { message }: { message?: Message; }) => {
    if (!message || !state.ready || message.author?.id !== selfId()) return;
    const parsed = parseContent(message.content);
    if (parsed?.kind !== "link") return;
    children.push(
        <Menu.MenuItem
            id="vc-cipher-delete-link"
            label="Delete everywhere (Cipher)"
            color="danger"
            action={async () => {
                const ok = await confirmDanger("Delete this disappearing message now?", "Deletes the encrypted copy on the server and the message in Discord.", "Delete");
                if (!ok) return;
                const failed: string[] = [];
                for (const l of parsed.links) {
                    if (!await canDeleteLink(l.id)) { failed.push(l.id); continue; }
                    await deleteLink(l.id).catch(() => failed.push(l.id));
                }
                try {
                    await MessageActions.deleteMessage(message.channel_id, message.id);
                } catch {
                    toastError(new CipherError("internal", "The Discord message couldn't be deleted."));
                }
                if (failed.length) toastError(new CipherError("internal", "The server copy couldn't be deleted from this computer (no delete code); it still disappears when it expires."));
            }}
        />
    );
};

let unsubscribe: (() => void) | undefined;
let warnedKeyChanges = false;

/** Once per session: warns if someone asked the Cipher server to replace or remove your key without proof from it. */
async function warnAboutKeyChanges() {
    if (warnedKeyChanges || !serverOrigin()) return;
    let changes;
    try {
        changes = await unexpectedKeyChanges();
    } catch {
        return;
    }
    if (!changes.length) return;
    warnedKeyChanges = true;
    const what = changes.map(k => `your ${k.type === "age" ? "age" : "PGP"} key (${k.pending!.removal ? "remove it" : "replace it"}, on ${new Date(k.pending!.effectiveAt).toLocaleString()})`).join(" and ");
    Alerts.show({
        title: "⚠ Someone asked to change your Cipher key",
        body: `The Cipher server has a request, made without proof from your key, to change ${what}. It happens then unless you cancel it. If this wasn't you, someone may have access to your Discord account: change your Discord password, log out other devices, then cancel the change in Cipher's settings.`,
        confirmText: "Open Cipher settings",
        cancelText: "Later",
        onConfirm: openKeyManager
    });
}

export default definePlugin({
    name: "Cipher",
    description: "End-to-end encrypted messages with age or OpenPGP (via your GnuPG), in DMs, group DMs and servers. You choose up to 10 readers per message.",
    authors: [{ name: "Cipher contributors", id: 0n }],
    tags: ["Chat", "Privacy"],
    settings,

    start() {
        // PGP is done by the user's installed GnuPG, through native.ts.
        setPgpEngine(gnupgBridge);
        // Any change to keys, contacts or lock state invalidates decrypted results.
        unsubscribe = state.subscribe(clearDecryptCache);
        state.ensure().then(warnAboutKeyChanges, () => { /* not logged in yet; CONNECTION_OPEN retries */ });
        startAutoLock();
    },

    stop() {
        void lockCipher();
        stopAutoLock();
        unsubscribe?.();
        setPgpEngine(undefined);
        state.reset();
        clearDecryptCache();
        clearHiddenContent();
        clearFetchedLinks();
    },

    flux: {
        CONNECTION_OPEN() {
            state.ensure().then(warnAboutKeyChanges, () => { });
        },
        LOGOUT() {
            void lockCipher();
            state.reset();
            clearDecryptCache();
        }
    },

    chatBarButton: {
        icon: LockIcon,
        render: CipherChatBarButton
    },

    onBeforeMessageSend: onBeforeSend,
    onBeforeMessageEdit: onBeforeEdit,

    renderMessageAccessory: props => props.isMessageSnapshot ? null : <CipherAccessory message={props.message} />,

    // A lock next to your contacts' names (messages, member and DM lists, profiles).
    renderMessageDecoration: props => <ContactBadge userId={props.message?.author?.id} />,
    renderMemberListDecorator: ({ user }) => <ContactBadge userId={user?.id} />,
    userProfileBadge: contactProfileBadge,

    contextMenus: {
        "user-context": userContextPatch,
        "message": messageContextPatch
    }
});
