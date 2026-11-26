/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import type { MessageEditListener, MessageSendListener } from "@api/MessageEvents";
import { sendMessage } from "@utils/discord";
import { CloudUpload as TCloudUpload } from "@vencord/discord-types";
import { CloudUploadPlatform } from "@vencord/discord-types/enums";
import { findLazy } from "@webpack";
import { Constants, MessageStore, RestAPI, SnowflakeUtils } from "@webpack/common";

import { buildLinkCiphertexts, buildOutgoing, type EncryptedFile } from "./core/compose";
import { formatLinkMessage, parseContent } from "./core/envelope";
import { CipherError, errorCode, safeMessage } from "./core/errors";
import { inspectKey, KEY_PROBLEM_TEXT, type KeyProblem, type KeyType } from "./core/keys";
import { type CiphertextPlan, describePlanError, planEncryption } from "./core/recipients";
import type { LinkTtl } from "./core/serverApi";
import { deleteLink, serverOrigin, uploadMessage } from "./server";
import { settings } from "./settings";
import { loadCandidates, selfId, state, userName } from "./state";
import { confirmDanger, explain } from "./ui/common";

const CloudUpload: typeof TCloudUpload = findLazy(m => m.prototype?.trackUploadFinished);

const NOT_SENT = "Message not sent";

class Blocked extends Error {
    constructor(readonly title: string, readonly body: string) {
        super(body);
    }
}

function block(body: string, title = NOT_SENT): never {
    throw new Blocked(title, body);
}

/**
 * Vencord ignores errors thrown by send listeners and sends the message
 * anyway, which would leak plaintext. So this wrapper catches everything and
 * cancels the send instead.
 */
export const onBeforeSend: MessageSendListener = async (channelId, message, options, props) => {
    try {
        await handleSend(channelId, message, options, props);
    } catch (e) {
        if (e instanceof Blocked) explain(e.title, e.body);
        else explain(NOT_SENT, `Cipher couldn't encrypt this message, so it was not sent. ${safeMessage(e)}`);
        return { cancel: true };
    }
};

const handleSend: (...a: Parameters<MessageSendListener>) => Promise<void> = async (channelId, message, options, props) => {
    await state.ensure();
    const prefs = state.channels.get(channelId);
    if (prefs.mode === "off") return;

    if (props?.hasAttachments || props?.hasStickers || options?.stickerIds?.length)
        block("Encryption is on in this chat, but Cipher can only encrypt text. Attachments and stickers would be sent unencrypted. Remove them, or turn encryption off for this message.");
    if (!message.content.trim()) block("There's no text to encrypt.");

    const candidates = await loadCandidates(prefs.recipients);
    await assertOwnKeysUsable();
    const plan = planEncryption({
        self: state.identity.selfKeys(selfId()),
        selectedIds: prefs.recipients,
        lookup: id => candidates.get(id),
        allowSplit: prefs.allowSplit
    });
    if (!plan.ok) block(describePlanError(plan.error, userName));

    // GnuPG holds the signing key and asks for its passphrase itself if needed.
    const signFingerprint = settings.store.signPgpMessages && plan.ciphertexts.some(c => c.type === "pgp")
        ? state.identity.publicIdentity.pgp?.fingerprint
        : undefined;

    if (prefs.linkDays && await sendAsLink(message, plan.ciphertexts, signFingerprint, prefs.linkDays)) {
        message.validNonShortcutEmojis = [];
        message.invalidEmojis = [];
        message.tts = false;
        state.channels.consumeOnce(channelId);
        return;
    }

    const out = await buildOutgoing({
        ciphertexts: plan.ciphertexts,
        text: message.content,
        signFingerprint,
        maxMessages: settings.store.maxMessages
    });

    if (out.kind === "messages") {
        // Earlier parts go out first and are awaited; the original send carries
        // the last part. If any earlier part fails, the send is cancelled and
        // the draft (still plaintext, only on this device) stays in the box.
        for (const part of out.messages.slice(0, -1)) {
            try {
                await sendMessage(channelId, { content: part }, true);
            } catch {
                block("Discord refused one of the parts of your encrypted message. Nothing readable was sent; try again.");
            }
        }
        message.content = out.messages[out.messages.length - 1];
    } else {
        try {
            await uploadEncrypted(channelId, out.attachmentContent, out.files);
        } catch {
            block("Uploading the encrypted attachment failed. Nothing readable was sent; your message is still in the chat box.");
        }
        message.content = out.notice;
    }

    // The plaintext's emoji metadata and TTS flag don't belong to the ciphertext.
    message.validNonShortcutEmojis = [];
    message.invalidEmojis = [];
    message.tts = false;
    state.channels.consumeOnce(channelId);
};

/**
 * Disappearing message: the ciphertexts go to the Cipher server and Discord
 * only gets links. Returns false if the user chose to send a normal
 * (permanent) message instead after a failure; never falls back silently.
 */
async function sendAsLink(message: { content: string; }, ciphertexts: CiphertextPlan[], signFingerprint: string | undefined, days: LinkTtl): Promise<boolean> {
    try {
        if (!serverOrigin()) throw new CipherError("internal", "No Cipher server is set up.");
        const cts = await buildLinkCiphertexts({ ciphertexts, text: message.content, signFingerprint });
        const ups: { url: string; id: string; type: KeyType; hash: string; expiresAt: number; }[] = [];
        try {
            for (const c of cts) ups.push({ ...await uploadMessage(c.armored, days), type: c.type });
        } catch (e) {
            // One copy failed: take back the copies already uploaded, so nothing is left behind.
            await Promise.all(ups.map(u => deleteLink(u.id).catch(() => { })));
            throw e;
        }
        message.content = formatLinkMessage(Math.min(...ups.map(u => u.expiresAt)), ups);
        return true;
    } catch (e) {
        if (errorCode(e) === "cancelled") throw e;
        const ok = await confirmDanger(
            "Couldn't send as a disappearing message",
            `${safeMessage(e)} Send it as a normal encrypted message instead? That one won't disappear: it stays in Discord.`,
            "Send normally"
        );
        if (!ok) block("Not sent. Your message is still in the chat box.");
        return false;
    }
}

/** An imported PGP key can expire or be revoked; say so instead of failing obscurely. */
async function assertOwnKeysUsable() {
    const own = state.identity.publicIdentity.pgp?.publicKey;
    if (!own) return;
    let problems: KeyProblem[];
    try {
        problems = (await inspectKey("pgp", own)).problems;
    } catch {
        problems = ["check-failed"];
    }
    if (problems.length)
        block(`Your own PGP key can't be used: ${problems.map(p => KEY_PROBLEM_TEXT[p]).join(" ")} Generate or import a new one in Cipher's settings, then share it.`);
}

function uploadOne(channelId: string, f: EncryptedFile): Promise<TCloudUpload> {
    return new Promise((resolve, reject) => {
        const upload = new CloudUpload({
            file: new File([f.content], f.name, { type: "text/plain" }),
            isThumbnail: false,
            platform: CloudUploadPlatform.WEB
        }, channelId);
        upload.on("complete", () => resolve(upload));
        upload.on("error", () => reject(new Error("upload failed")));
        upload.upload();
    });
}

async function uploadEncrypted(channelId: string, content: string, files: EncryptedFile[]) {
    const uploads = await Promise.all(files.map(f => uploadOne(channelId, f)));
    await RestAPI.post({
        url: Constants.Endpoints.MESSAGES(channelId),
        body: {
            channel_id: channelId,
            content,
            nonce: SnowflakeUtils.fromTimestamp(Date.now()),
            sticker_ids: [],
            type: 0,
            attachments: uploads.map((u, i) => ({ id: String(i), filename: u.filename, uploaded_filename: u.uploadedFilename }))
        }
    });
}

/** Edits are never encrypted, so refuse to edit while encryption is on or an encrypted message is being edited. */
export const onBeforeEdit: MessageEditListener = async (channelId, messageId, message) => {
    try {
        await state.ensure();
        const original = MessageStore.getMessage(channelId, messageId);
        const isCipher = (c?: string) => ["part", "raw", "file-notice", "attachment", "link"].includes(parseContent(c)?.kind ?? "");
        const on = state.channels.get(channelId).mode !== "off";
        if ((on || isCipher(original?.content)) && !isCipher(message.content)) {
            explain("Edit not saved", "Cipher can't encrypt edits, so this edit would be readable by everyone in the chat. Delete the message and send a new encrypted one instead.");
            return { cancel: true };
        }
    } catch {
        explain("Edit not saved", "Cipher couldn't check this edit, so it was cancelled to be safe.");
        return { cancel: true };
    }
};
