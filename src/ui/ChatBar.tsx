/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { ChatBarButton, type ChatBarButtonFactory } from "@api/ChatButtons";
import { DraftStore, DraftType, showToast, UserStore, useStateFromStores } from "@webpack/common";

import { selfId, state, useCipher, userName } from "../state";
import { cl, LockIcon } from "./common";
import { describeExposure, exposureFor } from "./exposure";
import { openPicker } from "./RecipientPicker";

/**
 * The lock in the chat bar. While encryption is on it also shows who can
 * read the next message, right next to the text box.
 */
export const CipherChatBarButton: ChatBarButtonFactory = ({ channel, isAnyChat }) => {
    const ready = useCipher();
    const draftLength = useStateFromStores([DraftStore], () => DraftStore.getDraft(channel.id, DraftType.ChannelMessage)?.length ?? 0);
    // Slash commands are run by Discord without going through the send hook,
    // so their text would go out unencrypted.
    const slash = useStateFromStores([DraftStore], () => DraftStore.getDraft(channel.id, DraftType.ChannelMessage)?.trimStart().startsWith("/") ?? false);
    if (!isAnyChat || !ready) return null;

    const prefs = state.channels.get(channel.id);
    const on = prefs.mode !== "off";
    const readers = on ? ["You", ...prefs.recipients.map(userName)] : [];
    const exposure = on ? describeExposure(exposureFor(channel, [selfId(), ...prefs.recipients])) : [];
    const pending = on && prefs.recipients.some(id => state.contacts.get(id)?.pendingKey);
    const missing = on && prefs.recipients.some(id => !state.contacts.get(id));
    // Over Discord's length limit, Discord itself may offer to upload the text
    // as a file before Cipher sees it, and that file would NOT be encrypted.
    const limit = UserStore.getCurrentUser()?.premiumType === 2 ? 4000 : 2000;
    const tooLong = on && draftLength > limit;
    const command = on && slash;
    const warn = exposure.length > 0 || pending || missing;

    const tooltip = !on
        ? "Cipher: encryption is off here. Click to choose readers."
        : [
            ...command ? ["SLASH COMMAND: commands are NOT encrypted. Their text goes out readable by everyone in the chat."] : [],
            ...tooLong ? [`TOO LONG: over ${limit} characters. Shorten it; if Discord offers to send it as a file, that file is NOT encrypted.`] : [],
            `Encrypted ${prefs.mode === "once" ? "(next message only)" : "(on in this chat)"}. Readers: ${readers.join(", ")}.`,
            ...prefs.linkDays ? [`Disappears after ${prefs.linkDays} day${prefs.linkDays > 1 ? "s" : ""} (stored on your Cipher server).`] : [],
            ...exposure,
            ...pending ? ["A reader posted a new key you haven't reviewed."] : [],
            ...missing ? ["A reader has no key saved anymore: sending will be blocked."] : [],
            "Right-click to turn off."
        ].join(" ");

    const label = readers.length > 3 ? `${readers.slice(0, 2).join(", ")} +${readers.length - 2}` : readers.join(", ");

    return (
        <ChatBarButton
            tooltip={tooltip}
            onClick={() => openPicker(channel)}
            onContextMenu={e => {
                if (!on) return;
                e.preventDefault();
                state.channels.turnOff(channel.id).then(
                    () => showToast({ text: "Cipher: encryption off here. Messages are sent in plaintext.", variant: "default" }),
                    () => showToast({ text: "Cipher: couldn't turn encryption off.", variant: "critical" })
                );
            }}
            buttonProps={{ "aria-haspopup": "dialog" }}
        >
            <span className={cl("chatbar", on && "chatbar-on", on && warn && "chatbar-warn", (tooLong || command) && "chatbar-bad")}>
                <LockIcon open={!on || command} />
                {on && <span className={cl("chatbar-readers")}>{command ? "commands aren't encrypted" : tooLong ? `too long (${draftLength}/${limit})` : `${prefs.linkDays ? `⏱${prefs.linkDays}d · ` : ""}${label}`}</span>}
            </span>
        </ChatBarButton>
    );
};
