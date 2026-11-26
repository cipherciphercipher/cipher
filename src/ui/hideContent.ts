/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { useEffect } from "@webpack/common";

/**
 * Hides the ciphertext of Cipher messages so the decrypted text (shown by the
 * message accessory) appears in its place. This is display only: Discord's
 * copy of the message is untouched and still holds only ciphertext.
 *
 * Done with one stylesheet keyed on Discord's `message-content-<id>` element
 * IDs (the same IDs Vencord's QuickReply relies on), so no webpack patch is
 * needed and nothing breaks if Discord renames its CSS classes.
 */

const hidden = new Map<string, number>();
let styleEl: HTMLStyleElement | undefined;

const SNOWFLAKE_RE = /^\d{1,25}$/;

function render() {
    if (hidden.size === 0) {
        styleEl?.remove();
        styleEl = undefined;
        return;
    }
    if (!styleEl) {
        styleEl = document.createElement("style");
        styleEl.id = "vc-cipher-hidden-content";
        document.head.appendChild(styleEl);
    }
    styleEl.textContent = [...hidden.keys()].map(id => `#message-content-${id}`).join(",\n") + " { display: none !important; }";
}

/** While `hide` is true, the message's own text is hidden. */
export function useHiddenContent(messageId: string, hide: boolean) {
    useEffect(() => {
        if (!hide || !SNOWFLAKE_RE.test(messageId)) return;
        hidden.set(messageId, (hidden.get(messageId) ?? 0) + 1);
        render();
        return () => {
            const n = (hidden.get(messageId) ?? 1) - 1;
            if (n > 0) hidden.set(messageId, n);
            else hidden.delete(messageId);
            render();
        };
    }, [messageId, hide]);
}

/** Shows every message's text again (plugin stop). */
export function clearHiddenContent() {
    hidden.clear();
    render();
}
