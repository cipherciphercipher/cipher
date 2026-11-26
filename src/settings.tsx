/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { definePluginSettings } from "@api/Settings";
import { OptionType } from "@utils/types";

import { DEFAULT_MAX_MESSAGES } from "./core/compose";
import { KeyManager } from "./ui/KeyManager";

export const settings = definePluginSettings({
    keys: {
        type: OptionType.COMPONENT,
        component: () => <KeyManager />
    },
    autoLockMinutes: {
        type: OptionType.SLIDER,
        description: "Lock Cipher after this many minutes without keyboard or mouse use on this computer, and whenever the screen locks or the computer sleeps (0 = never). Locking forgets your unlocked age key and makes GnuPG forget your PGP passphrase.",
        markers: [0, 5, 15, 30, 60, 240],
        stickToMarkers: true,
        default: 15
    },
    serverUrl: {
        type: OptionType.STRING,
        description: "Cipher server address (optional), e.g. https://cipher.example.com. Enables the key directory and disappearing messages. Leave empty to keep everything in Discord.",
        default: ""
    },
    hideCiphertext: {
        type: OptionType.BOOLEAN,
        description: "Show decrypted messages in place of the encrypted text (green, with a lock). Each message has a \"Show encrypted text\" link. Display only: Discord still stores just the ciphertext.",
        default: true
    },
    signPgpMessages: {
        type: OptionType.BOOLEAN,
        description: "Sign outgoing PGP messages with your GnuPG key so recipients can check they came from you (GnuPG may ask for the key's passphrase). age has no signatures.",
        default: true
    },
    maxMessages: {
        type: OptionType.SLIDER,
        description: "Longest split: an encrypted message that needs more chat messages than this is sent as an attachment instead.",
        markers: [1, 2, 3, 4, 5, 6, 8, 10],
        stickToMarkers: true,
        default: DEFAULT_MAX_MESSAGES
    }
});
