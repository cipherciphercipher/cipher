/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * The Discord-window side of the GnuPG bridge: forwards PgpEngine calls to
 * native.ts in Discord's main process. On Discord in a browser there is no
 * main process, so PGP reports "GnuPG not found".
 */

import type { PluginNative } from "@utils/types";

import { type PgpEngine, PgpEngineError } from "./core/pgpEngine";
import type { NativeResult } from "./native";

type Native = PluginNative<typeof import("./native")>;

function native(): Native {
    const n = (globalThis as any).VencordNative?.pluginHelpers?.Cipher as Native | undefined;
    if (!n) throw new PgpEngineError("not-found");
    return n;
}

async function call<T>(fn: (n: Native) => Promise<NativeResult<T>>): Promise<T> {
    const r = await fn(native());
    if (r.ok) return r.value;
    throw new PgpEngineError(r.code);
}

export const gnupgBridge: PgpEngine = {
    available: async () => {
        try {
            return await call(n => n.available());
        } catch {
            return { ok: false, reason: "GnuPG isn't available in this Discord (desktop app only)." };
        }
    },
    inspect: armored => call(n => n.inspect(armored)),
    listSecretKeys: () => call(n => n.listSecretKeys()),
    exportPublicKey: fpr => call(n => n.exportPublicKey(fpr)),
    generateKey: userId => call(n => n.generateKey(userId)),
    importSecretKey: armored => call(n => n.importSecretKey(armored)),
    exportSecretKey: fpr => call(n => n.exportSecretKey(fpr)),
    encrypt: ({ recipientKeys, signFingerprint, data }) => call(n => n.encrypt(recipientKeys, signFingerprint, data)),
    decrypt: ({ armoredMessage, verificationKeys, maxBytes }) => call(n => n.decrypt(armoredMessage, verificationKeys, maxBytes)),
    signProof: (fpr, statement) => call(n => n.signProof(fpr, statement)),
    keyProtection: fpr => call(n => n.keyProtection(fpr)),
    forgetPassphrase: fpr => call(n => n.forgetPassphrase(fpr))
};
