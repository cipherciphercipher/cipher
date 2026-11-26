/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Locks Cipher when you're away: after the set number of minutes without
 * keyboard or mouse input on this computer, when the screen locks, and after
 * sleep. Locking forgets the unsealed age key and asks gpg-agent to forget
 * your PGP key's passphrase, so the next decryption asks again.
 */

import type { PluginNative } from "@utils/types";

import { pgpEngine } from "./core/pgpCipher";
import { settings } from "./settings";
import { state } from "./state";

type Native = PluginNative<typeof import("./native")>;

const CHECK_EVERY_MS = 15_000;

let timer: ReturnType<typeof setInterval> | undefined;
let lastTick = 0;
let lastInput = Date.now();
const onInput = () => { lastInput = Date.now(); };
const INPUT_EVENTS = ["keydown", "pointerdown", "wheel", "pointermove"] as const;

/** Locks Cipher now and makes GnuPG forget the passphrase. Synchronous up to the GnuPG call, so it's safe right before the plugin stops. */
export async function lockCipher(): Promise<void> {
    if (!state.ready) return;
    const fingerprint = state.identity.publicIdentity.pgp?.fingerprint;
    state.identity.lock();
    if (!fingerprint) return;
    try {
        await pgpEngine().forgetPassphrase(fingerprint);
    } catch {
        // GnuPG missing, or gpg-agent not running: then nothing is remembered.
    }
}

async function idleMs(): Promise<{ idle: number; screenLocked: boolean; }> {
    const native = (globalThis as any).VencordNative?.pluginHelpers?.Cipher as Native | undefined;
    if (native) {
        const r = await native.systemIdle().catch(() => ({ ok: false as const }));
        if (r.ok) return { idle: r.idleSeconds * 1000, screenLocked: r.locked };
    }
    // Discord in a browser: input in this tab only.
    return { idle: Date.now() - lastInput, screenLocked: false };
}

async function check() {
    const now = Date.now();
    // A long gap between checks means the computer was asleep.
    const slept = lastTick !== 0 && now - lastTick > CHECK_EVERY_MS * 4;
    lastTick = now;
    const minutes = settings.store.autoLockMinutes ?? 15;
    if (!minutes || !state.ready || !state.identity.isUnlocked) return;
    const { idle, screenLocked } = await idleMs();
    if (slept || screenLocked || idle >= minutes * 60_000) await lockCipher();
}

export function startAutoLock() {
    stopAutoLock();
    lastTick = Date.now();
    lastInput = Date.now();
    for (const e of INPUT_EVENTS) document.addEventListener(e, onInput, { passive: true, capture: true });
    timer = setInterval(() => void check(), CHECK_EVERY_MS);
}

export function stopAutoLock() {
    if (timer) clearInterval(timer);
    timer = undefined;
    for (const e of INPUT_EVENTS) document.removeEventListener(e, onInput, { capture: true });
}
