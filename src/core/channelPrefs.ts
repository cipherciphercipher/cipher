/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import type { KV } from "./contacts";

/**
 * off:    messages are sent as normal (the default everywhere).
 * once:   the next message is encrypted, then the chat goes back to off.
 * sticky: every message in this chat is encrypted until turned off.
 *
 * Nothing in Cipher ever turns encryption on except the user choosing once
 * or sticky in the recipient picker.
 */
export type EncryptionMode = "off" | "once" | "sticky";

export interface ChannelState {
    mode: EncryptionMode;
    /** Other readers (you are always included). */
    recipients: string[];
    /** The user agreed to send one age and one PGP ciphertext for a mixed selection. */
    allowSplit: boolean;
    /** Send as a disappearing message on the Cipher server, kept this many days. */
    linkDays?: 1 | 3 | 7;
}

const STORE_KEY = "Cipher_channels_v1";
const OFF: ChannelState = Object.freeze({ mode: "off", recipients: [], allowSplit: false }) as ChannelState;

export class ChannelPrefs {
    /** Persisted: only sticky channels. */
    private sticky = new Map<string, ChannelState>();
    /** In memory only: once-mode channels. */
    private once = new Map<string, ChannelState>();
    private listeners = new Set<() => void>();

    constructor(private kv: KV) { }

    async load() {
        const stored = await this.kv.get<Record<string, ChannelState>>(STORE_KEY);
        this.sticky = new Map(Object.entries(stored ?? {}).filter(([, s]) => s.mode === "sticky"));
        this.emit();
    }

    subscribe(fn: () => void) {
        this.listeners.add(fn);
        return () => void this.listeners.delete(fn);
    }

    private emit() {
        for (const fn of this.listeners) fn();
    }

    private async save() {
        await this.kv.set(STORE_KEY, Object.fromEntries(this.sticky));
        this.emit();
    }

    get(channelId: string): ChannelState {
        return this.once.get(channelId) ?? this.sticky.get(channelId) ?? OFF;
    }

    async set(channelId: string, state: ChannelState) {
        const recipients = [...new Set(state.recipients)];
        this.once.delete(channelId);
        const hadSticky = this.sticky.delete(channelId);
        if (state.mode === "once") {
            this.once.set(channelId, { ...state, recipients });
        } else if (state.mode === "sticky") {
            this.sticky.set(channelId, { ...state, recipients });
        }
        if (state.mode === "sticky" || hadSticky) await this.save();
        else this.emit();
    }

    async turnOff(channelId: string) {
        await this.set(channelId, OFF);
    }

    /** Called after an encrypted message was sent. */
    consumeOnce(channelId: string) {
        if (this.once.delete(channelId)) this.emit();
    }

    // There is deliberately no "forget this recipient everywhere" helper: if a
    // contact is deleted, chats that still list them block the next send and
    // say why, instead of quietly dropping a reader.

    clearSession() {
        this.once.clear();
        this.emit();
    }
}
