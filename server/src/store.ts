/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * Where disappearing messages live. Two choices:
 *
 *  - D1 (the default, works on Cloudflare's free plan with no card): a
 *    `messages` table, swept every hour, with a cap on the bytes stored so
 *    messages can't fill the database the key directory also lives in. D1's
 *    own point-in-time backups ("Time Travel") keep deleted rows restorable by
 *    the account owner for up to 7 days (free plan).
 *  - R2 (if a MESSAGES bucket is bound): objects deleted by lifecycle rules,
 *    no backups.
 *
 * Either way only the ciphertext, its expiry and a hash of its delete code
 * are stored. Nothing about the sender.
 */

import type { D1Database, R2Bucket } from "./index";

export interface StoredMessage { text: string; expiresAt: number; deleteHash: string; }

export interface MessageStore {
    /** Stores a message; false if the store is full. */
    put(id: string, text: string, expiresAt: number, deleteHash: string): Promise<boolean>;
    get(id: string): Promise<StoredMessage | null>;
    delete(id: string): Promise<void>;
    /** Removes expired messages (the cron job). */
    sweep(now: number): Promise<void>;
}

/** m/<ttl>d/<id without the ttl digit>, matching the bucket's lifecycle rules. */
const r2Key = (id: string) => `m/${id[0]}d/${id.slice(1)}`;

export function r2Store(bucket: R2Bucket): MessageStore {
    return {
        async put(id, text, expiresAt, deleteHash) {
            await bucket.put(r2Key(id), text, {
                customMetadata: { e: String(expiresAt), d: deleteHash },
                httpMetadata: { contentType: "text/plain; charset=utf-8" }
            });
            return true;
        },
        async get(id) {
            const o = await bucket.get(r2Key(id));
            if (!o) return null;
            return { text: await o.text(), expiresAt: Number(o.customMetadata?.e), deleteHash: o.customMetadata?.d ?? "" };
        },
        async delete(id) {
            await bucket.delete(r2Key(id));
        },
        // R2's lifecycle rules delete expired objects.
        async sweep() { }
    };
}

export function d1Store(db: D1Database, maxBytes: number): MessageStore {
    return {
        async put(id, text, expiresAt, deleteHash) {
            const used = await db.prepare("SELECT bytes FROM stored_bytes WHERE k = 1").first<{ bytes: number; }>();
            if ((used?.bytes ?? 0) + text.length > maxBytes) return false;
            await db.prepare("INSERT INTO messages (id, body, expires_at, delete_hash) VALUES (?1, ?2, ?3, ?4)").bind(id, text, expiresAt, deleteHash).run();
            await db.prepare("INSERT INTO stored_bytes (k, bytes) VALUES (1, ?1) ON CONFLICT(k) DO UPDATE SET bytes = bytes + ?1").bind(text.length).run();
            return true;
        },
        async get(id) {
            const r = await db.prepare("SELECT body, expires_at, delete_hash FROM messages WHERE id = ?1").bind(id)
                .first<{ body: string; expires_at: number; delete_hash: string; }>();
            return r ? { text: r.body, expiresAt: r.expires_at, deleteHash: r.delete_hash } : null;
        },
        async delete(id) {
            const r = await db.prepare("DELETE FROM messages WHERE id = ?1 RETURNING length(body) AS n").bind(id).first<{ n: number; }>();
            if (r) await db.prepare("UPDATE stored_bytes SET bytes = max(0, bytes - ?1) WHERE k = 1").bind(r.n).run();
        },
        async sweep(now) {
            await db.prepare("DELETE FROM messages WHERE expires_at <= ?1").bind(now).run();
            // Recount, so the total never drifts.
            await db.prepare("INSERT INTO stored_bytes (k, bytes) VALUES (1, (SELECT coalesce(sum(length(body)), 0) FROM messages)) " +
                "ON CONFLICT(k) DO UPDATE SET bytes = excluded.bytes").run();
        }
    };
}
