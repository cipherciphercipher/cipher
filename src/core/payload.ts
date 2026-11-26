/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * The plaintext that goes inside the ciphertext.
 *
 *   [0xC1 'C' 'P' 0x01] [flags] [body]
 *
 * 0xC1 can never start valid UTF-8, so a payload without the magic is plain
 * UTF-8 text. That keeps messages encrypted by hand with `age -a` or `gpg -a`
 * readable by Cipher. Flag bit 0 means the body is deflate-raw compressed.
 */

import { concatBytes, utf8Decode, utf8Encode } from "./bytes";
import { CipherError } from "./errors";

const MAGIC = [0xC1, 0x43, 0x50, 0x01];
const FLAG_DEFLATE = 1;

/** Upper bound for a decrypted message, to stop decompression bombs. */
export const MAX_PLAINTEXT_BYTES = 256 * 1024;

async function readLimited(stream: ReadableStream<Uint8Array>, limit: number): Promise<Uint8Array> {
    const reader = stream.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.length;
        if (total > limit) {
            await reader.cancel();
            throw new CipherError("too-large");
        }
        chunks.push(value);
    }
    return concatBytes(...chunks);
}

function streamOf(data: Uint8Array): ReadableStream<Uint8Array> {
    return new ReadableStream({
        start(c) {
            c.enqueue(data);
            c.close();
        }
    });
}

export async function deflate(data: Uint8Array): Promise<Uint8Array> {
    return readLimited(streamOf(data).pipeThrough(new CompressionStream("deflate-raw") as unknown as TransformStream<Uint8Array, Uint8Array>), Infinity);
}

export async function inflate(data: Uint8Array, limit = MAX_PLAINTEXT_BYTES): Promise<Uint8Array> {
    try {
        return await readLimited(streamOf(data).pipeThrough(new DecompressionStream("deflate-raw") as unknown as TransformStream<Uint8Array, Uint8Array>), limit);
    } catch (e) {
        if (e instanceof CipherError) throw e;
        throw new CipherError("malformed");
    }
}

export async function encodePayload(text: string, compress: boolean): Promise<Uint8Array> {
    const raw = utf8Encode(text);
    if (raw.length > MAX_PLAINTEXT_BYTES) throw new CipherError("too-large");
    const body = compress ? await deflate(raw) : raw;
    return concatBytes(new Uint8Array(MAGIC), new Uint8Array([compress ? FLAG_DEFLATE : 0]), body);
}

export async function decodePayload(data: Uint8Array): Promise<string> {
    const hasMagic = data.length >= 5 && MAGIC.every((b, i) => data[i] === b);
    if (!hasMagic) {
        if (data.length > MAX_PLAINTEXT_BYTES) throw new CipherError("too-large");
        return utf8Decode(data);
    }
    const flags = data[4];
    if (flags & ~FLAG_DEFLATE) throw new CipherError("malformed");
    const body = data.subarray(5);
    return utf8Decode(flags & FLAG_DEFLATE ? await inflate(body) : body);
}
