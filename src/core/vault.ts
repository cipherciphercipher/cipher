/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * The user's age key at rest.
 *
 * The public half is stored in the clear so the fingerprint can be shown and
 * the key shared while Cipher is locked. The secret half is sealed with age's
 * passphrase mode (scrypt + ChaCha20-Poly1305) and only exists unsealed in
 * memory. PGP secret keys never pass through Cipher: GnuPG keeps them.
 */

import { ageIdentityToRecipient, agePassphraseDecrypt, agePassphraseEncrypt, DEFAULT_SCRYPT_LOG_N } from "./ageCipher";
import { utf8Decode, utf8Encode } from "./bytes";
import { CipherError } from "./errors";

export const MIN_PASSPHRASE_LENGTH = 8;

export interface PublicIdentity {
    age?: { recipient: string; createdAt: number; };
}

export interface SecretBundle {
    age?: { identity: string; };
}

export interface StoredIdentity {
    v: 2;
    public: PublicIdentity;
    /** age-armored, passphrase-encrypted JSON of SecretBundle. */
    sealed: string;
}

export function checkPassphrase(passphrase: string): void {
    if (passphrase.length < MIN_PASSPHRASE_LENGTH) throw new CipherError("weak-passphrase");
}

export async function sealIdentity(pub: PublicIdentity, secrets: SecretBundle, passphrase: string, logN = DEFAULT_SCRYPT_LOG_N): Promise<StoredIdentity> {
    checkPassphrase(passphrase);
    await assertConsistent(pub, secrets);
    const sealed = await agePassphraseEncrypt(utf8Encode(JSON.stringify(secrets)), passphrase, logN);
    return { v: 2, public: pub, sealed };
}

export async function unsealIdentity(stored: StoredIdentity, passphrase: string): Promise<SecretBundle> {
    const plain = await agePassphraseDecrypt(stored.sealed, passphrase);
    let secrets: SecretBundle;
    try {
        secrets = JSON.parse(utf8Decode(plain));
    } catch {
        throw new CipherError("key-mismatch");
    }
    await assertConsistent(stored.public, secrets);
    return secrets;
}

/** Makes sure the stored public key really belongs to the sealed secret key. */
async function assertConsistent(pub: PublicIdentity, secrets: SecretBundle): Promise<void> {
    if (!!pub.age !== !!secrets.age) throw new CipherError("key-mismatch");
    if (pub.age && secrets.age && await ageIdentityToRecipient(secrets.age.identity) !== pub.age.recipient)
        throw new CipherError("key-mismatch");
}
