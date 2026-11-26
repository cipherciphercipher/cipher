/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * A small lock next to the names of people whose Cipher key you have saved:
 * green when you've compared codes with them, grey when not yet, red when
 * they posted a different key. Only you see it (it's drawn by your Cipher),
 * and it comes from your own contact list: nothing is looked up anywhere, so
 * no server learns whose names you're looking at.
 */

import type { ProfileBadge } from "@api/Badges";
import { BadgePosition } from "@api/Badges";
import { Tooltip } from "@webpack/common";

import { settings } from "../settings";
import { selfId, state, useCipher } from "../state";
import { cl, LockIcon } from "./common";
import { openContactDialog } from "./ContactDialog";

type BadgeKind = "verified" | "unverified" | "changed";

function kindOf(userId: string): BadgeKind | null {
    if (!state.ready || !settings.store.showContactBadges || userId === selfId()) return null;
    const c = state.contacts.get(userId);
    if (!c) return null;
    if (c.pendingKey) return "changed";
    return c.verified ? "verified" : "unverified";
}

const TEXT: Record<BadgeKind, string> = {
    verified: "Cipher contact: you compared codes with them",
    unverified: "Cipher contact: codes not compared yet",
    changed: "Cipher contact posted a DIFFERENT key. Click to check it."
};

export function ContactBadge({ userId, size = 14 }: { userId: string | undefined; size?: number; }) {
    useCipher();
    const kind = userId ? kindOf(userId) : null;
    if (!kind || !userId) return null;
    return (
        <Tooltip text={TEXT[kind]}>
            {(props: any) => (
                <span
                    {...props}
                    className={cl("contact-badge", `contact-badge-${kind}`)}
                    role="img"
                    aria-label={TEXT[kind]}
                    onClick={e => { e.stopPropagation(); openContactDialog(userId); }}
                >
                    <LockIcon size={size} />
                </span>
            )}
        </Tooltip>
    );
}

/** The same lock among the badges in someone's profile. */
export const contactProfileBadge: ProfileBadge = {
    id: "vc-cipher-contact",
    key: "vc-cipher-contact",
    position: BadgePosition.END,
    shouldShow: ({ userId }) => kindOf(userId) !== null,
    component: ({ userId }) => <ContactBadge userId={userId} size={18} />
};
