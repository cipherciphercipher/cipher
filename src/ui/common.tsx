/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { Button } from "@components/Button";
import { classNameFactory } from "@utils/css";
import { confirmAction } from "@utils/discord";
import type { RenderModalProps } from "@vencord/discord-types";
import { Alerts, Modal, openModal, showToast, useState } from "@webpack/common";
import type { ReactNode } from "react";

import { safeMessage } from "../core/errors";
import { formatFingerprint, keyLabel, type KeyType } from "../core/keys";
import { state } from "../state";

export const cl = classNameFactory("vc-cipher-");

export function LockIcon({ open = false, size = 20, className }: { open?: boolean; size?: number; className?: string; }) {
    return (
        <svg width={size} height={size} viewBox="0 0 24 24" className={className} aria-hidden="true">
            <path fill="currentColor" d={open
                ? "M17 8h-1V6a4 4 0 0 0-7.75-1.4l1.87.7A2 2 0 0 1 14 6v2H7a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V10a2 2 0 0 0-2-2Zm-5 9a2 2 0 1 1 0-4 2 2 0 0 1 0 4Z"
                : "M17 8h-1V6a4 4 0 1 0-8 0v2H7a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V10a2 2 0 0 0-2-2Zm-7-2a2 2 0 1 1 4 0v2h-4V6Zm2 11a2 2 0 1 1 0-4 2 2 0 0 1 0 4Z"} />
        </svg>
    );
}

export type Tone = "good" | "warn" | "bad" | "info" | "muted";

export function Badge({ tone, children, title }: { tone: Tone; children: ReactNode; title?: string; }) {
    return <span className={cl("badge", `badge-${tone}`)} title={title}>{children}</span>;
}

export function TypeBadge({ type, material }: { type: KeyType; material?: string; }) {
    const label = keyLabel(type, material);
    return <Badge tone="info" title={label === "age PQ" ? "Post-quantum age key (ML-KEM-768 + X25519)" : undefined}>{label}</Badge>;
}

export function VerifiedBadge({ verified }: { verified: boolean; }) {
    return verified
        ? <Badge tone="good" title="You compared this key's code with them out of band">✓ verified</Badge>
        : <Badge tone="warn" title="You haven't compared this key's code with them yet">unverified</Badge>;
}

export function Notice({ tone, children }: { tone: Tone; children: ReactNode; }) {
    return <div className={cl("notice", `notice-${tone}`)}>{children}</div>;
}

export function Fingerprint({ fingerprint, code }: { fingerprint: string; code?: string; }) {
    return (
        <div className={cl("fp")}>
            {code && <div><span className={cl("fp-label")}>Code</span> <code className={cl("code")}>{code}</code></div>}
            <div><span className={cl("fp-label")}>Fingerprint</span> <code>{formatFingerprint(fingerprint)}</code></div>
        </div>
    );
}

export function TextField(props: { value: string; onChange(v: string): void; placeholder?: string; password?: boolean; autoFocus?: boolean; onEnter?(): void; }) {
    return (
        <input
            className={cl("input")}
            type={props.password ? "password" : "text"}
            value={props.value}
            placeholder={props.placeholder}
            autoFocus={props.autoFocus}
            autoComplete="off"
            spellCheck={false}
            onChange={e => props.onChange(e.currentTarget.value)}
            onKeyDown={e => {
                if (e.key === "Enter" && props.onEnter) {
                    e.preventDefault();
                    props.onEnter();
                }
            }}
        />
    );
}

export function TextBox(props: { value: string; onChange(v: string): void; placeholder?: string; rows?: number; readOnly?: boolean; }) {
    return (
        <textarea
            className={cl("textarea")}
            rows={props.rows ?? 6}
            value={props.value}
            placeholder={props.placeholder}
            readOnly={props.readOnly}
            spellCheck={false}
            autoComplete="off"
            onChange={e => props.onChange(e.currentTarget.value)}
        />
    );
}

export function Checkbox({ checked, onChange, disabled, children }: { checked: boolean; onChange(v: boolean): void; disabled?: boolean; children: ReactNode; }) {
    return (
        <label className={cl("check", disabled && "check-disabled")}>
            <input type="checkbox" checked={checked} disabled={disabled} onChange={e => onChange(e.currentTarget.checked)} />
            <span>{children}</span>
        </label>
    );
}

export { Button };

export function toastError(err: unknown) {
    showToast({ text: safeMessage(err), variant: "critical" });
}

export function toastOk(text: string) {
    showToast({ text, variant: "success" });
}

/** A blocking explanation. Used whenever a send is refused. */
export function explain(title: string, body: string) {
    Alerts.show({ title, body, confirmText: "OK" });
}

export function confirmDanger(title: string, body: ReactNode, confirmText: string): Promise<boolean> {
    return confirmAction({ title, subtitle: body, confirmText, cancelText: "Cancel", variant: "critical-primary" }).catch(() => false);
}

interface PassphraseOptions {
    title: string;
    subtitle?: ReactNode;
    /** Ask twice, for setting a new passphrase. */
    confirm?: boolean;
    submitText?: string;
    onSubmit(passphrase: string): Promise<void>;
}

function PassphraseModal({ modal, opts, done }: { modal: RenderModalProps; opts: PassphraseOptions; done(ok: boolean): void; }) {
    const [pass, setPass] = useState("");
    const [again, setAgain] = useState("");
    const [error, setError] = useState<string>();
    const [busy, setBusy] = useState(false);

    const submit = async () => {
        if (busy) return;
        if (opts.confirm && pass !== again) return setError("The passphrases don't match.");
        setBusy(true);
        setError(undefined);
        try {
            await opts.onSubmit(pass);
            done(true);
            modal.onClose();
        } catch (e) {
            setError(safeMessage(e));
        } finally {
            setBusy(false);
        }
    };

    return (
        <Modal
            {...modal}
            title={opts.title}
            subtitle={opts.subtitle}
            actions={[{ text: opts.submitText ?? "Unlock", variant: "primary", onClick: submit, loading: busy }]}
        >
            <div className={cl("stack")}>
                <TextField password autoFocus value={pass} onChange={setPass} placeholder="Passphrase" onEnter={opts.confirm ? undefined : submit} />
                {opts.confirm && <TextField password value={again} onChange={setAgain} placeholder="Repeat passphrase" onEnter={submit} />}
                {error && <Notice tone="bad">{error}</Notice>}
            </div>
        </Modal>
    );
}

export function promptPassphrase(opts: PassphraseOptions): Promise<boolean> {
    return new Promise(resolve => {
        let settled = false;
        const done = (ok: boolean) => {
            if (!settled) resolve(ok);
            settled = true;
        };
        openModal(modal => <PassphraseModal modal={modal} opts={opts} done={done} />, { onCloseCallback: () => done(false) });
    });
}

let unlocking: Promise<boolean> | undefined;

/** Makes sure secrets are unlocked, asking for the passphrase once if needed. */
export async function requestUnlock(reason?: string): Promise<boolean> {
    await state.ensure();
    const { identity } = state;
    if (identity.isUnlocked) return true;
    if (!identity.hasAnyKey) {
        explain("No keys yet", "You don't have any Cipher keys. Open Settings → Plugins → Cipher to set up an age key or choose your GnuPG key.");
        return false;
    }
    if (!identity.needsPassphrase) {
        // PGP only: GnuPG asks for its own passphrase when it needs it.
        await identity.unlock();
        return true;
    }
    unlocking ??= promptPassphrase({
        title: "Unlock Cipher",
        subtitle: reason ?? "Enter your Cipher passphrase (it protects your age key). Cipher stays unlocked until you lock it or restart Discord. For PGP, GnuPG asks for your key's passphrase itself.",
        onSubmit: p => identity.unlock(p)
    }).finally(() => unlocking = undefined);
    return unlocking;
}

/**
 * Asks for the passphrase needed to change your keys. On the very first key
 * this sets the passphrase instead.
 */
export function withPassphrase(action: string, run: (passphrase: string) => Promise<void>): Promise<boolean> {
    const first = !state.identity.has("age");
    return promptPassphrase({
        title: first ? "Choose a passphrase" : "Enter your passphrase",
        subtitle: first
            ? "Your age secret key is encrypted with this passphrase on this computer. It can't be recovered if you forget it. Use at least 8 characters; longer is better."
            : `Needed to ${action}.`,
        confirm: first,
        submitText: first ? "Save" : "Continue",
        onSubmit: run
    });
}
