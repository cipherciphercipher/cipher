/*
 * Cipher, end-to-end encrypted messaging for Vencord
 * Copyright (c) 2026 Cipher contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

export function parseLockfile(text: string): { integrity: Map<string, string>; deps: Map<string, string[]>; };
export function dependencyClosure(text: string, root: string): Record<string, string | null>;
export function compareClosure(expected: Record<string, string | null>, actual: Record<string, string | null>): string[];
