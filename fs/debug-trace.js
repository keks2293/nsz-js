// Global "where am I" trace for hang diagnostics. Two slots:
//   merge — the merge consumer's current blocking await (bktr-merge.js,
//           NczStreamSource.read waiting on a range)
//   pump  — the NCZ pump chain's current blocking await (input file read,
//           zstd streaming, AES-CTR decrypt, range fill)
// Each layer writes its slot right before an await; the update-path
// watchdogs print both slots, so a frozen run shows exactly which await
// never resolved. Property writes only — negligible cost on the hot path.
export const trace = { merge: 'idle', pump: 'idle' };

export function markMerge(d) { trace.merge = d; }
export function markPump(d) { trace.pump = d; }