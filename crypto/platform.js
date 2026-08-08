// Single source of truth for runtime platform detection.
// zstd and ncz dispatch on this instead of each re-detecting `process`.
export const isNode = typeof process !== 'undefined' && process.versions?.node;