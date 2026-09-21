// Validation policies with explicit revisions. Every build result is bound to
// the policy revision and verification instant it was computed under; the UI
// marks older results stale when either changes.

export const POLICIES = [
  {
    id: 'permissive',
    revision: 2,
    label: '宽松兼容（rev 2 · 2019）',
    allowSha1: true,
    minRsa: 1024,
    minEc: 256,
    requireCaBasicConstraints: false,
    enforcePathLen: false,
    requireKeyUsage: false,
    akiMismatchIsError: false,
    description: '接受 SHA-1 与 RSA-1024；不强制 basicConstraints/CA 位与 pathLen；AKI 不匹配仅提示。',
  },
  {
    id: 'standard',
    revision: 5,
    label: '标准基线（rev 5 · 2024，默认）',
    allowSha1: false,
    minRsa: 2048,
    minEc: 256,
    requireCaBasicConstraints: true,
    enforcePathLen: true,
    requireKeyUsage: false,
    akiMismatchIsError: true,
    description: '禁止 SHA-1；RSA≥2048；签发者必须为 CA（basicConstraints）；强制 pathLen；AKI 不一致即失败。',
  },
  {
    id: 'modern',
    revision: 8,
    label: '现代强化（rev 8 · 2026）',
    allowSha1: false,
    minRsa: 2048,
    minEc: 256,
    requireCaBasicConstraints: true,
    enforcePathLen: true,
    requireKeyUsage: true,
    akiMismatchIsError: true,
    requireKeyIdentifiers: true,
    description: '在标准基线之上要求 CA 证书具备 keyCertSign 且 SKI/AKI 齐全。',
  },
];

export const DEFAULT_POLICY_ID = 'standard';

export function getPolicy(id = DEFAULT_POLICY_ID) {
  return POLICIES.find((p) => p.id === id) ?? POLICIES.find((p) => p.id === DEFAULT_POLICY_ID);
}

export function policySummary(policy) {
  return {
    id: policy.id,
    revision: policy.revision,
    label: policy.label,
    description: policy.description,
    rules: {
      allowSha1: policy.allowSha1,
      minRsa: policy.minRsa,
      minEc: policy.minEc,
      requireCaBasicConstraints: policy.requireCaBasicConstraints,
      enforcePathLen: policy.enforcePathLen,
      requireKeyUsage: policy.requireKeyUsage,
      akiMismatchIsError: policy.akiMismatchIsError,
      requireKeyIdentifiers: Boolean(policy.requireKeyIdentifiers),
    },
  };
}
