/** Mirror of the server report shape (src/server/crypto/pathbuilder.ts). */

export type AlgorithmPolicy = {
  minRsaBits: number;
  allowSha1: boolean;
};

export type CertView = {
  fingerprint: string;
  subject: string;
  issuer: string;
  serial: string;
  cn: string;
  notBefore: string;
  notAfter: string;
  ski: string | null;
  aki: string | null;
  isCa: boolean;
  pathLen: number | null;
  sigAlg: string;
  sigHash: string | null;
  keyType: 'rsa' | 'ec' | 'unknown';
  subjectKeyType: 'rsa' | 'ec' | 'unknown';
  publicKeyBits: number;
  selfSigned: boolean;
  sources: string[];
  trusted: boolean;
};

export type EdgeCheck = {
  subjectFp: string;
  issuerFp: string;
  nameMatch: boolean;
  akiSki: 'match' | 'subject-no-aki' | 'issuer-no-ski' | 'neither' | 'mismatch';
  signatureVerified: boolean | null;
  usable: boolean;
  reasons: string[];
};

export type CertFailure = {
  code: string;
  message: string;
};

export type PathStatus = 'trusted' | 'invalid' | 'incomplete';

export type PathResult = {
  id: string;
  targetFp: string;
  chain: string[];
  status: PathStatus;
  terminal: 'anchor' | 'self-signed-untrusted' | 'dead-end' | 'cycle-cut';
  anchorFp: string | null;
  edges: EdgeCheck[];
  rejectedEdges: Record<string, EdgeCheck[]>;
  certFailures: Record<string, CertFailure[]>;
  failureCodes: string[];
  score: number;
  scoreBreakdown: {factor: string; points: number}[];
  rank: number;
};

export type ValidationReport = {
  verificationTime: string;
  policy: AlgorithmPolicy;
  policyRevision: number;
  certs: CertView[];
  anchors: CertView[];
  duplicateGroups: {fingerprint: string; sources: string[]}[];
  paths: PathResult[];
  targets: string[];
  enumeratedCap: number;
  truncated: boolean;
};

export type FixturesResponse = {
  certsPem: string;
  anchorsPem: string;
  files: {name: string; pem: string; suggestedTrust: 'anchor' | 'bulk' | 'untrusted'}[];
};
