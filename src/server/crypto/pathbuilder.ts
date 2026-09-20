/**
 * Certification path enumeration, validation and ranking.
 *
 * Pure, in-memory and offline: the only inputs are caller-supplied DER/PEM
 * certificates and trust anchors. Nothing reads the platform trust store or
 * the network.
 */
import {nameContentEquals, ParsedCertificate, verifySignature} from './x509';

export type AlgorithmPolicy = {
  /** Reject any RSA key shorter than this many bits. */
  minRsaBits: number;
  /** Allow SHA-1 signatures (default false). */
  allowSha1: boolean;
};

export const DEFAULT_POLICY: AlgorithmPolicy = {minRsaBits: 2048, allowSha1: false};

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
  /** source labels where this exact DER appeared (duplicates tracked here) */
  sources: string[];
  trusted: boolean;
};

export type EdgeCheck = {
  subjectFp: string;
  issuerFp: string;
  nameMatch: boolean;
  akiSki: 'match' | 'subject-no-aki' | 'issuer-no-ski' | 'neither' | 'mismatch';
  signatureVerified: boolean | null;
  /** candidate actually usable in path enumeration */
  usable: boolean;
  reasons: string[];
};

export type CertFailure = {
  code:
    | 'not_yet_valid'
    | 'expired'
    | 'not_ca'
    | 'no_key_cert_sign'
    | 'path_len_exceeded'
    | 'weak_rsa_key'
    | 'sha1_signature'
    | 'unsupported_signature_algorithm';
  message: string;
};

export type PathStatus = 'trusted' | 'invalid' | 'incomplete';
export type TerminalKind = 'anchor' | 'self-signed-untrusted' | 'dead-end' | 'cycle-cut';

export type PathResult = {
  id: string;
  targetFp: string;
  /** fingerprints leaf -> trust anchor */
  chain: string[];
  status: PathStatus;
  terminal: TerminalKind;
  anchorFp: string | null;
  edges: EdgeCheck[];
  /** rejected issuer candidates, grouped by child cert fingerprint */
  rejectedEdges: Record<string, EdgeCheck[]>;
  certFailures: Record<string, CertFailure[]>;
  failureCodes: string[];
  /** ranking */
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
  /** targets offered by the cert pool (non-CA leaves and self-signed roots) */
  targets: string[];
  enumeratedCap: number;
  truncated: boolean;
};

type PoolEntry = {
  cert: ParsedCertificate;
  sources: Set<string>;
  trusted: boolean;
};

const ENUMERATION_CAP = 200;

export type ValidateInput = {
  /** parsed, deduped pool certs (fingerprint -> entry) */
  pool: Map<string, PoolEntry>;
  anchors: Map<string, PoolEntry>;
  verificationTime: Date;
  policy: AlgorithmPolicy;
  policyRevision: number;
  /** fingerprint in first position; when omitted every plausible target runs */
  target?: string;
};

export type {PoolEntry};

function isCaWithKeyCertSign(entry: PoolEntry): boolean {
  const c = entry.cert;
  if (!c.isCa) return false;
  if (c.keyUsage === null) return true; // extension absent: stay lenient
  // RFC 5280 key usage bit numbering; fixtures encode into one byte:
  // digitalSignature=0x80, keyCertSign=0x04, cRLSign=0x02.
  return (c.keyUsage & 0x04) !== 0;
}

function evaluateEdge(subject: ParsedCertificate, issuer: ParsedCertificate): EdgeCheck {
  const check: EdgeCheck = {
    subjectFp: subject.fingerprint,
    issuerFp: issuer.fingerprint,
    nameMatch: false,
    akiSki: 'neither',
    signatureVerified: null,
    usable: false,
    reasons: [],
  };
  check.nameMatch = nameContentEquals(subject.issuer, issuer.subject);
  if (!check.nameMatch) check.reasons.push('issuer/subject name mismatch');

  if (subject.aki && issuer.ski) {
    check.akiSki = subject.aki === issuer.ski ? 'match' : 'mismatch';
    if (check.akiSki === 'mismatch') check.reasons.push('AKI does not match issuer SKI');
  } else if (subject.aki) {
    check.akiSki = 'issuer-no-ski';
  } else if (issuer.ski) {
    check.akiSki = 'subject-no-aki';
  }

  if (check.nameMatch) {
    try {
      check.signatureVerified = verifySignature(subject, issuer);
    } catch {
      check.signatureVerified = false;
    }
    if (!check.signatureVerified) check.reasons.push('signature does not verify under issuer key');
  }

  check.usable =
    check.nameMatch && check.akiSki !== 'mismatch' && check.signatureVerified === true;
  return check;
}

function certValidityFailures(entry: PoolEntry, when: Date): CertFailure[] {
  const failures: CertFailure[] = [];
  const c = entry.cert;
  if (when < c.notBefore) {
    failures.push({code: 'not_yet_valid', message: `notBefore ${c.notBefore.toISOString()} is after logic time ${when.toISOString()}`});
  }
  if (when > c.notAfter) {
    failures.push({code: 'expired', message: `notAfter ${c.notAfter.toISOString()} is before logic time ${when.toISOString()}`});
  }
  return failures;
}

function policyFailures(entry: PoolEntry, policy: AlgorithmPolicy): CertFailure[] {
  const failures: CertFailure[] = [];
  const c = entry.cert;
  // Policy applies to the certificate's OWN subject key, not to the algorithm
  // its issuer used to sign it (an EC intermediate can be RSA-signed).
  if (c.subjectKeyType === 'rsa' && c.publicKeyBits < policy.minRsaBits) {
    failures.push({
      code: 'weak_rsa_key',
      message: `RSA key ${c.publicKeyBits} bits < policy minimum ${policy.minRsaBits}`,
    });
  }
  if (c.signature.hash === 'sha1' && !policy.allowSha1) {
    failures.push({code: 'sha1_signature', message: 'certificate is signed with SHA-1 (disallowed by policy)'});
  }
  if (c.signature.keyType === 'unknown' || !c.signature.hash) {
    failures.push({code: 'unsupported_signature_algorithm', message: `unsupported signature algorithm ${c.signature.oid}`});
  }
  return failures;
}

export function validatePaths(input: ValidateInput): ValidationReport {
  const {pool, anchors, verificationTime, policy, policyRevision} = input;

  // Unified lookup: every anchor is also a possible chain node.
  const all = new Map<string, PoolEntry>();
  for (const [fp, entry] of pool) all.set(fp, entry);
  for (const [fp, entry] of anchors) all.set(fp, {...entry, trusted: true});
  const anchorFps = new Set(anchors.keys());

  // --- enumerate candidate edges (evidence, including rejected ones) --------
  const outgoing = new Map<string, EdgeCheck[]>();
  const entries = [...all.values()];
  for (const entry of entries) {
    const c = entry.cert;
    const edges: EdgeCheck[] = [];
    for (const candidate of entries) {
      if (nameContentEquals(candidate.cert.subject, c.issuer)) {
        edges.push(evaluateEdge(c, candidate.cert));
      }
    }
    outgoing.set(c.fingerprint, edges);
  }

  // --- targets ---------------------------------------------------------------
  let targets: string[];
  if (input.target && all.has(input.target)) {
    targets = [input.target];
  } else {
    // Anything that is not a CA, plus standalone self-signed certs, is a
    // selectable validation target.
    targets = [...all.values()]
      .filter(entry => !entry.cert.isCa || entry.cert.selfSigned)
      .map(entry => entry.cert.fingerprint);
  }

  const allPaths: PathResult[] = [];
  let truncated = false;

  const makeView = (entry: PoolEntry): CertView => ({
    fingerprint: entry.cert.fingerprint,
    subject: entry.cert.subjectText,
    issuer: entry.cert.issuerText,
    serial: entry.cert.serial,
    cn: entry.cert.commonName,
    notBefore: entry.cert.notBefore.toISOString(),
    notAfter: entry.cert.notAfter.toISOString(),
    ski: entry.cert.ski,
    aki: entry.cert.aki,
    isCa: entry.cert.isCa,
    pathLen: entry.cert.pathLen,
    sigAlg: entry.cert.signature.label,
    sigHash: entry.cert.signature.hash,
    keyType: entry.cert.signature.keyType,
    subjectKeyType: entry.cert.subjectKeyType,
    publicKeyBits: entry.cert.publicKeyBits,
    selfSigned: entry.cert.selfSigned,
    sources: [...entry.sources].sort(),
    trusted: entry.trusted || anchorFps.has(entry.cert.fingerprint),
  });

  for (const targetFp of targets) {
    const start = all.get(targetFp)!;

    // DFS of usable edges; visited fingerprint set prevents loops.
    const dfs = (nodeFp: string, chain: string[], visited: Set<string>) => {
      if (allPaths.length >= ENUMERATION_CAP) {
        truncated = true;
        return;
      }
      const node = all.get(nodeFp)!;
      const nextChain = [...chain, nodeFp];

      // Terminal 1: trust anchor (covers self-signed and pinned intermediates).
      if (anchorFps.has(nodeFp)) {
        allPaths.push(finalizePath(nextChain, targetFp, 'anchor', nodeFp));
        return;
      }

      const usableEdges = (outgoing.get(nodeFp) ?? []).filter(edge => edge.usable);

      // Terminal 2: self-signed but not trusted.
      if (node.cert.selfSigned) {
        allPaths.push(finalizePath(nextChain, targetFp, 'self-signed-untrusted', null));
        return;
      }

      // Terminal 3: dead end (missing intermediate or wrong keys).
      if (usableEdges.length === 0) {
        allPaths.push(finalizePath(nextChain, targetFp, 'dead-end', null));
        return;
      }

      let moved = false;
      for (const edge of usableEdges) {
        if (visited.has(edge.issuerFp)) continue; // cycle cut
        moved = true;
        const nextVisited = new Set(visited);
        nextVisited.add(edge.issuerFp);
        dfs(edge.issuerFp, nextChain, nextVisited);
        if (truncated) return;
      }
      if (!moved) allPaths.push(finalizePath(nextChain, targetFp, 'cycle-cut', null));
    };

    const visited0 = new Set<string>([start.cert.fingerprint]);
    dfs(start.cert.fingerprint, [], visited0);
  }

  function finalizePath(
    chainFps: string[],
    targetFp: string,
    terminal: TerminalKind,
    anchorFp: string | null
  ): PathResult {
    const certFailures: Record<string, CertFailure[]> = {};
    const edges: EdgeCheck[] = [];
    const rejectedEdges: Record<string, EdgeCheck[]> = {};
    const failureCodes = new Set<string>();
    const complete = terminal === 'anchor';

    for (let i = 0; i < chainFps.length; i++) {
      const entry = all.get(chainFps[i])!;
      const failures: CertFailure[] = [];

      // validity & algorithm policy apply to every cert in the path
      failures.push(...certValidityFailures(entry, verificationTime));
      failures.push(...policyFailures(entry, policy));

      const isLast = i === chainFps.length - 1;
      if (i > 0) {
        // Every cert above the leaf is an issuer and must be a CA allowed to
        // sign certificates — intermediate CAs and the anchor alike.
        if (!isCaWithKeyCertSign(entry)) {
          failures.push({
            code: entry.cert.isCa ? 'no_key_cert_sign' : 'not_ca',
            message: entry.cert.isCa
              ? 'issuing certificate is a CA but lacks keyCertSign in key usage'
              : 'issuing certificate lacks the cA basic constraint',
          });
        }
        if (entry.cert.pathLen !== null && i - 1 > entry.cert.pathLen) {
          failures.push({
            code: 'path_len_exceeded',
            message: `pathLenConstraint ${entry.cert.pathLen} exceeded (${i - 1} non-self-issued cert(s) below)`,
          });
        }
      }
      void isLast;

      if (failures.length) {
        certFailures[entry.cert.fingerprint] = failures;
        failures.forEach(f => failureCodes.add(f.code));
      }

      if (i < chainFps.length - 1) {
        const candidates = outgoing.get(chainFps[i]) ?? [];
        const edge = candidates.find(e => e.issuerFp === chainFps[i + 1]);
        if (edge) edges.push(edge);
      }
    }

    // A lone self-signed anchor is its own issuer: record the self-signature
    // check so the UI still shows cryptographic evidence for the single node.
    if (chainFps.length === 1) {
      const only = all.get(chainFps[0])!.cert;
      if (only.selfSigned) {
        const selfEdge = (outgoing.get(only.fingerprint) ?? []).find(e => e.issuerFp === only.fingerprint);
        if (selfEdge) edges.push(selfEdge);
      }
    }

    // rejected candidates for every node in the path: same-name certs whose
    // signature/AKI did not hold (cross-signed / same-name-different-key)
    for (const fp of chainFps) {
      const rejected = (outgoing.get(fp) ?? []).filter(e => !e.usable);
      if (rejected.length) rejectedEdges[fp] = rejected;
    }

    let status: PathStatus;
    if (!complete) status = 'incomplete';
    else if (Object.keys(certFailures).length > 0) status = 'invalid';
    else status = 'trusted';

    const scoreBreakdown = scorePath(chainFps, status);
    return {
      id: `${targetFp.slice(0, 8)}-${chainFps.map(fp => fp.slice(0, 6)).join('>')}`,
      targetFp,
      chain: chainFps,
      status,
      terminal,
      anchorFp,
      edges,
      rejectedEdges,
      certFailures,
      failureCodes: [...failureCodes],
      score: scoreBreakdown.reduce((sum, part) => sum + part.points, 0),
      scoreBreakdown,
      rank: 0,
    };
  }

  function scorePath(chainFps: string[], status: PathStatus) {
    const breakdown: {factor: string; points: number}[] = [];
    // 1. shorter paths win
    breakdown.push({factor: 'path length', points: chainFps.length * 10});
    // 2. algorithm policy penalties
    let weak = 0;
    for (const fp of chainFps) {
      const c = all.get(fp)!.cert;
      if (c.signature.hash === 'sha1') weak += 100;
      if (c.subjectKeyType === 'rsa' && c.publicKeyBits < policy.minRsaBits) weak += 100;
    }
    if (weak) breakdown.push({factor: 'algorithm policy', points: weak});
    // 3. anchor priority = anchor position in the supplied list (first=0)
    const anchorFp = chainFps[chainFps.length - 1];
    const anchorOrder = [...anchors.keys()];
    if (anchorFps.has(anchorFp)) {
      const idx = anchorOrder.indexOf(anchorFp);
      breakdown.push({factor: 'anchor priority', points: (idx === -1 ? anchorOrder.length : idx) * 25});
    } else {
      breakdown.push({factor: 'no trusted anchor', points: 1000});
    }
    // 4. status as tie-breaker (trusted < invalid < incomplete)
    breakdown.push({factor: 'status', points: status === 'trusted' ? 0 : status === 'invalid' ? 500 : 750});
    return breakdown;
  }

  // rank per target, best (lowest) score first — every path is retained.
  for (const targetFp of targets) {
    const group = allPaths
      .filter(p => p.targetFp === targetFp)
      .sort((a, b) => a.score - b.score || a.chain.length - b.chain.length);
    group.forEach((p, i) => (p.rank = i + 1));
  }
  allPaths.sort((a, b) => a.targetFp.localeCompare(b.targetFp) || a.rank - b.rank);

  const certViews = [...pool.values()].map(makeView);
  const anchorViews = [...anchors.values()].map(makeView);
  const duplicateGroups = [...all.values()]
    .filter(entry => entry.sources.size > 1)
    .map(entry => ({fingerprint: entry.cert.fingerprint, sources: [...entry.sources].sort()}));

  return {
    verificationTime: verificationTime.toISOString(),
    policy,
    policyRevision,
    certs: certViews,
    anchors: anchorViews,
    duplicateGroups,
    paths: allPaths,
    targets,
    enumeratedCap: ENUMERATION_CAP,
    truncated,
  };
}
