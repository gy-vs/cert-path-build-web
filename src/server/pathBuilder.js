// Path enumeration + validation engine.
//
// The workspace is a directed multigraph: each certificate is a node; an edge
// child -> candidate parent exists when name/AKI/SKI evidence links them and
// the cryptographic signature is checked. Traversal is DFS from the target
// upward, recording BOTH successful continuations and rejected alternatives
// (with evidence), until it reaches a trust anchor or a terminal failure.
// Every found path is validated independently; sorting only reorders — losing
// candidates are always retained.

import crypto from 'node:crypto';
import {parseCertificate, verifySignature} from '../shared/x509.js';

export const TERMINAL = {
  ANCHOR: 'anchor',
  UNTRUSTED_SELF_SIGNED: 'untrusted_self_signed',
  NO_ISSUER_MATCH: 'no_issuer_match',
  LOOP: 'loop',
  MAX_DEPTH: 'max_depth',
};

export const MAX_PATH_DEPTH = 10;
export const MAX_PATHS = 64;

/** Parse + de-duplicate a list of DER buffers (fingerprint identity). */
export function importCertificates(derList) {
  const seen = new Map();
  const duplicates = [];
  for (const der of derList) {
    let cert;
    try {
      cert = parseCertificate(der);
    } catch (e) {
      return {error: 'parse_failed', detail: String(e?.message ?? e)};
    }
    if (seen.has(cert.fingerprint256)) {
      duplicates.push(cert.fingerprint256);
      continue;
    }
    cert.uid = 'c' + seen.size;
    seen.set(cert.fingerprint256, cert);
  }
  return {certs: [...seen.values()], duplicates};
}

function subjectKey(cert) {
  return cert.ski ? `ski:${cert.ski}` : `dn:${cert.subjectCanonical}`;
}

/**
 * Build adjacency evidence from child to every plausible issuer certificate.
 * Matching stages, all recorded:
 *   1. issuer/subject DN equality
 *   2. AKI/SKI agreement (hard constraint under strict policy, hint otherwise)
 *   3. signature verification (the decisive cryptographic test)
 */
export function candidateParents(child, certs, policy, anchorsByFp) {
  const accepted = [];
  const rejected = [];

  for (const parent of certs) {
    if (parent.fingerprint256 === child.fingerprint256) continue; // never a self-edge here
    const evidence = [];

    // ---- stage 1: name ----
    const nameMatch = child.issuerCanonical === parent.subjectCanonical;
    const dnBytesEqual = child.issuerDer.equals(parent.subjectDer);
    if (!nameMatch) continue; // name mismatch isn't even a candidate edge
    evidence.push({
      check: 'name',
      ok: true,
      detail: dnBytesEqual
        ? `issuer DN 与 subject DN 字节一致：${parent.subject}`
        : `issuer/subject 规范化名称一致（DER 编码不同）：${parent.subject}`,
    });

    // ---- stage 2: AKI/SKI ----
    let akiStatus = 'not_present';
    if (child.aki && parent.ski) {
      akiStatus = child.aki === parent.ski ? 'match' : 'mismatch';
      evidence.push({
        check: 'aki_ski',
        ok: akiStatus === 'match',
        detail: akiStatus === 'match'
          ? `AKI ${child.aki.slice(0, 12)}… = SKI ${parent.ski.slice(0, 12)}…`
          : `AKI ${child.aki.slice(0, 12)}… ≠ SKI ${parent.ski.slice(0, 12)}…（同名但密钥不对应）`,
      });
    } else {
      evidence.push({
        check: 'aki_ski',
        ok: true,
        severity: child.aki || parent.ski ? 'warning' : 'info',
        detail: child.aki
          ? '叶子携带 AKI，但候选父证书无 SKI 扩展（按名称+签名继续）'
          : '证书未携带 AKI，按主体名称匹配（RFC 5280 允许的降级路径）',
      });
    }

    // ---- stage 3: signature ----
    const sv = verifySignature(child, parent);
    if (!sv.ok) {
      rejected.push({
        parentFp: parent.fingerprint256,
        parentSubject: parent.subject,
        reason: sv.reason === 'signature_key_type_mismatch' ? 'signature_key_type_mismatch'
          : sv.reason === 'signature_algorithm_unsupported' ? 'signature_algorithm_unsupported'
          : 'signature_invalid',
        detail: sv.detail ?? '签名值无法用候选父证书公钥验证通过',
        evidence,
        akiStatus,
      });
      continue;
    }
    evidence.push({check: 'signature', ok: true, detail: `用 ${parent.subject} 的公钥验签通过（${child.sigAlg.label}）`});

    // ---- stage 4: algorithm policy on the child's signature ----
    const algoChecks = algorithmChecks(child, parent, policy);
    evidence.push(...algoChecks.evidence);

    accepted.push({
      parentFp: parent.fingerprint256,
      parentSubject: parent.subject,
      akiStatus,
      evidence,
      errors: algoChecks.errors,
      warnings: algoChecks.warnings,
    });
  }

  return {accepted, rejected};
}

function algorithmChecks(child, parent, policy) {
  const evidence = [];
  const errors = [];
  const warnings = [];

  const legacy = Boolean(child.sigAlg.legacy);
  if (legacy && !policy.allowSha1) {
    errors.push('legacy_signature_algorithm');
    evidence.push({check: 'signature_algorithm_policy', ok: false,
      detail: `${child.sigAlg.label} 已被策略 rev ${policy.revision} 禁止`});
  } else if (legacy) {
    warnings.push('legacy_signature_algorithm');
    evidence.push({check: 'signature_algorithm_policy', ok: true, severity: 'warning',
      detail: `${child.sigAlg.label} 在宽松策略 rev ${policy.revision} 下暂时允许`});
  } else {
    evidence.push({check: 'signature_algorithm_policy', ok: true, detail: `${child.sigAlg.label} 符合策略`});
  }

  const strength = parent.publicKey.strength ?? 0;
  if (parent.publicKey.keyType === 'rsa' && strength < policy.minRsa) {
    errors.push('weak_issuer_key');
    evidence.push({check: 'issuer_key_strength', ok: false,
      detail: `签发者 RSA 密钥 ${strength} 位 < 策略要求 ${policy.minRsa} 位`});
  } else if (parent.publicKey.keyType === 'ec' && strength < policy.minEc) {
    errors.push('weak_issuer_key');
    evidence.push({check: 'issuer_key_strength', ok: false,
      detail: `签发者 EC 密钥 ${strength} 位 < 策略要求 ${policy.minEc} 位`});
  } else {
    evidence.push({check: 'issuer_key_strength', ok: true,
      detail: `签发者 ${parent.publicKey.keyType.toUpperCase()} ${strength} 位满足强度下限`});
  }
  return {evidence, errors, warnings};
}

/**
 * Node-level checks (validity window, CA bit, key usage).
 * The end-entity target is not expected to be a CA; CA-ness is only evaluated
 * for nodes that issue the certificate below them. Anchors are warned on
 * validity, never failed.
 */
function nodeChecks(cert, policy, {isAnchor, isEndEntity, verifyAt}) {
  const checks = [];
  const errors = [];
  const warnings = [];

  const time = verifyAt.getTime();
  if (time < cert.notBefore.getTime()) {
    (isAnchor ? warnings : errors).push('not_yet_valid');
    checks.push({check: 'validity', ok: isAnchor, severity: isAnchor ? 'warning' : 'error',
      detail: `notBefore ${cert.notBefore.toISOString()} 晚于校验时间 ${verifyAt.toISOString()}` +
        (isAnchor ? '（锚证书：仅警告）' : '')});
  } else if (time > cert.notAfter.getTime()) {
    (isAnchor ? warnings : errors).push('expired');
    checks.push({check: 'validity', ok: isAnchor, severity: isAnchor ? 'warning' : 'error',
      detail: `notAfter ${cert.notAfter.toISOString()} 早于校验时间 ${verifyAt.toISOString()}` +
        (isAnchor ? '（锚证书：仅警告）' : '')});
  } else {
    checks.push({check: 'validity', ok: true,
      detail: `校验时间 ${verifyAt.toISOString()} 位于有效期 [${cert.notBefore.toISOString()}, ${cert.notAfter.toISOString()}] 内`});
  }

  if (!isAnchor && !isEndEntity) {
    if (policy.requireCaBasicConstraints) {
      if (!cert.hasBasicConstraints) {
        errors.push('missing_basic_constraints');
        checks.push({check: 'basic_constraints', ok: false, detail: '非锚证书缺少 basicConstraints 扩展，不能作为 CA 签发下级'});
      } else if (!cert.isCa) {
        errors.push('not_a_ca');
        checks.push({check: 'basic_constraints', ok: false, detail: 'basicConstraints.cA=false，却在路径中承担签发角色'});
      } else {
        checks.push({check: 'basic_constraints', ok: true, detail: cert.pathLenConstraint !== null
          ? `cA=true，pathLenConstraint=${cert.pathLenConstraint}` : 'cA=true，未设置 pathLenConstraint'});
      }
    } else if (cert.hasBasicConstraints) {
      checks.push({check: 'basic_constraints', ok: true, severity: 'info',
        detail: `cA=${cert.isCa}（宽松策略不强制）`});
    }

    if (policy.requireKeyUsage) {
      if (!cert.keyUsage) {
        errors.push('missing_key_usage');
        checks.push({check: 'key_usage', ok: false, detail: '强化策略要求 keyUsage 扩展'});
      } else if (!cert.keyUsage.includes('keyCertSign')) {
        errors.push('no_key_cert_sign');
        checks.push({check: 'key_usage', ok: false, detail: 'keyUsage 未包含 keyCertSign'});
      } else {
        checks.push({check: 'key_usage', ok: true, detail: `keyUsage=${cert.keyUsage.join(',')}`});
      }
    }
  } else if (isAnchor) {
    checks.push({check: 'trust_anchor', ok: true, detail: `命中受信锚：${cert.subject}`});
  } else {
    // end-entity target: CA bit is not required, but record what it carries
    checks.push({check: 'end_entity', ok: true,
      detail: cert.hasBasicConstraints
        ? `末端实体证书；basicConstraints cA=${cert.isCa}（不作为 CA 使用）`
        : '末端实体证书；无 basicConstraints（符合终端证书形态）'});
  }

  return {checks, errors, warnings};
}

/**
 * Enumerate all plausible paths from `targetFp` up to trust anchors.
 *
 * @param {Array} certs parsed certificates
 * @param {Set<string>} anchorFps fingerprints designated as trust anchors
 * @param {string} targetFp starting certificate fingerprint
 * @param {object} policy resolved policy object
 * @param {Date} verifyAt validation instant
 */
export function buildPaths(certs, anchorFps, targetFp, policy, verifyAt) {
  const byFp = new Map(certs.map((c) => [c.fingerprint256, c]));
  const target = byFp.get(targetFp);
  if (!target) return {error: 'target_not_found'};

  const paths = [];
  const diagnosticEdges = [];
  const edgeCache = new Map(); // childFp -> {accepted,rejected}
  let pathSeq = 0;

  const edgesFor = (child) => {
    if (!edgeCache.has(child.fingerprint256)) {
      edgeCache.set(child.fingerprint256, candidateParents(child, certs, policy, anchorFps));
    }
    return edgeCache.get(child.fingerprint256);
  };

  // DFS state: chain of nodes (target first). A "continuation" is chosen parent.
  const dfs = (chain) => {
    if (paths.length >= MAX_PATHS) return;
    const current = chain[chain.length - 1].cert;
    const visited = new Set(chain.map((n) => n.cert.fingerprint256));

    // Target itself can be a trust anchor / self-signed.
    if (anchorFps.has(current.fingerprint256)) {
      paths.push(finalize(chain, TERMINAL.ANCHOR, policy, verifyAt, anchorFps, pathSeq++));
      return;
    }

    // Self-issued cert not in the anchor store closes without trust.
    if (current.selfIssued) {
      // Detect literal self-signature: signature over itself validates.
      const selfSig = verifySignature(current, current);
      paths.push(finalize(chain,
        selfSig.ok ? TERMINAL.UNTRUSTED_SELF_SIGNED : TERMINAL.NO_ISSUER_MATCH,
        policy, verifyAt, anchorFps, pathSeq++,
        selfSig.ok ? {selfSigned: true} : undefined));
      return;
    }

    if (chain.length >= MAX_PATH_DEPTH) {
      paths.push(finalize(chain, TERMINAL.MAX_DEPTH, policy, verifyAt, anchorFps, pathSeq++));
      return;
    }

    const {accepted, rejected} = edgesFor(current);

    // AKI hard mismatch edges are still carried (they validated by name/sig in
    // accepted); but a name match whose AKI disagrees is by definition never
    // signature-valid, so it lives in `rejected` already.
    const continuations = accepted.filter((e) => !(e.akiStatus === 'mismatch' && policy.akiMismatchIsError)
      && e.errors.length === 0);
    const blockedEdges = accepted.filter((e) => !continuations.includes(e));

    for (const edge of rejected) {
      diagnosticEdges.push({
        childFp: current.fingerprint256, childSubject: current.subject,
        ...edge,
      });
    }
    for (const edge of blockedEdges) {
      diagnosticEdges.push({
        childFp: current.fingerprint256, childSubject: current.subject,
        parentFp: edge.parentFp, parentSubject: edge.parentSubject,
        reason: edge.akiStatus === 'mismatch' && policy.akiMismatchIsError
          ? 'aki_ski_mismatch' : 'algorithm_policy_rejected',
        detail: edge.akiStatus === 'mismatch'
          ? 'AKI/SKI 不一致：候选父证书主体名相同但持有不同密钥'
          : edge.errors.join(', '),
        evidence: edge.evidence,
        akiStatus: edge.akiStatus,
      });
    }

    // Cycle pruning on otherwise-valid continuations.
    const nonCycle = [];
    for (const edge of continuations) {
      if (visited.has(edge.parentFp)) {
        diagnosticEdges.push({
          childFp: current.fingerprint256, childSubject: current.subject,
          parentFp: edge.parentFp, parentSubject: edge.parentSubject,
          reason: 'cycle', detail: `继续向上会再次经过 ${edge.parentSubject}（已在路径中），剪枝防止环路`,
          evidence: edge.evidence, akiStatus: edge.akiStatus,
        });
      } else {
        nonCycle.push(edge);
      }
    }

    if (nonCycle.length === 0) {
      paths.push(finalize(chain, TERMINAL.NO_ISSUER_MATCH, policy, verifyAt, anchorFps, pathSeq++,
        {rejectedCount: rejected.length + blockedEdges.length}));
      return;
    }

    for (const edge of nonCycle) {
      const parentCert = byFp.get(edge.parentFp);
      dfs([...chain, {cert: parentCert, edge}]);
    }
  };

  dfs([{cert: target, edge: null}]);

  // Ranking is finalized by rankPaths(), which knows the anchor order.
  return {
    targetFp,
    paths,
    rejectedEdges: dedupeEdges(diagnosticEdges),
    policyRevision: policy.revision,
    policyId: policy.id,
    verifyAt: verifyAt.toISOString(),
  };
}

function dedupeEdges(edges) {
  const seen = new Set();
  const out = [];
  for (const e of edges) {
    const k = `${e.childFp}|${e.parentFp}|${e.reason}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(e);
  }
  return out;
}

/**
 * Produce the validated candidate path object: per-node checks, per-edge
 * evidence, pathLen evaluation and final status.
 */
function finalize(chain, terminal, policy, verifyAt, anchorFps, idx, extra = {}) {
  const nodes = [];
  const edges = [];
  let valid = terminal === TERMINAL.ANCHOR;
  const failureReasons = new Set();

  for (let i = 0; i < chain.length; i++) {
    const {cert, edge} = chain[i];
    const isAnchor = i === chain.length - 1 && terminal === TERMINAL.ANCHOR;
    const isEndEntity = i === 0; // DFS chain starts at the target end-entity
    const nc = nodeChecks(cert, policy, {isAnchor, isEndEntity, verifyAt});
    if (!isAnchor) nc.errors.forEach((e) => failureReasons.add(e));
    nodes.push({
      fp: cert.fingerprint256,
      subject: cert.subject,
      issuer: cert.issuer,
      isCa: cert.isCa,
      selfIssued: cert.selfIssued,
      isAnchor,
      notBefore: cert.notBefore.toISOString(),
      notAfter: cert.notAfter.toISOString(),
      ski: cert.ski,
      aki: cert.aki,
      sigAlg: cert.sigAlg.label,
      keyInfo: {type: cert.publicKey.keyType, strength: cert.publicKey.strength, curve: cert.publicKey.curve},
      serial: cert.serialNumber,
      checks: nc.checks,
      errors: nc.errors,
      warnings: nc.warnings,
    });
    if (nc.errors.length) valid = false;

    if (edge) {
      // algorithm policy errors carried on the chosen edge
      edge.errors.forEach((e) => failureReasons.add(e));
      if (edge.errors.length) valid = false;
      edges.push({
        fromFp: chain[i - 1].cert.fingerprint256,
        toFp: cert.fingerprint256,
        fromSubject: chain[i - 1].cert.subject,
        toSubject: cert.subject,
        evidence: edge.evidence,
        errors: edge.errors,
        akiStatus: edge.akiStatus,
      });
    }
  }

  // ---- pathLen constraints (RFC 5280 4.2.1.9) ----
  // Evaluate every CA node that declares a constraint against the number of
  // non-self-issued intermediate CAs below it (end-entity leaf not counted).
  if (policy.enforcePathLen && terminal === TERMINAL.ANCHOR) {
    const rawCa = [...chain].reverse(); // anchor first
    for (let i = 0; i < rawCa.length; i++) {
      const c = rawCa[i].cert;
      if (c.pathLenConstraint === null) continue;
      // number of non-self-issued intermediate CAs strictly below `c`
      let intermedsBelow = 0;
      for (let j = i + 1; j < rawCa.length - 1; j++) {
        const below = rawCa[j].cert;
        if (!below.selfIssued) intermedsBelow++;
      }
      const edgeIdx = rawCa.length - 1 - i; // edge index on the child->... direction
      if (intermedsBelow > c.pathLenConstraint) {
        valid = false;
        failureReasons.add('path_len_violation');
        const targetEdge = edges[Math.min(edgeIdx, edges.length - 1)] ?? edges[edges.length - 1];
        const check = {
          check: 'path_len',
          ok: false,
          detail: `${c.subject} 的 pathLenConstraint=${c.pathLenConstraint}，但其下存在 ${intermedsBelow} 张非自签发中间 CA`,
        };
        if (targetEdge) targetEdge.evidence.push(check);
      } else {
        const targetEdge = edges[Math.min(edgeIdx, edges.length - 1)];
        if (targetEdge) targetEdge.evidence.push({
          check: 'path_len', ok: true,
          detail: `${c.subject} pathLenConstraint=${c.pathLenConstraint} ≥ 其下 ${intermedsBelow} 张中间 CA`,
        });
      }
    }
  }

  if (terminal !== TERMINAL.ANCHOR) failureReasons.add(terminal);

  const terminalLabels = {
    [TERMINAL.ANCHOR]: '到达受信锚',
    [TERMINAL.UNTRUSTED_SELF_SIGNED]: '自签名但不在信任锚列表',
    [TERMINAL.NO_ISSUER_MATCH]: '没有可继续的签发者（名称/AKI/签名均无有效连接）',
    [TERMINAL.LOOP]: '检测到签发环',
    [TERMINAL.MAX_DEPTH]: '达到最大路径深度',
  };

  return {
    idx,
    valid,
    status: valid ? 'valid' : terminal === TERMINAL.ANCHOR ? 'invalid' : 'untrusted',
    terminal,
    terminalLabel: terminalLabels[terminal],
    nodes,
    edges,
    failureReasons: [...failureReasons],
    anchorFp: terminal === TERMINAL.ANCHOR ? chain[chain.length - 1].cert.fingerprint256 : null,
    anchorPriority: null, // filled by scoring stage
    ...extra,
  };
}

/**
 * Candidate ranking. Valid paths beat others; among valid paths earlier anchors
 * (user priority) win, then shorter chains, then stronger/modern algorithms.
 * Losing candidates are never removed — only reordered.
 */
function scorePath(path, anchorOrder) {
  let s = 0;
  if (path.valid) s += 1000;
  else if (path.terminal === TERMINAL.ANCHOR) s += 300; // reaches anchor but fails checks
  if (path.anchorFp && anchorOrder.has(path.anchorFp)) {
    s += (10 - Math.min(anchorOrder.get(path.anchorFp), 10)) * 20;
  }
  s -= (path.nodes.length - 1) * 10; // prefer shorter
  for (const n of path.nodes) {
    if (/SHA1/i.test(n.sigAlg)) s -= 25;
    if (n.keyInfo.type === 'rsa' && n.keyInfo.strength <= 1024) s -= 25;
  }
  return s;
}

/** Attach anchor ordering priority, score and rank. */
export function rankPaths(result, anchorOrderedFps) {
  const order = new Map(anchorOrderedFps.map((fp, i) => [fp, i]));
  for (const p of result.paths) {
    p.anchorPriority = p.anchorFp && order.has(p.anchorFp) ? order.get(p.anchorFp) : null;
    p.score = scorePath(p, order);
  }
  result.paths.sort((a, b) => b.score - a.score || a.nodes.length - b.nodes.length || a.idx - b.idx);
  return result;
}

/** Project a parsed cert into the JSON-safe shape returned by /parse and /build. */
export function certView(cert, {isAnchor = false} = {}) {
  return {
    fingerprint: cert.fingerprint256,
    subject: cert.subject,
    issuer: cert.issuer,
    subjectCanonical: cert.subjectCanonical,
    issuerCanonical: cert.issuerCanonical,
    serial: cert.serialNumber,
    version: cert.version,
    notBefore: cert.notBefore.toISOString(),
    notAfter: cert.notAfter.toISOString(),
    isCa: cert.isCa,
    selfIssued: cert.selfIssued,
    ski: cert.ski,
    aki: cert.aki,
    sigAlg: cert.sigAlg.label,
    sigAlgLegacy: Boolean(cert.sigAlg.legacy),
    key: {
      type: cert.publicKey.keyType,
      strength: cert.publicKey.strength,
      curve: cert.publicKey.curve,
      spkiSha256: cert.publicKey.spkiSha256,
    },
    pathLenConstraint: cert.pathLenConstraint,
    keyUsage: cert.keyUsage,
    isAnchor,
  };
}
