// Fixture bundle: a small offline PKI minted at process start. It deliberately
// includes every ambiguous situation the path builder must reason about:
// cross-signs, same-name/different-key CAs, gaps, duplicates, expiry, weak
// algorithms, pathLen violations, loops and unknown anchors.

import {generateKeyPair, issueCertificate} from './certBuilder.js';

const T = {
  longBefore: new Date('2020-01-01T00:00:00Z'),
  start: new Date('2024-01-01T00:00:00Z'),
  expired: new Date('2025-01-01T00:00:00Z'),
  // validation instant used by the workbench
  verifyAt: new Date('2026-09-20T12:00:00Z'),
  end: new Date('2030-12-31T00:00:00Z'),
};

function byName(certs) {
  return Object.fromEntries(certs.map((c) => [c.label, c]));
}

/**
 * Build (and cache for process lifetime) the whole fixture set.
 * @returns {Promise<object>|object} scenarios + flat certificate list
 */
export function buildFixtures() {
  // ---- keys (RSA 2048 for roots, EC P-256 for most intermediates/leaves) ----
  const keys = {
    rootRsa: generateKeyPair('rsa'),
    root2Rsa: generateKeyPair('rsa'),
    legacyRsa1024: generateKeyPair('rsa', {modulusLength: 1024}),
    intA: generateKeyPair('ec'),
    intB: generateKeyPair('ec'),
    crossOld: generateKeyPair('ec'),
    gap: generateKeyPair('ec'),
    gapChild: generateKeyPair('ec'),
    twinA: generateKeyPair('ec'),
    twinB: generateKeyPair('ec'),
    loopA: generateKeyPair('ec'),
    loopB: generateKeyPair('ec'),
    loopLeaf: generateKeyPair('ec'),
    leaf: generateKeyPair('ec'),
    leafCross: generateKeyPair('ec'),
    leafExpired: generateKeyPair('ec'),
    leafLegacy: generateKeyPair('ec'),
    leafGap: generateKeyPair('ec'),
    leafTwin: generateKeyPair('ec'),
    leafOrphan: generateKeyPair('ec'),
    leafPathlen: generateKeyPair('ec'),
    intPathlen: generateKeyPair('ec'),
    rootPathlen: generateKeyPair('ec'),
    soloRoot: generateKeyPair('ec'),
    selfSigned: generateKeyPair('ec'),
  };

  const certs = [];
  const add = (label, role, desc, opts) => {
    const minted = issueCertificate(opts);
    certs.push({
      label, role, description: desc,
      der: minted.der,
      // hints surfaced for scenario selection / anchor defaults
      defaultAnchor: Boolean(opts._anchor),
      tags: opts._tags ?? [],
    });
    return minted;
  };

  // ---------- main hierarchy ----------
  const rootRsa = add('root-rsa', 'root', '受信根 CA（RSA 2048，主锚）', {
    subject: 'Global Trust Root', keyPair: keys.rootRsa, issuer: null,
    ca: true, pathLen: 3, keyUsage: 'ca', _anchor: true,
  });
  const root2 = add('root-rsa-2', 'root', '备用受信根 CA（锚优先级靠后）', {
    subject: 'Secondary Trust Root', keyPair: keys.root2Rsa, issuer: null,
    ca: true, pathLen: 3, keyUsage: 'ca', _anchor: true,
  });

  // ---------- cross-sign story ----------
  // "Old Cross Root" exists as two certs with the SAME subject & key:
  //   1) self-signed (a trust anchor candidate, not enabled by default)
  //   2) cross-certified by Global Trust Root -> chain reaches the main anchor
  const crossOldSelf = add('cross-root-self', 'cross-root',
    '"Old Cross Root" 自签名证书（可作为独立锚，但默认不受信）', {
      subject: 'Old Cross Root', keyPair: keys.crossOld, issuer: null,
      ca: true, pathLen: 2, keyUsage: 'ca',
    });
  const crossOldByRoot = add('cross-root-xcert', 'cross-root',
    '"Old Cross Root" 被 Global Trust Root 交叉签名（同主体同密钥的第二张证书）', {
      subject: 'Old Cross Root', keyPair: keys.crossOld,
      issuer: {name: 'Global Trust Root', keyPair: keys.rootRsa},
      ca: true, pathLen: 1, keyUsage: 'ca',
    });
  // intermediate issued by the old root; chains via BOTH versions of its issuer
  const intA = add('intermediate-a', 'intermediate',
    '由 Old Cross Root 签发：既可走交叉证书到主根，也可终止于其自签名根', {
      subject: 'Intermediate A', keyPair: keys.intA,
      issuer: {name: 'Old Cross Root', keyPair: keys.crossOld},
      ca: true, pathLen: 0, keyUsage: 'ca',
    });
  const leafCross = add('leaf-cross', 'leaf',
    '挂在 Intermediate A 下，用于观察两条可行路径', {
      subject: 'cross.example', keyPair: keys.leafCross,
      issuer: {name: 'Intermediate A', keyPair: keys.intA},
      ca: false, keyUsage: 'leaf', sigAlg: 'sha256:ec',
      _tags: ['cross'],
    });

  // ---------- plain main branch ----------
  const intB = add('intermediate-b', 'intermediate', '主根签发的中间 CA B', {
    subject: 'Intermediate B', keyPair: keys.intB,
    issuer: {name: 'Global Trust Root', keyPair: keys.rootRsa},
    ca: true, pathLen: 0, keyUsage: 'ca',
  });
  const leaf = add('leaf-ok', 'leaf', '正常终端证书 leaf.example', {
    subject: 'leaf.example', keyPair: keys.leaf,
    issuer: {name: 'Intermediate B', keyPair: keys.intB},
    ca: false, keyUsage: 'leaf', sigAlg: 'sha256:ec',
  });

  // ---------- missing intermediate ----------
  const gap = add('missing-intermediate', 'intermediate',
    '缺失的中间 CA：不放入工作区时，下层证书无法到达根（用于缺中间证书场景）', {
      subject: 'Missing Intermediate', keyPair: keys.gap,
      issuer: {name: 'Global Trust Root', keyPair: keys.rootRsa},
      ca: true, pathLen: 1, keyUsage: 'ca',
    });
  const gapChild = add('gap-child', 'intermediate', '由缺失中间 CA 签发的下层 CA', {
    subject: 'Gap Child CA', keyPair: keys.gapChild,
    issuer: {name: 'Missing Intermediate', keyPair: keys.gap},
    ca: true, pathLen: 0, keyUsage: 'ca',
  });
  const leafGap = add('leaf-gap', 'leaf', '叶子：需要工作区里缺失的 Missing Intermediate', {
    subject: 'gap.example', keyPair: keys.leafGap,
    issuer: {name: 'Gap Child CA', keyPair: keys.gapChild},
    ca: false, keyUsage: 'leaf', sigAlg: 'sha256:ec',
    _tags: ['gap'],
  });

  // ---------- same subject, different keys ----------
  add('twin-a', 'intermediate', '"Shared Name CA" 实例 A（密钥 A，主根签发）', {
    subject: 'Shared Name CA', keyPair: keys.twinA,
    issuer: {name: 'Global Trust Root', keyPair: keys.rootRsa},
    ca: true, pathLen: 0, keyUsage: 'ca',
  });
  add('twin-b', 'intermediate', '"Shared Name CA" 实例 B（不同密钥，备用根签发）', {
    subject: 'Shared Name CA', keyPair: keys.twinB,
    issuer: {name: 'Secondary Trust Root', keyPair: keys.root2Rsa},
    ca: true, pathLen: 0, keyUsage: 'ca',
  });
  add('leaf-twin', 'leaf', '叶子：主体名匹配两张同名 CA，但只有一张能验签', {
    subject: 'twin.example', keyPair: keys.leafTwin,
    issuer: {name: 'Shared Name CA', keyPair: keys.twinA}, // signed by A only
    ca: false, keyUsage: 'leaf', sigAlg: 'sha256:ec',
    _tags: ['twin'],
  });

  // ---------- expiry ----------
  const leafExpired = add('leaf-expired', 'leaf', '过期叶子（2025-01-01 到期，校验时间为 2026-09）', {
    subject: 'expired.example', keyPair: keys.leafExpired,
    issuer: {name: 'Intermediate B', keyPair: keys.intB},
    ca: false, keyUsage: 'leaf', sigAlg: 'sha256:ec',
    notBefore: T.start, notAfter: T.expired,
    _tags: ['expired'],
  });

  // ---------- weak algorithms ----------
  // Legacy root: RSA-1024, self-signed with SHA-1
  const legacy = add('legacy-root', 'root',
    '遗留根：RSA-1024 + SHA1WithRSA 自签名（宽松策略下可接受）', {
      subject: 'Legacy 1024 Root', keyPair: keys.legacyRsa1024, issuer: null,
      ca: true, pathLen: 2, keyUsage: 'ca', sigAlg: 'sha1:rsa',
      _tags: ['legacy'],
    });
  add('leaf-legacy', 'leaf',
    '遗留叶子：RSA-1024 根路径上的 SHA-1 签名（策略敏感性演示）', {
      subject: 'legacy.example', keyPair: keys.leafLegacy,
      issuer: {name: 'Legacy 1024 Root', keyPair: keys.legacyRsa1024},
      ca: false, keyUsage: 'leaf', sigAlg: 'sha1:rsa',
      _tags: ['legacy'],
    });

  // ---------- untrusted / unknown anchor ----------
  add('solo-root', 'root', '未知自签名根（不在锚列表中，不被信任）', {
    subject: 'Unknown Solo Root', keyPair: keys.soloRoot, issuer: null,
    ca: true, pathLen: 2, keyUsage: 'ca',
  });
  add('leaf-orphan', 'leaf', '孤儿叶子：由一张工作区里不存在的 CA 签发', {
    subject: 'orphan.example', keyPair: keys.leafOrphan,
    issuer: {name: 'Vanished Issuer CA', keyPair: keys.leafOrphan}, // key never appears elsewhere
    ca: false, keyUsage: 'leaf', sigAlg: 'sha256:ec',
    _tags: ['untrusted'],
  });

  // ---------- self-signed leaf ----------
  add('self-signed-leaf', 'leaf',
    '自签名终端证书（非锚）：名字与签名都闭合，但不会被当作信任锚', {
      subject: 'Self Signed Service', keyPair: keys.selfSigned, issuer: null,
      ca: false, includeBC: true,
      _tags: ['selfsigned'],
    });

  // ---------- pathLen violation ----------
  // root pathLen=0 -> any non-self-issued intermediate below must fail
  add('pathlen-root', 'root', 'pathLenConstraint=0 的根（其下不允许再有非自签发中间 CA）', {
    subject: 'Strict PathLen Root', keyPair: keys.rootPathlen, issuer: null,
    ca: true, pathLen: 0, keyUsage: 'ca', _anchor: true,
  });
  add('pathlen-intermediate', 'intermediate', '严格根签发的中间 CA（会违反根的 pathLen=0）', {
    subject: 'Too Deep Intermediate', keyPair: keys.intPathlen,
    issuer: {name: 'Strict PathLen Root', keyPair: keys.rootPathlen},
    ca: true, pathLen: 0, keyUsage: 'ca', _tags: ['pathlen'],
  });
  add('leaf-pathlen', 'leaf', '叶子：位于过深的中间 CA 之下', {
    subject: 'pathlen.example', keyPair: keys.leafPathlen,
    issuer: {name: 'Too Deep Intermediate', keyPair: keys.intPathlen},
    ca: false, keyUsage: 'leaf', sigAlg: 'sha256:ec', _tags: ['pathlen'],
  });

  // ---------- loop: two CAs signing each other (real cryptographic cycle) ----------
  // Loop CA A is signed by Loop CA B and vice versa; both signatures validate,
  // so only the cycle detector (visited fingerprints) can stop the traversal.
  // Both omit AKI to also exercise name-only + signature matching.
  add('loop-b', 'intermediate', '环 B：由环 A 的密钥签发', {
    subject: 'Loop CA B', keyPair: keys.loopB,
    issuer: {name: 'Loop CA A', keyPair: keys.loopA},
    ca: true, pathLen: 0, keyUsage: 'ca',
    includeAki: false, _tags: ['loop'],
  });
  add('loop-a', 'intermediate', '环 A：由环 B 的密钥签发（A↔B 构成真环）', {
    subject: 'Loop CA A', keyPair: keys.loopA,
    issuer: {name: 'Loop CA B', keyPair: keys.loopB},
    ca: true, pathLen: 0, keyUsage: 'ca',
    includeAki: false, _tags: ['loop'],
  });
  add('leaf-loop', 'leaf', '叶子：挂在环 A 下，枚举必须在 A↔B 环路上终止', {
    subject: 'loop.example', keyPair: keys.loopLeaf,
    issuer: {name: 'Loop CA A', keyPair: keys.loopA},
    ca: false, keyUsage: 'leaf', sigAlg: 'sha256:ec',
    includeAki: false, _tags: ['loop'],
  });

  const all = certs;
  const defaultAnchors = certs.filter((c) => c.defaultAnchor).map((c) => c.label);

  const scenario = (id, title, desc, certLabels, target, anchorLabels) => ({
    id, title, description: desc,
    certs: certLabels,
    target,
    anchors: anchorLabels ?? defaultAnchors,
  });

  const scenarios = [
    scenario('all', '全量工作台', '载入全部夹具证书与全部受信锚，可自由切换目标',
      all.map((c) => c.label), 'leaf-ok'),
    scenario('cross', '交叉签名 / 多路径',
      'Intermediate A 同时存在「主根交叉签名」与「自签名旧根」两条路径，候选排序保留全部结果',
      ['root-rsa', 'cross-root-self', 'cross-root-xcert', 'intermediate-a', 'leaf-cross'],
      'leaf-cross', ['root-rsa']),
    scenario('gap', '缺少中间证书',
      '从工作区移除 Missing Intermediate，链路在缺口处终止并给出失败约束',
      ['root-rsa', 'gap-child', 'leaf-gap'],
      'leaf-gap', ['root-rsa']),
    scenario('dup', '重复证书（同一张 DER 多次导入）',
      '同一 DER 重复出现时去重，且路径枚举不会因副本产生伪路径',
      ['root-rsa', 'root-rsa', 'intermediate-b', 'intermediate-b', 'leaf-ok', 'leaf-ok'],
      'leaf-ok', ['root-rsa']),
    scenario('twin', '同名不同密钥',
      'Shared Name CA 有两张同主体名、不同密钥的证书；仅签名证据能区分真伪',
      ['root-rsa', 'root-rsa-2', 'twin-a', 'twin-b', 'leaf-twin'],
      'leaf-twin', ['root-rsa', 'root-rsa-2']),
    scenario('expired', '过期证书',
      'expired.example 在 2025 年到期；绑定校验时间 2026-09-20 后路径因时间约束失败',
      ['root-rsa', 'intermediate-b', 'leaf-expired'],
      'leaf-expired', ['root-rsa']),
    scenario('untrusted', '不受信锚 / 孤儿证书',
      '自签名叶子与孤儿叶子均无法到达任何受信锚',
      ['self-signed-leaf', 'solo-root', 'leaf-orphan'],
      'leaf-orphan', ['root-rsa']),
    scenario('legacy', '算法策略：SHA-1 / RSA-1024',
      '切换严格/宽松策略后，旧结果标记过期并重新枚举',
      ['legacy-root', 'leaf-legacy'],
      'leaf-legacy', ['legacy-root']),
    scenario('pathlen', 'pathLenConstraint 冲突',
      '严格根 pathLen=0，其下再放一张非自签发中间 CA 即违反约束',
      ['pathlen-root', 'pathlen-intermediate', 'leaf-pathlen'],
      'leaf-pathlen', ['pathlen-root']),
    scenario('loop', '签发环与自引用防御',
      'A↔B 两张 CA 互签构成真环，自签名叶子则自行闭合；构建器必须检出环并终止该分支',
      ['self-signed-leaf', 'loop-a', 'loop-b', 'leaf-loop'],
      'leaf-loop', ['root-rsa']),
  ];

  return {
    certs: all,
    scenarios,
    verifyAt: T.verifyAt.toISOString(),
    defaults: {anchors: defaultAnchors},
    _byLabel: byName(all),
  };
}
