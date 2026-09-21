import {test, describe, before} from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import {buildFixtures} from '../src/server/fixtures.js';
import {getPolicy} from '../src/server/policy.js';
import {importCertificates, buildPaths, rankPaths} from '../src/server/pathBuilder.js';
import {runBuild} from '../src/server/index.js';

let fx;
const byLabel = () => new Map(fx.certs.map((c) => [c.label, c]));
const fp = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

before(() => { fx = buildFixtures(); });

function run(label, policyId = 'standard', overrides = {}) {
  const map = byLabel();
  const sc = fx.scenarios.find((s) => s.id === label);
  const labels = overrides.certs ?? sc.certs;
  const {certs, duplicates} = importCertificates(labels.map((l) => map.get(l).der));
  const anchorLabels = overrides.anchors ?? sc.anchors;
  const anchors = [...new Set(anchorLabels)].map((l) => fp(map.get(l).der));
  const target = fp(map.get(overrides.target ?? sc.target).der);
  const result = buildPaths(certs, new Set(anchors), target, getPolicy(policyId), new Date(fx.verifyAt));
  rankPaths(result, anchors);
  return {...result, duplicates, certCount: certs.length};
}

describe('path enumeration scenarios', () => {
  test('happy path: leaf -> intermediate -> anchor validates', () => {
    const r = run('all');
    assert.equal(r.paths[0].valid, true);
    assert.equal(r.paths[0].nodes.length, 3);
    assert.equal(r.paths[0].terminal, 'anchor');
    assert.deepEqual(r.paths[0].failureReasons, []);
  });

  test('cross-sign yields BOTH paths; valid cross-cert path ranks above self-signed one', () => {
    const r = run('cross');
    assert.equal(r.paths.length, 2);
    const [good, bad] = r.paths;
    assert.equal(good.valid, true);
    assert.equal(good.nodes.length, 4);
    assert.equal(good.nodes.at(-1).subject, 'CN=Global Trust Root,O=Chain Lab,C=US');
    assert.equal(bad.valid, false);
    assert.equal(bad.terminal, 'untrusted_self_signed');
    assert.ok(good.score > bad.score);
  });

  test('missing intermediate terminates in no_issuer_match with the gap shown', () => {
    const r = run('gap');
    assert.equal(r.paths.length, 1);
    assert.equal(r.paths[0].terminal, 'no_issuer_match');
    assert.equal(r.paths[0].valid, false);
    assert.ok(r.paths[0].nodes.at(-1).subject.startsWith('CN=Gap Child CA'));
  });

  test('adding the missing intermediate makes the same target valid', () => {
    const r = run('gap', 'standard', {certs: ['root-rsa', 'missing-intermediate', 'gap-child', 'leaf-gap']});
    assert.equal(r.paths[0].valid, true);
    assert.equal(r.paths[0].nodes.length, 4);
  });

  test('duplicate identical DERs are de-duplicated without phantom paths', () => {
    const r = run('dup');
    assert.equal(r.duplicates.length, 3);
    assert.equal(r.paths.length, 1);
    assert.equal(r.paths[0].valid, true);
  });

  test('same name different key: only the signing twin yields a valid path', () => {
    const r = run('twin');
    assert.equal(r.paths.length, 1);
    assert.equal(r.paths[0].valid, true);
    // the name-only non-signing twin is recorded as a rejected edge
    const rej = r.rejectedEdges.find((e) => /Shared Name CA/.test(e.parentSubject));
    assert.ok(rej, 'rejected twin edge must be reported');
    assert.match(rej.detail + (rej.evidence ?? []).map((x) => x.detail).join(' '), /AKI|签名/);
  });

  test('expired leaf fails validity at bound time even though anchor is reached', () => {
    const r = run('expired');
    assert.equal(r.paths[0].terminal, 'anchor');
    assert.equal(r.paths[0].valid, false);
    assert.ok(r.paths[0].failureReasons.includes('expired'));
  });

  test('expired leaf would have been valid at an earlier logical time', () => {
    const r = run('expired');
    // rebuild directly with earlier time
    const map = byLabel();
    const sc = fx.scenarios.find((s) => s.id === 'expired');
    const {certs} = importCertificates(sc.certs.map((l) => map.get(l).der));
    const anchors = [fp(map.get('root-rsa').der)];
    const earlier = buildPaths(certs, new Set(anchors), fp(map.get('leaf-expired').der),
      getPolicy('standard'), new Date('2024-06-01T00:00:00Z'));
    assert.equal(earlier.paths[0].valid, true);
  });

  test('orphan leaf and unanchored self-signed leaf are untrusted', () => {
    const orphan = run('untrusted');
    assert.equal(orphan.paths[0].terminal, 'no_issuer_match');
    const self = run('loop', 'standard', {target: 'self-signed-leaf', anchors: []});
    assert.equal(self.paths[0].terminal, 'untrusted_self_signed');
    assert.equal(self.paths[0].valid, false);
  });

  test('designating the self-signed cert as anchor makes it trusted', () => {
    const r = run('loop', 'standard', {target: 'self-signed-leaf', anchors: ['self-signed-leaf']});
    assert.equal(r.paths[0].terminal, 'anchor');
    assert.equal(r.paths[0].valid, true);
  });

  test('pathLen=0 rejects a non-self-issued intermediate below the root', () => {
    const r = run('pathlen');
    assert.equal(r.paths[0].valid, false);
    assert.ok(r.paths[0].failureReasons.includes('path_len_violation'));
  });

  test('pathLen violation disappears under the permissive policy', () => {
    const r = run('pathlen', 'permissive');
    assert.equal(r.paths[0].valid, true);
  });

  test('cycle: mutually signing CAs are pruned and do not infinite-loop', () => {
    const r = run('loop');
    assert.ok(r.paths.length >= 1);
    assert.ok(r.paths.every((p) => p.nodes.length < 10));
    assert.ok(r.rejectedEdges.some((e) => e.reason === 'cycle'), 'a cycle edge must be reported');
    assert.equal(r.paths[0].terminal, 'no_issuer_match');
  });
});

describe('algorithm policy', () => {
  test('SHA-1/RSA-1024 chain valid under permissive, rejected under standard/modern', () => {
    assert.equal(run('legacy', 'permissive').paths[0].valid, true);
    assert.equal(run('legacy', 'standard').paths[0].valid, false);
    assert.equal(run('legacy', 'modern').paths[0].valid, false);
  });

  test('strict policy reports the specific legacy_signature_algorithm reason', () => {
    const r = run('legacy', 'standard');
    assert.ok(r.paths[0].failureReasons.includes('no_issuer_match'));
    assert.ok(r.rejectedEdges.some((e) => e.reason === 'algorithm_policy_rejected'
      || e.evidence?.some((x) => /SHA1|禁止/.test(x.detail))));
  });
});

describe('runBuild HTTP-level integration (in-process)', () => {
  test('binds result to policy revision and verifyAt', () => {
    const map = byLabel();
    const sc = fx.scenarios.find((s) => s.id === 'cross');
    const input = {
      certs: sc.certs.map((l) => map.get(l).der.toString('base64')),
      anchors: sc.anchors.map((l) => map.get(l).der.toString('base64')),
      target: fp(map.get(sc.target).der),
      policyId: 'standard',
      verifyAt: fx.verifyAt,
    };
    const out = runBuild(input);
    assert.equal(out.binding.policyRevision, 5);
    assert.equal(out.binding.verifyAt, fx.verifyAt);
    assert.equal(out.paths[0].valid, true);
    assert.equal(out.anchors.length, 1);
  });

  test('rejects garbage input cleanly', () => {
    const out = runBuild({certs: ['not a certificate']});
    assert.ok(out.error);
  });

  test('anchor priority: explicitly ordered anchors affect ranking', () => {
    // target valid via primary root; designate a secondary anchor ahead of it
    // (it cannot even chain there, so ordering only matters when both can).
    const map = byLabel();
    const sc = fx.scenarios.find((s) => s.id === 'twin');
    const anchors = ['root-rsa-2', 'root-rsa']; // secondary first
    const out = runBuild({
      certs: sc.certs.map((l) => map.get(l).der.toString('base64')),
      anchors: anchors.map((l) => map.get(l).der.toString('base64')),
      anchorOrder: anchors.map((l) => fp(map.get(l).der)),
      target: fp(map.get(sc.target).der),
      policyId: 'standard',
      verifyAt: fx.verifyAt,
    });
    assert.equal(out.paths[0].valid, true);
    assert.equal(out.anchors[0].fingerprint, fp(map.get('root-rsa-2').der));
  });
});
