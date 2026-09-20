import {describe, expect, it} from 'vitest';
import {generateFixtures} from '../src/server/crypto/fixtures';
import {parseCertificate, splitPemDer} from '../src/server/crypto/x509';
import {DEFAULT_POLICY, PoolEntry, validatePaths} from '../src/server/crypto/pathbuilder';

const WHEN = new Date('2026-09-01T12:00:00Z');

type Ingested = {
  pool: Map<string, PoolEntry>;
  anchors: Map<string, PoolEntry>;
  byName: Map<string, ReturnType<typeof parseCertificate>>;
  fixtures: ReturnType<typeof generateFixtures>;
};

function ingest(opts: {trustRootC?: boolean; trustDecoy?: boolean} = {}): Ingested {
  const fixtures = generateFixtures();
  const pool = new Map<string, PoolEntry>();
  const anchors = new Map<string, PoolEntry>();
  const byName = new Map<string, ReturnType<typeof parseCertificate>>();

  const add = (pem: string, source: string, target: Map<string, PoolEntry>, trusted: boolean) => {
    const cert = parseCertificate(splitPemDer(pem)[0]);
    byName.set(cert.commonName, cert);
    const existing = target.get(cert.fingerprint);
    if (existing) existing.sources.add(source);
    else target.set(cert.fingerprint, {cert, sources: new Set([source]), trusted});
  };

  // bulk: anything suggested as anchor goes to anchors, rest to pool
  for (const file of fixtures.files) {
    if (file.trust === 'anchor') add(file.pem, file.name, anchors, true);
    else add(file.pem, file.name, pool, false);
  }
  if (opts.trustRootC) {
    const rootC = fixtures.files.find(f => f.name === 'root-c-untrusted.pem')!;
    add(rootC.pem, rootC.name, anchors, true);
  }
  if (opts.trustDecoy) {
    const decoy = fixtures.files.find(f => f.name === 'root-a-same-name-different-key.pem')!;
    add(decoy.pem, decoy.name, anchors, true);
  }
  return {pool, anchors, byName, fixtures};
}

function reportFor(name: string, ingested: Ingested, policy = DEFAULT_POLICY, when = WHEN) {
  const target = ingested.byName.get(name)!.fingerprint;
  return validatePaths({
    pool: ingested.pool,
    anchors: ingested.anchors,
    verificationTime: when,
    policy,
    policyRevision: 1,
    target,
  });
}

describe('path building', () => {
  it('builds the straightforward trusted chain leaf -> A1 -> Root A', () => {
    const report = reportFor('leaf.example', ingest());
    expect(report.paths.length).toBeGreaterThanOrEqual(2);
    const best = report.paths.find(p => p.rank === 1)!;
    expect(best.status).toBe('trusted');
    expect(best.terminal).toBe('anchor');
    expect(best.chain).toHaveLength(3);
    expect(best.edges).toHaveLength(2);
    expect(best.edges.every(e => e.usable && e.nameMatch && e.signatureVerified === true && e.akiSki === 'match')).toBe(true);
  });

  it('enumerates the cross-signed alternative via Root B and keeps both results', () => {
    const report = reportFor('leaf.example', ingest());
    const chainNames = report.paths.map(p =>
      p.chain.map(fp => report.certs.concat(report.anchors).find(c => c.fingerprint === fp)?.cn)
    );
    // one path ends at Root A, another at Root B (through the cross-signed Root A cert)
    const ends = chainNames.map(names => names[names.length - 1]);
    expect(ends).toContain('Root B');
    expect(ends.filter(n => n === 'Root A').length).toBeGreaterThanOrEqual(1);
    // both complete paths validate; the direct Root A path is ranked first
    const complete = report.paths.filter(p => p.status === 'trusted');
    expect(complete.length).toBeGreaterThanOrEqual(2);
    // both complete paths validate; the direct Root A path is ranked #1
    const rootAFp = report.anchors.find(a => a.cn === 'Root A')!.fingerprint;
    expect(report.paths.find(p => p.rank === 1)!.chain).toContain(rootAFp);
  });

  it('shows the same-name different-key root as a rejected candidate', () => {
    const report = reportFor('leaf.example', ingest());
    // the decoy's source file uniquely distinguishes it from the valid
    // cross-signed "Root A" certificate
    const decoy = report.certs.find(c => c.sources.includes('root-a-same-name-different-key.pem'))!;
    expect(decoy).toBeTruthy();
    const rejectedIssuers = report.paths.flatMap(p =>
      Object.values(p.rejectedEdges).flat().map(e => e.issuerFp)
    );
    expect(rejectedIssuers).toContain(decoy.fingerprint);
    // every rejected edge for the decoy cites the failed signature
    const decoyRejections = report.paths.flatMap(p => Object.values(p.rejectedEdges).flat()).filter(
      e => e.issuerFp === decoy.fingerprint
    );
    expect(decoyRejections.some(e => e.signatureVerified === false)).toBe(true);
  });

  it('flags an expired leaf against the logic time and recovers at an earlier time', () => {
    const ingested = ingest();
    const expired = reportFor('leaf-expired.example', ingested);
    const best = expired.paths.find(p => p.rank === 1)!;
    expect(best.status).toBe('invalid');
    expect(best.certFailures[best.targetFp]?.map(f => f.code)).toContain('expired');

    // move logic time inside the intersection of leaf + issuer validity windows
    const past = reportFor('leaf-expired.example', ingested, DEFAULT_POLICY, new Date('2024-06-01T00:00:00Z'));
    expect(past.paths.find(p => p.rank === 1)!.status).toBe('trusted');
  });

  it('rejects SHA-1 under the default policy and accepts it when policy allows SHA-1', () => {
    const ingested = ingest();
    const strict = reportFor('leaf-sha1.example', ingested);
    expect(strict.paths.find(p => p.rank === 1)!.failureCodes).toContain('sha1_signature');
    const relaxed = reportFor('leaf-sha1.example', ingested, {...DEFAULT_POLICY, allowSha1: true});
    expect(relaxed.paths.find(p => p.rank === 1)!.status).toBe('trusted');
  });

  it('marks the path incomplete when the intermediate issuer is absent', () => {
    const report = reportFor('leaf-missing.example', ingest());
    expect(report.paths).toHaveLength(1);
    const only = report.paths[0];
    expect(only.status).toBe('incomplete');
    expect(only.terminal).toBe('dead-end');
    expect(only.chain).toHaveLength(1);
    // the report still shows why: the leaf expects "Intermediate X"
    expect(report.certs.find(c => c.cn === 'leaf-missing.example')?.issuer).toContain('Intermediate X');
  });

  it('does not trust the untrusted Root C until promoted to an anchor', () => {
    const plain = reportFor('leaf-untrusted.example', ingest());
    const untrustedPath = plain.paths.find(p => p.chain.some(fp => plain.certs.find(c => c.fingerprint === fp)?.cn === 'Root C'))!;
    expect(untrustedPath.status).toBe('incomplete');
    expect(untrustedPath.terminal).toBe('self-signed-untrusted');

    const trusted = reportFor('leaf-untrusted.example', ingest({trustRootC: true}));
    expect(trusted.paths.find(p => p.rank === 1)!.status).toBe('trusted');
  });

  it('deduplicates identical DER certs while retaining all source labels', () => {
    const report = reportFor('leaf.example', ingest());
    const dup = report.duplicateGroups.find(g =>
      report.certs.find(c => c.fingerprint === g.fingerprint)?.cn === 'leaf.example'
    );
    expect(dup).toBeTruthy();
    expect(dup!.sources).toContain('leaf.pem');
    expect(dup!.sources).toContain('leaf-copy-duplicate.pem');
  });

  it('verifies a self-signed anchor cryptographically when it is the target', () => {
    const ingested = ingest();
    // byName is ambiguous for "Root A" (cross-signed + decoy share the name);
    // select the real anchor directly from the anchor pool
    const rootAFp = [...ingested.anchors.entries()].find(
      ([, e]) => e.cert.commonName === 'Root A'
    )![0];
    const report = validatePaths({
      pool: ingested.pool,
      anchors: ingested.anchors,
      verificationTime: WHEN,
      policy: DEFAULT_POLICY,
      policyRevision: 1,
      target: rootAFp,
    });
    const best = report.paths.find(p => p.rank === 1)!;
    expect(best.chain).toEqual([rootAFp]);
    expect(best.status).toBe('trusted');
  });

  it('never produces cycles in enumerated chains', () => {
    const report = reportFor('leaf.example', ingest());
    for (const path of report.paths) {
      expect(new Set(path.chain).size).toBe(path.chain.length);
    }
  });
});
