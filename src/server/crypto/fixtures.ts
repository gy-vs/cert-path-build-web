/**
 * Built-in fixture certificates, generated entirely in memory.
 *
 * Scenario map (all dates are fixed; verification runs against an adjustable
 * logic time, defaulting to 2026-09-01 so the expired leaf visibly fails):
 *
 *   Root A (RSA, trusted)
 *     └─ Intermediate A1 (EC P-256)
 *          └─ leaf.example            (valid leaf, chains to Root A)
 *          └─ leaf-expired.example    (expired 2025)
 *          └─ leaf-sha1.example       (SHA-1 signature, algorithm policy fails)
 *   Root B (RSA, trusted, lower priority)
 *     └─ Cross Root A-by-B  ("CN=Root A" but Root B's signature, different key)
 *        └─ (same Intermediate A1 AKI/SKI link) alternative trusted path
 *   Same Name CA (self-signed, same CN "Root A" but different key; NOT trusted)
 *   Orphan Intermediate X ("CN=Intermediate X") with leaf-missing.example —
 *        no issuer certificate anywhere (missing intermediate scenario)
 *   Untrusted Root C (self-signed) -> leaf-untrusted.example
 */
import {KeyObject} from 'node:crypto';
import {mintCert, mintChild, mintRoot} from './certgen';

export type FixtureLabel = {
  label: string;
  fileName: string;
  role: 'anchor' | 'cert' | 'untrusted-anchor' | 'decoys';
};

export type GeneratedFixture = {
  label: string;
  fileName: string;
  pem: string;
  trust: 'anchor' | 'bulk';
};

const PEM_CERT_HEADER = '-----BEGIN CERTIFICATE-----';
const PEM_CERT_FOOTER = '-----END CERTIFICATE-----';

function derToPem(der: Buffer): string {
  const b64 = der.toString('base64');
  const lines = b64.match(/.{1,64}/g)!.join('\n');
  return `${PEM_CERT_HEADER}\n${lines}\n${PEM_CERT_FOOTER}\n`;
}

export type FixtureBundle = {
  /** bulk cert PEM bundle (paste/upload as the cert set) */
  certsPem: string;
  /** trusted anchor PEM bundle (Root A + Root B) */
  anchorsPem: string;
  /** extra anchors available but disabled by default */
  untrustedPem: string;
  /** individual files for selective UI loading */
  files: {name: string; pem: string; trust: 'anchor' | 'bulk' | 'untrusted'}[];
  keys: {
    rootA: KeyObject;
    rootB: KeyObject;
    rootC: KeyObject;
  };
};

export function generateFixtures(): FixtureBundle {
  const files: FixtureBundle['files'] = [];
  const add = (name: string, der: Buffer, trust: 'anchor' | 'bulk' | 'untrusted') => {
    files.push({name, pem: derToPem(der), trust});
    return der;
  };

  // --- Root A (primary trust anchor, RSA) -----------------------------------
  const rootA = mintRoot({CN: 'Root A', O: 'Cert Lab'}, 'rsa');
  add('root-a.pem', rootA.cert.der, 'anchor');

  // --- Root B (secondary anchor, cross-signer) ------------------------------
  const rootB = mintRoot({CN: 'Root B', O: 'Cert Lab'}, 'rsa');
  add('root-b.pem', rootB.cert.der, 'anchor');

  // --- "Root A" cross-signed by Root B: SAME SUBJECT NAME & SAME KEY as Root A
  // (a classic cross-cert: it carries Root A's public key but Root B's
  // signature), so A1 chains through it to Root B. ---------------------------
  const rootACrossByB = mintCert({
    subject: {CN: 'Root A', O: 'Cert Lab'},
    issuerPrivateKey: rootB.key,
    issuerName: {CN: 'Root B', O: 'Cert Lab'},
    subjectPublicKey: rootA.key,
    aki: rootB.cert.ski,
    isCa: true,
    notBefore: new Date('2024-01-01T00:00:00Z'),
    notAfter: new Date('2030-01-01T00:00:00Z'),
  });
  add('root-a-cross-signed-by-b.pem', rootACrossByB.der, 'bulk');

  // --- Same-name/different-key "Root A" (decoy, self-signed, not trusted) ---
  const sameNameOther = mintRoot({CN: 'Root A', O: 'Cert Lab'}, 'rsa', {
    notBefore: new Date('2024-01-01T00:00:00Z'),
    notAfter: new Date('2030-01-01T00:00:00Z'),
  });
  add('root-a-same-name-different-key.pem', sameNameOther.cert.der, 'untrusted');

  // --- Intermediate A1, signed by Root A ------------------------------------
  const interA1 = mintChild(
    {CN: 'Intermediate A1', O: 'Cert Lab'},
    {name: {CN: 'Root A', O: 'Cert Lab'}, key: rootA.key, ski: rootA.cert.ski},
    {isCa: true, pathLen: 0, keyAlg: 'ec-p256'}
  );
  add('intermediate-a1.pem', interA1.der, 'bulk');

  // --- Valid leaf under A1 --------------------------------------------------
  const leaf = mintChild(
    {CN: 'leaf.example'},
    {name: {CN: 'Intermediate A1', O: 'Cert Lab'}, key: interA1.privateKey, ski: interA1.ski},
    {keyAlg: 'ec-p256'}
  );
  add('leaf.pem', leaf.der, 'bulk');

  // --- Expired leaf under A1 ------------------------------------------------
  const leafExpired = mintChild(
    {CN: 'leaf-expired.example'},
    {name: {CN: 'Intermediate A1', O: 'Cert Lab'}, key: interA1.privateKey, ski: interA1.ski},
    {
      keyAlg: 'ec-p256',
      notBefore: new Date('2022-01-01T00:00:00Z'),
      notAfter: new Date('2025-01-01T00:00:00Z'),
    }
  );
  add('leaf-expired.pem', leafExpired.der, 'bulk');

  // --- SHA-1 leaf (algorithm policy rejection) ------------------------------
  const leafSha1 = mintChild(
    {CN: 'leaf-sha1.example'},
    {name: {CN: 'Intermediate A1', O: 'Cert Lab'}, key: interA1.privateKey, ski: interA1.ski},
    {keyAlg: 'rsa', sigAlg: 'sha1'}
  );
  add('leaf-sha1.pem', leafSha1.der, 'bulk');

  // --- Orphan intermediate + leaf with missing issuer -----------------------
  const interX = mintRoot({CN: 'Intermediate X', O: 'Nowhere'}, 'ec-p256');
  const orphanLeaf = mintChild(
    {CN: 'leaf-missing.example'},
    {name: {CN: 'Intermediate X', O: 'Nowhere'}, key: interX.key, ski: interX.cert.ski},
    {keyAlg: 'ec-p256'}
  );
  add('leaf-missing-intermediate.pem', orphanLeaf.der, 'bulk');
  // NOTE: intermediate X itself is deliberately NOT included anywhere.

  // --- Untrusted Root C and its leaf ----------------------------------------
  const rootC = mintRoot({CN: 'Root C', O: 'Cert Lab'}, 'ec-p384');
  const leafC = mintChild(
    {CN: 'leaf-untrusted.example'},
    {name: {CN: 'Root C', O: 'Cert Lab'}, key: rootC.key, ski: rootC.cert.ski},
    {keyAlg: 'rsa'}
  );
  add('root-c-untrusted.pem', rootC.cert.der, 'untrusted');
  add('leaf-untrusted.pem', leafC.der, 'bulk');

  // --- Duplicate cert (identical DER to leaf.pem, different filename) -------
  add('leaf-copy-duplicate.pem', leaf.der, 'bulk');

  const bundleOf = (trusts: ('anchor' | 'bulk' | 'untrusted')[]) =>
    files.filter(f => trusts.includes(f.trust)).map(f => f.pem).join('\n');

  return {
    // untrusted candidates (same-name decoy, Root C) ship in the cert bundle so
    // the UI shows why they do/don't validate, and each can be promoted to a
    // trust anchor with a toggle.
    certsPem: bundleOf(['bulk', 'untrusted']),
    anchorsPem: bundleOf(['anchor']),
    untrustedPem: bundleOf(['untrusted']),
    files,
    keys: {rootA: rootA.key, rootB: rootB.key, rootC: rootC.key},
  };
}
