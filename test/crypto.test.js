import {test, describe} from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import {
  parseTlv, childList, decodeOid, encodeOid, encodeTime, decodeTime,
  integer, tlv, TAG_OCTET_STRING,
} from '../src/shared/der.js';
import {
  parseCertificate, verifySignature, decodePem, toPem, OID,
} from '../src/shared/x509.js';
import {generateKeyPair, issueCertificate} from '../src/server/certBuilder.js';

describe('DER codec', () => {
  test('OID round trips for common arcs', () => {
    for (const oid of ['1.2.840.113549.1.1.11', '2.5.29.19', '1.2.840.10045.4.3.2', '0.9.2342.19200300.100.1.25']) {
      assert.equal(decodeOid(encodeOid(oid)), oid);
    }
  });

  test('time encoding uses UTCTime before 2050 and GeneralizedTime after', () => {
    const a = encodeTime(new Date('2026-09-20T12:00:00Z'));
    assert.equal(a[0], 0x17);
    const b = encodeTime(new Date('2061-01-01T00:00:00Z'));
    assert.equal(b[0], 0x18);
    assert.equal(decodeTime(a instanceof Buffer ? a : Buffer.from(a), parseTlv(a, 0)).toISOString(), '2026-09-20T12:00:00.000Z');
  });

  test('long-form length handles >127 byte payloads', () => {
    const body = Buffer.alloc(300, 0x30);
    const der = tlv(TAG_OCTET_STRING, body);
    const parsed = parseTlv(der, 0);
    assert.equal(parsed.end, der.length);
    assert.equal(parsed.valueEnd - parsed.valueStart, 300);
  });

  test('integer encoding preserves leading zero for positive high bit', () => {
    const a = integer(255);
    assert.deepEqual([...a.subarray(a.length - 2)], [0, 255]);
  });
});

describe('X.509 parse and verify', () => {
  const root = generateKeyPair('rsa');
  const ic = generateKeyPair('ec');
  const lf = generateKeyPair('ec');
  const rootCert = issueCertificate({subject: 'Root', keyPair: root, ca: true, pathLen: 2, keyUsage: 'ca'});
  const intCert = issueCertificate({subject: 'Intermediate', keyPair: ic,
    issuer: {name: 'Root', keyPair: root}, ca: true, pathLen: 0, keyUsage: 'ca'});
  const leafCert = issueCertificate({subject: 'leaf', keyPair: lf,
    issuer: {name: 'Intermediate', keyPair: ic}, ca: false, keyUsage: 'leaf', sigAlg: 'sha256:ec'});

  test('parses subject/issuer/validity/extensions', () => {
    const r = parseCertificate(rootCert.der);
    assert.equal(r.subject, 'CN=Root,O=Chain Lab,C=US');
    assert.equal(r.isCa, true);
    assert.equal(r.pathLenConstraint, 2);
    assert.deepEqual(r.keyUsage, ['keyCertSign', 'cRLSign']);
    assert.ok(r.ski?.length === 40);
    assert.equal(r.aki, r.ski); // self-signed AKI defaults to own SKI
    assert.equal(r.version, 3);
    assert.equal(r.publicKey.strength, 2048);
  });

  test('EC intermediate parses key type and P-256 strength', () => {
    const i = parseCertificate(intCert.der);
    assert.equal(i.publicKey.keyType, 'ec');
    assert.equal(i.publicKey.strength, 256);
    assert.equal(i.aki, parseCertificate(rootCert.der).ski);
  });

  test('signature verification succeeds up the chain and on self-signed root', () => {
    const r = parseCertificate(rootCert.der);
    const i = parseCertificate(intCert.der);
    const l = parseCertificate(leafCert.der);
    assert.equal(verifySignature(r, r).ok, true);
    assert.equal(verifySignature(i, r).ok, true);
    assert.equal(verifySignature(l, i).ok, true);
  });

  test('signature verification fails with the wrong key', () => {
    const l = parseCertificate(leafCert.der);
    const r = parseCertificate(rootCert.der);
    const stranger = generateKeyPair('ec');
    const strangerCert = parseCertificate(issueCertificate({subject: 'Stranger CA', keyPair: stranger, ca: true}).der);
    // leaf was signed by the EC intermediate; root is RSA, stranger is unrelated
    assert.equal(verifySignature(l, r).ok, false);
    assert.equal(verifySignature(l, strangerCert).ok, false);
  });

  test('minted certs validate against Node/OpenSSL X509Certificate', () => {
    const nxLeaf = new crypto.X509Certificate(leafCert.der);
    const nxInt = new crypto.X509Certificate(intCert.der);
    const nxRoot = new crypto.X509Certificate(rootCert.der);
    assert.equal(nxLeaf.verify(ic.publicKey), true);
    assert.equal(nxInt.verify(root.publicKey), true);
    assert.equal(nxRoot.verify(root.publicKey), true);
    assert.equal(nxRoot.ca, true);
    assert.equal(nxLeaf.ca, false);
  });

  test('PEM decode: single, concatenated, and raw DER buffer', () => {
    const doublePem = rootCert.pem + intCert.pem;
    assert.equal(decodePem(doublePem).length, 2);
    assert.equal(decodePem(rootCert.der).length, 1);
    const roundtrip = decodePem(toPem(leafCert.der));
    assert.ok(roundtrip[0].equals(leafCert.der));
  });

  test('legacy SHA-1 self-signature still verifies cryptographically', () => {
    const legacy = generateKeyPair('rsa', {modulusLength: 1024});
    const c = issueCertificate({subject: 'Legacy', keyPair: legacy, ca: true, sigAlg: 'sha1:rsa'});
    const p = parseCertificate(c.der);
    assert.equal(p.sigOid, OID.sha1WithRSA);
    assert.equal(p.sigAlg.legacy, true);
    assert.equal(verifySignature(p, p).ok, true);
  });
});
