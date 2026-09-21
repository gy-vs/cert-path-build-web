// Local certificate minting for the fixture scenarios.
// Uses only node:crypto key generation/signing and our DER encoder, so fixture
// generation stays fully offline and independent of the OS trust store.

import crypto from 'node:crypto';
import {
  sequence, setOf, integer, integerBuf, boolean, bitString, oid, nullValue,
  contextExplicit, printable, utf8, tlv, encodeTime, TAG_OCTET_STRING,
} from '../shared/der.js';
import {OID, toPem} from '../shared/x509.js';

export function generateKeyPair(type = 'rsa', options = {}) {
  if (type === 'rsa') return crypto.generateKeyPairSync('rsa', {modulusLength: options.modulusLength ?? 2048});
  if (type === 'ec') return crypto.generateKeyPairSync('ec', {namedCurve: options.curve ?? 'P-256'});
  throw new Error(`unsupported key type ${type}`);
}

export const CURVE_OID = {'P-256': OID.P256, 'P-384': OID.P384, 'P-521': OID.P521};

function rsaSpki(publicKey) {
  const jwk = publicKey.export({format: 'jwk'});
  const mod = Buffer.from(jwk.n, 'base64url');
  const exp = Buffer.from(jwk.e, 'base64url');
  const rsaPub = sequence(integerBuf(mod), integerBuf(exp));
  return sequence(sequence(oid(OID.rsaEncryption), nullValue()), bitString(rsaPub));
}

function ecSpki(publicKey, curve) {
  const jwk = publicKey.export({format: 'jwk'});
  // uncompressed point: 0x04 || x || y
  const point = Buffer.concat([
    Buffer.from([0x04]),
    Buffer.from(jwk.x, 'base64url'),
    Buffer.from(jwk.y, 'base64url'),
  ]);
  return sequence(sequence(oid(OID.ecPublicKey), oid(CURVE_OID[curve])), bitString(point));
}

export function spkiFor(publicKey) {
  const jwk = publicKey.export({format: 'jwk'});
  if (jwk.kty === 'RSA') return rsaSpki(publicKey);
  if (jwk.kty === 'EC') return ecSpki(publicKey, jwk.crv);
  throw new Error('unsupported public key');
}

// tiny structural reader, just enough for the RFC 5280 method-1 SKI computation
function readTlv(buf, off) {
  let p = off + 1;
  let len = buf[p++];
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[p++];
  }
  const node = {payloadStart: p, payloadEnd: p + len, end: p + len, children: []};
  if (buf[off] === 0x30) {
    let q = p;
    while (q < node.payloadEnd) { const c = readTlv(buf, q); node.children.push(c); q = c.end; }
  }
  return node;
}

/** RFC 5280 method 1 SKI: SHA-1 of the subjectPublicKey BIT STRING content. */
export function skiFromSpki(spkiDer) {
  const root = readTlv(spkiDer, 0);
  const bitT = root.children[1];
  return crypto.createHash('sha1')
    .update(spkiDer.subarray(bitT.payloadStart + 1, bitT.payloadEnd)) // skip unused-bits byte
    .digest();
}

// ---- Name encoding ----
const CN = '2.5.4.3', C = '2.5.4.6', O = '2.5.4.10', OU = '2.5.4.11';
const ATTR_OID = {CN, C, O, OU};

function atv(attrOid, value) {
  const val = /^[\x20-\x7e]*$/.test(value) ? printable(value) : utf8(value);
  return sequence(oid(attrOid), val);
}

/** [['CN','Root CA'],['O','Lab']] -> Name ::= SEQUENCE OF RDN(SET OF ATV) */
export function encodeName(parts) {
  return sequence(...parts.map(([attr, value]) =>
    setOf(atv(ATTR_OID[attr] ?? attr, value))));
}

// ---- extensions ----
// `ext` emits: [OID, [critical], extnValue OCTET STRING content].
// Per RFC 5280 the `content` for each extension is its ASN.1 type directly
// (SEQUENCE for BC/AKI, OCTET STRING for SKI, BIT STRING for KU) — no extra wrap.
const octet = (content) => tlv(TAG_OCTET_STRING, Buffer.from(content));
const ext = (oidStr, content) => sequence(oid(oidStr), octet(content));
const extCritical = (oidStr, content) => sequence(oid(oidStr), boolean(true), octet(content));

const implicitPrim = (tagNum, data) => {
  const body = Buffer.from(data);
  const len = body.length < 0x80 ? Buffer.from([body.length])
    : (() => { const b = []; let x = body.length; while (x) { b.unshift(x & 0xff); x >>= 8; } return Buffer.from([0x80 | b.length, ...b]); })();
  return Buffer.concat([Buffer.from([0x80 | tagNum]), len, body]);
};

// Wire bytes for SKI: extnValue OCTET STRING(04 16) wrapping SubjectKeyIdentifier
// OCTET STRING(04 14 <20 bytes>). `ext()` emits the outer 04 16, so the content
// passed in is exactly one octet(ski) -> 04 14 <keyid>.
const extSki = (ski, critical = false) =>
  (critical ? extCritical : ext)(OID.skI, octet(ski));
const extAki = (aki) => ext(OID.akI, sequence(implicitPrim(0, aki)));

function extBasicConstraints(ca, pathLen, critical = true) {
  let body = ca ? boolean(true) : Buffer.alloc(0);
  if (ca && pathLen !== null && pathLen !== undefined) body = Buffer.concat([body, integer(pathLen)]);
  return extCritical(OID.basicConstraints, sequence(body));
}
// KeyUsage ::= BIT STRING (directly inside the extnValue OCTET STRING)
// keyCertSign(5)+cRLSign(6) -> mask 0b00000110, 1 unused bit
const extKeyUsageCA = () => extCritical(OID.keyUsage, bitString(Buffer.from([0x06]), 1));
// digitalSignature(0) -> 0b10000000, 7 unused bits
const extKeyUsageLeaf = () => extCritical(OID.keyUsage, bitString(Buffer.from([0x80]), 7));

const SIG_OID = {
  'sha1:rsa': OID.sha1WithRSA,
  'sha256:rsa': OID.sha256WithRSA,
  'sha384:rsa': OID.sha384WithRSA,
  'sha512:rsa': OID.sha512WithRSA,
  'sha1:ec': OID.ecdsaWithSHA1,
  'sha256:ec': OID.ecdsaWithSHA256,
  'sha384:ec': OID.ecdsaWithSHA384,
};

let serialCounter = 1;

/**
 * Mint a certificate.
 *
 * opts:
 *   subject  CN string or [['CN',..],['O',..]]
 *   keyPair  {publicKey,privateKey}
 *   issuer   null (self-signed) | {name, keyPair}
 *   notBefore, notAfter
 *   ca, pathLen, keyUsage ('ca'|'leaf'|null)
 *   includeSki/includeAki/includeBC (default true)
 *   skiCritical, aki (force AKI value; null to omit the field), sigAlg
 */
export function issueCertificate(opts) {
  const defaultName = (cn) => Array.isArray(cn) ? cn : [['CN', cn], ['O', 'Chain Lab'], ['C', 'US']];
  const subjectParts = defaultName(opts.subject);
  const issuerParts = opts.issuer ? defaultName(opts.issuer.name) : subjectParts;
  const issuerKey = opts.issuer ? opts.issuer.keyPair.privateKey : opts.keyPair.privateKey;

  const spki = spkiFor(opts.keyPair.publicKey);
  const ski = skiFromSpki(spki);

  let akiValue;
  if (Object.prototype.hasOwnProperty.call(opts, 'aki')) {
    akiValue = opts.aki; // explicit: Buffer, or null
  } else if (opts.issuer) {
    akiValue = skiFromSpki(spkiFor(opts.issuer.keyPair.publicKey));
  } else {
    akiValue = ski; // self-signed
  }

  const exts = [];
  if (opts.includeSki !== false) exts.push(extSki(ski, Boolean(opts.skiCritical)));
  if (opts.includeAki !== false && akiValue) exts.push(extAki(akiValue));
  if (opts.includeBC !== false) exts.push(extBasicConstraints(opts.ca ?? false, opts.pathLen ?? null));
  if (opts.keyUsage === 'ca') exts.push(extKeyUsageCA());
  if (opts.keyUsage === 'leaf') exts.push(extKeyUsageLeaf());

  // Default signature hash follows the ISSUER key type: crypto.sign produces
  // PKCS#1 v1.5 for RSA keys and ECDSA for EC keys regardless of the OID we
  // claim, so the OID must match the key or verification fails.
  const issuerJwk = (opts.issuer ? opts.issuer.keyPair : opts.keyPair).publicKey.export({format: 'jwk'});
  const sigAlg = opts.sigAlg ?? (issuerJwk.kty === 'EC' ? 'sha256:ec' : 'sha256:rsa');
  const notBefore = opts.notBefore ?? new Date('2024-01-01T00:00:00Z');
  const notAfter = opts.notAfter ?? new Date('2030-01-01T00:00:00Z');

  const sigAlgSeq = sigAlg === 'ed25519'
    ? sequence(oid(OID.ed25519))
    : sequence(oid(SIG_OID[sigAlg]));

  const serial = serialCounter++;
  const tbs = sequence(
    contextExplicit(0, integer(2)), // v3
    integer(serial),
    sigAlgSeq,
    encodeName(issuerParts),
    sequence(encodeTime(notBefore), encodeTime(notAfter)),
    encodeName(subjectParts),
    spki,
    contextExplicit(3, sequence(...exts)),
  );

  let sigBits;
  if (sigAlg === 'ed25519') {
    sigBits = bitString(crypto.sign(null, tbs, issuerKey));
  } else {
    const [hash] = sigAlg.split(':');
    // crypto.sign returns DER INTEGER-pair signatures for EC and PKCS#1 v1.5
    // signatures for RSA — exactly the X.509 BIT STRING content in both cases.
    sigBits = bitString(crypto.sign(hash, tbs, issuerKey));
  }

  const certDer = sequence(tbs, sigAlgSeq, sigBits);
  return {
    der: certDer,
    pem: toPem(certDer),
    subject: subjectParts,
    issuer: issuerParts,
    spki,
    ski: ski.toString('hex'),
    serial,
  };
}
