// X.509 parsing and signature verification on top of the local DER codec.
// The trust store is always caller-supplied; the OS root store and network
// are never touched.

import crypto from 'node:crypto';
import {
  parseTlv, childList, valueOf, decodeOid, decodeTime,
  TAG_OID, TAG_SEQUENCE, TAG_SET, TAG_UTC_TIME, TAG_GENERALIZED_TIME,
  TAG_PRINTABLE_STRING, TAG_UTF8_STRING, TAG_IA5_STRING, TAG_TELETEX_STRING,
  TAG_BMP_STRING, TAG_BIT_STRING,
} from './der.js';

export const OID = {
  rsaEncryption: '1.2.840.113549.1.1.1',
  sha1WithRSA: '1.2.840.113549.1.1.5',
  sha256WithRSA: '1.2.840.113549.1.1.11',
  sha384WithRSA: '1.2.840.113549.1.1.12',
  sha512WithRSA: '1.2.840.113549.1.1.13',
  ecPublicKey: '1.2.840.10045.2.1',
  ecdsaWithSHA256: '1.2.840.10045.4.3.2',
  ecdsaWithSHA384: '1.2.840.10045.4.3.3',
  ecdsaWithSHA512: '1.2.840.10045.4.3.4',
  ecdsaWithSHA1: '1.2.840.10045.4.1',
  ed25519: '1.3.101.112',
  P256: '1.2.840.10045.3.1.7',
  P384: '1.3.132.0.34',
  P521: '1.3.132.0.35',
  skI: '2.5.29.14',
  keyUsage: '2.5.29.15',
  subjectAltName: '2.5.29.17',
  basicConstraints: '2.5.29.19',
  nameConstraints: '2.5.29.30',
  akI: '2.5.29.35',
};

export const SIG_ALGS = {
  [OID.sha1WithRSA]: {label: 'SHA1-RSA', hash: 'sha1', keyType: 'rsa', legacy: true},
  [OID.sha256WithRSA]: {label: 'SHA256-RSA', hash: 'sha256', keyType: 'rsa'},
  [OID.sha384WithRSA]: {label: 'SHA384-RSA', hash: 'sha384', keyType: 'rsa'},
  [OID.sha512WithRSA]: {label: 'SHA512-RSA', hash: 'sha512', keyType: 'rsa'},
  [OID.ecdsaWithSHA1]: {label: 'SHA1-ECDSA', hash: 'sha1', keyType: 'ec', legacy: true},
  [OID.ecdsaWithSHA256]: {label: 'SHA256-ECDSA', hash: 'sha256', keyType: 'ec'},
  [OID.ecdsaWithSHA384]: {label: 'SHA384-ECDSA', hash: 'sha384', keyType: 'ec'},
  [OID.ecdsaWithSHA512]: {label: 'SHA512-ECDSA', hash: 'sha512', keyType: 'ec'},
  [OID.ed25519]: {label: 'Ed25519', hash: undefined, keyType: 'ed25519'},
};

const ATTR_LABEL = {
  '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST',
  '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.5': 'serialNumber',
  '1.2.840.113549.1.9.1': 'emailAddress', '0.9.2342.19200300.100.1.25': 'DC',
};

const STRING_TAGS = new Set([TAG_PRINTABLE_STRING, TAG_UTF8_STRING, TAG_IA5_STRING, TAG_TELETEX_STRING, TAG_BMP_STRING]);

function attrValue(buf, t) {
  if (t.tag === TAG_BMP_STRING) return Buffer.from(valueOf(buf, t)).swap16().toString('utf16le');
  if (STRING_TAGS.has(t.tag)) return valueOf(buf, t).toString('utf8');
  return valueOf(buf, t).toString('utf8');
}

/** Parse an X.500 Name into [{oid,label,value,der}] RDN attribute-sets (flattened). */
export function parseName(buf, nameTlv) {
  const rdns = [];
  for (const rdn of childList(buf, nameTlv.valueStart, nameTlv.valueEnd)) {
    if (rdn.tag !== TAG_SET) throw new Error('RDN is not a SET');
    for (const atv of childList(buf, rdn.valueStart, rdn.valueEnd)) {
      const [oidTlv, valTlv] = childList(buf, atv.valueStart, atv.valueEnd);
      const oidStr = decodeOid(buf, oidTlv.valueStart, oidTlv.valueEnd);
      rdns.push({
        oid: oidStr,
        label: ATTR_LABEL[oidStr] ?? oidStr,
        value: attrValue(buf, valTlv),
        der: Buffer.from(valueOf(buf, atv)),
      });
    }
  }
  return rdns;
}

/** Canonical, comparison-safe rendering: comma joined key=value, RDN order kept. */
export function canonicalName(attrs) {
  return attrs
    .map((a) => `${a.oid}=${a.value.trim().toLowerCase()}`)
    .join(',');
}

/** Human readable DN, e.g. CN=Root CA,O=Lab,C=US */
export function formatName(attrs) {
  return attrs.map((a) => `${a.label}=${a.value}`).join(',');
}

function parseValidity(buf, validityTlv) {
  const [n, a] = childList(buf, validityTlv.valueStart, validityTlv.valueEnd);
  if (![TAG_UTC_TIME, TAG_GENERALIZED_TIME].includes(n.tag)) throw new Error('bad notBefore');
  return {notBefore: decodeTime(buf, n), notAfter: decodeTime(buf, a)};
}

function parseExtensions(buf, extsTlv) {
  const out = [];
  for (const ext of childList(buf, extsTlv.valueStart, extsTlv.valueEnd)) {
    const kids = childList(buf, ext.valueStart, ext.valueEnd);
    const oidTlv = kids[0];
    const oidStr = decodeOid(buf, oidTlv.valueStart, oidTlv.valueEnd);
    let idx = 1;
    let critical = false;
    if (kids[idx] && kids[idx].tag === 0x01) { critical = buf[kids[idx].valueStart] !== 0; idx++; }
    const dataTlv = kids[idx];
    // Copy: subarray keeps the parent buffer's offsets, but parseExtension
    // treats the slice as a standalone buffer with relative indexing.
    const data = Buffer.from(valueOf(buf, dataTlv));
    const parsed = parseExtension(oidStr, data);
    out.push({oid: oidStr, critical, ...parsed});
  }
  return out;
}

// NOTE: all TLV offsets inside an extnValue are relative to `data` itself.
function parseExtension(oidStr, data) {
  const inner = parseTlv(data, 0);
  if (oidStr === OID.skI) {
    // SubjectKeyIdentifier ::= OCTET STRING. `data` is that OCTET STRING
    // (the outer extnValue wrapper was stripped by parseExtensions).
    return {name: 'subjectKeyIdentifier', ski: valueOf(data, inner).toString('hex')};
  }
  if (oidStr === OID.akI) {
    const r = {name: 'authorityKeyIdentifier', aki: null, keyCertIssuer: null};
    for (const f of childList(data, inner.valueStart, inner.valueEnd)) {
      if (f.tag === 0 && !f.constructed) r.aki = valueOf(data, f).toString('hex'); // [0] keyIdentifier
      if (f.tag === 1) r.keyCertIssuer = true;
    }
    return r;
  }
  if (oidStr === OID.basicConstraints) {
    const r = {name: 'basicConstraints', ca: false, pathLen: null};
    const seqKids = childList(data, inner.valueStart, inner.valueEnd);
    if (seqKids[0] && seqKids[0].tag === 0x01) r.ca = data[seqKids[0].valueStart] !== 0;
    if (seqKids[1] && seqKids[1].tag === 0x02) {
      let n = 0;
      for (let i = seqKids[1].valueStart; i < seqKids[1].valueEnd; i++) n = n * 256 + data[i];
      r.pathLen = n;
    }
    return r;
  }
  if (oidStr === OID.keyUsage) {
    // KeyUsage ::= BIT STRING (unwrapped inside extnValue)
    const unused = data[inner.valueStart];
    const maskBytes = valueOf(data, inner).subarray(1);
    let bits = 0n;
    for (const b of maskBytes) bits = (bits << 8n) | BigInt(b);
    const names = ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment',
      'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly'];
    const keyUsage = names.filter((_, i) => i < maskBytes.length * 8 - unused &&
      (bits & (1n << BigInt(maskBytes.length * 8 - 1 - i))) !== 0n);
    return {name: 'keyUsage', keyUsage};
  }
  if (oidStr === OID.subjectAltName) {
    return {name: 'subjectAltName'};
  }
  return {name: oidStr};
}

function parsePublicKey(buf, spkiSeq) {
  const [algId, pubBits] = childList(buf, spkiSeq.valueStart, spkiSeq.valueEnd);
  const [algOid, params] = childList(buf, algId.valueStart, algId.valueEnd);
  const keyAlg = decodeOid(buf, algOid.valueStart, algOid.valueEnd);
  const payload = valueOf(buf, pubBits).subarray(1); // strip unused-bits octet
  let keyType = keyAlg;
  let curve = null;
  let strength = null;

  if (keyAlg === OID.rsaEncryption) {
    keyType = 'rsa';
    const rsapub = parseTlv(payload, 0);
    const [nTlv] = childList(payload, rsapub.valueStart, rsapub.valueEnd);
    // strip leading zero to get true modulus bit length
    let first = nTlv.valueStart;
    while (first < nTlv.valueEnd && payload[first] === 0) first++;
    strength = (nTlv.valueEnd - first) * 8 -
      (payload[first] ? 8 - Math.ceil(Math.log2(payload[first] + 1)) : 0);
  } else if (keyAlg === OID.ecPublicKey) {
    keyType = 'ec';
    if (params && params.tag === TAG_OID) {
      curve = decodeOid(buf, params.valueStart, params.valueEnd);
      strength = {[OID.P256]: 256, [OID.P384]: 384, [OID.P521]: 521}[curve] ?? null;
    }
  } else if (keyAlg === OID.ed25519) {
    keyType = 'ed25519';
    strength = 256;
  }

  return {
    keyType, curve, strength,
    spkiDer: Buffer.from(buf.subarray(spkiSeq.start, spkiSeq.end)),
    spkiSha1: crypto.createHash('sha1').update(buf.subarray(spkiSeq.start, spkiSeq.end)).digest('hex'),
    spkiSha256: crypto.createHash('sha256').update(buf.subarray(spkiSeq.start, spkiSeq.end)).digest('hex'),
    payload: Buffer.from(payload),
  };
}

/**
 * Full structural parse of a DER-encoded certificate.
 * @param {Buffer} der
 */
export function parseCertificate(der) {
  // Force an independent allocation: a pooled subarray view keeps its parent's
  // byteOffset, and slices handed to extension parsing would index wrong.
  const buf = Buffer.alloc(der.length);
  der.copy(buf);
  const cert = parseTlv(buf, 0);
  if (cert.tag !== TAG_SEQUENCE || !cert.constructed) throw new Error('not a certificate (SEQUENCE)');
  const [tbs, sigAlg, sigValue] = childList(buf, cert.valueStart, cert.valueEnd);
  const tbsKids = childList(buf, tbs.valueStart, tbs.valueEnd);
  let i = 0;
  let version = 0;
  if (tbsKids[i] && tbsKids[i].tag === 0 && tbsKids[i].constructed) {
    const [v] = childList(buf, tbsKids[i].valueStart, tbsKids[i].valueEnd);
    let n = 0;
    for (let k = v.valueStart; k < v.valueEnd; k++) n = n * 256 + buf[k];
    version = n; // v3 -> 2
    i++;
  }
  const serialTlv = tbsKids[i++];
  const serialHex = valueOf(buf, serialTlv).toString('hex');
  const serialBig = valueOf(buf, serialTlv).toString('hex').replace(/^0+/, '') || '0';
  const sigAlgTlv = tbsKids[i++];
  const issuerTlv = tbsKids[i++];
  const validityTlv = tbsKids[i++];
  const subjectTlv = tbsKids[i++];
  const spkiTlv = tbsKids[i++];

  const [outerSigOid] = childList(buf, sigAlg.valueStart, sigAlg.valueEnd);
  const sigOid = decodeOid(buf, outerSigOid.valueStart, outerSigOid.valueEnd);
  const signaturePayload = valueOf(buf, sigValue).subarray(1); // BIT STRING unused-bits byte

  const issuerAttrs = parseName(buf, issuerTlv);
  const subjectAttrs = parseName(buf, subjectTlv);
  const validity = parseValidity(buf, validityTlv);
  const publicKey = parsePublicKey(buf, spkiTlv);

  let extensions = [];
  for (let k = i; k < tbsKids.length; k++) {
    const t = tbsKids[k];
    if (t.tag === 3 && t.constructed) {
      const [extsSeq] = childList(buf, t.valueStart, t.valueEnd);
      extensions = parseExtensions(buf, extsSeq);
    }
  }
  const ext = Object.fromEntries(extensions.map((e) => [e.name ?? e.oid, e]));

  return {
    der: buf,
    tbsDer: Buffer.from(buf.subarray(tbs.start, tbs.end)),
    signature: Buffer.from(signaturePayload),
    sigOid,
    sigAlg: SIG_ALGS[sigOid] ?? {label: sigOid, hash: null, keyType: 'unknown'},
    serialHex,
    serialNumber: serialBig,
    version: version + 1,
    issuerAttrs,
    subjectAttrs,
    issuerCanonical: canonicalName(issuerAttrs),
    subjectCanonical: canonicalName(subjectAttrs),
    issuer: formatName(issuerAttrs),
    subject: formatName(subjectAttrs),
    issuerDer: Buffer.from(valueOf(buf, issuerTlv)),
    subjectDer: Buffer.from(valueOf(buf, subjectTlv)),
    notBefore: validity.notBefore,
    notAfter: validity.notAfter,
    publicKey,
    extensions,
    ext,
    ski: ext.subjectKeyIdentifier?.ski ?? null,
    aki: ext.authorityKeyIdentifier?.aki ?? null,
    isCa: Boolean(ext.basicConstraints?.ca),
    hasBasicConstraints: Boolean(ext.basicConstraints),
    pathLenConstraint: ext.basicConstraints?.pathLen ?? null,
    keyUsage: ext.keyUsage?.keyUsage ?? null,
    fingerprint256: crypto.createHash('sha256').update(buf).digest('hex'),
    selfIssued: canonicalName(issuerAttrs) === canonicalName(subjectAttrs),
  };
}

/**
 * Verify that `cert` was signed by the key in `issuer`.
 * @returns {{ok:boolean, reason?:string, detail?:string}}
 */
export function verifySignature(cert, issuer) {
  const meta = SIG_ALGS[cert.sigOid];
  if (!meta) return {ok: false, reason: 'signature_algorithm_unsupported', detail: cert.sigOid};
  if (issuer.publicKey.keyType !== meta.keyType) {
    return {
      ok: false,
      reason: 'signature_key_type_mismatch',
      detail: `certificate uses ${meta.label} but issuer key is ${issuer.publicKey.keyType.toUpperCase()}`,
    };
  }
  let verifier;
  try {
    if (meta.keyType === 'ed25519') {
      verifier = crypto.createVerify(null);
      verifier.update(cert.tbsDer);
      const key = crypto.createPublicKey({key: issuer.publicKey.spkiDer, format: 'der', type: 'spki'});
      return {ok: verifier.verify(key, cert.signature)};
    }
    verifier = crypto.createVerify(meta.hash);
    verifier.update(cert.tbsDer);
    const key = crypto.createPublicKey({key: issuer.publicKey.spkiDer, format: 'der', type: 'spki'});
    // ECDSA signatures are carried in DER (SEQUENCE of two INTEGERs), which is
    // the form Node's OpenSSL binding expects; pass through unchanged.
    return {ok: verifier.verify(key, cert.signature)};
  } catch (e) {
    return {ok: false, reason: 'signature_verify_error', detail: String(e?.message ?? e)};
  }
}

/** Cheap structural test used by the PEM/import path before full parsing. */
export function looksLikeDer(buf) {
  try {
    const t = parseTlv(buf, 0);
    return t.end === buf.length && t.tag === TAG_SEQUENCE;
  } catch {
    return false;
  }
}

/**
 * Split PEM text (or DER buffer) into DER certificate buffers.
 * Accepts concatenated PEM blocks and/or PEM + DER bytes.
 */
export function decodePem(input) {
  const out = [];
  if (Buffer.isBuffer(input) || input instanceof Uint8Array) {
    const buf = Buffer.from(input);
    // Single DER cert?
    if (looksLikeDer(buf)) { out.push(buf); return out; }
    return decodePem(buf.toString('binary'));
  }
  const text = String(input);
  const re = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;
  let m;
  while ((m = re.exec(text))) {
    if (/CERTIFICATE/.test(m[1])) {
      const b64 = m[2].replace(/\s+/g, '');
      out.push(Buffer.from(b64, 'base64'));
    }
  }
  if (out.length === 0) {
    // maybe raw base64 DER
    const compact = text.replace(/\s+/g, '');
    if (/^[A-Za-z0-9+/=]+$/.test(compact)) {
      const buf = Buffer.from(compact, 'base64');
      if (looksLikeDer(buf)) out.push(buf);
    }
  }
  return out;
}

export function toPem(der) {
  const b64 = Buffer.from(der).toString('base64');
  const lines = b64.match(/.{1,64}/g).join('\n');
  return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----\n`;
}
