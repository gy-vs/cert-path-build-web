import {createHash, createPublicKey, KeyObject, verify as cryptoVerify, X509Certificate} from 'node:crypto';
import {
  decodeOid,
  DerNode,
  nameToText,
  OID,
  parseNode,
  TAG,
} from './der';

export type SignatureInfo = {
  oid: string;
  label: string;
  /** e.g. "sha256WithRSAEncryption" -> hash "sha256" */
  hash: string | null;
  keyType: 'rsa' | 'ec' | 'unknown';
};

const SIG_ALGORITHMS: Record<string, SignatureInfo> = {
  [OID.RSA_SHA256]: {oid: OID.RSA_SHA256, label: 'sha256WithRSAEncryption', hash: 'sha256', keyType: 'rsa'},
  [OID.RSA_SHA384]: {oid: OID.RSA_SHA384, label: 'sha384WithRSAEncryption', hash: 'sha384', keyType: 'rsa'},
  [OID.RSA_SHA512]: {oid: OID.RSA_SHA512, label: 'sha512WithRSAEncryption', hash: 'sha512', keyType: 'rsa'},
  [OID.RSA_SHA1]: {oid: OID.RSA_SHA1, label: 'sha1WithRSAEncryption', hash: 'sha1', keyType: 'rsa'},
  [OID.EC_SHA256]: {oid: OID.EC_SHA256, label: 'ecdsa-with-SHA256', hash: 'sha256', keyType: 'ec'},
  [OID.EC_SHA384]: {oid: OID.EC_SHA384, label: 'ecdsa-with-SHA384', hash: 'sha384', keyType: 'ec'},
  [OID.EC_SHA1]: {oid: OID.EC_SHA1, label: 'ecdsa-with-SHA1', hash: 'sha1', keyType: 'ec'},
};

export type ParsedCertificate = {
  /** sha256 fingerprint of the DER encoding */
  fingerprint: string;
  der: Buffer;
  pem: string;
  x509: X509Certificate;
  serial: string;
  issuer: Buffer; // raw Name encoding
  subject: Buffer; // raw Name encoding
  issuerText: string;
  subjectText: string;
  commonName: string;
  notBefore: Date;
  notAfter: Date;
  ski: string | null; // hex
  aki: string | null; // hex keyIdentifier only
  isCa: boolean;
  pathLen: number | null;
  keyUsage: number | null; // bit string
  signature: SignatureInfo;
  publicKey: KeyObject;
  publicKeyBits: number;
  /** algorithm of the certificate's OWN public key (independent of how it was signed) */
  subjectKeyType: 'rsa' | 'ec' | 'unknown';
  selfSigned: boolean;
};

function findExtension(tbsExtensions: DerNode[] | undefined, oid: string): DerNode | null {
  if (!tbsExtensions) return null;
  for (const ext of tbsExtensions) {
    if (decodeOid(ext.children[0].content) === oid) return ext;
  }
  return null;
}

function extOctetValue(ext: DerNode | null): DerNode | null {
  if (!ext) return null;
  // Extension ::= SEQUENCE { OID, BOOLEAN? , OCTET STRING }
  const octet = ext.children.find(child => child.tag === TAG.OCTET_STRING);
  if (!octet) return null;
  return parseNode(octet.content, 0);
}

/** Extract CN from a raw Name node, used as a compact display label. */
function cnOf(nameNode: DerNode): string {
  for (const rdn of nameNode.children) {
    for (const atv of rdn.children) {
      const [oidNode, valueNode] = atv.children;
      if (decodeOid(oidNode.content) === OID.CN) return valueNode.content.toString('utf8');
    }
  }
  return nameToText(nameNode);
}

export function parseCertificate(der: Buffer): ParsedCertificate {
  const x509 = new X509Certificate(der);
  const cert = parseNode(der, 0);
  const [tbs, sigAlgNode] = cert.children;
  const tbsChildren = tbs.children;

  // TBSCertificate: [0]version?, serialNumber, signature, issuer, validity, subject, ...
  let cursor = 0;
  if (tbsChildren[0].tag === 0xa0) cursor += 1; // explicit [0] version
  const serialNode = tbsChildren[cursor];
  cursor += 1; // serialNumber
  cursor += 1; // inner signature AlgorithmIdentifier
  const issuerNode = tbsChildren[cursor++];
  const validityNode = tbsChildren[cursor++];
  const subjectNode = tbsChildren[cursor++];
  const spkiNode = tbsChildren[cursor++];

  // extensions is the last element, tagged [3] EXPLICIT
  const extensionsWrapper = tbsChildren.find(child => child.tag === 0xa3);
  const extensions = extensionsWrapper?.children?.[0]?.children;

  // SKI
  let ski: string | null = null;
  const skiExt = extOctetValue(findExtension(extensions, OID.SKI));
  if (skiExt && skiExt.tag === TAG.OCTET_STRING) ski = skiExt.content.toString('hex');

  // AKI (keyIdentifier only)
  let aki: string | null = null;
  const akiExt = extOctetValue(findExtension(extensions, OID.AKI));
  if (akiExt) {
    const kid = akiExt.children.find(child => child.tag === 0x80);
    if (kid) aki = kid.content.toString('hex');
  }

  // Basic constraints
  let isCa = false;
  let pathLen: number | null = null;
  const bcExt = extOctetValue(findExtension(extensions, OID.BASIC_CONSTRAINTS));
  if (bcExt) {
    // SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }
    const cA = bcExt.children.find(child => child.tag === TAG.BOOLEAN);
    isCa = cA ? cA.content[0] !== 0 : false;
    const pathLenNode = bcExt.children.find(child => child.tag === TAG.INTEGER);
    if (pathLenNode) {
      pathLen = 0;
      for (const byte of pathLenNode.content) pathLen = pathLen * 256 + byte;
    }
  }

  // Key usage bit string
  let keyUsage: number | null = null;
  const kuExt = extOctetValue(findExtension(extensions, OID.KEY_USAGE));
  if (kuExt && kuExt.tag === TAG.BIT_STRING) {
    // first content byte = unused bits
    let bits = 0;
    for (const byte of kuExt.content.subarray(1)) bits = bits * 256 + byte;
    keyUsage = bits;
  }

  const sigOid = decodeOid(sigAlgNode.children[0].content);
  const signature = SIG_ALGORITHMS[sigOid] ?? {oid: sigOid, label: sigOid, hash: null, keyType: 'unknown'};

  // Validity ::= SEQUENCE { notBefore Time, notAfter Time }
  const [notBeforeNode, notAfterNode] = validityNode.children;
  const parseTime = (node: DerNode): Date => {
    const text = node.content.toString('ascii');
    if (node.tag === TAG.UTC_TIME) {
      // YYMMDDHHMMSSZ
      const year = 2000 + Number(text.slice(0, 2));
      return new Date(Date.UTC(year, Number(text.slice(2, 4)) - 1, Number(text.slice(4, 6)),
        Number(text.slice(6, 8)), Number(text.slice(8, 10)), Number(text.slice(10, 12))));
    }
    // GENERALIZEDTIME YYYYMMDDHHMMSSZ
    return new Date(Date.UTC(Number(text.slice(0, 4)), Number(text.slice(4, 6)) - 1, Number(text.slice(6, 8)),
      Number(text.slice(8, 10)), Number(text.slice(10, 12)), Number(text.slice(12, 14))));
  };

  const publicKey = createPublicKey({key: spkiNode.raw, format: 'der', type: 'spki'});
  const jwk = publicKey.export({format: 'jwk'}) as {n?: string; crv?: string; kty?: string};
  const subjectKeyType: 'rsa' | 'ec' | 'unknown' =
    jwk.kty === 'RSA' ? 'rsa' : jwk.kty === 'EC' ? 'ec' : 'unknown';
  let publicKeyBits: number;
  if (jwk.n) {
    // RSA: bit length of the modulus
    const modulus = Buffer.from(jwk.n, 'base64url');
    let highBits = 0;
    let high = modulus[0] ?? 0;
    while (high > 0) {
      highBits += 1;
      high >>= 1;
    }
    publicKeyBits = (modulus.length - 1) * 8 + highBits;
  } else {
    // EC: SPKI BIT STRING holds an uncompressed point 0x04 || X || Y
    const point = spkiNode.children[1].content.subarray(1);
    publicKeyBits = (point.length - 1) * 4;
  }

  return {
    fingerprint: createHash('sha256').update(der).digest('hex'),
    der,
    pem: x509.toString(),
    x509,
    serial: serialNode.content.toString('hex'),
    issuer: issuerNode.raw,
    subject: subjectNode.raw,
    issuerText: nameToText(issuerNode),
    subjectText: nameToText(subjectNode),
    commonName: cnOf(subjectNode),
    notBefore: parseTime(notBeforeNode),
    notAfter: parseTime(notAfterNode),
    ski,
    aki,
    isCa,
    pathLen,
    keyUsage,
    signature,
    publicKey,
    publicKeyBits,
    subjectKeyType,
    selfSigned: nameContentEquals(issuerNode.raw, subjectNode.raw),
  };
}

/**
 * Cryptographically verify that `subjectCert` was signed by `issuerCert`.
 * Returns false instead of throwing for malformed/alg-mismatch input.
 */
export function verifySignature(subjectCert: ParsedCertificate, issuerCert: ParsedCertificate): boolean {
  const info = subjectCert.signature;
  if (!info.hash) return false;
  const cert = parseNode(subjectCert.der, 0);
  const tbs = cert.children[0];
  // signature BIT STRING is third element; strip the "unused bits" leading byte
  const sigBitString = cert.children[2];
  const signatureBytes = sigBitString.content.subarray(1);
  const dsaEncoding = info.keyType === 'ec' ? 'der' : undefined;
  try {
    return cryptoVerify(
      info.hash,
      Buffer.from(tbs.raw),
      {key: issuerCert.publicKey, ...(dsaEncoding ? {dsaEncoding} : {})},
      signatureBytes
    );
  } catch {
    return false;
  }
}

/** Compare subject public key material by DER SPKI. */
export function samePublicKey(a: ParsedCertificate, b: ParsedCertificate): boolean {
  if (a.ski && b.ski) return a.ski === b.ski;
  const aSpki = a.publicKey.export({format: 'der', type: 'spki'});
  const bSpki = b.publicKey.export({format: 'der', type: 'spki'});
  return aSpki.equals(bSpki);
}

/**
 * Compare two raw Name encodings by their RDNSequence content rather than the
 * full TLV: independently encoded names for the same identity can differ in
 * SEQUENCE length encoding while the RDN bytes are identical.
 */
export function nameContentEquals(aName: Buffer, bName: Buffer): boolean {
  try {
    const a = parseNode(aName, 0);
    const b = parseNode(bName, 0);
    return a.content.equals(b.content);
  } catch {
    return aName.equals(bName);
  }
}

/** Split one PEM blob that may hold several CERTIFICATE blocks; accept raw DER too. */
export function splitPemDer(input: string | Buffer): Buffer[] {
  const text = typeof input === 'string' ? input : input.toString('latin1');
  const matches = [...text.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g)];
  if (matches.length > 0) {
    return matches
      .map(match => Buffer.from(match[1].replace(/\s+/g, ''), 'base64'))
      .filter(buf => buf.length > 0);
  }
  const trimmed = typeof input === 'string' ? text.trim() : text;
  if (/^[A-Za-z0-9+/=\r\n]+$/.test(trimmed)) {
    const buf = Buffer.from(trimmed.replace(/\s+/g, ''), 'base64');
    if (buf.length > 0 && parseSafe(buf)) return [buf];
  }
  const raw = typeof input === 'string' ? Buffer.from(text, 'latin1') : input;
  return parseSafe(raw) ? [raw] : [];
}

function parseSafe(buf: Buffer): boolean {
  try {
    // eslint-disable-next-line no-new
    new X509Certificate(buf);
    return true;
  } catch {
    return false;
  }
}

export function parseMany(input: string | Buffer): ParsedCertificate[] {
  return splitPemDer(input).map(parseCertificate);
}
