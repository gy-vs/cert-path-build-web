/**
 * Local X.509 certificate minting for the built-in lab fixtures.
 *
 * Everything is generated in-process with node:crypto — no system store and no
 * network. Supports RSA-PKCS#1 v1.5 and ECDSA (P-256/P-384), CA/basic
 * constraints, SKI/AKI, key usage and arbitrary validity windows.
 */
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  KeyObject,
  randomBytes,
  sign as cryptoSign,
} from 'node:crypto';
import {
  bitString,
  boolean,
  DerNode,
  integer,
  nullValue,
  oid,
  octetString,
  OID,
  parseNode,
  sequence,
  set,
  tlv,
  TAG,
} from './der';

export type KeyAlg = 'rsa' | 'ec-p256' | 'ec-p384';
export type SigAlg = 'sha256' | 'sha384' | 'sha512' | 'sha1';

export type NameInput = {CN: string; O?: string; OU?: string; C?: string};

export type CertOptions = {
  subject: NameInput;
  issuerPrivateKey: KeyObject;
  /** issuer subject Name DER; defaults to subject (self-issued) */
  issuerName?: NameInput;
  /** AKI keyIdentifier; usually the issuer's SKI */
  aki?: string | null;
  isCa?: boolean;
  pathLen?: number | null;
  keyCertSign?: boolean;
  sigAlg?: SigAlg;
  notBefore?: Date;
  notAfter?: Date;
  serial?: Buffer;
  /** Emit an SKI extension. Defaults to true. */
  ski?: boolean;
  /** Emit an AKI extension when aki is provided. Defaults to true. */
  includeAki?: boolean;
  /**
   * Public key bound into the certificate. Defaults to the issuer key, which
   * produces a self-issued certificate; set it to mint a cert for another party.
   */
  subjectPublicKey?: KeyObject;
};

export function generateKey(alg: KeyAlg): {publicKey: KeyObject; privateKey: KeyObject} {
  if (alg === 'rsa') return generateKeyPairSync('rsa', {modulusLength: 2048});
  return generateKeyPairSync('ec', {namedCurve: alg === 'ec-p384' ? 'secp384r1' : 'prime256v1'});
}

function encodeName(name: NameInput): Buffer {
  const attr = (attrOid: string, value: string | undefined) => {
    if (value === undefined) return null;
    // most lab names are PrintableString-safe; CN with spaces also fits
    const printable = /^[\x20-\x7e]*$/.test(value);
    const valueTlv = tlv(printable ? TAG.PRINTABLE_STRING : TAG.UTF8_STRING, value);
    return set(sequence(oid(attrOid), valueTlv));
  };
  return sequence(
    ...[attr(OID.C, name.C), attr(OID.O, name.O), attr(OID.OU, name.OU), attr(OID.CN, name.CN)].filter(
      (part): part is Buffer => part !== null
    )
  );
}

function keyAlgorithmIdentifier(key: KeyObject): Buffer {
  const jwk = key.export({format: 'jwk'}) as {kty?: string; crv?: string};
  if (jwk.kty === 'RSA') return sequence(oid(OID.RSA_ENCRYPTION), nullValue());
  const curve = jwk.crv === 'P-384' ? OID.EC_P384 : OID.EC_P256;
  return sequence(oid(OID.EC_PUBLIC_KEY), oid(curve));
}

function sigAlgorithmIdentifier(key: KeyObject, hash: SigAlg): {algId: Buffer; keyType: 'rsa' | 'ec'} {
  const jwk = key.export({format: 'jwk'}) as {kty?: string};
  if (jwk.kty === 'RSA') {
    const map: Record<SigAlg, string> = {
      sha1: OID.RSA_SHA1,
      sha256: OID.RSA_SHA256,
      sha384: OID.RSA_SHA384,
      sha512: OID.RSA_SHA512,
    };
    return {algId: sequence(oid(map[hash]), nullValue()), keyType: 'rsa'};
  }
  const map: Record<SigAlg, string> = {
    sha1: OID.EC_SHA1,
    sha256: OID.EC_SHA256,
    sha384: OID.EC_SHA384,
    sha512: OID.EC_SHA384,
  };
  return {algId: sequence(oid(map[hash])), keyType: 'ec'};
}

function encodeSubjectPublicKeyInfo(key: KeyObject): Buffer {
  // export() accepts either a private or public KeyObject directly
  return key.export({format: 'der', type: 'spki'});
}

function encodeValidity(notBefore: Date, notAfter: Date): Buffer {
  const time = (date: Date) => {
    const year = date.getUTCFullYear();
    const pad = (n: number) => String(n).padStart(2, '0');
    const body =
      year >= 2050
        ? tlv(TAG.GENERALIZED_TIME, `${year}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`)
        : tlv(
            TAG.UTC_TIME,
            `${String(year).slice(2)}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`
          );
    return body;
  };
  return sequence(time(notBefore), time(notAfter));
}

function skiFor(key: KeyObject): string {
  // RFC 5280 method(1): 160-bit SHA-1 of the BIT STRING subjectPublicKey
  const spki = parseNode(encodeSubjectPublicKeyInfo(key), 0);
  const bitStringNode = spki.children[1];
  return createHash('sha1').update(bitStringNode.content.subarray(1)).digest('hex');
}

/** Mint a DER certificate signed by issuerPrivateKey. */
export function mintCert(options: CertOptions): {der: Buffer; privateKey: KeyObject; ski: string} {
  const sigAlg: SigAlg = options.sigAlg ?? 'sha256';
  // The subject key defaults to the issuer key, producing a self-issued cert.
  const subjectKey = options.subjectPublicKey ?? options.issuerPrivateKey;
  const publicKey = createPublicKey(subjectKey);

  const version = tlv(0xa0, integer(2)); // v3
  const serial = integer(options.serial ?? randomBytes(12));
  const {algId, keyType} = sigAlgorithmIdentifier(options.issuerPrivateKey, sigAlg);
  const subjectName = encodeName(options.subject);
  const issuerName = encodeName(options.issuerName ?? options.subject);
  const notBefore = options.notBefore ?? new Date('2024-01-01T00:00:00Z');
  const notAfter = options.notAfter ?? new Date('2030-01-01T00:00:00Z');
  const spki = encodeSubjectPublicKeyInfo(publicKey);

  const extensions: Buffer[] = [];

  // basic constraints
  const bcParts: Buffer[] = [];
  if (options.isCa) bcParts.push(boolean(true));
  if (options.pathLen != null) bcParts.push(integer(options.pathLen));
  if (options.isCa || options.pathLen != null) {
    extensions.push(
      sequence(oid(OID.BASIC_CONSTRAINTS), boolean(true), octetString(sequence(...bcParts)))
    );
  }

  // key usage: CA certs get keyCertSign+cRLSign (0x06); leaves digitalSignature (0x80)
  const kuByte = options.isCa || options.keyCertSign ? 0x06 : 0x80;
  extensions.push(
    sequence(oid(OID.KEY_USAGE), boolean(true), octetString(bitString(Buffer.from([kuByte]), 1)))
  );

  // SKI
  const ski = skiFor(publicKey);
  if (options.ski !== false) {
    extensions.push(sequence(oid(OID.SKI), octetString(octetString(Buffer.from(ski, 'hex')))));
  }

  // AKI
  if (options.aki && options.includeAki !== false) {
    const aki = sequence(tlv(0x80, Buffer.from(options.aki, 'hex')));
    extensions.push(sequence(oid(OID.AKI), octetString(aki)));
  }

  const extsWrapper = tlv(0xa3, sequence(...extensions));

  const tbs = sequence(
    version,
    serial,
    algId,
    issuerName,
    encodeValidity(notBefore, notAfter),
    subjectName,
    spki,
    extsWrapper
  );

  const signatureBytes = cryptoSign(sigAlg, tbs, {
    key: options.issuerPrivateKey,
    ...(keyType === 'ec' ? {dsaEncoding: 'der' as const} : {}),
  });

  const cert = sequence(tbs, algId, bitString(signatureBytes));
  // Return the SUBJECT private key (callers use it to sign descendants); for a
  // self-issued cert this is the same key that signed it.
  return {der: cert, privateKey: subjectKey, ski};
}

/** Convenience: generate a self-signed root plus its key. */
export function mintRoot(
  subject: NameInput,
  alg: KeyAlg = 'rsa',
  extra: Partial<CertOptions> = {}
): {cert: {der: Buffer; privateKey: KeyObject; ski: string}; key: KeyObject} {
  const {privateKey} = generateKey(alg);
  const result = mintCert({subject, issuerPrivateKey: privateKey, isCa: true, pathLen: null, ...extra});
  return {cert: result, key: privateKey};
}

/** Mint a child cert (CA or leaf) with a freshly generated key. */
export function mintChild(
  subject: NameInput,
  issuer: {name: NameInput; key: KeyObject; ski: string},
  options: Partial<CertOptions> & {keyAlg?: KeyAlg; sigAlg?: SigAlg} = {}
): {der: Buffer; privateKey: KeyObject; ski: string} {
  const {privateKey} = generateKey(options.keyAlg ?? 'rsa');
  return mintCert({
    subject,
    subjectPublicKey: privateKey,
    issuerPrivateKey: issuer.key,
    issuerName: issuer.name,
    aki: issuer.ski,
    isCa: false,
    sigAlg: options.sigAlg ?? 'sha256',
    ...options,
  });
}

// Augment CertOptions with the internal subjectPublicKey field used above.
export type CertOptionsWithKey = CertOptions;

export function publicKeyOf(key: KeyObject): KeyObject {
  return createPublicKey(key);
}
