/**
 * Minimal ASN.1 / DER toolkit, written on top of Buffer.
 * Only what X.509 parsing and test-certificate minting needs.
 */

export const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTF8_STRING: 0x0c,
  PRINTABLE_STRING: 0x13,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
  SEQUENCE: 0x30,
  SET: 0x31,
} as const;

export type DerNode = {
  tag: number;
  content: Buffer;
  raw: Buffer;
  children: DerNode[];
};

function readLength(buf: Buffer, offset: number): {length: number; bytes: number} {
  const first = buf[offset];
  if ((first & 0x80) === 0) return {length: first, bytes: 1};
  const numBytes = first & 0x7f;
  let length = 0;
  for (let i = 1; i <= numBytes; i++) length = length * 256 + buf[offset + i];
  return {length, bytes: 1 + numBytes};
}

export function encodeLength(length: number): Buffer {
  if (length < 0x80) return Buffer.from([length]);
  const bytes: number[] = [];
  let value = length;
  while (value > 0) {
    bytes.unshift(value & 0xff);
    value = Math.floor(value / 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

export function tlv(tag: number, content: Buffer | number[] | string): Buffer {
  const body = Buffer.isBuffer(content) ? content : Buffer.from(content as number[]);
  return Buffer.concat([Buffer.from([tag]), encodeLength(body.length), body]);
}

export function sequence(...parts: Buffer[]): Buffer {
  return tlv(TAG.SEQUENCE, Buffer.concat(parts));
}

export function set(...parts: Buffer[]): Buffer {
  return tlv(TAG.SET, Buffer.concat(parts));
}

export function integer(value: number | Buffer): Buffer {
  if (Buffer.isBuffer(value)) {
    let body = value;
    // strip leading zero bytes, then make sure high bit is not set
    body = body.subarray(body.findIndex(b => b !== 0) === -1 ? body.length - 1 : body.findIndex(b => b !== 0));
    if (body[0] & 0x80) body = Buffer.concat([Buffer.from([0]), body]);
    return tlv(TAG.INTEGER, body.length === 0 ? Buffer.from([0]) : body);
  }
  if (value === 0) return tlv(TAG.INTEGER, [0]);
  const bytes: number[] = [];
  let n = value;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n = Math.floor(n / 256);
  }
  if (bytes[0] & 0x80) bytes.unshift(0);
  return tlv(TAG.INTEGER, bytes);
}

export function boolean(value: boolean): Buffer {
  return tlv(TAG.BOOLEAN, [value ? 0xff : 0x00]);
}

export function bitString(content: Buffer, unusedBits = 0): Buffer {
  return tlv(TAG.BIT_STRING, Buffer.concat([Buffer.from([unusedBits]), content]));
}

export function octetString(content: Buffer): Buffer {
  return tlv(TAG.OCTET_STRING, content);
}

export function nullValue(): Buffer {
  return tlv(TAG.NULL, []);
}

export function oid(value: string): Buffer {
  const arcs = value.split('.').map(Number);
  const out: number[] = [40 * arcs[0] + arcs[1]];
  for (let i = 2; i < arcs.length; i++) {
    const arc = arcs[i];
    const chunks = [arc & 0x7f];
    let rest = arc >> 7;
    while (rest > 0) {
      chunks.unshift((rest & 0x7f) | 0x80);
      rest >>= 7;
    }
    out.push(...chunks);
  }
  return tlv(TAG.OID, out);
}

/** Parse one DER TLV at `offset`. */
export function parseNode(buf: Buffer, offset = 0): DerNode & {end: number} {
  const tag = buf[offset];
  const lenInfo = readLength(buf, offset + 1);
  const contentStart = offset + 1 + lenInfo.bytes;
  const end = contentStart + lenInfo.length;
  const content = buf.subarray(contentStart, end);
  const raw = buf.subarray(offset, end);
  const constructed = (tag & 0x20) !== 0;
  let children: DerNode[] = [];
  if (constructed || tag === TAG.SEQUENCE || tag ===(TAG.SET)) {
    try {
      children = parseAll(content);
    } catch {
      children = [];
    }
  }
  return {tag, content, raw, children, end};
}

/** Parse every TLV contained in a constructed node's content. */
export function parseAll(content: Buffer): DerNode[] {
  const nodes: DerNode[] = [];
  let offset = 0;
  while (offset < content.length) {
    const node = parseNode(content, offset);
    nodes.push(node);
    offset = node.end;
  }
  return nodes;
}

export function decodeOid(buf: Buffer): string {
  if (buf.length === 0) return '';
  const arcs = [Math.floor(buf[0] / 40), buf[0] % 40];
  let value = 0;
  for (let i = 1; i < buf.length; i++) {
    value = value * 128 + (buf[i] & 0x7f);
    if ((buf[i] & 0x80) === 0) {
      arcs.push(value);
      value = 0;
    }
  }
  return arcs.join('.');
}

// ----- well-known OIDs -------------------------------------------------------

export const OID = {
  // name attributes
  CN: '2.5.4.3',
  C: '2.5.4.6',
  O: '2.5.4.10',
  OU: '2.5.4.11',
  // certificate extensions
  SKI: '2.5.29.14',
  AKI: '2.5.29.35',
  KEY_USAGE: '2.5.29.15',
  BASIC_CONSTRAINTS: '2.5.29.19',
  // signature algorithms
  RSA_SHA256: '1.2.840.113549.1.1.11',
  RSA_SHA384: '1.2.840.113549.1.1.12',
  RSA_SHA512: '1.2.840.113549.1.1.13',
  RSA_SHA1: '1.2.840.113549.1.1.5',
  EC_SHA1: '1.2.840.10045.4.1',
  EC_SHA256: '1.2.840.10045.4.3.2',
  EC_SHA384: '1.2.840.10045.4.3.3',
  // key types
  RSA_ENCRYPTION: '1.2.840.113549.1.1.1',
  EC_PUBLIC_KEY: '1.2.840.10045.2.1',
  EC_P256: '1.2.840.10045.3.1.7',
  EC_P384: '1.3.132.0.34',
} as const;

/** RFC 5280 display form of an X.500 Name node (e.g. "CN=Root CA,O=Lab"). */
const ATTR_LABELS: Record<string, string> = {
  [OID.CN]: 'CN',
  [OID.C]: 'C',
  [OID.O]: 'O',
  [OID.OU]: 'OU',
  '2.5.4.5': 'serialNumber',
  '1.2.840.113549.1.9.1': 'emailAddress',
};

function readDirectoryString(node: DerNode): string {
  return node.content.toString('utf8');
}

export function nameToText(nameNode: DerNode): string {
  const parts: string[] = [];
  for (const rdn of nameNode.children) {
    for (const attrTypeAndValue of rdn.children) {
      const [oidNode, valueNode] = attrTypeAndValue.children;
      const attrOid = decodeOid(oidNode.content);
      const label = ATTR_LABELS[attrOid] ?? attrOid;
      parts.push(`${label}=${readDirectoryString(valueNode)}`);
    }
  }
  return parts.join(',');
}

export function namesEqual(a: Buffer, b: Buffer): boolean {
  return a.equals(b);
}
