// Minimal DER/BER codec for X.509 structures. No third-party dependencies.
// Everything here works on Buffer/Uint8Array views of a certificate's raw bytes.

/**
 * Parse one TLV at `offset`.
 * @returns {{tag:number, constructed:boolean, start:number, headerEnd:number,
 *           valueStart:number, valueEnd:number, end:number, raw:Buffer}}
 */
export function parseTlv(buf, offset = 0) {
  const start = offset;
  const tagByte = buf[offset++];
  const tag = tagByte & 0x1f;
  const constructed = (tagByte & 0x20) === 0x20;
  if (tag === 0x1f) throw new Error('multi-byte tags not supported');
  let lenByte = buf[offset++];
  if ((lenByte & 0x80) === 0) {
    // short form
  } else {
    const n = lenByte & 0x7f;
    if (n === 0) throw new Error('indefinite length not supported (DER only)');
    if (offset + n > buf.length) throw new Error('truncated length');
    let len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[offset++];
    lenByte = len;
  }
  const len = lenByte;
  const valueStart = offset;
  const valueEnd = valueStart + len;
  if (valueEnd > buf.length) throw new Error('truncated value');
  return {
    tag, constructed, start, headerEnd: valueStart,
    valueStart, valueEnd, end: valueEnd,
    raw: buf.subarray(start, valueEnd),
  };
}

/** Iterate all TLV children inside a constructed value region. */
export function* children(buf, start, end) {
  let off = start;
  while (off < end) {
    const tlv = parseTlv(buf, off);
    yield tlv;
    off = tlv.end;
  }
  if (off !== end) throw new Error('children overflow');
}

export function childList(buf, start, end) {
  return [...children(buf, start, end)];
}

/** Value slice of a TLV. */
export const valueOf = (buf, tlv) => buf.subarray(tlv.valueStart, tlv.valueEnd);

// ---- DER tag constants (low tag number form) ----
export const TAG_BOOLEAN = 0x01;
export const TAG_INTEGER = 0x02;
export const TAG_BIT_STRING = 0x03;
export const TAG_OCTET_STRING = 0x04;
export const TAG_NULL = 0x05;
export const TAG_OID = 0x06;
export const TAG_UTF8_STRING = 0x0c;
export const TAG_PRINTABLE_STRING = 0x13;
export const TAG_TELETEX_STRING = 0x14;
export const TAG_IA5_STRING = 0x16;
export const TAG_UTC_TIME = 0x17;
export const TAG_GENERALIZED_TIME = 0x18;
export const TAG_BMP_STRING = 0x1e;
// Parsed tags are the tag NUMBER (class/constructed bits stripped).
export const TAG_SEQUENCE = 0x10;
export const TAG_SET = 0x11;
export const contextTag = (n, constructed = false) => n | (constructed ? 0x20 : 0);

// Full tag bytes used by the DER encoders.
export const DER_SEQUENCE = 0x30;
export const DER_SET = 0x31;
export const DER_CONTEXT = 0xa0; // constructed [0] base
export const derContext = (n) => 0xa0 | n;

// ---- primitives ----
export function encodeLen(len) {
  if (len < 0x80) return Buffer.from([len]);
  const bytes = [];
  let x = len;
  while (x) { bytes.unshift(x & 0xff); x = Math.floor(x / 256); }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

export function tlv(tag, value) {
  return Buffer.concat([Buffer.from([tag]), encodeLen(value.length), value]);
}

export const integer = (n) => {
  if (n === 0) return tlv(TAG_INTEGER, Buffer.from([0]));
  const bytes = [];
  let x = BigInt(n);
  const neg = x < 0n;
  while (x > 0n) { bytes.unshift(Number(x & 0xffn)); x >>= 8n; }
  if (!neg && bytes[0] & 0x80) bytes.unshift(0);
  return tlv(TAG_INTEGER, Buffer.from(bytes));
};

export const integerBuf = (b) => tlv(TAG_INTEGER, Buffer.isBuffer(b) ? b : Buffer.from(b));
export const boolean = (v) => tlv(TAG_BOOLEAN, Buffer.from([v ? 0xff : 0x00]));
export const bitString = (payload, unusedBits = 0) =>
  tlv(TAG_BIT_STRING, Buffer.concat([Buffer.from([unusedBits]), payload]));
export const octetString = (b) => tlv(TAG_OCTET_STRING, Buffer.from(b));
export const nullValue = () => Buffer.from([TAG_NULL, 0x00]);
export const oid = (s) => tlv(TAG_OID, encodeOid(s));
export const sequence = (...parts) => tlv(DER_SEQUENCE, Buffer.concat(parts.map((p) => Buffer.from(p))));
export const setOf = (...parts) => tlv(DER_SET, Buffer.concat(parts.map((p) => Buffer.from(p))));
export const contextExplicit = (n, content) => tlv(derContext(n), Buffer.from(content));
export const contextImplicit = (n, content) => tlv(0x80 | n, Buffer.from(content));
export const printable = (s) => tlv(TAG_PRINTABLE_STRING, Buffer.from(s, 'utf8'));
export const utf8 = (s) => tlv(TAG_UTF8_STRING, Buffer.from(s, 'utf8'));

export function encodeOid(oidStr) {
  const parts = oidStr.split('.').map((p) => BigInt(p));
  const out = [Number(parts[0] * 40n + parts[1])];
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i];
    const stack = [Number(v & 0x7fn)];
    v >>= 7n;
    while (v > 0n) { stack.unshift(Number(v & 0x7fn) | 0x80); v >>= 7n; }
    out.push(...stack);
  }
  return Buffer.from(out);
}

export function decodeOid(buf, start = 0, end = buf.length) {
  if (start >= end) throw new Error('empty OID');
  const first = buf[start++];
  const parts = [Math.floor(first / 40), first % 40];
  let cur = 0;
  for (let i = start; i < end; i++) {
    const b = buf[i];
    cur = cur * 128 + (b & 0x7f);
    if ((b & 0x80) === 0) { parts.push(cur); cur = 0; }
  }
  return parts.join('.');
}

/** Read an INTEGER's (small, non-negative) value. */
export function readInteger(buf, t) {
  let n = 0;
  for (let i = t.valueStart; i < t.valueEnd; i++) n = n * 256 + buf[i];
  return n;
}

// ---- time ----
// UTCTime: YYMMDDHHMMSSZ (years 1950-2049), GeneralizedTime: YYYYMMDDHHMMSSZ
export function encodeTime(date) {
  const p = {
    y: date.getUTCFullYear(), mo: date.getUTCMonth() + 1, d: date.getUTCDate(),
    h: date.getUTCHours(), mi: date.getUTCMinutes(), s: date.getUTCSeconds(),
  };
  const pad = (v, w = 2) => String(v).padStart(w, '0');
  const body = `${pad(p.mo)}${pad(p.d)}${pad(p.h)}${pad(p.mi)}${pad(p.s)}Z`;
  if (p.y >= 1950 && p.y < 2050) {
    return tlv(TAG_UTC_TIME, Buffer.from(String(p.y % 100).padStart(2, '0') + body, 'ascii'));
  }
  return tlv(TAG_GENERALIZED_TIME, Buffer.from(pad(p.y, 4) + body, 'ascii'));
}

export function decodeTime(buf, t) {
  let s = buf.subarray(t.valueStart, t.valueEnd).toString('ascii').replace(/[Zz]$/, '');
  let year;
  if (t.tag === TAG_UTC_TIME) {
    year = 2000 + Number(s.slice(0, 2));
    s = s.slice(2);
  } else {
    year = Number(s.slice(0, 4));
    s = s.slice(4);
  }
  const month = Number(s.slice(0, 2));
  const day = Number(s.slice(2, 4));
  const hour = Number(s.slice(4, 6));
  const minute = Number(s.slice(6, 8));
  const second = s.length >= 10 ? Number(s.slice(8, 10)) : 0;
  return new Date(Date.UTC(year, month - 1, day, hour, minute, second));
}
