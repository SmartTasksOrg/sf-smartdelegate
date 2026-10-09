// Canonical JSON (sorted keys, compact) and SHA-256 helpers.
//
// The audit hash chain, approval ids, bundle versions and bundle signatures
// depend on this being byte-identical in every port. Rules: keys sorted by
// code point, no whitespace, non-ASCII characters written as themselves,
// control characters as \u00xx (lowercase), integers only.
import { createHash } from 'node:crypto';
import { toInternal, write } from './json.mjs';

export { parse, stringify, write, toInternal, toPlain, quote, cmpCodePoint, jsonEq, JSONError } from './json.mjs';

/** Canonical text of a value in the internal model (integers are BigInt). */
export function canonInternal(value) {
  return write(value, { sortKeys: true });
}

/** Canonical text of an ordinary JavaScript value. Integer-valued Numbers and
 * BigInts are integers. A non-integer number has no canonical form; it is
 * written the way the reference writes it, but must not be relied on. */
export function canon(value) {
  return write(toInternal(value), { sortKeys: true });
}

const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

/** UTF-8 bytes of a string. A string that is not well-formed Unicode has no
 * UTF-8 encoding: that is an error here, as it is in the reference, instead
 * of a silent replacement character. */
export function utf8(text) {
  if (LONE_SURROGATE.test(text)) throw new TypeError('string is not well-formed Unicode (lone surrogate)');
  return Buffer.from(text, 'utf8');
}

const DECODER = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/** Strict UTF-8 decoding; a BOM is kept. Throws TypeError on invalid input. */
export function decodeUtf8(bytes) {
  return DECODER.decode(bytes);
}

export function sha256Hex(data) {
  return createHash('sha256').update(typeof data === 'string' ? utf8(data) : data).digest('hex');
}

export function hashInternal(value) {
  return sha256Hex(canonInternal(value));
}

export function hashValue(value) {
  return sha256Hex(canon(value));
}
