// (5a) JSON with exact integers, and canonical JSON.
import assert from 'node:assert/strict';
import test from 'node:test';
import { canon, hashValue, sha256Hex } from '../lib/canon.mjs';
import { JSONError, cmpCodePoint, floatRepr, keysOf, parse, stringify, toInternal, toPlain, write } from '../lib/json.mjs';

test('integers of any size survive parse and write exactly', () => {
  const text = '{"a":9223372036854775807,"b":-9223372036854775808,"c":9007199254740993,"d":123456789012345678901234567890,"e":0,"f":-0}';
  const v = parse(text);
  assert.equal(v.a, 9223372036854775807n);
  assert.equal(v.b, -9223372036854775808n);
  assert.equal(v.c, 9007199254740993n);          // 2^53 + 1: not representable as a Number
  assert.equal(typeof v.e, 'bigint');
  assert.equal(write(v), text.replace('"f":-0', '"f":0'));
  assert.equal(JSON.parse('9007199254740993'), 9007199254740992, 'the built-in parser really does lose this');
});

test('numbers with a fraction or an exponent are floats, and stay distinct from integers', () => {
  const v = parse('[1, 1.0, 1e2, -2.5, 1E+2, 0.1]');
  assert.deepEqual(v.map((x) => typeof x), ['bigint', 'number', 'number', 'number', 'number', 'number']);
  assert.equal(write(v), '[1,1.0,100.0,-2.5,100.0,0.1]');
});

test('floats are written the way the reference (Python repr) writes them', () => {
  const cases = [[1.5, '1.5'], [100, '100.0'], [1e16, '1e+16'], [1.5e16, '1.5e+16'], [123456789012345.6, '123456789012345.6'],
    [1e15, '1000000000000000.0'], [0.0001, '0.0001'], [0.00001, '1e-05'], [1.5e-7, '1.5e-07'], [-0, '-0.0'], [1e300, '1e+300'],
    [5e-324, '5e-324'], [0.1 + 0.2, '0.30000000000000004'], [NaN, 'NaN'], [Infinity, 'Infinity'], [-Infinity, '-Infinity']];
  for (const [x, text] of cases) assert.equal(floatRepr(x), text);
});

test('canonical JSON: keys sorted, compact, non-ASCII as itself, control characters escaped', () => {
  assert.equal(canon({ b: 1, a: [true, false, null, 'x'], c: { z: 1, y: 2 } }), '{"a":[true,false,null,"x"],"b":1,"c":{"y":2,"z":1}}');
  assert.equal(canon({ s: 'Zażółć gęślą jaźń — 日本語 😀' }), '{"s":"Zażółć gęślą jaźń — 日本語 😀"}');
  assert.equal(canon('\u0000\u0001\b\t\n\u000b\f\r\u001f "\\/\u007f '), '"\\u0000\\u0001\\b\\t\\n\\u000b\\f\\r\\u001f \\"\\\\/\u007f "');
  assert.equal(canon({}), '{}');
  assert.equal(canon([]), '[]');
  assert.equal(canon({ '': 1 }), '{"":1}');
});

test('canonical JSON: big integers are exact, from BigInt and from parsed text', () => {
  assert.equal(canon({ n: 9223372036854775807n, m: 2 ** 53, k: -5 }), '{"k":-5,"m":9007199254740992,"n":9223372036854775807}');
  assert.equal(canon(toPlain(parse('{"x":18446744073709551616}'))), '{"x":18446744073709551616}');
  assert.equal(stringify({ x: 12345678901234567890n }), '{"x":12345678901234567890}');
});

test('canonical JSON: keys sort by Unicode code point, not by UTF-16 unit', () => {
  // U+1F600 (surrogates D83D DE00) sorts after U+FF5E by code point, before it by UTF-16 unit
  const keys = ['\u{1F600}', '～', 'a', 'B', 'é', '10', '9', '\u007f', ''];
  const o = Object.fromEntries(keys.map((k, i) => [k, i]));
  const order = [...canon(o).matchAll(/"((?:[^"\\]|\\.)*)":/g)].map((m) => m[1]);
  assert.deepEqual(order, ['', '10', '9', 'B', 'a', '\u007f', 'é', '～', '\u{1F600}']);
  assert.ok(cmpCodePoint('～', '\u{1F600}') < 0);
  assert.ok(['～', '\u{1F600}'].sort()[0] === '\u{1F600}', 'the default sort gets this wrong');
  assert.ok(cmpCodePoint('ab', 'abc') < 0 && cmpCodePoint('abc', 'ab') > 0 && cmpCodePoint('x', 'x') === 0);
});

test('object keys like __proto__ and constructor are ordinary keys', () => {
  const v = parse('{"__proto__":{"polluted":true},"constructor":1,"toString":2}');
  assert.equal(Object.getPrototypeOf(v), null);
  assert.equal(write(v, { sortKeys: true }), '{"__proto__":{"polluted":true},"constructor":1,"toString":2}');
  assert.equal({}.polluted, undefined);
  const plain = toPlain(v);
  assert.equal(Object.getPrototypeOf(plain), Object.prototype);
  assert.deepEqual(Object.keys(plain).sort(), ['__proto__', 'constructor', 'toString']);
  assert.equal(canon(plain), '{"__proto__":{"polluted":true},"constructor":1,"toString":2}');
});

test('strings: escapes, surrogate pairs and strictness', () => {
  assert.equal(parse('"a\\u00e9\\ud83d\\ude00\\n\\"\\\\\\/"'), 'aé😀\n"\\/');
  assert.equal(parse(' \t\r\n"x" \n'), 'x');
  for (const bad of ['"a\nb"', '"\\x41"', '"\\u12"', '"abc', '01', '1.', '.5', '+1', '[1,]', '{"a":1,}', '{a:1}', "'a'", '', '1 2', 'nul', '  1', '[1', '{"a"}', '-']) {
    assert.throws(() => parse(bad), JSONError, JSON.stringify(bad));
  }
  assert.equal(write(parse('{"a":1,"a":2}')), '{"a":2}', 'the last duplicate key wins, as in the reference');
});

test('deep nesting is an error, not a crash', () => {
  assert.throws(() => parse('['.repeat(100000) + ']'.repeat(100000)), JSONError);
  let deep = [];
  for (let i = 0; i < 100000; i++) deep = [deep];
  assert.throws(() => toInternal(deep), RangeError);
  assert.doesNotThrow(() => parse('['.repeat(500) + ']'.repeat(500)));
});

test('write options: ascii escaping and indentation match Python json.dumps', () => {
  const v = parse('{"k":"é😀","l":[1,{"a":[]}],"e":{}}');
  assert.equal(write(v, { ascii: true }), '{"k":"\\u00e9\\ud83d\\ude00","l":[1,{"a":[]}],"e":{}}');
  assert.equal(write(v, { indent: 2 }), '{\n  "k": "é😀",\n  "l": [\n    1,\n    {\n      "a": []\n    }\n  ],\n  "e": {}\n}');
});

test('values JSON cannot carry are refused', () => {
  assert.throws(() => canon({ f() {} }), TypeError);
  assert.throws(() => canon(new Map()), TypeError);
  assert.throws(() => canon(Symbol('x')), TypeError);
  assert.equal(canon({ a: undefined, b: [undefined] }), '{"b":[null]}');
});

test('hashes are over the UTF-8 bytes; a lone surrogate has none', () => {
  assert.equal(sha256Hex(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(hashValue({ b: 'é', a: 1 }), sha256Hex(Buffer.from('{"a":1,"b":"é"}', 'utf8')));
  assert.throws(() => hashValue({ a: '\ud800' }), TypeError);
  assert.throws(() => hashValue({ a: 'x\udc00y' }), TypeError);
  assert.doesNotThrow(() => hashValue({ a: '😀' }));
});

test('member order: parse and write keep the written order, also for integer-like keys', () => {
  // JavaScript itself would list "9" and "10" first
  const text = '{"b":1,"10":2,"9":3,"a":{"2":true,"x":[{"1":1,"0":0}],"1":false},"00":4,"-1":5,"4294967296":6}';
  assert.deepEqual(Object.keys(JSON.parse(text)).slice(0, 2), ['9', '10'], 'what the built-in parser does');
  const v = parse(text);
  assert.equal(write(v), text);
  assert.deepEqual(keysOf(v), ['b', '10', '9', 'a', '00', '-1', '4294967296']);
  assert.equal(write(v, { indent: 2 }).replace(/\s+/g, '').replaceAll('":', '":'), text);
  assert.equal(write(v, { sortKeys: true }), '{"-1":5,"00":4,"10":2,"4294967296":6,"9":3,"a":{"1":false,"2":true,"x":[{"0":0,"1":1}]},"b":1}', 'canonical order is by code point');
  // a duplicate key keeps its first position and its last value, as in the reference
  assert.equal(write(parse('{"2":"a","1":"b","2":"c"}')), '{"2":"c","1":"b"}');
  // keys added or removed afterwards
  v.z = 1n;
  delete v['10'];
  assert.deepEqual(keysOf(v), ['b', '9', 'a', '00', '-1', '4294967296', 'z']);
  // objects without such keys carry no extra bookkeeping
  assert.equal(Object.getOwnPropertySymbols(parse('{"a":1,"b":{"c":2}}')).length, 0);
});
