var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// node_modules/@noble/hashes/esm/utils.js
function isBytes(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}
function anumber(n) {
  if (!Number.isSafeInteger(n) || n < 0)
    throw new Error("positive integer expected, got " + n);
}
function abytes(b, ...lengths) {
  if (!isBytes(b))
    throw new Error("Uint8Array expected");
  if (lengths.length > 0 && !lengths.includes(b.length))
    throw new Error("Uint8Array expected of length " + lengths + ", got length=" + b.length);
}
function aexists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("Hash instance has been destroyed");
  if (checkFinished && instance.finished)
    throw new Error("Hash#digest() has already been called");
}
function aoutput(out, instance) {
  abytes(out);
  const min = instance.outputLen;
  if (out.length < min) {
    throw new Error("digestInto() expects output buffer of length at least " + min);
  }
}
function u8(arr) {
  return new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
}
function u32(arr) {
  return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
function clean(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
function rotr(word, shift) {
  return word << 32 - shift | word >>> shift;
}
function byteSwap(word) {
  return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
}
function byteSwap32(arr) {
  for (let i = 0; i < arr.length; i++) {
    arr[i] = byteSwap(arr[i]);
  }
  return arr;
}
function utf8ToBytes(str) {
  if (typeof str !== "string")
    throw new Error("string expected");
  return new Uint8Array(new TextEncoder().encode(str));
}
function toBytes(data) {
  if (typeof data === "string")
    data = utf8ToBytes(data);
  abytes(data);
  return data;
}
function createXOFer(hashCons) {
  const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
  const tmp = hashCons({});
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = (opts) => hashCons(opts);
  return hashC;
}
var isLE, swap8IfBE, swap32IfBE, Hash;
var init_utils = __esm({
  "node_modules/@noble/hashes/esm/utils.js"() {
    isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
    swap8IfBE = isLE ? (n) => n : (n) => byteSwap(n);
    swap32IfBE = isLE ? (u) => u : byteSwap32;
    Hash = class {
    };
  }
});

// node_modules/@noble/hashes/esm/_md.js
var SHA256_IV;
var init_md = __esm({
  "node_modules/@noble/hashes/esm/_md.js"() {
    SHA256_IV = /* @__PURE__ */ Uint32Array.from([
      1779033703,
      3144134277,
      1013904242,
      2773480762,
      1359893119,
      2600822924,
      528734635,
      1541459225
    ]);
  }
});

// node_modules/@noble/hashes/esm/_u64.js
function fromBig(n, le = false) {
  if (le)
    return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
  return { h: Number(n >> _32n & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
var U32_MASK64, _32n;
var init_u64 = __esm({
  "node_modules/@noble/hashes/esm/_u64.js"() {
    U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
    _32n = /* @__PURE__ */ BigInt(32);
  }
});

// node_modules/@noble/hashes/esm/_blake.js
function G1s(a, b, c, d, x) {
  a = a + b + x | 0;
  d = rotr(d ^ a, 16);
  c = c + d | 0;
  b = rotr(b ^ c, 12);
  return { a, b, c, d };
}
function G2s(a, b, c, d, x) {
  a = a + b + x | 0;
  d = rotr(d ^ a, 8);
  c = c + d | 0;
  b = rotr(b ^ c, 7);
  return { a, b, c, d };
}
var init_blake = __esm({
  "node_modules/@noble/hashes/esm/_blake.js"() {
    init_utils();
  }
});

// node_modules/@noble/hashes/esm/blake2.js
function compress(s, offset, msg, rounds, v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) {
  let j = 0;
  for (let i = 0; i < rounds; i++) {
    ({ a: v0, b: v4, c: v8, d: v12 } = G1s(v0, v4, v8, v12, msg[offset + s[j++]]));
    ({ a: v0, b: v4, c: v8, d: v12 } = G2s(v0, v4, v8, v12, msg[offset + s[j++]]));
    ({ a: v1, b: v5, c: v9, d: v13 } = G1s(v1, v5, v9, v13, msg[offset + s[j++]]));
    ({ a: v1, b: v5, c: v9, d: v13 } = G2s(v1, v5, v9, v13, msg[offset + s[j++]]));
    ({ a: v2, b: v6, c: v10, d: v14 } = G1s(v2, v6, v10, v14, msg[offset + s[j++]]));
    ({ a: v2, b: v6, c: v10, d: v14 } = G2s(v2, v6, v10, v14, msg[offset + s[j++]]));
    ({ a: v3, b: v7, c: v11, d: v15 } = G1s(v3, v7, v11, v15, msg[offset + s[j++]]));
    ({ a: v3, b: v7, c: v11, d: v15 } = G2s(v3, v7, v11, v15, msg[offset + s[j++]]));
    ({ a: v0, b: v5, c: v10, d: v15 } = G1s(v0, v5, v10, v15, msg[offset + s[j++]]));
    ({ a: v0, b: v5, c: v10, d: v15 } = G2s(v0, v5, v10, v15, msg[offset + s[j++]]));
    ({ a: v1, b: v6, c: v11, d: v12 } = G1s(v1, v6, v11, v12, msg[offset + s[j++]]));
    ({ a: v1, b: v6, c: v11, d: v12 } = G2s(v1, v6, v11, v12, msg[offset + s[j++]]));
    ({ a: v2, b: v7, c: v8, d: v13 } = G1s(v2, v7, v8, v13, msg[offset + s[j++]]));
    ({ a: v2, b: v7, c: v8, d: v13 } = G2s(v2, v7, v8, v13, msg[offset + s[j++]]));
    ({ a: v3, b: v4, c: v9, d: v14 } = G1s(v3, v4, v9, v14, msg[offset + s[j++]]));
    ({ a: v3, b: v4, c: v9, d: v14 } = G2s(v3, v4, v9, v14, msg[offset + s[j++]]));
  }
  return { v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15 };
}
var BLAKE2;
var init_blake2 = __esm({
  "node_modules/@noble/hashes/esm/blake2.js"() {
    init_blake();
    init_utils();
    BLAKE2 = class extends Hash {
      constructor(blockLen, outputLen) {
        super();
        this.finished = false;
        this.destroyed = false;
        this.length = 0;
        this.pos = 0;
        anumber(blockLen);
        anumber(outputLen);
        this.blockLen = blockLen;
        this.outputLen = outputLen;
        this.buffer = new Uint8Array(blockLen);
        this.buffer32 = u32(this.buffer);
      }
      update(data) {
        aexists(this);
        data = toBytes(data);
        abytes(data);
        const { blockLen, buffer, buffer32 } = this;
        const len = data.length;
        const offset = data.byteOffset;
        const buf = data.buffer;
        for (let pos = 0; pos < len; ) {
          if (this.pos === blockLen) {
            swap32IfBE(buffer32);
            this.compress(buffer32, 0, false);
            swap32IfBE(buffer32);
            this.pos = 0;
          }
          const take = Math.min(blockLen - this.pos, len - pos);
          const dataOffset = offset + pos;
          if (take === blockLen && !(dataOffset % 4) && pos + take < len) {
            const data32 = new Uint32Array(buf, dataOffset, Math.floor((len - pos) / 4));
            swap32IfBE(data32);
            for (let pos32 = 0; pos + blockLen < len; pos32 += buffer32.length, pos += blockLen) {
              this.length += blockLen;
              this.compress(data32, pos32, false);
            }
            swap32IfBE(data32);
            continue;
          }
          buffer.set(data.subarray(pos, pos + take), this.pos);
          this.pos += take;
          this.length += take;
          pos += take;
        }
        return this;
      }
      digestInto(out) {
        aexists(this);
        aoutput(out, this);
        const { pos, buffer32 } = this;
        this.finished = true;
        clean(this.buffer.subarray(pos));
        swap32IfBE(buffer32);
        this.compress(buffer32, 0, true);
        swap32IfBE(buffer32);
        const out32 = u32(out);
        this.get().forEach((v, i) => out32[i] = swap8IfBE(v));
      }
      digest() {
        const { buffer, outputLen } = this;
        this.digestInto(buffer);
        const res = buffer.slice(0, outputLen);
        this.destroy();
        return res;
      }
      _cloneInto(to) {
        const { buffer, length, finished, destroyed, outputLen, pos } = this;
        to || (to = new this.constructor({ dkLen: outputLen }));
        to.set(...this.get());
        to.buffer.set(buffer);
        to.destroyed = destroyed;
        to.finished = finished;
        to.length = length;
        to.pos = pos;
        to.outputLen = outputLen;
        return to;
      }
      clone() {
        return this._cloneInto();
      }
    };
  }
});

// node_modules/@noble/hashes/esm/blake3.js
var blake3_exports = {};
__export(blake3_exports, {
  BLAKE3: () => BLAKE3,
  blake3: () => blake3
});
var B3_Flags, B3_IV, B3_SIGMA, BLAKE3, blake3;
var init_blake3 = __esm({
  "node_modules/@noble/hashes/esm/blake3.js"() {
    init_md();
    init_u64();
    init_blake2();
    init_utils();
    B3_Flags = {
      CHUNK_START: 1,
      CHUNK_END: 2,
      PARENT: 4,
      ROOT: 8,
      KEYED_HASH: 16,
      DERIVE_KEY_CONTEXT: 32,
      DERIVE_KEY_MATERIAL: 64
    };
    B3_IV = SHA256_IV.slice();
    B3_SIGMA = /* @__PURE__ */ (() => {
      const Id = Array.from({ length: 16 }, (_, i) => i);
      const permute = (arr) => [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8].map((i) => arr[i]);
      const res = [];
      for (let i = 0, v = Id; i < 7; i++, v = permute(v))
        res.push(...v);
      return Uint8Array.from(res);
    })();
    BLAKE3 = class _BLAKE3 extends BLAKE2 {
      constructor(opts = {}, flags = 0) {
        super(64, opts.dkLen === void 0 ? 32 : opts.dkLen);
        this.chunkPos = 0;
        this.chunksDone = 0;
        this.flags = 0 | 0;
        this.stack = [];
        this.posOut = 0;
        this.bufferOut32 = new Uint32Array(16);
        this.chunkOut = 0;
        this.enableXOF = true;
        const { key, context } = opts;
        const hasContext = context !== void 0;
        if (key !== void 0) {
          if (hasContext)
            throw new Error('Only "key" or "context" can be specified at same time');
          const k = toBytes(key).slice();
          abytes(k, 32);
          this.IV = u32(k);
          swap32IfBE(this.IV);
          this.flags = flags | B3_Flags.KEYED_HASH;
        } else if (hasContext) {
          const ctx = toBytes(context);
          const contextKey = new _BLAKE3({ dkLen: 32 }, B3_Flags.DERIVE_KEY_CONTEXT).update(ctx).digest();
          this.IV = u32(contextKey);
          swap32IfBE(this.IV);
          this.flags = flags | B3_Flags.DERIVE_KEY_MATERIAL;
        } else {
          this.IV = B3_IV.slice();
          this.flags = flags;
        }
        this.state = this.IV.slice();
        this.bufferOut = u8(this.bufferOut32);
      }
      // Unused
      get() {
        return [];
      }
      set() {
      }
      b2Compress(counter, flags, buf, bufPos = 0) {
        const { state: s, pos } = this;
        const { h: h2, l } = fromBig(BigInt(counter), true);
        const { v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15 } = compress(B3_SIGMA, bufPos, buf, 7, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], B3_IV[0], B3_IV[1], B3_IV[2], B3_IV[3], h2, l, pos, flags);
        s[0] = v0 ^ v8;
        s[1] = v1 ^ v9;
        s[2] = v2 ^ v10;
        s[3] = v3 ^ v11;
        s[4] = v4 ^ v12;
        s[5] = v5 ^ v13;
        s[6] = v6 ^ v14;
        s[7] = v7 ^ v15;
      }
      compress(buf, bufPos = 0, isLast = false) {
        let flags = this.flags;
        if (!this.chunkPos)
          flags |= B3_Flags.CHUNK_START;
        if (this.chunkPos === 15 || isLast)
          flags |= B3_Flags.CHUNK_END;
        if (!isLast)
          this.pos = this.blockLen;
        this.b2Compress(this.chunksDone, flags, buf, bufPos);
        this.chunkPos += 1;
        if (this.chunkPos === 16 || isLast) {
          let chunk = this.state;
          this.state = this.IV.slice();
          for (let last, chunks = this.chunksDone + 1; isLast || !(chunks & 1); chunks >>= 1) {
            if (!(last = this.stack.pop()))
              break;
            this.buffer32.set(last, 0);
            this.buffer32.set(chunk, 8);
            this.pos = this.blockLen;
            this.b2Compress(0, this.flags | B3_Flags.PARENT, this.buffer32, 0);
            chunk = this.state;
            this.state = this.IV.slice();
          }
          this.chunksDone++;
          this.chunkPos = 0;
          this.stack.push(chunk);
        }
        this.pos = 0;
      }
      _cloneInto(to) {
        to = super._cloneInto(to);
        const { IV, flags, state, chunkPos, posOut, chunkOut, stack, chunksDone } = this;
        to.state.set(state.slice());
        to.stack = stack.map((i) => Uint32Array.from(i));
        to.IV.set(IV);
        to.flags = flags;
        to.chunkPos = chunkPos;
        to.chunksDone = chunksDone;
        to.posOut = posOut;
        to.chunkOut = chunkOut;
        to.enableXOF = this.enableXOF;
        to.bufferOut32.set(this.bufferOut32);
        return to;
      }
      destroy() {
        this.destroyed = true;
        clean(this.state, this.buffer32, this.IV, this.bufferOut32);
        clean(...this.stack);
      }
      // Same as b2Compress, but doesn't modify state and returns 16 u32 array (instead of 8)
      b2CompressOut() {
        const { state: s, pos, flags, buffer32, bufferOut32: out32 } = this;
        const { h: h2, l } = fromBig(BigInt(this.chunkOut++));
        swap32IfBE(buffer32);
        const { v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15 } = compress(B3_SIGMA, 0, buffer32, 7, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], B3_IV[0], B3_IV[1], B3_IV[2], B3_IV[3], l, h2, pos, flags);
        out32[0] = v0 ^ v8;
        out32[1] = v1 ^ v9;
        out32[2] = v2 ^ v10;
        out32[3] = v3 ^ v11;
        out32[4] = v4 ^ v12;
        out32[5] = v5 ^ v13;
        out32[6] = v6 ^ v14;
        out32[7] = v7 ^ v15;
        out32[8] = s[0] ^ v8;
        out32[9] = s[1] ^ v9;
        out32[10] = s[2] ^ v10;
        out32[11] = s[3] ^ v11;
        out32[12] = s[4] ^ v12;
        out32[13] = s[5] ^ v13;
        out32[14] = s[6] ^ v14;
        out32[15] = s[7] ^ v15;
        swap32IfBE(buffer32);
        swap32IfBE(out32);
        this.posOut = 0;
      }
      finish() {
        if (this.finished)
          return;
        this.finished = true;
        clean(this.buffer.subarray(this.pos));
        let flags = this.flags | B3_Flags.ROOT;
        if (this.stack.length) {
          flags |= B3_Flags.PARENT;
          swap32IfBE(this.buffer32);
          this.compress(this.buffer32, 0, true);
          swap32IfBE(this.buffer32);
          this.chunksDone = 0;
          this.pos = this.blockLen;
        } else {
          flags |= (!this.chunkPos ? B3_Flags.CHUNK_START : 0) | B3_Flags.CHUNK_END;
        }
        this.flags = flags;
        this.b2CompressOut();
      }
      writeInto(out) {
        aexists(this, false);
        abytes(out);
        this.finish();
        const { blockLen, bufferOut } = this;
        for (let pos = 0, len = out.length; pos < len; ) {
          if (this.posOut >= blockLen)
            this.b2CompressOut();
          const take = Math.min(blockLen - this.posOut, len - pos);
          out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
          this.posOut += take;
          pos += take;
        }
        return out;
      }
      xofInto(out) {
        if (!this.enableXOF)
          throw new Error("XOF is not possible after digest call");
        return this.writeInto(out);
      }
      xof(bytes) {
        anumber(bytes);
        return this.xofInto(new Uint8Array(bytes));
      }
      digestInto(out) {
        aoutput(out, this);
        if (this.finished)
          throw new Error("digest() was already called");
        this.enableXOF = false;
        this.writeInto(out);
        this.destroy();
        return out;
      }
      digest() {
        return this.digestInto(new Uint8Array(this.outputLen));
      }
    };
    blake3 = /* @__PURE__ */ createXOFer((opts) => new BLAKE3(opts));
  }
});

// node_modules/@noble/ed25519/index.js
var ed25519_exports = {};
__export(ed25519_exports, {
  CURVE: () => ed25519_CURVE,
  ExtendedPoint: () => Point,
  Point: () => Point,
  etc: () => etc,
  getPublicKey: () => getPublicKey,
  getPublicKeyAsync: () => getPublicKeyAsync,
  sign: () => sign,
  signAsync: () => signAsync,
  utils: () => utils,
  verify: () => verify,
  verifyAsync: () => verifyAsync
});
var ed25519_CURVE, P, N, Gx, Gy, _a, _d, h, L, L2, err, isBig, isStr, isBytes2, abytes2, u8n, u8fr, padh, bytesToHex, C, _ch, hexToBytes, toU8, cr, subtle, concatBytes, randomBytes, big, arange, M, modN, invert, callHash, apoint, B256, Point, G, I, numTo32bLE, bytesToNumLE, pow2, pow_2_252_3, RM1, uvRatio, modL_LE, sha512a, sha512s, hash2extK, getExtendedPublicKeyAsync, getExtendedPublicKey, getPublicKeyAsync, getPublicKey, hashFinishA, hashFinishS, _sign, signAsync, sign, veriOpts, _verify, verifyAsync, verify, etc, utils, W, scalarBits, pwindows, pwindowSize, precompute, Gpows, ctneg, wNAF;
var init_ed25519 = __esm({
  "node_modules/@noble/ed25519/index.js"() {
    ed25519_CURVE = {
      p: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffedn,
      n: 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn,
      h: 8n,
      a: 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffecn,
      d: 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3n,
      Gx: 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51an,
      Gy: 0x6666666666666666666666666666666666666666666666666666666666666658n
    };
    ({ p: P, n: N, Gx, Gy, a: _a, d: _d } = ed25519_CURVE);
    h = 8n;
    L = 32;
    L2 = 64;
    err = (m = "") => {
      throw new Error(m);
    };
    isBig = (n) => typeof n === "bigint";
    isStr = (s) => typeof s === "string";
    isBytes2 = (a) => a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
    abytes2 = (a, l) => !isBytes2(a) || typeof l === "number" && l > 0 && a.length !== l ? err("Uint8Array expected") : a;
    u8n = (len) => new Uint8Array(len);
    u8fr = (buf) => Uint8Array.from(buf);
    padh = (n, pad) => n.toString(16).padStart(pad, "0");
    bytesToHex = (b) => Array.from(abytes2(b)).map((e) => padh(e, 2)).join("");
    C = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
    _ch = (ch) => {
      if (ch >= C._0 && ch <= C._9)
        return ch - C._0;
      if (ch >= C.A && ch <= C.F)
        return ch - (C.A - 10);
      if (ch >= C.a && ch <= C.f)
        return ch - (C.a - 10);
      return;
    };
    hexToBytes = (hex) => {
      const e = "hex invalid";
      if (!isStr(hex))
        return err(e);
      const hl = hex.length;
      const al = hl / 2;
      if (hl % 2)
        return err(e);
      const array = u8n(al);
      for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
        const n1 = _ch(hex.charCodeAt(hi));
        const n2 = _ch(hex.charCodeAt(hi + 1));
        if (n1 === void 0 || n2 === void 0)
          return err(e);
        array[ai] = n1 * 16 + n2;
      }
      return array;
    };
    toU8 = (a, len) => abytes2(isStr(a) ? hexToBytes(a) : u8fr(abytes2(a)), len);
    cr = () => globalThis?.crypto;
    subtle = () => cr()?.subtle ?? err("crypto.subtle must be defined");
    concatBytes = (...arrs) => {
      const r = u8n(arrs.reduce((sum, a) => sum + abytes2(a).length, 0));
      let pad = 0;
      arrs.forEach((a) => {
        r.set(a, pad);
        pad += a.length;
      });
      return r;
    };
    randomBytes = (len = L) => {
      const c = cr();
      return c.getRandomValues(u8n(len));
    };
    big = BigInt;
    arange = (n, min, max, msg = "bad number: out of range") => isBig(n) && min <= n && n < max ? n : err(msg);
    M = (a, b = P) => {
      const r = a % b;
      return r >= 0n ? r : b + r;
    };
    modN = (a) => M(a, N);
    invert = (num, md) => {
      if (num === 0n || md <= 0n)
        err("no inverse n=" + num + " mod=" + md);
      let a = M(num, md), b = md, x = 0n, y = 1n, u = 1n, v = 0n;
      while (a !== 0n) {
        const q = b / a, r = b % a;
        const m = x - u * q, n = y - v * q;
        b = a, a = r, x = u, y = v, u = m, v = n;
      }
      return b === 1n ? M(x, md) : err("no inverse");
    };
    callHash = (name) => {
      const fn = etc[name];
      if (typeof fn !== "function")
        err("hashes." + name + " not set");
      return fn;
    };
    apoint = (p) => p instanceof Point ? p : err("Point expected");
    B256 = 2n ** 256n;
    Point = class _Point {
      static BASE;
      static ZERO;
      ex;
      ey;
      ez;
      et;
      constructor(ex, ey, ez, et) {
        const max = B256;
        this.ex = arange(ex, 0n, max);
        this.ey = arange(ey, 0n, max);
        this.ez = arange(ez, 1n, max);
        this.et = arange(et, 0n, max);
        Object.freeze(this);
      }
      static fromAffine(p) {
        return new _Point(p.x, p.y, 1n, M(p.x * p.y));
      }
      /** RFC8032 5.1.3: Uint8Array to Point. */
      static fromBytes(hex, zip215 = false) {
        const d = _d;
        const normed = u8fr(abytes2(hex, L));
        const lastByte = hex[31];
        normed[31] = lastByte & ~128;
        const y = bytesToNumLE(normed);
        const max = zip215 ? B256 : P;
        arange(y, 0n, max);
        const y2 = M(y * y);
        const u = M(y2 - 1n);
        const v = M(d * y2 + 1n);
        let { isValid, value: x } = uvRatio(u, v);
        if (!isValid)
          err("bad point: y not sqrt");
        const isXOdd = (x & 1n) === 1n;
        const isLastByteOdd = (lastByte & 128) !== 0;
        if (!zip215 && x === 0n && isLastByteOdd)
          err("bad point: x==0, isLastByteOdd");
        if (isLastByteOdd !== isXOdd)
          x = M(-x);
        return new _Point(x, y, 1n, M(x * y));
      }
      /** Checks if the point is valid and on-curve. */
      assertValidity() {
        const a = _a;
        const d = _d;
        const p = this;
        if (p.is0())
          throw new Error("bad point: ZERO");
        const { ex: X, ey: Y, ez: Z, et: T } = p;
        const X2 = M(X * X);
        const Y2 = M(Y * Y);
        const Z2 = M(Z * Z);
        const Z4 = M(Z2 * Z2);
        const aX2 = M(X2 * a);
        const left = M(Z2 * M(aX2 + Y2));
        const right = M(Z4 + M(d * M(X2 * Y2)));
        if (left !== right)
          throw new Error("bad point: equation left != right (1)");
        const XY = M(X * Y);
        const ZT = M(Z * T);
        if (XY !== ZT)
          throw new Error("bad point: equation left != right (2)");
        return this;
      }
      /** Equality check: compare points P&Q. */
      equals(other) {
        const { ex: X1, ey: Y1, ez: Z1 } = this;
        const { ex: X2, ey: Y2, ez: Z2 } = apoint(other);
        const X1Z2 = M(X1 * Z2);
        const X2Z1 = M(X2 * Z1);
        const Y1Z2 = M(Y1 * Z2);
        const Y2Z1 = M(Y2 * Z1);
        return X1Z2 === X2Z1 && Y1Z2 === Y2Z1;
      }
      is0() {
        return this.equals(I);
      }
      /** Flip point over y coordinate. */
      negate() {
        return new _Point(M(-this.ex), this.ey, this.ez, M(-this.et));
      }
      /** Point doubling. Complete formula. Cost: `4M + 4S + 1*a + 6add + 1*2`. */
      double() {
        const { ex: X1, ey: Y1, ez: Z1 } = this;
        const a = _a;
        const A = M(X1 * X1);
        const B = M(Y1 * Y1);
        const C2 = M(2n * M(Z1 * Z1));
        const D = M(a * A);
        const x1y1 = X1 + Y1;
        const E = M(M(x1y1 * x1y1) - A - B);
        const G2 = D + B;
        const F = G2 - C2;
        const H = D - B;
        const X3 = M(E * F);
        const Y3 = M(G2 * H);
        const T3 = M(E * H);
        const Z3 = M(F * G2);
        return new _Point(X3, Y3, Z3, T3);
      }
      /** Point addition. Complete formula. Cost: `8M + 1*k + 8add + 1*2`. */
      add(other) {
        const { ex: X1, ey: Y1, ez: Z1, et: T1 } = this;
        const { ex: X2, ey: Y2, ez: Z2, et: T2 } = apoint(other);
        const a = _a;
        const d = _d;
        const A = M(X1 * X2);
        const B = M(Y1 * Y2);
        const C2 = M(T1 * d * T2);
        const D = M(Z1 * Z2);
        const E = M((X1 + Y1) * (X2 + Y2) - A - B);
        const F = M(D - C2);
        const G2 = M(D + C2);
        const H = M(B - a * A);
        const X3 = M(E * F);
        const Y3 = M(G2 * H);
        const T3 = M(E * H);
        const Z3 = M(F * G2);
        return new _Point(X3, Y3, Z3, T3);
      }
      /**
       * Point-by-scalar multiplication. Scalar must be in range 1 <= n < CURVE.n.
       * Uses {@link wNAF} for base point.
       * Uses fake point to mitigate side-channel leakage.
       * @param n scalar by which point is multiplied
       * @param safe safe mode guards against timing attacks; unsafe mode is faster
       */
      multiply(n, safe = true) {
        if (!safe && (n === 0n || this.is0()))
          return I;
        arange(n, 1n, N);
        if (n === 1n)
          return this;
        if (this.equals(G))
          return wNAF(n).p;
        let p = I;
        let f = G;
        for (let d = this; n > 0n; d = d.double(), n >>= 1n) {
          if (n & 1n)
            p = p.add(d);
          else if (safe)
            f = f.add(d);
        }
        return p;
      }
      /** Convert point to 2d xy affine point. (X, Y, Z) ∋ (x=X/Z, y=Y/Z) */
      toAffine() {
        const { ex: x, ey: y, ez: z } = this;
        if (this.equals(I))
          return { x: 0n, y: 1n };
        const iz = invert(z, P);
        if (M(z * iz) !== 1n)
          err("invalid inverse");
        return { x: M(x * iz), y: M(y * iz) };
      }
      toBytes() {
        const { x, y } = this.assertValidity().toAffine();
        const b = numTo32bLE(y);
        b[31] |= x & 1n ? 128 : 0;
        return b;
      }
      toHex() {
        return bytesToHex(this.toBytes());
      }
      // encode to hex string
      clearCofactor() {
        return this.multiply(big(h), false);
      }
      isSmallOrder() {
        return this.clearCofactor().is0();
      }
      isTorsionFree() {
        let p = this.multiply(N / 2n, false).double();
        if (N % 2n)
          p = p.add(this);
        return p.is0();
      }
      static fromHex(hex, zip215) {
        return _Point.fromBytes(toU8(hex), zip215);
      }
      get x() {
        return this.toAffine().x;
      }
      get y() {
        return this.toAffine().y;
      }
      toRawBytes() {
        return this.toBytes();
      }
    };
    G = new Point(Gx, Gy, 1n, M(Gx * Gy));
    I = new Point(0n, 1n, 1n, 0n);
    Point.BASE = G;
    Point.ZERO = I;
    numTo32bLE = (num) => hexToBytes(padh(arange(num, 0n, B256), L2)).reverse();
    bytesToNumLE = (b) => big("0x" + bytesToHex(u8fr(abytes2(b)).reverse()));
    pow2 = (x, power) => {
      let r = x;
      while (power-- > 0n) {
        r *= r;
        r %= P;
      }
      return r;
    };
    pow_2_252_3 = (x) => {
      const x2 = x * x % P;
      const b2 = x2 * x % P;
      const b4 = pow2(b2, 2n) * b2 % P;
      const b5 = pow2(b4, 1n) * x % P;
      const b10 = pow2(b5, 5n) * b5 % P;
      const b20 = pow2(b10, 10n) * b10 % P;
      const b40 = pow2(b20, 20n) * b20 % P;
      const b80 = pow2(b40, 40n) * b40 % P;
      const b160 = pow2(b80, 80n) * b80 % P;
      const b240 = pow2(b160, 80n) * b80 % P;
      const b250 = pow2(b240, 10n) * b10 % P;
      const pow_p_5_8 = pow2(b250, 2n) * x % P;
      return { pow_p_5_8, b2 };
    };
    RM1 = 0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0n;
    uvRatio = (u, v) => {
      const v3 = M(v * v * v);
      const v7 = M(v3 * v3 * v);
      const pow = pow_2_252_3(u * v7).pow_p_5_8;
      let x = M(u * v3 * pow);
      const vx2 = M(v * x * x);
      const root1 = x;
      const root2 = M(x * RM1);
      const useRoot1 = vx2 === u;
      const useRoot2 = vx2 === M(-u);
      const noRoot = vx2 === M(-u * RM1);
      if (useRoot1)
        x = root1;
      if (useRoot2 || noRoot)
        x = root2;
      if ((M(x) & 1n) === 1n)
        x = M(-x);
      return { isValid: useRoot1 || useRoot2, value: x };
    };
    modL_LE = (hash) => modN(bytesToNumLE(hash));
    sha512a = (...m) => etc.sha512Async(...m);
    sha512s = (...m) => callHash("sha512Sync")(...m);
    hash2extK = (hashed) => {
      const head = hashed.slice(0, L);
      head[0] &= 248;
      head[31] &= 127;
      head[31] |= 64;
      const prefix = hashed.slice(L, L2);
      const scalar = modL_LE(head);
      const point = G.multiply(scalar);
      const pointBytes = point.toBytes();
      return { head, prefix, scalar, point, pointBytes };
    };
    getExtendedPublicKeyAsync = (priv) => sha512a(toU8(priv, L)).then(hash2extK);
    getExtendedPublicKey = (priv) => hash2extK(sha512s(toU8(priv, L)));
    getPublicKeyAsync = (priv) => getExtendedPublicKeyAsync(priv).then((p) => p.pointBytes);
    getPublicKey = (priv) => getExtendedPublicKey(priv).pointBytes;
    hashFinishA = (res) => sha512a(res.hashable).then(res.finish);
    hashFinishS = (res) => res.finish(sha512s(res.hashable));
    _sign = (e, rBytes, msg) => {
      const { pointBytes: P2, scalar: s } = e;
      const r = modL_LE(rBytes);
      const R = G.multiply(r).toBytes();
      const hashable = concatBytes(R, P2, msg);
      const finish = (hashed) => {
        const S = modN(r + modL_LE(hashed) * s);
        return abytes2(concatBytes(R, numTo32bLE(S)), L2);
      };
      return { hashable, finish };
    };
    signAsync = async (msg, privKey) => {
      const m = toU8(msg);
      const e = await getExtendedPublicKeyAsync(privKey);
      const rBytes = await sha512a(e.prefix, m);
      return hashFinishA(_sign(e, rBytes, m));
    };
    sign = (msg, privKey) => {
      const m = toU8(msg);
      const e = getExtendedPublicKey(privKey);
      const rBytes = sha512s(e.prefix, m);
      return hashFinishS(_sign(e, rBytes, m));
    };
    veriOpts = { zip215: true };
    _verify = (sig, msg, pub, opts = veriOpts) => {
      sig = toU8(sig, L2);
      msg = toU8(msg);
      pub = toU8(pub, L);
      const { zip215 } = opts;
      let A;
      let R;
      let s;
      let SB;
      let hashable = Uint8Array.of();
      try {
        A = Point.fromHex(pub, zip215);
        R = Point.fromHex(sig.slice(0, L), zip215);
        s = bytesToNumLE(sig.slice(L, L2));
        SB = G.multiply(s, false);
        hashable = concatBytes(R.toBytes(), A.toBytes(), msg);
      } catch (error) {
      }
      const finish = (hashed) => {
        if (SB == null)
          return false;
        if (!zip215 && A.isSmallOrder())
          return false;
        const k = modL_LE(hashed);
        const RkA = R.add(A.multiply(k, false));
        return RkA.add(SB.negate()).clearCofactor().is0();
      };
      return { hashable, finish };
    };
    verifyAsync = async (s, m, p, opts = veriOpts) => hashFinishA(_verify(s, m, p, opts));
    verify = (s, m, p, opts = veriOpts) => hashFinishS(_verify(s, m, p, opts));
    etc = {
      sha512Async: async (...messages) => {
        const s = subtle();
        const m = concatBytes(...messages);
        return u8n(await s.digest("SHA-512", m.buffer));
      },
      sha512Sync: void 0,
      bytesToHex,
      hexToBytes,
      concatBytes,
      mod: M,
      invert,
      randomBytes
    };
    utils = {
      getExtendedPublicKeyAsync,
      getExtendedPublicKey,
      randomPrivateKey: () => randomBytes(L),
      precompute: (w = 8, p = G) => {
        p.multiply(3n);
        w;
        return p;
      }
      // no-op
    };
    W = 8;
    scalarBits = 256;
    pwindows = Math.ceil(scalarBits / W) + 1;
    pwindowSize = 2 ** (W - 1);
    precompute = () => {
      const points = [];
      let p = G;
      let b = p;
      for (let w = 0; w < pwindows; w++) {
        b = p;
        points.push(b);
        for (let i = 1; i < pwindowSize; i++) {
          b = b.add(p);
          points.push(b);
        }
        p = b.double();
      }
      return points;
    };
    Gpows = void 0;
    ctneg = (cnd, p) => {
      const n = p.negate();
      return cnd ? n : p;
    };
    wNAF = (n) => {
      const comp = Gpows || (Gpows = precompute());
      let p = I;
      let f = G;
      const pow_2_w = 2 ** W;
      const maxNum = pow_2_w;
      const mask = big(pow_2_w - 1);
      const shiftBy = big(W);
      for (let w = 0; w < pwindows; w++) {
        let wbits = Number(n & mask);
        n >>= shiftBy;
        if (wbits > pwindowSize) {
          wbits -= maxNum;
          n += 1n;
        }
        const off = w * pwindowSize;
        const offF = off;
        const offP = off + Math.abs(wbits) - 1;
        const isEven = w % 2 !== 0;
        const isNeg = wbits < 0;
        if (wbits === 0) {
          f = f.add(ctneg(isEven, comp[offF]));
        } else {
          p = p.add(ctneg(isNeg, comp[offP]));
        }
      }
      return { p, f };
    };
  }
});

// src/index.ts
function jcsStringify(val) {
  if (val === null) return "null";
  if (typeof val === "boolean") return val ? "true" : "false";
  if (typeof val === "number") {
    if (!isFinite(val)) throw new Error("JCS: non-finite number");
    return String(val);
  }
  if (typeof val === "string") return JSON.stringify(val);
  if (Array.isArray(val)) return "[" + val.map(jcsStringify).join(",") + "]";
  if (typeof val === "object") {
    const obj = val;
    const sorted = Object.keys(obj).sort();
    return "{" + sorted.map((k) => JSON.stringify(k) + ":" + jcsStringify(obj[k])).join(",") + "}";
  }
  throw new Error(`JCS: unsupported type ${typeof val}`);
}
async function blake3Hex(data) {
  let blake32;
  try {
    ({ blake3: blake32 } = await Promise.resolve().then(() => (init_blake3(), blake3_exports)));
  } catch (e) {
    throw new Error(
      "@noble/hashes/blake3 unavailable \u2014 cannot compute VERDICT/v1 content hash (refusing SHA-256 substitution): " + (e instanceof Error ? e.message : String(e))
    );
  }
  const hash = blake32(data);
  return Array.from(hash).map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function sha256Hex(data) {
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function extractContentPayload(line) {
  const v = line.verdict;
  if (!v) return null;
  if (v["event"] && typeof v["event"] === "object") {
    const ev = v["event"];
    const payload2 = {
      description: ev["description"],
      delta_sv: ev["delta_sv"],
      timestamp: ev["timestamp"]
    };
    if (ev["evidence_root"] != null) payload2["evidence_root"] = ev["evidence_root"];
    return payload2;
  }
  const payload = {
    agent: v["agent"],
    description: v["description"],
    timestamp: v["timestamp"],
    delta_sv: v["delta_sv"]
  };
  if (v["evidence_root"] != null) payload["evidence_root"] = v["evidence_root"];
  return payload;
}
async function verifyReceipt(line) {
  const v = line.verdict;
  if (!v) return { verified: true, reason: "no_verdict_field" };
  const sig = v["signature"] ?? v["signature_hex"];
  const pub = v["signer_pubkey"] ?? v["signer_pubkey_hex"];
  const ev = v["event"];
  const hash = v["event_hash"] ?? (ev && ev["hash"]);
  if (!sig || !pub || !hash) return { verified: false, reason: "missing_fields" };
  const payload = extractContentPayload(line);
  if (!payload) return { verified: false, reason: "no_content_payload" };
  const isOmegaFormat = ev != null;
  const canonical = isOmegaFormat ? jcsStringify(payload) : jcsStringify(payload);
  const recomputed = await blake3Hex(new TextEncoder().encode(canonical));
  if (recomputed !== hash.toLowerCase()) {
    const legacyFloat = (n) => Number.isFinite(n) && Number.isInteger(n) ? n.toFixed(1) : JSON.stringify(n);
    const dsv = payload["delta_sv"];
    let legacyStr = `{"description":${JSON.stringify(payload["description"])},"delta_sv":${legacyFloat(dsv)},"timestamp":${JSON.stringify(payload["timestamp"])}`;
    if (payload["evidence_root"] != null) legacyStr += `,"evidence_root":${JSON.stringify(payload["evidence_root"])}`;
    legacyStr += "}";
    const legacyRecomputed = await blake3Hex(new TextEncoder().encode(legacyStr));
    if (legacyRecomputed !== hash.toLowerCase()) {
      return { verified: false, reason: "hash_mismatch", event_hash: hash };
    }
  }
  try {
    const { verifyAsync: verifyAsync2 } = await Promise.resolve().then(() => (init_ed25519(), ed25519_exports));
    const sigBytes = hexToBytes2(sig);
    const pubBytes = hexToBytes2(pub);
    const msgBytes = new TextEncoder().encode(hash.toLowerCase());
    const ok = await verifyAsync2(sigBytes, msgBytes, pubBytes);
    return ok ? { verified: true, event_hash: hash, signer_pubkey: pub } : { verified: false, reason: "sig_invalid" };
  } catch (e) {
    return { verified: false, reason: `sig_error: ${e}` };
  }
}
async function verifyLedger(jsonlText) {
  const lines = jsonlText.split("\n").filter((l) => l.trim());
  const parsed = lines.map((raw, i) => {
    try {
      return { idx: i, line: JSON.parse(raw), raw };
    } catch {
      return { idx: i, line: null, raw };
    }
  });
  let expectedPrev = void 0;
  const chainBreaks = /* @__PURE__ */ new Set();
  for (const { idx, line } of parsed) {
    if (!line) {
      expectedPrev = void 0;
      continue;
    }
    if (line.verdict == null) continue;
    const ev = line.verdict?.["event"];
    const thisHash = ev?.["hash"] ?? line.verdict?.event_hash;
    if (line.prev_hash != null) {
      const prevToCheck = line.prev_hash ?? void 0;
      if (prevToCheck !== expectedPrev) chainBreaks.add(idx);
    }
    if (thisHash !== void 0) expectedPrev = thisHash;
  }
  const results = await Promise.all(
    parsed.map(async ({ idx, line }) => {
      if (!line) return { line: idx + 1, verified: false, reason: "parse_error" };
      const r = await verifyReceipt(line);
      const ev = line.verdict?.["event"];
      const event_hash = ev?.["hash"] ?? line.verdict?.event_hash;
      return { line: idx + 1, event_hash, ...r };
    })
  );
  const chain_valid = chainBreaks.size === 0 && results.every((r) => r.verified);
  return { results, chain_valid };
}
async function createVerdictV1(opts) {
  const ed = await Promise.resolve().then(() => (init_ed25519(), ed25519_exports));
  if (!ed.etc.sha512Sync) {
    try {
      const { createHash } = await import("node:crypto");
      ed.etc.sha512Sync = (...msgs) => {
        const h2 = createHash("sha512");
        for (const m of msgs) h2.update(m);
        return h2.digest();
      };
    } catch {
    }
  }
  const { sign: sign2, getPublicKey: getPublicKey3 } = ed;
  const privBytes = hexToBytes2(opts.privateKeyHex);
  const pubBytes = getPublicKey3(privBytes);
  const pubHex = bytesToHex2(pubBytes);
  const timestamp = (/* @__PURE__ */ new Date()).toISOString();
  const payload = {
    agent: opts.agent,
    description: opts.description,
    timestamp,
    delta_sv: opts.delta_sv ?? 0.1,
    ...opts.evidence_root ? { evidence_root: opts.evidence_root } : {}
  };
  const canonical = jcsStringify(payload);
  const event_hash = await blake3Hex(new TextEncoder().encode(canonical));
  const sigBytes = await sign2(new TextEncoder().encode(event_hash), privBytes);
  const signature = bytesToHex2(sigBytes);
  return {
    verdict: {
      event_hash,
      signature,
      signer_pubkey: pubHex,
      ...opts.prevHash ? { prev_hash: opts.prevHash } : {},
      timestamp,
      delta_sv: opts.delta_sv ?? 0.1,
      description: opts.description,
      agent: opts.agent,
      // evidence_root is part of the SIGNED payload, so it MUST be carried into the
      // envelope — otherwise the verifier can't reconstruct the hash and verification
      // fails for every content-bound receipt. (Regression: see round-trip test.)
      ...opts.evidence_root ? { evidence_root: opts.evidence_root } : {},
      chain_valid: true,
      content_valid: true
    }
  };
}
function hexToBytes2(hex) {
  const h2 = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(h2.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(h2.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
function bytesToHex2(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function hashContent(text) {
  return blake3Hex(new TextEncoder().encode(text));
}
async function ed25519Verify(signatureHex, message, publicKeyHex) {
  const { verifyAsync: verifyAsync2 } = await Promise.resolve().then(() => (init_ed25519(), ed25519_exports));
  const msgBytes = typeof message === "string" ? new TextEncoder().encode(message) : message;
  try {
    return await verifyAsync2(hexToBytes2(signatureHex), msgBytes, hexToBytes2(publicKeyHex));
  } catch {
    return false;
  }
}
function asRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}
function numberValue(value) {
  return typeof value === "number" && Number.isFinite(value) ? value : void 0;
}
function stringValue(value) {
  return typeof value === "string" ? value : void 0;
}
function warrantCredentialGateCount(report) {
  const repos = Array.isArray(report["repos"]) ? report["repos"] : [];
  let count = 0;
  for (const rawRepo of repos) {
    const repo = asRecord(rawRepo);
    const checks = asRecord(repo["checks"]);
    const credential = asRecord(checks["credential_requires_approval"]);
    const decision = credential["decision"];
    if (decision === "require_approval" || decision === "block") count++;
  }
  return count;
}
function warrantDecisionCount(report, checkName, expected) {
  const repos = Array.isArray(report["repos"]) ? report["repos"] : [];
  let count = 0;
  for (const rawRepo of repos) {
    const repo = asRecord(rawRepo);
    const checks = asRecord(repo["checks"]);
    const check = asRecord(checks[checkName]);
    if (check["decision"] === expected) count++;
  }
  return count;
}
async function verifyWarrantProofPacket(packetInput, reportInput) {
  const reasons = [];
  const packet = asRecord(packetInput);
  const reportRaw = typeof reportInput === "string" ? reportInput : JSON.stringify(reportInput, null, 2);
  let report;
  try {
    report = asRecord(typeof reportInput === "string" ? JSON.parse(reportInput) : reportInput);
  } catch {
    return {
      verified: false,
      status: "invalid",
      reasons: ["report_parse_error"],
      private_ledger_status: "not_checked"
    };
  }
  if (packet["schema"] !== "meridian-warrant-proof-packet/0.1") {
    reasons.push("packet_schema_mismatch");
  }
  if (packet["status"] !== "pass") reasons.push("packet_status_not_pass");
  const reportSection = asRecord(packet["report"]);
  const preflight = asRecord(packet["preflight"]);
  const receipt = asRecord(packet["receipt"]);
  const receiptVerification = asRecord(receipt["verification"]);
  const reportHash = "sha256:" + await sha256Hex(new TextEncoder().encode(reportRaw));
  if (reportSection["evidenceHash"] !== reportHash) reasons.push("report_hash_mismatch");
  const repos = Array.isArray(report["repos"]) ? report["repos"] : [];
  const repoCount = repos.length;
  const policyGenerated = repos.filter((repo) => asRecord(repo)["policy_generated"] === true).length;
  const summary = asRecord(report["summary"]);
  const failures = Array.isArray(summary["failures"]) ? summary["failures"].length : 0;
  const coverageHash = stringValue(report["coverage_hash"]);
  const destructiveBlocks = warrantDecisionCount(report, "builtin_destructive_block", "block");
  const readOnlyAllows = warrantDecisionCount(report, "read_only_allows", "allow");
  const credentialGates = warrantCredentialGateCount(report);
  if (numberValue(reportSection["repoCount"]) !== repoCount) reasons.push("repo_count_mismatch");
  if (numberValue(reportSection["policyGenerated"]) !== policyGenerated) reasons.push("policy_generated_mismatch");
  if (numberValue(reportSection["failures"]) !== failures) reasons.push("failure_count_mismatch");
  if (reportSection["coverageHash"] !== coverageHash) reasons.push("coverage_hash_mismatch");
  if (numberValue(preflight["destructiveBlocks"]) !== destructiveBlocks) reasons.push("destructive_blocks_mismatch");
  if (numberValue(preflight["readOnlyAllows"]) !== readOnlyAllows) reasons.push("read_only_allows_mismatch");
  if (numberValue(preflight["credentialGates"]) !== credentialGates) reasons.push("credential_gates_mismatch");
  const reportReceipt = asRecord(report["receipt"]);
  const receiptEventHash = stringValue(reportReceipt["event_hash"]);
  const receiptCoverageHash = stringValue(reportReceipt["coverage_hash"]);
  if (receipt["status"] !== "signed") reasons.push("receipt_not_signed");
  if (receipt["eventHash"] !== receiptEventHash) reasons.push("receipt_event_hash_mismatch");
  if (receipt["coverageHash"] !== receiptCoverageHash || receipt["coverageHash"] !== coverageHash) {
    reasons.push("receipt_coverage_hash_mismatch");
  }
  const privateLedgerRedacted = receiptVerification["status"] === "unavailable" && receiptVerification["reason"] === "private Omega ledger redacted from public fixture";
  const privateLedgerStatus = privateLedgerRedacted ? "redacted" : "not_checked";
  if (!privateLedgerRedacted) reasons.push("private_ledger_status_not_redacted");
  const verified = reasons.length === 0;
  return {
    verified,
    status: verified ? "unavailable_private_ledger" : "invalid",
    reasons: verified ? ["public_packet_verified_private_ledger_redacted"] : reasons,
    report_hash: reportHash,
    coverage_hash: coverageHash,
    repo_count: repoCount,
    credential_gates: credentialGates,
    receipt_event_hash: receiptEventHash,
    private_ledger_status: privateLedgerStatus
  };
}
var PROOF_PACKET_SCHEMA = "verdict.proof-packet/v1";
var SHA256_HEX_RE = /^[0-9a-f]{64}$/;
function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function nonEmptyString(value) {
  return typeof value === "string" && value.trim() !== "";
}
function decimalValue(value) {
  if (value === null || value === void 0 || value === "") return void 0;
  if (typeof value !== "number" && typeof value !== "string") return void 0;
  const n = Number(value);
  return Number.isFinite(n) ? n : void 0;
}
async function validateProofPacketClaim(claim, errors) {
  const statement = claim["statement"];
  const statementSha256 = claim["statement_sha256"];
  if (!statement && !statementSha256) {
    errors.push("claim must include statement or statement_sha256");
    return;
  }
  if (statement !== void 0 && statement !== null && typeof statement !== "string") {
    errors.push("claim.statement must be a string");
    return;
  }
  if (statementSha256 !== void 0 && statementSha256 !== null && (typeof statementSha256 !== "string" || !SHA256_HEX_RE.test(statementSha256))) {
    errors.push("claim.statement_sha256 must be 64 lowercase hex chars");
    return;
  }
  if (statement && statementSha256) {
    const recomputed = await sha256Hex(new TextEncoder().encode(statement));
    if (recomputed !== statementSha256) {
      errors.push("claim.statement_sha256 does not match claim.statement");
    }
  }
}
async function validateProofPacket(packetInput) {
  if (!isPlainObject(packetInput)) {
    return { valid: false, errors: ["packet must be an object"] };
  }
  const packet = packetInput;
  const errors = [];
  if (packet["schema"] !== PROOF_PACKET_SCHEMA) {
    errors.push(`schema must be ${PROOF_PACKET_SCHEMA}`);
  }
  for (const field of ["issued_at", "producer", "subject", "action"]) {
    if (!nonEmptyString(packet[field])) errors.push(`${field} must be a non-empty string`);
  }
  const unit = packet["unit"];
  if (!isPlainObject(unit)) {
    errors.push("unit must be an object");
  } else {
    for (const field of ["id", "unit", "currency"]) {
      if (!nonEmptyString(unit[field])) errors.push(`unit.${field} must be a non-empty string`);
    }
    const amount = decimalValue(unit["amount_usd"]);
    const maxAmount = decimalValue(unit["max_amount_usd"]);
    if (amount !== void 0 && amount < 0) errors.push("unit.amount_usd must be non-negative");
    if (maxAmount !== void 0 && maxAmount < 0) {
      errors.push("unit.max_amount_usd must be non-negative");
    }
    if (amount !== void 0 && maxAmount !== void 0 && amount > maxAmount) {
      errors.push("unit.amount_usd must not exceed unit.max_amount_usd");
    }
  }
  const claim = packet["claim"];
  if (!isPlainObject(claim)) {
    errors.push("claim must be an object");
  } else {
    await validateProofPacketClaim(claim, errors);
  }
  const evidence = packet["evidence"];
  if (!Array.isArray(evidence)) {
    errors.push("evidence must be a list");
  } else {
    evidence.forEach((item, index) => {
      if (!isPlainObject(item)) {
        errors.push(`evidence[${index}] must be an object`);
        return;
      }
      if (!nonEmptyString(item["type"])) {
        errors.push(`evidence[${index}].type must be a non-empty string`);
      }
      const hasRef = ["uri", "content_sha256", "content_hash", "chain_hash"].some(
        (f) => Boolean(item[f])
      );
      if (!hasRef) {
        errors.push(
          `evidence[${index}] must include uri, content_sha256, content_hash, or chain_hash`
        );
      }
    });
  }
  const receipts = packet["receipts"];
  if (!Array.isArray(receipts)) {
    errors.push("receipts must be a list");
  } else {
    receipts.forEach((item, index) => {
      if (!isPlainObject(item)) {
        errors.push(`receipts[${index}] must be an object`);
        return;
      }
      if (!nonEmptyString(item["protocol"])) {
        errors.push(`receipts[${index}].protocol must be a non-empty string`);
      }
      const hasRef = [
        "content_hash",
        "chain_hash",
        "receipt_sha256",
        "envelope_sha256",
        "signature"
      ].some((f) => Boolean(item[f]));
      if (!hasRef) {
        errors.push(
          `receipts[${index}] must include content_hash, chain_hash, receipt_sha256, envelope_sha256, or signature`
        );
      }
    });
  }
  const payment = packet["payment"];
  if (payment !== void 0 && payment !== null) {
    if (!isPlainObject(payment)) {
      errors.push("payment must be an object when present");
    } else if (isPlainObject(unit)) {
      const amount = decimalValue(payment["amount_usd"]);
      const maxAmount = decimalValue(unit["max_amount_usd"]);
      if (amount !== void 0 && amount < 0) {
        errors.push("payment.amount_usd must be non-negative");
      }
      if (amount !== void 0 && maxAmount !== void 0 && amount > maxAmount) {
        errors.push("payment.amount_usd must not exceed unit.max_amount_usd");
      }
    }
  }
  return { valid: errors.length === 0, errors };
}
function extractProofPacketArtifact(payload) {
  const p = asRecord(payload);
  if (isPlainObject(p["packet"])) return ["proof_packet", p["packet"]];
  if (isPlainObject(p["envelope"])) return ["verdict_v1_envelope", p["envelope"]];
  if (p["schema"] === PROOF_PACKET_SCHEMA) return ["proof_packet", payload];
  if (p["protocol"] === "VERDICT/v1") return ["verdict_v1_envelope", payload];
  throw new Error(
    "input must be a proof packet, a VERDICT/v1 envelope, or include packet/envelope"
  );
}
function proofPacketUnitId(packet) {
  const unit = packet["unit"];
  return isPlainObject(unit) ? stringValue(unit["id"]) : void 0;
}
async function verifyV1EnvelopeSignature(envelope) {
  const receipt = envelope["receipt"];
  const claimed = envelope["content_hash"];
  const sig = envelope["signature"];
  const pub = envelope["signer_pubkey"];
  if (!isPlainObject(receipt) || typeof claimed !== "string" || typeof sig !== "string" || typeof pub !== "string") {
    return false;
  }
  try {
    const recomputed = await blake3Hex(new TextEncoder().encode(jcsStringify(receipt)));
    if (recomputed !== claimed) return false;
    const { verifyAsync: verifyAsync2 } = await Promise.resolve().then(() => (init_ed25519(), ed25519_exports));
    return await verifyAsync2(
      hexToBytes2(sig),
      new TextEncoder().encode(claimed),
      hexToBytes2(pub)
    );
  } catch {
    return false;
  }
}
async function verifyProofPacket(input) {
  const [kind, artifact] = extractProofPacketArtifact(input);
  if (kind === "proof_packet") {
    const validation2 = await validateProofPacket(artifact);
    const packet2 = asRecord(artifact);
    return {
      kind,
      valid: validation2.valid,
      signature_valid: null,
      validation: validation2,
      errors: [...validation2.errors],
      subject: stringValue(packet2["subject"]),
      action: stringValue(packet2["action"]),
      unit_id: proofPacketUnitId(packet2)
    };
  }
  const envelope = asRecord(artifact);
  const receipt = envelope["receipt"];
  const validation = await validateProofPacket(receipt);
  const errors = [...validation.errors];
  if (envelope["protocol"] !== "VERDICT/v1") {
    errors.push("envelope.protocol must be VERDICT/v1");
  }
  const signatureValid = await verifyV1EnvelopeSignature(envelope);
  if (!signatureValid) errors.push("signature_invalid");
  const packet = asRecord(receipt);
  return {
    kind,
    // Derived from the full error list so it can never disagree with errors.
    valid: errors.length === 0,
    signature_valid: signatureValid,
    validation,
    errors,
    subject: stringValue(packet["subject"]),
    action: stringValue(packet["action"]),
    unit_id: proofPacketUnitId(packet),
    content_hash: stringValue(envelope["content_hash"]),
    signer_pubkey: stringValue(envelope["signer_pubkey"])
  };
}
async function getPublicKey2(privateKeyHex) {
  const ed = await Promise.resolve().then(() => (init_ed25519(), ed25519_exports));
  if (!ed.etc.sha512Sync) {
    try {
      const { createHash } = await import("node:crypto");
      ed.etc.sha512Sync = (...msgs) => {
        const h2 = createHash("sha512");
        for (const m of msgs) h2.update(m);
        return h2.digest();
      };
    } catch {
    }
  }
  const privBytes = hexToBytes2(privateKeyHex);
  const pubBytes = ed.getPublicKey(privBytes);
  return bytesToHex2(pubBytes);
}
function parseLedger(text) {
  return text.split("\n").filter((l) => l.trim()).flatMap((line) => {
    try {
      return [JSON.parse(line)];
    } catch {
      return [];
    }
  });
}
export {
  PROOF_PACKET_SCHEMA,
  blake3Hex,
  bytesToHex2 as bytesToHex,
  createVerdictV1,
  ed25519Verify,
  getPublicKey2 as getPublicKey,
  hashContent,
  hexToBytes2 as hexToBytes,
  jcsStringify,
  parseLedger,
  sha256Hex,
  validateProofPacket,
  verifyLedger,
  verifyProofPacket,
  verifyReceipt,
  verifyWarrantProofPacket
};
/*! Bundled license information:

@noble/hashes/esm/utils.js:
  (*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@noble/ed25519/index.js:
  (*! noble-ed25519 - MIT License (c) 2019 Paul Miller (paulmillr.com) *)
*/
