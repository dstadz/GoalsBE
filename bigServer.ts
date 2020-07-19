// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.

// This is a specialised implementation of a System module loader.

"use strict";

// @ts-nocheck
/* eslint-disable */
let System, __instantiateAsync, __instantiate;

(() => {
  const r = new Map();

  System = {
    register(id, d, f) {
      r.set(id, { d, f, exp: {} });
    },
  };

  async function dI(mid, src) {
    let id = mid.replace(/\.\w+$/i, "");
    if (id.includes("./")) {
      const [o, ...ia] = id.split("/").reverse(),
        [, ...sa] = src.split("/").reverse(),
        oa = [o];
      let s = 0,
        i;
      while ((i = ia.shift())) {
        if (i === "..") s++;
        else if (i === ".") break;
        else oa.push(i);
      }
      if (s < sa.length) oa.push(...sa.slice(s));
      id = oa.reverse().join("/");
    }
    return r.has(id) ? gExpA(id) : import(mid);
  }

  function gC(id, main) {
    return {
      id,
      import: (m) => dI(m, id),
      meta: { url: id, main },
    };
  }

  function gE(exp) {
    return (id, v) => {
      v = typeof id === "string" ? { [id]: v } : id;
      for (const [id, value] of Object.entries(v)) {
        Object.defineProperty(exp, id, {
          value,
          writable: true,
          enumerable: true,
        });
      }
    };
  }

  function rF(main) {
    for (const [id, m] of r.entries()) {
      const { f, exp } = m;
      const { execute: e, setters: s } = f(gE(exp), gC(id, id === main));
      delete m.f;
      m.e = e;
      m.s = s;
    }
  }

  async function gExpA(id) {
    if (!r.has(id)) return;
    const m = r.get(id);
    if (m.s) {
      const { d, e, s } = m;
      delete m.s;
      delete m.e;
      for (let i = 0; i < s.length; i++) s[i](await gExpA(d[i]));
      const r = e();
      if (r) await r;
    }
    return m.exp;
  }

  function gExp(id) {
    if (!r.has(id)) return;
    const m = r.get(id);
    if (m.s) {
      const { d, e, s } = m;
      delete m.s;
      delete m.e;
      for (let i = 0; i < s.length; i++) s[i](gExp(d[i]));
      e();
    }
    return m.exp;
  }

  __instantiateAsync = async (m) => {
    System = __instantiateAsync = __instantiate = undefined;
    rF(m);
    return gExpA(m);
  };

  __instantiate = (m) => {
    System = __instantiateAsync = __instantiate = undefined;
    rF(m);
    return gExp(m);
  };
})();

/*
 * Adapted to deno from:
 *
 * [js-sha256]{@link https://github.com/emn178/js-sha256}
 *
 * @version 0.9.0
 * @author Chen, Yi-Cyuan [emn178@gmail.com]
 * @copyright Chen, Yi-Cyuan 2014-2017
 * @license MIT
 */
System.register(
  "https://deno.land/std@0.53.0/hash/sha256",
  [],
  function (exports_1, context_1) {
    "use strict";
    var HEX_CHARS, EXTRA, SHIFT, K, blocks, Sha256, HmacSha256;
    var __moduleName = context_1 && context_1.id;
    return {
      setters: [],
      execute: function () {
        HEX_CHARS = "0123456789abcdef".split("");
        EXTRA = [-2147483648, 8388608, 32768, 128];
        SHIFT = [24, 16, 8, 0];
        // prettier-ignore
        // dprint-ignore
        K = [
          0x428a2f98,
          0x71374491,
          0xb5c0fbcf,
          0xe9b5dba5,
          0x3956c25b,
          0x59f111f1,
          0x923f82a4,
          0xab1c5ed5,
          0xd807aa98,
          0x12835b01,
          0x243185be,
          0x550c7dc3,
          0x72be5d74,
          0x80deb1fe,
          0x9bdc06a7,
          0xc19bf174,
          0xe49b69c1,
          0xefbe4786,
          0x0fc19dc6,
          0x240ca1cc,
          0x2de92c6f,
          0x4a7484aa,
          0x5cb0a9dc,
          0x76f988da,
          0x983e5152,
          0xa831c66d,
          0xb00327c8,
          0xbf597fc7,
          0xc6e00bf3,
          0xd5a79147,
          0x06ca6351,
          0x14292967,
          0x27b70a85,
          0x2e1b2138,
          0x4d2c6dfc,
          0x53380d13,
          0x650a7354,
          0x766a0abb,
          0x81c2c92e,
          0x92722c85,
          0xa2bfe8a1,
          0xa81a664b,
          0xc24b8b70,
          0xc76c51a3,
          0xd192e819,
          0xd6990624,
          0xf40e3585,
          0x106aa070,
          0x19a4c116,
          0x1e376c08,
          0x2748774c,
          0x34b0bcb5,
          0x391c0cb3,
          0x4ed8aa4a,
          0x5b9cca4f,
          0x682e6ff3,
          0x748f82ee,
          0x78a5636f,
          0x84c87814,
          0x8cc70208,
          0x90befffa,
          0xa4506ceb,
          0xbef9a3f7,
          0xc67178f2,
        ];
        blocks = [];
        Sha256 = class Sha256 {
          constructor(is224 = false, sharedMemory = false) {
            this.#lastByteIndex = 0;
            this.init(is224, sharedMemory);
          }
          #block;
          #blocks;
          #bytes;
          #finalized;
          #first;
          #h0;
          #h1;
          #h2;
          #h3;
          #h4;
          #h5;
          #h6;
          #h7;
          #hashed;
          #hBytes;
          #is224;
          #lastByteIndex;
          #start;
          init(is224, sharedMemory) {
            if (sharedMemory) {
              blocks[0] = blocks[16] = blocks[1] = blocks[2] = blocks[3] =
                blocks[4] = blocks[5] = blocks[6] = blocks[7] = blocks[8] =
                  blocks[9] = blocks[10] = blocks[11] = blocks[12] =
                    blocks[13] = blocks[14] = blocks[15] = 0;
              this.#blocks = blocks;
            } else {
              this.#blocks = [
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
              ];
            }
            if (is224) {
              this.#h0 = 0xc1059ed8;
              this.#h1 = 0x367cd507;
              this.#h2 = 0x3070dd17;
              this.#h3 = 0xf70e5939;
              this.#h4 = 0xffc00b31;
              this.#h5 = 0x68581511;
              this.#h6 = 0x64f98fa7;
              this.#h7 = 0xbefa4fa4;
            } else {
              // 256
              this.#h0 = 0x6a09e667;
              this.#h1 = 0xbb67ae85;
              this.#h2 = 0x3c6ef372;
              this.#h3 = 0xa54ff53a;
              this.#h4 = 0x510e527f;
              this.#h5 = 0x9b05688c;
              this.#h6 = 0x1f83d9ab;
              this.#h7 = 0x5be0cd19;
            }
            this.#block = this.#start = this.#bytes = this.#hBytes = 0;
            this.#finalized = this.#hashed = false;
            this.#first = true;
            this.#is224 = is224;
          }
          /** Update hash
                 *
                 * @param message The message you want to hash.
                 */
          update(message) {
            if (this.#finalized) {
              return this;
            }
            let msg;
            if (message instanceof ArrayBuffer) {
              msg = new Uint8Array(message);
            } else {
              msg = message;
            }
            let index = 0;
            const length = msg.length;
            const blocks = this.#blocks;
            while (index < length) {
              let i;
              if (this.#hashed) {
                this.#hashed = false;
                blocks[0] = this.#block;
                blocks[16] = blocks[1] = blocks[2] = blocks[3] = blocks[4] =
                  blocks[5] = blocks[6] = blocks[7] = blocks[8] = blocks[9] =
                    blocks[10] = blocks[11] = blocks[12] = blocks[13] =
                      blocks[14] = blocks[15] = 0;
              }
              if (typeof msg !== "string") {
                for (i = this.#start; index < length && i < 64; ++index) {
                  blocks[i >> 2] |= msg[index] << SHIFT[i++ & 3];
                }
              } else {
                for (i = this.#start; index < length && i < 64; ++index) {
                  let code = msg.charCodeAt(index);
                  if (code < 0x80) {
                    blocks[i >> 2] |= code << SHIFT[i++ & 3];
                  } else if (code < 0x800) {
                    blocks[i >> 2] |= (0xc0 | (code >> 6)) << SHIFT[i++ & 3];
                    blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
                  } else if (code < 0xd800 || code >= 0xe000) {
                    blocks[i >> 2] |= (0xe0 | (code >> 12)) << SHIFT[i++ & 3];
                    blocks[i >> 2] |= (0x80 | ((code >> 6) & 0x3f)) <<
                      SHIFT[i++ & 3];
                    blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
                  } else {
                    code = 0x10000 +
                      (((code & 0x3ff) << 10) |
                        (msg.charCodeAt(++index) & 0x3ff));
                    blocks[i >> 2] |= (0xf0 | (code >> 18)) << SHIFT[i++ & 3];
                    blocks[i >> 2] |= (0x80 | ((code >> 12) & 0x3f)) <<
                      SHIFT[i++ & 3];
                    blocks[i >> 2] |= (0x80 | ((code >> 6) & 0x3f)) <<
                      SHIFT[i++ & 3];
                    blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
                  }
                }
              }
              this.#lastByteIndex = i;
              this.#bytes += i - this.#start;
              if (i >= 64) {
                this.#block = blocks[16];
                this.#start = i - 64;
                this.hash();
                this.#hashed = true;
              } else {
                this.#start = i;
              }
            }
            if (this.#bytes > 4294967295) {
              this.#hBytes += (this.#bytes / 4294967296) << 0;
              this.#bytes = this.#bytes % 4294967296;
            }
            return this;
          }
          finalize() {
            if (this.#finalized) {
              return;
            }
            this.#finalized = true;
            const blocks = this.#blocks;
            const i = this.#lastByteIndex;
            blocks[16] = this.#block;
            blocks[i >> 2] |= EXTRA[i & 3];
            this.#block = blocks[16];
            if (i >= 56) {
              if (!this.#hashed) {
                this.hash();
              }
              blocks[0] = this.#block;
              blocks[16] = blocks[1] = blocks[2] = blocks[3] = blocks[4] =
                blocks[5] = blocks[6] = blocks[7] = blocks[8] = blocks[9] =
                  blocks[10] = blocks[11] = blocks[12] = blocks[13] =
                    blocks[14] = blocks[15] = 0;
            }
            blocks[14] = (this.#hBytes << 3) | (this.#bytes >>> 29);
            blocks[15] = this.#bytes << 3;
            this.hash();
          }
          hash() {
            let a = this.#h0;
            let b = this.#h1;
            let c = this.#h2;
            let d = this.#h3;
            let e = this.#h4;
            let f = this.#h5;
            let g = this.#h6;
            let h = this.#h7;
            const blocks = this.#blocks;
            let s0;
            let s1;
            let maj;
            let t1;
            let t2;
            let ch;
            let ab;
            let da;
            let cd;
            let bc;
            for (let j = 16; j < 64; ++j) {
              // rightrotate
              t1 = blocks[j - 15];
              s0 = ((t1 >>> 7) | (t1 << 25)) ^ ((t1 >>> 18) | (t1 << 14)) ^
                (t1 >>> 3);
              t1 = blocks[j - 2];
              s1 = ((t1 >>> 17) | (t1 << 15)) ^ ((t1 >>> 19) | (t1 << 13)) ^
                (t1 >>> 10);
              blocks[j] = (blocks[j - 16] + s0 + blocks[j - 7] + s1) << 0;
            }
            bc = b & c;
            for (let j = 0; j < 64; j += 4) {
              if (this.#first) {
                if (this.#is224) {
                  ab = 300032;
                  t1 = blocks[0] - 1413257819;
                  h = (t1 - 150054599) << 0;
                  d = (t1 + 24177077) << 0;
                } else {
                  ab = 704751109;
                  t1 = blocks[0] - 210244248;
                  h = (t1 - 1521486534) << 0;
                  d = (t1 + 143694565) << 0;
                }
                this.#first = false;
              } else {
                s0 = ((a >>> 2) | (a << 30)) ^
                  ((a >>> 13) | (a << 19)) ^
                  ((a >>> 22) | (a << 10));
                s1 = ((e >>> 6) | (e << 26)) ^
                  ((e >>> 11) | (e << 21)) ^
                  ((e >>> 25) | (e << 7));
                ab = a & b;
                maj = ab ^ (a & c) ^ bc;
                ch = (e & f) ^ (~e & g);
                t1 = h + s1 + ch + K[j] + blocks[j];
                t2 = s0 + maj;
                h = (d + t1) << 0;
                d = (t1 + t2) << 0;
              }
              s0 = ((d >>> 2) | (d << 30)) ^
                ((d >>> 13) | (d << 19)) ^
                ((d >>> 22) | (d << 10));
              s1 = ((h >>> 6) | (h << 26)) ^
                ((h >>> 11) | (h << 21)) ^
                ((h >>> 25) | (h << 7));
              da = d & a;
              maj = da ^ (d & b) ^ ab;
              ch = (h & e) ^ (~h & f);
              t1 = g + s1 + ch + K[j + 1] + blocks[j + 1];
              t2 = s0 + maj;
              g = (c + t1) << 0;
              c = (t1 + t2) << 0;
              s0 = ((c >>> 2) | (c << 30)) ^
                ((c >>> 13) | (c << 19)) ^
                ((c >>> 22) | (c << 10));
              s1 = ((g >>> 6) | (g << 26)) ^
                ((g >>> 11) | (g << 21)) ^
                ((g >>> 25) | (g << 7));
              cd = c & d;
              maj = cd ^ (c & a) ^ da;
              ch = (g & h) ^ (~g & e);
              t1 = f + s1 + ch + K[j + 2] + blocks[j + 2];
              t2 = s0 + maj;
              f = (b + t1) << 0;
              b = (t1 + t2) << 0;
              s0 = ((b >>> 2) | (b << 30)) ^
                ((b >>> 13) | (b << 19)) ^
                ((b >>> 22) | (b << 10));
              s1 = ((f >>> 6) | (f << 26)) ^
                ((f >>> 11) | (f << 21)) ^
                ((f >>> 25) | (f << 7));
              bc = b & c;
              maj = bc ^ (b & d) ^ cd;
              ch = (f & g) ^ (~f & h);
              t1 = e + s1 + ch + K[j + 3] + blocks[j + 3];
              t2 = s0 + maj;
              e = (a + t1) << 0;
              a = (t1 + t2) << 0;
            }
            this.#h0 = (this.#h0 + a) << 0;
            this.#h1 = (this.#h1 + b) << 0;
            this.#h2 = (this.#h2 + c) << 0;
            this.#h3 = (this.#h3 + d) << 0;
            this.#h4 = (this.#h4 + e) << 0;
            this.#h5 = (this.#h5 + f) << 0;
            this.#h6 = (this.#h6 + g) << 0;
            this.#h7 = (this.#h7 + h) << 0;
          }
          /** Return hash in hex string. */
          hex() {
            this.finalize();
            const h0 = this.#h0;
            const h1 = this.#h1;
            const h2 = this.#h2;
            const h3 = this.#h3;
            const h4 = this.#h4;
            const h5 = this.#h5;
            const h6 = this.#h6;
            const h7 = this.#h7;
            let hex = HEX_CHARS[(h0 >> 28) & 0x0f] +
              HEX_CHARS[(h0 >> 24) & 0x0f] +
              HEX_CHARS[(h0 >> 20) & 0x0f] +
              HEX_CHARS[(h0 >> 16) & 0x0f] +
              HEX_CHARS[(h0 >> 12) & 0x0f] +
              HEX_CHARS[(h0 >> 8) & 0x0f] +
              HEX_CHARS[(h0 >> 4) & 0x0f] +
              HEX_CHARS[h0 & 0x0f] +
              HEX_CHARS[(h1 >> 28) & 0x0f] +
              HEX_CHARS[(h1 >> 24) & 0x0f] +
              HEX_CHARS[(h1 >> 20) & 0x0f] +
              HEX_CHARS[(h1 >> 16) & 0x0f] +
              HEX_CHARS[(h1 >> 12) & 0x0f] +
              HEX_CHARS[(h1 >> 8) & 0x0f] +
              HEX_CHARS[(h1 >> 4) & 0x0f] +
              HEX_CHARS[h1 & 0x0f] +
              HEX_CHARS[(h2 >> 28) & 0x0f] +
              HEX_CHARS[(h2 >> 24) & 0x0f] +
              HEX_CHARS[(h2 >> 20) & 0x0f] +
              HEX_CHARS[(h2 >> 16) & 0x0f] +
              HEX_CHARS[(h2 >> 12) & 0x0f] +
              HEX_CHARS[(h2 >> 8) & 0x0f] +
              HEX_CHARS[(h2 >> 4) & 0x0f] +
              HEX_CHARS[h2 & 0x0f] +
              HEX_CHARS[(h3 >> 28) & 0x0f] +
              HEX_CHARS[(h3 >> 24) & 0x0f] +
              HEX_CHARS[(h3 >> 20) & 0x0f] +
              HEX_CHARS[(h3 >> 16) & 0x0f] +
              HEX_CHARS[(h3 >> 12) & 0x0f] +
              HEX_CHARS[(h3 >> 8) & 0x0f] +
              HEX_CHARS[(h3 >> 4) & 0x0f] +
              HEX_CHARS[h3 & 0x0f] +
              HEX_CHARS[(h4 >> 28) & 0x0f] +
              HEX_CHARS[(h4 >> 24) & 0x0f] +
              HEX_CHARS[(h4 >> 20) & 0x0f] +
              HEX_CHARS[(h4 >> 16) & 0x0f] +
              HEX_CHARS[(h4 >> 12) & 0x0f] +
              HEX_CHARS[(h4 >> 8) & 0x0f] +
              HEX_CHARS[(h4 >> 4) & 0x0f] +
              HEX_CHARS[h4 & 0x0f] +
              HEX_CHARS[(h5 >> 28) & 0x0f] +
              HEX_CHARS[(h5 >> 24) & 0x0f] +
              HEX_CHARS[(h5 >> 20) & 0x0f] +
              HEX_CHARS[(h5 >> 16) & 0x0f] +
              HEX_CHARS[(h5 >> 12) & 0x0f] +
              HEX_CHARS[(h5 >> 8) & 0x0f] +
              HEX_CHARS[(h5 >> 4) & 0x0f] +
              HEX_CHARS[h5 & 0x0f] +
              HEX_CHARS[(h6 >> 28) & 0x0f] +
              HEX_CHARS[(h6 >> 24) & 0x0f] +
              HEX_CHARS[(h6 >> 20) & 0x0f] +
              HEX_CHARS[(h6 >> 16) & 0x0f] +
              HEX_CHARS[(h6 >> 12) & 0x0f] +
              HEX_CHARS[(h6 >> 8) & 0x0f] +
              HEX_CHARS[(h6 >> 4) & 0x0f] +
              HEX_CHARS[h6 & 0x0f];
            if (!this.#is224) {
              hex += HEX_CHARS[(h7 >> 28) & 0x0f] +
                HEX_CHARS[(h7 >> 24) & 0x0f] +
                HEX_CHARS[(h7 >> 20) & 0x0f] +
                HEX_CHARS[(h7 >> 16) & 0x0f] +
                HEX_CHARS[(h7 >> 12) & 0x0f] +
                HEX_CHARS[(h7 >> 8) & 0x0f] +
                HEX_CHARS[(h7 >> 4) & 0x0f] +
                HEX_CHARS[h7 & 0x0f];
            }
            return hex;
          }
          /** Return hash in hex string. */
          toString() {
            return this.hex();
          }
          /** Return hash in integer array. */
          digest() {
            this.finalize();
            const h0 = this.#h0;
            const h1 = this.#h1;
            const h2 = this.#h2;
            const h3 = this.#h3;
            const h4 = this.#h4;
            const h5 = this.#h5;
            const h6 = this.#h6;
            const h7 = this.#h7;
            const arr = [
              (h0 >> 24) & 0xff,
              (h0 >> 16) & 0xff,
              (h0 >> 8) & 0xff,
              h0 & 0xff,
              (h1 >> 24) & 0xff,
              (h1 >> 16) & 0xff,
              (h1 >> 8) & 0xff,
              h1 & 0xff,
              (h2 >> 24) & 0xff,
              (h2 >> 16) & 0xff,
              (h2 >> 8) & 0xff,
              h2 & 0xff,
              (h3 >> 24) & 0xff,
              (h3 >> 16) & 0xff,
              (h3 >> 8) & 0xff,
              h3 & 0xff,
              (h4 >> 24) & 0xff,
              (h4 >> 16) & 0xff,
              (h4 >> 8) & 0xff,
              h4 & 0xff,
              (h5 >> 24) & 0xff,
              (h5 >> 16) & 0xff,
              (h5 >> 8) & 0xff,
              h5 & 0xff,
              (h6 >> 24) & 0xff,
              (h6 >> 16) & 0xff,
              (h6 >> 8) & 0xff,
              h6 & 0xff,
            ];
            if (!this.#is224) {
              arr.push(
                (h7 >> 24) & 0xff,
                (h7 >> 16) & 0xff,
                (h7 >> 8) & 0xff,
                h7 & 0xff,
              );
            }
            return arr;
          }
          /** Return hash in integer array. */
          array() {
            return this.digest();
          }
          /** Return hash in ArrayBuffer. */
          arrayBuffer() {
            this.finalize();
            const buffer = new ArrayBuffer(this.#is224 ? 28 : 32);
            const dataView = new DataView(buffer);
            dataView.setUint32(0, this.#h0);
            dataView.setUint32(4, this.#h1);
            dataView.setUint32(8, this.#h2);
            dataView.setUint32(12, this.#h3);
            dataView.setUint32(16, this.#h4);
            dataView.setUint32(20, this.#h5);
            dataView.setUint32(24, this.#h6);
            if (!this.#is224) {
              dataView.setUint32(28, this.#h7);
            }
            return buffer;
          }
        };
        exports_1("Sha256", Sha256);
        HmacSha256 = class HmacSha256 extends Sha256 {
          constructor(secretKey, is224 = false, sharedMemory = false) {
            super(is224, sharedMemory);
            let key;
            if (typeof secretKey === "string") {
              const bytes = [];
              const length = secretKey.length;
              let index = 0;
              for (let i = 0; i < length; ++i) {
                let code = secretKey.charCodeAt(i);
                if (code < 0x80) {
                  bytes[index++] = code;
                } else if (code < 0x800) {
                  bytes[index++] = 0xc0 | (code >> 6);
                  bytes[index++] = 0x80 | (code & 0x3f);
                } else if (code < 0xd800 || code >= 0xe000) {
                  bytes[index++] = 0xe0 | (code >> 12);
                  bytes[index++] = 0x80 | ((code >> 6) & 0x3f);
                  bytes[index++] = 0x80 | (code & 0x3f);
                } else {
                  code = 0x10000 +
                    (((code & 0x3ff) << 10) |
                      (secretKey.charCodeAt(++i) & 0x3ff));
                  bytes[index++] = 0xf0 | (code >> 18);
                  bytes[index++] = 0x80 | ((code >> 12) & 0x3f);
                  bytes[index++] = 0x80 | ((code >> 6) & 0x3f);
                  bytes[index++] = 0x80 | (code & 0x3f);
                }
              }
              key = bytes;
            } else {
              if (secretKey instanceof ArrayBuffer) {
                key = new Uint8Array(secretKey);
              } else {
                key = secretKey;
              }
            }
            if (key.length > 64) {
              key = new Sha256(is224, true).update(key).array();
            }
            const oKeyPad = [];
            const iKeyPad = [];
            for (let i = 0; i < 64; ++i) {
              const b = key[i] || 0;
              oKeyPad[i] = 0x5c ^ b;
              iKeyPad[i] = 0x36 ^ b;
            }
            this.update(iKeyPad);
            this.#oKeyPad = oKeyPad;
            this.#inner = true;
            this.#is224 = is224;
            this.#sharedMemory = sharedMemory;
          }
          #inner;
          #is224;
          #oKeyPad;
          #sharedMemory;
          finalize() {
            super.finalize();
            if (this.#inner) {
              this.#inner = false;
              const innerHash = this.array();
              super.init(this.#is224, this.#sharedMemory);
              this.update(this.#oKeyPad);
              this.update(innerHash);
              super.finalize();
            }
          }
        };
        exports_1("HmacSha256", HmacSha256);
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.53.0/encoding/utf8",
  [],
  function (exports_2, context_2) {
    "use strict";
    var encoder, decoder;
    var __moduleName = context_2 && context_2.id;
    /** Shorthand for new TextEncoder().encode() */
    function encode(input) {
      return encoder.encode(input);
    }
    exports_2("encode", encode);
    /** Shorthand for new TextDecoder().decode() */
    function decode(input) {
      return decoder.decode(input);
    }
    exports_2("decode", decode);
    return {
      setters: [],
      execute: function () {
        /** A default TextEncoder instance */
        exports_2("encoder", encoder = new TextEncoder());
        /** A default TextDecoder instance */
        exports_2("decoder", decoder = new TextDecoder());
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.53.0/path/interface",
  [],
  function (exports_3, context_3) {
    "use strict";
    var __moduleName = context_3 && context_3.id;
    return {
      setters: [],
      execute: function () {
      },
    };
  },
);
// Copyright the Browserify authors. MIT License.
// Ported from https://github.com/browserify/path-browserify/
System.register(
  "https://deno.land/std@0.53.0/path/_constants",
  [],
  function (exports_4, context_4) {
    "use strict";
    var build,
      CHAR_UPPERCASE_A,
      CHAR_LOWERCASE_A,
      CHAR_UPPERCASE_Z,
      CHAR_LOWERCASE_Z,
      CHAR_DOT,
      CHAR_FORWARD_SLASH,
      CHAR_BACKWARD_SLASH,
      CHAR_VERTICAL_LINE,
      CHAR_COLON,
      CHAR_QUESTION_MARK,
      CHAR_UNDERSCORE,
      CHAR_LINE_FEED,
      CHAR_CARRIAGE_RETURN,
      CHAR_TAB,
      CHAR_FORM_FEED,
      CHAR_EXCLAMATION_MARK,
      CHAR_HASH,
      CHAR_SPACE,
      CHAR_NO_BREAK_SPACE,
      CHAR_ZERO_WIDTH_NOBREAK_SPACE,
      CHAR_LEFT_SQUARE_BRACKET,
      CHAR_RIGHT_SQUARE_BRACKET,
      CHAR_LEFT_ANGLE_BRACKET,
      CHAR_RIGHT_ANGLE_BRACKET,
      CHAR_LEFT_CURLY_BRACKET,
      CHAR_RIGHT_CURLY_BRACKET,
      CHAR_HYPHEN_MINUS,
      CHAR_PLUS,
      CHAR_DOUBLE_QUOTE,
      CHAR_SINGLE_QUOTE,
      CHAR_PERCENT,
      CHAR_SEMICOLON,
      CHAR_CIRCUMFLEX_ACCENT,
      CHAR_GRAVE_ACCENT,
      CHAR_AT,
      CHAR_AMPERSAND,
      CHAR_EQUAL,
      CHAR_0,
      CHAR_9,
      isWindows,
      SEP,
      SEP_PATTERN;
    var __moduleName = context_4 && context_4.id;
    return {
      setters: [],
      execute: function () {
        build = Deno.build;
        // Alphabet chars.
        exports_4("CHAR_UPPERCASE_A", CHAR_UPPERCASE_A = 65); /* A */
        exports_4("CHAR_LOWERCASE_A", CHAR_LOWERCASE_A = 97); /* a */
        exports_4("CHAR_UPPERCASE_Z", CHAR_UPPERCASE_Z = 90); /* Z */
        exports_4("CHAR_LOWERCASE_Z", CHAR_LOWERCASE_Z = 122); /* z */
        // Non-alphabetic chars.
        exports_4("CHAR_DOT", CHAR_DOT = 46); /* . */
        exports_4("CHAR_FORWARD_SLASH", CHAR_FORWARD_SLASH = 47); /* / */
        exports_4("CHAR_BACKWARD_SLASH", CHAR_BACKWARD_SLASH = 92); /* \ */
        exports_4("CHAR_VERTICAL_LINE", CHAR_VERTICAL_LINE = 124); /* | */
        exports_4("CHAR_COLON", CHAR_COLON = 58); /* : */
        exports_4("CHAR_QUESTION_MARK", CHAR_QUESTION_MARK = 63); /* ? */
        exports_4("CHAR_UNDERSCORE", CHAR_UNDERSCORE = 95); /* _ */
        exports_4("CHAR_LINE_FEED", CHAR_LINE_FEED = 10); /* \n */
        exports_4("CHAR_CARRIAGE_RETURN", CHAR_CARRIAGE_RETURN = 13); /* \r */
        exports_4("CHAR_TAB", CHAR_TAB = 9); /* \t */
        exports_4("CHAR_FORM_FEED", CHAR_FORM_FEED = 12); /* \f */
        exports_4("CHAR_EXCLAMATION_MARK", CHAR_EXCLAMATION_MARK = 33); /* ! */
        exports_4("CHAR_HASH", CHAR_HASH = 35); /* # */
        exports_4("CHAR_SPACE", CHAR_SPACE = 32); /*   */
        exports_4(
          "CHAR_NO_BREAK_SPACE",
          CHAR_NO_BREAK_SPACE = 160,
        ); /* \u00A0 */
        exports_4(
          "CHAR_ZERO_WIDTH_NOBREAK_SPACE",
          CHAR_ZERO_WIDTH_NOBREAK_SPACE = 65279,
        ); /* \uFEFF */
        exports_4(
          "CHAR_LEFT_SQUARE_BRACKET",
          CHAR_LEFT_SQUARE_BRACKET = 91,
        ); /* [ */
        exports_4(
          "CHAR_RIGHT_SQUARE_BRACKET",
          CHAR_RIGHT_SQUARE_BRACKET = 93,
        ); /* ] */
        exports_4(
          "CHAR_LEFT_ANGLE_BRACKET",
          CHAR_LEFT_ANGLE_BRACKET = 60,
        ); /* < */
        exports_4(
          "CHAR_RIGHT_ANGLE_BRACKET",
          CHAR_RIGHT_ANGLE_BRACKET = 62,
        ); /* > */
        exports_4(
          "CHAR_LEFT_CURLY_BRACKET",
          CHAR_LEFT_CURLY_BRACKET = 123,
        ); /* { */
        exports_4(
          "CHAR_RIGHT_CURLY_BRACKET",
          CHAR_RIGHT_CURLY_BRACKET = 125,
        ); /* } */
        exports_4("CHAR_HYPHEN_MINUS", CHAR_HYPHEN_MINUS = 45); /* - */
        exports_4("CHAR_PLUS", CHAR_PLUS = 43); /* + */
        exports_4("CHAR_DOUBLE_QUOTE", CHAR_DOUBLE_QUOTE = 34); /* " */
        exports_4("CHAR_SINGLE_QUOTE", CHAR_SINGLE_QUOTE = 39); /* ' */
        exports_4("CHAR_PERCENT", CHAR_PERCENT = 37); /* % */
        exports_4("CHAR_SEMICOLON", CHAR_SEMICOLON = 59); /* ; */
        exports_4(
          "CHAR_CIRCUMFLEX_ACCENT",
          CHAR_CIRCUMFLEX_ACCENT = 94,
        ); /* ^ */
        exports_4("CHAR_GRAVE_ACCENT", CHAR_GRAVE_ACCENT = 96); /* ` */
        exports_4("CHAR_AT", CHAR_AT = 64); /* @ */
        exports_4("CHAR_AMPERSAND", CHAR_AMPERSAND = 38); /* & */
        exports_4("CHAR_EQUAL", CHAR_EQUAL = 61); /* = */
        // Digits
        exports_4("CHAR_0", CHAR_0 = 48); /* 0 */
        exports_4("CHAR_9", CHAR_9 = 57); /* 9 */
        isWindows = build.os == "windows";
        exports_4("SEP", SEP = isWindows ? "\\" : "/");
        exports_4("SEP_PATTERN", SEP_PATTERN = isWindows ? /[\\/]+/ : /\/+/);
      },
    };
  },
);
// Copyright the Browserify authors. MIT License.
// Ported from https://github.com/browserify/path-browserify/
System.register(
  "https://deno.land/std@0.53.0/path/_util",
  ["https://deno.land/std@0.53.0/path/_constants"],
  function (exports_5, context_5) {
    "use strict";
    var _constants_ts_1;
    var __moduleName = context_5 && context_5.id;
    function assertPath(path) {
      if (typeof path !== "string") {
        throw new TypeError(
          `Path must be a string. Received ${JSON.stringify(path)}`,
        );
      }
    }
    exports_5("assertPath", assertPath);
    function isPosixPathSeparator(code) {
      return code === _constants_ts_1.CHAR_FORWARD_SLASH;
    }
    exports_5("isPosixPathSeparator", isPosixPathSeparator);
    function isPathSeparator(code) {
      return isPosixPathSeparator(code) ||
        code === _constants_ts_1.CHAR_BACKWARD_SLASH;
    }
    exports_5("isPathSeparator", isPathSeparator);
    function isWindowsDeviceRoot(code) {
      return ((code >= _constants_ts_1.CHAR_LOWERCASE_A &&
        code <= _constants_ts_1.CHAR_LOWERCASE_Z) ||
        (code >= _constants_ts_1.CHAR_UPPERCASE_A &&
          code <= _constants_ts_1.CHAR_UPPERCASE_Z));
    }
    exports_5("isWindowsDeviceRoot", isWindowsDeviceRoot);
    // Resolves . and .. elements in a path with directory names
    function normalizeString(path, allowAboveRoot, separator, isPathSeparator) {
      let res = "";
      let lastSegmentLength = 0;
      let lastSlash = -1;
      let dots = 0;
      let code;
      for (let i = 0, len = path.length; i <= len; ++i) {
        if (i < len) {
          code = path.charCodeAt(i);
        } else if (isPathSeparator(code)) {
          break;
        } else {
          code = _constants_ts_1.CHAR_FORWARD_SLASH;
        }
        if (isPathSeparator(code)) {
          if (lastSlash === i - 1 || dots === 1) {
            // NOOP
          } else if (lastSlash !== i - 1 && dots === 2) {
            if (
              res.length < 2 ||
              lastSegmentLength !== 2 ||
              res.charCodeAt(res.length - 1) !== _constants_ts_1.CHAR_DOT ||
              res.charCodeAt(res.length - 2) !== _constants_ts_1.CHAR_DOT
            ) {
              if (res.length > 2) {
                const lastSlashIndex = res.lastIndexOf(separator);
                if (lastSlashIndex === -1) {
                  res = "";
                  lastSegmentLength = 0;
                } else {
                  res = res.slice(0, lastSlashIndex);
                  lastSegmentLength = res.length - 1 -
                    res.lastIndexOf(separator);
                }
                lastSlash = i;
                dots = 0;
                continue;
              } else if (res.length === 2 || res.length === 1) {
                res = "";
                lastSegmentLength = 0;
                lastSlash = i;
                dots = 0;
                continue;
              }
            }
            if (allowAboveRoot) {
              if (res.length > 0) {
                res += `${separator}..`;
              } else {
                res = "..";
              }
              lastSegmentLength = 2;
            }
          } else {
            if (res.length > 0) {
              res += separator + path.slice(lastSlash + 1, i);
            } else {
              res = path.slice(lastSlash + 1, i);
            }
            lastSegmentLength = i - lastSlash - 1;
          }
          lastSlash = i;
          dots = 0;
        } else if (code === _constants_ts_1.CHAR_DOT && dots !== -1) {
          ++dots;
        } else {
          dots = -1;
        }
      }
      return res;
    }
    exports_5("normalizeString", normalizeString);
    function _format(sep, pathObject) {
      const dir = pathObject.dir || pathObject.root;
      const base = pathObject.base ||
        (pathObject.name || "") + (pathObject.ext || "");
      if (!dir) {
        return base;
      }
      if (dir === pathObject.root) {
        return dir + base;
      }
      return dir + sep + base;
    }
    exports_5("_format", _format);
    return {
      setters: [
        function (_constants_ts_1_1) {
          _constants_ts_1 = _constants_ts_1_1;
        },
      ],
      execute: function () {
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.53.0/fmt/colors",
  [],
  function (exports_6, context_6) {
    "use strict";
    var noColor, enabled, ANSI_PATTERN;
    var __moduleName = context_6 && context_6.id;
    function setColorEnabled(value) {
      if (noColor) {
        return;
      }
      enabled = value;
    }
    exports_6("setColorEnabled", setColorEnabled);
    function getColorEnabled() {
      return enabled;
    }
    exports_6("getColorEnabled", getColorEnabled);
    function code(open, close) {
      return {
        open: `\x1b[${open.join(";")}m`,
        close: `\x1b[${close}m`,
        regexp: new RegExp(`\\x1b\\[${close}m`, "g"),
      };
    }
    function run(str, code) {
      return enabled
        ? `${code.open}${str.replace(code.regexp, code.open)}${code.close}`
        : str;
    }
    function reset(str) {
      return run(str, code([0], 0));
    }
    exports_6("reset", reset);
    function bold(str) {
      return run(str, code([1], 22));
    }
    exports_6("bold", bold);
    function dim(str) {
      return run(str, code([2], 22));
    }
    exports_6("dim", dim);
    function italic(str) {
      return run(str, code([3], 23));
    }
    exports_6("italic", italic);
    function underline(str) {
      return run(str, code([4], 24));
    }
    exports_6("underline", underline);
    function inverse(str) {
      return run(str, code([7], 27));
    }
    exports_6("inverse", inverse);
    function hidden(str) {
      return run(str, code([8], 28));
    }
    exports_6("hidden", hidden);
    function strikethrough(str) {
      return run(str, code([9], 29));
    }
    exports_6("strikethrough", strikethrough);
    function black(str) {
      return run(str, code([30], 39));
    }
    exports_6("black", black);
    function red(str) {
      return run(str, code([31], 39));
    }
    exports_6("red", red);
    function green(str) {
      return run(str, code([32], 39));
    }
    exports_6("green", green);
    function yellow(str) {
      return run(str, code([33], 39));
    }
    exports_6("yellow", yellow);
    function blue(str) {
      return run(str, code([34], 39));
    }
    exports_6("blue", blue);
    function magenta(str) {
      return run(str, code([35], 39));
    }
    exports_6("magenta", magenta);
    function cyan(str) {
      return run(str, code([36], 39));
    }
    exports_6("cyan", cyan);
    function white(str) {
      return run(str, code([37], 39));
    }
    exports_6("white", white);
    function gray(str) {
      return run(str, code([90], 39));
    }
    exports_6("gray", gray);
    function bgBlack(str) {
      return run(str, code([40], 49));
    }
    exports_6("bgBlack", bgBlack);
    function bgRed(str) {
      return run(str, code([41], 49));
    }
    exports_6("bgRed", bgRed);
    function bgGreen(str) {
      return run(str, code([42], 49));
    }
    exports_6("bgGreen", bgGreen);
    function bgYellow(str) {
      return run(str, code([43], 49));
    }
    exports_6("bgYellow", bgYellow);
    function bgBlue(str) {
      return run(str, code([44], 49));
    }
    exports_6("bgBlue", bgBlue);
    function bgMagenta(str) {
      return run(str, code([45], 49));
    }
    exports_6("bgMagenta", bgMagenta);
    function bgCyan(str) {
      return run(str, code([46], 49));
    }
    exports_6("bgCyan", bgCyan);
    function bgWhite(str) {
      return run(str, code([47], 49));
    }
    exports_6("bgWhite", bgWhite);
    /* Special Color Sequences */
    function clampAndTruncate(n, max = 255, min = 0) {
      return Math.trunc(Math.max(Math.min(n, max), min));
    }
    /** Set text color using paletted 8bit colors.
     * https://en.wikipedia.org/wiki/ANSI_escape_code#8-bit */
    function rgb8(str, color) {
      return run(str, code([38, 5, clampAndTruncate(color)], 39));
    }
    exports_6("rgb8", rgb8);
    /** Set background color using paletted 8bit colors.
     * https://en.wikipedia.org/wiki/ANSI_escape_code#8-bit */
    function bgRgb8(str, color) {
      return run(str, code([48, 5, clampAndTruncate(color)], 49));
    }
    exports_6("bgRgb8", bgRgb8);
    /** Set text color using 24bit rgb.
     * `color` can be a number in range `0x000000` to `0xffffff` or
     * an `Rgb`.
     *
     * To produce the color magenta:
     *
     *      rgba24("foo", 0xff00ff);
     *      rgba24("foo", {r: 255, g: 0, b: 255});
     */
    function rgb24(str, color) {
      if (typeof color === "number") {
        return run(
          str,
          code(
            [38, 2, (color >> 16) & 0xff, (color >> 8) & 0xff, color & 0xff],
            39,
          ),
        );
      }
      return run(
        str,
        code([
          38,
          2,
          clampAndTruncate(color.r),
          clampAndTruncate(color.g),
          clampAndTruncate(color.b),
        ], 39),
      );
    }
    exports_6("rgb24", rgb24);
    /** Set background color using 24bit rgb.
     * `color` can be a number in range `0x000000` to `0xffffff` or
     * an `Rgb`.
     *
     * To produce the color magenta:
     *
     *      bgRgba24("foo", 0xff00ff);
     *      bgRgba24("foo", {r: 255, g: 0, b: 255});
     */
    function bgRgb24(str, color) {
      if (typeof color === "number") {
        return run(
          str,
          code(
            [48, 2, (color >> 16) & 0xff, (color >> 8) & 0xff, color & 0xff],
            49,
          ),
        );
      }
      return run(
        str,
        code([
          48,
          2,
          clampAndTruncate(color.r),
          clampAndTruncate(color.g),
          clampAndTruncate(color.b),
        ], 49),
      );
    }
    exports_6("bgRgb24", bgRgb24);
    function stripColor(string) {
      return string.replace(ANSI_PATTERN, "");
    }
    exports_6("stripColor", stripColor);
    return {
      setters: [],
      execute: function () {
        // Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
        /**
             * A module to print ANSI terminal colors. Inspired by chalk, kleur, and colors
             * on npm.
             *
             * ```
             * import { bgBlue, red, bold } from "https://deno.land/std/fmt/colors.ts";
             * console.log(bgBlue(red(bold("Hello world!"))));
             * ```
             *
             * This module supports `NO_COLOR` environmental variable disabling any coloring
             * if `NO_COLOR` is set.
             */
        noColor = Deno.noColor;
        enabled = !noColor;
        // https://github.com/chalk/ansi-regex/blob/2b56fb0c7a07108e5b54241e8faec160d393aedb/index.js
        ANSI_PATTERN = new RegExp(
          [
            "[\\u001B\\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[-a-zA-Z\\d\\/#&.:=?%@~_]*)*)?\\u0007)",
            "(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PR-TZcf-ntqry=><~]))",
          ].join("|"),
          "g",
        );
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.53.0/testing/diff",
  [],
  function (exports_7, context_7) {
    "use strict";
    var DiffType, REMOVED, COMMON, ADDED;
    var __moduleName = context_7 && context_7.id;
    function createCommon(A, B, reverse) {
      const common = [];
      if (A.length === 0 || B.length === 0) {
        return [];
      }
      for (let i = 0; i < Math.min(A.length, B.length); i += 1) {
        if (
          A[reverse ? A.length - i - 1 : i] ===
            B[reverse ? B.length - i - 1 : i]
        ) {
          common.push(A[reverse ? A.length - i - 1 : i]);
        } else {
          return common;
        }
      }
      return common;
    }
    function diff(A, B) {
      const prefixCommon = createCommon(A, B);
      const suffixCommon = createCommon(
        A.slice(prefixCommon.length),
        B.slice(prefixCommon.length),
        true,
      ).reverse();
      A = suffixCommon.length
        ? A.slice(prefixCommon.length, -suffixCommon.length)
        : A.slice(prefixCommon.length);
      B = suffixCommon.length
        ? B.slice(prefixCommon.length, -suffixCommon.length)
        : B.slice(prefixCommon.length);
      const swapped = B.length > A.length;
      [A, B] = swapped ? [B, A] : [A, B];
      const M = A.length;
      const N = B.length;
      if (!M && !N && !suffixCommon.length && !prefixCommon.length) {
        return [];
      }
      if (!N) {
        return [
          ...prefixCommon.map((c) => ({ type: DiffType.common, value: c })),
          ...A.map((a) => ({
            type: swapped ? DiffType.added : DiffType.removed,
            value: a,
          })),
          ...suffixCommon.map((c) => ({ type: DiffType.common, value: c })),
        ];
      }
      const offset = N;
      const delta = M - N;
      const size = M + N + 1;
      const fp = new Array(size).fill({ y: -1 });
      /**
         * INFO:
         * This buffer is used to save memory and improve performance.
         * The first half is used to save route and last half is used to save diff
         * type.
         * This is because, when I kept new uint8array area to save type,performance
         * worsened.
         */
      const routes = new Uint32Array((M * N + size + 1) * 2);
      const diffTypesPtrOffset = routes.length / 2;
      let ptr = 0;
      let p = -1;
      function backTrace(A, B, current, swapped) {
        const M = A.length;
        const N = B.length;
        const result = [];
        let a = M - 1;
        let b = N - 1;
        let j = routes[current.id];
        let type = routes[current.id + diffTypesPtrOffset];
        while (true) {
          if (!j && !type) {
            break;
          }
          const prev = j;
          if (type === REMOVED) {
            result.unshift({
              type: swapped ? DiffType.removed : DiffType.added,
              value: B[b],
            });
            b -= 1;
          } else if (type === ADDED) {
            result.unshift({
              type: swapped ? DiffType.added : DiffType.removed,
              value: A[a],
            });
            a -= 1;
          } else {
            result.unshift({ type: DiffType.common, value: A[a] });
            a -= 1;
            b -= 1;
          }
          j = routes[prev];
          type = routes[prev + diffTypesPtrOffset];
        }
        return result;
      }
      function createFP(slide, down, k, M) {
        if (slide && slide.y === -1 && down && down.y === -1) {
          return { y: 0, id: 0 };
        }
        if (
          (down && down.y === -1) ||
          k === M ||
          (slide && slide.y) > (down && down.y) + 1
        ) {
          const prev = slide.id;
          ptr++;
          routes[ptr] = prev;
          routes[ptr + diffTypesPtrOffset] = ADDED;
          return { y: slide.y, id: ptr };
        } else {
          const prev = down.id;
          ptr++;
          routes[ptr] = prev;
          routes[ptr + diffTypesPtrOffset] = REMOVED;
          return { y: down.y + 1, id: ptr };
        }
      }
      function snake(k, slide, down, _offset, A, B) {
        const M = A.length;
        const N = B.length;
        if (k < -N || M < k) {
          return { y: -1, id: -1 };
        }
        const fp = createFP(slide, down, k, M);
        while (fp.y + k < M && fp.y < N && A[fp.y + k] === B[fp.y]) {
          const prev = fp.id;
          ptr++;
          fp.id = ptr;
          fp.y += 1;
          routes[ptr] = prev;
          routes[ptr + diffTypesPtrOffset] = COMMON;
        }
        return fp;
      }
      while (fp[delta + offset].y < N) {
        p = p + 1;
        for (let k = -p; k < delta; ++k) {
          fp[k + offset] = snake(
            k,
            fp[k - 1 + offset],
            fp[k + 1 + offset],
            offset,
            A,
            B,
          );
        }
        for (let k = delta + p; k > delta; --k) {
          fp[k + offset] = snake(
            k,
            fp[k - 1 + offset],
            fp[k + 1 + offset],
            offset,
            A,
            B,
          );
        }
        fp[delta + offset] = snake(
          delta,
          fp[delta - 1 + offset],
          fp[delta + 1 + offset],
          offset,
          A,
          B,
        );
      }
      return [
        ...prefixCommon.map((c) => ({ type: DiffType.common, value: c })),
        ...backTrace(A, B, fp[delta + offset], swapped),
        ...suffixCommon.map((c) => ({ type: DiffType.common, value: c })),
      ];
    }
    exports_7("default", diff);
    return {
      setters: [],
      execute: function () {
        (function (DiffType) {
          DiffType["removed"] = "removed";
          DiffType["common"] = "common";
          DiffType["added"] = "added";
        })(DiffType || (DiffType = {}));
        exports_7("DiffType", DiffType);
        REMOVED = 1;
        COMMON = 2;
        ADDED = 3;
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.53.0/testing/asserts",
  [
    "https://deno.land/std@0.53.0/fmt/colors",
    "https://deno.land/std@0.53.0/testing/diff",
  ],
  function (exports_8, context_8) {
    "use strict";
    var colors_ts_1, diff_ts_1, CAN_NOT_DISPLAY, AssertionError;
    var __moduleName = context_8 && context_8.id;
    function format(v) {
      let string = Deno.inspect(v);
      if (typeof v == "string") {
        string = `"${string.replace(/(?=["\\])/g, "\\")}"`;
      }
      return string;
    }
    function createColor(diffType) {
      switch (diffType) {
        case diff_ts_1.DiffType.added:
          return (s) => colors_ts_1.green(colors_ts_1.bold(s));
        case diff_ts_1.DiffType.removed:
          return (s) => colors_ts_1.red(colors_ts_1.bold(s));
        default:
          return colors_ts_1.white;
      }
    }
    function createSign(diffType) {
      switch (diffType) {
        case diff_ts_1.DiffType.added:
          return "+   ";
        case diff_ts_1.DiffType.removed:
          return "-   ";
        default:
          return "    ";
      }
    }
    function buildMessage(diffResult) {
      const messages = [];
      messages.push("");
      messages.push("");
      messages.push(
        `    ${colors_ts_1.gray(colors_ts_1.bold("[Diff]"))} ${
          colors_ts_1.red(colors_ts_1.bold("Actual"))
        } / ${colors_ts_1.green(colors_ts_1.bold("Expected"))}`,
      );
      messages.push("");
      messages.push("");
      diffResult.forEach((result) => {
        const c = createColor(result.type);
        messages.push(c(`${createSign(result.type)}${result.value}`));
      });
      messages.push("");
      return messages;
    }
    function isKeyedCollection(x) {
      return [Symbol.iterator, "size"].every((k) => k in x);
    }
    function equal(c, d) {
      const seen = new Map();
      return (function compare(a, b) {
        // Have to render RegExp & Date for string comparison
        // unless it's mistreated as object
        if (
          a &&
          b &&
          ((a instanceof RegExp && b instanceof RegExp) ||
            (a instanceof Date && b instanceof Date))
        ) {
          return String(a) === String(b);
        }
        if (Object.is(a, b)) {
          return true;
        }
        if (a && typeof a === "object" && b && typeof b === "object") {
          if (seen.get(a) === b) {
            return true;
          }
          if (Object.keys(a || {}).length !== Object.keys(b || {}).length) {
            return false;
          }
          if (isKeyedCollection(a) && isKeyedCollection(b)) {
            if (a.size !== b.size) {
              return false;
            }
            let unmatchedEntries = a.size;
            for (const [aKey, aValue] of a.entries()) {
              for (const [bKey, bValue] of b.entries()) {
                /* Given that Map keys can be references, we need
                             * to ensure that they are also deeply equal */
                if (
                  (aKey === aValue && bKey === bValue && compare(aKey, bKey)) ||
                  (compare(aKey, bKey) && compare(aValue, bValue))
                ) {
                  unmatchedEntries--;
                }
              }
            }
            return unmatchedEntries === 0;
          }
          const merged = { ...a, ...b };
          for (const key in merged) {
            if (!compare(a && a[key], b && b[key])) {
              return false;
            }
          }
          seen.set(a, b);
          return true;
        }
        return false;
      })(c, d);
    }
    exports_8("equal", equal);
    /** Make an assertion, if not `true`, then throw. */
    function assert(expr, msg = "") {
      if (!expr) {
        throw new AssertionError(msg);
      }
    }
    exports_8("assert", assert);
    /**
     * Make an assertion that `actual` and `expected` are equal, deeply. If not
     * deeply equal, then throw.
     */
    function assertEquals(actual, expected, msg) {
      if (equal(actual, expected)) {
        return;
      }
      let message = "";
      const actualString = format(actual);
      const expectedString = format(expected);
      try {
        const diffResult = diff_ts_1.default(
          actualString.split("\n"),
          expectedString.split("\n"),
        );
        const diffMsg = buildMessage(diffResult).join("\n");
        message = `Values are not equal:\n${diffMsg}`;
      } catch (e) {
        message = `\n${colors_ts_1.red(CAN_NOT_DISPLAY)} + \n\n`;
      }
      if (msg) {
        message = msg;
      }
      throw new AssertionError(message);
    }
    exports_8("assertEquals", assertEquals);
    /**
     * Make an assertion that `actual` and `expected` are not equal, deeply.
     * If not then throw.
     */
    function assertNotEquals(actual, expected, msg) {
      if (!equal(actual, expected)) {
        return;
      }
      let actualString;
      let expectedString;
      try {
        actualString = String(actual);
      } catch (e) {
        actualString = "[Cannot display]";
      }
      try {
        expectedString = String(expected);
      } catch (e) {
        expectedString = "[Cannot display]";
      }
      if (!msg) {
        msg = `actual: ${actualString} expected: ${expectedString}`;
      }
      throw new AssertionError(msg);
    }
    exports_8("assertNotEquals", assertNotEquals);
    /**
     * Make an assertion that `actual` and `expected` are strictly equal.  If
     * not then throw.
     */
    function assertStrictEq(actual, expected, msg) {
      if (actual === expected) {
        return;
      }
      let message;
      if (msg) {
        message = msg;
      } else {
        const actualString = format(actual);
        const expectedString = format(expected);
        if (actualString === expectedString) {
          const withOffset = actualString
            .split("\n")
            .map((l) => `     ${l}`)
            .join("\n");
          message =
            `Values have the same structure but are not reference-equal:\n\n${
              colors_ts_1.red(withOffset)
            }\n`;
        } else {
          try {
            const diffResult = diff_ts_1.default(
              actualString.split("\n"),
              expectedString.split("\n"),
            );
            const diffMsg = buildMessage(diffResult).join("\n");
            message = `Values are not strictly equal:\n${diffMsg}`;
          } catch (e) {
            message = `\n${colors_ts_1.red(CAN_NOT_DISPLAY)} + \n\n`;
          }
        }
      }
      throw new AssertionError(message);
    }
    exports_8("assertStrictEq", assertStrictEq);
    /**
     * Make an assertion that actual contains expected. If not
     * then thrown.
     */
    function assertStrContains(actual, expected, msg) {
      if (!actual.includes(expected)) {
        if (!msg) {
          msg = `actual: "${actual}" expected to contains: "${expected}"`;
        }
        throw new AssertionError(msg);
      }
    }
    exports_8("assertStrContains", assertStrContains);
    /**
     * Make an assertion that `actual` contains the `expected` values
     * If not then thrown.
     */
    function assertArrayContains(actual, expected, msg) {
      const missing = [];
      for (let i = 0; i < expected.length; i++) {
        let found = false;
        for (let j = 0; j < actual.length; j++) {
          if (equal(expected[i], actual[j])) {
            found = true;
            break;
          }
        }
        if (!found) {
          missing.push(expected[i]);
        }
      }
      if (missing.length === 0) {
        return;
      }
      if (!msg) {
        msg = `actual: "${actual}" expected to contains: "${expected}"`;
        msg += "\n";
        msg += `missing: ${missing}`;
      }
      throw new AssertionError(msg);
    }
    exports_8("assertArrayContains", assertArrayContains);
    /**
     * Make an assertion that `actual` match RegExp `expected`. If not
     * then thrown
     */
    function assertMatch(actual, expected, msg) {
      if (!expected.test(actual)) {
        if (!msg) {
          msg = `actual: "${actual}" expected to match: "${expected}"`;
        }
        throw new AssertionError(msg);
      }
    }
    exports_8("assertMatch", assertMatch);
    /**
     * Forcefully throws a failed assertion
     */
    function fail(msg) {
      // eslint-disable-next-line @typescript-eslint/no-use-before-define
      assert(false, `Failed assertion${msg ? `: ${msg}` : "."}`);
    }
    exports_8("fail", fail);
    /** Executes a function, expecting it to throw.  If it does not, then it
     * throws.  An error class and a string that should be included in the
     * error message can also be asserted.
     */
    function assertThrows(fn, ErrorClass, msgIncludes = "", msg) {
      let doesThrow = false;
      let error = null;
      try {
        fn();
      } catch (e) {
        if (
          ErrorClass && !(Object.getPrototypeOf(e) === ErrorClass.prototype)
        ) {
          msg =
            `Expected error to be instance of "${ErrorClass.name}", but was "${e.constructor.name}"${
              msg ? `: ${msg}` : "."
            }`;
          throw new AssertionError(msg);
        }
        if (msgIncludes && !e.message.includes(msgIncludes)) {
          msg =
            `Expected error message to include "${msgIncludes}", but got "${e.message}"${
              msg ? `: ${msg}` : "."
            }`;
          throw new AssertionError(msg);
        }
        doesThrow = true;
        error = e;
      }
      if (!doesThrow) {
        msg = `Expected function to throw${msg ? `: ${msg}` : "."}`;
        throw new AssertionError(msg);
      }
      return error;
    }
    exports_8("assertThrows", assertThrows);
    async function assertThrowsAsync(fn, ErrorClass, msgIncludes = "", msg) {
      let doesThrow = false;
      let error = null;
      try {
        await fn();
      } catch (e) {
        if (
          ErrorClass && !(Object.getPrototypeOf(e) === ErrorClass.prototype)
        ) {
          msg =
            `Expected error to be instance of "${ErrorClass.name}", but got "${e.name}"${
              msg ? `: ${msg}` : "."
            }`;
          throw new AssertionError(msg);
        }
        if (msgIncludes && !e.message.includes(msgIncludes)) {
          msg =
            `Expected error message to include "${msgIncludes}", but got "${e.message}"${
              msg ? `: ${msg}` : "."
            }`;
          throw new AssertionError(msg);
        }
        doesThrow = true;
        error = e;
      }
      if (!doesThrow) {
        msg = `Expected function to throw${msg ? `: ${msg}` : "."}`;
        throw new AssertionError(msg);
      }
      return error;
    }
    exports_8("assertThrowsAsync", assertThrowsAsync);
    /** Use this to stub out methods that will throw when invoked. */
    function unimplemented(msg) {
      throw new AssertionError(msg || "unimplemented");
    }
    exports_8("unimplemented", unimplemented);
    /** Use this to assert unreachable code. */
    function unreachable() {
      throw new AssertionError("unreachable");
    }
    exports_8("unreachable", unreachable);
    return {
      setters: [
        function (colors_ts_1_1) {
          colors_ts_1 = colors_ts_1_1;
        },
        function (diff_ts_1_1) {
          diff_ts_1 = diff_ts_1_1;
        },
      ],
      execute: function () {
        CAN_NOT_DISPLAY = "[Cannot display]";
        AssertionError = class AssertionError extends Error {
          constructor(message) {
            super(message);
            this.name = "AssertionError";
          }
        };
        exports_8("AssertionError", AssertionError);
      },
    };
  },
);
// Copyright the Browserify authors. MIT License.
// Ported from https://github.com/browserify/path-browserify/
System.register(
  "https://deno.land/std@0.53.0/path/win32",
  [
    "https://deno.land/std@0.53.0/path/_constants",
    "https://deno.land/std@0.53.0/path/_util",
    "https://deno.land/std@0.53.0/testing/asserts",
  ],
  function (exports_9, context_9) {
    "use strict";
    var cwd, env, _constants_ts_2, _util_ts_1, asserts_ts_1, sep, delimiter;
    var __moduleName = context_9 && context_9.id;
    function resolve(...pathSegments) {
      let resolvedDevice = "";
      let resolvedTail = "";
      let resolvedAbsolute = false;
      for (let i = pathSegments.length - 1; i >= -1; i--) {
        let path;
        if (i >= 0) {
          path = pathSegments[i];
        } else if (!resolvedDevice) {
          path = cwd();
        } else {
          // Windows has the concept of drive-specific current working
          // directories. If we've resolved a drive letter but not yet an
          // absolute path, get cwd for that drive, or the process cwd if
          // the drive cwd is not available. We're sure the device is not
          // a UNC path at this points, because UNC paths are always absolute.
          path = env.get(`=${resolvedDevice}`) || cwd();
          // Verify that a cwd was found and that it actually points
          // to our drive. If not, default to the drive's root.
          if (
            path === undefined ||
            path.slice(0, 3).toLowerCase() !==
              `${resolvedDevice.toLowerCase()}\\`
          ) {
            path = `${resolvedDevice}\\`;
          }
        }
        _util_ts_1.assertPath(path);
        const len = path.length;
        // Skip empty entries
        if (len === 0) {
          continue;
        }
        let rootEnd = 0;
        let device = "";
        let isAbsolute = false;
        const code = path.charCodeAt(0);
        // Try to match a root
        if (len > 1) {
          if (_util_ts_1.isPathSeparator(code)) {
            // Possible UNC root
            // If we started with a separator, we know we at least have an
            // absolute path of some kind (UNC or otherwise)
            isAbsolute = true;
            if (_util_ts_1.isPathSeparator(path.charCodeAt(1))) {
              // Matched double path separator at beginning
              let j = 2;
              let last = j;
              // Match 1 or more non-path separators
              for (; j < len; ++j) {
                if (_util_ts_1.isPathSeparator(path.charCodeAt(j))) {
                  break;
                }
              }
              if (j < len && j !== last) {
                const firstPart = path.slice(last, j);
                // Matched!
                last = j;
                // Match 1 or more path separators
                for (; j < len; ++j) {
                  if (!_util_ts_1.isPathSeparator(path.charCodeAt(j))) {
                    break;
                  }
                }
                if (j < len && j !== last) {
                  // Matched!
                  last = j;
                  // Match 1 or more non-path separators
                  for (; j < len; ++j) {
                    if (_util_ts_1.isPathSeparator(path.charCodeAt(j))) {
                      break;
                    }
                  }
                  if (j === len) {
                    // We matched a UNC root only
                    device = `\\\\${firstPart}\\${path.slice(last)}`;
                    rootEnd = j;
                  } else if (j !== last) {
                    // We matched a UNC root with leftovers
                    device = `\\\\${firstPart}\\${path.slice(last, j)}`;
                    rootEnd = j;
                  }
                }
              }
            } else {
              rootEnd = 1;
            }
          } else if (_util_ts_1.isWindowsDeviceRoot(code)) {
            // Possible device root
            if (path.charCodeAt(1) === _constants_ts_2.CHAR_COLON) {
              device = path.slice(0, 2);
              rootEnd = 2;
              if (len > 2) {
                if (_util_ts_1.isPathSeparator(path.charCodeAt(2))) {
                  // Treat separator following drive name as an absolute path
                  // indicator
                  isAbsolute = true;
                  rootEnd = 3;
                }
              }
            }
          }
        } else if (_util_ts_1.isPathSeparator(code)) {
          // `path` contains just a path separator
          rootEnd = 1;
          isAbsolute = true;
        }
        if (
          device.length > 0 &&
          resolvedDevice.length > 0 &&
          device.toLowerCase() !== resolvedDevice.toLowerCase()
        ) {
          // This path points to another device so it is not applicable
          continue;
        }
        if (resolvedDevice.length === 0 && device.length > 0) {
          resolvedDevice = device;
        }
        if (!resolvedAbsolute) {
          resolvedTail = `${path.slice(rootEnd)}\\${resolvedTail}`;
          resolvedAbsolute = isAbsolute;
        }
        if (resolvedAbsolute && resolvedDevice.length > 0) {
          break;
        }
      }
      // At this point the path should be resolved to a full absolute path,
      // but handle relative paths to be safe (might happen when process.cwd()
      // fails)
      // Normalize the tail path
      resolvedTail = _util_ts_1.normalizeString(
        resolvedTail,
        !resolvedAbsolute,
        "\\",
        _util_ts_1.isPathSeparator,
      );
      return resolvedDevice + (resolvedAbsolute ? "\\" : "") + resolvedTail ||
        ".";
    }
    exports_9("resolve", resolve);
    function normalize(path) {
      _util_ts_1.assertPath(path);
      const len = path.length;
      if (len === 0) {
        return ".";
      }
      let rootEnd = 0;
      let device;
      let isAbsolute = false;
      const code = path.charCodeAt(0);
      // Try to match a root
      if (len > 1) {
        if (_util_ts_1.isPathSeparator(code)) {
          // Possible UNC root
          // If we started with a separator, we know we at least have an absolute
          // path of some kind (UNC or otherwise)
          isAbsolute = true;
          if (_util_ts_1.isPathSeparator(path.charCodeAt(1))) {
            // Matched double path separator at beginning
            let j = 2;
            let last = j;
            // Match 1 or more non-path separators
            for (; j < len; ++j) {
              if (_util_ts_1.isPathSeparator(path.charCodeAt(j))) {
                break;
              }
            }
            if (j < len && j !== last) {
              const firstPart = path.slice(last, j);
              // Matched!
              last = j;
              // Match 1 or more path separators
              for (; j < len; ++j) {
                if (!_util_ts_1.isPathSeparator(path.charCodeAt(j))) {
                  break;
                }
              }
              if (j < len && j !== last) {
                // Matched!
                last = j;
                // Match 1 or more non-path separators
                for (; j < len; ++j) {
                  if (_util_ts_1.isPathSeparator(path.charCodeAt(j))) {
                    break;
                  }
                }
                if (j === len) {
                  // We matched a UNC root only
                  // Return the normalized version of the UNC root since there
                  // is nothing left to process
                  return `\\\\${firstPart}\\${path.slice(last)}\\`;
                } else if (j !== last) {
                  // We matched a UNC root with leftovers
                  device = `\\\\${firstPart}\\${path.slice(last, j)}`;
                  rootEnd = j;
                }
              }
            }
          } else {
            rootEnd = 1;
          }
        } else if (_util_ts_1.isWindowsDeviceRoot(code)) {
          // Possible device root
          if (path.charCodeAt(1) === _constants_ts_2.CHAR_COLON) {
            device = path.slice(0, 2);
            rootEnd = 2;
            if (len > 2) {
              if (_util_ts_1.isPathSeparator(path.charCodeAt(2))) {
                // Treat separator following drive name as an absolute path
                // indicator
                isAbsolute = true;
                rootEnd = 3;
              }
            }
          }
        }
      } else if (_util_ts_1.isPathSeparator(code)) {
        // `path` contains just a path separator, exit early to avoid unnecessary
        // work
        return "\\";
      }
      let tail;
      if (rootEnd < len) {
        tail = _util_ts_1.normalizeString(
          path.slice(rootEnd),
          !isAbsolute,
          "\\",
          _util_ts_1.isPathSeparator,
        );
      } else {
        tail = "";
      }
      if (tail.length === 0 && !isAbsolute) {
        tail = ".";
      }
      if (
        tail.length > 0 &&
        _util_ts_1.isPathSeparator(path.charCodeAt(len - 1))
      ) {
        tail += "\\";
      }
      if (device === undefined) {
        if (isAbsolute) {
          if (tail.length > 0) {
            return `\\${tail}`;
          } else {
            return "\\";
          }
        } else if (tail.length > 0) {
          return tail;
        } else {
          return "";
        }
      } else if (isAbsolute) {
        if (tail.length > 0) {
          return `${device}\\${tail}`;
        } else {
          return `${device}\\`;
        }
      } else if (tail.length > 0) {
        return device + tail;
      } else {
        return device;
      }
    }
    exports_9("normalize", normalize);
    function isAbsolute(path) {
      _util_ts_1.assertPath(path);
      const len = path.length;
      if (len === 0) {
        return false;
      }
      const code = path.charCodeAt(0);
      if (_util_ts_1.isPathSeparator(code)) {
        return true;
      } else if (_util_ts_1.isWindowsDeviceRoot(code)) {
        // Possible device root
        if (len > 2 && path.charCodeAt(1) === _constants_ts_2.CHAR_COLON) {
          if (_util_ts_1.isPathSeparator(path.charCodeAt(2))) {
            return true;
          }
        }
      }
      return false;
    }
    exports_9("isAbsolute", isAbsolute);
    function join(...paths) {
      const pathsCount = paths.length;
      if (pathsCount === 0) {
        return ".";
      }
      let joined;
      let firstPart = null;
      for (let i = 0; i < pathsCount; ++i) {
        const path = paths[i];
        _util_ts_1.assertPath(path);
        if (path.length > 0) {
          if (joined === undefined) {
            joined = firstPart = path;
          } else {
            joined += `\\${path}`;
          }
        }
      }
      if (joined === undefined) {
        return ".";
      }
      // Make sure that the joined path doesn't start with two slashes, because
      // normalize() will mistake it for an UNC path then.
      //
      // This step is skipped when it is very clear that the user actually
      // intended to point at an UNC path. This is assumed when the first
      // non-empty string arguments starts with exactly two slashes followed by
      // at least one more non-slash character.
      //
      // Note that for normalize() to treat a path as an UNC path it needs to
      // have at least 2 components, so we don't filter for that here.
      // This means that the user can use join to construct UNC paths from
      // a server name and a share name; for example:
      //   path.join('//server', 'share') -> '\\\\server\\share\\')
      let needsReplace = true;
      let slashCount = 0;
      asserts_ts_1.assert(firstPart != null);
      if (_util_ts_1.isPathSeparator(firstPart.charCodeAt(0))) {
        ++slashCount;
        const firstLen = firstPart.length;
        if (firstLen > 1) {
          if (_util_ts_1.isPathSeparator(firstPart.charCodeAt(1))) {
            ++slashCount;
            if (firstLen > 2) {
              if (_util_ts_1.isPathSeparator(firstPart.charCodeAt(2))) {
                ++slashCount;
              } else {
                // We matched a UNC path in the first part
                needsReplace = false;
              }
            }
          }
        }
      }
      if (needsReplace) {
        // Find any more consecutive slashes we need to replace
        for (; slashCount < joined.length; ++slashCount) {
          if (!_util_ts_1.isPathSeparator(joined.charCodeAt(slashCount))) {
            break;
          }
        }
        // Replace the slashes if needed
        if (slashCount >= 2) {
          joined = `\\${joined.slice(slashCount)}`;
        }
      }
      return normalize(joined);
    }
    exports_9("join", join);
    // It will solve the relative path from `from` to `to`, for instance:
    //  from = 'C:\\orandea\\test\\aaa'
    //  to = 'C:\\orandea\\impl\\bbb'
    // The output of the function should be: '..\\..\\impl\\bbb'
    function relative(from, to) {
      _util_ts_1.assertPath(from);
      _util_ts_1.assertPath(to);
      if (from === to) {
        return "";
      }
      const fromOrig = resolve(from);
      const toOrig = resolve(to);
      if (fromOrig === toOrig) {
        return "";
      }
      from = fromOrig.toLowerCase();
      to = toOrig.toLowerCase();
      if (from === to) {
        return "";
      }
      // Trim any leading backslashes
      let fromStart = 0;
      let fromEnd = from.length;
      for (; fromStart < fromEnd; ++fromStart) {
        if (
          from.charCodeAt(fromStart) !== _constants_ts_2.CHAR_BACKWARD_SLASH
        ) {
          break;
        }
      }
      // Trim trailing backslashes (applicable to UNC paths only)
      for (; fromEnd - 1 > fromStart; --fromEnd) {
        if (
          from.charCodeAt(fromEnd - 1) !== _constants_ts_2.CHAR_BACKWARD_SLASH
        ) {
          break;
        }
      }
      const fromLen = fromEnd - fromStart;
      // Trim any leading backslashes
      let toStart = 0;
      let toEnd = to.length;
      for (; toStart < toEnd; ++toStart) {
        if (to.charCodeAt(toStart) !== _constants_ts_2.CHAR_BACKWARD_SLASH) {
          break;
        }
      }
      // Trim trailing backslashes (applicable to UNC paths only)
      for (; toEnd - 1 > toStart; --toEnd) {
        if (to.charCodeAt(toEnd - 1) !== _constants_ts_2.CHAR_BACKWARD_SLASH) {
          break;
        }
      }
      const toLen = toEnd - toStart;
      // Compare paths to find the longest common path from root
      const length = fromLen < toLen ? fromLen : toLen;
      let lastCommonSep = -1;
      let i = 0;
      for (; i <= length; ++i) {
        if (i === length) {
          if (toLen > length) {
            if (
              to.charCodeAt(toStart + i) === _constants_ts_2.CHAR_BACKWARD_SLASH
            ) {
              // We get here if `from` is the exact base path for `to`.
              // For example: from='C:\\foo\\bar'; to='C:\\foo\\bar\\baz'
              return toOrig.slice(toStart + i + 1);
            } else if (i === 2) {
              // We get here if `from` is the device root.
              // For example: from='C:\\'; to='C:\\foo'
              return toOrig.slice(toStart + i);
            }
          }
          if (fromLen > length) {
            if (
              from.charCodeAt(fromStart + i) ===
                _constants_ts_2.CHAR_BACKWARD_SLASH
            ) {
              // We get here if `to` is the exact base path for `from`.
              // For example: from='C:\\foo\\bar'; to='C:\\foo'
              lastCommonSep = i;
            } else if (i === 2) {
              // We get here if `to` is the device root.
              // For example: from='C:\\foo\\bar'; to='C:\\'
              lastCommonSep = 3;
            }
          }
          break;
        }
        const fromCode = from.charCodeAt(fromStart + i);
        const toCode = to.charCodeAt(toStart + i);
        if (fromCode !== toCode) {
          break;
        } else if (fromCode === _constants_ts_2.CHAR_BACKWARD_SLASH) {
          lastCommonSep = i;
        }
      }
      // We found a mismatch before the first common path separator was seen, so
      // return the original `to`.
      if (i !== length && lastCommonSep === -1) {
        return toOrig;
      }
      let out = "";
      if (lastCommonSep === -1) {
        lastCommonSep = 0;
      }
      // Generate the relative path based on the path difference between `to` and
      // `from`
      for (i = fromStart + lastCommonSep + 1; i <= fromEnd; ++i) {
        if (
          i === fromEnd ||
          from.charCodeAt(i) === _constants_ts_2.CHAR_BACKWARD_SLASH
        ) {
          if (out.length === 0) {
            out += "..";
          } else {
            out += "\\..";
          }
        }
      }
      // Lastly, append the rest of the destination (`to`) path that comes after
      // the common path parts
      if (out.length > 0) {
        return out + toOrig.slice(toStart + lastCommonSep, toEnd);
      } else {
        toStart += lastCommonSep;
        if (
          toOrig.charCodeAt(toStart) === _constants_ts_2.CHAR_BACKWARD_SLASH
        ) {
          ++toStart;
        }
        return toOrig.slice(toStart, toEnd);
      }
    }
    exports_9("relative", relative);
    function toNamespacedPath(path) {
      // Note: this will *probably* throw somewhere.
      if (typeof path !== "string") {
        return path;
      }
      if (path.length === 0) {
        return "";
      }
      const resolvedPath = resolve(path);
      if (resolvedPath.length >= 3) {
        if (
          resolvedPath.charCodeAt(0) === _constants_ts_2.CHAR_BACKWARD_SLASH
        ) {
          // Possible UNC root
          if (
            resolvedPath.charCodeAt(1) === _constants_ts_2.CHAR_BACKWARD_SLASH
          ) {
            const code = resolvedPath.charCodeAt(2);
            if (
              code !== _constants_ts_2.CHAR_QUESTION_MARK &&
              code !== _constants_ts_2.CHAR_DOT
            ) {
              // Matched non-long UNC root, convert the path to a long UNC path
              return `\\\\?\\UNC\\${resolvedPath.slice(2)}`;
            }
          }
        } else if (_util_ts_1.isWindowsDeviceRoot(resolvedPath.charCodeAt(0))) {
          // Possible device root
          if (
            resolvedPath.charCodeAt(1) === _constants_ts_2.CHAR_COLON &&
            resolvedPath.charCodeAt(2) === _constants_ts_2.CHAR_BACKWARD_SLASH
          ) {
            // Matched device root, convert the path to a long UNC path
            return `\\\\?\\${resolvedPath}`;
          }
        }
      }
      return path;
    }
    exports_9("toNamespacedPath", toNamespacedPath);
    function dirname(path) {
      _util_ts_1.assertPath(path);
      const len = path.length;
      if (len === 0) {
        return ".";
      }
      let rootEnd = -1;
      let end = -1;
      let matchedSlash = true;
      let offset = 0;
      const code = path.charCodeAt(0);
      // Try to match a root
      if (len > 1) {
        if (_util_ts_1.isPathSeparator(code)) {
          // Possible UNC root
          rootEnd = offset = 1;
          if (_util_ts_1.isPathSeparator(path.charCodeAt(1))) {
            // Matched double path separator at beginning
            let j = 2;
            let last = j;
            // Match 1 or more non-path separators
            for (; j < len; ++j) {
              if (_util_ts_1.isPathSeparator(path.charCodeAt(j))) {
                break;
              }
            }
            if (j < len && j !== last) {
              // Matched!
              last = j;
              // Match 1 or more path separators
              for (; j < len; ++j) {
                if (!_util_ts_1.isPathSeparator(path.charCodeAt(j))) {
                  break;
                }
              }
              if (j < len && j !== last) {
                // Matched!
                last = j;
                // Match 1 or more non-path separators
                for (; j < len; ++j) {
                  if (_util_ts_1.isPathSeparator(path.charCodeAt(j))) {
                    break;
                  }
                }
                if (j === len) {
                  // We matched a UNC root only
                  return path;
                }
                if (j !== last) {
                  // We matched a UNC root with leftovers
                  // Offset by 1 to include the separator after the UNC root to
                  // treat it as a "normal root" on top of a (UNC) root
                  rootEnd = offset = j + 1;
                }
              }
            }
          }
        } else if (_util_ts_1.isWindowsDeviceRoot(code)) {
          // Possible device root
          if (path.charCodeAt(1) === _constants_ts_2.CHAR_COLON) {
            rootEnd = offset = 2;
            if (len > 2) {
              if (_util_ts_1.isPathSeparator(path.charCodeAt(2))) {
                rootEnd = offset = 3;
              }
            }
          }
        }
      } else if (_util_ts_1.isPathSeparator(code)) {
        // `path` contains just a path separator, exit early to avoid
        // unnecessary work
        return path;
      }
      for (let i = len - 1; i >= offset; --i) {
        if (_util_ts_1.isPathSeparator(path.charCodeAt(i))) {
          if (!matchedSlash) {
            end = i;
            break;
          }
        } else {
          // We saw the first non-path separator
          matchedSlash = false;
        }
      }
      if (end === -1) {
        if (rootEnd === -1) {
          return ".";
        } else {
          end = rootEnd;
        }
      }
      return path.slice(0, end);
    }
    exports_9("dirname", dirname);
    function basename(path, ext = "") {
      if (ext !== undefined && typeof ext !== "string") {
        throw new TypeError('"ext" argument must be a string');
      }
      _util_ts_1.assertPath(path);
      let start = 0;
      let end = -1;
      let matchedSlash = true;
      let i;
      // Check for a drive letter prefix so as not to mistake the following
      // path separator as an extra separator at the end of the path that can be
      // disregarded
      if (path.length >= 2) {
        const drive = path.charCodeAt(0);
        if (_util_ts_1.isWindowsDeviceRoot(drive)) {
          if (path.charCodeAt(1) === _constants_ts_2.CHAR_COLON) {
            start = 2;
          }
        }
      }
      if (ext !== undefined && ext.length > 0 && ext.length <= path.length) {
        if (ext.length === path.length && ext === path) {
          return "";
        }
        let extIdx = ext.length - 1;
        let firstNonSlashEnd = -1;
        for (i = path.length - 1; i >= start; --i) {
          const code = path.charCodeAt(i);
          if (_util_ts_1.isPathSeparator(code)) {
            // If we reached a path separator that was not part of a set of path
            // separators at the end of the string, stop now
            if (!matchedSlash) {
              start = i + 1;
              break;
            }
          } else {
            if (firstNonSlashEnd === -1) {
              // We saw the first non-path separator, remember this index in case
              // we need it if the extension ends up not matching
              matchedSlash = false;
              firstNonSlashEnd = i + 1;
            }
            if (extIdx >= 0) {
              // Try to match the explicit extension
              if (code === ext.charCodeAt(extIdx)) {
                if (--extIdx === -1) {
                  // We matched the extension, so mark this as the end of our path
                  // component
                  end = i;
                }
              } else {
                // Extension does not match, so our result is the entire path
                // component
                extIdx = -1;
                end = firstNonSlashEnd;
              }
            }
          }
        }
        if (start === end) {
          end = firstNonSlashEnd;
        } else if (end === -1) {
          end = path.length;
        }
        return path.slice(start, end);
      } else {
        for (i = path.length - 1; i >= start; --i) {
          if (_util_ts_1.isPathSeparator(path.charCodeAt(i))) {
            // If we reached a path separator that was not part of a set of path
            // separators at the end of the string, stop now
            if (!matchedSlash) {
              start = i + 1;
              break;
            }
          } else if (end === -1) {
            // We saw the first non-path separator, mark this as the end of our
            // path component
            matchedSlash = false;
            end = i + 1;
          }
        }
        if (end === -1) {
          return "";
        }
        return path.slice(start, end);
      }
    }
    exports_9("basename", basename);
    function extname(path) {
      _util_ts_1.assertPath(path);
      let start = 0;
      let startDot = -1;
      let startPart = 0;
      let end = -1;
      let matchedSlash = true;
      // Track the state of characters (if any) we see before our first dot and
      // after any path separator we find
      let preDotState = 0;
      // Check for a drive letter prefix so as not to mistake the following
      // path separator as an extra separator at the end of the path that can be
      // disregarded
      if (
        path.length >= 2 &&
        path.charCodeAt(1) === _constants_ts_2.CHAR_COLON &&
        _util_ts_1.isWindowsDeviceRoot(path.charCodeAt(0))
      ) {
        start = startPart = 2;
      }
      for (let i = path.length - 1; i >= start; --i) {
        const code = path.charCodeAt(i);
        if (_util_ts_1.isPathSeparator(code)) {
          // If we reached a path separator that was not part of a set of path
          // separators at the end of the string, stop now
          if (!matchedSlash) {
            startPart = i + 1;
            break;
          }
          continue;
        }
        if (end === -1) {
          // We saw the first non-path separator, mark this as the end of our
          // extension
          matchedSlash = false;
          end = i + 1;
        }
        if (code === _constants_ts_2.CHAR_DOT) {
          // If this is our first dot, mark it as the start of our extension
          if (startDot === -1) {
            startDot = i;
          } else if (preDotState !== 1) {
            preDotState = 1;
          }
        } else if (startDot !== -1) {
          // We saw a non-dot and non-path separator before our dot, so we should
          // have a good chance at having a non-empty extension
          preDotState = -1;
        }
      }
      if (
        startDot === -1 ||
        end === -1 ||
        // We saw a non-dot character immediately before the dot
        preDotState === 0 ||
        // The (right-most) trimmed path component is exactly '..'
        (preDotState === 1 && startDot === end - 1 &&
          startDot === startPart + 1)
      ) {
        return "";
      }
      return path.slice(startDot, end);
    }
    exports_9("extname", extname);
    function format(pathObject) {
      /* eslint-disable max-len */
      if (pathObject === null || typeof pathObject !== "object") {
        throw new TypeError(
          `The "pathObject" argument must be of type Object. Received type ${typeof pathObject}`,
        );
      }
      return _util_ts_1._format("\\", pathObject);
    }
    exports_9("format", format);
    function parse(path) {
      _util_ts_1.assertPath(path);
      const ret = { root: "", dir: "", base: "", ext: "", name: "" };
      const len = path.length;
      if (len === 0) {
        return ret;
      }
      let rootEnd = 0;
      let code = path.charCodeAt(0);
      // Try to match a root
      if (len > 1) {
        if (_util_ts_1.isPathSeparator(code)) {
          // Possible UNC root
          rootEnd = 1;
          if (_util_ts_1.isPathSeparator(path.charCodeAt(1))) {
            // Matched double path separator at beginning
            let j = 2;
            let last = j;
            // Match 1 or more non-path separators
            for (; j < len; ++j) {
              if (_util_ts_1.isPathSeparator(path.charCodeAt(j))) {
                break;
              }
            }
            if (j < len && j !== last) {
              // Matched!
              last = j;
              // Match 1 or more path separators
              for (; j < len; ++j) {
                if (!_util_ts_1.isPathSeparator(path.charCodeAt(j))) {
                  break;
                }
              }
              if (j < len && j !== last) {
                // Matched!
                last = j;
                // Match 1 or more non-path separators
                for (; j < len; ++j) {
                  if (_util_ts_1.isPathSeparator(path.charCodeAt(j))) {
                    break;
                  }
                }
                if (j === len) {
                  // We matched a UNC root only
                  rootEnd = j;
                } else if (j !== last) {
                  // We matched a UNC root with leftovers
                  rootEnd = j + 1;
                }
              }
            }
          }
        } else if (_util_ts_1.isWindowsDeviceRoot(code)) {
          // Possible device root
          if (path.charCodeAt(1) === _constants_ts_2.CHAR_COLON) {
            rootEnd = 2;
            if (len > 2) {
              if (_util_ts_1.isPathSeparator(path.charCodeAt(2))) {
                if (len === 3) {
                  // `path` contains just a drive root, exit early to avoid
                  // unnecessary work
                  ret.root = ret.dir = path;
                  return ret;
                }
                rootEnd = 3;
              }
            } else {
              // `path` contains just a drive root, exit early to avoid
              // unnecessary work
              ret.root = ret.dir = path;
              return ret;
            }
          }
        }
      } else if (_util_ts_1.isPathSeparator(code)) {
        // `path` contains just a path separator, exit early to avoid
        // unnecessary work
        ret.root = ret.dir = path;
        return ret;
      }
      if (rootEnd > 0) {
        ret.root = path.slice(0, rootEnd);
      }
      let startDot = -1;
      let startPart = rootEnd;
      let end = -1;
      let matchedSlash = true;
      let i = path.length - 1;
      // Track the state of characters (if any) we see before our first dot and
      // after any path separator we find
      let preDotState = 0;
      // Get non-dir info
      for (; i >= rootEnd; --i) {
        code = path.charCodeAt(i);
        if (_util_ts_1.isPathSeparator(code)) {
          // If we reached a path separator that was not part of a set of path
          // separators at the end of the string, stop now
          if (!matchedSlash) {
            startPart = i + 1;
            break;
          }
          continue;
        }
        if (end === -1) {
          // We saw the first non-path separator, mark this as the end of our
          // extension
          matchedSlash = false;
          end = i + 1;
        }
        if (code === _constants_ts_2.CHAR_DOT) {
          // If this is our first dot, mark it as the start of our extension
          if (startDot === -1) {
            startDot = i;
          } else if (preDotState !== 1) {
            preDotState = 1;
          }
        } else if (startDot !== -1) {
          // We saw a non-dot and non-path separator before our dot, so we should
          // have a good chance at having a non-empty extension
          preDotState = -1;
        }
      }
      if (
        startDot === -1 ||
        end === -1 ||
        // We saw a non-dot character immediately before the dot
        preDotState === 0 ||
        // The (right-most) trimmed path component is exactly '..'
        (preDotState === 1 && startDot === end - 1 &&
          startDot === startPart + 1)
      ) {
        if (end !== -1) {
          ret.base = ret.name = path.slice(startPart, end);
        }
      } else {
        ret.name = path.slice(startPart, startDot);
        ret.base = path.slice(startPart, end);
        ret.ext = path.slice(startDot, end);
      }
      // If the directory is the root, use the entire root as the `dir` including
      // the trailing slash if any (`C:\abc` -> `C:\`). Otherwise, strip out the
      // trailing slash (`C:\abc\def` -> `C:\abc`).
      if (startPart > 0 && startPart !== rootEnd) {
        ret.dir = path.slice(0, startPart - 1);
      } else {
        ret.dir = ret.root;
      }
      return ret;
    }
    exports_9("parse", parse);
    /** Converts a file URL to a path string.
     *
     *      fromFileUrl("file:///C:/Users/foo"); // "C:\\Users\\foo"
     *      fromFileUrl("file:///home/foo"); // "\\home\\foo"
     *
     * Note that non-file URLs are treated as file URLs and irrelevant components
     * are ignored.
     */
    function fromFileUrl(url) {
      return new URL(url).pathname
        .replace(/^\/*([A-Za-z]:)(\/|$)/, "$1/")
        .replace(/\//g, "\\");
    }
    exports_9("fromFileUrl", fromFileUrl);
    return {
      setters: [
        function (_constants_ts_2_1) {
          _constants_ts_2 = _constants_ts_2_1;
        },
        function (_util_ts_1_1) {
          _util_ts_1 = _util_ts_1_1;
        },
        function (asserts_ts_1_1) {
          asserts_ts_1 = asserts_ts_1_1;
        },
      ],
      execute: function () {
        cwd = Deno.cwd, env = Deno.env;
        exports_9("sep", sep = "\\");
        exports_9("delimiter", delimiter = ";");
      },
    };
  },
);
// Copyright the Browserify authors. MIT License.
// Ported from https://github.com/browserify/path-browserify/
System.register(
  "https://deno.land/std@0.53.0/path/posix",
  [
    "https://deno.land/std@0.53.0/path/_constants",
    "https://deno.land/std@0.53.0/path/_util",
  ],
  function (exports_10, context_10) {
    "use strict";
    var cwd, _constants_ts_3, _util_ts_2, sep, delimiter;
    var __moduleName = context_10 && context_10.id;
    // path.resolve([from ...], to)
    function resolve(...pathSegments) {
      let resolvedPath = "";
      let resolvedAbsolute = false;
      for (let i = pathSegments.length - 1; i >= -1 && !resolvedAbsolute; i--) {
        let path;
        if (i >= 0) {
          path = pathSegments[i];
        } else {
          path = cwd();
        }
        _util_ts_2.assertPath(path);
        // Skip empty entries
        if (path.length === 0) {
          continue;
        }
        resolvedPath = `${path}/${resolvedPath}`;
        resolvedAbsolute =
          path.charCodeAt(0) === _constants_ts_3.CHAR_FORWARD_SLASH;
      }
      // At this point the path should be resolved to a full absolute path, but
      // handle relative paths to be safe (might happen when process.cwd() fails)
      // Normalize the path
      resolvedPath = _util_ts_2.normalizeString(
        resolvedPath,
        !resolvedAbsolute,
        "/",
        _util_ts_2.isPosixPathSeparator,
      );
      if (resolvedAbsolute) {
        if (resolvedPath.length > 0) {
          return `/${resolvedPath}`;
        } else {
          return "/";
        }
      } else if (resolvedPath.length > 0) {
        return resolvedPath;
      } else {
        return ".";
      }
    }
    exports_10("resolve", resolve);
    function normalize(path) {
      _util_ts_2.assertPath(path);
      if (path.length === 0) {
        return ".";
      }
      const isAbsolute =
        path.charCodeAt(0) === _constants_ts_3.CHAR_FORWARD_SLASH;
      const trailingSeparator =
        path.charCodeAt(path.length - 1) === _constants_ts_3.CHAR_FORWARD_SLASH;
      // Normalize the path
      path = _util_ts_2.normalizeString(
        path,
        !isAbsolute,
        "/",
        _util_ts_2.isPosixPathSeparator,
      );
      if (path.length === 0 && !isAbsolute) {
        path = ".";
      }
      if (path.length > 0 && trailingSeparator) {
        path += "/";
      }
      if (isAbsolute) {
        return `/${path}`;
      }
      return path;
    }
    exports_10("normalize", normalize);
    function isAbsolute(path) {
      _util_ts_2.assertPath(path);
      return path.length > 0 &&
        path.charCodeAt(0) === _constants_ts_3.CHAR_FORWARD_SLASH;
    }
    exports_10("isAbsolute", isAbsolute);
    function join(...paths) {
      if (paths.length === 0) {
        return ".";
      }
      let joined;
      for (let i = 0, len = paths.length; i < len; ++i) {
        const path = paths[i];
        _util_ts_2.assertPath(path);
        if (path.length > 0) {
          if (!joined) {
            joined = path;
          } else {
            joined += `/${path}`;
          }
        }
      }
      if (!joined) {
        return ".";
      }
      return normalize(joined);
    }
    exports_10("join", join);
    function relative(from, to) {
      _util_ts_2.assertPath(from);
      _util_ts_2.assertPath(to);
      if (from === to) {
        return "";
      }
      from = resolve(from);
      to = resolve(to);
      if (from === to) {
        return "";
      }
      // Trim any leading backslashes
      let fromStart = 1;
      const fromEnd = from.length;
      for (; fromStart < fromEnd; ++fromStart) {
        if (from.charCodeAt(fromStart) !== _constants_ts_3.CHAR_FORWARD_SLASH) {
          break;
        }
      }
      const fromLen = fromEnd - fromStart;
      // Trim any leading backslashes
      let toStart = 1;
      const toEnd = to.length;
      for (; toStart < toEnd; ++toStart) {
        if (to.charCodeAt(toStart) !== _constants_ts_3.CHAR_FORWARD_SLASH) {
          break;
        }
      }
      const toLen = toEnd - toStart;
      // Compare paths to find the longest common path from root
      const length = fromLen < toLen ? fromLen : toLen;
      let lastCommonSep = -1;
      let i = 0;
      for (; i <= length; ++i) {
        if (i === length) {
          if (toLen > length) {
            if (
              to.charCodeAt(toStart + i) === _constants_ts_3.CHAR_FORWARD_SLASH
            ) {
              // We get here if `from` is the exact base path for `to`.
              // For example: from='/foo/bar'; to='/foo/bar/baz'
              return to.slice(toStart + i + 1);
            } else if (i === 0) {
              // We get here if `from` is the root
              // For example: from='/'; to='/foo'
              return to.slice(toStart + i);
            }
          } else if (fromLen > length) {
            if (
              from.charCodeAt(fromStart + i) ===
                _constants_ts_3.CHAR_FORWARD_SLASH
            ) {
              // We get here if `to` is the exact base path for `from`.
              // For example: from='/foo/bar/baz'; to='/foo/bar'
              lastCommonSep = i;
            } else if (i === 0) {
              // We get here if `to` is the root.
              // For example: from='/foo'; to='/'
              lastCommonSep = 0;
            }
          }
          break;
        }
        const fromCode = from.charCodeAt(fromStart + i);
        const toCode = to.charCodeAt(toStart + i);
        if (fromCode !== toCode) {
          break;
        } else if (fromCode === _constants_ts_3.CHAR_FORWARD_SLASH) {
          lastCommonSep = i;
        }
      }
      let out = "";
      // Generate the relative path based on the path difference between `to`
      // and `from`
      for (i = fromStart + lastCommonSep + 1; i <= fromEnd; ++i) {
        if (
          i === fromEnd ||
          from.charCodeAt(i) === _constants_ts_3.CHAR_FORWARD_SLASH
        ) {
          if (out.length === 0) {
            out += "..";
          } else {
            out += "/..";
          }
        }
      }
      // Lastly, append the rest of the destination (`to`) path that comes after
      // the common path parts
      if (out.length > 0) {
        return out + to.slice(toStart + lastCommonSep);
      } else {
        toStart += lastCommonSep;
        if (to.charCodeAt(toStart) === _constants_ts_3.CHAR_FORWARD_SLASH) {
          ++toStart;
        }
        return to.slice(toStart);
      }
    }
    exports_10("relative", relative);
    function toNamespacedPath(path) {
      // Non-op on posix systems
      return path;
    }
    exports_10("toNamespacedPath", toNamespacedPath);
    function dirname(path) {
      _util_ts_2.assertPath(path);
      if (path.length === 0) {
        return ".";
      }
      const hasRoot = path.charCodeAt(0) === _constants_ts_3.CHAR_FORWARD_SLASH;
      let end = -1;
      let matchedSlash = true;
      for (let i = path.length - 1; i >= 1; --i) {
        if (path.charCodeAt(i) === _constants_ts_3.CHAR_FORWARD_SLASH) {
          if (!matchedSlash) {
            end = i;
            break;
          }
        } else {
          // We saw the first non-path separator
          matchedSlash = false;
        }
      }
      if (end === -1) {
        return hasRoot ? "/" : ".";
      }
      if (hasRoot && end === 1) {
        return "//";
      }
      return path.slice(0, end);
    }
    exports_10("dirname", dirname);
    function basename(path, ext = "") {
      if (ext !== undefined && typeof ext !== "string") {
        throw new TypeError('"ext" argument must be a string');
      }
      _util_ts_2.assertPath(path);
      let start = 0;
      let end = -1;
      let matchedSlash = true;
      let i;
      if (ext !== undefined && ext.length > 0 && ext.length <= path.length) {
        if (ext.length === path.length && ext === path) {
          return "";
        }
        let extIdx = ext.length - 1;
        let firstNonSlashEnd = -1;
        for (i = path.length - 1; i >= 0; --i) {
          const code = path.charCodeAt(i);
          if (code === _constants_ts_3.CHAR_FORWARD_SLASH) {
            // If we reached a path separator that was not part of a set of path
            // separators at the end of the string, stop now
            if (!matchedSlash) {
              start = i + 1;
              break;
            }
          } else {
            if (firstNonSlashEnd === -1) {
              // We saw the first non-path separator, remember this index in case
              // we need it if the extension ends up not matching
              matchedSlash = false;
              firstNonSlashEnd = i + 1;
            }
            if (extIdx >= 0) {
              // Try to match the explicit extension
              if (code === ext.charCodeAt(extIdx)) {
                if (--extIdx === -1) {
                  // We matched the extension, so mark this as the end of our path
                  // component
                  end = i;
                }
              } else {
                // Extension does not match, so our result is the entire path
                // component
                extIdx = -1;
                end = firstNonSlashEnd;
              }
            }
          }
        }
        if (start === end) {
          end = firstNonSlashEnd;
        } else if (end === -1) {
          end = path.length;
        }
        return path.slice(start, end);
      } else {
        for (i = path.length - 1; i >= 0; --i) {
          if (path.charCodeAt(i) === _constants_ts_3.CHAR_FORWARD_SLASH) {
            // If we reached a path separator that was not part of a set of path
            // separators at the end of the string, stop now
            if (!matchedSlash) {
              start = i + 1;
              break;
            }
          } else if (end === -1) {
            // We saw the first non-path separator, mark this as the end of our
            // path component
            matchedSlash = false;
            end = i + 1;
          }
        }
        if (end === -1) {
          return "";
        }
        return path.slice(start, end);
      }
    }
    exports_10("basename", basename);
    function extname(path) {
      _util_ts_2.assertPath(path);
      let startDot = -1;
      let startPart = 0;
      let end = -1;
      let matchedSlash = true;
      // Track the state of characters (if any) we see before our first dot and
      // after any path separator we find
      let preDotState = 0;
      for (let i = path.length - 1; i >= 0; --i) {
        const code = path.charCodeAt(i);
        if (code === _constants_ts_3.CHAR_FORWARD_SLASH) {
          // If we reached a path separator that was not part of a set of path
          // separators at the end of the string, stop now
          if (!matchedSlash) {
            startPart = i + 1;
            break;
          }
          continue;
        }
        if (end === -1) {
          // We saw the first non-path separator, mark this as the end of our
          // extension
          matchedSlash = false;
          end = i + 1;
        }
        if (code === _constants_ts_3.CHAR_DOT) {
          // If this is our first dot, mark it as the start of our extension
          if (startDot === -1) {
            startDot = i;
          } else if (preDotState !== 1) {
            preDotState = 1;
          }
        } else if (startDot !== -1) {
          // We saw a non-dot and non-path separator before our dot, so we should
          // have a good chance at having a non-empty extension
          preDotState = -1;
        }
      }
      if (
        startDot === -1 ||
        end === -1 ||
        // We saw a non-dot character immediately before the dot
        preDotState === 0 ||
        // The (right-most) trimmed path component is exactly '..'
        (preDotState === 1 && startDot === end - 1 &&
          startDot === startPart + 1)
      ) {
        return "";
      }
      return path.slice(startDot, end);
    }
    exports_10("extname", extname);
    function format(pathObject) {
      /* eslint-disable max-len */
      if (pathObject === null || typeof pathObject !== "object") {
        throw new TypeError(
          `The "pathObject" argument must be of type Object. Received type ${typeof pathObject}`,
        );
      }
      return _util_ts_2._format("/", pathObject);
    }
    exports_10("format", format);
    function parse(path) {
      _util_ts_2.assertPath(path);
      const ret = { root: "", dir: "", base: "", ext: "", name: "" };
      if (path.length === 0) {
        return ret;
      }
      const isAbsolute =
        path.charCodeAt(0) === _constants_ts_3.CHAR_FORWARD_SLASH;
      let start;
      if (isAbsolute) {
        ret.root = "/";
        start = 1;
      } else {
        start = 0;
      }
      let startDot = -1;
      let startPart = 0;
      let end = -1;
      let matchedSlash = true;
      let i = path.length - 1;
      // Track the state of characters (if any) we see before our first dot and
      // after any path separator we find
      let preDotState = 0;
      // Get non-dir info
      for (; i >= start; --i) {
        const code = path.charCodeAt(i);
        if (code === _constants_ts_3.CHAR_FORWARD_SLASH) {
          // If we reached a path separator that was not part of a set of path
          // separators at the end of the string, stop now
          if (!matchedSlash) {
            startPart = i + 1;
            break;
          }
          continue;
        }
        if (end === -1) {
          // We saw the first non-path separator, mark this as the end of our
          // extension
          matchedSlash = false;
          end = i + 1;
        }
        if (code === _constants_ts_3.CHAR_DOT) {
          // If this is our first dot, mark it as the start of our extension
          if (startDot === -1) {
            startDot = i;
          } else if (preDotState !== 1) {
            preDotState = 1;
          }
        } else if (startDot !== -1) {
          // We saw a non-dot and non-path separator before our dot, so we should
          // have a good chance at having a non-empty extension
          preDotState = -1;
        }
      }
      if (
        startDot === -1 ||
        end === -1 ||
        // We saw a non-dot character immediately before the dot
        preDotState === 0 ||
        // The (right-most) trimmed path component is exactly '..'
        (preDotState === 1 && startDot === end - 1 &&
          startDot === startPart + 1)
      ) {
        if (end !== -1) {
          if (startPart === 0 && isAbsolute) {
            ret.base = ret.name = path.slice(1, end);
          } else {
            ret.base = ret.name = path.slice(startPart, end);
          }
        }
      } else {
        if (startPart === 0 && isAbsolute) {
          ret.name = path.slice(1, startDot);
          ret.base = path.slice(1, end);
        } else {
          ret.name = path.slice(startPart, startDot);
          ret.base = path.slice(startPart, end);
        }
        ret.ext = path.slice(startDot, end);
      }
      if (startPart > 0) {
        ret.dir = path.slice(0, startPart - 1);
      } else if (isAbsolute) {
        ret.dir = "/";
      }
      return ret;
    }
    exports_10("parse", parse);
    /** Converts a file URL to a path string.
     *
     *      fromFileUrl("file:///home/foo"); // "/home/foo"
     *
     * Note that non-file URLs are treated as file URLs and irrelevant components
     * are ignored.
     */
    function fromFileUrl(url) {
      return new URL(url).pathname;
    }
    exports_10("fromFileUrl", fromFileUrl);
    return {
      setters: [
        function (_constants_ts_3_1) {
          _constants_ts_3 = _constants_ts_3_1;
        },
        function (_util_ts_2_1) {
          _util_ts_2 = _util_ts_2_1;
        },
      ],
      execute: function () {
        cwd = Deno.cwd;
        exports_10("sep", sep = "/");
        exports_10("delimiter", delimiter = ":");
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.53.0/path/separator",
  [],
  function (exports_11, context_11) {
    "use strict";
    var isWindows, SEP, SEP_PATTERN;
    var __moduleName = context_11 && context_11.id;
    return {
      setters: [],
      execute: function () {
        // Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
        isWindows = Deno.build.os == "windows";
        exports_11("SEP", SEP = isWindows ? "\\" : "/");
        exports_11("SEP_PATTERN", SEP_PATTERN = isWindows ? /[\\/]+/ : /\/+/);
      },
    };
  },
);
// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
System.register(
  "https://deno.land/std@0.53.0/path/common",
  ["https://deno.land/std@0.53.0/path/separator"],
  function (exports_12, context_12) {
    "use strict";
    var separator_ts_1;
    var __moduleName = context_12 && context_12.id;
    /** Determines the common path from a set of paths, using an optional separator,
     * which defaults to the OS default separator.
     *
     *       import { common } from "https://deno.land/std/path/mod.ts";
     *       const p = common([
     *         "./deno/std/path/mod.ts",
     *         "./deno/std/fs/mod.ts",
     *       ]);
     *       console.log(p); // "./deno/std/"
     *
     */
    function common(paths, sep = separator_ts_1.SEP) {
      const [first = "", ...remaining] = paths;
      if (first === "" || remaining.length === 0) {
        return first.substring(0, first.lastIndexOf(sep) + 1);
      }
      const parts = first.split(sep);
      let endOfPrefix = parts.length;
      for (const path of remaining) {
        const compare = path.split(sep);
        for (let i = 0; i < endOfPrefix; i++) {
          if (compare[i] !== parts[i]) {
            endOfPrefix = i;
          }
        }
        if (endOfPrefix === 0) {
          return "";
        }
      }
      const prefix = parts.slice(0, endOfPrefix).join(sep);
      return prefix.endsWith(sep) ? prefix : `${prefix}${sep}`;
    }
    exports_12("common", common);
    return {
      setters: [
        function (separator_ts_1_1) {
          separator_ts_1 = separator_ts_1_1;
        },
      ],
      execute: function () {
      },
    };
  },
);
// This file is ported from globrex@0.1.2
// MIT License
// Copyright (c) 2018 Terkel Gjervig Nielsen
System.register(
  "https://deno.land/std@0.53.0/path/_globrex",
  [],
  function (exports_13, context_13) {
    "use strict";
    var isWin,
      SEP,
      SEP_ESC,
      SEP_RAW,
      GLOBSTAR,
      WILDCARD,
      GLOBSTAR_SEGMENT,
      WILDCARD_SEGMENT;
    var __moduleName = context_13 && context_13.id;
    /**
     * Convert any glob pattern to a JavaScript Regexp object
     * @param glob Glob pattern to convert
     * @param opts Configuration object
     * @returns Converted object with string, segments and RegExp object
     */
    function globrex(
      glob,
      {
        extended = false,
        globstar = false,
        strict = false,
        filepath = false,
        flags = "",
      } = {},
    ) {
      const sepPattern = new RegExp(`^${SEP}${strict ? "" : "+"}$`);
      let regex = "";
      let segment = "";
      let pathRegexStr = "";
      const pathSegments = [];
      // If we are doing extended matching, this boolean is true when we are inside
      // a group (eg {*.html,*.js}), and false otherwise.
      let inGroup = false;
      let inRange = false;
      // extglob stack. Keep track of scope
      const ext = [];
      // Helper function to build string and segments
      function add(str, options = { split: false, last: false, only: "" }) {
        const { split, last, only } = options;
        if (only !== "path") {
          regex += str;
        }
        if (filepath && only !== "regex") {
          pathRegexStr += str.match(sepPattern) ? SEP : str;
          if (split) {
            if (last) {
              segment += str;
            }
            if (segment !== "") {
              // change it 'includes'
              if (!flags.includes("g")) {
                segment = `^${segment}$`;
              }
              pathSegments.push(new RegExp(segment, flags));
            }
            segment = "";
          } else {
            segment += str;
          }
        }
      }
      let c, n;
      for (let i = 0; i < glob.length; i++) {
        c = glob[i];
        n = glob[i + 1];
        if (["\\", "$", "^", ".", "="].includes(c)) {
          add(`\\${c}`);
          continue;
        }
        if (c.match(sepPattern)) {
          add(SEP, { split: true });
          if (n != null && n.match(sepPattern) && !strict) {
            regex += "?";
          }
          continue;
        }
        if (c === "(") {
          if (ext.length) {
            add(`${c}?:`);
            continue;
          }
          add(`\\${c}`);
          continue;
        }
        if (c === ")") {
          if (ext.length) {
            add(c);
            const type = ext.pop();
            if (type === "@") {
              add("{1}");
            } else if (type === "!") {
              add(WILDCARD);
            } else {
              add(type);
            }
            continue;
          }
          add(`\\${c}`);
          continue;
        }
        if (c === "|") {
          if (ext.length) {
            add(c);
            continue;
          }
          add(`\\${c}`);
          continue;
        }
        if (c === "+") {
          if (n === "(" && extended) {
            ext.push(c);
            continue;
          }
          add(`\\${c}`);
          continue;
        }
        if (c === "@" && extended) {
          if (n === "(") {
            ext.push(c);
            continue;
          }
        }
        if (c === "!") {
          if (extended) {
            if (inRange) {
              add("^");
              continue;
            }
            if (n === "(") {
              ext.push(c);
              add("(?!");
              i++;
              continue;
            }
            add(`\\${c}`);
            continue;
          }
          add(`\\${c}`);
          continue;
        }
        if (c === "?") {
          if (extended) {
            if (n === "(") {
              ext.push(c);
            } else {
              add(".");
            }
            continue;
          }
          add(`\\${c}`);
          continue;
        }
        if (c === "[") {
          if (inRange && n === ":") {
            i++; // skip [
            let value = "";
            while (glob[++i] !== ":") {
              value += glob[i];
            }
            if (value === "alnum") {
              add("(?:\\w|\\d)");
            } else if (value === "space") {
              add("\\s");
            } else if (value === "digit") {
              add("\\d");
            }
            i++; // skip last ]
            continue;
          }
          if (extended) {
            inRange = true;
            add(c);
            continue;
          }
          add(`\\${c}`);
          continue;
        }
        if (c === "]") {
          if (extended) {
            inRange = false;
            add(c);
            continue;
          }
          add(`\\${c}`);
          continue;
        }
        if (c === "{") {
          if (extended) {
            inGroup = true;
            add("(?:");
            continue;
          }
          add(`\\${c}`);
          continue;
        }
        if (c === "}") {
          if (extended) {
            inGroup = false;
            add(")");
            continue;
          }
          add(`\\${c}`);
          continue;
        }
        if (c === ",") {
          if (inGroup) {
            add("|");
            continue;
          }
          add(`\\${c}`);
          continue;
        }
        if (c === "*") {
          if (n === "(" && extended) {
            ext.push(c);
            continue;
          }
          // Move over all consecutive "*"'s.
          // Also store the previous and next characters
          const prevChar = glob[i - 1];
          let starCount = 1;
          while (glob[i + 1] === "*") {
            starCount++;
            i++;
          }
          const nextChar = glob[i + 1];
          if (!globstar) {
            // globstar is disabled, so treat any number of "*" as one
            add(".*");
          } else {
            // globstar is enabled, so determine if this is a globstar segment
            const isGlobstar = starCount > 1 && // multiple "*"'s
              // from the start of the segment
              [SEP_RAW, "/", undefined].includes(prevChar) &&
              // to the end of the segment
              [SEP_RAW, "/", undefined].includes(nextChar);
            if (isGlobstar) {
              // it's a globstar, so match zero or more path segments
              add(GLOBSTAR, { only: "regex" });
              add(GLOBSTAR_SEGMENT, { only: "path", last: true, split: true });
              i++; // move over the "/"
            } else {
              // it's not a globstar, so only match one path segment
              add(WILDCARD, { only: "regex" });
              add(WILDCARD_SEGMENT, { only: "path" });
            }
          }
          continue;
        }
        add(c);
      }
      // When regexp 'g' flag is specified don't
      // constrain the regular expression with ^ & $
      if (!flags.includes("g")) {
        regex = `^${regex}$`;
        segment = `^${segment}$`;
        if (filepath) {
          pathRegexStr = `^${pathRegexStr}$`;
        }
      }
      const result = { regex: new RegExp(regex, flags) };
      // Push the last segment
      if (filepath) {
        pathSegments.push(new RegExp(segment, flags));
        result.path = {
          regex: new RegExp(pathRegexStr, flags),
          segments: pathSegments,
          globstar: new RegExp(
            !flags.includes("g") ? `^${GLOBSTAR_SEGMENT}$` : GLOBSTAR_SEGMENT,
            flags,
          ),
        };
      }
      return result;
    }
    exports_13("globrex", globrex);
    return {
      setters: [],
      execute: function () {
        isWin = Deno.build.os === "windows";
        SEP = isWin ? `(?:\\\\|\\/)` : `\\/`;
        SEP_ESC = isWin ? `\\\\` : `/`;
        SEP_RAW = isWin ? `\\` : `/`;
        GLOBSTAR = `(?:(?:[^${SEP_ESC}/]*(?:${SEP_ESC}|\/|$))*)`;
        WILDCARD = `(?:[^${SEP_ESC}/]*)`;
        GLOBSTAR_SEGMENT = `((?:[^${SEP_ESC}/]*(?:${SEP_ESC}|\/|$))*)`;
        WILDCARD_SEGMENT = `(?:[^${SEP_ESC}/]*)`;
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.53.0/path/glob",
  [
    "https://deno.land/std@0.53.0/path/separator",
    "https://deno.land/std@0.53.0/path/_globrex",
    "https://deno.land/std@0.53.0/path/mod",
    "https://deno.land/std@0.53.0/testing/asserts",
  ],
  function (exports_14, context_14) {
    "use strict";
    var separator_ts_2, _globrex_ts_1, mod_ts_1, asserts_ts_2;
    var __moduleName = context_14 && context_14.id;
    /**
     * Generate a regex based on glob pattern and options
     * This was meant to be using the the `fs.walk` function
     * but can be used anywhere else.
     * Examples:
     *
     *     Looking for all the `ts` files:
     *     walkSync(".", {
     *       match: [globToRegExp("*.ts")]
     *     })
     *
     *     Looking for all the `.json` files in any subfolder:
     *     walkSync(".", {
     *       match: [globToRegExp(join("a", "**", "*.json"),{
     *         flags: "g",
     *         extended: true,
     *         globstar: true
     *       })]
     *     })
     *
     * @param glob - Glob pattern to be used
     * @param options - Specific options for the glob pattern
     * @returns A RegExp for the glob pattern
     */
    function globToRegExp(glob, { extended = false, globstar = true } = {}) {
      const result = _globrex_ts_1.globrex(glob, {
        extended,
        globstar,
        strict: false,
        filepath: true,
      });
      asserts_ts_2.assert(result.path != null);
      return result.path.regex;
    }
    exports_14("globToRegExp", globToRegExp);
    /** Test whether the given string is a glob */
    function isGlob(str) {
      const chars = { "{": "}", "(": ")", "[": "]" };
      /* eslint-disable-next-line max-len */
      const regex =
        /\\(.)|(^!|\*|[\].+)]\?|\[[^\\\]]+\]|\{[^\\}]+\}|\(\?[:!=][^\\)]+\)|\([^|]+\|[^\\)]+\))/;
      if (str === "") {
        return false;
      }
      let match;
      while ((match = regex.exec(str))) {
        if (match[2]) {
          return true;
        }
        let idx = match.index + match[0].length;
        // if an open bracket/brace/paren is escaped,
        // set the index to the next closing character
        const open = match[1];
        const close = open ? chars[open] : null;
        if (open && close) {
          const n = str.indexOf(close, idx);
          if (n !== -1) {
            idx = n + 1;
          }
        }
        str = str.slice(idx);
      }
      return false;
    }
    exports_14("isGlob", isGlob);
    /** Like normalize(), but doesn't collapse "**\/.." when `globstar` is true. */
    function normalizeGlob(glob, { globstar = false } = {}) {
      if (!!glob.match(/\0/g)) {
        throw new Error(`Glob contains invalid characters: "${glob}"`);
      }
      if (!globstar) {
        return mod_ts_1.normalize(glob);
      }
      const s = separator_ts_2.SEP_PATTERN.source;
      const badParentPattern = new RegExp(
        `(?<=(${s}|^)\\*\\*${s})\\.\\.(?=${s}|$)`,
        "g",
      );
      return mod_ts_1.normalize(glob.replace(badParentPattern, "\0")).replace(
        /\0/g,
        "..",
      );
    }
    exports_14("normalizeGlob", normalizeGlob);
    /** Like join(), but doesn't collapse "**\/.." when `globstar` is true. */
    function joinGlobs(globs, { extended = false, globstar = false } = {}) {
      if (!globstar || globs.length == 0) {
        return mod_ts_1.join(...globs);
      }
      if (globs.length === 0) {
        return ".";
      }
      let joined;
      for (const glob of globs) {
        const path = glob;
        if (path.length > 0) {
          if (!joined) {
            joined = path;
          } else {
            joined += `${separator_ts_2.SEP}${path}`;
          }
        }
      }
      if (!joined) {
        return ".";
      }
      return normalizeGlob(joined, { extended, globstar });
    }
    exports_14("joinGlobs", joinGlobs);
    return {
      setters: [
        function (separator_ts_2_1) {
          separator_ts_2 = separator_ts_2_1;
        },
        function (_globrex_ts_1_1) {
          _globrex_ts_1 = _globrex_ts_1_1;
        },
        function (mod_ts_1_1) {
          mod_ts_1 = mod_ts_1_1;
        },
        function (asserts_ts_2_1) {
          asserts_ts_2 = asserts_ts_2_1;
        },
      ],
      execute: function () {
      },
    };
  },
);
// Copyright the Browserify authors. MIT License.
// Ported mostly from https://github.com/browserify/path-browserify/
System.register(
  "https://deno.land/std@0.53.0/path/mod",
  [
    "https://deno.land/std@0.53.0/path/win32",
    "https://deno.land/std@0.53.0/path/posix",
    "https://deno.land/std@0.53.0/path/common",
    "https://deno.land/std@0.53.0/path/separator",
    "https://deno.land/std@0.53.0/path/interface",
    "https://deno.land/std@0.53.0/path/glob",
  ],
  function (exports_15, context_15) {
    "use strict";
    var _win32,
      _posix,
      isWindows,
      path,
      win32,
      posix,
      basename,
      delimiter,
      dirname,
      extname,
      format,
      fromFileUrl,
      isAbsolute,
      join,
      normalize,
      parse,
      relative,
      resolve,
      sep,
      toNamespacedPath;
    var __moduleName = context_15 && context_15.id;
    var exportedNames_1 = {
      "win32": true,
      "posix": true,
      "basename": true,
      "delimiter": true,
      "dirname": true,
      "extname": true,
      "format": true,
      "fromFileUrl": true,
      "isAbsolute": true,
      "join": true,
      "normalize": true,
      "parse": true,
      "relative": true,
      "resolve": true,
      "sep": true,
      "toNamespacedPath": true,
      "SEP": true,
      "SEP_PATTERN": true,
    };
    function exportStar_1(m) {
      var exports = {};
      for (var n in m) {
        if (n !== "default" && !exportedNames_1.hasOwnProperty(n)) {
          exports[n] = m[n];
        }
      }
      exports_15(exports);
    }
    return {
      setters: [
        function (_win32_1) {
          _win32 = _win32_1;
        },
        function (_posix_1) {
          _posix = _posix_1;
        },
        function (common_ts_1_1) {
          exportStar_1(common_ts_1_1);
        },
        function (separator_ts_3_1) {
          exports_15({
            "SEP": separator_ts_3_1["SEP"],
            "SEP_PATTERN": separator_ts_3_1["SEP_PATTERN"],
          });
        },
        function (interface_ts_1_1) {
          exportStar_1(interface_ts_1_1);
        },
        function (glob_ts_1_1) {
          exportStar_1(glob_ts_1_1);
        },
      ],
      execute: function () {
        isWindows = Deno.build.os == "windows";
        path = isWindows ? _win32 : _posix;
        exports_15("win32", win32 = _win32);
        exports_15("posix", posix = _posix);
        exports_15("basename", basename = path.basename),
          exports_15("delimiter", delimiter = path.delimiter),
          exports_15("dirname", dirname = path.dirname),
          exports_15("extname", extname = path.extname),
          exports_15("format", format = path.format),
          exports_15("fromFileUrl", fromFileUrl = path.fromFileUrl),
          exports_15("isAbsolute", isAbsolute = path.isAbsolute),
          exports_15("join", join = path.join),
          exports_15("normalize", normalize = path.normalize),
          exports_15("parse", parse = path.parse),
          exports_15("relative", relative = path.relative),
          exports_15("resolve", resolve = path.resolve),
          exports_15("sep", sep = path.sep),
          exports_15(
            "toNamespacedPath",
            toNamespacedPath = path.toNamespacedPath,
          );
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.53.0/io/util",
  [
    "https://deno.land/std@0.53.0/path/mod",
    "https://deno.land/std@0.53.0/encoding/utf8",
  ],
  function (exports_16, context_16) {
    "use strict";
    var Buffer, mkdir, open, path, utf8_ts_1;
    var __moduleName = context_16 && context_16.id;
    /**
     * Copy bytes from one Uint8Array to another.  Bytes from `src` which don't fit
     * into `dst` will not be copied.
     *
     * @param src Source byte array
     * @param dst Destination byte array
     * @param off Offset into `dst` at which to begin writing values from `src`.
     * @return number of bytes copied
     */
    function copyBytes(src, dst, off = 0) {
      off = Math.max(0, Math.min(off, dst.byteLength));
      const dstBytesAvailable = dst.byteLength - off;
      if (src.byteLength > dstBytesAvailable) {
        src = src.subarray(0, dstBytesAvailable);
      }
      dst.set(src, off);
      return src.byteLength;
    }
    exports_16("copyBytes", copyBytes);
    function charCode(s) {
      return s.charCodeAt(0);
    }
    exports_16("charCode", charCode);
    function stringsReader(s) {
      return new Buffer(utf8_ts_1.encode(s).buffer);
    }
    exports_16("stringsReader", stringsReader);
    /** Create or open a temporal file at specified directory with prefix and
     *  postfix
     * */
    async function tempFile(dir, opts = { prefix: "", postfix: "" }) {
      const r = Math.floor(Math.random() * 1000000);
      const filepath = path.resolve(
        `${dir}/${opts.prefix || ""}${r}${opts.postfix || ""}`,
      );
      await mkdir(path.dirname(filepath), { recursive: true });
      const file = await open(filepath, {
        create: true,
        read: true,
        write: true,
        append: true,
      });
      return { file, filepath };
    }
    exports_16("tempFile", tempFile);
    return {
      setters: [
        function (path_1) {
          path = path_1;
        },
        function (utf8_ts_1_1) {
          utf8_ts_1 = utf8_ts_1_1;
        },
      ],
      execute: function () {
        // Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
        Buffer = Deno.Buffer, mkdir = Deno.mkdir, open = Deno.open;
      },
    };
  },
);
// Based on https://github.com/golang/go/blob/891682/src/bufio/bufio.go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
System.register(
  "https://deno.land/std@0.53.0/io/bufio",
  [
    "https://deno.land/std@0.53.0/io/util",
    "https://deno.land/std@0.53.0/testing/asserts",
  ],
  function (exports_17, context_17) {
    "use strict";
    var util_ts_1,
      asserts_ts_3,
      DEFAULT_BUF_SIZE,
      MIN_BUF_SIZE,
      MAX_CONSECUTIVE_EMPTY_READS,
      CR,
      LF,
      BufferFullError,
      PartialReadError,
      BufReader,
      AbstractBufBase,
      BufWriter,
      BufWriterSync;
    var __moduleName = context_17 && context_17.id;
    /** Generate longest proper prefix which is also suffix array. */
    function createLPS(pat) {
      const lps = new Uint8Array(pat.length);
      lps[0] = 0;
      let prefixEnd = 0;
      let i = 1;
      while (i < lps.length) {
        if (pat[i] == pat[prefixEnd]) {
          prefixEnd++;
          lps[i] = prefixEnd;
          i++;
        } else if (prefixEnd === 0) {
          lps[i] = 0;
          i++;
        } else {
          prefixEnd = pat[prefixEnd - 1];
        }
      }
      return lps;
    }
    /** Read delimited bytes from a Reader. */
    async function* readDelim(reader, delim) {
      // Avoid unicode problems
      const delimLen = delim.length;
      const delimLPS = createLPS(delim);
      let inputBuffer = new Deno.Buffer();
      const inspectArr = new Uint8Array(Math.max(1024, delimLen + 1));
      // Modified KMP
      let inspectIndex = 0;
      let matchIndex = 0;
      while (true) {
        const result = await reader.read(inspectArr);
        if (result === null) {
          // Yield last chunk.
          yield inputBuffer.bytes();
          return;
        }
        if (result < 0) {
          // Discard all remaining and silently fail.
          return;
        }
        const sliceRead = inspectArr.subarray(0, result);
        await Deno.writeAll(inputBuffer, sliceRead);
        let sliceToProcess = inputBuffer.bytes();
        while (inspectIndex < sliceToProcess.length) {
          if (sliceToProcess[inspectIndex] === delim[matchIndex]) {
            inspectIndex++;
            matchIndex++;
            if (matchIndex === delimLen) {
              // Full match
              const matchEnd = inspectIndex - delimLen;
              const readyBytes = sliceToProcess.subarray(0, matchEnd);
              // Copy
              const pendingBytes = sliceToProcess.slice(inspectIndex);
              yield readyBytes;
              // Reset match, different from KMP.
              sliceToProcess = pendingBytes;
              inspectIndex = 0;
              matchIndex = 0;
            }
          } else {
            if (matchIndex === 0) {
              inspectIndex++;
            } else {
              matchIndex = delimLPS[matchIndex - 1];
            }
          }
        }
        // Keep inspectIndex and matchIndex.
        inputBuffer = new Deno.Buffer(sliceToProcess);
      }
    }
    exports_17("readDelim", readDelim);
    /** Read delimited strings from a Reader. */
    async function* readStringDelim(reader, delim) {
      const encoder = new TextEncoder();
      const decoder = new TextDecoder();
      for await (const chunk of readDelim(reader, encoder.encode(delim))) {
        yield decoder.decode(chunk);
      }
    }
    exports_17("readStringDelim", readStringDelim);
    /** Read strings line-by-line from a Reader. */
    // eslint-disable-next-line require-await
    async function* readLines(reader) {
      yield* readStringDelim(reader, "\n");
    }
    exports_17("readLines", readLines);
    return {
      setters: [
        function (util_ts_1_1) {
          util_ts_1 = util_ts_1_1;
        },
        function (asserts_ts_3_1) {
          asserts_ts_3 = asserts_ts_3_1;
        },
      ],
      execute: function () {
        DEFAULT_BUF_SIZE = 4096;
        MIN_BUF_SIZE = 16;
        MAX_CONSECUTIVE_EMPTY_READS = 100;
        CR = util_ts_1.charCode("\r");
        LF = util_ts_1.charCode("\n");
        BufferFullError = class BufferFullError extends Error {
          constructor(partial) {
            super("Buffer full");
            this.partial = partial;
            this.name = "BufferFullError";
          }
        };
        exports_17("BufferFullError", BufferFullError);
        PartialReadError = class PartialReadError
          extends Deno.errors.UnexpectedEof {
          constructor() {
            super("Encountered UnexpectedEof, data only partially read");
            this.name = "PartialReadError";
          }
        };
        exports_17("PartialReadError", PartialReadError);
        /** BufReader implements buffering for a Reader object. */
        BufReader = class BufReader {
          constructor(rd, size = DEFAULT_BUF_SIZE) {
            this.r = 0; // buf read position.
            this.w = 0; // buf write position.
            this.eof = false;
            if (size < MIN_BUF_SIZE) {
              size = MIN_BUF_SIZE;
            }
            this._reset(new Uint8Array(size), rd);
          }
          // private lastByte: number;
          // private lastCharSize: number;
          /** return new BufReader unless r is BufReader */
          static create(r, size = DEFAULT_BUF_SIZE) {
            return r instanceof BufReader ? r : new BufReader(r, size);
          }
          /** Returns the size of the underlying buffer in bytes. */
          size() {
            return this.buf.byteLength;
          }
          buffered() {
            return this.w - this.r;
          }
          // Reads a new chunk into the buffer.
          async _fill() {
            // Slide existing data to beginning.
            if (this.r > 0) {
              this.buf.copyWithin(0, this.r, this.w);
              this.w -= this.r;
              this.r = 0;
            }
            if (this.w >= this.buf.byteLength) {
              throw Error("bufio: tried to fill full buffer");
            }
            // Read new data: try a limited number of times.
            for (let i = MAX_CONSECUTIVE_EMPTY_READS; i > 0; i--) {
              const rr = await this.rd.read(this.buf.subarray(this.w));
              if (rr === null) {
                this.eof = true;
                return;
              }
              asserts_ts_3.assert(rr >= 0, "negative read");
              this.w += rr;
              if (rr > 0) {
                return;
              }
            }
            throw new Error(
              `No progress after ${MAX_CONSECUTIVE_EMPTY_READS} read() calls`,
            );
          }
          /** Discards any buffered data, resets all state, and switches
                 * the buffered reader to read from r.
                 */
          reset(r) {
            this._reset(this.buf, r);
          }
          _reset(buf, rd) {
            this.buf = buf;
            this.rd = rd;
            this.eof = false;
            // this.lastByte = -1;
            // this.lastCharSize = -1;
          }
          /** reads data into p.
                 * It returns the number of bytes read into p.
                 * The bytes are taken from at most one Read on the underlying Reader,
                 * hence n may be less than len(p).
                 * To read exactly len(p) bytes, use io.ReadFull(b, p).
                 */
          async read(p) {
            let rr = p.byteLength;
            if (p.byteLength === 0) {
              return rr;
            }
            if (this.r === this.w) {
              if (p.byteLength >= this.buf.byteLength) {
                // Large read, empty buffer.
                // Read directly into p to avoid copy.
                const rr = await this.rd.read(p);
                const nread = rr ?? 0;
                asserts_ts_3.assert(nread >= 0, "negative read");
                // if (rr.nread > 0) {
                //   this.lastByte = p[rr.nread - 1];
                //   this.lastCharSize = -1;
                // }
                return rr;
              }
              // One read.
              // Do not use this.fill, which will loop.
              this.r = 0;
              this.w = 0;
              rr = await this.rd.read(this.buf);
              if (rr === 0 || rr === null) {
                return rr;
              }
              asserts_ts_3.assert(rr >= 0, "negative read");
              this.w += rr;
            }
            // copy as much as we can
            const copied = util_ts_1.copyBytes(
              this.buf.subarray(this.r, this.w),
              p,
              0,
            );
            this.r += copied;
            // this.lastByte = this.buf[this.r - 1];
            // this.lastCharSize = -1;
            return copied;
          }
          /** reads exactly `p.length` bytes into `p`.
                 *
                 * If successful, `p` is returned.
                 *
                 * If the end of the underlying stream has been reached, and there are no more
                 * bytes available in the buffer, `readFull()` returns `null` instead.
                 *
                 * An error is thrown if some bytes could be read, but not enough to fill `p`
                 * entirely before the underlying stream reported an error or EOF. Any error
                 * thrown will have a `partial` property that indicates the slice of the
                 * buffer that has been successfully filled with data.
                 *
                 * Ported from https://golang.org/pkg/io/#ReadFull
                 */
          async readFull(p) {
            let bytesRead = 0;
            while (bytesRead < p.length) {
              try {
                const rr = await this.read(p.subarray(bytesRead));
                if (rr === null) {
                  if (bytesRead === 0) {
                    return null;
                  } else {
                    throw new PartialReadError();
                  }
                }
                bytesRead += rr;
              } catch (err) {
                err.partial = p.subarray(0, bytesRead);
                throw err;
              }
            }
            return p;
          }
          /** Returns the next byte [0, 255] or `null`. */
          async readByte() {
            while (this.r === this.w) {
              if (this.eof) {
                return null;
              }
              await this._fill(); // buffer is empty.
            }
            const c = this.buf[this.r];
            this.r++;
            // this.lastByte = c;
            return c;
          }
          /** readString() reads until the first occurrence of delim in the input,
                 * returning a string containing the data up to and including the delimiter.
                 * If ReadString encounters an error before finding a delimiter,
                 * it returns the data read before the error and the error itself
                 * (often `null`).
                 * ReadString returns err != nil if and only if the returned data does not end
                 * in delim.
                 * For simple uses, a Scanner may be more convenient.
                 */
          async readString(delim) {
            if (delim.length !== 1) {
              throw new Error("Delimiter should be a single character");
            }
            const buffer = await this.readSlice(delim.charCodeAt(0));
            if (buffer === null) {
              return null;
            }
            return new TextDecoder().decode(buffer);
          }
          /** `readLine()` is a low-level line-reading primitive. Most callers should
                 * use `readString('\n')` instead or use a Scanner.
                 *
                 * `readLine()` tries to return a single line, not including the end-of-line
                 * bytes. If the line was too long for the buffer then `more` is set and the
                 * beginning of the line is returned. The rest of the line will be returned
                 * from future calls. `more` will be false when returning the last fragment
                 * of the line. The returned buffer is only valid until the next call to
                 * `readLine()`.
                 *
                 * The text returned from ReadLine does not include the line end ("\r\n" or
                 * "\n").
                 *
                 * When the end of the underlying stream is reached, the final bytes in the
                 * stream are returned. No indication or error is given if the input ends
                 * without a final line end. When there are no more trailing bytes to read,
                 * `readLine()` returns `null`.
                 *
                 * Calling `unreadByte()` after `readLine()` will always unread the last byte
                 * read (possibly a character belonging to the line end) even if that byte is
                 * not part of the line returned by `readLine()`.
                 */
          async readLine() {
            let line;
            try {
              line = await this.readSlice(LF);
            } catch (err) {
              let { partial } = err;
              asserts_ts_3.assert(
                partial instanceof Uint8Array,
                "bufio: caught error from `readSlice()` without `partial` property",
              );
              // Don't throw if `readSlice()` failed with `BufferFullError`, instead we
              // just return whatever is available and set the `more` flag.
              if (!(err instanceof BufferFullError)) {
                throw err;
              }
              // Handle the case where "\r\n" straddles the buffer.
              if (
                !this.eof &&
                partial.byteLength > 0 &&
                partial[partial.byteLength - 1] === CR
              ) {
                // Put the '\r' back on buf and drop it from line.
                // Let the next call to ReadLine check for "\r\n".
                asserts_ts_3.assert(
                  this.r > 0,
                  "bufio: tried to rewind past start of buffer",
                );
                this.r--;
                partial = partial.subarray(0, partial.byteLength - 1);
              }
              return { line: partial, more: !this.eof };
            }
            if (line === null) {
              return null;
            }
            if (line.byteLength === 0) {
              return { line, more: false };
            }
            if (line[line.byteLength - 1] == LF) {
              let drop = 1;
              if (line.byteLength > 1 && line[line.byteLength - 2] === CR) {
                drop = 2;
              }
              line = line.subarray(0, line.byteLength - drop);
            }
            return { line, more: false };
          }
          /** `readSlice()` reads until the first occurrence of `delim` in the input,
                 * returning a slice pointing at the bytes in the buffer. The bytes stop
                 * being valid at the next read.
                 *
                 * If `readSlice()` encounters an error before finding a delimiter, or the
                 * buffer fills without finding a delimiter, it throws an error with a
                 * `partial` property that contains the entire buffer.
                 *
                 * If `readSlice()` encounters the end of the underlying stream and there are
                 * any bytes left in the buffer, the rest of the buffer is returned. In other
                 * words, EOF is always treated as a delimiter. Once the buffer is empty,
                 * it returns `null`.
                 *
                 * Because the data returned from `readSlice()` will be overwritten by the
                 * next I/O operation, most clients should use `readString()` instead.
                 */
          async readSlice(delim) {
            let s = 0; // search start index
            let slice;
            while (true) {
              // Search buffer.
              let i = this.buf.subarray(this.r + s, this.w).indexOf(delim);
              if (i >= 0) {
                i += s;
                slice = this.buf.subarray(this.r, this.r + i + 1);
                this.r += i + 1;
                break;
              }
              // EOF?
              if (this.eof) {
                if (this.r === this.w) {
                  return null;
                }
                slice = this.buf.subarray(this.r, this.w);
                this.r = this.w;
                break;
              }
              // Buffer full?
              if (this.buffered() >= this.buf.byteLength) {
                this.r = this.w;
                // #4521 The internal buffer should not be reused across reads because it causes corruption of data.
                const oldbuf = this.buf;
                const newbuf = this.buf.slice(0);
                this.buf = newbuf;
                throw new BufferFullError(oldbuf);
              }
              s = this.w - this.r; // do not rescan area we scanned before
              // Buffer is not full.
              try {
                await this._fill();
              } catch (err) {
                err.partial = slice;
                throw err;
              }
            }
            // Handle last byte, if any.
            // const i = slice.byteLength - 1;
            // if (i >= 0) {
            //   this.lastByte = slice[i];
            //   this.lastCharSize = -1
            // }
            return slice;
          }
          /** `peek()` returns the next `n` bytes without advancing the reader. The
                 * bytes stop being valid at the next read call.
                 *
                 * When the end of the underlying stream is reached, but there are unread
                 * bytes left in the buffer, those bytes are returned. If there are no bytes
                 * left in the buffer, it returns `null`.
                 *
                 * If an error is encountered before `n` bytes are available, `peek()` throws
                 * an error with the `partial` property set to a slice of the buffer that
                 * contains the bytes that were available before the error occurred.
                 */
          async peek(n) {
            if (n < 0) {
              throw Error("negative count");
            }
            let avail = this.w - this.r;
            while (avail < n && avail < this.buf.byteLength && !this.eof) {
              try {
                await this._fill();
              } catch (err) {
                err.partial = this.buf.subarray(this.r, this.w);
                throw err;
              }
              avail = this.w - this.r;
            }
            if (avail === 0 && this.eof) {
              return null;
            } else if (avail < n && this.eof) {
              return this.buf.subarray(this.r, this.r + avail);
            } else if (avail < n) {
              throw new BufferFullError(this.buf.subarray(this.r, this.w));
            }
            return this.buf.subarray(this.r, this.r + n);
          }
        };
        exports_17("BufReader", BufReader);
        AbstractBufBase = class AbstractBufBase {
          constructor() {
            this.usedBufferBytes = 0;
            this.err = null;
          }
          /** Size returns the size of the underlying buffer in bytes. */
          size() {
            return this.buf.byteLength;
          }
          /** Returns how many bytes are unused in the buffer. */
          available() {
            return this.buf.byteLength - this.usedBufferBytes;
          }
          /** buffered returns the number of bytes that have been written into the
                 * current buffer.
                 */
          buffered() {
            return this.usedBufferBytes;
          }
          checkBytesWritten(numBytesWritten) {
            if (numBytesWritten < this.usedBufferBytes) {
              if (numBytesWritten > 0) {
                this.buf.copyWithin(0, numBytesWritten, this.usedBufferBytes);
                this.usedBufferBytes -= numBytesWritten;
              }
              this.err = new Error("Short write");
              throw this.err;
            }
          }
        };
        /** BufWriter implements buffering for an deno.Writer object.
             * If an error occurs writing to a Writer, no more data will be
             * accepted and all subsequent writes, and flush(), will return the error.
             * After all data has been written, the client should call the
             * flush() method to guarantee all data has been forwarded to
             * the underlying deno.Writer.
             */
        BufWriter = class BufWriter extends AbstractBufBase {
          constructor(writer, size = DEFAULT_BUF_SIZE) {
            super();
            this.writer = writer;
            if (size <= 0) {
              size = DEFAULT_BUF_SIZE;
            }
            this.buf = new Uint8Array(size);
          }
          /** return new BufWriter unless writer is BufWriter */
          static create(writer, size = DEFAULT_BUF_SIZE) {
            return writer instanceof BufWriter ? writer
            : new BufWriter(writer, size);
          }
          /** Discards any unflushed buffered data, clears any error, and
                 * resets buffer to write its output to w.
                 */
          reset(w) {
            this.err = null;
            this.usedBufferBytes = 0;
            this.writer = w;
          }
          /** Flush writes any buffered data to the underlying io.Writer. */
          async flush() {
            if (this.err !== null) {
              throw this.err;
            }
            if (this.usedBufferBytes === 0) {
              return;
            }
            let numBytesWritten = 0;
            try {
              numBytesWritten = await this.writer.write(
                this.buf.subarray(0, this.usedBufferBytes),
              );
            } catch (e) {
              this.err = e;
              throw e;
            }
            this.checkBytesWritten(numBytesWritten);
            this.usedBufferBytes = 0;
          }
          /** Writes the contents of `data` into the buffer.  If the contents won't fully
                 * fit into the buffer, those bytes that can are copied into the buffer, the
                 * buffer is the flushed to the writer and the remaining bytes are copied into
                 * the now empty buffer.
                 *
                 * @return the number of bytes written to the buffer.
                 */
          async write(data) {
            if (this.err !== null) {
              throw this.err;
            }
            if (data.length === 0) {
              return 0;
            }
            let totalBytesWritten = 0;
            let numBytesWritten = 0;
            while (data.byteLength > this.available()) {
              if (this.buffered() === 0) {
                // Large write, empty buffer.
                // Write directly from data to avoid copy.
                try {
                  numBytesWritten = await this.writer.write(data);
                } catch (e) {
                  this.err = e;
                  throw e;
                }
              } else {
                numBytesWritten = util_ts_1.copyBytes(
                  data,
                  this.buf,
                  this.usedBufferBytes,
                );
                this.usedBufferBytes += numBytesWritten;
                await this.flush();
              }
              totalBytesWritten += numBytesWritten;
              data = data.subarray(numBytesWritten);
            }
            numBytesWritten = util_ts_1.copyBytes(
              data,
              this.buf,
              this.usedBufferBytes,
            );
            this.usedBufferBytes += numBytesWritten;
            totalBytesWritten += numBytesWritten;
            return totalBytesWritten;
          }
        };
        exports_17("BufWriter", BufWriter);
        /** BufWriterSync implements buffering for a deno.WriterSync object.
             * If an error occurs writing to a WriterSync, no more data will be
             * accepted and all subsequent writes, and flush(), will return the error.
             * After all data has been written, the client should call the
             * flush() method to guarantee all data has been forwarded to
             * the underlying deno.WriterSync.
             */
        BufWriterSync = class BufWriterSync extends AbstractBufBase {
          constructor(writer, size = DEFAULT_BUF_SIZE) {
            super();
            this.writer = writer;
            if (size <= 0) {
              size = DEFAULT_BUF_SIZE;
            }
            this.buf = new Uint8Array(size);
          }
          /** return new BufWriterSync unless writer is BufWriterSync */
          static create(writer, size = DEFAULT_BUF_SIZE) {
            return writer instanceof BufWriterSync
              ? writer
              : new BufWriterSync(writer, size);
          }
          /** Discards any unflushed buffered data, clears any error, and
                 * resets buffer to write its output to w.
                 */
          reset(w) {
            this.err = null;
            this.usedBufferBytes = 0;
            this.writer = w;
          }
          /** Flush writes any buffered data to the underlying io.WriterSync. */
          flush() {
            if (this.err !== null) {
              throw this.err;
            }
            if (this.usedBufferBytes === 0) {
              return;
            }
            let numBytesWritten = 0;
            try {
              numBytesWritten = this.writer.writeSync(
                this.buf.subarray(0, this.usedBufferBytes),
              );
            } catch (e) {
              this.err = e;
              throw e;
            }
            this.checkBytesWritten(numBytesWritten);
            this.usedBufferBytes = 0;
          }
          /** Writes the contents of `data` into the buffer.  If the contents won't fully
                 * fit into the buffer, those bytes that can are copied into the buffer, the
                 * buffer is the flushed to the writer and the remaining bytes are copied into
                 * the now empty buffer.
                 *
                 * @return the number of bytes written to the buffer.
                 */
          writeSync(data) {
            if (this.err !== null) {
              throw this.err;
            }
            if (data.length === 0) {
              return 0;
            }
            let totalBytesWritten = 0;
            let numBytesWritten = 0;
            while (data.byteLength > this.available()) {
              if (this.buffered() === 0) {
                // Large write, empty buffer.
                // Write directly from data to avoid copy.
                try {
                  numBytesWritten = this.writer.writeSync(data);
                } catch (e) {
                  this.err = e;
                  throw e;
                }
              } else {
                numBytesWritten = util_ts_1.copyBytes(
                  data,
                  this.buf,
                  this.usedBufferBytes,
                );
                this.usedBufferBytes += numBytesWritten;
                this.flush();
              }
              totalBytesWritten += numBytesWritten;
              data = data.subarray(numBytesWritten);
            }
            numBytesWritten = util_ts_1.copyBytes(
              data,
              this.buf,
              this.usedBufferBytes,
            );
            this.usedBufferBytes += numBytesWritten;
            totalBytesWritten += numBytesWritten;
            return totalBytesWritten;
          }
        };
        exports_17("BufWriterSync", BufWriterSync);
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.53.0/async/deferred",
  [],
  function (exports_18, context_18) {
    "use strict";
    var __moduleName = context_18 && context_18.id;
    /** Creates a Promise with the `reject` and `resolve` functions
     * placed as methods on the promise object itself. It allows you to do:
     *
     *     const p = deferred<number>();
     *     // ...
     *     p.resolve(42);
     */
    function deferred() {
      let methods;
      const promise = new Promise((resolve, reject) => {
        methods = { resolve, reject };
      });
      return Object.assign(promise, methods);
    }
    exports_18("deferred", deferred);
    return {
      setters: [],
      execute: function () {
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.53.0/async/delay",
  [],
  function (exports_19, context_19) {
    "use strict";
    var __moduleName = context_19 && context_19.id;
    // Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
    /* Resolves after the given number of milliseconds. */
    function delay(ms) {
      return new Promise((res) =>
        setTimeout(() => {
          res();
        }, ms)
      );
    }
    exports_19("delay", delay);
    return {
      setters: [],
      execute: function () {
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.53.0/async/mux_async_iterator",
  ["https://deno.land/std@0.53.0/async/deferred"],
  function (exports_20, context_20) {
    "use strict";
    var deferred_ts_1, MuxAsyncIterator;
    var __moduleName = context_20 && context_20.id;
    return {
      setters: [
        function (deferred_ts_1_1) {
          deferred_ts_1 = deferred_ts_1_1;
        },
      ],
      execute: function () {
        /** The MuxAsyncIterator class multiplexes multiple async iterators into a
             * single stream. It currently makes a few assumptions:
             * - The iterators do not throw.
             * - The final result (the value returned and not yielded from the iterator)
             *   does not matter; if there is any, it is discarded.
             */
        MuxAsyncIterator = class MuxAsyncIterator {
          constructor() {
            this.iteratorCount = 0;
            this.yields = [];
            this.signal = deferred_ts_1.deferred();
          }
          add(iterator) {
            ++this.iteratorCount;
            this.callIteratorNext(iterator);
          }
          async callIteratorNext(iterator) {
            const { value, done } = await iterator.next();
            if (done) {
              --this.iteratorCount;
            } else {
              this.yields.push({ iterator, value });
            }
            this.signal.resolve();
          }
          async *iterate() {
            while (this.iteratorCount > 0) {
              // Sleep until any of the wrapped iterators yields.
              await this.signal;
              // Note that while we're looping over `yields`, new items may be added.
              for (let i = 0; i < this.yields.length; i++) {
                const { iterator, value } = this.yields[i];
                yield value;
                this.callIteratorNext(iterator);
              }
              // Clear the `yields` list and reset the `signal` promise.
              this.yields.length = 0;
              this.signal = deferred_ts_1.deferred();
            }
          }
          [Symbol.asyncIterator]() {
            return this.iterate();
          }
        };
        exports_20("MuxAsyncIterator", MuxAsyncIterator);
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.53.0/async/mod",
  [
    "https://deno.land/std@0.53.0/async/deferred",
    "https://deno.land/std@0.53.0/async/delay",
    "https://deno.land/std@0.53.0/async/mux_async_iterator",
  ],
  function (exports_21, context_21) {
    "use strict";
    var __moduleName = context_21 && context_21.id;
    function exportStar_2(m) {
      var exports = {};
      for (var n in m) {
        if (n !== "default") exports[n] = m[n];
      }
      exports_21(exports);
    }
    return {
      setters: [
        function (deferred_ts_2_1) {
          exportStar_2(deferred_ts_2_1);
        },
        function (delay_ts_1_1) {
          exportStar_2(delay_ts_1_1);
        },
        function (mux_async_iterator_ts_1_1) {
          exportStar_2(mux_async_iterator_ts_1_1);
        },
      ],
      execute: function () {
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.53.0/bytes/mod",
  ["https://deno.land/std@0.53.0/io/util"],
  function (exports_22, context_22) {
    "use strict";
    var util_ts_2;
    var __moduleName = context_22 && context_22.id;
    /** Find first index of binary pattern from a. If not found, then return -1
     * @param source soruce array
     * @param pat pattern to find in source array
     */
    function findIndex(source, pat) {
      const s = pat[0];
      for (let i = 0; i < source.length; i++) {
        if (source[i] !== s) {
          continue;
        }
        const pin = i;
        let matched = 1;
        let j = i;
        while (matched < pat.length) {
          j++;
          if (source[j] !== pat[j - pin]) {
            break;
          }
          matched++;
        }
        if (matched === pat.length) {
          return pin;
        }
      }
      return -1;
    }
    exports_22("findIndex", findIndex);
    /** Find last index of binary pattern from a. If not found, then return -1.
     * @param source soruce array
     * @param pat pattern to find in source array
     */
    function findLastIndex(source, pat) {
      const e = pat[pat.length - 1];
      for (let i = source.length - 1; i >= 0; i--) {
        if (source[i] !== e) {
          continue;
        }
        const pin = i;
        let matched = 1;
        let j = i;
        while (matched < pat.length) {
          j--;
          if (source[j] !== pat[pat.length - 1 - (pin - j)]) {
            break;
          }
          matched++;
        }
        if (matched === pat.length) {
          return pin - pat.length + 1;
        }
      }
      return -1;
    }
    exports_22("findLastIndex", findLastIndex);
    /** Check whether binary arrays are equal to each other.
     * @param source first array to check equality
     * @param match second array to check equality
     */
    function equal(source, match) {
      if (source.length !== match.length) {
        return false;
      }
      for (let i = 0; i < match.length; i++) {
        if (source[i] !== match[i]) {
          return false;
        }
      }
      return true;
    }
    exports_22("equal", equal);
    /** Check whether binary array starts with prefix.
     * @param source srouce array
     * @param prefix prefix array to check in source
     */
    function hasPrefix(source, prefix) {
      for (let i = 0, max = prefix.length; i < max; i++) {
        if (source[i] !== prefix[i]) {
          return false;
        }
      }
      return true;
    }
    exports_22("hasPrefix", hasPrefix);
    /** Check whether binary array ends with suffix.
     * @param source srouce array
     * @param suffix suffix array to check in source
     */
    function hasSuffix(source, suffix) {
      for (
        let srci = source.length - 1, sfxi = suffix.length - 1;
        sfxi >= 0;
        srci--, sfxi--
      ) {
        if (source[srci] !== suffix[sfxi]) {
          return false;
        }
      }
      return true;
    }
    exports_22("hasSuffix", hasSuffix);
    /** Repeat bytes. returns a new byte slice consisting of `count` copies of `b`.
     * @param origin The origin bytes
     * @param count The count you want to repeat.
     */
    function repeat(origin, count) {
      if (count === 0) {
        return new Uint8Array();
      }
      if (count < 0) {
        throw new Error("bytes: negative repeat count");
      } else if ((origin.length * count) / count !== origin.length) {
        throw new Error("bytes: repeat count causes overflow");
      }
      const int = Math.floor(count);
      if (int !== count) {
        throw new Error("bytes: repeat count must be an integer");
      }
      const nb = new Uint8Array(origin.length * count);
      let bp = util_ts_2.copyBytes(origin, nb);
      for (; bp < nb.length; bp *= 2) {
        util_ts_2.copyBytes(nb.slice(0, bp), nb, bp);
      }
      return nb;
    }
    exports_22("repeat", repeat);
    /** Concatenate two binary arrays and return new one.
     * @param origin origin array to concatenate
     * @param b array to concatenate with origin
     */
    function concat(origin, b) {
      const output = new Uint8Array(origin.length + b.length);
      output.set(origin, 0);
      output.set(b, origin.length);
      return output;
    }
    exports_22("concat", concat);
    /** Check srouce array contains pattern array.
     * @param source srouce array
     * @param pat patter array
     */
    function contains(source, pat) {
      return findIndex(source, pat) != -1;
    }
    exports_22("contains", contains);
    return {
      setters: [
        function (util_ts_2_1) {
          util_ts_2 = util_ts_2_1;
        },
      ],
      execute: function () {
      },
    };
  },
);
// Based on https://github.com/golang/go/tree/master/src/net/textproto
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
System.register(
  "https://deno.land/std@0.53.0/textproto/mod",
  [
    "https://deno.land/std@0.53.0/io/util",
    "https://deno.land/std@0.53.0/bytes/mod",
    "https://deno.land/std@0.53.0/encoding/utf8",
  ],
  function (exports_23, context_23) {
    "use strict";
    var util_ts_3, mod_ts_2, utf8_ts_2, invalidHeaderCharRegex, TextProtoReader;
    var __moduleName = context_23 && context_23.id;
    function str(buf) {
      if (buf == null) {
        return "";
      } else {
        return utf8_ts_2.decode(buf);
      }
    }
    return {
      setters: [
        function (util_ts_3_1) {
          util_ts_3 = util_ts_3_1;
        },
        function (mod_ts_2_1) {
          mod_ts_2 = mod_ts_2_1;
        },
        function (utf8_ts_2_1) {
          utf8_ts_2 = utf8_ts_2_1;
        },
      ],
      execute: function () {
        // FROM https://github.com/denoland/deno/blob/b34628a26ab0187a827aa4ebe256e23178e25d39/cli/js/web/headers.ts#L9
        invalidHeaderCharRegex = /[^\t\x20-\x7e\x80-\xff]/g;
        TextProtoReader = class TextProtoReader {
          constructor(r) {
            this.r = r;
          }
          /** readLine() reads a single line from the TextProtoReader,
                 * eliding the final \n or \r\n from the returned string.
                 */
          async readLine() {
            const s = await this.readLineSlice();
            if (s === null) {
              return null;
            }
            return str(s);
          }
          /** ReadMIMEHeader reads a MIME-style header from r.
                 * The header is a sequence of possibly continued Key: Value lines
                 * ending in a blank line.
                 * The returned map m maps CanonicalMIMEHeaderKey(key) to a
                 * sequence of values in the same order encountered in the input.
                 *
                 * For example, consider this input:
                 *
                 *	My-Key: Value 1
                 *	Long-Key: Even
                 *	       Longer Value
                 *	My-Key: Value 2
                 *
                 * Given that input, ReadMIMEHeader returns the map:
                 *
                 *	map[string][]string{
                 *		"My-Key": {"Value 1", "Value 2"},
                 *		"Long-Key": {"Even Longer Value"},
                 *	}
                 */
          async readMIMEHeader() {
            const m = new Headers();
            let line;
            // The first line cannot start with a leading space.
            let buf = await this.r.peek(1);
            if (buf === null) {
              return null;
            } else if (
              buf[0] == util_ts_3.charCode(" ") ||
              buf[0] == util_ts_3.charCode("\t")
            ) {
              line = (await this.readLineSlice());
            }
            buf = await this.r.peek(1);
            if (buf === null) {
              throw new Deno.errors.UnexpectedEof();
            } else if (
              buf[0] == util_ts_3.charCode(" ") ||
              buf[0] == util_ts_3.charCode("\t")
            ) {
              throw new Deno.errors.InvalidData(
                `malformed MIME header initial line: ${str(line)}`,
              );
            }
            while (true) {
              const kv = await this.readLineSlice(); // readContinuedLineSlice
              if (kv === null) {
                throw new Deno.errors.UnexpectedEof();
              }
              if (kv.byteLength === 0) {
                return m;
              }
              // Key ends at first colon
              let i = kv.indexOf(util_ts_3.charCode(":"));
              if (i < 0) {
                throw new Deno.errors.InvalidData(
                  `malformed MIME header line: ${str(kv)}`,
                );
              }
              //let key = canonicalMIMEHeaderKey(kv.subarray(0, endKey));
              const key = str(kv.subarray(0, i));
              // As per RFC 7230 field-name is a token,
              // tokens consist of one or more chars.
              // We could throw `Deno.errors.InvalidData` here,
              // but better to be liberal in what we
              // accept, so if we get an empty key, skip it.
              if (key == "") {
                continue;
              }
              // Skip initial spaces in value.
              i++; // skip colon
              while (
                i < kv.byteLength &&
                (kv[i] == util_ts_3.charCode(" ") ||
                  kv[i] == util_ts_3.charCode("\t"))
              ) {
                i++;
              }
              const value = str(kv.subarray(i)).replace(
                invalidHeaderCharRegex,
                encodeURI,
              );
              // In case of invalid header we swallow the error
              // example: "Audio Mode" => invalid due to space in the key
              try {
                m.append(key, value);
              } catch {}
            }
          }
          async readLineSlice() {
            // this.closeDot();
            let line;
            while (true) {
              const r = await this.r.readLine();
              if (r === null) {
                return null;
              }
              const { line: l, more } = r;
              // Avoid the copy if the first call produced a full line.
              if (!line && !more) {
                // TODO(ry):
                // This skipSpace() is definitely misplaced, but I don't know where it
                // comes from nor how to fix it.
                if (this.skipSpace(l) === 0) {
                  return new Uint8Array(0);
                }
                return l;
              }
              line = line ? mod_ts_2.concat(line, l) : l;
              if (!more) {
                break;
              }
            }
            return line;
          }
          skipSpace(l) {
            let n = 0;
            for (let i = 0; i < l.length; i++) {
              if (
                l[i] === util_ts_3.charCode(" ") ||
                l[i] === util_ts_3.charCode("\t")
              ) {
                continue;
              }
              n++;
            }
            return n;
          }
        };
        exports_23("TextProtoReader", TextProtoReader);
      },
    };
  },
);
// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
System.register(
  "https://deno.land/std@0.53.0/http/http_status",
  [],
  function (exports_24, context_24) {
    "use strict";
    var Status, STATUS_TEXT;
    var __moduleName = context_24 && context_24.id;
    return {
      setters: [],
      execute: function () {
        /** HTTP status codes */
        (function (Status) {
          /** RFC 7231, 6.2.1 */
          Status[Status["Continue"] = 100] = "Continue";
          /** RFC 7231, 6.2.2 */
          Status[Status["SwitchingProtocols"] = 101] = "SwitchingProtocols";
          /** RFC 2518, 10.1 */
          Status[Status["Processing"] = 102] = "Processing";
          /** RFC 7231, 6.3.1 */
          Status[Status["OK"] = 200] = "OK";
          /** RFC 7231, 6.3.2 */
          Status[Status["Created"] = 201] = "Created";
          /** RFC 7231, 6.3.3 */
          Status[Status["Accepted"] = 202] = "Accepted";
          /** RFC 7231, 6.3.4 */
          Status[Status["NonAuthoritativeInfo"] = 203] = "NonAuthoritativeInfo";
          /** RFC 7231, 6.3.5 */
          Status[Status["NoContent"] = 204] = "NoContent";
          /** RFC 7231, 6.3.6 */
          Status[Status["ResetContent"] = 205] = "ResetContent";
          /** RFC 7233, 4.1 */
          Status[Status["PartialContent"] = 206] = "PartialContent";
          /** RFC 4918, 11.1 */
          Status[Status["MultiStatus"] = 207] = "MultiStatus";
          /** RFC 5842, 7.1 */
          Status[Status["AlreadyReported"] = 208] = "AlreadyReported";
          /** RFC 3229, 10.4.1 */
          Status[Status["IMUsed"] = 226] = "IMUsed";
          /** RFC 7231, 6.4.1 */
          Status[Status["MultipleChoices"] = 300] = "MultipleChoices";
          /** RFC 7231, 6.4.2 */
          Status[Status["MovedPermanently"] = 301] = "MovedPermanently";
          /** RFC 7231, 6.4.3 */
          Status[Status["Found"] = 302] = "Found";
          /** RFC 7231, 6.4.4 */
          Status[Status["SeeOther"] = 303] = "SeeOther";
          /** RFC 7232, 4.1 */
          Status[Status["NotModified"] = 304] = "NotModified";
          /** RFC 7231, 6.4.5 */
          Status[Status["UseProxy"] = 305] = "UseProxy";
          /** RFC 7231, 6.4.7 */
          Status[Status["TemporaryRedirect"] = 307] = "TemporaryRedirect";
          /** RFC 7538, 3 */
          Status[Status["PermanentRedirect"] = 308] = "PermanentRedirect";
          /** RFC 7231, 6.5.1 */
          Status[Status["BadRequest"] = 400] = "BadRequest";
          /** RFC 7235, 3.1 */
          Status[Status["Unauthorized"] = 401] = "Unauthorized";
          /** RFC 7231, 6.5.2 */
          Status[Status["PaymentRequired"] = 402] = "PaymentRequired";
          /** RFC 7231, 6.5.3 */
          Status[Status["Forbidden"] = 403] = "Forbidden";
          /** RFC 7231, 6.5.4 */
          Status[Status["NotFound"] = 404] = "NotFound";
          /** RFC 7231, 6.5.5 */
          Status[Status["MethodNotAllowed"] = 405] = "MethodNotAllowed";
          /** RFC 7231, 6.5.6 */
          Status[Status["NotAcceptable"] = 406] = "NotAcceptable";
          /** RFC 7235, 3.2 */
          Status[Status["ProxyAuthRequired"] = 407] = "ProxyAuthRequired";
          /** RFC 7231, 6.5.7 */
          Status[Status["RequestTimeout"] = 408] = "RequestTimeout";
          /** RFC 7231, 6.5.8 */
          Status[Status["Conflict"] = 409] = "Conflict";
          /** RFC 7231, 6.5.9 */
          Status[Status["Gone"] = 410] = "Gone";
          /** RFC 7231, 6.5.10 */
          Status[Status["LengthRequired"] = 411] = "LengthRequired";
          /** RFC 7232, 4.2 */
          Status[Status["PreconditionFailed"] = 412] = "PreconditionFailed";
          /** RFC 7231, 6.5.11 */
          Status[Status["RequestEntityTooLarge"] = 413] =
            "RequestEntityTooLarge";
          /** RFC 7231, 6.5.12 */
          Status[Status["RequestURITooLong"] = 414] = "RequestURITooLong";
          /** RFC 7231, 6.5.13 */
          Status[Status["UnsupportedMediaType"] = 415] = "UnsupportedMediaType";
          /** RFC 7233, 4.4 */
          Status[Status["RequestedRangeNotSatisfiable"] = 416] =
            "RequestedRangeNotSatisfiable";
          /** RFC 7231, 6.5.14 */
          Status[Status["ExpectationFailed"] = 417] = "ExpectationFailed";
          /** RFC 7168, 2.3.3 */
          Status[Status["Teapot"] = 418] = "Teapot";
          /** RFC 7540, 9.1.2 */
          Status[Status["MisdirectedRequest"] = 421] = "MisdirectedRequest";
          /** RFC 4918, 11.2 */
          Status[Status["UnprocessableEntity"] = 422] = "UnprocessableEntity";
          /** RFC 4918, 11.3 */
          Status[Status["Locked"] = 423] = "Locked";
          /** RFC 4918, 11.4 */
          Status[Status["FailedDependency"] = 424] = "FailedDependency";
          /** RFC 7231, 6.5.15 */
          Status[Status["UpgradeRequired"] = 426] = "UpgradeRequired";
          /** RFC 6585, 3 */
          Status[Status["PreconditionRequired"] = 428] = "PreconditionRequired";
          /** RFC 6585, 4 */
          Status[Status["TooManyRequests"] = 429] = "TooManyRequests";
          /** RFC 6585, 5 */
          Status[Status["RequestHeaderFieldsTooLarge"] = 431] =
            "RequestHeaderFieldsTooLarge";
          /** RFC 7725, 3 */
          Status[Status["UnavailableForLegalReasons"] = 451] =
            "UnavailableForLegalReasons";
          /** RFC 7231, 6.6.1 */
          Status[Status["InternalServerError"] = 500] = "InternalServerError";
          /** RFC 7231, 6.6.2 */
          Status[Status["NotImplemented"] = 501] = "NotImplemented";
          /** RFC 7231, 6.6.3 */
          Status[Status["BadGateway"] = 502] = "BadGateway";
          /** RFC 7231, 6.6.4 */
          Status[Status["ServiceUnavailable"] = 503] = "ServiceUnavailable";
          /** RFC 7231, 6.6.5 */
          Status[Status["GatewayTimeout"] = 504] = "GatewayTimeout";
          /** RFC 7231, 6.6.6 */
          Status[Status["HTTPVersionNotSupported"] = 505] =
            "HTTPVersionNotSupported";
          /** RFC 2295, 8.1 */
          Status[Status["VariantAlsoNegotiates"] = 506] =
            "VariantAlsoNegotiates";
          /** RFC 4918, 11.5 */
          Status[Status["InsufficientStorage"] = 507] = "InsufficientStorage";
          /** RFC 5842, 7.2 */
          Status[Status["LoopDetected"] = 508] = "LoopDetected";
          /** RFC 2774, 7 */
          Status[Status["NotExtended"] = 510] = "NotExtended";
          /** RFC 6585, 6 */
          Status[Status["NetworkAuthenticationRequired"] = 511] =
            "NetworkAuthenticationRequired";
        })(Status || (Status = {}));
        exports_24("Status", Status);
        exports_24(
          "STATUS_TEXT",
          STATUS_TEXT = new Map([
            [Status.Continue, "Continue"],
            [Status.SwitchingProtocols, "Switching Protocols"],
            [Status.Processing, "Processing"],
            [Status.OK, "OK"],
            [Status.Created, "Created"],
            [Status.Accepted, "Accepted"],
            [Status.NonAuthoritativeInfo, "Non-Authoritative Information"],
            [Status.NoContent, "No Content"],
            [Status.ResetContent, "Reset Content"],
            [Status.PartialContent, "Partial Content"],
            [Status.MultiStatus, "Multi-Status"],
            [Status.AlreadyReported, "Already Reported"],
            [Status.IMUsed, "IM Used"],
            [Status.MultipleChoices, "Multiple Choices"],
            [Status.MovedPermanently, "Moved Permanently"],
            [Status.Found, "Found"],
            [Status.SeeOther, "See Other"],
            [Status.NotModified, "Not Modified"],
            [Status.UseProxy, "Use Proxy"],
            [Status.TemporaryRedirect, "Temporary Redirect"],
            [Status.PermanentRedirect, "Permanent Redirect"],
            [Status.BadRequest, "Bad Request"],
            [Status.Unauthorized, "Unauthorized"],
            [Status.PaymentRequired, "Payment Required"],
            [Status.Forbidden, "Forbidden"],
            [Status.NotFound, "Not Found"],
            [Status.MethodNotAllowed, "Method Not Allowed"],
            [Status.NotAcceptable, "Not Acceptable"],
            [Status.ProxyAuthRequired, "Proxy Authentication Required"],
            [Status.RequestTimeout, "Request Timeout"],
            [Status.Conflict, "Conflict"],
            [Status.Gone, "Gone"],
            [Status.LengthRequired, "Length Required"],
            [Status.PreconditionFailed, "Precondition Failed"],
            [Status.RequestEntityTooLarge, "Request Entity Too Large"],
            [Status.RequestURITooLong, "Request URI Too Long"],
            [Status.UnsupportedMediaType, "Unsupported Media Type"],
            [
              Status.RequestedRangeNotSatisfiable,
              "Requested Range Not Satisfiable",
            ],
            [Status.ExpectationFailed, "Expectation Failed"],
            [Status.Teapot, "I'm a teapot"],
            [Status.MisdirectedRequest, "Misdirected Request"],
            [Status.UnprocessableEntity, "Unprocessable Entity"],
            [Status.Locked, "Locked"],
            [Status.FailedDependency, "Failed Dependency"],
            [Status.UpgradeRequired, "Upgrade Required"],
            [Status.PreconditionRequired, "Precondition Required"],
            [Status.TooManyRequests, "Too Many Requests"],
            [
              Status.RequestHeaderFieldsTooLarge,
              "Request Header Fields Too Large",
            ],
            [
              Status.UnavailableForLegalReasons,
              "Unavailable For Legal Reasons",
            ],
            [Status.InternalServerError, "Internal Server Error"],
            [Status.NotImplemented, "Not Implemented"],
            [Status.BadGateway, "Bad Gateway"],
            [Status.ServiceUnavailable, "Service Unavailable"],
            [Status.GatewayTimeout, "Gateway Timeout"],
            [Status.HTTPVersionNotSupported, "HTTP Version Not Supported"],
            [Status.VariantAlsoNegotiates, "Variant Also Negotiates"],
            [Status.InsufficientStorage, "Insufficient Storage"],
            [Status.LoopDetected, "Loop Detected"],
            [Status.NotExtended, "Not Extended"],
            [
              Status.NetworkAuthenticationRequired,
              "Network Authentication Required",
            ],
          ]),
        );
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.53.0/http/_io",
  [
    "https://deno.land/std@0.53.0/io/bufio",
    "https://deno.land/std@0.53.0/textproto/mod",
    "https://deno.land/std@0.53.0/testing/asserts",
    "https://deno.land/std@0.53.0/encoding/utf8",
    "https://deno.land/std@0.53.0/http/server",
    "https://deno.land/std@0.53.0/http/http_status",
  ],
  function (exports_25, context_25) {
    "use strict";
    var bufio_ts_1,
      mod_ts_3,
      asserts_ts_4,
      utf8_ts_3,
      server_ts_1,
      http_status_ts_1,
      kProhibitedTrailerHeaders;
    var __moduleName = context_25 && context_25.id;
    function emptyReader() {
      return {
        read(_) {
          return Promise.resolve(null);
        },
      };
    }
    exports_25("emptyReader", emptyReader);
    function bodyReader(contentLength, r) {
      let totalRead = 0;
      let finished = false;
      async function read(buf) {
        if (finished) {
          return null;
        }
        let result;
        const remaining = contentLength - totalRead;
        if (remaining >= buf.byteLength) {
          result = await r.read(buf);
        } else {
          const readBuf = buf.subarray(0, remaining);
          result = await r.read(readBuf);
        }
        if (result !== null) {
          totalRead += result;
        }
        finished = totalRead === contentLength;
        return result;
      }
      return { read };
    }
    exports_25("bodyReader", bodyReader);
    function chunkedBodyReader(h, r) {
      // Based on https://tools.ietf.org/html/rfc2616#section-19.4.6
      const tp = new mod_ts_3.TextProtoReader(r);
      let finished = false;
      const chunks = [];
      async function read(buf) {
        if (finished) {
          return null;
        }
        const [chunk] = chunks;
        if (chunk) {
          const chunkRemaining = chunk.data.byteLength - chunk.offset;
          const readLength = Math.min(chunkRemaining, buf.byteLength);
          for (let i = 0; i < readLength; i++) {
            buf[i] = chunk.data[chunk.offset + i];
          }
          chunk.offset += readLength;
          if (chunk.offset === chunk.data.byteLength) {
            chunks.shift();
            // Consume \r\n;
            if ((await tp.readLine()) === null) {
              throw new Deno.errors.UnexpectedEof();
            }
          }
          return readLength;
        }
        const line = await tp.readLine();
        if (line === null) {
          throw new Deno.errors.UnexpectedEof();
        }
        // TODO: handle chunk extension
        const [chunkSizeString] = line.split(";");
        const chunkSize = parseInt(chunkSizeString, 16);
        if (Number.isNaN(chunkSize) || chunkSize < 0) {
          throw new Error("Invalid chunk size");
        }
        if (chunkSize > 0) {
          if (chunkSize > buf.byteLength) {
            let eof = await r.readFull(buf);
            if (eof === null) {
              throw new Deno.errors.UnexpectedEof();
            }
            const restChunk = new Uint8Array(chunkSize - buf.byteLength);
            eof = await r.readFull(restChunk);
            if (eof === null) {
              throw new Deno.errors.UnexpectedEof();
            } else {
              chunks.push({
                offset: 0,
                data: restChunk,
              });
            }
            return buf.byteLength;
          } else {
            const bufToFill = buf.subarray(0, chunkSize);
            const eof = await r.readFull(bufToFill);
            if (eof === null) {
              throw new Deno.errors.UnexpectedEof();
            }
            // Consume \r\n
            if ((await tp.readLine()) === null) {
              throw new Deno.errors.UnexpectedEof();
            }
            return chunkSize;
          }
        } else {
          asserts_ts_4.assert(chunkSize === 0);
          // Consume \r\n
          if ((await r.readLine()) === null) {
            throw new Deno.errors.UnexpectedEof();
          }
          await readTrailers(h, r);
          finished = true;
          return null;
        }
      }
      return { read };
    }
    exports_25("chunkedBodyReader", chunkedBodyReader);
    /**
     * Read trailer headers from reader and append values to headers.
     * "trailer" field will be deleted.
     * */
    async function readTrailers(headers, r) {
      const keys = parseTrailer(headers.get("trailer"));
      if (!keys) {
        return;
      }
      const tp = new mod_ts_3.TextProtoReader(r);
      const result = await tp.readMIMEHeader();
      asserts_ts_4.assert(result !== null, "trailer must be set");
      for (const [k, v] of result) {
        if (!keys.has(k)) {
          throw new Error("Undeclared trailer field");
        }
        keys.delete(k);
        headers.append(k, v);
      }
      asserts_ts_4.assert(keys.size === 0, "Missing trailers");
      headers.delete("trailer");
    }
    exports_25("readTrailers", readTrailers);
    function parseTrailer(field) {
      if (field == null) {
        return undefined;
      }
      const keys = field.split(",").map((v) => v.trim());
      if (keys.length === 0) {
        throw new Error("Empty trailer");
      }
      for (const invalid of kProhibitedTrailerHeaders) {
        if (keys.includes(invalid)) {
          throw new Error(`Prohibited field for trailer`);
        }
      }
      return new Set(keys);
    }
    async function writeChunkedBody(w, r) {
      const writer = bufio_ts_1.BufWriter.create(w);
      for await (const chunk of Deno.iter(r)) {
        if (chunk.byteLength <= 0) {
          continue;
        }
        const start = utf8_ts_3.encoder.encode(
          `${chunk.byteLength.toString(16)}\r\n`,
        );
        const end = utf8_ts_3.encoder.encode("\r\n");
        await writer.write(start);
        await writer.write(chunk);
        await writer.write(end);
      }
      const endChunk = utf8_ts_3.encoder.encode("0\r\n\r\n");
      await writer.write(endChunk);
    }
    exports_25("writeChunkedBody", writeChunkedBody);
    /** write trailer headers to writer. it mostly should be called after writeResponse */
    async function writeTrailers(w, headers, trailers) {
      const trailer = headers.get("trailer");
      if (trailer === null) {
        throw new Error('response headers must have "trailer" header field');
      }
      const transferEncoding = headers.get("transfer-encoding");
      if (transferEncoding === null || !transferEncoding.match(/^chunked/)) {
        throw new Error(
          `trailer headers is only allowed for "transfer-encoding: chunked": got "${transferEncoding}"`,
        );
      }
      const writer = bufio_ts_1.BufWriter.create(w);
      const trailerHeaderFields = trailer
        .split(",")
        .map((s) => s.trim().toLowerCase());
      for (const f of trailerHeaderFields) {
        asserts_ts_4.assert(
          !kProhibitedTrailerHeaders.includes(f),
          `"${f}" is prohibited for trailer header`,
        );
      }
      for (const [key, value] of trailers) {
        asserts_ts_4.assert(
          trailerHeaderFields.includes(key),
          `Not trailer header field: ${key}`,
        );
        await writer.write(utf8_ts_3.encoder.encode(`${key}: ${value}\r\n`));
      }
      await writer.write(utf8_ts_3.encoder.encode("\r\n"));
      await writer.flush();
    }
    exports_25("writeTrailers", writeTrailers);
    async function writeResponse(w, r) {
      const protoMajor = 1;
      const protoMinor = 1;
      const statusCode = r.status || 200;
      const statusText = http_status_ts_1.STATUS_TEXT.get(statusCode);
      const writer = bufio_ts_1.BufWriter.create(w);
      if (!statusText) {
        throw new Deno.errors.InvalidData("Bad status code");
      }
      if (!r.body) {
        r.body = new Uint8Array();
      }
      if (typeof r.body === "string") {
        r.body = utf8_ts_3.encoder.encode(r.body);
      }
      let out =
        `HTTP/${protoMajor}.${protoMinor} ${statusCode} ${statusText}\r\n`;
      const headers = r.headers ?? new Headers();
      if (r.body && !headers.get("content-length")) {
        if (r.body instanceof Uint8Array) {
          out += `content-length: ${r.body.byteLength}\r\n`;
        } else if (!headers.get("transfer-encoding")) {
          out += "transfer-encoding: chunked\r\n";
        }
      }
      for (const [key, value] of headers) {
        out += `${key}: ${value}\r\n`;
      }
      out += `\r\n`;
      const header = utf8_ts_3.encoder.encode(out);
      const n = await writer.write(header);
      asserts_ts_4.assert(n === header.byteLength);
      if (r.body instanceof Uint8Array) {
        const n = await writer.write(r.body);
        asserts_ts_4.assert(n === r.body.byteLength);
      } else if (headers.has("content-length")) {
        const contentLength = headers.get("content-length");
        asserts_ts_4.assert(contentLength != null);
        const bodyLength = parseInt(contentLength);
        const n = await Deno.copy(r.body, writer);
        asserts_ts_4.assert(n === bodyLength);
      } else {
        await writeChunkedBody(writer, r.body);
      }
      if (r.trailers) {
        const t = await r.trailers();
        await writeTrailers(writer, headers, t);
      }
      await writer.flush();
    }
    exports_25("writeResponse", writeResponse);
    /**
     * ParseHTTPVersion parses a HTTP version string.
     * "HTTP/1.0" returns (1, 0).
     * Ported from https://github.com/golang/go/blob/f5c43b9/src/net/http/request.go#L766-L792
     */
    function parseHTTPVersion(vers) {
      switch (vers) {
        case "HTTP/1.1":
          return [1, 1];
        case "HTTP/1.0":
          return [1, 0];
        default: {
          const Big = 1000000; // arbitrary upper bound
          if (!vers.startsWith("HTTP/")) {
            break;
          }
          const dot = vers.indexOf(".");
          if (dot < 0) {
            break;
          }
          const majorStr = vers.substring(vers.indexOf("/") + 1, dot);
          const major = Number(majorStr);
          if (!Number.isInteger(major) || major < 0 || major > Big) {
            break;
          }
          const minorStr = vers.substring(dot + 1);
          const minor = Number(minorStr);
          if (!Number.isInteger(minor) || minor < 0 || minor > Big) {
            break;
          }
          return [major, minor];
        }
      }
      throw new Error(`malformed HTTP version ${vers}`);
    }
    exports_25("parseHTTPVersion", parseHTTPVersion);
    async function readRequest(conn, bufr) {
      const tp = new mod_ts_3.TextProtoReader(bufr);
      const firstLine = await tp.readLine(); // e.g. GET /index.html HTTP/1.0
      if (firstLine === null) {
        return null;
      }
      const headers = await tp.readMIMEHeader();
      if (headers === null) {
        throw new Deno.errors.UnexpectedEof();
      }
      const req = new server_ts_1.ServerRequest();
      req.conn = conn;
      req.r = bufr;
      [req.method, req.url, req.proto] = firstLine.split(" ", 3);
      [req.protoMinor, req.protoMajor] = parseHTTPVersion(req.proto);
      req.headers = headers;
      fixLength(req);
      return req;
    }
    exports_25("readRequest", readRequest);
    function fixLength(req) {
      const contentLength = req.headers.get("Content-Length");
      if (contentLength) {
        const arrClen = contentLength.split(",");
        if (arrClen.length > 1) {
          const distinct = [...new Set(arrClen.map((e) => e.trim()))];
          if (distinct.length > 1) {
            throw Error("cannot contain multiple Content-Length headers");
          } else {
            req.headers.set("Content-Length", distinct[0]);
          }
        }
        const c = req.headers.get("Content-Length");
        if (req.method === "HEAD" && c && c !== "0") {
          throw Error("http: method cannot contain a Content-Length");
        }
        if (c && req.headers.has("transfer-encoding")) {
          // A sender MUST NOT send a Content-Length header field in any message
          // that contains a Transfer-Encoding header field.
          // rfc: https://tools.ietf.org/html/rfc7230#section-3.3.2
          throw new Error(
            "http: Transfer-Encoding and Content-Length cannot be send together",
          );
        }
      }
    }
    return {
      setters: [
        function (bufio_ts_1_1) {
          bufio_ts_1 = bufio_ts_1_1;
        },
        function (mod_ts_3_1) {
          mod_ts_3 = mod_ts_3_1;
        },
        function (asserts_ts_4_1) {
          asserts_ts_4 = asserts_ts_4_1;
        },
        function (utf8_ts_3_1) {
          utf8_ts_3 = utf8_ts_3_1;
        },
        function (server_ts_1_1) {
          server_ts_1 = server_ts_1_1;
        },
        function (http_status_ts_1_1) {
          http_status_ts_1 = http_status_ts_1_1;
        },
      ],
      execute: function () {
        kProhibitedTrailerHeaders = [
          "transfer-encoding",
          "content-length",
          "trailer",
        ];
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.53.0/http/server",
  [
    "https://deno.land/std@0.53.0/encoding/utf8",
    "https://deno.land/std@0.53.0/io/bufio",
    "https://deno.land/std@0.53.0/testing/asserts",
    "https://deno.land/std@0.53.0/async/mod",
    "https://deno.land/std@0.53.0/http/_io",
  ],
  function (exports_26, context_26) {
    "use strict";
    var utf8_ts_4,
      bufio_ts_2,
      asserts_ts_5,
      mod_ts_4,
      _io_ts_1,
      listen,
      listenTls,
      ServerRequest,
      Server;
    var __moduleName = context_26 && context_26.id;
    /**
     * Create a HTTP server
     *
     *     import { serve } from "https://deno.land/std/http/server.ts";
     *     const body = "Hello World\n";
     *     const s = serve({ port: 8000 });
     *     for await (const req of s) {
     *       req.respond({ body });
     *     }
     */
    function serve(addr) {
      if (typeof addr === "string") {
        const [hostname, port] = addr.split(":");
        addr = { hostname, port: Number(port) };
      }
      const listener = listen(addr);
      return new Server(listener);
    }
    exports_26("serve", serve);
    /**
     * Start an HTTP server with given options and request handler
     *
     *     const body = "Hello World\n";
     *     const options = { port: 8000 };
     *     listenAndServe(options, (req) => {
     *       req.respond({ body });
     *     });
     *
     * @param options Server configuration
     * @param handler Request handler
     */
    async function listenAndServe(addr, handler) {
      const server = serve(addr);
      for await (const request of server) {
        handler(request);
      }
    }
    exports_26("listenAndServe", listenAndServe);
    /**
     * Create an HTTPS server with given options
     *
     *     const body = "Hello HTTPS";
     *     const options = {
     *       hostname: "localhost",
     *       port: 443,
     *       certFile: "./path/to/localhost.crt",
     *       keyFile: "./path/to/localhost.key",
     *     };
     *     for await (const req of serveTLS(options)) {
     *       req.respond({ body });
     *     }
     *
     * @param options Server configuration
     * @return Async iterable server instance for incoming requests
     */
    function serveTLS(options) {
      const tlsOptions = {
        ...options,
        transport: "tcp",
      };
      const listener = listenTls(tlsOptions);
      return new Server(listener);
    }
    exports_26("serveTLS", serveTLS);
    /**
     * Start an HTTPS server with given options and request handler
     *
     *     const body = "Hello HTTPS";
     *     const options = {
     *       hostname: "localhost",
     *       port: 443,
     *       certFile: "./path/to/localhost.crt",
     *       keyFile: "./path/to/localhost.key",
     *     };
     *     listenAndServeTLS(options, (req) => {
     *       req.respond({ body });
     *     });
     *
     * @param options Server configuration
     * @param handler Request handler
     */
    async function listenAndServeTLS(options, handler) {
      const server = serveTLS(options);
      for await (const request of server) {
        handler(request);
      }
    }
    exports_26("listenAndServeTLS", listenAndServeTLS);
    return {
      setters: [
        function (utf8_ts_4_1) {
          utf8_ts_4 = utf8_ts_4_1;
        },
        function (bufio_ts_2_1) {
          bufio_ts_2 = bufio_ts_2_1;
        },
        function (asserts_ts_5_1) {
          asserts_ts_5 = asserts_ts_5_1;
        },
        function (mod_ts_4_1) {
          mod_ts_4 = mod_ts_4_1;
        },
        function (_io_ts_1_1) {
          _io_ts_1 = _io_ts_1_1;
        },
      ],
      execute: function () {
        listen = Deno.listen, listenTls = Deno.listenTls;
        ServerRequest = class ServerRequest {
          constructor() {
            this.done = mod_ts_4.deferred();
            this._contentLength = undefined;
            this._body = null;
            this.finalized = false;
          }
          /**
                 * Value of Content-Length header.
                 * If null, then content length is invalid or not given (e.g. chunked encoding).
                 */
          get contentLength() {
            // undefined means not cached.
            // null means invalid or not provided.
            if (this._contentLength === undefined) {
              const cl = this.headers.get("content-length");
              if (cl) {
                this._contentLength = parseInt(cl);
                // Convert NaN to null (as NaN harder to test)
                if (Number.isNaN(this._contentLength)) {
                  this._contentLength = null;
                }
              } else {
                this._contentLength = null;
              }
            }
            return this._contentLength;
          }
          /**
                 * Body of the request.
                 *
                 *     const buf = new Uint8Array(req.contentLength);
                 *     let bufSlice = buf;
                 *     let totRead = 0;
                 *     while (true) {
                 *       const nread = await req.body.read(bufSlice);
                 *       if (nread === null) break;
                 *       totRead += nread;
                 *       if (totRead >= req.contentLength) break;
                 *       bufSlice = bufSlice.subarray(nread);
                 *     }
                 */
          get body() {
            if (!this._body) {
              if (this.contentLength != null) {
                this._body = _io_ts_1.bodyReader(this.contentLength, this.r);
              } else {
                const transferEncoding = this.headers.get("transfer-encoding");
                if (transferEncoding != null) {
                  const parts = transferEncoding
                    .split(",")
                    .map((e) => e.trim().toLowerCase());
                  asserts_ts_5.assert(
                    parts.includes("chunked"),
                    'transfer-encoding must include "chunked" if content-length is not set',
                  );
                  this._body = _io_ts_1.chunkedBodyReader(this.headers, this.r);
                } else {
                  // Neither content-length nor transfer-encoding: chunked
                  this._body = _io_ts_1.emptyReader();
                }
              }
            }
            return this._body;
          }
          async respond(r) {
            let err;
            try {
              // Write our response!
              await _io_ts_1.writeResponse(this.w, r);
            } catch (e) {
              try {
                // Eagerly close on error.
                this.conn.close();
              } catch {}
              err = e;
            }
            // Signal that this request has been processed and the next pipelined
            // request on the same connection can be accepted.
            this.done.resolve(err);
            if (err) {
              // Error during responding, rethrow.
              throw err;
            }
          }
          async finalize() {
            if (this.finalized) {
              return;
            }
            // Consume unread body
            const body = this.body;
            const buf = new Uint8Array(1024);
            while ((await body.read(buf)) !== null) {}
            this.finalized = true;
          }
        };
        exports_26("ServerRequest", ServerRequest);
        Server = class Server {
          constructor(listener) {
            this.listener = listener;
            this.closing = false;
            this.connections = [];
          }
          close() {
            this.closing = true;
            this.listener.close();
            for (const conn of this.connections) {
              try {
                conn.close();
              } catch (e) {
                // Connection might have been already closed
                if (!(e instanceof Deno.errors.BadResource)) {
                  throw e;
                }
              }
            }
          }
          // Yields all HTTP requests on a single TCP connection.
          async *iterateHttpRequests(conn) {
            const reader = new bufio_ts_2.BufReader(conn);
            const writer = new bufio_ts_2.BufWriter(conn);
            while (!this.closing) {
              let request;
              try {
                request = await _io_ts_1.readRequest(conn, reader);
              } catch (error) {
                if (
                  error instanceof Deno.errors.InvalidData ||
                  error instanceof Deno.errors.UnexpectedEof
                ) {
                  // An error was thrown while parsing request headers.
                  await _io_ts_1.writeResponse(writer, {
                    status: 400,
                    body: utf8_ts_4.encode(`${error.message}\r\n\r\n`),
                  });
                }
                break;
              }
              if (request === null) {
                break;
              }
              request.w = writer;
              yield request;
              // Wait for the request to be processed before we accept a new request on
              // this connection.
              const responseError = await request.done;
              if (responseError) {
                // Something bad happened during response.
                // (likely other side closed during pipelined req)
                // req.done implies this connection already closed, so we can just return.
                this.untrackConnection(request.conn);
                return;
              }
              // Consume unread body and trailers if receiver didn't consume those data
              await request.finalize();
            }
            this.untrackConnection(conn);
            try {
              conn.close();
            } catch (e) {
              // might have been already closed
            }
          }
          trackConnection(conn) {
            this.connections.push(conn);
          }
          untrackConnection(conn) {
            const index = this.connections.indexOf(conn);
            if (index !== -1) {
              this.connections.splice(index, 1);
            }
          }
          // Accepts a new TCP connection and yields all HTTP requests that arrive on
          // it. When a connection is accepted, it also creates a new iterator of the
          // same kind and adds it to the request multiplexer so that another TCP
          // connection can be accepted.
          async *acceptConnAndIterateHttpRequests(mux) {
            if (this.closing) {
              return;
            }
            // Wait for a new connection.
            let conn;
            try {
              conn = await this.listener.accept();
            } catch (error) {
              if (error instanceof Deno.errors.BadResource) {
                return;
              }
              throw error;
            }
            this.trackConnection(conn);
            // Try to accept another connection and add it to the multiplexer.
            mux.add(this.acceptConnAndIterateHttpRequests(mux));
            // Yield the requests that arrive on the just-accepted connection.
            yield* this.iterateHttpRequests(conn);
          }
          [Symbol.asyncIterator]() {
            const mux = new mod_ts_4.MuxAsyncIterator();
            mux.add(this.acceptConnAndIterateHttpRequests(mux));
            return mux.iterate();
          }
        };
        exports_26("Server", Server);
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.53.0/datetime/mod",
  ["https://deno.land/std@0.53.0/testing/asserts"],
  function (exports_27, context_27) {
    "use strict";
    var asserts_ts_6;
    var __moduleName = context_27 && context_27.id;
    function execForce(reg, pat) {
      const v = reg.exec(pat);
      asserts_ts_6.assert(v != null);
      return v;
    }
    /**
     * Parse date from string using format string
     * @param dateStr Date string
     * @param format Format string
     * @return Parsed date
     */
    function parseDate(dateStr, format) {
      let m, d, y;
      let datePattern;
      switch (format) {
        case "mm-dd-yyyy":
          datePattern = /^(\d{2})-(\d{2})-(\d{4})$/;
          [, m, d, y] = execForce(datePattern, dateStr);
          break;
        case "dd-mm-yyyy":
          datePattern = /^(\d{2})-(\d{2})-(\d{4})$/;
          [, d, m, y] = execForce(datePattern, dateStr);
          break;
        case "yyyy-mm-dd":
          datePattern = /^(\d{4})-(\d{2})-(\d{2})$/;
          [, y, m, d] = execForce(datePattern, dateStr);
          break;
        default:
          throw new Error("Invalid date format!");
      }
      return new Date(Number(y), Number(m) - 1, Number(d));
    }
    exports_27("parseDate", parseDate);
    /**
     * Parse date & time from string using format string
     * @param dateStr Date & time string
     * @param format Format string
     * @return Parsed date
     */
    function parseDateTime(datetimeStr, format) {
      let m, d, y, ho, mi;
      let datePattern;
      switch (format) {
        case "mm-dd-yyyy hh:mm":
          datePattern = /^(\d{2})-(\d{2})-(\d{4}) (\d{2}):(\d{2})$/;
          [, m, d, y, ho, mi] = execForce(datePattern, datetimeStr);
          break;
        case "dd-mm-yyyy hh:mm":
          datePattern = /^(\d{2})-(\d{2})-(\d{4}) (\d{2}):(\d{2})$/;
          [, d, m, y, ho, mi] = execForce(datePattern, datetimeStr);
          break;
        case "yyyy-mm-dd hh:mm":
          datePattern = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2})$/;
          [, y, m, d, ho, mi] = execForce(datePattern, datetimeStr);
          break;
        case "hh:mm mm-dd-yyyy":
          datePattern = /^(\d{2}):(\d{2}) (\d{2})-(\d{2})-(\d{4})$/;
          [, ho, mi, m, d, y] = execForce(datePattern, datetimeStr);
          break;
        case "hh:mm dd-mm-yyyy":
          datePattern = /^(\d{2}):(\d{2}) (\d{2})-(\d{2})-(\d{4})$/;
          [, ho, mi, d, m, y] = execForce(datePattern, datetimeStr);
          break;
        case "hh:mm yyyy-mm-dd":
          datePattern = /^(\d{2}):(\d{2}) (\d{4})-(\d{2})-(\d{2})$/;
          [, ho, mi, y, m, d] = execForce(datePattern, datetimeStr);
          break;
        default:
          throw new Error("Invalid datetime format!");
      }
      return new Date(
        Number(y),
        Number(m) - 1,
        Number(d),
        Number(ho),
        Number(mi),
      );
    }
    exports_27("parseDateTime", parseDateTime);
    /**
     * Get number of the day in the year
     * @return Number of the day in year
     */
    function dayOfYear(date) {
      const dayMs = 1000 * 60 * 60 * 24;
      const yearStart = new Date(date.getFullYear(), 0, 0);
      const diff = date.getTime() -
        yearStart.getTime() +
        (yearStart.getTimezoneOffset() - date.getTimezoneOffset()) * 60 *
          1000;
      return Math.floor(diff / dayMs);
    }
    exports_27("dayOfYear", dayOfYear);
    /**
     * Get number of current day in year
     * @return Number of current day in year
     */
    function currentDayOfYear() {
      return dayOfYear(new Date());
    }
    exports_27("currentDayOfYear", currentDayOfYear);
    /**
     * Parse a date to return a IMF formated string date
     * RFC: https://tools.ietf.org/html/rfc7231#section-7.1.1.1
     * IMF is the time format to use when generating times in HTTP
     * headers. The time being formatted must be in UTC for Format to
     * generate the correct format.
     * @param date Date to parse
     * @return IMF date formated string
     */
    function toIMF(date) {
      function dtPad(v, lPad = 2) {
        return v.padStart(lPad, "0");
      }
      const d = dtPad(date.getUTCDate().toString());
      const h = dtPad(date.getUTCHours().toString());
      const min = dtPad(date.getUTCMinutes().toString());
      const s = dtPad(date.getUTCSeconds().toString());
      const y = date.getUTCFullYear();
      const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
      const months = [
        "Jan",
        "Feb",
        "Mar",
        "Apr",
        "May",
        "Jun",
        "Jul",
        "Aug",
        "Sep",
        "Oct",
        "Nov",
        "Dec",
      ];
      return `${days[date.getUTCDay()]}, ${d} ${
        months[date.getUTCMonth()]
      } ${y} ${h}:${min}:${s} GMT`;
    }
    exports_27("toIMF", toIMF);
    return {
      setters: [
        function (asserts_ts_6_1) {
          asserts_ts_6 = asserts_ts_6_1;
        },
      ],
      execute: function () {
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.53.0/http/cookie",
  [
    "https://deno.land/std@0.53.0/testing/asserts",
    "https://deno.land/std@0.53.0/datetime/mod",
  ],
  function (exports_28, context_28) {
    "use strict";
    var asserts_ts_7, mod_ts_5;
    var __moduleName = context_28 && context_28.id;
    function toString(cookie) {
      if (!cookie.name) {
        return "";
      }
      const out = [];
      out.push(`${cookie.name}=${cookie.value}`);
      // Fallback for invalid Set-Cookie
      // ref: https://tools.ietf.org/html/draft-ietf-httpbis-cookie-prefixes-00#section-3.1
      if (cookie.name.startsWith("__Secure")) {
        cookie.secure = true;
      }
      if (cookie.name.startsWith("__Host")) {
        cookie.path = "/";
        cookie.secure = true;
        delete cookie.domain;
      }
      if (cookie.secure) {
        out.push("Secure");
      }
      if (cookie.httpOnly) {
        out.push("HttpOnly");
      }
      if (
        typeof cookie.maxAge === "number" && Number.isInteger(cookie.maxAge)
      ) {
        asserts_ts_7.assert(
          cookie.maxAge > 0,
          "Max-Age must be an integer superior to 0",
        );
        out.push(`Max-Age=${cookie.maxAge}`);
      }
      if (cookie.domain) {
        out.push(`Domain=${cookie.domain}`);
      }
      if (cookie.sameSite) {
        out.push(`SameSite=${cookie.sameSite}`);
      }
      if (cookie.path) {
        out.push(`Path=${cookie.path}`);
      }
      if (cookie.expires) {
        const dateString = mod_ts_5.toIMF(cookie.expires);
        out.push(`Expires=${dateString}`);
      }
      if (cookie.unparsed) {
        out.push(cookie.unparsed.join("; "));
      }
      return out.join("; ");
    }
    /**
     * Parse the cookies of the Server Request
     * @param req Server Request
     */
    function getCookies(req) {
      const cookie = req.headers.get("Cookie");
      if (cookie != null) {
        const out = {};
        const c = cookie.split(";");
        for (const kv of c) {
          const [cookieKey, ...cookieVal] = kv.split("=");
          asserts_ts_7.assert(cookieKey != null);
          const key = cookieKey.trim();
          out[key] = cookieVal.join("=");
        }
        return out;
      }
      return {};
    }
    exports_28("getCookies", getCookies);
    /**
     * Set the cookie header properly in the Response
     * @param res Server Response
     * @param cookie Cookie to set
     * Example:
     *
     *     setCookie(response, { name: 'deno', value: 'runtime',
     *        httpOnly: true, secure: true, maxAge: 2, domain: "deno.land" });
     */
    function setCookie(res, cookie) {
      if (!res.headers) {
        res.headers = new Headers();
      }
      // TODO (zekth) : Add proper parsing of Set-Cookie headers
      // Parsing cookie headers to make consistent set-cookie header
      // ref: https://tools.ietf.org/html/rfc6265#section-4.1.1
      const v = toString(cookie);
      if (v) {
        res.headers.append("Set-Cookie", v);
      }
    }
    exports_28("setCookie", setCookie);
    /**
     *  Set the cookie header properly in the Response to delete it
     * @param res Server Response
     * @param name Name of the cookie to Delete
     * Example:
     *
     *     delCookie(res,'foo');
     */
    function delCookie(res, name) {
      setCookie(res, {
        name: name,
        value: "",
        expires: new Date(0),
      });
    }
    exports_28("delCookie", delCookie);
    return {
      setters: [
        function (asserts_ts_7_1) {
          asserts_ts_7 = asserts_ts_7_1;
        },
        function (mod_ts_5_1) {
          mod_ts_5 = mod_ts_5_1;
        },
      ],
      execute: function () {
      },
    };
  },
);
System.register(
  "https://deno.land/x/media_types@v2.3.3/db",
  [],
  function (exports_29, context_29) {
    "use strict";
    var db;
    var __moduleName = context_29 && context_29.id;
    return {
      setters: [],
      execute: function () {
        exports_29(
          "db",
          db = {
            "application/1d-interleaved-parityfec": {
              source: "iana",
            },
            "application/3gpdash-qoe-report+xml": {
              source: "iana",
              charset: "UTF-8",
              compressible: true,
            },
            "application/3gpp-ims+xml": {
              source: "iana",
              compressible: true,
            },
            "application/a2l": {
              source: "iana",
            },
            "application/activemessage": {
              source: "iana",
            },
            "application/activity+json": {
              source: "iana",
              compressible: true,
            },
            "application/alto-costmap+json": {
              source: "iana",
              compressible: true,
            },
            "application/alto-costmapfilter+json": {
              source: "iana",
              compressible: true,
            },
            "application/alto-directory+json": {
              source: "iana",
              compressible: true,
            },
            "application/alto-endpointcost+json": {
              source: "iana",
              compressible: true,
            },
            "application/alto-endpointcostparams+json": {
              source: "iana",
              compressible: true,
            },
            "application/alto-endpointprop+json": {
              source: "iana",
              compressible: true,
            },
            "application/alto-endpointpropparams+json": {
              source: "iana",
              compressible: true,
            },
            "application/alto-error+json": {
              source: "iana",
              compressible: true,
            },
            "application/alto-networkmap+json": {
              source: "iana",
              compressible: true,
            },
            "application/alto-networkmapfilter+json": {
              source: "iana",
              compressible: true,
            },
            "application/alto-updatestreamcontrol+json": {
              source: "iana",
              compressible: true,
            },
            "application/alto-updatestreamparams+json": {
              source: "iana",
              compressible: true,
            },
            "application/aml": {
              source: "iana",
            },
            "application/andrew-inset": {
              source: "iana",
              extensions: ["ez"],
            },
            "application/applefile": {
              source: "iana",
            },
            "application/applixware": {
              source: "apache",
              extensions: ["aw"],
            },
            "application/atf": {
              source: "iana",
            },
            "application/atfx": {
              source: "iana",
            },
            "application/atom+xml": {
              source: "iana",
              compressible: true,
              extensions: ["atom"],
            },
            "application/atomcat+xml": {
              source: "iana",
              compressible: true,
              extensions: ["atomcat"],
            },
            "application/atomdeleted+xml": {
              source: "iana",
              compressible: true,
              extensions: ["atomdeleted"],
            },
            "application/atomicmail": {
              source: "iana",
            },
            "application/atomsvc+xml": {
              source: "iana",
              compressible: true,
              extensions: ["atomsvc"],
            },
            "application/atsc-dwd+xml": {
              source: "iana",
              compressible: true,
              extensions: ["dwd"],
            },
            "application/atsc-dynamic-event-message": {
              source: "iana",
            },
            "application/atsc-held+xml": {
              source: "iana",
              compressible: true,
              extensions: ["held"],
            },
            "application/atsc-rdt+json": {
              source: "iana",
              compressible: true,
            },
            "application/atsc-rsat+xml": {
              source: "iana",
              compressible: true,
              extensions: ["rsat"],
            },
            "application/atxml": {
              source: "iana",
            },
            "application/auth-policy+xml": {
              source: "iana",
              compressible: true,
            },
            "application/bacnet-xdd+zip": {
              source: "iana",
              compressible: false,
            },
            "application/batch-smtp": {
              source: "iana",
            },
            "application/bdoc": {
              compressible: false,
              extensions: ["bdoc"],
            },
            "application/beep+xml": {
              source: "iana",
              charset: "UTF-8",
              compressible: true,
            },
            "application/calendar+json": {
              source: "iana",
              compressible: true,
            },
            "application/calendar+xml": {
              source: "iana",
              compressible: true,
              extensions: ["xcs"],
            },
            "application/call-completion": {
              source: "iana",
            },
            "application/cals-1840": {
              source: "iana",
            },
            "application/cap+xml": {
              source: "iana",
              charset: "UTF-8",
              compressible: true,
            },
            "application/cbor": {
              source: "iana",
            },
            "application/cbor-seq": {
              source: "iana",
            },
            "application/cccex": {
              source: "iana",
            },
            "application/ccmp+xml": {
              source: "iana",
              compressible: true,
            },
            "application/ccxml+xml": {
              source: "iana",
              compressible: true,
              extensions: ["ccxml"],
            },
            "application/cdfx+xml": {
              source: "iana",
              compressible: true,
              extensions: ["cdfx"],
            },
            "application/cdmi-capability": {
              source: "iana",
              extensions: ["cdmia"],
            },
            "application/cdmi-container": {
              source: "iana",
              extensions: ["cdmic"],
            },
            "application/cdmi-domain": {
              source: "iana",
              extensions: ["cdmid"],
            },
            "application/cdmi-object": {
              source: "iana",
              extensions: ["cdmio"],
            },
            "application/cdmi-queue": {
              source: "iana",
              extensions: ["cdmiq"],
            },
            "application/cdni": {
              source: "iana",
            },
            "application/cea": {
              source: "iana",
            },
            "application/cea-2018+xml": {
              source: "iana",
              compressible: true,
            },
            "application/cellml+xml": {
              source: "iana",
              compressible: true,
            },
            "application/cfw": {
              source: "iana",
            },
            "application/clue+xml": {
              source: "iana",
              compressible: true,
            },
            "application/clue_info+xml": {
              source: "iana",
              compressible: true,
            },
            "application/cms": {
              source: "iana",
            },
            "application/cnrp+xml": {
              source: "iana",
              compressible: true,
            },
            "application/coap-group+json": {
              source: "iana",
              compressible: true,
            },
            "application/coap-payload": {
              source: "iana",
            },
            "application/commonground": {
              source: "iana",
            },
            "application/conference-info+xml": {
              source: "iana",
              compressible: true,
            },
            "application/cose": {
              source: "iana",
            },
            "application/cose-key": {
              source: "iana",
            },
            "application/cose-key-set": {
              source: "iana",
            },
            "application/cpl+xml": {
              source: "iana",
              compressible: true,
            },
            "application/csrattrs": {
              source: "iana",
            },
            "application/csta+xml": {
              source: "iana",
              compressible: true,
            },
            "application/cstadata+xml": {
              source: "iana",
              compressible: true,
            },
            "application/csvm+json": {
              source: "iana",
              compressible: true,
            },
            "application/cu-seeme": {
              source: "apache",
              extensions: ["cu"],
            },
            "application/cwt": {
              source: "iana",
            },
            "application/cybercash": {
              source: "iana",
            },
            "application/dart": {
              compressible: true,
            },
            "application/dash+xml": {
              source: "iana",
              compressible: true,
              extensions: ["mpd"],
            },
            "application/dashdelta": {
              source: "iana",
            },
            "application/davmount+xml": {
              source: "iana",
              compressible: true,
              extensions: ["davmount"],
            },
            "application/dca-rft": {
              source: "iana",
            },
            "application/dcd": {
              source: "iana",
            },
            "application/dec-dx": {
              source: "iana",
            },
            "application/dialog-info+xml": {
              source: "iana",
              compressible: true,
            },
            "application/dicom": {
              source: "iana",
            },
            "application/dicom+json": {
              source: "iana",
              compressible: true,
            },
            "application/dicom+xml": {
              source: "iana",
              compressible: true,
            },
            "application/dii": {
              source: "iana",
            },
            "application/dit": {
              source: "iana",
            },
            "application/dns": {
              source: "iana",
            },
            "application/dns+json": {
              source: "iana",
              compressible: true,
            },
            "application/dns-message": {
              source: "iana",
            },
            "application/docbook+xml": {
              source: "apache",
              compressible: true,
              extensions: ["dbk"],
            },
            "application/dots+cbor": {
              source: "iana",
            },
            "application/dskpp+xml": {
              source: "iana",
              compressible: true,
            },
            "application/dssc+der": {
              source: "iana",
              extensions: ["dssc"],
            },
            "application/dssc+xml": {
              source: "iana",
              compressible: true,
              extensions: ["xdssc"],
            },
            "application/dvcs": {
              source: "iana",
            },
            "application/ecmascript": {
              source: "iana",
              compressible: true,
              extensions: ["ecma", "es"],
            },
            "application/edi-consent": {
              source: "iana",
            },
            "application/edi-x12": {
              source: "iana",
              compressible: false,
            },
            "application/edifact": {
              source: "iana",
              compressible: false,
            },
            "application/efi": {
              source: "iana",
            },
            "application/emergencycalldata.comment+xml": {
              source: "iana",
              compressible: true,
            },
            "application/emergencycalldata.control+xml": {
              source: "iana",
              compressible: true,
            },
            "application/emergencycalldata.deviceinfo+xml": {
              source: "iana",
              compressible: true,
            },
            "application/emergencycalldata.ecall.msd": {
              source: "iana",
            },
            "application/emergencycalldata.providerinfo+xml": {
              source: "iana",
              compressible: true,
            },
            "application/emergencycalldata.serviceinfo+xml": {
              source: "iana",
              compressible: true,
            },
            "application/emergencycalldata.subscriberinfo+xml": {
              source: "iana",
              compressible: true,
            },
            "application/emergencycalldata.veds+xml": {
              source: "iana",
              compressible: true,
            },
            "application/emma+xml": {
              source: "iana",
              compressible: true,
              extensions: ["emma"],
            },
            "application/emotionml+xml": {
              source: "iana",
              compressible: true,
              extensions: ["emotionml"],
            },
            "application/encaprtp": {
              source: "iana",
            },
            "application/epp+xml": {
              source: "iana",
              compressible: true,
            },
            "application/epub+zip": {
              source: "iana",
              compressible: false,
              extensions: ["epub"],
            },
            "application/eshop": {
              source: "iana",
            },
            "application/exi": {
              source: "iana",
              extensions: ["exi"],
            },
            "application/expect-ct-report+json": {
              source: "iana",
              compressible: true,
            },
            "application/fastinfoset": {
              source: "iana",
            },
            "application/fastsoap": {
              source: "iana",
            },
            "application/fdt+xml": {
              source: "iana",
              compressible: true,
              extensions: ["fdt"],
            },
            "application/fhir+json": {
              source: "iana",
              charset: "UTF-8",
              compressible: true,
            },
            "application/fhir+xml": {
              source: "iana",
              charset: "UTF-8",
              compressible: true,
            },
            "application/fido.trusted-apps+json": {
              compressible: true,
            },
            "application/fits": {
              source: "iana",
            },
            "application/flexfec": {
              source: "iana",
            },
            "application/font-sfnt": {
              source: "iana",
            },
            "application/font-tdpfr": {
              source: "iana",
              extensions: ["pfr"],
            },
            "application/font-woff": {
              source: "iana",
              compressible: false,
            },
            "application/framework-attributes+xml": {
              source: "iana",
              compressible: true,
            },
            "application/geo+json": {
              source: "iana",
              compressible: true,
              extensions: ["geojson"],
            },
            "application/geo+json-seq": {
              source: "iana",
            },
            "application/geopackage+sqlite3": {
              source: "iana",
            },
            "application/geoxacml+xml": {
              source: "iana",
              compressible: true,
            },
            "application/gltf-buffer": {
              source: "iana",
            },
            "application/gml+xml": {
              source: "iana",
              compressible: true,
              extensions: ["gml"],
            },
            "application/gpx+xml": {
              source: "apache",
              compressible: true,
              extensions: ["gpx"],
            },
            "application/gxf": {
              source: "apache",
              extensions: ["gxf"],
            },
            "application/gzip": {
              source: "iana",
              compressible: false,
              extensions: ["gz"],
            },
            "application/h224": {
              source: "iana",
            },
            "application/held+xml": {
              source: "iana",
              compressible: true,
            },
            "application/hjson": {
              extensions: ["hjson"],
            },
            "application/http": {
              source: "iana",
            },
            "application/hyperstudio": {
              source: "iana",
              extensions: ["stk"],
            },
            "application/ibe-key-request+xml": {
              source: "iana",
              compressible: true,
            },
            "application/ibe-pkg-reply+xml": {
              source: "iana",
              compressible: true,
            },
            "application/ibe-pp-data": {
              source: "iana",
            },
            "application/iges": {
              source: "iana",
            },
            "application/im-iscomposing+xml": {
              source: "iana",
              charset: "UTF-8",
              compressible: true,
            },
            "application/index": {
              source: "iana",
            },
            "application/index.cmd": {
              source: "iana",
            },
            "application/index.obj": {
              source: "iana",
            },
            "application/index.response": {
              source: "iana",
            },
            "application/index.vnd": {
              source: "iana",
            },
            "application/inkml+xml": {
              source: "iana",
              compressible: true,
              extensions: ["ink", "inkml"],
            },
            "application/iotp": {
              source: "iana",
            },
            "application/ipfix": {
              source: "iana",
              extensions: ["ipfix"],
            },
            "application/ipp": {
              source: "iana",
            },
            "application/isup": {
              source: "iana",
            },
            "application/its+xml": {
              source: "iana",
              compressible: true,
              extensions: ["its"],
            },
            "application/java-archive": {
              source: "apache",
              compressible: false,
              extensions: ["jar", "war", "ear"],
            },
            "application/java-serialized-object": {
              source: "apache",
              compressible: false,
              extensions: ["ser"],
            },
            "application/java-vm": {
              source: "apache",
              compressible: false,
              extensions: ["class"],
            },
            "application/javascript": {
              source: "iana",
              charset: "UTF-8",
              compressible: true,
              extensions: ["js", "mjs"],
            },
            "application/jf2feed+json": {
              source: "iana",
              compressible: true,
            },
            "application/jose": {
              source: "iana",
            },
            "application/jose+json": {
              source: "iana",
              compressible: true,
            },
            "application/jrd+json": {
              source: "iana",
              compressible: true,
            },
            "application/json": {
              source: "iana",
              charset: "UTF-8",
              compressible: true,
              extensions: ["json", "map"],
            },
            "application/json-patch+json": {
              source: "iana",
              compressible: true,
            },
            "application/json-seq": {
              source: "iana",
            },
            "application/json5": {
              extensions: ["json5"],
            },
            "application/jsonml+json": {
              source: "apache",
              compressible: true,
              extensions: ["jsonml"],
            },
            "application/jwk+json": {
              source: "iana",
              compressible: true,
            },
            "application/jwk-set+json": {
              source: "iana",
              compressible: true,
            },
            "application/jwt": {
              source: "iana",
            },
            "application/kpml-request+xml": {
              source: "iana",
              compressible: true,
            },
            "application/kpml-response+xml": {
              source: "iana",
              compressible: true,
            },
            "application/ld+json": {
              source: "iana",
              compressible: true,
              extensions: ["jsonld"],
            },
            "application/lgr+xml": {
              source: "iana",
              compressible: true,
              extensions: ["lgr"],
            },
            "application/link-format": {
              source: "iana",
            },
            "application/load-control+xml": {
              source: "iana",
              compressible: true,
            },
            "application/lost+xml": {
              source: "iana",
              compressible: true,
              extensions: ["lostxml"],
            },
            "application/lostsync+xml": {
              source: "iana",
              compressible: true,
            },
            "application/lpf+zip": {
              source: "iana",
              compressible: false,
            },
            "application/lxf": {
              source: "iana",
            },
            "application/mac-binhex40": {
              source: "iana",
              extensions: ["hqx"],
            },
            "application/mac-compactpro": {
              source: "apache",
              extensions: ["cpt"],
            },
            "application/macwriteii": {
              source: "iana",
            },
            "application/mads+xml": {
              source: "iana",
              compressible: true,
              extensions: ["mads"],
            },
            "application/manifest+json": {
              charset: "UTF-8",
              compressible: true,
              extensions: ["webmanifest"],
            },
            "application/marc": {
              source: "iana",
              extensions: ["mrc"],
            },
            "application/marcxml+xml": {
              source: "iana",
              compressible: true,
              extensions: ["mrcx"],
            },
            "application/mathematica": {
              source: "iana",
              extensions: ["ma", "nb", "mb"],
            },
            "application/mathml+xml": {
              source: "iana",
              compressible: true,
              extensions: ["mathml"],
            },
            "application/mathml-content+xml": {
              source: "iana",
              compressible: true,
            },
            "application/mathml-presentation+xml": {
              source: "iana",
              compressible: true,
            },
            "application/mbms-associated-procedure-description+xml": {
              source: "iana",
              compressible: true,
            },
            "application/mbms-deregister+xml": {
              source: "iana",
              compressible: true,
            },
            "application/mbms-envelope+xml": {
              source: "iana",
              compressible: true,
            },
            "application/mbms-msk+xml": {
              source: "iana",
              compressible: true,
            },
            "application/mbms-msk-response+xml": {
              source: "iana",
              compressible: true,
            },
            "application/mbms-protection-description+xml": {
              source: "iana",
              compressible: true,
            },
            "application/mbms-reception-report+xml": {
              source: "iana",
              compressible: true,
            },
            "application/mbms-register+xml": {
              source: "iana",
              compressible: true,
            },
            "application/mbms-register-response+xml": {
              source: "iana",
              compressible: true,
            },
            "application/mbms-schedule+xml": {
              source: "iana",
              compressible: true,
            },
            "application/mbms-user-service-description+xml": {
              source: "iana",
              compressible: true,
            },
            "application/mbox": {
              source: "iana",
              extensions: ["mbox"],
            },
            "application/media-policy-dataset+xml": {
              source: "iana",
              compressible: true,
            },
            "application/media_control+xml": {
              source: "iana",
              compressible: true,
            },
            "application/mediaservercontrol+xml": {
              source: "iana",
              compressible: true,
              extensions: ["mscml"],
            },
            "application/merge-patch+json": {
              source: "iana",
              compressible: true,
            },
            "application/metalink+xml": {
              source: "apache",
              compressible: true,
              extensions: ["metalink"],
            },
            "application/metalink4+xml": {
              source: "iana",
              compressible: true,
              extensions: ["meta4"],
            },
            "application/mets+xml": {
              source: "iana",
              compressible: true,
              extensions: ["mets"],
            },
            "application/mf4": {
              source: "iana",
            },
            "application/mikey": {
              source: "iana",
            },
            "application/mipc": {
              source: "iana",
            },
            "application/mmt-aei+xml": {
              source: "iana",
              compressible: true,
              extensions: ["maei"],
            },
            "application/mmt-usd+xml": {
              source: "iana",
              compressible: true,
              extensions: ["musd"],
            },
            "application/mods+xml": {
              source: "iana",
              compressible: true,
              extensions: ["mods"],
            },
            "application/moss-keys": {
              source: "iana",
            },
            "application/moss-signature": {
              source: "iana",
            },
            "application/mosskey-data": {
              source: "iana",
            },
            "application/mosskey-request": {
              source: "iana",
            },
            "application/mp21": {
              source: "iana",
              extensions: ["m21", "mp21"],
            },
            "application/mp4": {
              source: "iana",
              extensions: ["mp4s", "m4p"],
            },
            "application/mpeg4-generic": {
              source: "iana",
            },
            "application/mpeg4-iod": {
              source: "iana",
            },
            "application/mpeg4-iod-xmt": {
              source: "iana",
            },
            "application/mrb-consumer+xml": {
              source: "iana",
              compressible: true,
              extensions: ["xdf"],
            },
            "application/mrb-publish+xml": {
              source: "iana",
              compressible: true,
              extensions: ["xdf"],
            },
            "application/msc-ivr+xml": {
              source: "iana",
              charset: "UTF-8",
              compressible: true,
            },
            "application/msc-mixer+xml": {
              source: "iana",
              charset: "UTF-8",
              compressible: true,
            },
            "application/msword": {
              source: "iana",
              compressible: false,
              extensions: ["doc", "dot"],
            },
            "application/mud+json": {
              source: "iana",
              compressible: true,
            },
            "application/multipart-core": {
              source: "iana",
            },
            "application/mxf": {
              source: "iana",
              extensions: ["mxf"],
            },
            "application/n-quads": {
              source: "iana",
              extensions: ["nq"],
            },
            "application/n-triples": {
              source: "iana",
              extensions: ["nt"],
            },
            "application/nasdata": {
              source: "iana",
            },
            "application/news-checkgroups": {
              source: "iana",
              charset: "US-ASCII",
            },
            "application/news-groupinfo": {
              source: "iana",
              charset: "US-ASCII",
            },
            "application/news-transmission": {
              source: "iana",
            },
            "application/nlsml+xml": {
              source: "iana",
              compressible: true,
            },
            "application/node": {
              source: "iana",
              extensions: ["cjs"],
            },
            "application/nss": {
              source: "iana",
            },
            "application/ocsp-request": {
              source: "iana",
            },
            "application/ocsp-response": {
              source: "iana",
            },
            "application/octet-stream": {
              source: "iana",
              compressible: false,
              extensions: [
                "bin",
                "dms",
                "lrf",
                "mar",
                "so",
                "dist",
                "distz",
                "pkg",
                "bpk",
                "dump",
                "elc",
                "deploy",
                "exe",
                "dll",
                "deb",
                "dmg",
                "iso",
                "img",
                "msi",
                "msp",
                "msm",
                "buffer",
              ],
            },
            "application/oda": {
              source: "iana",
              extensions: ["oda"],
            },
            "application/odm+xml": {
              source: "iana",
              compressible: true,
            },
            "application/odx": {
              source: "iana",
            },
            "application/oebps-package+xml": {
              source: "iana",
              compressible: true,
              extensions: ["opf"],
            },
            "application/ogg": {
              source: "iana",
              compressible: false,
              extensions: ["ogx"],
            },
            "application/omdoc+xml": {
              source: "apache",
              compressible: true,
              extensions: ["omdoc"],
            },
            "application/onenote": {
              source: "apache",
              extensions: ["onetoc", "onetoc2", "onetmp", "onepkg"],
            },
            "application/oscore": {
              source: "iana",
            },
            "application/oxps": {
              source: "iana",
              extensions: ["oxps"],
            },
            "application/p2p-overlay+xml": {
              source: "iana",
              compressible: true,
              extensions: ["relo"],
            },
            "application/parityfec": {
              source: "iana",
            },
            "application/passport": {
              source: "iana",
            },
            "application/patch-ops-error+xml": {
              source: "iana",
              compressible: true,
              extensions: ["xer"],
            },
            "application/pdf": {
              source: "iana",
              compressible: false,
              extensions: ["pdf"],
            },
            "application/pdx": {
              source: "iana",
            },
            "application/pem-certificate-chain": {
              source: "iana",
            },
            "application/pgp-encrypted": {
              source: "iana",
              compressible: false,
              extensions: ["pgp"],
            },
            "application/pgp-keys": {
              source: "iana",
            },
            "application/pgp-signature": {
              source: "iana",
              extensions: ["asc", "sig"],
            },
            "application/pics-rules": {
              source: "apache",
              extensions: ["prf"],
            },
            "application/pidf+xml": {
              source: "iana",
              charset: "UTF-8",
              compressible: true,
            },
            "application/pidf-diff+xml": {
              source: "iana",
              charset: "UTF-8",
              compressible: true,
            },
            "application/pkcs10": {
              source: "iana",
              extensions: ["p10"],
            },
            "application/pkcs12": {
              source: "iana",
            },
            "application/pkcs7-mime": {
              source: "iana",
              extensions: ["p7m", "p7c"],
            },
            "application/pkcs7-signature": {
              source: "iana",
              extensions: ["p7s"],
            },
            "application/pkcs8": {
              source: "iana",
              extensions: ["p8"],
            },
            "application/pkcs8-encrypted": {
              source: "iana",
            },
            "application/pkix-attr-cert": {
              source: "iana",
              extensions: ["ac"],
            },
            "application/pkix-cert": {
              source: "iana",
              extensions: ["cer"],
            },
            "application/pkix-crl": {
              source: "iana",
              extensions: ["crl"],
            },
            "application/pkix-pkipath": {
              source: "iana",
              extensions: ["pkipath"],
            },
            "application/pkixcmp": {
              source: "iana",
              extensions: ["pki"],
            },
            "application/pls+xml": {
              source: "iana",
              compressible: true,
              extensions: ["pls"],
            },
            "application/poc-settings+xml": {
              source: "iana",
              charset: "UTF-8",
              compressible: true,
            },
            "application/postscript": {
              source: "iana",
              compressible: true,
              extensions: ["ai", "eps", "ps"],
            },
            "application/ppsp-tracker+json": {
              source: "iana",
              compressible: true,
            },
            "application/problem+json": {
              source: "iana",
              compressible: true,
            },
            "application/problem+xml": {
              source: "iana",
              compressible: true,
            },
            "application/provenance+xml": {
              source: "iana",
              compressible: true,
              extensions: ["provx"],
            },
            "application/prs.alvestrand.titrax-sheet": {
              source: "iana",
            },
            "application/prs.cww": {
              source: "iana",
              extensions: ["cww"],
            },
            "application/prs.hpub+zip": {
              source: "iana",
              compressible: false,
            },
            "application/prs.nprend": {
              source: "iana",
            },
            "application/prs.plucker": {
              source: "iana",
            },
            "application/prs.rdf-xml-crypt": {
              source: "iana",
            },
            "application/prs.xsf+xml": {
              source: "iana",
              compressible: true,
            },
            "application/pskc+xml": {
              source: "iana",
              compressible: true,
              extensions: ["pskcxml"],
            },
            "application/pvd+json": {
              source: "iana",
              compressible: true,
            },
            "application/qsig": {
              source: "iana",
            },
            "application/raml+yaml": {
              compressible: true,
              extensions: ["raml"],
            },
            "application/raptorfec": {
              source: "iana",
            },
            "application/rdap+json": {
              source: "iana",
              compressible: true,
            },
            "application/rdf+xml": {
              source: "iana",
              compressible: true,
              extensions: ["rdf", "owl"],
            },
            "application/reginfo+xml": {
              source: "iana",
              compressible: true,
              extensions: ["rif"],
            },
            "application/relax-ng-compact-syntax": {
              source: "iana",
              extensions: ["rnc"],
            },
            "application/remote-printing": {
              source: "iana",
            },
            "application/reputon+json": {
              source: "iana",
              compressible: true,
            },
            "application/resource-lists+xml": {
              source: "iana",
              compressible: true,
              extensions: ["rl"],
            },
            "application/resource-lists-diff+xml": {
              source: "iana",
              compressible: true,
              extensions: ["rld"],
            },
            "application/rfc+xml": {
              source: "iana",
              compressible: true,
            },
            "application/riscos": {
              source: "iana",
            },
            "application/rlmi+xml": {
              source: "iana",
              compressible: true,
            },
            "application/rls-services+xml": {
              source: "iana",
              compressible: true,
              extensions: ["rs"],
            },
            "application/route-apd+xml": {
              source: "iana",
              compressible: true,
              extensions: ["rapd"],
            },
            "application/route-s-tsid+xml": {
              source: "iana",
              compressible: true,
              extensions: ["sls"],
            },
            "application/route-usd+xml": {
              source: "iana",
              compressible: true,
              extensions: ["rusd"],
            },
            "application/rpki-ghostbusters": {
              source: "iana",
              extensions: ["gbr"],
            },
            "application/rpki-manifest": {
              source: "iana",
              extensions: ["mft"],
            },
            "application/rpki-publication": {
              source: "iana",
            },
            "application/rpki-roa": {
              source: "iana",
              extensions: ["roa"],
            },
            "application/rpki-updown": {
              source: "iana",
            },
            "application/rsd+xml": {
              source: "apache",
              compressible: true,
              extensions: ["rsd"],
            },
            "application/rss+xml": {
              source: "apache",
              compressible: true,
              extensions: ["rss"],
            },
            "application/rtf": {
              source: "iana",
              compressible: true,
              extensions: ["rtf"],
            },
            "application/rtploopback": {
              source: "iana",
            },
            "application/rtx": {
              source: "iana",
            },
            "application/samlassertion+xml": {
              source: "iana",
              compressible: true,
            },
            "application/samlmetadata+xml": {
              source: "iana",
              compressible: true,
            },
            "application/sbe": {
              source: "iana",
            },
            "application/sbml+xml": {
              source: "iana",
              compressible: true,
              extensions: ["sbml"],
            },
            "application/scaip+xml": {
              source: "iana",
              compressible: true,
            },
            "application/scim+json": {
              source: "iana",
              compressible: true,
            },
            "application/scvp-cv-request": {
              source: "iana",
              extensions: ["scq"],
            },
            "application/scvp-cv-response": {
              source: "iana",
              extensions: ["scs"],
            },
            "application/scvp-vp-request": {
              source: "iana",
              extensions: ["spq"],
            },
            "application/scvp-vp-response": {
              source: "iana",
              extensions: ["spp"],
            },
            "application/sdp": {
              source: "iana",
              extensions: ["sdp"],
            },
            "application/secevent+jwt": {
              source: "iana",
            },
            "application/senml+cbor": {
              source: "iana",
            },
            "application/senml+json": {
              source: "iana",
              compressible: true,
            },
            "application/senml+xml": {
              source: "iana",
              compressible: true,
              extensions: ["senmlx"],
            },
            "application/senml-etch+cbor": {
              source: "iana",
            },
            "application/senml-etch+json": {
              source: "iana",
              compressible: true,
            },
            "application/senml-exi": {
              source: "iana",
            },
            "application/sensml+cbor": {
              source: "iana",
            },
            "application/sensml+json": {
              source: "iana",
              compressible: true,
            },
            "application/sensml+xml": {
              source: "iana",
              compressible: true,
              extensions: ["sensmlx"],
            },
            "application/sensml-exi": {
              source: "iana",
            },
            "application/sep+xml": {
              source: "iana",
              compressible: true,
            },
            "application/sep-exi": {
              source: "iana",
            },
            "application/session-info": {
              source: "iana",
            },
            "application/set-payment": {
              source: "iana",
            },
            "application/set-payment-initiation": {
              source: "iana",
              extensions: ["setpay"],
            },
            "application/set-registration": {
              source: "iana",
            },
            "application/set-registration-initiation": {
              source: "iana",
              extensions: ["setreg"],
            },
            "application/sgml": {
              source: "iana",
            },
            "application/sgml-open-catalog": {
              source: "iana",
            },
            "application/shf+xml": {
              source: "iana",
              compressible: true,
              extensions: ["shf"],
            },
            "application/sieve": {
              source: "iana",
              extensions: ["siv", "sieve"],
            },
            "application/simple-filter+xml": {
              source: "iana",
              compressible: true,
            },
            "application/simple-message-summary": {
              source: "iana",
            },
            "application/simplesymbolcontainer": {
              source: "iana",
            },
            "application/sipc": {
              source: "iana",
            },
            "application/slate": {
              source: "iana",
            },
            "application/smil": {
              source: "iana",
            },
            "application/smil+xml": {
              source: "iana",
              compressible: true,
              extensions: ["smi", "smil"],
            },
            "application/smpte336m": {
              source: "iana",
            },
            "application/soap+fastinfoset": {
              source: "iana",
            },
            "application/soap+xml": {
              source: "iana",
              compressible: true,
            },
            "application/sparql-query": {
              source: "iana",
              extensions: ["rq"],
            },
            "application/sparql-results+xml": {
              source: "iana",
              compressible: true,
              extensions: ["srx"],
            },
            "application/spirits-event+xml": {
              source: "iana",
              compressible: true,
            },
            "application/sql": {
              source: "iana",
            },
            "application/srgs": {
              source: "iana",
              extensions: ["gram"],
            },
            "application/srgs+xml": {
              source: "iana",
              compressible: true,
              extensions: ["grxml"],
            },
            "application/sru+xml": {
              source: "iana",
              compressible: true,
              extensions: ["sru"],
            },
            "application/ssdl+xml": {
              source: "apache",
              compressible: true,
              extensions: ["ssdl"],
            },
            "application/ssml+xml": {
              source: "iana",
              compressible: true,
              extensions: ["ssml"],
            },
            "application/stix+json": {
              source: "iana",
              compressible: true,
            },
            "application/swid+xml": {
              source: "iana",
              compressible: true,
              extensions: ["swidtag"],
            },
            "application/tamp-apex-update": {
              source: "iana",
            },
            "application/tamp-apex-update-confirm": {
              source: "iana",
            },
            "application/tamp-community-update": {
              source: "iana",
            },
            "application/tamp-community-update-confirm": {
              source: "iana",
            },
            "application/tamp-error": {
              source: "iana",
            },
            "application/tamp-sequence-adjust": {
              source: "iana",
            },
            "application/tamp-sequence-adjust-confirm": {
              source: "iana",
            },
            "application/tamp-status-query": {
              source: "iana",
            },
            "application/tamp-status-response": {
              source: "iana",
            },
            "application/tamp-update": {
              source: "iana",
            },
            "application/tamp-update-confirm": {
              source: "iana",
            },
            "application/tar": {
              compressible: true,
            },
            "application/taxii+json": {
              source: "iana",
              compressible: true,
            },
            "application/td+json": {
              source: "iana",
              compressible: true,
            },
            "application/tei+xml": {
              source: "iana",
              compressible: true,
              extensions: ["tei", "teicorpus"],
            },
            "application/tetra_isi": {
              source: "iana",
            },
            "application/thraud+xml": {
              source: "iana",
              compressible: true,
              extensions: ["tfi"],
            },
            "application/timestamp-query": {
              source: "iana",
            },
            "application/timestamp-reply": {
              source: "iana",
            },
            "application/timestamped-data": {
              source: "iana",
              extensions: ["tsd"],
            },
            "application/tlsrpt+gzip": {
              source: "iana",
            },
            "application/tlsrpt+json": {
              source: "iana",
              compressible: true,
            },
            "application/tnauthlist": {
              source: "iana",
            },
            "application/toml": {
              compressible: true,
              extensions: ["toml"],
            },
            "application/trickle-ice-sdpfrag": {
              source: "iana",
            },
            "application/trig": {
              source: "iana",
            },
            "application/ttml+xml": {
              source: "iana",
              compressible: true,
              extensions: ["ttml"],
            },
            "application/tve-trigger": {
              source: "iana",
            },
            "application/tzif": {
              source: "iana",
            },
            "application/tzif-leap": {
              source: "iana",
            },
            "application/ulpfec": {
              source: "iana",
            },
            "application/urc-grpsheet+xml": {
              source: "iana",
              compressible: true,
            },
            "application/urc-ressheet+xml": {
              source: "iana",
              compressible: true,
              extensions: ["rsheet"],
            },
            "application/urc-targetdesc+xml": {
              source: "iana",
              compressible: true,
            },
            "application/urc-uisocketdesc+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vcard+json": {
              source: "iana",
              compressible: true,
            },
            "application/vcard+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vemmi": {
              source: "iana",
            },
            "application/vividence.scriptfile": {
              source: "apache",
            },
            "application/vnd.1000minds.decision-model+xml": {
              source: "iana",
              compressible: true,
              extensions: ["1km"],
            },
            "application/vnd.3gpp-prose+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp-prose-pc3ch+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp-v2x-local-service-information": {
              source: "iana",
            },
            "application/vnd.3gpp.access-transfer-events+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.bsf+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.gmop+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.mc-signalling-ear": {
              source: "iana",
            },
            "application/vnd.3gpp.mcdata-affiliation-command+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.mcdata-info+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.mcdata-payload": {
              source: "iana",
            },
            "application/vnd.3gpp.mcdata-service-config+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.mcdata-signalling": {
              source: "iana",
            },
            "application/vnd.3gpp.mcdata-ue-config+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.mcdata-user-profile+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.mcptt-affiliation-command+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.mcptt-floor-request+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.mcptt-info+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.mcptt-location-info+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.mcptt-mbms-usage-info+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.mcptt-service-config+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.mcptt-signed+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.mcptt-ue-config+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.mcptt-ue-init-config+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.mcptt-user-profile+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.mcvideo-affiliation-command+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.mcvideo-affiliation-info+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.mcvideo-info+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.mcvideo-location-info+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.mcvideo-mbms-usage-info+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.mcvideo-service-config+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.mcvideo-transmission-request+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.mcvideo-ue-config+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.mcvideo-user-profile+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.mid-call+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.pic-bw-large": {
              source: "iana",
              extensions: ["plb"],
            },
            "application/vnd.3gpp.pic-bw-small": {
              source: "iana",
              extensions: ["psb"],
            },
            "application/vnd.3gpp.pic-bw-var": {
              source: "iana",
              extensions: ["pvb"],
            },
            "application/vnd.3gpp.sms": {
              source: "iana",
            },
            "application/vnd.3gpp.sms+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.srvcc-ext+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.srvcc-info+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.state-and-event-info+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp.ussd+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp2.bcmcsinfo+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.3gpp2.sms": {
              source: "iana",
            },
            "application/vnd.3gpp2.tcap": {
              source: "iana",
              extensions: ["tcap"],
            },
            "application/vnd.3lightssoftware.imagescal": {
              source: "iana",
            },
            "application/vnd.3m.post-it-notes": {
              source: "iana",
              extensions: ["pwn"],
            },
            "application/vnd.accpac.simply.aso": {
              source: "iana",
              extensions: ["aso"],
            },
            "application/vnd.accpac.simply.imp": {
              source: "iana",
              extensions: ["imp"],
            },
            "application/vnd.acucobol": {
              source: "iana",
              extensions: ["acu"],
            },
            "application/vnd.acucorp": {
              source: "iana",
              extensions: ["atc", "acutc"],
            },
            "application/vnd.adobe.air-application-installer-package+zip": {
              source: "apache",
              compressible: false,
              extensions: ["air"],
            },
            "application/vnd.adobe.flash.movie": {
              source: "iana",
            },
            "application/vnd.adobe.formscentral.fcdt": {
              source: "iana",
              extensions: ["fcdt"],
            },
            "application/vnd.adobe.fxp": {
              source: "iana",
              extensions: ["fxp", "fxpl"],
            },
            "application/vnd.adobe.partial-upload": {
              source: "iana",
            },
            "application/vnd.adobe.xdp+xml": {
              source: "iana",
              compressible: true,
              extensions: ["xdp"],
            },
            "application/vnd.adobe.xfdf": {
              source: "iana",
              extensions: ["xfdf"],
            },
            "application/vnd.aether.imp": {
              source: "iana",
            },
            "application/vnd.afpc.afplinedata": {
              source: "iana",
            },
            "application/vnd.afpc.afplinedata-pagedef": {
              source: "iana",
            },
            "application/vnd.afpc.foca-charset": {
              source: "iana",
            },
            "application/vnd.afpc.foca-codedfont": {
              source: "iana",
            },
            "application/vnd.afpc.foca-codepage": {
              source: "iana",
            },
            "application/vnd.afpc.modca": {
              source: "iana",
            },
            "application/vnd.afpc.modca-formdef": {
              source: "iana",
            },
            "application/vnd.afpc.modca-mediummap": {
              source: "iana",
            },
            "application/vnd.afpc.modca-objectcontainer": {
              source: "iana",
            },
            "application/vnd.afpc.modca-overlay": {
              source: "iana",
            },
            "application/vnd.afpc.modca-pagesegment": {
              source: "iana",
            },
            "application/vnd.ah-barcode": {
              source: "iana",
            },
            "application/vnd.ahead.space": {
              source: "iana",
              extensions: ["ahead"],
            },
            "application/vnd.airzip.filesecure.azf": {
              source: "iana",
              extensions: ["azf"],
            },
            "application/vnd.airzip.filesecure.azs": {
              source: "iana",
              extensions: ["azs"],
            },
            "application/vnd.amadeus+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.amazon.ebook": {
              source: "apache",
              extensions: ["azw"],
            },
            "application/vnd.amazon.mobi8-ebook": {
              source: "iana",
            },
            "application/vnd.americandynamics.acc": {
              source: "iana",
              extensions: ["acc"],
            },
            "application/vnd.amiga.ami": {
              source: "iana",
              extensions: ["ami"],
            },
            "application/vnd.amundsen.maze+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.android.ota": {
              source: "iana",
            },
            "application/vnd.android.package-archive": {
              source: "apache",
              compressible: false,
              extensions: ["apk"],
            },
            "application/vnd.anki": {
              source: "iana",
            },
            "application/vnd.anser-web-certificate-issue-initiation": {
              source: "iana",
              extensions: ["cii"],
            },
            "application/vnd.anser-web-funds-transfer-initiation": {
              source: "apache",
              extensions: ["fti"],
            },
            "application/vnd.antix.game-component": {
              source: "iana",
              extensions: ["atx"],
            },
            "application/vnd.apache.thrift.binary": {
              source: "iana",
            },
            "application/vnd.apache.thrift.compact": {
              source: "iana",
            },
            "application/vnd.apache.thrift.json": {
              source: "iana",
            },
            "application/vnd.api+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.aplextor.warrp+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.apothekende.reservation+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.apple.installer+xml": {
              source: "iana",
              compressible: true,
              extensions: ["mpkg"],
            },
            "application/vnd.apple.keynote": {
              source: "iana",
              extensions: ["keynote"],
            },
            "application/vnd.apple.mpegurl": {
              source: "iana",
              extensions: ["m3u8"],
            },
            "application/vnd.apple.numbers": {
              source: "iana",
              extensions: ["numbers"],
            },
            "application/vnd.apple.pages": {
              source: "iana",
              extensions: ["pages"],
            },
            "application/vnd.apple.pkpass": {
              compressible: false,
              extensions: ["pkpass"],
            },
            "application/vnd.arastra.swi": {
              source: "iana",
            },
            "application/vnd.aristanetworks.swi": {
              source: "iana",
              extensions: ["swi"],
            },
            "application/vnd.artisan+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.artsquare": {
              source: "iana",
            },
            "application/vnd.astraea-software.iota": {
              source: "iana",
              extensions: ["iota"],
            },
            "application/vnd.audiograph": {
              source: "iana",
              extensions: ["aep"],
            },
            "application/vnd.autopackage": {
              source: "iana",
            },
            "application/vnd.avalon+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.avistar+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.balsamiq.bmml+xml": {
              source: "iana",
              compressible: true,
              extensions: ["bmml"],
            },
            "application/vnd.balsamiq.bmpr": {
              source: "iana",
            },
            "application/vnd.banana-accounting": {
              source: "iana",
            },
            "application/vnd.bbf.usp.error": {
              source: "iana",
            },
            "application/vnd.bbf.usp.msg": {
              source: "iana",
            },
            "application/vnd.bbf.usp.msg+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.bekitzur-stech+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.bint.med-content": {
              source: "iana",
            },
            "application/vnd.biopax.rdf+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.blink-idb-value-wrapper": {
              source: "iana",
            },
            "application/vnd.blueice.multipass": {
              source: "iana",
              extensions: ["mpm"],
            },
            "application/vnd.bluetooth.ep.oob": {
              source: "iana",
            },
            "application/vnd.bluetooth.le.oob": {
              source: "iana",
            },
            "application/vnd.bmi": {
              source: "iana",
              extensions: ["bmi"],
            },
            "application/vnd.bpf": {
              source: "iana",
            },
            "application/vnd.bpf3": {
              source: "iana",
            },
            "application/vnd.businessobjects": {
              source: "iana",
              extensions: ["rep"],
            },
            "application/vnd.byu.uapi+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.cab-jscript": {
              source: "iana",
            },
            "application/vnd.canon-cpdl": {
              source: "iana",
            },
            "application/vnd.canon-lips": {
              source: "iana",
            },
            "application/vnd.capasystems-pg+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.cendio.thinlinc.clientconf": {
              source: "iana",
            },
            "application/vnd.century-systems.tcp_stream": {
              source: "iana",
            },
            "application/vnd.chemdraw+xml": {
              source: "iana",
              compressible: true,
              extensions: ["cdxml"],
            },
            "application/vnd.chess-pgn": {
              source: "iana",
            },
            "application/vnd.chipnuts.karaoke-mmd": {
              source: "iana",
              extensions: ["mmd"],
            },
            "application/vnd.ciedi": {
              source: "iana",
            },
            "application/vnd.cinderella": {
              source: "iana",
              extensions: ["cdy"],
            },
            "application/vnd.cirpack.isdn-ext": {
              source: "iana",
            },
            "application/vnd.citationstyles.style+xml": {
              source: "iana",
              compressible: true,
              extensions: ["csl"],
            },
            "application/vnd.claymore": {
              source: "iana",
              extensions: ["cla"],
            },
            "application/vnd.cloanto.rp9": {
              source: "iana",
              extensions: ["rp9"],
            },
            "application/vnd.clonk.c4group": {
              source: "iana",
              extensions: ["c4g", "c4d", "c4f", "c4p", "c4u"],
            },
            "application/vnd.cluetrust.cartomobile-config": {
              source: "iana",
              extensions: ["c11amc"],
            },
            "application/vnd.cluetrust.cartomobile-config-pkg": {
              source: "iana",
              extensions: ["c11amz"],
            },
            "application/vnd.coffeescript": {
              source: "iana",
            },
            "application/vnd.collabio.xodocuments.document": {
              source: "iana",
            },
            "application/vnd.collabio.xodocuments.document-template": {
              source: "iana",
            },
            "application/vnd.collabio.xodocuments.presentation": {
              source: "iana",
            },
            "application/vnd.collabio.xodocuments.presentation-template": {
              source: "iana",
            },
            "application/vnd.collabio.xodocuments.spreadsheet": {
              source: "iana",
            },
            "application/vnd.collabio.xodocuments.spreadsheet-template": {
              source: "iana",
            },
            "application/vnd.collection+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.collection.doc+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.collection.next+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.comicbook+zip": {
              source: "iana",
              compressible: false,
            },
            "application/vnd.comicbook-rar": {
              source: "iana",
            },
            "application/vnd.commerce-battelle": {
              source: "iana",
            },
            "application/vnd.commonspace": {
              source: "iana",
              extensions: ["csp"],
            },
            "application/vnd.contact.cmsg": {
              source: "iana",
              extensions: ["cdbcmsg"],
            },
            "application/vnd.coreos.ignition+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.cosmocaller": {
              source: "iana",
              extensions: ["cmc"],
            },
            "application/vnd.crick.clicker": {
              source: "iana",
              extensions: ["clkx"],
            },
            "application/vnd.crick.clicker.keyboard": {
              source: "iana",
              extensions: ["clkk"],
            },
            "application/vnd.crick.clicker.palette": {
              source: "iana",
              extensions: ["clkp"],
            },
            "application/vnd.crick.clicker.template": {
              source: "iana",
              extensions: ["clkt"],
            },
            "application/vnd.crick.clicker.wordbank": {
              source: "iana",
              extensions: ["clkw"],
            },
            "application/vnd.criticaltools.wbs+xml": {
              source: "iana",
              compressible: true,
              extensions: ["wbs"],
            },
            "application/vnd.cryptii.pipe+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.crypto-shade-file": {
              source: "iana",
            },
            "application/vnd.ctc-posml": {
              source: "iana",
              extensions: ["pml"],
            },
            "application/vnd.ctct.ws+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.cups-pdf": {
              source: "iana",
            },
            "application/vnd.cups-postscript": {
              source: "iana",
            },
            "application/vnd.cups-ppd": {
              source: "iana",
              extensions: ["ppd"],
            },
            "application/vnd.cups-raster": {
              source: "iana",
            },
            "application/vnd.cups-raw": {
              source: "iana",
            },
            "application/vnd.curl": {
              source: "iana",
            },
            "application/vnd.curl.car": {
              source: "apache",
              extensions: ["car"],
            },
            "application/vnd.curl.pcurl": {
              source: "apache",
              extensions: ["pcurl"],
            },
            "application/vnd.cyan.dean.root+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.cybank": {
              source: "iana",
            },
            "application/vnd.d2l.coursepackage1p0+zip": {
              source: "iana",
              compressible: false,
            },
            "application/vnd.dart": {
              source: "iana",
              compressible: true,
              extensions: ["dart"],
            },
            "application/vnd.data-vision.rdz": {
              source: "iana",
              extensions: ["rdz"],
            },
            "application/vnd.datapackage+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.dataresource+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.dbf": {
              source: "iana",
            },
            "application/vnd.debian.binary-package": {
              source: "iana",
            },
            "application/vnd.dece.data": {
              source: "iana",
              extensions: ["uvf", "uvvf", "uvd", "uvvd"],
            },
            "application/vnd.dece.ttml+xml": {
              source: "iana",
              compressible: true,
              extensions: ["uvt", "uvvt"],
            },
            "application/vnd.dece.unspecified": {
              source: "iana",
              extensions: ["uvx", "uvvx"],
            },
            "application/vnd.dece.zip": {
              source: "iana",
              extensions: ["uvz", "uvvz"],
            },
            "application/vnd.denovo.fcselayout-link": {
              source: "iana",
              extensions: ["fe_launch"],
            },
            "application/vnd.desmume.movie": {
              source: "iana",
            },
            "application/vnd.dir-bi.plate-dl-nosuffix": {
              source: "iana",
            },
            "application/vnd.dm.delegation+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.dna": {
              source: "iana",
              extensions: ["dna"],
            },
            "application/vnd.document+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.dolby.mlp": {
              source: "apache",
              extensions: ["mlp"],
            },
            "application/vnd.dolby.mobile.1": {
              source: "iana",
            },
            "application/vnd.dolby.mobile.2": {
              source: "iana",
            },
            "application/vnd.doremir.scorecloud-binary-document": {
              source: "iana",
            },
            "application/vnd.dpgraph": {
              source: "iana",
              extensions: ["dpg"],
            },
            "application/vnd.dreamfactory": {
              source: "iana",
              extensions: ["dfac"],
            },
            "application/vnd.drive+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.ds-keypoint": {
              source: "apache",
              extensions: ["kpxx"],
            },
            "application/vnd.dtg.local": {
              source: "iana",
            },
            "application/vnd.dtg.local.flash": {
              source: "iana",
            },
            "application/vnd.dtg.local.html": {
              source: "iana",
            },
            "application/vnd.dvb.ait": {
              source: "iana",
              extensions: ["ait"],
            },
            "application/vnd.dvb.dvbisl+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.dvb.dvbj": {
              source: "iana",
            },
            "application/vnd.dvb.esgcontainer": {
              source: "iana",
            },
            "application/vnd.dvb.ipdcdftnotifaccess": {
              source: "iana",
            },
            "application/vnd.dvb.ipdcesgaccess": {
              source: "iana",
            },
            "application/vnd.dvb.ipdcesgaccess2": {
              source: "iana",
            },
            "application/vnd.dvb.ipdcesgpdd": {
              source: "iana",
            },
            "application/vnd.dvb.ipdcroaming": {
              source: "iana",
            },
            "application/vnd.dvb.iptv.alfec-base": {
              source: "iana",
            },
            "application/vnd.dvb.iptv.alfec-enhancement": {
              source: "iana",
            },
            "application/vnd.dvb.notif-aggregate-root+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.dvb.notif-container+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.dvb.notif-generic+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.dvb.notif-ia-msglist+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.dvb.notif-ia-registration-request+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.dvb.notif-ia-registration-response+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.dvb.notif-init+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.dvb.pfr": {
              source: "iana",
            },
            "application/vnd.dvb.service": {
              source: "iana",
              extensions: ["svc"],
            },
            "application/vnd.dxr": {
              source: "iana",
            },
            "application/vnd.dynageo": {
              source: "iana",
              extensions: ["geo"],
            },
            "application/vnd.dzr": {
              source: "iana",
            },
            "application/vnd.easykaraoke.cdgdownload": {
              source: "iana",
            },
            "application/vnd.ecdis-update": {
              source: "iana",
            },
            "application/vnd.ecip.rlp": {
              source: "iana",
            },
            "application/vnd.ecowin.chart": {
              source: "iana",
              extensions: ["mag"],
            },
            "application/vnd.ecowin.filerequest": {
              source: "iana",
            },
            "application/vnd.ecowin.fileupdate": {
              source: "iana",
            },
            "application/vnd.ecowin.series": {
              source: "iana",
            },
            "application/vnd.ecowin.seriesrequest": {
              source: "iana",
            },
            "application/vnd.ecowin.seriesupdate": {
              source: "iana",
            },
            "application/vnd.efi.img": {
              source: "iana",
            },
            "application/vnd.efi.iso": {
              source: "iana",
            },
            "application/vnd.emclient.accessrequest+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.enliven": {
              source: "iana",
              extensions: ["nml"],
            },
            "application/vnd.enphase.envoy": {
              source: "iana",
            },
            "application/vnd.eprints.data+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.epson.esf": {
              source: "iana",
              extensions: ["esf"],
            },
            "application/vnd.epson.msf": {
              source: "iana",
              extensions: ["msf"],
            },
            "application/vnd.epson.quickanime": {
              source: "iana",
              extensions: ["qam"],
            },
            "application/vnd.epson.salt": {
              source: "iana",
              extensions: ["slt"],
            },
            "application/vnd.epson.ssf": {
              source: "iana",
              extensions: ["ssf"],
            },
            "application/vnd.ericsson.quickcall": {
              source: "iana",
            },
            "application/vnd.espass-espass+zip": {
              source: "iana",
              compressible: false,
            },
            "application/vnd.eszigno3+xml": {
              source: "iana",
              compressible: true,
              extensions: ["es3", "et3"],
            },
            "application/vnd.etsi.aoc+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.etsi.asic-e+zip": {
              source: "iana",
              compressible: false,
            },
            "application/vnd.etsi.asic-s+zip": {
              source: "iana",
              compressible: false,
            },
            "application/vnd.etsi.cug+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.etsi.iptvcommand+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.etsi.iptvdiscovery+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.etsi.iptvprofile+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.etsi.iptvsad-bc+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.etsi.iptvsad-cod+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.etsi.iptvsad-npvr+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.etsi.iptvservice+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.etsi.iptvsync+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.etsi.iptvueprofile+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.etsi.mcid+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.etsi.mheg5": {
              source: "iana",
            },
            "application/vnd.etsi.overload-control-policy-dataset+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.etsi.pstn+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.etsi.sci+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.etsi.simservs+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.etsi.timestamp-token": {
              source: "iana",
            },
            "application/vnd.etsi.tsl+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.etsi.tsl.der": {
              source: "iana",
            },
            "application/vnd.eudora.data": {
              source: "iana",
            },
            "application/vnd.evolv.ecig.profile": {
              source: "iana",
            },
            "application/vnd.evolv.ecig.settings": {
              source: "iana",
            },
            "application/vnd.evolv.ecig.theme": {
              source: "iana",
            },
            "application/vnd.exstream-empower+zip": {
              source: "iana",
              compressible: false,
            },
            "application/vnd.exstream-package": {
              source: "iana",
            },
            "application/vnd.ezpix-album": {
              source: "iana",
              extensions: ["ez2"],
            },
            "application/vnd.ezpix-package": {
              source: "iana",
              extensions: ["ez3"],
            },
            "application/vnd.f-secure.mobile": {
              source: "iana",
            },
            "application/vnd.fastcopy-disk-image": {
              source: "iana",
            },
            "application/vnd.fdf": {
              source: "iana",
              extensions: ["fdf"],
            },
            "application/vnd.fdsn.mseed": {
              source: "iana",
              extensions: ["mseed"],
            },
            "application/vnd.fdsn.seed": {
              source: "iana",
              extensions: ["seed", "dataless"],
            },
            "application/vnd.ffsns": {
              source: "iana",
            },
            "application/vnd.ficlab.flb+zip": {
              source: "iana",
              compressible: false,
            },
            "application/vnd.filmit.zfc": {
              source: "iana",
            },
            "application/vnd.fints": {
              source: "iana",
            },
            "application/vnd.firemonkeys.cloudcell": {
              source: "iana",
            },
            "application/vnd.flographit": {
              source: "iana",
              extensions: ["gph"],
            },
            "application/vnd.fluxtime.clip": {
              source: "iana",
              extensions: ["ftc"],
            },
            "application/vnd.font-fontforge-sfd": {
              source: "iana",
            },
            "application/vnd.framemaker": {
              source: "iana",
              extensions: ["fm", "frame", "maker", "book"],
            },
            "application/vnd.frogans.fnc": {
              source: "iana",
              extensions: ["fnc"],
            },
            "application/vnd.frogans.ltf": {
              source: "iana",
              extensions: ["ltf"],
            },
            "application/vnd.fsc.weblaunch": {
              source: "iana",
              extensions: ["fsc"],
            },
            "application/vnd.fujitsu.oasys": {
              source: "iana",
              extensions: ["oas"],
            },
            "application/vnd.fujitsu.oasys2": {
              source: "iana",
              extensions: ["oa2"],
            },
            "application/vnd.fujitsu.oasys3": {
              source: "iana",
              extensions: ["oa3"],
            },
            "application/vnd.fujitsu.oasysgp": {
              source: "iana",
              extensions: ["fg5"],
            },
            "application/vnd.fujitsu.oasysprs": {
              source: "iana",
              extensions: ["bh2"],
            },
            "application/vnd.fujixerox.art-ex": {
              source: "iana",
            },
            "application/vnd.fujixerox.art4": {
              source: "iana",
            },
            "application/vnd.fujixerox.ddd": {
              source: "iana",
              extensions: ["ddd"],
            },
            "application/vnd.fujixerox.docuworks": {
              source: "iana",
              extensions: ["xdw"],
            },
            "application/vnd.fujixerox.docuworks.binder": {
              source: "iana",
              extensions: ["xbd"],
            },
            "application/vnd.fujixerox.docuworks.container": {
              source: "iana",
            },
            "application/vnd.fujixerox.hbpl": {
              source: "iana",
            },
            "application/vnd.fut-misnet": {
              source: "iana",
            },
            "application/vnd.futoin+cbor": {
              source: "iana",
            },
            "application/vnd.futoin+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.fuzzysheet": {
              source: "iana",
              extensions: ["fzs"],
            },
            "application/vnd.genomatix.tuxedo": {
              source: "iana",
              extensions: ["txd"],
            },
            "application/vnd.gentics.grd+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.geo+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.geocube+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.geogebra.file": {
              source: "iana",
              extensions: ["ggb"],
            },
            "application/vnd.geogebra.tool": {
              source: "iana",
              extensions: ["ggt"],
            },
            "application/vnd.geometry-explorer": {
              source: "iana",
              extensions: ["gex", "gre"],
            },
            "application/vnd.geonext": {
              source: "iana",
              extensions: ["gxt"],
            },
            "application/vnd.geoplan": {
              source: "iana",
              extensions: ["g2w"],
            },
            "application/vnd.geospace": {
              source: "iana",
              extensions: ["g3w"],
            },
            "application/vnd.gerber": {
              source: "iana",
            },
            "application/vnd.globalplatform.card-content-mgt": {
              source: "iana",
            },
            "application/vnd.globalplatform.card-content-mgt-response": {
              source: "iana",
            },
            "application/vnd.gmx": {
              source: "iana",
              extensions: ["gmx"],
            },
            "application/vnd.google-apps.document": {
              compressible: false,
              extensions: ["gdoc"],
            },
            "application/vnd.google-apps.presentation": {
              compressible: false,
              extensions: ["gslides"],
            },
            "application/vnd.google-apps.spreadsheet": {
              compressible: false,
              extensions: ["gsheet"],
            },
            "application/vnd.google-earth.kml+xml": {
              source: "iana",
              compressible: true,
              extensions: ["kml"],
            },
            "application/vnd.google-earth.kmz": {
              source: "iana",
              compressible: false,
              extensions: ["kmz"],
            },
            "application/vnd.gov.sk.e-form+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.gov.sk.e-form+zip": {
              source: "iana",
              compressible: false,
            },
            "application/vnd.gov.sk.xmldatacontainer+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.grafeq": {
              source: "iana",
              extensions: ["gqf", "gqs"],
            },
            "application/vnd.gridmp": {
              source: "iana",
            },
            "application/vnd.groove-account": {
              source: "iana",
              extensions: ["gac"],
            },
            "application/vnd.groove-help": {
              source: "iana",
              extensions: ["ghf"],
            },
            "application/vnd.groove-identity-message": {
              source: "iana",
              extensions: ["gim"],
            },
            "application/vnd.groove-injector": {
              source: "iana",
              extensions: ["grv"],
            },
            "application/vnd.groove-tool-message": {
              source: "iana",
              extensions: ["gtm"],
            },
            "application/vnd.groove-tool-template": {
              source: "iana",
              extensions: ["tpl"],
            },
            "application/vnd.groove-vcard": {
              source: "iana",
              extensions: ["vcg"],
            },
            "application/vnd.hal+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.hal+xml": {
              source: "iana",
              compressible: true,
              extensions: ["hal"],
            },
            "application/vnd.handheld-entertainment+xml": {
              source: "iana",
              compressible: true,
              extensions: ["zmm"],
            },
            "application/vnd.hbci": {
              source: "iana",
              extensions: ["hbci"],
            },
            "application/vnd.hc+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.hcl-bireports": {
              source: "iana",
            },
            "application/vnd.hdt": {
              source: "iana",
            },
            "application/vnd.heroku+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.hhe.lesson-player": {
              source: "iana",
              extensions: ["les"],
            },
            "application/vnd.hp-hpgl": {
              source: "iana",
              extensions: ["hpgl"],
            },
            "application/vnd.hp-hpid": {
              source: "iana",
              extensions: ["hpid"],
            },
            "application/vnd.hp-hps": {
              source: "iana",
              extensions: ["hps"],
            },
            "application/vnd.hp-jlyt": {
              source: "iana",
              extensions: ["jlt"],
            },
            "application/vnd.hp-pcl": {
              source: "iana",
              extensions: ["pcl"],
            },
            "application/vnd.hp-pclxl": {
              source: "iana",
              extensions: ["pclxl"],
            },
            "application/vnd.httphone": {
              source: "iana",
            },
            "application/vnd.hydrostatix.sof-data": {
              source: "iana",
              extensions: ["sfd-hdstx"],
            },
            "application/vnd.hyper+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.hyper-item+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.hyperdrive+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.hzn-3d-crossword": {
              source: "iana",
            },
            "application/vnd.ibm.afplinedata": {
              source: "iana",
            },
            "application/vnd.ibm.electronic-media": {
              source: "iana",
            },
            "application/vnd.ibm.minipay": {
              source: "iana",
              extensions: ["mpy"],
            },
            "application/vnd.ibm.modcap": {
              source: "iana",
              extensions: ["afp", "listafp", "list3820"],
            },
            "application/vnd.ibm.rights-management": {
              source: "iana",
              extensions: ["irm"],
            },
            "application/vnd.ibm.secure-container": {
              source: "iana",
              extensions: ["sc"],
            },
            "application/vnd.iccprofile": {
              source: "iana",
              extensions: ["icc", "icm"],
            },
            "application/vnd.ieee.1905": {
              source: "iana",
            },
            "application/vnd.igloader": {
              source: "iana",
              extensions: ["igl"],
            },
            "application/vnd.imagemeter.folder+zip": {
              source: "iana",
              compressible: false,
            },
            "application/vnd.imagemeter.image+zip": {
              source: "iana",
              compressible: false,
            },
            "application/vnd.immervision-ivp": {
              source: "iana",
              extensions: ["ivp"],
            },
            "application/vnd.immervision-ivu": {
              source: "iana",
              extensions: ["ivu"],
            },
            "application/vnd.ims.imsccv1p1": {
              source: "iana",
            },
            "application/vnd.ims.imsccv1p2": {
              source: "iana",
            },
            "application/vnd.ims.imsccv1p3": {
              source: "iana",
            },
            "application/vnd.ims.lis.v2.result+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.ims.lti.v2.toolconsumerprofile+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.ims.lti.v2.toolproxy+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.ims.lti.v2.toolproxy.id+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.ims.lti.v2.toolsettings+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.ims.lti.v2.toolsettings.simple+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.informedcontrol.rms+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.informix-visionary": {
              source: "iana",
            },
            "application/vnd.infotech.project": {
              source: "iana",
            },
            "application/vnd.infotech.project+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.innopath.wamp.notification": {
              source: "iana",
            },
            "application/vnd.insors.igm": {
              source: "iana",
              extensions: ["igm"],
            },
            "application/vnd.intercon.formnet": {
              source: "iana",
              extensions: ["xpw", "xpx"],
            },
            "application/vnd.intergeo": {
              source: "iana",
              extensions: ["i2g"],
            },
            "application/vnd.intertrust.digibox": {
              source: "iana",
            },
            "application/vnd.intertrust.nncp": {
              source: "iana",
            },
            "application/vnd.intu.qbo": {
              source: "iana",
              extensions: ["qbo"],
            },
            "application/vnd.intu.qfx": {
              source: "iana",
              extensions: ["qfx"],
            },
            "application/vnd.iptc.g2.catalogitem+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.iptc.g2.conceptitem+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.iptc.g2.knowledgeitem+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.iptc.g2.newsitem+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.iptc.g2.newsmessage+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.iptc.g2.packageitem+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.iptc.g2.planningitem+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.ipunplugged.rcprofile": {
              source: "iana",
              extensions: ["rcprofile"],
            },
            "application/vnd.irepository.package+xml": {
              source: "iana",
              compressible: true,
              extensions: ["irp"],
            },
            "application/vnd.is-xpr": {
              source: "iana",
              extensions: ["xpr"],
            },
            "application/vnd.isac.fcs": {
              source: "iana",
              extensions: ["fcs"],
            },
            "application/vnd.iso11783-10+zip": {
              source: "iana",
              compressible: false,
            },
            "application/vnd.jam": {
              source: "iana",
              extensions: ["jam"],
            },
            "application/vnd.japannet-directory-service": {
              source: "iana",
            },
            "application/vnd.japannet-jpnstore-wakeup": {
              source: "iana",
            },
            "application/vnd.japannet-payment-wakeup": {
              source: "iana",
            },
            "application/vnd.japannet-registration": {
              source: "iana",
            },
            "application/vnd.japannet-registration-wakeup": {
              source: "iana",
            },
            "application/vnd.japannet-setstore-wakeup": {
              source: "iana",
            },
            "application/vnd.japannet-verification": {
              source: "iana",
            },
            "application/vnd.japannet-verification-wakeup": {
              source: "iana",
            },
            "application/vnd.jcp.javame.midlet-rms": {
              source: "iana",
              extensions: ["rms"],
            },
            "application/vnd.jisp": {
              source: "iana",
              extensions: ["jisp"],
            },
            "application/vnd.joost.joda-archive": {
              source: "iana",
              extensions: ["joda"],
            },
            "application/vnd.jsk.isdn-ngn": {
              source: "iana",
            },
            "application/vnd.kahootz": {
              source: "iana",
              extensions: ["ktz", "ktr"],
            },
            "application/vnd.kde.karbon": {
              source: "iana",
              extensions: ["karbon"],
            },
            "application/vnd.kde.kchart": {
              source: "iana",
              extensions: ["chrt"],
            },
            "application/vnd.kde.kformula": {
              source: "iana",
              extensions: ["kfo"],
            },
            "application/vnd.kde.kivio": {
              source: "iana",
              extensions: ["flw"],
            },
            "application/vnd.kde.kontour": {
              source: "iana",
              extensions: ["kon"],
            },
            "application/vnd.kde.kpresenter": {
              source: "iana",
              extensions: ["kpr", "kpt"],
            },
            "application/vnd.kde.kspread": {
              source: "iana",
              extensions: ["ksp"],
            },
            "application/vnd.kde.kword": {
              source: "iana",
              extensions: ["kwd", "kwt"],
            },
            "application/vnd.kenameaapp": {
              source: "iana",
              extensions: ["htke"],
            },
            "application/vnd.kidspiration": {
              source: "iana",
              extensions: ["kia"],
            },
            "application/vnd.kinar": {
              source: "iana",
              extensions: ["kne", "knp"],
            },
            "application/vnd.koan": {
              source: "iana",
              extensions: ["skp", "skd", "skt", "skm"],
            },
            "application/vnd.kodak-descriptor": {
              source: "iana",
              extensions: ["sse"],
            },
            "application/vnd.las": {
              source: "iana",
            },
            "application/vnd.las.las+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.las.las+xml": {
              source: "iana",
              compressible: true,
              extensions: ["lasxml"],
            },
            "application/vnd.laszip": {
              source: "iana",
            },
            "application/vnd.leap+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.liberty-request+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.llamagraphics.life-balance.desktop": {
              source: "iana",
              extensions: ["lbd"],
            },
            "application/vnd.llamagraphics.life-balance.exchange+xml": {
              source: "iana",
              compressible: true,
              extensions: ["lbe"],
            },
            "application/vnd.logipipe.circuit+zip": {
              source: "iana",
              compressible: false,
            },
            "application/vnd.loom": {
              source: "iana",
            },
            "application/vnd.lotus-1-2-3": {
              source: "iana",
              extensions: ["123"],
            },
            "application/vnd.lotus-approach": {
              source: "iana",
              extensions: ["apr"],
            },
            "application/vnd.lotus-freelance": {
              source: "iana",
              extensions: ["pre"],
            },
            "application/vnd.lotus-notes": {
              source: "iana",
              extensions: ["nsf"],
            },
            "application/vnd.lotus-organizer": {
              source: "iana",
              extensions: ["org"],
            },
            "application/vnd.lotus-screencam": {
              source: "iana",
              extensions: ["scm"],
            },
            "application/vnd.lotus-wordpro": {
              source: "iana",
              extensions: ["lwp"],
            },
            "application/vnd.macports.portpkg": {
              source: "iana",
              extensions: ["portpkg"],
            },
            "application/vnd.mapbox-vector-tile": {
              source: "iana",
            },
            "application/vnd.marlin.drm.actiontoken+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.marlin.drm.conftoken+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.marlin.drm.license+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.marlin.drm.mdcf": {
              source: "iana",
            },
            "application/vnd.mason+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.maxmind.maxmind-db": {
              source: "iana",
            },
            "application/vnd.mcd": {
              source: "iana",
              extensions: ["mcd"],
            },
            "application/vnd.medcalcdata": {
              source: "iana",
              extensions: ["mc1"],
            },
            "application/vnd.mediastation.cdkey": {
              source: "iana",
              extensions: ["cdkey"],
            },
            "application/vnd.meridian-slingshot": {
              source: "iana",
            },
            "application/vnd.mfer": {
              source: "iana",
              extensions: ["mwf"],
            },
            "application/vnd.mfmp": {
              source: "iana",
              extensions: ["mfm"],
            },
            "application/vnd.micro+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.micrografx.flo": {
              source: "iana",
              extensions: ["flo"],
            },
            "application/vnd.micrografx.igx": {
              source: "iana",
              extensions: ["igx"],
            },
            "application/vnd.microsoft.portable-executable": {
              source: "iana",
            },
            "application/vnd.microsoft.windows.thumbnail-cache": {
              source: "iana",
            },
            "application/vnd.miele+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.mif": {
              source: "iana",
              extensions: ["mif"],
            },
            "application/vnd.minisoft-hp3000-save": {
              source: "iana",
            },
            "application/vnd.mitsubishi.misty-guard.trustweb": {
              source: "iana",
            },
            "application/vnd.mobius.daf": {
              source: "iana",
              extensions: ["daf"],
            },
            "application/vnd.mobius.dis": {
              source: "iana",
              extensions: ["dis"],
            },
            "application/vnd.mobius.mbk": {
              source: "iana",
              extensions: ["mbk"],
            },
            "application/vnd.mobius.mqy": {
              source: "iana",
              extensions: ["mqy"],
            },
            "application/vnd.mobius.msl": {
              source: "iana",
              extensions: ["msl"],
            },
            "application/vnd.mobius.plc": {
              source: "iana",
              extensions: ["plc"],
            },
            "application/vnd.mobius.txf": {
              source: "iana",
              extensions: ["txf"],
            },
            "application/vnd.mophun.application": {
              source: "iana",
              extensions: ["mpn"],
            },
            "application/vnd.mophun.certificate": {
              source: "iana",
              extensions: ["mpc"],
            },
            "application/vnd.motorola.flexsuite": {
              source: "iana",
            },
            "application/vnd.motorola.flexsuite.adsi": {
              source: "iana",
            },
            "application/vnd.motorola.flexsuite.fis": {
              source: "iana",
            },
            "application/vnd.motorola.flexsuite.gotap": {
              source: "iana",
            },
            "application/vnd.motorola.flexsuite.kmr": {
              source: "iana",
            },
            "application/vnd.motorola.flexsuite.ttc": {
              source: "iana",
            },
            "application/vnd.motorola.flexsuite.wem": {
              source: "iana",
            },
            "application/vnd.motorola.iprm": {
              source: "iana",
            },
            "application/vnd.mozilla.xul+xml": {
              source: "iana",
              compressible: true,
              extensions: ["xul"],
            },
            "application/vnd.ms-3mfdocument": {
              source: "iana",
            },
            "application/vnd.ms-artgalry": {
              source: "iana",
              extensions: ["cil"],
            },
            "application/vnd.ms-asf": {
              source: "iana",
            },
            "application/vnd.ms-cab-compressed": {
              source: "iana",
              extensions: ["cab"],
            },
            "application/vnd.ms-color.iccprofile": {
              source: "apache",
            },
            "application/vnd.ms-excel": {
              source: "iana",
              compressible: false,
              extensions: ["xls", "xlm", "xla", "xlc", "xlt", "xlw"],
            },
            "application/vnd.ms-excel.addin.macroenabled.12": {
              source: "iana",
              extensions: ["xlam"],
            },
            "application/vnd.ms-excel.sheet.binary.macroenabled.12": {
              source: "iana",
              extensions: ["xlsb"],
            },
            "application/vnd.ms-excel.sheet.macroenabled.12": {
              source: "iana",
              extensions: ["xlsm"],
            },
            "application/vnd.ms-excel.template.macroenabled.12": {
              source: "iana",
              extensions: ["xltm"],
            },
            "application/vnd.ms-fontobject": {
              source: "iana",
              compressible: true,
              extensions: ["eot"],
            },
            "application/vnd.ms-htmlhelp": {
              source: "iana",
              extensions: ["chm"],
            },
            "application/vnd.ms-ims": {
              source: "iana",
              extensions: ["ims"],
            },
            "application/vnd.ms-lrm": {
              source: "iana",
              extensions: ["lrm"],
            },
            "application/vnd.ms-office.activex+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.ms-officetheme": {
              source: "iana",
              extensions: ["thmx"],
            },
            "application/vnd.ms-opentype": {
              source: "apache",
              compressible: true,
            },
            "application/vnd.ms-outlook": {
              compressible: false,
              extensions: ["msg"],
            },
            "application/vnd.ms-package.obfuscated-opentype": {
              source: "apache",
            },
            "application/vnd.ms-pki.seccat": {
              source: "apache",
              extensions: ["cat"],
            },
            "application/vnd.ms-pki.stl": {
              source: "apache",
              extensions: ["stl"],
            },
            "application/vnd.ms-playready.initiator+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.ms-powerpoint": {
              source: "iana",
              compressible: false,
              extensions: ["ppt", "pps", "pot"],
            },
            "application/vnd.ms-powerpoint.addin.macroenabled.12": {
              source: "iana",
              extensions: ["ppam"],
            },
            "application/vnd.ms-powerpoint.presentation.macroenabled.12": {
              source: "iana",
              extensions: ["pptm"],
            },
            "application/vnd.ms-powerpoint.slide.macroenabled.12": {
              source: "iana",
              extensions: ["sldm"],
            },
            "application/vnd.ms-powerpoint.slideshow.macroenabled.12": {
              source: "iana",
              extensions: ["ppsm"],
            },
            "application/vnd.ms-powerpoint.template.macroenabled.12": {
              source: "iana",
              extensions: ["potm"],
            },
            "application/vnd.ms-printdevicecapabilities+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.ms-printing.printticket+xml": {
              source: "apache",
              compressible: true,
            },
            "application/vnd.ms-printschematicket+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.ms-project": {
              source: "iana",
              extensions: ["mpp", "mpt"],
            },
            "application/vnd.ms-tnef": {
              source: "iana",
            },
            "application/vnd.ms-windows.devicepairing": {
              source: "iana",
            },
            "application/vnd.ms-windows.nwprinting.oob": {
              source: "iana",
            },
            "application/vnd.ms-windows.printerpairing": {
              source: "iana",
            },
            "application/vnd.ms-windows.wsd.oob": {
              source: "iana",
            },
            "application/vnd.ms-wmdrm.lic-chlg-req": {
              source: "iana",
            },
            "application/vnd.ms-wmdrm.lic-resp": {
              source: "iana",
            },
            "application/vnd.ms-wmdrm.meter-chlg-req": {
              source: "iana",
            },
            "application/vnd.ms-wmdrm.meter-resp": {
              source: "iana",
            },
            "application/vnd.ms-word.document.macroenabled.12": {
              source: "iana",
              extensions: ["docm"],
            },
            "application/vnd.ms-word.template.macroenabled.12": {
              source: "iana",
              extensions: ["dotm"],
            },
            "application/vnd.ms-works": {
              source: "iana",
              extensions: ["wps", "wks", "wcm", "wdb"],
            },
            "application/vnd.ms-wpl": {
              source: "iana",
              extensions: ["wpl"],
            },
            "application/vnd.ms-xpsdocument": {
              source: "iana",
              compressible: false,
              extensions: ["xps"],
            },
            "application/vnd.msa-disk-image": {
              source: "iana",
            },
            "application/vnd.mseq": {
              source: "iana",
              extensions: ["mseq"],
            },
            "application/vnd.msign": {
              source: "iana",
            },
            "application/vnd.multiad.creator": {
              source: "iana",
            },
            "application/vnd.multiad.creator.cif": {
              source: "iana",
            },
            "application/vnd.music-niff": {
              source: "iana",
            },
            "application/vnd.musician": {
              source: "iana",
              extensions: ["mus"],
            },
            "application/vnd.muvee.style": {
              source: "iana",
              extensions: ["msty"],
            },
            "application/vnd.mynfc": {
              source: "iana",
              extensions: ["taglet"],
            },
            "application/vnd.ncd.control": {
              source: "iana",
            },
            "application/vnd.ncd.reference": {
              source: "iana",
            },
            "application/vnd.nearst.inv+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.nervana": {
              source: "iana",
            },
            "application/vnd.netfpx": {
              source: "iana",
            },
            "application/vnd.neurolanguage.nlu": {
              source: "iana",
              extensions: ["nlu"],
            },
            "application/vnd.nimn": {
              source: "iana",
            },
            "application/vnd.nintendo.nitro.rom": {
              source: "iana",
            },
            "application/vnd.nintendo.snes.rom": {
              source: "iana",
            },
            "application/vnd.nitf": {
              source: "iana",
              extensions: ["ntf", "nitf"],
            },
            "application/vnd.noblenet-directory": {
              source: "iana",
              extensions: ["nnd"],
            },
            "application/vnd.noblenet-sealer": {
              source: "iana",
              extensions: ["nns"],
            },
            "application/vnd.noblenet-web": {
              source: "iana",
              extensions: ["nnw"],
            },
            "application/vnd.nokia.catalogs": {
              source: "iana",
            },
            "application/vnd.nokia.conml+wbxml": {
              source: "iana",
            },
            "application/vnd.nokia.conml+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.nokia.iptv.config+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.nokia.isds-radio-presets": {
              source: "iana",
            },
            "application/vnd.nokia.landmark+wbxml": {
              source: "iana",
            },
            "application/vnd.nokia.landmark+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.nokia.landmarkcollection+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.nokia.n-gage.ac+xml": {
              source: "iana",
              compressible: true,
              extensions: ["ac"],
            },
            "application/vnd.nokia.n-gage.data": {
              source: "iana",
              extensions: ["ngdat"],
            },
            "application/vnd.nokia.n-gage.symbian.install": {
              source: "iana",
              extensions: ["n-gage"],
            },
            "application/vnd.nokia.ncd": {
              source: "iana",
            },
            "application/vnd.nokia.pcd+wbxml": {
              source: "iana",
            },
            "application/vnd.nokia.pcd+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.nokia.radio-preset": {
              source: "iana",
              extensions: ["rpst"],
            },
            "application/vnd.nokia.radio-presets": {
              source: "iana",
              extensions: ["rpss"],
            },
            "application/vnd.novadigm.edm": {
              source: "iana",
              extensions: ["edm"],
            },
            "application/vnd.novadigm.edx": {
              source: "iana",
              extensions: ["edx"],
            },
            "application/vnd.novadigm.ext": {
              source: "iana",
              extensions: ["ext"],
            },
            "application/vnd.ntt-local.content-share": {
              source: "iana",
            },
            "application/vnd.ntt-local.file-transfer": {
              source: "iana",
            },
            "application/vnd.ntt-local.ogw_remote-access": {
              source: "iana",
            },
            "application/vnd.ntt-local.sip-ta_remote": {
              source: "iana",
            },
            "application/vnd.ntt-local.sip-ta_tcp_stream": {
              source: "iana",
            },
            "application/vnd.oasis.opendocument.chart": {
              source: "iana",
              extensions: ["odc"],
            },
            "application/vnd.oasis.opendocument.chart-template": {
              source: "iana",
              extensions: ["otc"],
            },
            "application/vnd.oasis.opendocument.database": {
              source: "iana",
              extensions: ["odb"],
            },
            "application/vnd.oasis.opendocument.formula": {
              source: "iana",
              extensions: ["odf"],
            },
            "application/vnd.oasis.opendocument.formula-template": {
              source: "iana",
              extensions: ["odft"],
            },
            "application/vnd.oasis.opendocument.graphics": {
              source: "iana",
              compressible: false,
              extensions: ["odg"],
            },
            "application/vnd.oasis.opendocument.graphics-template": {
              source: "iana",
              extensions: ["otg"],
            },
            "application/vnd.oasis.opendocument.image": {
              source: "iana",
              extensions: ["odi"],
            },
            "application/vnd.oasis.opendocument.image-template": {
              source: "iana",
              extensions: ["oti"],
            },
            "application/vnd.oasis.opendocument.presentation": {
              source: "iana",
              compressible: false,
              extensions: ["odp"],
            },
            "application/vnd.oasis.opendocument.presentation-template": {
              source: "iana",
              extensions: ["otp"],
            },
            "application/vnd.oasis.opendocument.spreadsheet": {
              source: "iana",
              compressible: false,
              extensions: ["ods"],
            },
            "application/vnd.oasis.opendocument.spreadsheet-template": {
              source: "iana",
              extensions: ["ots"],
            },
            "application/vnd.oasis.opendocument.text": {
              source: "iana",
              compressible: false,
              extensions: ["odt"],
            },
            "application/vnd.oasis.opendocument.text-master": {
              source: "iana",
              extensions: ["odm"],
            },
            "application/vnd.oasis.opendocument.text-template": {
              source: "iana",
              extensions: ["ott"],
            },
            "application/vnd.oasis.opendocument.text-web": {
              source: "iana",
              extensions: ["oth"],
            },
            "application/vnd.obn": {
              source: "iana",
            },
            "application/vnd.ocf+cbor": {
              source: "iana",
            },
            "application/vnd.oci.image.manifest.v1+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oftn.l10n+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oipf.contentaccessdownload+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oipf.contentaccessstreaming+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oipf.cspg-hexbinary": {
              source: "iana",
            },
            "application/vnd.oipf.dae.svg+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oipf.dae.xhtml+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oipf.mippvcontrolmessage+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oipf.pae.gem": {
              source: "iana",
            },
            "application/vnd.oipf.spdiscovery+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oipf.spdlist+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oipf.ueprofile+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oipf.userprofile+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.olpc-sugar": {
              source: "iana",
              extensions: ["xo"],
            },
            "application/vnd.oma-scws-config": {
              source: "iana",
            },
            "application/vnd.oma-scws-http-request": {
              source: "iana",
            },
            "application/vnd.oma-scws-http-response": {
              source: "iana",
            },
            "application/vnd.oma.bcast.associated-procedure-parameter+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oma.bcast.drm-trigger+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oma.bcast.imd+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oma.bcast.ltkm": {
              source: "iana",
            },
            "application/vnd.oma.bcast.notification+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oma.bcast.provisioningtrigger": {
              source: "iana",
            },
            "application/vnd.oma.bcast.sgboot": {
              source: "iana",
            },
            "application/vnd.oma.bcast.sgdd+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oma.bcast.sgdu": {
              source: "iana",
            },
            "application/vnd.oma.bcast.simple-symbol-container": {
              source: "iana",
            },
            "application/vnd.oma.bcast.smartcard-trigger+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oma.bcast.sprov+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oma.bcast.stkm": {
              source: "iana",
            },
            "application/vnd.oma.cab-address-book+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oma.cab-feature-handler+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oma.cab-pcc+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oma.cab-subs-invite+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oma.cab-user-prefs+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oma.dcd": {
              source: "iana",
            },
            "application/vnd.oma.dcdc": {
              source: "iana",
            },
            "application/vnd.oma.dd2+xml": {
              source: "iana",
              compressible: true,
              extensions: ["dd2"],
            },
            "application/vnd.oma.drm.risd+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oma.group-usage-list+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oma.lwm2m+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oma.lwm2m+tlv": {
              source: "iana",
            },
            "application/vnd.oma.pal+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oma.poc.detailed-progress-report+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oma.poc.final-report+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oma.poc.groups+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oma.poc.invocation-descriptor+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oma.poc.optimized-progress-report+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oma.push": {
              source: "iana",
            },
            "application/vnd.oma.scidm.messages+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oma.xcap-directory+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.omads-email+xml": {
              source: "iana",
              charset: "UTF-8",
              compressible: true,
            },
            "application/vnd.omads-file+xml": {
              source: "iana",
              charset: "UTF-8",
              compressible: true,
            },
            "application/vnd.omads-folder+xml": {
              source: "iana",
              charset: "UTF-8",
              compressible: true,
            },
            "application/vnd.omaloc-supl-init": {
              source: "iana",
            },
            "application/vnd.onepager": {
              source: "iana",
            },
            "application/vnd.onepagertamp": {
              source: "iana",
            },
            "application/vnd.onepagertamx": {
              source: "iana",
            },
            "application/vnd.onepagertat": {
              source: "iana",
            },
            "application/vnd.onepagertatp": {
              source: "iana",
            },
            "application/vnd.onepagertatx": {
              source: "iana",
            },
            "application/vnd.openblox.game+xml": {
              source: "iana",
              compressible: true,
              extensions: ["obgx"],
            },
            "application/vnd.openblox.game-binary": {
              source: "iana",
            },
            "application/vnd.openeye.oeb": {
              source: "iana",
            },
            "application/vnd.openofficeorg.extension": {
              source: "apache",
              extensions: ["oxt"],
            },
            "application/vnd.openstreetmap.data+xml": {
              source: "iana",
              compressible: true,
              extensions: ["osm"],
            },
            "application/vnd.openxmlformats-officedocument.custom-properties+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.customxmlproperties+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.drawing+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.openxmlformats-officedocument.drawingml.chart+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.drawingml.chartshapes+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.drawingml.diagramcolors+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.drawingml.diagramdata+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.drawingml.diagramlayout+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.drawingml.diagramstyle+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.extended-properties+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.presentationml.commentauthors+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.presentationml.comments+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.presentationml.handoutmaster+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.presentationml.notesmaster+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.presentationml.notesslide+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.presentationml.presentation":
              {
                source: "iana",
                compressible: false,
                extensions: ["pptx"],
              },
            "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.presentationml.presprops+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.presentationml.slide":
              {
                source: "iana",
                extensions: ["sldx"],
              },
            "application/vnd.openxmlformats-officedocument.presentationml.slide+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.presentationml.slidelayout+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.presentationml.slidemaster+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.presentationml.slideshow":
              {
                source: "iana",
                extensions: ["ppsx"],
              },
            "application/vnd.openxmlformats-officedocument.presentationml.slideshow.main+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.presentationml.slideupdateinfo+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.presentationml.tablestyles+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.presentationml.tags+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.presentationml.template":
              {
                source: "iana",
                extensions: ["potx"],
              },
            "application/vnd.openxmlformats-officedocument.presentationml.template.main+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.presentationml.viewprops+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.spreadsheetml.calcchain+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.spreadsheetml.chartsheet+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.spreadsheetml.comments+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.spreadsheetml.connections+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.spreadsheetml.dialogsheet+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.spreadsheetml.externallink+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.spreadsheetml.pivotcachedefinition+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.spreadsheetml.pivotcacherecords+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.spreadsheetml.pivottable+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.spreadsheetml.querytable+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.spreadsheetml.revisionheaders+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.spreadsheetml.revisionlog+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sharedstrings+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
              {
                source: "iana",
                compressible: false,
                extensions: ["xlsx"],
              },
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheetmetadata+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.spreadsheetml.table+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.spreadsheetml.tablesinglecells+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.spreadsheetml.template":
              {
                source: "iana",
                extensions: ["xltx"],
              },
            "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.spreadsheetml.usernames+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.spreadsheetml.volatiledependencies+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.theme+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.openxmlformats-officedocument.themeoverride+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.openxmlformats-officedocument.vmldrawing": {
              source: "iana",
            },
            "application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
              {
                source: "iana",
                compressible: false,
                extensions: ["docx"],
              },
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document.glossary+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.wordprocessingml.endnotes+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.wordprocessingml.fonttable+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.wordprocessingml.footnotes+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.wordprocessingml.template":
              {
                source: "iana",
                extensions: ["dotx"],
              },
            "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-officedocument.wordprocessingml.websettings+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-package.core-properties+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml":
              {
                source: "iana",
                compressible: true,
              },
            "application/vnd.openxmlformats-package.relationships+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oracle.resource+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.orange.indata": {
              source: "iana",
            },
            "application/vnd.osa.netdeploy": {
              source: "iana",
            },
            "application/vnd.osgeo.mapguide.package": {
              source: "iana",
              extensions: ["mgp"],
            },
            "application/vnd.osgi.bundle": {
              source: "iana",
            },
            "application/vnd.osgi.dp": {
              source: "iana",
              extensions: ["dp"],
            },
            "application/vnd.osgi.subsystem": {
              source: "iana",
              extensions: ["esa"],
            },
            "application/vnd.otps.ct-kip+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.oxli.countgraph": {
              source: "iana",
            },
            "application/vnd.pagerduty+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.palm": {
              source: "iana",
              extensions: ["pdb", "pqa", "oprc"],
            },
            "application/vnd.panoply": {
              source: "iana",
            },
            "application/vnd.paos.xml": {
              source: "iana",
            },
            "application/vnd.patentdive": {
              source: "iana",
            },
            "application/vnd.patientecommsdoc": {
              source: "iana",
            },
            "application/vnd.pawaafile": {
              source: "iana",
              extensions: ["paw"],
            },
            "application/vnd.pcos": {
              source: "iana",
            },
            "application/vnd.pg.format": {
              source: "iana",
              extensions: ["str"],
            },
            "application/vnd.pg.osasli": {
              source: "iana",
              extensions: ["ei6"],
            },
            "application/vnd.piaccess.application-licence": {
              source: "iana",
            },
            "application/vnd.picsel": {
              source: "iana",
              extensions: ["efif"],
            },
            "application/vnd.pmi.widget": {
              source: "iana",
              extensions: ["wg"],
            },
            "application/vnd.poc.group-advertisement+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.pocketlearn": {
              source: "iana",
              extensions: ["plf"],
            },
            "application/vnd.powerbuilder6": {
              source: "iana",
              extensions: ["pbd"],
            },
            "application/vnd.powerbuilder6-s": {
              source: "iana",
            },
            "application/vnd.powerbuilder7": {
              source: "iana",
            },
            "application/vnd.powerbuilder7-s": {
              source: "iana",
            },
            "application/vnd.powerbuilder75": {
              source: "iana",
            },
            "application/vnd.powerbuilder75-s": {
              source: "iana",
            },
            "application/vnd.preminet": {
              source: "iana",
            },
            "application/vnd.previewsystems.box": {
              source: "iana",
              extensions: ["box"],
            },
            "application/vnd.proteus.magazine": {
              source: "iana",
              extensions: ["mgz"],
            },
            "application/vnd.psfs": {
              source: "iana",
            },
            "application/vnd.publishare-delta-tree": {
              source: "iana",
              extensions: ["qps"],
            },
            "application/vnd.pvi.ptid1": {
              source: "iana",
              extensions: ["ptid"],
            },
            "application/vnd.pwg-multiplexed": {
              source: "iana",
            },
            "application/vnd.pwg-xhtml-print+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.qualcomm.brew-app-res": {
              source: "iana",
            },
            "application/vnd.quarantainenet": {
              source: "iana",
            },
            "application/vnd.quark.quarkxpress": {
              source: "iana",
              extensions: ["qxd", "qxt", "qwd", "qwt", "qxl", "qxb"],
            },
            "application/vnd.quobject-quoxdocument": {
              source: "iana",
            },
            "application/vnd.radisys.moml+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.radisys.msml+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.radisys.msml-audit+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.radisys.msml-audit-conf+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.radisys.msml-audit-conn+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.radisys.msml-audit-dialog+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.radisys.msml-audit-stream+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.radisys.msml-conf+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.radisys.msml-dialog+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.radisys.msml-dialog-base+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.radisys.msml-dialog-fax-detect+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.radisys.msml-dialog-fax-sendrecv+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.radisys.msml-dialog-group+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.radisys.msml-dialog-speech+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.radisys.msml-dialog-transform+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.rainstor.data": {
              source: "iana",
            },
            "application/vnd.rapid": {
              source: "iana",
            },
            "application/vnd.rar": {
              source: "iana",
            },
            "application/vnd.realvnc.bed": {
              source: "iana",
              extensions: ["bed"],
            },
            "application/vnd.recordare.musicxml": {
              source: "iana",
              extensions: ["mxl"],
            },
            "application/vnd.recordare.musicxml+xml": {
              source: "iana",
              compressible: true,
              extensions: ["musicxml"],
            },
            "application/vnd.renlearn.rlprint": {
              source: "iana",
            },
            "application/vnd.restful+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.rig.cryptonote": {
              source: "iana",
              extensions: ["cryptonote"],
            },
            "application/vnd.rim.cod": {
              source: "apache",
              extensions: ["cod"],
            },
            "application/vnd.rn-realmedia": {
              source: "apache",
              extensions: ["rm"],
            },
            "application/vnd.rn-realmedia-vbr": {
              source: "apache",
              extensions: ["rmvb"],
            },
            "application/vnd.route66.link66+xml": {
              source: "iana",
              compressible: true,
              extensions: ["link66"],
            },
            "application/vnd.rs-274x": {
              source: "iana",
            },
            "application/vnd.ruckus.download": {
              source: "iana",
            },
            "application/vnd.s3sms": {
              source: "iana",
            },
            "application/vnd.sailingtracker.track": {
              source: "iana",
              extensions: ["st"],
            },
            "application/vnd.sar": {
              source: "iana",
            },
            "application/vnd.sbm.cid": {
              source: "iana",
            },
            "application/vnd.sbm.mid2": {
              source: "iana",
            },
            "application/vnd.scribus": {
              source: "iana",
            },
            "application/vnd.sealed.3df": {
              source: "iana",
            },
            "application/vnd.sealed.csf": {
              source: "iana",
            },
            "application/vnd.sealed.doc": {
              source: "iana",
            },
            "application/vnd.sealed.eml": {
              source: "iana",
            },
            "application/vnd.sealed.mht": {
              source: "iana",
            },
            "application/vnd.sealed.net": {
              source: "iana",
            },
            "application/vnd.sealed.ppt": {
              source: "iana",
            },
            "application/vnd.sealed.tiff": {
              source: "iana",
            },
            "application/vnd.sealed.xls": {
              source: "iana",
            },
            "application/vnd.sealedmedia.softseal.html": {
              source: "iana",
            },
            "application/vnd.sealedmedia.softseal.pdf": {
              source: "iana",
            },
            "application/vnd.seemail": {
              source: "iana",
              extensions: ["see"],
            },
            "application/vnd.sema": {
              source: "iana",
              extensions: ["sema"],
            },
            "application/vnd.semd": {
              source: "iana",
              extensions: ["semd"],
            },
            "application/vnd.semf": {
              source: "iana",
              extensions: ["semf"],
            },
            "application/vnd.shade-save-file": {
              source: "iana",
            },
            "application/vnd.shana.informed.formdata": {
              source: "iana",
              extensions: ["ifm"],
            },
            "application/vnd.shana.informed.formtemplate": {
              source: "iana",
              extensions: ["itp"],
            },
            "application/vnd.shana.informed.interchange": {
              source: "iana",
              extensions: ["iif"],
            },
            "application/vnd.shana.informed.package": {
              source: "iana",
              extensions: ["ipk"],
            },
            "application/vnd.shootproof+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.shopkick+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.shp": {
              source: "iana",
            },
            "application/vnd.shx": {
              source: "iana",
            },
            "application/vnd.sigrok.session": {
              source: "iana",
            },
            "application/vnd.simtech-mindmapper": {
              source: "iana",
              extensions: ["twd", "twds"],
            },
            "application/vnd.siren+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.smaf": {
              source: "iana",
              extensions: ["mmf"],
            },
            "application/vnd.smart.notebook": {
              source: "iana",
            },
            "application/vnd.smart.teacher": {
              source: "iana",
              extensions: ["teacher"],
            },
            "application/vnd.snesdev-page-table": {
              source: "iana",
            },
            "application/vnd.software602.filler.form+xml": {
              source: "iana",
              compressible: true,
              extensions: ["fo"],
            },
            "application/vnd.software602.filler.form-xml-zip": {
              source: "iana",
            },
            "application/vnd.solent.sdkm+xml": {
              source: "iana",
              compressible: true,
              extensions: ["sdkm", "sdkd"],
            },
            "application/vnd.spotfire.dxp": {
              source: "iana",
              extensions: ["dxp"],
            },
            "application/vnd.spotfire.sfs": {
              source: "iana",
              extensions: ["sfs"],
            },
            "application/vnd.sqlite3": {
              source: "iana",
            },
            "application/vnd.sss-cod": {
              source: "iana",
            },
            "application/vnd.sss-dtf": {
              source: "iana",
            },
            "application/vnd.sss-ntf": {
              source: "iana",
            },
            "application/vnd.stardivision.calc": {
              source: "apache",
              extensions: ["sdc"],
            },
            "application/vnd.stardivision.draw": {
              source: "apache",
              extensions: ["sda"],
            },
            "application/vnd.stardivision.impress": {
              source: "apache",
              extensions: ["sdd"],
            },
            "application/vnd.stardivision.math": {
              source: "apache",
              extensions: ["smf"],
            },
            "application/vnd.stardivision.writer": {
              source: "apache",
              extensions: ["sdw", "vor"],
            },
            "application/vnd.stardivision.writer-global": {
              source: "apache",
              extensions: ["sgl"],
            },
            "application/vnd.stepmania.package": {
              source: "iana",
              extensions: ["smzip"],
            },
            "application/vnd.stepmania.stepchart": {
              source: "iana",
              extensions: ["sm"],
            },
            "application/vnd.street-stream": {
              source: "iana",
            },
            "application/vnd.sun.wadl+xml": {
              source: "iana",
              compressible: true,
              extensions: ["wadl"],
            },
            "application/vnd.sun.xml.calc": {
              source: "apache",
              extensions: ["sxc"],
            },
            "application/vnd.sun.xml.calc.template": {
              source: "apache",
              extensions: ["stc"],
            },
            "application/vnd.sun.xml.draw": {
              source: "apache",
              extensions: ["sxd"],
            },
            "application/vnd.sun.xml.draw.template": {
              source: "apache",
              extensions: ["std"],
            },
            "application/vnd.sun.xml.impress": {
              source: "apache",
              extensions: ["sxi"],
            },
            "application/vnd.sun.xml.impress.template": {
              source: "apache",
              extensions: ["sti"],
            },
            "application/vnd.sun.xml.math": {
              source: "apache",
              extensions: ["sxm"],
            },
            "application/vnd.sun.xml.writer": {
              source: "apache",
              extensions: ["sxw"],
            },
            "application/vnd.sun.xml.writer.global": {
              source: "apache",
              extensions: ["sxg"],
            },
            "application/vnd.sun.xml.writer.template": {
              source: "apache",
              extensions: ["stw"],
            },
            "application/vnd.sus-calendar": {
              source: "iana",
              extensions: ["sus", "susp"],
            },
            "application/vnd.svd": {
              source: "iana",
              extensions: ["svd"],
            },
            "application/vnd.swiftview-ics": {
              source: "iana",
            },
            "application/vnd.symbian.install": {
              source: "apache",
              extensions: ["sis", "sisx"],
            },
            "application/vnd.syncml+xml": {
              source: "iana",
              charset: "UTF-8",
              compressible: true,
              extensions: ["xsm"],
            },
            "application/vnd.syncml.dm+wbxml": {
              source: "iana",
              charset: "UTF-8",
              extensions: ["bdm"],
            },
            "application/vnd.syncml.dm+xml": {
              source: "iana",
              charset: "UTF-8",
              compressible: true,
              extensions: ["xdm"],
            },
            "application/vnd.syncml.dm.notification": {
              source: "iana",
            },
            "application/vnd.syncml.dmddf+wbxml": {
              source: "iana",
            },
            "application/vnd.syncml.dmddf+xml": {
              source: "iana",
              charset: "UTF-8",
              compressible: true,
              extensions: ["ddf"],
            },
            "application/vnd.syncml.dmtnds+wbxml": {
              source: "iana",
            },
            "application/vnd.syncml.dmtnds+xml": {
              source: "iana",
              charset: "UTF-8",
              compressible: true,
            },
            "application/vnd.syncml.ds.notification": {
              source: "iana",
            },
            "application/vnd.tableschema+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.tao.intent-module-archive": {
              source: "iana",
              extensions: ["tao"],
            },
            "application/vnd.tcpdump.pcap": {
              source: "iana",
              extensions: ["pcap", "cap", "dmp"],
            },
            "application/vnd.think-cell.ppttc+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.tmd.mediaflex.api+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.tml": {
              source: "iana",
            },
            "application/vnd.tmobile-livetv": {
              source: "iana",
              extensions: ["tmo"],
            },
            "application/vnd.tri.onesource": {
              source: "iana",
            },
            "application/vnd.trid.tpt": {
              source: "iana",
              extensions: ["tpt"],
            },
            "application/vnd.triscape.mxs": {
              source: "iana",
              extensions: ["mxs"],
            },
            "application/vnd.trueapp": {
              source: "iana",
              extensions: ["tra"],
            },
            "application/vnd.truedoc": {
              source: "iana",
            },
            "application/vnd.ubisoft.webplayer": {
              source: "iana",
            },
            "application/vnd.ufdl": {
              source: "iana",
              extensions: ["ufd", "ufdl"],
            },
            "application/vnd.uiq.theme": {
              source: "iana",
              extensions: ["utz"],
            },
            "application/vnd.umajin": {
              source: "iana",
              extensions: ["umj"],
            },
            "application/vnd.unity": {
              source: "iana",
              extensions: ["unityweb"],
            },
            "application/vnd.uoml+xml": {
              source: "iana",
              compressible: true,
              extensions: ["uoml"],
            },
            "application/vnd.uplanet.alert": {
              source: "iana",
            },
            "application/vnd.uplanet.alert-wbxml": {
              source: "iana",
            },
            "application/vnd.uplanet.bearer-choice": {
              source: "iana",
            },
            "application/vnd.uplanet.bearer-choice-wbxml": {
              source: "iana",
            },
            "application/vnd.uplanet.cacheop": {
              source: "iana",
            },
            "application/vnd.uplanet.cacheop-wbxml": {
              source: "iana",
            },
            "application/vnd.uplanet.channel": {
              source: "iana",
            },
            "application/vnd.uplanet.channel-wbxml": {
              source: "iana",
            },
            "application/vnd.uplanet.list": {
              source: "iana",
            },
            "application/vnd.uplanet.list-wbxml": {
              source: "iana",
            },
            "application/vnd.uplanet.listcmd": {
              source: "iana",
            },
            "application/vnd.uplanet.listcmd-wbxml": {
              source: "iana",
            },
            "application/vnd.uplanet.signal": {
              source: "iana",
            },
            "application/vnd.uri-map": {
              source: "iana",
            },
            "application/vnd.valve.source.material": {
              source: "iana",
            },
            "application/vnd.vcx": {
              source: "iana",
              extensions: ["vcx"],
            },
            "application/vnd.vd-study": {
              source: "iana",
            },
            "application/vnd.vectorworks": {
              source: "iana",
            },
            "application/vnd.vel+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.verimatrix.vcas": {
              source: "iana",
            },
            "application/vnd.veryant.thin": {
              source: "iana",
            },
            "application/vnd.ves.encrypted": {
              source: "iana",
            },
            "application/vnd.vidsoft.vidconference": {
              source: "iana",
            },
            "application/vnd.visio": {
              source: "iana",
              extensions: ["vsd", "vst", "vss", "vsw"],
            },
            "application/vnd.visionary": {
              source: "iana",
              extensions: ["vis"],
            },
            "application/vnd.vividence.scriptfile": {
              source: "iana",
            },
            "application/vnd.vsf": {
              source: "iana",
              extensions: ["vsf"],
            },
            "application/vnd.wap.sic": {
              source: "iana",
            },
            "application/vnd.wap.slc": {
              source: "iana",
            },
            "application/vnd.wap.wbxml": {
              source: "iana",
              charset: "UTF-8",
              extensions: ["wbxml"],
            },
            "application/vnd.wap.wmlc": {
              source: "iana",
              extensions: ["wmlc"],
            },
            "application/vnd.wap.wmlscriptc": {
              source: "iana",
              extensions: ["wmlsc"],
            },
            "application/vnd.webturbo": {
              source: "iana",
              extensions: ["wtb"],
            },
            "application/vnd.wfa.p2p": {
              source: "iana",
            },
            "application/vnd.wfa.wsc": {
              source: "iana",
            },
            "application/vnd.windows.devicepairing": {
              source: "iana",
            },
            "application/vnd.wmc": {
              source: "iana",
            },
            "application/vnd.wmf.bootstrap": {
              source: "iana",
            },
            "application/vnd.wolfram.mathematica": {
              source: "iana",
            },
            "application/vnd.wolfram.mathematica.package": {
              source: "iana",
            },
            "application/vnd.wolfram.player": {
              source: "iana",
              extensions: ["nbp"],
            },
            "application/vnd.wordperfect": {
              source: "iana",
              extensions: ["wpd"],
            },
            "application/vnd.wqd": {
              source: "iana",
              extensions: ["wqd"],
            },
            "application/vnd.wrq-hp3000-labelled": {
              source: "iana",
            },
            "application/vnd.wt.stf": {
              source: "iana",
              extensions: ["stf"],
            },
            "application/vnd.wv.csp+wbxml": {
              source: "iana",
            },
            "application/vnd.wv.csp+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.wv.ssp+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.xacml+json": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.xara": {
              source: "iana",
              extensions: ["xar"],
            },
            "application/vnd.xfdl": {
              source: "iana",
              extensions: ["xfdl"],
            },
            "application/vnd.xfdl.webform": {
              source: "iana",
            },
            "application/vnd.xmi+xml": {
              source: "iana",
              compressible: true,
            },
            "application/vnd.xmpie.cpkg": {
              source: "iana",
            },
            "application/vnd.xmpie.dpkg": {
              source: "iana",
            },
            "application/vnd.xmpie.plan": {
              source: "iana",
            },
            "application/vnd.xmpie.ppkg": {
              source: "iana",
            },
            "application/vnd.xmpie.xlim": {
              source: "iana",
            },
            "application/vnd.yamaha.hv-dic": {
              source: "iana",
              extensions: ["hvd"],
            },
            "application/vnd.yamaha.hv-script": {
              source: "iana",
              extensions: ["hvs"],
            },
            "application/vnd.yamaha.hv-voice": {
              source: "iana",
              extensions: ["hvp"],
            },
            "application/vnd.yamaha.openscoreformat": {
              source: "iana",
              extensions: ["osf"],
            },
            "application/vnd.yamaha.openscoreformat.osfpvg+xml": {
              source: "iana",
              compressible: true,
              extensions: ["osfpvg"],
            },
            "application/vnd.yamaha.remote-setup": {
              source: "iana",
            },
            "application/vnd.yamaha.smaf-audio": {
              source: "iana",
              extensions: ["saf"],
            },
            "application/vnd.yamaha.smaf-phrase": {
              source: "iana",
              extensions: ["spf"],
            },
            "application/vnd.yamaha.through-ngn": {
              source: "iana",
            },
            "application/vnd.yamaha.tunnel-udpencap": {
              source: "iana",
            },
            "application/vnd.yaoweme": {
              source: "iana",
            },
            "application/vnd.yellowriver-custom-menu": {
              source: "iana",
              extensions: ["cmp"],
            },
            "application/vnd.youtube.yt": {
              source: "iana",
            },
            "application/vnd.zul": {
              source: "iana",
              extensions: ["zir", "zirz"],
            },
            "application/vnd.zzazz.deck+xml": {
              source: "iana",
              compressible: true,
              extensions: ["zaz"],
            },
            "application/voicexml+xml": {
              source: "iana",
              compressible: true,
              extensions: ["vxml"],
            },
            "application/voucher-cms+json": {
              source: "iana",
              compressible: true,
            },
            "application/vq-rtcpxr": {
              source: "iana",
            },
            "application/wasm": {
              compressible: true,
              extensions: ["wasm"],
            },
            "application/watcherinfo+xml": {
              source: "iana",
              compressible: true,
            },
            "application/webpush-options+json": {
              source: "iana",
              compressible: true,
            },
            "application/whoispp-query": {
              source: "iana",
            },
            "application/whoispp-response": {
              source: "iana",
            },
            "application/widget": {
              source: "iana",
              extensions: ["wgt"],
            },
            "application/winhlp": {
              source: "apache",
              extensions: ["hlp"],
            },
            "application/wita": {
              source: "iana",
            },
            "application/wordperfect5.1": {
              source: "iana",
            },
            "application/wsdl+xml": {
              source: "iana",
              compressible: true,
              extensions: ["wsdl"],
            },
            "application/wspolicy+xml": {
              source: "iana",
              compressible: true,
              extensions: ["wspolicy"],
            },
            "application/x-7z-compressed": {
              source: "apache",
              compressible: false,
              extensions: ["7z"],
            },
            "application/x-abiword": {
              source: "apache",
              extensions: ["abw"],
            },
            "application/x-ace-compressed": {
              source: "apache",
              extensions: ["ace"],
            },
            "application/x-amf": {
              source: "apache",
            },
            "application/x-apple-diskimage": {
              source: "apache",
              extensions: ["dmg"],
            },
            "application/x-arj": {
              compressible: false,
              extensions: ["arj"],
            },
            "application/x-authorware-bin": {
              source: "apache",
              extensions: ["aab", "x32", "u32", "vox"],
            },
            "application/x-authorware-map": {
              source: "apache",
              extensions: ["aam"],
            },
            "application/x-authorware-seg": {
              source: "apache",
              extensions: ["aas"],
            },
            "application/x-bcpio": {
              source: "apache",
              extensions: ["bcpio"],
            },
            "application/x-bdoc": {
              compressible: false,
              extensions: ["bdoc"],
            },
            "application/x-bittorrent": {
              source: "apache",
              extensions: ["torrent"],
            },
            "application/x-blorb": {
              source: "apache",
              extensions: ["blb", "blorb"],
            },
            "application/x-bzip": {
              source: "apache",
              compressible: false,
              extensions: ["bz"],
            },
            "application/x-bzip2": {
              source: "apache",
              compressible: false,
              extensions: ["bz2", "boz"],
            },
            "application/x-cbr": {
              source: "apache",
              extensions: ["cbr", "cba", "cbt", "cbz", "cb7"],
            },
            "application/x-cdlink": {
              source: "apache",
              extensions: ["vcd"],
            },
            "application/x-cfs-compressed": {
              source: "apache",
              extensions: ["cfs"],
            },
            "application/x-chat": {
              source: "apache",
              extensions: ["chat"],
            },
            "application/x-chess-pgn": {
              source: "apache",
              extensions: ["pgn"],
            },
            "application/x-chrome-extension": {
              extensions: ["crx"],
            },
            "application/x-cocoa": {
              source: "nginx",
              extensions: ["cco"],
            },
            "application/x-compress": {
              source: "apache",
            },
            "application/x-conference": {
              source: "apache",
              extensions: ["nsc"],
            },
            "application/x-cpio": {
              source: "apache",
              extensions: ["cpio"],
            },
            "application/x-csh": {
              source: "apache",
              extensions: ["csh"],
            },
            "application/x-deb": {
              compressible: false,
            },
            "application/x-debian-package": {
              source: "apache",
              extensions: ["deb", "udeb"],
            },
            "application/x-dgc-compressed": {
              source: "apache",
              extensions: ["dgc"],
            },
            "application/x-director": {
              source: "apache",
              extensions: [
                "dir",
                "dcr",
                "dxr",
                "cst",
                "cct",
                "cxt",
                "w3d",
                "fgd",
                "swa",
              ],
            },
            "application/x-doom": {
              source: "apache",
              extensions: ["wad"],
            },
            "application/x-dtbncx+xml": {
              source: "apache",
              compressible: true,
              extensions: ["ncx"],
            },
            "application/x-dtbook+xml": {
              source: "apache",
              compressible: true,
              extensions: ["dtb"],
            },
            "application/x-dtbresource+xml": {
              source: "apache",
              compressible: true,
              extensions: ["res"],
            },
            "application/x-dvi": {
              source: "apache",
              compressible: false,
              extensions: ["dvi"],
            },
            "application/x-envoy": {
              source: "apache",
              extensions: ["evy"],
            },
            "application/x-eva": {
              source: "apache",
              extensions: ["eva"],
            },
            "application/x-font-bdf": {
              source: "apache",
              extensions: ["bdf"],
            },
            "application/x-font-dos": {
              source: "apache",
            },
            "application/x-font-framemaker": {
              source: "apache",
            },
            "application/x-font-ghostscript": {
              source: "apache",
              extensions: ["gsf"],
            },
            "application/x-font-libgrx": {
              source: "apache",
            },
            "application/x-font-linux-psf": {
              source: "apache",
              extensions: ["psf"],
            },
            "application/x-font-pcf": {
              source: "apache",
              extensions: ["pcf"],
            },
            "application/x-font-snf": {
              source: "apache",
              extensions: ["snf"],
            },
            "application/x-font-speedo": {
              source: "apache",
            },
            "application/x-font-sunos-news": {
              source: "apache",
            },
            "application/x-font-type1": {
              source: "apache",
              extensions: ["pfa", "pfb", "pfm", "afm"],
            },
            "application/x-font-vfont": {
              source: "apache",
            },
            "application/x-freearc": {
              source: "apache",
              extensions: ["arc"],
            },
            "application/x-futuresplash": {
              source: "apache",
              extensions: ["spl"],
            },
            "application/x-gca-compressed": {
              source: "apache",
              extensions: ["gca"],
            },
            "application/x-glulx": {
              source: "apache",
              extensions: ["ulx"],
            },
            "application/x-gnumeric": {
              source: "apache",
              extensions: ["gnumeric"],
            },
            "application/x-gramps-xml": {
              source: "apache",
              extensions: ["gramps"],
            },
            "application/x-gtar": {
              source: "apache",
              extensions: ["gtar"],
            },
            "application/x-gzip": {
              source: "apache",
            },
            "application/x-hdf": {
              source: "apache",
              extensions: ["hdf"],
            },
            "application/x-httpd-php": {
              compressible: true,
              extensions: ["php"],
            },
            "application/x-install-instructions": {
              source: "apache",
              extensions: ["install"],
            },
            "application/x-iso9660-image": {
              source: "apache",
              extensions: ["iso"],
            },
            "application/x-java-archive-diff": {
              source: "nginx",
              extensions: ["jardiff"],
            },
            "application/x-java-jnlp-file": {
              source: "apache",
              compressible: false,
              extensions: ["jnlp"],
            },
            "application/x-javascript": {
              compressible: true,
            },
            "application/x-keepass2": {
              extensions: ["kdbx"],
            },
            "application/x-latex": {
              source: "apache",
              compressible: false,
              extensions: ["latex"],
            },
            "application/x-lua-bytecode": {
              extensions: ["luac"],
            },
            "application/x-lzh-compressed": {
              source: "apache",
              extensions: ["lzh", "lha"],
            },
            "application/x-makeself": {
              source: "nginx",
              extensions: ["run"],
            },
            "application/x-mie": {
              source: "apache",
              extensions: ["mie"],
            },
            "application/x-mobipocket-ebook": {
              source: "apache",
              extensions: ["prc", "mobi"],
            },
            "application/x-mpegurl": {
              compressible: false,
            },
            "application/x-ms-application": {
              source: "apache",
              extensions: ["application"],
            },
            "application/x-ms-shortcut": {
              source: "apache",
              extensions: ["lnk"],
            },
            "application/x-ms-wmd": {
              source: "apache",
              extensions: ["wmd"],
            },
            "application/x-ms-wmz": {
              source: "apache",
              extensions: ["wmz"],
            },
            "application/x-ms-xbap": {
              source: "apache",
              extensions: ["xbap"],
            },
            "application/x-msaccess": {
              source: "apache",
              extensions: ["mdb"],
            },
            "application/x-msbinder": {
              source: "apache",
              extensions: ["obd"],
            },
            "application/x-mscardfile": {
              source: "apache",
              extensions: ["crd"],
            },
            "application/x-msclip": {
              source: "apache",
              extensions: ["clp"],
            },
            "application/x-msdos-program": {
              extensions: ["exe"],
            },
            "application/x-msdownload": {
              source: "apache",
              extensions: ["exe", "dll", "com", "bat", "msi"],
            },
            "application/x-msmediaview": {
              source: "apache",
              extensions: ["mvb", "m13", "m14"],
            },
            "application/x-msmetafile": {
              source: "apache",
              extensions: ["wmf", "wmz", "emf", "emz"],
            },
            "application/x-msmoney": {
              source: "apache",
              extensions: ["mny"],
            },
            "application/x-mspublisher": {
              source: "apache",
              extensions: ["pub"],
            },
            "application/x-msschedule": {
              source: "apache",
              extensions: ["scd"],
            },
            "application/x-msterminal": {
              source: "apache",
              extensions: ["trm"],
            },
            "application/x-mswrite": {
              source: "apache",
              extensions: ["wri"],
            },
            "application/x-netcdf": {
              source: "apache",
              extensions: ["nc", "cdf"],
            },
            "application/x-ns-proxy-autoconfig": {
              compressible: true,
              extensions: ["pac"],
            },
            "application/x-nzb": {
              source: "apache",
              extensions: ["nzb"],
            },
            "application/x-perl": {
              source: "nginx",
              extensions: ["pl", "pm"],
            },
            "application/x-pilot": {
              source: "nginx",
              extensions: ["prc", "pdb"],
            },
            "application/x-pkcs12": {
              source: "apache",
              compressible: false,
              extensions: ["p12", "pfx"],
            },
            "application/x-pkcs7-certificates": {
              source: "apache",
              extensions: ["p7b", "spc"],
            },
            "application/x-pkcs7-certreqresp": {
              source: "apache",
              extensions: ["p7r"],
            },
            "application/x-pki-message": {
              source: "iana",
            },
            "application/x-rar-compressed": {
              source: "apache",
              compressible: false,
              extensions: ["rar"],
            },
            "application/x-redhat-package-manager": {
              source: "nginx",
              extensions: ["rpm"],
            },
            "application/x-research-info-systems": {
              source: "apache",
              extensions: ["ris"],
            },
            "application/x-sea": {
              source: "nginx",
              extensions: ["sea"],
            },
            "application/x-sh": {
              source: "apache",
              compressible: true,
              extensions: ["sh"],
            },
            "application/x-shar": {
              source: "apache",
              extensions: ["shar"],
            },
            "application/x-shockwave-flash": {
              source: "apache",
              compressible: false,
              extensions: ["swf"],
            },
            "application/x-silverlight-app": {
              source: "apache",
              extensions: ["xap"],
            },
            "application/x-sql": {
              source: "apache",
              extensions: ["sql"],
            },
            "application/x-stuffit": {
              source: "apache",
              compressible: false,
              extensions: ["sit"],
            },
            "application/x-stuffitx": {
              source: "apache",
              extensions: ["sitx"],
            },
            "application/x-subrip": {
              source: "apache",
              extensions: ["srt"],
            },
            "application/x-sv4cpio": {
              source: "apache",
              extensions: ["sv4cpio"],
            },
            "application/x-sv4crc": {
              source: "apache",
              extensions: ["sv4crc"],
            },
            "application/x-t3vm-image": {
              source: "apache",
              extensions: ["t3"],
            },
            "application/x-tads": {
              source: "apache",
              extensions: ["gam"],
            },
            "application/x-tar": {
              source: "apache",
              compressible: true,
              extensions: ["tar"],
            },
            "application/x-tcl": {
              source: "apache",
              extensions: ["tcl", "tk"],
            },
            "application/x-tex": {
              source: "apache",
              extensions: ["tex"],
            },
            "application/x-tex-tfm": {
              source: "apache",
              extensions: ["tfm"],
            },
            "application/x-texinfo": {
              source: "apache",
              extensions: ["texinfo", "texi"],
            },
            "application/x-tgif": {
              source: "apache",
              extensions: ["obj"],
            },
            "application/x-ustar": {
              source: "apache",
              extensions: ["ustar"],
            },
            "application/x-virtualbox-hdd": {
              compressible: true,
              extensions: ["hdd"],
            },
            "application/x-virtualbox-ova": {
              compressible: true,
              extensions: ["ova"],
            },
            "application/x-virtualbox-ovf": {
              compressible: true,
              extensions: ["ovf"],
            },
            "application/x-virtualbox-vbox": {
              compressible: true,
              extensions: ["vbox"],
            },
            "application/x-virtualbox-vbox-extpack": {
              compressible: false,
              extensions: ["vbox-extpack"],
            },
            "application/x-virtualbox-vdi": {
              compressible: true,
              extensions: ["vdi"],
            },
            "application/x-virtualbox-vhd": {
              compressible: true,
              extensions: ["vhd"],
            },
            "application/x-virtualbox-vmdk": {
              compressible: true,
              extensions: ["vmdk"],
            },
            "application/x-wais-source": {
              source: "apache",
              extensions: ["src"],
            },
            "application/x-web-app-manifest+json": {
              compressible: true,
              extensions: ["webapp"],
            },
            "application/x-www-form-urlencoded": {
              source: "iana",
              compressible: true,
            },
            "application/x-x509-ca-cert": {
              source: "iana",
              extensions: ["der", "crt", "pem"],
            },
            "application/x-x509-ca-ra-cert": {
              source: "iana",
            },
            "application/x-x509-next-ca-cert": {
              source: "iana",
            },
            "application/x-xfig": {
              source: "apache",
              extensions: ["fig"],
            },
            "application/x-xliff+xml": {
              source: "apache",
              compressible: true,
              extensions: ["xlf"],
            },
            "application/x-xpinstall": {
              source: "apache",
              compressible: false,
              extensions: ["xpi"],
            },
            "application/x-xz": {
              source: "apache",
              extensions: ["xz"],
            },
            "application/x-zmachine": {
              source: "apache",
              extensions: ["z1", "z2", "z3", "z4", "z5", "z6", "z7", "z8"],
            },
            "application/x400-bp": {
              source: "iana",
            },
            "application/xacml+xml": {
              source: "iana",
              compressible: true,
            },
            "application/xaml+xml": {
              source: "apache",
              compressible: true,
              extensions: ["xaml"],
            },
            "application/xcap-att+xml": {
              source: "iana",
              compressible: true,
              extensions: ["xav"],
            },
            "application/xcap-caps+xml": {
              source: "iana",
              compressible: true,
              extensions: ["xca"],
            },
            "application/xcap-diff+xml": {
              source: "iana",
              compressible: true,
              extensions: ["xdf"],
            },
            "application/xcap-el+xml": {
              source: "iana",
              compressible: true,
              extensions: ["xel"],
            },
            "application/xcap-error+xml": {
              source: "iana",
              compressible: true,
              extensions: ["xer"],
            },
            "application/xcap-ns+xml": {
              source: "iana",
              compressible: true,
              extensions: ["xns"],
            },
            "application/xcon-conference-info+xml": {
              source: "iana",
              compressible: true,
            },
            "application/xcon-conference-info-diff+xml": {
              source: "iana",
              compressible: true,
            },
            "application/xenc+xml": {
              source: "iana",
              compressible: true,
              extensions: ["xenc"],
            },
            "application/xhtml+xml": {
              source: "iana",
              compressible: true,
              extensions: ["xhtml", "xht"],
            },
            "application/xhtml-voice+xml": {
              source: "apache",
              compressible: true,
            },
            "application/xliff+xml": {
              source: "iana",
              compressible: true,
              extensions: ["xlf"],
            },
            "application/xml": {
              source: "iana",
              compressible: true,
              extensions: ["xml", "xsl", "xsd", "rng"],
            },
            "application/xml-dtd": {
              source: "iana",
              compressible: true,
              extensions: ["dtd"],
            },
            "application/xml-external-parsed-entity": {
              source: "iana",
            },
            "application/xml-patch+xml": {
              source: "iana",
              compressible: true,
            },
            "application/xmpp+xml": {
              source: "iana",
              compressible: true,
            },
            "application/xop+xml": {
              source: "iana",
              compressible: true,
              extensions: ["xop"],
            },
            "application/xproc+xml": {
              source: "apache",
              compressible: true,
              extensions: ["xpl"],
            },
            "application/xslt+xml": {
              source: "iana",
              compressible: true,
              extensions: ["xslt"],
            },
            "application/xspf+xml": {
              source: "apache",
              compressible: true,
              extensions: ["xspf"],
            },
            "application/xv+xml": {
              source: "iana",
              compressible: true,
              extensions: ["mxml", "xhvml", "xvml", "xvm"],
            },
            "application/yang": {
              source: "iana",
              extensions: ["yang"],
            },
            "application/yang-data+json": {
              source: "iana",
              compressible: true,
            },
            "application/yang-data+xml": {
              source: "iana",
              compressible: true,
            },
            "application/yang-patch+json": {
              source: "iana",
              compressible: true,
            },
            "application/yang-patch+xml": {
              source: "iana",
              compressible: true,
            },
            "application/yin+xml": {
              source: "iana",
              compressible: true,
              extensions: ["yin"],
            },
            "application/zip": {
              source: "iana",
              compressible: false,
              extensions: ["zip"],
            },
            "application/zlib": {
              source: "iana",
            },
            "application/zstd": {
              source: "iana",
            },
            "audio/1d-interleaved-parityfec": {
              source: "iana",
            },
            "audio/32kadpcm": {
              source: "iana",
            },
            "audio/3gpp": {
              source: "iana",
              compressible: false,
              extensions: ["3gpp"],
            },
            "audio/3gpp2": {
              source: "iana",
            },
            "audio/aac": {
              source: "iana",
            },
            "audio/ac3": {
              source: "iana",
            },
            "audio/adpcm": {
              source: "apache",
              extensions: ["adp"],
            },
            "audio/amr": {
              source: "iana",
            },
            "audio/amr-wb": {
              source: "iana",
            },
            "audio/amr-wb+": {
              source: "iana",
            },
            "audio/aptx": {
              source: "iana",
            },
            "audio/asc": {
              source: "iana",
            },
            "audio/atrac-advanced-lossless": {
              source: "iana",
            },
            "audio/atrac-x": {
              source: "iana",
            },
            "audio/atrac3": {
              source: "iana",
            },
            "audio/basic": {
              source: "iana",
              compressible: false,
              extensions: ["au", "snd"],
            },
            "audio/bv16": {
              source: "iana",
            },
            "audio/bv32": {
              source: "iana",
            },
            "audio/clearmode": {
              source: "iana",
            },
            "audio/cn": {
              source: "iana",
            },
            "audio/dat12": {
              source: "iana",
            },
            "audio/dls": {
              source: "iana",
            },
            "audio/dsr-es201108": {
              source: "iana",
            },
            "audio/dsr-es202050": {
              source: "iana",
            },
            "audio/dsr-es202211": {
              source: "iana",
            },
            "audio/dsr-es202212": {
              source: "iana",
            },
            "audio/dv": {
              source: "iana",
            },
            "audio/dvi4": {
              source: "iana",
            },
            "audio/eac3": {
              source: "iana",
            },
            "audio/encaprtp": {
              source: "iana",
            },
            "audio/evrc": {
              source: "iana",
            },
            "audio/evrc-qcp": {
              source: "iana",
            },
            "audio/evrc0": {
              source: "iana",
            },
            "audio/evrc1": {
              source: "iana",
            },
            "audio/evrcb": {
              source: "iana",
            },
            "audio/evrcb0": {
              source: "iana",
            },
            "audio/evrcb1": {
              source: "iana",
            },
            "audio/evrcnw": {
              source: "iana",
            },
            "audio/evrcnw0": {
              source: "iana",
            },
            "audio/evrcnw1": {
              source: "iana",
            },
            "audio/evrcwb": {
              source: "iana",
            },
            "audio/evrcwb0": {
              source: "iana",
            },
            "audio/evrcwb1": {
              source: "iana",
            },
            "audio/evs": {
              source: "iana",
            },
            "audio/flexfec": {
              source: "iana",
            },
            "audio/fwdred": {
              source: "iana",
            },
            "audio/g711-0": {
              source: "iana",
            },
            "audio/g719": {
              source: "iana",
            },
            "audio/g722": {
              source: "iana",
            },
            "audio/g7221": {
              source: "iana",
            },
            "audio/g723": {
              source: "iana",
            },
            "audio/g726-16": {
              source: "iana",
            },
            "audio/g726-24": {
              source: "iana",
            },
            "audio/g726-32": {
              source: "iana",
            },
            "audio/g726-40": {
              source: "iana",
            },
            "audio/g728": {
              source: "iana",
            },
            "audio/g729": {
              source: "iana",
            },
            "audio/g7291": {
              source: "iana",
            },
            "audio/g729d": {
              source: "iana",
            },
            "audio/g729e": {
              source: "iana",
            },
            "audio/gsm": {
              source: "iana",
            },
            "audio/gsm-efr": {
              source: "iana",
            },
            "audio/gsm-hr-08": {
              source: "iana",
            },
            "audio/ilbc": {
              source: "iana",
            },
            "audio/ip-mr_v2.5": {
              source: "iana",
            },
            "audio/isac": {
              source: "apache",
            },
            "audio/l16": {
              source: "iana",
            },
            "audio/l20": {
              source: "iana",
            },
            "audio/l24": {
              source: "iana",
              compressible: false,
            },
            "audio/l8": {
              source: "iana",
            },
            "audio/lpc": {
              source: "iana",
            },
            "audio/melp": {
              source: "iana",
            },
            "audio/melp1200": {
              source: "iana",
            },
            "audio/melp2400": {
              source: "iana",
            },
            "audio/melp600": {
              source: "iana",
            },
            "audio/mhas": {
              source: "iana",
            },
            "audio/midi": {
              source: "apache",
              extensions: ["mid", "midi", "kar", "rmi"],
            },
            "audio/mobile-xmf": {
              source: "iana",
              extensions: ["mxmf"],
            },
            "audio/mp3": {
              compressible: false,
              extensions: ["mp3"],
            },
            "audio/mp4": {
              source: "iana",
              compressible: false,
              extensions: ["m4a", "mp4a"],
            },
            "audio/mp4a-latm": {
              source: "iana",
            },
            "audio/mpa": {
              source: "iana",
            },
            "audio/mpa-robust": {
              source: "iana",
            },
            "audio/mpeg": {
              source: "iana",
              compressible: false,
              extensions: ["mpga", "mp2", "mp2a", "mp3", "m2a", "m3a"],
            },
            "audio/mpeg4-generic": {
              source: "iana",
            },
            "audio/musepack": {
              source: "apache",
            },
            "audio/ogg": {
              source: "iana",
              compressible: false,
              extensions: ["oga", "ogg", "spx"],
            },
            "audio/opus": {
              source: "iana",
            },
            "audio/parityfec": {
              source: "iana",
            },
            "audio/pcma": {
              source: "iana",
            },
            "audio/pcma-wb": {
              source: "iana",
            },
            "audio/pcmu": {
              source: "iana",
            },
            "audio/pcmu-wb": {
              source: "iana",
            },
            "audio/prs.sid": {
              source: "iana",
            },
            "audio/qcelp": {
              source: "iana",
            },
            "audio/raptorfec": {
              source: "iana",
            },
            "audio/red": {
              source: "iana",
            },
            "audio/rtp-enc-aescm128": {
              source: "iana",
            },
            "audio/rtp-midi": {
              source: "iana",
            },
            "audio/rtploopback": {
              source: "iana",
            },
            "audio/rtx": {
              source: "iana",
            },
            "audio/s3m": {
              source: "apache",
              extensions: ["s3m"],
            },
            "audio/silk": {
              source: "apache",
              extensions: ["sil"],
            },
            "audio/smv": {
              source: "iana",
            },
            "audio/smv-qcp": {
              source: "iana",
            },
            "audio/smv0": {
              source: "iana",
            },
            "audio/sp-midi": {
              source: "iana",
            },
            "audio/speex": {
              source: "iana",
            },
            "audio/t140c": {
              source: "iana",
            },
            "audio/t38": {
              source: "iana",
            },
            "audio/telephone-event": {
              source: "iana",
            },
            "audio/tetra_acelp": {
              source: "iana",
            },
            "audio/tetra_acelp_bb": {
              source: "iana",
            },
            "audio/tone": {
              source: "iana",
            },
            "audio/uemclip": {
              source: "iana",
            },
            "audio/ulpfec": {
              source: "iana",
            },
            "audio/usac": {
              source: "iana",
            },
            "audio/vdvi": {
              source: "iana",
            },
            "audio/vmr-wb": {
              source: "iana",
            },
            "audio/vnd.3gpp.iufp": {
              source: "iana",
            },
            "audio/vnd.4sb": {
              source: "iana",
            },
            "audio/vnd.audiokoz": {
              source: "iana",
            },
            "audio/vnd.celp": {
              source: "iana",
            },
            "audio/vnd.cisco.nse": {
              source: "iana",
            },
            "audio/vnd.cmles.radio-events": {
              source: "iana",
            },
            "audio/vnd.cns.anp1": {
              source: "iana",
            },
            "audio/vnd.cns.inf1": {
              source: "iana",
            },
            "audio/vnd.dece.audio": {
              source: "iana",
              extensions: ["uva", "uvva"],
            },
            "audio/vnd.digital-winds": {
              source: "iana",
              extensions: ["eol"],
            },
            "audio/vnd.dlna.adts": {
              source: "iana",
            },
            "audio/vnd.dolby.heaac.1": {
              source: "iana",
            },
            "audio/vnd.dolby.heaac.2": {
              source: "iana",
            },
            "audio/vnd.dolby.mlp": {
              source: "iana",
            },
            "audio/vnd.dolby.mps": {
              source: "iana",
            },
            "audio/vnd.dolby.pl2": {
              source: "iana",
            },
            "audio/vnd.dolby.pl2x": {
              source: "iana",
            },
            "audio/vnd.dolby.pl2z": {
              source: "iana",
            },
            "audio/vnd.dolby.pulse.1": {
              source: "iana",
            },
            "audio/vnd.dra": {
              source: "iana",
              extensions: ["dra"],
            },
            "audio/vnd.dts": {
              source: "iana",
              extensions: ["dts"],
            },
            "audio/vnd.dts.hd": {
              source: "iana",
              extensions: ["dtshd"],
            },
            "audio/vnd.dts.uhd": {
              source: "iana",
            },
            "audio/vnd.dvb.file": {
              source: "iana",
            },
            "audio/vnd.everad.plj": {
              source: "iana",
            },
            "audio/vnd.hns.audio": {
              source: "iana",
            },
            "audio/vnd.lucent.voice": {
              source: "iana",
              extensions: ["lvp"],
            },
            "audio/vnd.ms-playready.media.pya": {
              source: "iana",
              extensions: ["pya"],
            },
            "audio/vnd.nokia.mobile-xmf": {
              source: "iana",
            },
            "audio/vnd.nortel.vbk": {
              source: "iana",
            },
            "audio/vnd.nuera.ecelp4800": {
              source: "iana",
              extensions: ["ecelp4800"],
            },
            "audio/vnd.nuera.ecelp7470": {
              source: "iana",
              extensions: ["ecelp7470"],
            },
            "audio/vnd.nuera.ecelp9600": {
              source: "iana",
              extensions: ["ecelp9600"],
            },
            "audio/vnd.octel.sbc": {
              source: "iana",
            },
            "audio/vnd.presonus.multitrack": {
              source: "iana",
            },
            "audio/vnd.qcelp": {
              source: "iana",
            },
            "audio/vnd.rhetorex.32kadpcm": {
              source: "iana",
            },
            "audio/vnd.rip": {
              source: "iana",
              extensions: ["rip"],
            },
            "audio/vnd.rn-realaudio": {
              compressible: false,
            },
            "audio/vnd.sealedmedia.softseal.mpeg": {
              source: "iana",
            },
            "audio/vnd.vmx.cvsd": {
              source: "iana",
            },
            "audio/vnd.wave": {
              compressible: false,
            },
            "audio/vorbis": {
              source: "iana",
              compressible: false,
            },
            "audio/vorbis-config": {
              source: "iana",
            },
            "audio/wav": {
              compressible: false,
              extensions: ["wav"],
            },
            "audio/wave": {
              compressible: false,
              extensions: ["wav"],
            },
            "audio/webm": {
              source: "apache",
              compressible: false,
              extensions: ["weba"],
            },
            "audio/x-aac": {
              source: "apache",
              compressible: false,
              extensions: ["aac"],
            },
            "audio/x-aiff": {
              source: "apache",
              extensions: ["aif", "aiff", "aifc"],
            },
            "audio/x-caf": {
              source: "apache",
              compressible: false,
              extensions: ["caf"],
            },
            "audio/x-flac": {
              source: "apache",
              extensions: ["flac"],
            },
            "audio/x-m4a": {
              source: "nginx",
              extensions: ["m4a"],
            },
            "audio/x-matroska": {
              source: "apache",
              extensions: ["mka"],
            },
            "audio/x-mpegurl": {
              source: "apache",
              extensions: ["m3u"],
            },
            "audio/x-ms-wax": {
              source: "apache",
              extensions: ["wax"],
            },
            "audio/x-ms-wma": {
              source: "apache",
              extensions: ["wma"],
            },
            "audio/x-pn-realaudio": {
              source: "apache",
              extensions: ["ram", "ra"],
            },
            "audio/x-pn-realaudio-plugin": {
              source: "apache",
              extensions: ["rmp"],
            },
            "audio/x-realaudio": {
              source: "nginx",
              extensions: ["ra"],
            },
            "audio/x-tta": {
              source: "apache",
            },
            "audio/x-wav": {
              source: "apache",
              extensions: ["wav"],
            },
            "audio/xm": {
              source: "apache",
              extensions: ["xm"],
            },
            "chemical/x-cdx": {
              source: "apache",
              extensions: ["cdx"],
            },
            "chemical/x-cif": {
              source: "apache",
              extensions: ["cif"],
            },
            "chemical/x-cmdf": {
              source: "apache",
              extensions: ["cmdf"],
            },
            "chemical/x-cml": {
              source: "apache",
              extensions: ["cml"],
            },
            "chemical/x-csml": {
              source: "apache",
              extensions: ["csml"],
            },
            "chemical/x-pdb": {
              source: "apache",
            },
            "chemical/x-xyz": {
              source: "apache",
              extensions: ["xyz"],
            },
            "font/collection": {
              source: "iana",
              extensions: ["ttc"],
            },
            "font/otf": {
              source: "iana",
              compressible: true,
              extensions: ["otf"],
            },
            "font/sfnt": {
              source: "iana",
            },
            "font/ttf": {
              source: "iana",
              compressible: true,
              extensions: ["ttf"],
            },
            "font/woff": {
              source: "iana",
              extensions: ["woff"],
            },
            "font/woff2": {
              source: "iana",
              extensions: ["woff2"],
            },
            "image/aces": {
              source: "iana",
              extensions: ["exr"],
            },
            "image/apng": {
              compressible: false,
              extensions: ["apng"],
            },
            "image/avci": {
              source: "iana",
            },
            "image/avcs": {
              source: "iana",
            },
            "image/bmp": {
              source: "iana",
              compressible: true,
              extensions: ["bmp"],
            },
            "image/cgm": {
              source: "iana",
              extensions: ["cgm"],
            },
            "image/dicom-rle": {
              source: "iana",
              extensions: ["drle"],
            },
            "image/emf": {
              source: "iana",
              extensions: ["emf"],
            },
            "image/fits": {
              source: "iana",
              extensions: ["fits"],
            },
            "image/g3fax": {
              source: "iana",
              extensions: ["g3"],
            },
            "image/gif": {
              source: "iana",
              compressible: false,
              extensions: ["gif"],
            },
            "image/heic": {
              source: "iana",
              extensions: ["heic"],
            },
            "image/heic-sequence": {
              source: "iana",
              extensions: ["heics"],
            },
            "image/heif": {
              source: "iana",
              extensions: ["heif"],
            },
            "image/heif-sequence": {
              source: "iana",
              extensions: ["heifs"],
            },
            "image/hej2k": {
              source: "iana",
              extensions: ["hej2"],
            },
            "image/hsj2": {
              source: "iana",
              extensions: ["hsj2"],
            },
            "image/ief": {
              source: "iana",
              extensions: ["ief"],
            },
            "image/jls": {
              source: "iana",
              extensions: ["jls"],
            },
            "image/jp2": {
              source: "iana",
              compressible: false,
              extensions: ["jp2", "jpg2"],
            },
            "image/jpeg": {
              source: "iana",
              compressible: false,
              extensions: ["jpeg", "jpg", "jpe"],
            },
            "image/jph": {
              source: "iana",
              extensions: ["jph"],
            },
            "image/jphc": {
              source: "iana",
              extensions: ["jhc"],
            },
            "image/jpm": {
              source: "iana",
              compressible: false,
              extensions: ["jpm"],
            },
            "image/jpx": {
              source: "iana",
              compressible: false,
              extensions: ["jpx", "jpf"],
            },
            "image/jxr": {
              source: "iana",
              extensions: ["jxr"],
            },
            "image/jxra": {
              source: "iana",
              extensions: ["jxra"],
            },
            "image/jxrs": {
              source: "iana",
              extensions: ["jxrs"],
            },
            "image/jxs": {
              source: "iana",
              extensions: ["jxs"],
            },
            "image/jxsc": {
              source: "iana",
              extensions: ["jxsc"],
            },
            "image/jxsi": {
              source: "iana",
              extensions: ["jxsi"],
            },
            "image/jxss": {
              source: "iana",
              extensions: ["jxss"],
            },
            "image/ktx": {
              source: "iana",
              extensions: ["ktx"],
            },
            "image/naplps": {
              source: "iana",
            },
            "image/pjpeg": {
              compressible: false,
            },
            "image/png": {
              source: "iana",
              compressible: false,
              extensions: ["png"],
            },
            "image/prs.btif": {
              source: "iana",
              extensions: ["btif"],
            },
            "image/prs.pti": {
              source: "iana",
              extensions: ["pti"],
            },
            "image/pwg-raster": {
              source: "iana",
            },
            "image/sgi": {
              source: "apache",
              extensions: ["sgi"],
            },
            "image/svg+xml": {
              source: "iana",
              compressible: true,
              extensions: ["svg", "svgz"],
            },
            "image/t38": {
              source: "iana",
              extensions: ["t38"],
            },
            "image/tiff": {
              source: "iana",
              compressible: false,
              extensions: ["tif", "tiff"],
            },
            "image/tiff-fx": {
              source: "iana",
              extensions: ["tfx"],
            },
            "image/vnd.adobe.photoshop": {
              source: "iana",
              compressible: true,
              extensions: ["psd"],
            },
            "image/vnd.airzip.accelerator.azv": {
              source: "iana",
              extensions: ["azv"],
            },
            "image/vnd.cns.inf2": {
              source: "iana",
            },
            "image/vnd.dece.graphic": {
              source: "iana",
              extensions: ["uvi", "uvvi", "uvg", "uvvg"],
            },
            "image/vnd.djvu": {
              source: "iana",
              extensions: ["djvu", "djv"],
            },
            "image/vnd.dvb.subtitle": {
              source: "iana",
              extensions: ["sub"],
            },
            "image/vnd.dwg": {
              source: "iana",
              extensions: ["dwg"],
            },
            "image/vnd.dxf": {
              source: "iana",
              extensions: ["dxf"],
            },
            "image/vnd.fastbidsheet": {
              source: "iana",
              extensions: ["fbs"],
            },
            "image/vnd.fpx": {
              source: "iana",
              extensions: ["fpx"],
            },
            "image/vnd.fst": {
              source: "iana",
              extensions: ["fst"],
            },
            "image/vnd.fujixerox.edmics-mmr": {
              source: "iana",
              extensions: ["mmr"],
            },
            "image/vnd.fujixerox.edmics-rlc": {
              source: "iana",
              extensions: ["rlc"],
            },
            "image/vnd.globalgraphics.pgb": {
              source: "iana",
            },
            "image/vnd.microsoft.icon": {
              source: "iana",
              extensions: ["ico"],
            },
            "image/vnd.mix": {
              source: "iana",
            },
            "image/vnd.mozilla.apng": {
              source: "iana",
            },
            "image/vnd.ms-dds": {
              extensions: ["dds"],
            },
            "image/vnd.ms-modi": {
              source: "iana",
              extensions: ["mdi"],
            },
            "image/vnd.ms-photo": {
              source: "apache",
              extensions: ["wdp"],
            },
            "image/vnd.net-fpx": {
              source: "iana",
              extensions: ["npx"],
            },
            "image/vnd.radiance": {
              source: "iana",
            },
            "image/vnd.sealed.png": {
              source: "iana",
            },
            "image/vnd.sealedmedia.softseal.gif": {
              source: "iana",
            },
            "image/vnd.sealedmedia.softseal.jpg": {
              source: "iana",
            },
            "image/vnd.svf": {
              source: "iana",
            },
            "image/vnd.tencent.tap": {
              source: "iana",
              extensions: ["tap"],
            },
            "image/vnd.valve.source.texture": {
              source: "iana",
              extensions: ["vtf"],
            },
            "image/vnd.wap.wbmp": {
              source: "iana",
              extensions: ["wbmp"],
            },
            "image/vnd.xiff": {
              source: "iana",
              extensions: ["xif"],
            },
            "image/vnd.zbrush.pcx": {
              source: "iana",
              extensions: ["pcx"],
            },
            "image/webp": {
              source: "apache",
              extensions: ["webp"],
            },
            "image/wmf": {
              source: "iana",
              extensions: ["wmf"],
            },
            "image/x-3ds": {
              source: "apache",
              extensions: ["3ds"],
            },
            "image/x-cmu-raster": {
              source: "apache",
              extensions: ["ras"],
            },
            "image/x-cmx": {
              source: "apache",
              extensions: ["cmx"],
            },
            "image/x-freehand": {
              source: "apache",
              extensions: ["fh", "fhc", "fh4", "fh5", "fh7"],
            },
            "image/x-icon": {
              source: "apache",
              compressible: true,
              extensions: ["ico"],
            },
            "image/x-jng": {
              source: "nginx",
              extensions: ["jng"],
            },
            "image/x-mrsid-image": {
              source: "apache",
              extensions: ["sid"],
            },
            "image/x-ms-bmp": {
              source: "nginx",
              compressible: true,
              extensions: ["bmp"],
            },
            "image/x-pcx": {
              source: "apache",
              extensions: ["pcx"],
            },
            "image/x-pict": {
              source: "apache",
              extensions: ["pic", "pct"],
            },
            "image/x-portable-anymap": {
              source: "apache",
              extensions: ["pnm"],
            },
            "image/x-portable-bitmap": {
              source: "apache",
              extensions: ["pbm"],
            },
            "image/x-portable-graymap": {
              source: "apache",
              extensions: ["pgm"],
            },
            "image/x-portable-pixmap": {
              source: "apache",
              extensions: ["ppm"],
            },
            "image/x-rgb": {
              source: "apache",
              extensions: ["rgb"],
            },
            "image/x-tga": {
              source: "apache",
              extensions: ["tga"],
            },
            "image/x-xbitmap": {
              source: "apache",
              extensions: ["xbm"],
            },
            "image/x-xcf": {
              compressible: false,
            },
            "image/x-xpixmap": {
              source: "apache",
              extensions: ["xpm"],
            },
            "image/x-xwindowdump": {
              source: "apache",
              extensions: ["xwd"],
            },
            "message/cpim": {
              source: "iana",
            },
            "message/delivery-status": {
              source: "iana",
            },
            "message/disposition-notification": {
              source: "iana",
              extensions: ["disposition-notification"],
            },
            "message/external-body": {
              source: "iana",
            },
            "message/feedback-report": {
              source: "iana",
            },
            "message/global": {
              source: "iana",
              extensions: ["u8msg"],
            },
            "message/global-delivery-status": {
              source: "iana",
              extensions: ["u8dsn"],
            },
            "message/global-disposition-notification": {
              source: "iana",
              extensions: ["u8mdn"],
            },
            "message/global-headers": {
              source: "iana",
              extensions: ["u8hdr"],
            },
            "message/http": {
              source: "iana",
              compressible: false,
            },
            "message/imdn+xml": {
              source: "iana",
              compressible: true,
            },
            "message/news": {
              source: "iana",
            },
            "message/partial": {
              source: "iana",
              compressible: false,
            },
            "message/rfc822": {
              source: "iana",
              compressible: true,
              extensions: ["eml", "mime"],
            },
            "message/s-http": {
              source: "iana",
            },
            "message/sip": {
              source: "iana",
            },
            "message/sipfrag": {
              source: "iana",
            },
            "message/tracking-status": {
              source: "iana",
            },
            "message/vnd.si.simp": {
              source: "iana",
            },
            "message/vnd.wfa.wsc": {
              source: "iana",
              extensions: ["wsc"],
            },
            "model/3mf": {
              source: "iana",
              extensions: ["3mf"],
            },
            "model/gltf+json": {
              source: "iana",
              compressible: true,
              extensions: ["gltf"],
            },
            "model/gltf-binary": {
              source: "iana",
              compressible: true,
              extensions: ["glb"],
            },
            "model/iges": {
              source: "iana",
              compressible: false,
              extensions: ["igs", "iges"],
            },
            "model/mesh": {
              source: "iana",
              compressible: false,
              extensions: ["msh", "mesh", "silo"],
            },
            "model/mtl": {
              source: "iana",
              extensions: ["mtl"],
            },
            "model/obj": {
              source: "iana",
              extensions: ["obj"],
            },
            "model/stl": {
              source: "iana",
              extensions: ["stl"],
            },
            "model/vnd.collada+xml": {
              source: "iana",
              compressible: true,
              extensions: ["dae"],
            },
            "model/vnd.dwf": {
              source: "iana",
              extensions: ["dwf"],
            },
            "model/vnd.flatland.3dml": {
              source: "iana",
            },
            "model/vnd.gdl": {
              source: "iana",
              extensions: ["gdl"],
            },
            "model/vnd.gs-gdl": {
              source: "apache",
            },
            "model/vnd.gs.gdl": {
              source: "iana",
            },
            "model/vnd.gtw": {
              source: "iana",
              extensions: ["gtw"],
            },
            "model/vnd.moml+xml": {
              source: "iana",
              compressible: true,
            },
            "model/vnd.mts": {
              source: "iana",
              extensions: ["mts"],
            },
            "model/vnd.opengex": {
              source: "iana",
              extensions: ["ogex"],
            },
            "model/vnd.parasolid.transmit.binary": {
              source: "iana",
              extensions: ["x_b"],
            },
            "model/vnd.parasolid.transmit.text": {
              source: "iana",
              extensions: ["x_t"],
            },
            "model/vnd.rosette.annotated-data-model": {
              source: "iana",
            },
            "model/vnd.usdz+zip": {
              source: "iana",
              compressible: false,
              extensions: ["usdz"],
            },
            "model/vnd.valve.source.compiled-map": {
              source: "iana",
              extensions: ["bsp"],
            },
            "model/vnd.vtu": {
              source: "iana",
              extensions: ["vtu"],
            },
            "model/vrml": {
              source: "iana",
              compressible: false,
              extensions: ["wrl", "vrml"],
            },
            "model/x3d+binary": {
              source: "apache",
              compressible: false,
              extensions: ["x3db", "x3dbz"],
            },
            "model/x3d+fastinfoset": {
              source: "iana",
              extensions: ["x3db"],
            },
            "model/x3d+vrml": {
              source: "apache",
              compressible: false,
              extensions: ["x3dv", "x3dvz"],
            },
            "model/x3d+xml": {
              source: "iana",
              compressible: true,
              extensions: ["x3d", "x3dz"],
            },
            "model/x3d-vrml": {
              source: "iana",
              extensions: ["x3dv"],
            },
            "multipart/alternative": {
              source: "iana",
              compressible: false,
            },
            "multipart/appledouble": {
              source: "iana",
            },
            "multipart/byteranges": {
              source: "iana",
            },
            "multipart/digest": {
              source: "iana",
            },
            "multipart/encrypted": {
              source: "iana",
              compressible: false,
            },
            "multipart/form-data": {
              source: "iana",
              compressible: false,
            },
            "multipart/header-set": {
              source: "iana",
            },
            "multipart/mixed": {
              source: "iana",
            },
            "multipart/multilingual": {
              source: "iana",
            },
            "multipart/parallel": {
              source: "iana",
            },
            "multipart/related": {
              source: "iana",
              compressible: false,
            },
            "multipart/report": {
              source: "iana",
            },
            "multipart/signed": {
              source: "iana",
              compressible: false,
            },
            "multipart/vnd.bint.med-plus": {
              source: "iana",
            },
            "multipart/voice-message": {
              source: "iana",
            },
            "multipart/x-mixed-replace": {
              source: "iana",
            },
            "text/1d-interleaved-parityfec": {
              source: "iana",
            },
            "text/cache-manifest": {
              source: "iana",
              compressible: true,
              extensions: ["appcache", "manifest"],
            },
            "text/calendar": {
              source: "iana",
              extensions: ["ics", "ifb"],
            },
            "text/calender": {
              compressible: true,
            },
            "text/cmd": {
              compressible: true,
            },
            "text/coffeescript": {
              extensions: ["coffee", "litcoffee"],
            },
            "text/css": {
              source: "iana",
              charset: "UTF-8",
              compressible: true,
              extensions: ["css"],
            },
            "text/csv": {
              source: "iana",
              compressible: true,
              extensions: ["csv"],
            },
            "text/csv-schema": {
              source: "iana",
            },
            "text/directory": {
              source: "iana",
            },
            "text/dns": {
              source: "iana",
            },
            "text/ecmascript": {
              source: "iana",
            },
            "text/encaprtp": {
              source: "iana",
            },
            "text/enriched": {
              source: "iana",
            },
            "text/flexfec": {
              source: "iana",
            },
            "text/fwdred": {
              source: "iana",
            },
            "text/grammar-ref-list": {
              source: "iana",
            },
            "text/html": {
              source: "iana",
              compressible: true,
              extensions: ["html", "htm", "shtml"],
            },
            "text/jade": {
              extensions: ["jade"],
            },
            "text/javascript": {
              source: "iana",
              compressible: true,
            },
            "text/jcr-cnd": {
              source: "iana",
            },
            "text/jsx": {
              compressible: true,
              extensions: ["jsx"],
            },
            "text/less": {
              compressible: true,
              extensions: ["less"],
            },
            "text/markdown": {
              source: "iana",
              compressible: true,
              extensions: ["markdown", "md"],
            },
            "text/mathml": {
              source: "nginx",
              extensions: ["mml"],
            },
            "text/mdx": {
              compressible: true,
              extensions: ["mdx"],
            },
            "text/mizar": {
              source: "iana",
            },
            "text/n3": {
              source: "iana",
              charset: "UTF-8",
              compressible: true,
              extensions: ["n3"],
            },
            "text/parameters": {
              source: "iana",
              charset: "UTF-8",
            },
            "text/parityfec": {
              source: "iana",
            },
            "text/plain": {
              source: "iana",
              compressible: true,
              extensions: [
                "txt",
                "text",
                "conf",
                "def",
                "list",
                "log",
                "in",
                "ini",
              ],
            },
            "text/provenance-notation": {
              source: "iana",
              charset: "UTF-8",
            },
            "text/prs.fallenstein.rst": {
              source: "iana",
            },
            "text/prs.lines.tag": {
              source: "iana",
              extensions: ["dsc"],
            },
            "text/prs.prop.logic": {
              source: "iana",
            },
            "text/raptorfec": {
              source: "iana",
            },
            "text/red": {
              source: "iana",
            },
            "text/rfc822-headers": {
              source: "iana",
            },
            "text/richtext": {
              source: "iana",
              compressible: true,
              extensions: ["rtx"],
            },
            "text/rtf": {
              source: "iana",
              compressible: true,
              extensions: ["rtf"],
            },
            "text/rtp-enc-aescm128": {
              source: "iana",
            },
            "text/rtploopback": {
              source: "iana",
            },
            "text/rtx": {
              source: "iana",
            },
            "text/sgml": {
              source: "iana",
              extensions: ["sgml", "sgm"],
            },
            "text/shex": {
              extensions: ["shex"],
            },
            "text/slim": {
              extensions: ["slim", "slm"],
            },
            "text/strings": {
              source: "iana",
            },
            "text/stylus": {
              extensions: ["stylus", "styl"],
            },
            "text/t140": {
              source: "iana",
            },
            "text/tab-separated-values": {
              source: "iana",
              compressible: true,
              extensions: ["tsv"],
            },
            "text/troff": {
              source: "iana",
              extensions: ["t", "tr", "roff", "man", "me", "ms"],
            },
            "text/turtle": {
              source: "iana",
              charset: "UTF-8",
              extensions: ["ttl"],
            },
            "text/ulpfec": {
              source: "iana",
            },
            "text/uri-list": {
              source: "iana",
              compressible: true,
              extensions: ["uri", "uris", "urls"],
            },
            "text/vcard": {
              source: "iana",
              compressible: true,
              extensions: ["vcard"],
            },
            "text/vnd.a": {
              source: "iana",
            },
            "text/vnd.abc": {
              source: "iana",
            },
            "text/vnd.ascii-art": {
              source: "iana",
            },
            "text/vnd.curl": {
              source: "iana",
              extensions: ["curl"],
            },
            "text/vnd.curl.dcurl": {
              source: "apache",
              extensions: ["dcurl"],
            },
            "text/vnd.curl.mcurl": {
              source: "apache",
              extensions: ["mcurl"],
            },
            "text/vnd.curl.scurl": {
              source: "apache",
              extensions: ["scurl"],
            },
            "text/vnd.debian.copyright": {
              source: "iana",
              charset: "UTF-8",
            },
            "text/vnd.dmclientscript": {
              source: "iana",
            },
            "text/vnd.dvb.subtitle": {
              source: "iana",
              extensions: ["sub"],
            },
            "text/vnd.esmertec.theme-descriptor": {
              source: "iana",
              charset: "UTF-8",
            },
            "text/vnd.ficlab.flt": {
              source: "iana",
            },
            "text/vnd.fly": {
              source: "iana",
              extensions: ["fly"],
            },
            "text/vnd.fmi.flexstor": {
              source: "iana",
              extensions: ["flx"],
            },
            "text/vnd.gml": {
              source: "iana",
            },
            "text/vnd.graphviz": {
              source: "iana",
              extensions: ["gv"],
            },
            "text/vnd.hgl": {
              source: "iana",
            },
            "text/vnd.in3d.3dml": {
              source: "iana",
              extensions: ["3dml"],
            },
            "text/vnd.in3d.spot": {
              source: "iana",
              extensions: ["spot"],
            },
            "text/vnd.iptc.newsml": {
              source: "iana",
            },
            "text/vnd.iptc.nitf": {
              source: "iana",
            },
            "text/vnd.latex-z": {
              source: "iana",
            },
            "text/vnd.motorola.reflex": {
              source: "iana",
            },
            "text/vnd.ms-mediapackage": {
              source: "iana",
            },
            "text/vnd.net2phone.commcenter.command": {
              source: "iana",
            },
            "text/vnd.radisys.msml-basic-layout": {
              source: "iana",
            },
            "text/vnd.senx.warpscript": {
              source: "iana",
            },
            "text/vnd.si.uricatalogue": {
              source: "iana",
            },
            "text/vnd.sosi": {
              source: "iana",
            },
            "text/vnd.sun.j2me.app-descriptor": {
              source: "iana",
              charset: "UTF-8",
              extensions: ["jad"],
            },
            "text/vnd.trolltech.linguist": {
              source: "iana",
              charset: "UTF-8",
            },
            "text/vnd.wap.si": {
              source: "iana",
            },
            "text/vnd.wap.sl": {
              source: "iana",
            },
            "text/vnd.wap.wml": {
              source: "iana",
              extensions: ["wml"],
            },
            "text/vnd.wap.wmlscript": {
              source: "iana",
              extensions: ["wmls"],
            },
            "text/vtt": {
              source: "iana",
              charset: "UTF-8",
              compressible: true,
              extensions: ["vtt"],
            },
            "text/x-asm": {
              source: "apache",
              extensions: ["s", "asm"],
            },
            "text/x-c": {
              source: "apache",
              extensions: ["c", "cc", "cxx", "cpp", "h", "hh", "dic"],
            },
            "text/x-component": {
              source: "nginx",
              extensions: ["htc"],
            },
            "text/x-fortran": {
              source: "apache",
              extensions: ["f", "for", "f77", "f90"],
            },
            "text/x-gwt-rpc": {
              compressible: true,
            },
            "text/x-handlebars-template": {
              extensions: ["hbs"],
            },
            "text/x-java-source": {
              source: "apache",
              extensions: ["java"],
            },
            "text/x-jquery-tmpl": {
              compressible: true,
            },
            "text/x-lua": {
              extensions: ["lua"],
            },
            "text/x-markdown": {
              compressible: true,
              extensions: ["mkd"],
            },
            "text/x-nfo": {
              source: "apache",
              extensions: ["nfo"],
            },
            "text/x-opml": {
              source: "apache",
              extensions: ["opml"],
            },
            "text/x-org": {
              compressible: true,
              extensions: ["org"],
            },
            "text/x-pascal": {
              source: "apache",
              extensions: ["p", "pas"],
            },
            "text/x-processing": {
              compressible: true,
              extensions: ["pde"],
            },
            "text/x-sass": {
              extensions: ["sass"],
            },
            "text/x-scss": {
              extensions: ["scss"],
            },
            "text/x-setext": {
              source: "apache",
              extensions: ["etx"],
            },
            "text/x-sfv": {
              source: "apache",
              extensions: ["sfv"],
            },
            "text/x-suse-ymp": {
              compressible: true,
              extensions: ["ymp"],
            },
            "text/x-uuencode": {
              source: "apache",
              extensions: ["uu"],
            },
            "text/x-vcalendar": {
              source: "apache",
              extensions: ["vcs"],
            },
            "text/x-vcard": {
              source: "apache",
              extensions: ["vcf"],
            },
            "text/xml": {
              source: "iana",
              compressible: true,
              extensions: ["xml"],
            },
            "text/xml-external-parsed-entity": {
              source: "iana",
            },
            "text/yaml": {
              extensions: ["yaml", "yml"],
            },
            "video/1d-interleaved-parityfec": {
              source: "iana",
            },
            "video/3gpp": {
              source: "iana",
              extensions: ["3gp", "3gpp"],
            },
            "video/3gpp-tt": {
              source: "iana",
            },
            "video/3gpp2": {
              source: "iana",
              extensions: ["3g2"],
            },
            "video/bmpeg": {
              source: "iana",
            },
            "video/bt656": {
              source: "iana",
            },
            "video/celb": {
              source: "iana",
            },
            "video/dv": {
              source: "iana",
            },
            "video/encaprtp": {
              source: "iana",
            },
            "video/flexfec": {
              source: "iana",
            },
            "video/h261": {
              source: "iana",
              extensions: ["h261"],
            },
            "video/h263": {
              source: "iana",
              extensions: ["h263"],
            },
            "video/h263-1998": {
              source: "iana",
            },
            "video/h263-2000": {
              source: "iana",
            },
            "video/h264": {
              source: "iana",
              extensions: ["h264"],
            },
            "video/h264-rcdo": {
              source: "iana",
            },
            "video/h264-svc": {
              source: "iana",
            },
            "video/h265": {
              source: "iana",
            },
            "video/iso.segment": {
              source: "iana",
            },
            "video/jpeg": {
              source: "iana",
              extensions: ["jpgv"],
            },
            "video/jpeg2000": {
              source: "iana",
            },
            "video/jpm": {
              source: "apache",
              extensions: ["jpm", "jpgm"],
            },
            "video/mj2": {
              source: "iana",
              extensions: ["mj2", "mjp2"],
            },
            "video/mp1s": {
              source: "iana",
            },
            "video/mp2p": {
              source: "iana",
            },
            "video/mp2t": {
              source: "iana",
              extensions: ["ts"],
            },
            "video/mp4": {
              source: "iana",
              compressible: false,
              extensions: ["mp4", "mp4v", "mpg4"],
            },
            "video/mp4v-es": {
              source: "iana",
            },
            "video/mpeg": {
              source: "iana",
              compressible: false,
              extensions: ["mpeg", "mpg", "mpe", "m1v", "m2v"],
            },
            "video/mpeg4-generic": {
              source: "iana",
            },
            "video/mpv": {
              source: "iana",
            },
            "video/nv": {
              source: "iana",
            },
            "video/ogg": {
              source: "iana",
              compressible: false,
              extensions: ["ogv"],
            },
            "video/parityfec": {
              source: "iana",
            },
            "video/pointer": {
              source: "iana",
            },
            "video/quicktime": {
              source: "iana",
              compressible: false,
              extensions: ["qt", "mov"],
            },
            "video/raptorfec": {
              source: "iana",
            },
            "video/raw": {
              source: "iana",
            },
            "video/rtp-enc-aescm128": {
              source: "iana",
            },
            "video/rtploopback": {
              source: "iana",
            },
            "video/rtx": {
              source: "iana",
            },
            "video/smpte291": {
              source: "iana",
            },
            "video/smpte292m": {
              source: "iana",
            },
            "video/ulpfec": {
              source: "iana",
            },
            "video/vc1": {
              source: "iana",
            },
            "video/vc2": {
              source: "iana",
            },
            "video/vnd.cctv": {
              source: "iana",
            },
            "video/vnd.dece.hd": {
              source: "iana",
              extensions: ["uvh", "uvvh"],
            },
            "video/vnd.dece.mobile": {
              source: "iana",
              extensions: ["uvm", "uvvm"],
            },
            "video/vnd.dece.mp4": {
              source: "iana",
            },
            "video/vnd.dece.pd": {
              source: "iana",
              extensions: ["uvp", "uvvp"],
            },
            "video/vnd.dece.sd": {
              source: "iana",
              extensions: ["uvs", "uvvs"],
            },
            "video/vnd.dece.video": {
              source: "iana",
              extensions: ["uvv", "uvvv"],
            },
            "video/vnd.directv.mpeg": {
              source: "iana",
            },
            "video/vnd.directv.mpeg-tts": {
              source: "iana",
            },
            "video/vnd.dlna.mpeg-tts": {
              source: "iana",
            },
            "video/vnd.dvb.file": {
              source: "iana",
              extensions: ["dvb"],
            },
            "video/vnd.fvt": {
              source: "iana",
              extensions: ["fvt"],
            },
            "video/vnd.hns.video": {
              source: "iana",
            },
            "video/vnd.iptvforum.1dparityfec-1010": {
              source: "iana",
            },
            "video/vnd.iptvforum.1dparityfec-2005": {
              source: "iana",
            },
            "video/vnd.iptvforum.2dparityfec-1010": {
              source: "iana",
            },
            "video/vnd.iptvforum.2dparityfec-2005": {
              source: "iana",
            },
            "video/vnd.iptvforum.ttsavc": {
              source: "iana",
            },
            "video/vnd.iptvforum.ttsmpeg2": {
              source: "iana",
            },
            "video/vnd.motorola.video": {
              source: "iana",
            },
            "video/vnd.motorola.videop": {
              source: "iana",
            },
            "video/vnd.mpegurl": {
              source: "iana",
              extensions: ["mxu", "m4u"],
            },
            "video/vnd.ms-playready.media.pyv": {
              source: "iana",
              extensions: ["pyv"],
            },
            "video/vnd.nokia.interleaved-multimedia": {
              source: "iana",
            },
            "video/vnd.nokia.mp4vr": {
              source: "iana",
            },
            "video/vnd.nokia.videovoip": {
              source: "iana",
            },
            "video/vnd.objectvideo": {
              source: "iana",
            },
            "video/vnd.radgamettools.bink": {
              source: "iana",
            },
            "video/vnd.radgamettools.smacker": {
              source: "iana",
            },
            "video/vnd.sealed.mpeg1": {
              source: "iana",
            },
            "video/vnd.sealed.mpeg4": {
              source: "iana",
            },
            "video/vnd.sealed.swf": {
              source: "iana",
            },
            "video/vnd.sealedmedia.softseal.mov": {
              source: "iana",
            },
            "video/vnd.uvvu.mp4": {
              source: "iana",
              extensions: ["uvu", "uvvu"],
            },
            "video/vnd.vivo": {
              source: "iana",
              extensions: ["viv"],
            },
            "video/vnd.youtube.yt": {
              source: "iana",
            },
            "video/vp8": {
              source: "iana",
            },
            "video/webm": {
              source: "apache",
              compressible: false,
              extensions: ["webm"],
            },
            "video/x-f4v": {
              source: "apache",
              extensions: ["f4v"],
            },
            "video/x-fli": {
              source: "apache",
              extensions: ["fli"],
            },
            "video/x-flv": {
              source: "apache",
              compressible: false,
              extensions: ["flv"],
            },
            "video/x-m4v": {
              source: "apache",
              extensions: ["m4v"],
            },
            "video/x-matroska": {
              source: "apache",
              compressible: false,
              extensions: ["mkv", "mk3d", "mks"],
            },
            "video/x-mng": {
              source: "apache",
              extensions: ["mng"],
            },
            "video/x-ms-asf": {
              source: "apache",
              extensions: ["asf", "asx"],
            },
            "video/x-ms-vob": {
              source: "apache",
              extensions: ["vob"],
            },
            "video/x-ms-wm": {
              source: "apache",
              extensions: ["wm"],
            },
            "video/x-ms-wmv": {
              source: "apache",
              compressible: false,
              extensions: ["wmv"],
            },
            "video/x-ms-wmx": {
              source: "apache",
              extensions: ["wmx"],
            },
            "video/x-ms-wvx": {
              source: "apache",
              extensions: ["wvx"],
            },
            "video/x-msvideo": {
              source: "apache",
              extensions: ["avi"],
            },
            "video/x-sgi-movie": {
              source: "apache",
              extensions: ["movie"],
            },
            "video/x-smv": {
              source: "apache",
              extensions: ["smv"],
            },
            "x-conference/x-cooltalk": {
              source: "apache",
              extensions: ["ice"],
            },
            "x-shader/x-fragment": {
              compressible: true,
            },
            "x-shader/x-vertex": {
              compressible: true,
            },
          },
        );
      },
    };
  },
);
// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
System.register(
  "https://deno.land/x/media_types@v2.3.3/deps",
  ["https://deno.land/std@0.53.0/path/mod"],
  function (exports_30, context_30) {
    "use strict";
    var __moduleName = context_30 && context_30.id;
    return {
      setters: [
        function (mod_ts_6_1) {
          exports_30({
            "extname": mod_ts_6_1["extname"],
          });
        },
      ],
      execute: function () {
      },
    };
  },
);
/*!
 * Ported from: https://github.com/jshttp/mime-types and licensed as:
 *
 * (The MIT License)
 *
 * Copyright (c) 2014 Jonathan Ong <me@jongleberry.com>
 * Copyright (c) 2015 Douglas Christopher Wilson <doug@somethingdoug.com>
 * Copyright (c) 2020 the Deno authors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * 'Software'), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
System.register(
  "https://deno.land/x/media_types@v2.3.3/mod",
  [
    "https://deno.land/x/media_types@v2.3.3/db",
    "https://deno.land/x/media_types@v2.3.3/deps",
  ],
  function (exports_31, context_31) {
    "use strict";
    var db_ts_1,
      deps_ts_1,
      EXTRACT_TYPE_REGEXP,
      TEXT_TYPE_REGEXP,
      extensions,
      types;
    var __moduleName = context_31 && context_31.id;
    /** Internal function to populate the maps based on the Mime DB */
    function populateMaps(extensions, types) {
      const preference = ["nginx", "apache", undefined, "iana"];
      for (const type of Object.keys(db_ts_1.db)) {
        const mime = db_ts_1.db[type];
        const exts = mime.extensions;
        if (!exts || !exts.length) {
          continue;
        }
        extensions.set(type, exts);
        for (const ext of exts) {
          const current = types.get(ext);
          if (current) {
            const from = preference.indexOf(db_ts_1.db[current].source);
            const to = preference.indexOf(mime.source);
            if (
              current !== "application/octet-stream" &&
              (from > to ||
                (from === to && current.substr(0, 12) === "application/"))
            ) {
              continue;
            }
          }
          types.set(ext, type);
        }
      }
    }
    /** Given a media type return any default charset string.  Returns `undefined`
     * if not resolvable.
     */
    function charset(type) {
      const m = EXTRACT_TYPE_REGEXP.exec(type);
      if (!m) {
        return;
      }
      const [match] = m;
      const mime = db_ts_1.db[match.toLowerCase()];
      if (mime && mime.charset) {
        return mime.charset;
      }
      if (TEXT_TYPE_REGEXP.test(match)) {
        return "UTF-8";
      }
    }
    exports_31("charset", charset);
    /** Given an extension, lookup the appropriate media type for that extension.
     * Likely you should be using `contentType()` though instead.
     */
    function lookup(path) {
      const extension = deps_ts_1.extname("x." + path)
        .toLowerCase()
        .substr(1);
      return types.get(extension);
    }
    exports_31("lookup", lookup);
    /** Given an extension or media type, return the full `Content-Type` header
     * string.  Returns `undefined` if not resolvable.
     */
    function contentType(str) {
      let mime = str.includes("/") ? str : lookup(str);
      if (!mime) {
        return;
      }
      if (!mime.includes("charset")) {
        const cs = charset(mime);
        if (cs) {
          mime += `; charset=${cs.toLowerCase()}`;
        }
      }
      return mime;
    }
    exports_31("contentType", contentType);
    /** Given a media type, return the most appropriate extension or return
     * `undefined` if there is none.
     */
    function extension(type) {
      const match = EXTRACT_TYPE_REGEXP.exec(type);
      if (!match) {
        return;
      }
      const exts = extensions.get(match[1].toLowerCase());
      if (!exts || !exts.length) {
        return;
      }
      return exts[0];
    }
    exports_31("extension", extension);
    return {
      setters: [
        function (db_ts_1_1) {
          db_ts_1 = db_ts_1_1;
        },
        function (deps_ts_1_1) {
          deps_ts_1 = deps_ts_1_1;
        },
      ],
      execute: function () {
        EXTRACT_TYPE_REGEXP = /^\s*([^;\s]*)(?:;|\s|$)/;
        TEXT_TYPE_REGEXP = /^text\//i;
        /** A map of extensions for a given media type */
        exports_31("extensions", extensions = new Map());
        /** A map of the media type for a given extension */
        exports_31("types", types = new Map());
        // Populate the maps upon module load
        populateMaps(extensions, types);
      },
    };
  },
);
System.register(
  "https://raw.githubusercontent.com/pillarjs/path-to-regexp/v6.1.0/src/index",
  [],
  function (exports_32, context_32) {
    "use strict";
    var __moduleName = context_32 && context_32.id;
    /**
     * Tokenize input string.
     */
    function lexer(str) {
      const tokens = [];
      let i = 0;
      while (i < str.length) {
        const char = str[i];
        if (char === "*" || char === "+" || char === "?") {
          tokens.push({ type: "MODIFIER", index: i, value: str[i++] });
          continue;
        }
        if (char === "\\") {
          tokens.push({ type: "ESCAPED_CHAR", index: i++, value: str[i++] });
          continue;
        }
        if (char === "{") {
          tokens.push({ type: "OPEN", index: i, value: str[i++] });
          continue;
        }
        if (char === "}") {
          tokens.push({ type: "CLOSE", index: i, value: str[i++] });
          continue;
        }
        if (char === ":") {
          let name = "";
          let j = i + 1;
          while (j < str.length) {
            const code = str.charCodeAt(j);
            if (
              // `0-9`
              (code >= 48 && code <= 57) ||
              // `A-Z`
              (code >= 65 && code <= 90) ||
              // `a-z`
              (code >= 97 && code <= 122) ||
              // `_`
              code === 95
            ) {
              name += str[j++];
              continue;
            }
            break;
          }
          if (!name) {
            throw new TypeError(`Missing parameter name at ${i}`);
          }
          tokens.push({ type: "NAME", index: i, value: name });
          i = j;
          continue;
        }
        if (char === "(") {
          let count = 1;
          let pattern = "";
          let j = i + 1;
          if (str[j] === "?") {
            throw new TypeError(`Pattern cannot start with "?" at ${j}`);
          }
          while (j < str.length) {
            if (str[j] === "\\") {
              pattern += str[j++] + str[j++];
              continue;
            }
            if (str[j] === ")") {
              count--;
              if (count === 0) {
                j++;
                break;
              }
            } else if (str[j] === "(") {
              count++;
              if (str[j + 1] !== "?") {
                throw new TypeError(`Capturing groups are not allowed at ${j}`);
              }
            }
            pattern += str[j++];
          }
          if (count) {
            throw new TypeError(`Unbalanced pattern at ${i}`);
          }
          if (!pattern) {
            throw new TypeError(`Missing pattern at ${i}`);
          }
          tokens.push({ type: "PATTERN", index: i, value: pattern });
          i = j;
          continue;
        }
        tokens.push({ type: "CHAR", index: i, value: str[i++] });
      }
      tokens.push({ type: "END", index: i, value: "" });
      return tokens;
    }
    /**
     * Parse a string for the raw tokens.
     */
    function parse(str, options = {}) {
      const tokens = lexer(str);
      const { prefixes = "./" } = options;
      const defaultPattern = `[^${escapeString(options.delimiter || "/#?")}]+?`;
      const result = [];
      let key = 0;
      let i = 0;
      let path = "";
      const tryConsume = (type) => {
        if (i < tokens.length && tokens[i].type === type) {
          return tokens[i++].value;
        }
      };
      const mustConsume = (type) => {
        const value = tryConsume(type);
        if (value !== undefined) {
          return value;
        }
        const { type: nextType, index } = tokens[i];
        throw new TypeError(
          `Unexpected ${nextType} at ${index}, expected ${type}`,
        );
      };
      const consumeText = () => {
        let result = "";
        let value;
        // tslint:disable-next-line
        while ((value = tryConsume("CHAR") || tryConsume("ESCAPED_CHAR"))) {
          result += value;
        }
        return result;
      };
      while (i < tokens.length) {
        const char = tryConsume("CHAR");
        const name = tryConsume("NAME");
        const pattern = tryConsume("PATTERN");
        if (name || pattern) {
          let prefix = char || "";
          if (prefixes.indexOf(prefix) === -1) {
            path += prefix;
            prefix = "";
          }
          if (path) {
            result.push(path);
            path = "";
          }
          result.push({
            name: name || key++,
            prefix,
            suffix: "",
            pattern: pattern || defaultPattern,
            modifier: tryConsume("MODIFIER") || "",
          });
          continue;
        }
        const value = char || tryConsume("ESCAPED_CHAR");
        if (value) {
          path += value;
          continue;
        }
        if (path) {
          result.push(path);
          path = "";
        }
        const open = tryConsume("OPEN");
        if (open) {
          const prefix = consumeText();
          const name = tryConsume("NAME") || "";
          const pattern = tryConsume("PATTERN") || "";
          const suffix = consumeText();
          mustConsume("CLOSE");
          result.push({
            name: name || (pattern ? key++ : ""),
            pattern: name && !pattern ? defaultPattern : pattern,
            prefix,
            suffix,
            modifier: tryConsume("MODIFIER") || "",
          });
          continue;
        }
        mustConsume("END");
      }
      return result;
    }
    exports_32("parse", parse);
    /**
     * Compile a string to a template function for the path.
     */
    function compile(str, options) {
      return tokensToFunction(parse(str, options), options);
    }
    exports_32("compile", compile);
    /**
     * Expose a method for transforming tokens into the path function.
     */
    function tokensToFunction(tokens, options = {}) {
      const reFlags = flags(options);
      const { encode = (x) => x, validate = true } = options;
      // Compile all the tokens into regexps.
      const matches = tokens.map((token) => {
        if (typeof token === "object") {
          return new RegExp(`^(?:${token.pattern})$`, reFlags);
        }
      });
      return (data) => {
        let path = "";
        for (let i = 0; i < tokens.length; i++) {
          const token = tokens[i];
          if (typeof token === "string") {
            path += token;
            continue;
          }
          const value = data ? data[token.name] : undefined;
          const optional = token.modifier === "?" || token.modifier === "*";
          const repeat = token.modifier === "*" || token.modifier === "+";
          if (Array.isArray(value)) {
            if (!repeat) {
              throw new TypeError(
                `Expected "${token.name}" to not repeat, but got an array`,
              );
            }
            if (value.length === 0) {
              if (optional) {
                continue;
              }
              throw new TypeError(`Expected "${token.name}" to not be empty`);
            }
            for (let j = 0; j < value.length; j++) {
              const segment = encode(value[j], token);
              if (validate && !matches[i].test(segment)) {
                throw new TypeError(
                  `Expected all "${token.name}" to match "${token.pattern}", but got "${segment}"`,
                );
              }
              path += token.prefix + segment + token.suffix;
            }
            continue;
          }
          if (typeof value === "string" || typeof value === "number") {
            const segment = encode(String(value), token);
            if (validate && !matches[i].test(segment)) {
              throw new TypeError(
                `Expected "${token.name}" to match "${token.pattern}", but got "${segment}"`,
              );
            }
            path += token.prefix + segment + token.suffix;
            continue;
          }
          if (optional) {
            continue;
          }
          const typeOfMessage = repeat ? "an array" : "a string";
          throw new TypeError(
            `Expected "${token.name}" to be ${typeOfMessage}`,
          );
        }
        return path;
      };
    }
    exports_32("tokensToFunction", tokensToFunction);
    /**
     * Create path match function from `path-to-regexp` spec.
     */
    function match(str, options) {
      const keys = [];
      const re = pathToRegexp(str, keys, options);
      return regexpToFunction(re, keys, options);
    }
    exports_32("match", match);
    /**
     * Create a path match function from `path-to-regexp` output.
     */
    function regexpToFunction(re, keys, options = {}) {
      const { decode = (x) => x } = options;
      return function (pathname) {
        const m = re.exec(pathname);
        if (!m) {
          return false;
        }
        const { 0: path, index } = m;
        const params = Object.create(null);
        for (let i = 1; i < m.length; i++) {
          // tslint:disable-next-line
          if (m[i] === undefined) {
            continue;
          }
          const key = keys[i - 1];
          if (key.modifier === "*" || key.modifier === "+") {
            params[key.name] = m[i].split(key.prefix + key.suffix).map(
              (value) => {
                return decode(value, key);
              },
            );
          } else {
            params[key.name] = decode(m[i], key);
          }
        }
        return { path, index, params };
      };
    }
    exports_32("regexpToFunction", regexpToFunction);
    /**
     * Escape a regular expression string.
     */
    function escapeString(str) {
      return str.replace(/([.+*?=^!:${}()[\]|/\\])/g, "\\$1");
    }
    /**
     * Get the flags for a regexp from the options.
     */
    function flags(options) {
      return options && options.sensitive ? "" : "i";
    }
    /**
     * Pull out keys from a regexp.
     */
    function regexpToRegexp(path, keys) {
      if (!keys) {
        return path;
      }
      // Use a negative lookahead to match only capturing groups.
      const groups = path.source.match(/\((?!\?)/g);
      if (groups) {
        for (let i = 0; i < groups.length; i++) {
          keys.push({
            name: i,
            prefix: "",
            suffix: "",
            modifier: "",
            pattern: "",
          });
        }
      }
      return path;
    }
    /**
     * Transform an array into a regexp.
     */
    function arrayToRegexp(paths, keys, options) {
      const parts = paths.map((path) =>
        pathToRegexp(path, keys, options).source
      );
      return new RegExp(`(?:${parts.join("|")})`, flags(options));
    }
    /**
     * Create a path regexp from string input.
     */
    function stringToRegexp(path, keys, options) {
      return tokensToRegexp(parse(path, options), keys, options);
    }
    /**
     * Expose a function for taking tokens and returning a RegExp.
     */
    function tokensToRegexp(tokens, keys, options = {}) {
      const { strict = false, start = true, end = true, encode = (x) => x } =
        options;
      const endsWith = `[${escapeString(options.endsWith || "")}]|$`;
      const delimiter = `[${escapeString(options.delimiter || "/#?")}]`;
      let route = start ? "^" : "";
      // Iterate over the tokens and create our regexp string.
      for (const token of tokens) {
        if (typeof token === "string") {
          route += escapeString(encode(token));
        } else {
          const prefix = escapeString(encode(token.prefix));
          const suffix = escapeString(encode(token.suffix));
          if (token.pattern) {
            if (keys) {
              keys.push(token);
            }
            if (prefix || suffix) {
              if (token.modifier === "+" || token.modifier === "*") {
                const mod = token.modifier === "*" ? "?" : "";
                route +=
                  `(?:${prefix}((?:${token.pattern})(?:${suffix}${prefix}(?:${token.pattern}))*)${suffix})${mod}`;
              } else {
                route +=
                  `(?:${prefix}(${token.pattern})${suffix})${token.modifier}`;
              }
            } else {
              route += `(${token.pattern})${token.modifier}`;
            }
          } else {
            route += `(?:${prefix}${suffix})${token.modifier}`;
          }
        }
      }
      if (end) {
        if (!strict) {
          route += `${delimiter}?`;
        }
        route += !options.endsWith ? "$" : `(?=${endsWith})`;
      } else {
        const endToken = tokens[tokens.length - 1];
        const isEndDelimited = typeof endToken === "string"
          ? delimiter.indexOf(endToken[endToken.length - 1]) > -1 : // tslint:disable-next-line
            endToken === undefined;
        if (!strict) {
          route += `(?:${delimiter}(?=${endsWith}))?`;
        }
        if (!isEndDelimited) {
          route += `(?=${delimiter}|${endsWith})`;
        }
      }
      return new RegExp(route, flags(options));
    }
    exports_32("tokensToRegexp", tokensToRegexp);
    /**
     * Normalize the given path string, returning a regular expression.
     *
     * An empty array can be passed in for the keys, which will hold the
     * placeholder key descriptions. For example, using `/user/:id`, `keys` will
     * contain `[{ name: 'id', delimiter: '/', optional: false, repeat: false }]`.
     */
    function pathToRegexp(path, keys, options) {
      if (path instanceof RegExp) {
        return regexpToRegexp(path, keys);
      }
      if (Array.isArray(path)) {
        return arrayToRegexp(path, keys, options);
      }
      return stringToRegexp(path, keys, options);
    }
    exports_32("pathToRegexp", pathToRegexp);
    return {
      setters: [],
      execute: function () {
      },
    };
  },
);
// Copyright 2018-2020 the oak authors. All rights reserved. MIT license.
System.register(
  "https://deno.land/x/oak/deps",
  [
    "https://deno.land/std@0.53.0/hash/sha256",
    "https://deno.land/std@0.53.0/http/server",
    "https://deno.land/std@0.53.0/http/http_status",
    "https://deno.land/std@0.53.0/http/cookie",
    "https://deno.land/std@0.53.0/path/mod",
    "https://deno.land/std@0.53.0/testing/asserts",
    "https://deno.land/x/media_types@v2.3.3/mod",
    "https://raw.githubusercontent.com/pillarjs/path-to-regexp/v6.1.0/src/index",
  ],
  function (exports_33, context_33) {
    "use strict";
    var __moduleName = context_33 && context_33.id;
    return {
      setters: [
        function (sha256_ts_1_1) {
          exports_33({
            "HmacSha256": sha256_ts_1_1["HmacSha256"],
          });
        },
        function (server_ts_2_1) {
          exports_33({
            "serve": server_ts_2_1["serve"],
            "Server": server_ts_2_1["Server"],
            "ServerRequest": server_ts_2_1["ServerRequest"],
            "serveTLS": server_ts_2_1["serveTLS"],
          });
        },
        function (http_status_ts_2_1) {
          exports_33({
            "Status": http_status_ts_2_1["Status"],
            "STATUS_TEXT": http_status_ts_2_1["STATUS_TEXT"],
          });
        },
        function (cookie_ts_1_1) {
          exports_33({
            "setCookie": cookie_ts_1_1["setCookie"],
            "getCookies": cookie_ts_1_1["getCookies"],
            "delCookie": cookie_ts_1_1["delCookie"],
          });
        },
        function (mod_ts_7_1) {
          exports_33({
            "basename": mod_ts_7_1["basename"],
            "extname": mod_ts_7_1["extname"],
            "join": mod_ts_7_1["join"],
            "isAbsolute": mod_ts_7_1["isAbsolute"],
            "normalize": mod_ts_7_1["normalize"],
            "parse": mod_ts_7_1["parse"],
            "resolve": mod_ts_7_1["resolve"],
            "sep": mod_ts_7_1["sep"],
          });
        },
        function (asserts_ts_8_1) {
          exports_33({
            "assert": asserts_ts_8_1["assert"],
          });
        },
        function (mod_ts_8_1) {
          exports_33({
            "contentType": mod_ts_8_1["contentType"],
            "lookup": mod_ts_8_1["lookup"],
          });
        },
        function (index_ts_1_1) {
          exports_33({
            "compile": index_ts_1_1["compile"],
            "pathParse": index_ts_1_1["parse"],
            "pathToRegexp": index_ts_1_1["pathToRegexp"],
          });
        },
      ],
      execute: function () {
      },
    };
  },
);
// Copyright 2018-2020 the oak authors. All rights reserved. MIT license.
System.register(
  "https://deno.land/x/oak/tssCompare",
  ["https://deno.land/x/oak/deps"],
  function (exports_34, context_34) {
    "use strict";
    var deps_ts_2;
    var __moduleName = context_34 && context_34.id;
    function compareArrayBuffer(a, b) {
      deps_ts_2.assert(
        a.byteLength === b.byteLength,
        "ArrayBuffer lengths must match.",
      );
      const va = new DataView(a);
      const vb = new DataView(b);
      const length = va.byteLength;
      let out = 0;
      let i = -1;
      while (++i < length) {
        out |= va.getUint8(i) ^ vb.getUint8(i);
      }
      return out === 0;
    }
    /** Compare two strings, Uint8Arrays, ArrayBuffers, or arrays of numbers in a
     * way that avoids timing based attacks on the comparisons on the values.
     *
     * The function will return `true` if the values match, or `false`, if they
     * do not match. */
    function compare(a, b) {
      const key = new Uint8Array(32);
      window.crypto.getRandomValues(key);
      const ah = (new deps_ts_2.HmacSha256(key)).update(a).arrayBuffer();
      const bh = (new deps_ts_2.HmacSha256(key)).update(b).arrayBuffer();
      return compareArrayBuffer(ah, bh);
    }
    exports_34("compare", compare);
    return {
      setters: [
        function (deps_ts_2_1) {
          deps_ts_2 = deps_ts_2_1;
        },
      ],
      execute: function () {
      },
    };
  },
);
// Copyright 2018-2020 the oak authors. All rights reserved. MIT license.
System.register(
  "https://deno.land/x/oak/keyStack",
  ["https://deno.land/x/oak/deps", "https://deno.land/x/oak/tssCompare"],
  function (exports_35, context_35) {
    "use strict";
    var deps_ts_3, tssCompare_ts_1, replacements, KeyStack;
    var __moduleName = context_35 && context_35.id;
    return {
      setters: [
        function (deps_ts_3_1) {
          deps_ts_3 = deps_ts_3_1;
        },
        function (tssCompare_ts_1_1) {
          tssCompare_ts_1 = tssCompare_ts_1_1;
        },
      ],
      execute: function () {
        replacements = {
          "/": "_",
          "+": "-",
          "=": "",
        };
        KeyStack = class KeyStack {
          /** A class which accepts an array of keys that are used to sign and verify
                 * data and allows easy key rotation without invalidation of previously signed
                 * data.
                 *
                 * @param keys An array of keys, of which the index 0 will be used to sign
                 *             data, but verification can happen against any key.
                 */
          constructor(keys) {
            this.#sign = (data, key) => {
              return btoa(
                String.fromCharCode.apply(
                  undefined,
                  new Uint8Array(
                    new deps_ts_3.HmacSha256(key).update(data).arrayBuffer(),
                  ),
                ),
              )
                .replace(/\/|\+|=/g, (c) => replacements[c]);
            };
            if (!(0 in keys)) {
              throw new TypeError("keys must contain at least one value");
            }
            this.#keys = keys;
          }
          #keys;
          #sign;
          /** Take `data` and return a SHA256 HMAC digest that uses the current 0 index
                 * of the `keys` passed to the constructor.  This digest is in the form of a
                 * URL safe base64 encoded string. */
          sign(data) {
            return this.#sign(data, this.#keys[0]);
          }
          /** Given `data` and a `digest`, verify that one of the `keys` provided the
                 * constructor was used to generate the `digest`.  Returns `true` if one of
                 * the keys was used, otherwise `false`. */
          verify(data, digest) {
            return this.indexOf(data, digest) > -1;
          }
          /** Given `data` and a `digest`, return the current index of the key in the
                 * `keys` passed the constructor that was used to generate the digest.  If no
                 * key can be found, the method returns `-1`. */
          indexOf(data, digest) {
            for (let i = 0; i < this.#keys.length; i++) {
              if (
                tssCompare_ts_1.compare(digest, this.#sign(data, this.#keys[i]))
              ) {
                return i;
              }
            }
            return -1;
          }
        };
        exports_35("KeyStack", KeyStack);
      },
    };
  },
);
/*!
 * Adapted directly from http-errors at https://github.com/jshttp/http-errors
 * which is licensed as follows:
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Jonathan Ong me@jongleberry.com
 * Copyright (c) 2016 Douglas Christopher Wilson doug@somethingdoug.com
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
System.register(
  "https://deno.land/x/oak/httpError",
  ["https://deno.land/x/oak/deps"],
  function (exports_36, context_36) {
    "use strict";
    var deps_ts_4, errorStatusMap, HttpError, httpErrors;
    var __moduleName = context_36 && context_36.id;
    function createHttpErrorConstructor(status) {
      const name = `${deps_ts_4.Status[status]}Error`;
      const Ctor = class extends HttpError {
        constructor(message) {
          super();
          this.message = message || deps_ts_4.STATUS_TEXT.get(status);
          this.status = status;
          this.expose = status >= 400 && status < 500 ? true : false;
          Object.defineProperty(this, "name", {
            configurable: true,
            enumerable: false,
            value: name,
            writable: true,
          });
        }
      };
      return Ctor;
    }
    /** Create a specific class of `HttpError` based on the status, which defaults
     * to _500 Internal Server Error_.
     */
    function createHttpError(status = 500, message) {
      return new httpErrors[deps_ts_4.Status[status]](message);
    }
    exports_36("createHttpError", createHttpError);
    function isHttpError(value) {
      return value instanceof HttpError;
    }
    exports_36("isHttpError", isHttpError);
    return {
      setters: [
        function (deps_ts_4_1) {
          deps_ts_4 = deps_ts_4_1;
        },
      ],
      execute: function () {
        errorStatusMap = {
          "BadRequest": 400,
          "Unauthorized": 401,
          "PaymentRequired": 402,
          "Forbidden": 403,
          "NotFound": 404,
          "MethodNotAllowed": 405,
          "NotAcceptable": 406,
          "ProxyAuthRequired": 407,
          "RequestTimeout": 408,
          "Conflict": 409,
          "Gone": 410,
          "LengthRequired": 411,
          "PreconditionFailed": 412,
          "RequestEntityTooLarge": 413,
          "RequestURITooLong": 414,
          "UnsupportedMediaType": 415,
          "RequestedRangeNotSatisfiable": 416,
          "ExpectationFailed": 417,
          "Teapot": 418,
          "MisdirectedRequest": 421,
          "UnprocessableEntity": 422,
          "Locked": 423,
          "FailedDependency": 424,
          "UpgradeRequired": 426,
          "PreconditionRequired": 428,
          "TooManyRequests": 429,
          "RequestHeaderFieldsTooLarge": 431,
          "UnavailableForLegalReasons": 451,
          "InternalServerError": 500,
          "NotImplemented": 501,
          "BadGateway": 502,
          "ServiceUnavailable": 503,
          "GatewayTimeout": 504,
          "HTTPVersionNotSupported": 505,
          "VariantAlsoNegotiates": 506,
          "InsufficientStorage": 507,
          "LoopDetected": 508,
          "NotExtended": 510,
          "NetworkAuthenticationRequired": 511,
        };
        HttpError = class HttpError extends Error {
          constructor() {
            super(...arguments);
            this.expose = false;
            this.status = deps_ts_4.Status.InternalServerError;
          }
        };
        exports_36("HttpError", HttpError);
        exports_36("httpErrors", httpErrors = {});
        for (const [key, value] of Object.entries(errorStatusMap)) {
          httpErrors[key] = createHttpErrorConstructor(value);
        }
      },
    };
  },
);
/*!
 * Adapted directly from media-typer at https://github.com/jshttp/media-typer/
 * which is licensed as follows:
 *
 * media-typer
 * Copyright(c) 2014-2017 Douglas Christopher Wilson
 * MIT Licensed
 */
System.register(
  "https://deno.land/x/oak/mediaTyper",
  [],
  function (exports_37, context_37) {
    "use strict";
    var SUBTYPE_NAME_REGEXP, TYPE_NAME_REGEXP, TYPE_REGEXP, MediaType;
    var __moduleName = context_37 && context_37.id;
    /** Given a media type object, return a media type string.
     *
     *       format({
     *         type: "text",
     *         subtype: "html"
     *       }); // returns "text/html"
     */
    function format(obj) {
      const { subtype, suffix, type } = obj;
      if (!TYPE_NAME_REGEXP.test(type)) {
        throw new TypeError("Invalid type.");
      }
      if (!SUBTYPE_NAME_REGEXP.test(subtype)) {
        throw new TypeError("Invalid subtype.");
      }
      let str = `${type}/${subtype}`;
      if (suffix) {
        if (!TYPE_NAME_REGEXP.test(suffix)) {
          throw new TypeError("Invalid suffix.");
        }
        str += `+${suffix}`;
      }
      return str;
    }
    exports_37("format", format);
    /** Given a media type string, return a media type object.
     *
     *       parse("application/json-patch+json");
     *       // returns {
     *       //   type: "application",
     *       //   subtype: "json-patch",
     *       //   suffix: "json"
     *       // }
     */
    function parse(str) {
      const match = TYPE_REGEXP.exec(str.toLowerCase());
      if (!match) {
        throw new TypeError("Invalid media type.");
      }
      let [, type, subtype] = match;
      let suffix;
      const idx = subtype.lastIndexOf("+");
      if (idx !== -1) {
        suffix = subtype.substr(idx + 1);
        subtype = subtype.substr(0, idx);
      }
      return new MediaType(type, subtype, suffix);
    }
    exports_37("parse", parse);
    return {
      setters: [],
      execute: function () {
        SUBTYPE_NAME_REGEXP = /^[A-Za-z0-9][A-Za-z0-9!#$&^_.-]{0,126}$/;
        TYPE_NAME_REGEXP = /^[A-Za-z0-9][A-Za-z0-9!#$&^_-]{0,126}$/;
        TYPE_REGEXP =
          /^ *([A-Za-z0-9][A-Za-z0-9!#$&^_-]{0,126})\/([A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}) *$/;
        MediaType = class MediaType {
          constructor(
            /** The type of the media type. */
            type,
            /** The subtype of the media type. */
            subtype,
            /** The optional suffix of the media type. */
            suffix,
          ) {
            this.type = type;
            this.subtype = subtype;
            this.suffix = suffix;
          }
        };
      },
    };
  },
);
/*!
 * Adapted directly from type-is at https://github.com/jshttp/type-is/
 * which is licensed as follows:
 *
 * Copyright(c) 2014 Jonathan Ong
 * Copyright(c) 2014-2015 Douglas Christopher Wilson
 * MIT Licensed
 */
System.register(
  "https://deno.land/x/oak/isMediaType",
  ["https://deno.land/x/oak/deps", "https://deno.land/x/oak/mediaTyper"],
  function (exports_38, context_38) {
    "use strict";
    var deps_ts_5, mediaTyper_ts_1;
    var __moduleName = context_38 && context_38.id;
    function mimeMatch(expected, actual) {
      if (expected === undefined) {
        return false;
      }
      const actualParts = actual.split("/");
      const expectedParts = expected.split("/");
      if (actualParts.length !== 2 || expectedParts.length !== 2) {
        return false;
      }
      const [actualType, actualSubtype] = actualParts;
      const [expectedType, expectedSubtype] = expectedParts;
      if (expectedType !== "*" && expectedType !== actualType) {
        return false;
      }
      if (expectedSubtype.substr(0, 2) === "*+") {
        return (expectedSubtype.length <= actualSubtype.length + 1 &&
          expectedSubtype.substr(1) ===
            actualSubtype.substr(1 - expectedSubtype.length));
      }
      if (expectedSubtype !== "*" && expectedSubtype !== actualSubtype) {
        return false;
      }
      return true;
    }
    function normalize(type) {
      switch (type) {
        case "urlencoded":
          return "application/x-www-form-urlencoded";
        case "multipart":
          return "multipart/*";
      }
      if (type[0] === "+") {
        return `*/*${type}`;
      }
      return type.includes("/") ? type : deps_ts_5.lookup(type);
    }
    function normalizeType(value) {
      try {
        const val = value.split(";");
        const type = mediaTyper_ts_1.parse(val[0]);
        return mediaTyper_ts_1.format(type);
      } catch {
        return;
      }
    }
    /** Given a value of the content type of a request and an array of types,
     * provide the matching type or `false` if no types are matched.
     */
    function isMediaType(value, types) {
      const val = normalizeType(value);
      if (!val) {
        return false;
      }
      if (!types.length) {
        return val;
      }
      for (const type of types) {
        if (mimeMatch(normalize(type), val)) {
          return type[0] === "+" || type.includes("*") ? val : type;
        }
      }
      return false;
    }
    exports_38("isMediaType", isMediaType);
    return {
      setters: [
        function (deps_ts_5_1) {
          deps_ts_5 = deps_ts_5_1;
        },
        function (mediaTyper_ts_1_1) {
          mediaTyper_ts_1 = mediaTyper_ts_1_1;
        },
      ],
      execute: function () {
      },
    };
  },
);
/*!
 * Adapted directly from negotiator at https://github.com/jshttp/negotiator/
 * which is licensed as follows:
 *
 * (The MIT License)
 *
 * Copyright (c) 2012-2014 Federico Romero
 * Copyright (c) 2012-2014 Isaac Z. Schlueter
 * Copyright (c) 2014-2015 Douglas Christopher Wilson
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * 'Software'), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
System.register(
  "https://deno.land/x/oak/negotiation/common",
  [],
  function (exports_39, context_39) {
    "use strict";
    var __moduleName = context_39 && context_39.id;
    function compareSpecs(a, b) {
      return (b.q - a.q ||
        (b.s ?? 0) - (a.s ?? 0) ||
        (a.o ?? 0) - (b.o ?? 0) ||
        a.i - b.i ||
        0);
    }
    exports_39("compareSpecs", compareSpecs);
    function isQuality(spec) {
      return spec.q > 0;
    }
    exports_39("isQuality", isQuality);
    return {
      setters: [],
      execute: function () {
      },
    };
  },
);
/*!
 * Adapted directly from negotiator at https://github.com/jshttp/negotiator/
 * which is licensed as follows:
 *
 * (The MIT License)
 *
 * Copyright (c) 2012-2014 Federico Romero
 * Copyright (c) 2012-2014 Isaac Z. Schlueter
 * Copyright (c) 2014-2015 Douglas Christopher Wilson
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * 'Software'), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
System.register(
  "https://deno.land/x/oak/negotiation/charset",
  ["https://deno.land/x/oak/negotiation/common"],
  function (exports_40, context_40) {
    "use strict";
    var common_ts_2, SIMPLE_CHARSET_REGEXP;
    var __moduleName = context_40 && context_40.id;
    function parseCharset(str, i) {
      const match = SIMPLE_CHARSET_REGEXP.exec(str);
      if (!match) {
        return;
      }
      const [, charset] = match;
      let q = 1;
      if (match[2]) {
        const params = match[2].split(";");
        for (const param of params) {
          const [key, value] = param.trim().split("=");
          if (key === "q") {
            q = parseFloat(value);
            break;
          }
        }
      }
      return { charset, q, i };
    }
    function parseAcceptCharset(accept) {
      const accepts = accept.split(",");
      const result = [];
      for (let i = 0; i < accepts.length; i++) {
        const charset = parseCharset(accepts[i].trim(), i);
        if (charset) {
          result.push(charset);
        }
      }
      return result;
    }
    function specify(charset, spec, i) {
      let s = 0;
      if (spec.charset.toLowerCase() === charset.toLocaleLowerCase()) {
        s |= 1;
      } else if (spec.charset !== "*") {
        return;
      }
      return { i, o: spec.i, q: spec.q, s };
    }
    function getCharsetPriority(charset, accepted, index) {
      let priority = { i: -1, o: -1, q: 0, s: 0 };
      for (const accepts of accepted) {
        const spec = specify(charset, accepts, index);
        if (
          spec &&
          ((priority.s ?? 0) - (spec.s ?? 0) || priority.q - spec.q ||
              (priority.o ?? 0) - (spec.o ?? 0)) < 0
        ) {
          priority = spec;
        }
      }
      return priority;
    }
    function preferredCharsets(accept = "*", provided) {
      const accepts = parseAcceptCharset(accept);
      if (!provided) {
        return accepts
          .filter(common_ts_2.isQuality)
          .sort(common_ts_2.compareSpecs)
          .map((spec) => spec.charset);
      }
      const priorities = provided
        .map((type, index) => getCharsetPriority(type, accepts, index));
      return priorities
        .filter(common_ts_2.isQuality)
        .sort(common_ts_2.compareSpecs)
        .map((priority) => provided[priorities.indexOf(priority)]);
    }
    exports_40("preferredCharsets", preferredCharsets);
    return {
      setters: [
        function (common_ts_2_1) {
          common_ts_2 = common_ts_2_1;
        },
      ],
      execute: function () {
        SIMPLE_CHARSET_REGEXP = /^\s*([^\s;]+)\s*(?:;(.*))?$/;
      },
    };
  },
);
/*!
 * Adapted directly from negotiator at https://github.com/jshttp/negotiator/
 * which is licensed as follows:
 *
 * (The MIT License)
 *
 * Copyright (c) 2012-2014 Federico Romero
 * Copyright (c) 2012-2014 Isaac Z. Schlueter
 * Copyright (c) 2014-2015 Douglas Christopher Wilson
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * 'Software'), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
System.register(
  "https://deno.land/x/oak/negotiation/encoding",
  ["https://deno.land/x/oak/negotiation/common"],
  function (exports_41, context_41) {
    "use strict";
    var common_ts_3, simpleEncodingRegExp;
    var __moduleName = context_41 && context_41.id;
    function parseEncoding(str, i) {
      const match = simpleEncodingRegExp.exec(str);
      if (!match) {
        return undefined;
      }
      const encoding = match[1];
      let q = 1;
      if (match[2]) {
        const params = match[2].split(";");
        for (const param of params) {
          const p = param.trim().split("=");
          if (p[0] === "q") {
            q = parseFloat(p[1]);
            break;
          }
        }
      }
      return { encoding, q, i };
    }
    function specify(encoding, spec, i = -1) {
      if (!spec.encoding) {
        return;
      }
      let s = 0;
      if (spec.encoding.toLocaleLowerCase() === encoding.toLocaleLowerCase()) {
        s = 1;
      } else if (spec.encoding !== "*") {
        return;
      }
      return {
        i,
        o: spec.i,
        q: spec.q,
        s,
      };
    }
    function parseAcceptEncoding(accept) {
      const accepts = accept.split(",");
      const parsedAccepts = [];
      let hasIdentity = false;
      let minQuality = 1;
      for (let i = 0; i < accepts.length; i++) {
        const encoding = parseEncoding(accepts[i].trim(), i);
        if (encoding) {
          parsedAccepts.push(encoding);
          hasIdentity = hasIdentity || !!specify("identity", encoding);
          minQuality = Math.min(minQuality, encoding.q || 1);
        }
      }
      if (!hasIdentity) {
        parsedAccepts.push({
          encoding: "identity",
          q: minQuality,
          i: accepts.length - 1,
        });
      }
      return parsedAccepts;
    }
    function getEncodingPriority(encoding, accepted, index) {
      let priority = { o: -1, q: 0, s: 0, i: 0 };
      for (const s of accepted) {
        const spec = specify(encoding, s, index);
        if (
          spec &&
          (priority.s - spec.s || priority.q - spec.q ||
              priority.o - spec.o) <
            0
        ) {
          priority = spec;
        }
      }
      return priority;
    }
    /** Given an `Accept-Encoding` string, parse out the encoding returning a
     * negotiated encoding based on the `provided` encodings otherwise just a
     * prioritized array of encodings. */
    function preferredEncodings(accept, provided) {
      const accepts = parseAcceptEncoding(accept);
      if (!provided) {
        return accepts
          .filter(common_ts_3.isQuality)
          .sort(common_ts_3.compareSpecs)
          .map((spec) => spec.encoding);
      }
      const priorities = provided.map((type, index) =>
        getEncodingPriority(type, accepts, index)
      );
      return priorities
        .filter(common_ts_3.isQuality)
        .sort(common_ts_3.compareSpecs)
        .map((priority) => provided[priorities.indexOf(priority)]);
    }
    exports_41("preferredEncodings", preferredEncodings);
    return {
      setters: [
        function (common_ts_3_1) {
          common_ts_3 = common_ts_3_1;
        },
      ],
      execute: function () {
        simpleEncodingRegExp = /^\s*([^\s;]+)\s*(?:;(.*))?$/;
      },
    };
  },
);
/*!
 * Adapted directly from negotiator at https://github.com/jshttp/negotiator/
 * which is licensed as follows:
 *
 * (The MIT License)
 *
 * Copyright (c) 2012-2014 Federico Romero
 * Copyright (c) 2012-2014 Isaac Z. Schlueter
 * Copyright (c) 2014-2015 Douglas Christopher Wilson
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * 'Software'), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
System.register(
  "https://deno.land/x/oak/negotiation/language",
  ["https://deno.land/x/oak/negotiation/common"],
  function (exports_42, context_42) {
    "use strict";
    var common_ts_4, SIMPLE_LANGUAGE_REGEXP;
    var __moduleName = context_42 && context_42.id;
    function parseLanguage(str, i) {
      const match = SIMPLE_LANGUAGE_REGEXP.exec(str);
      if (!match) {
        return undefined;
      }
      const [, prefix, suffix] = match;
      const full = suffix ? `${prefix}-${suffix}` : prefix;
      let q = 1;
      if (match[3]) {
        const params = match[3].split(";");
        for (const param of params) {
          const [key, value] = param.trim().split("=");
          if (key === "q") {
            q = parseFloat(value);
            break;
          }
        }
      }
      return { prefix, suffix, full, q, i };
    }
    function parseAcceptLanguage(accept) {
      const accepts = accept.split(",");
      const result = [];
      for (let i = 0; i < accepts.length; i++) {
        const language = parseLanguage(accepts[i].trim(), i);
        if (language) {
          result.push(language);
        }
      }
      return result;
    }
    function specify(language, spec, i) {
      const p = parseLanguage(language, i);
      if (!p) {
        return undefined;
      }
      let s = 0;
      if (spec.full.toLowerCase() === p.full.toLowerCase()) {
        s |= 4;
      } else if (spec.prefix.toLowerCase() === p.prefix.toLowerCase()) {
        s |= 2;
      } else if (spec.full.toLowerCase() === p.prefix.toLowerCase()) {
        s |= 1;
      } else if (spec.full !== "*") {
        return;
      }
      return { i, o: spec.i, q: spec.q, s };
    }
    function getLanguagePriority(language, accepted, index) {
      let priority = { i: -1, o: -1, q: 0, s: 0 };
      for (const accepts of accepted) {
        const spec = specify(language, accepts, index);
        if (
          spec &&
          ((priority.s ?? 0) - (spec.s ?? 0) || priority.q - spec.q ||
              (priority.o ?? 0) - (spec.o ?? 0)) < 0
        ) {
          priority = spec;
        }
      }
      return priority;
    }
    function preferredLanguages(accept = "*", provided) {
      const accepts = parseAcceptLanguage(accept);
      if (!provided) {
        return accepts
          .filter(common_ts_4.isQuality)
          .sort(common_ts_4.compareSpecs)
          .map((spec) => spec.full);
      }
      const priorities = provided
        .map((type, index) => getLanguagePriority(type, accepts, index));
      return priorities
        .filter(common_ts_4.isQuality)
        .sort(common_ts_4.compareSpecs)
        .map((priority) => provided[priorities.indexOf(priority)]);
    }
    exports_42("preferredLanguages", preferredLanguages);
    return {
      setters: [
        function (common_ts_4_1) {
          common_ts_4 = common_ts_4_1;
        },
      ],
      execute: function () {
        SIMPLE_LANGUAGE_REGEXP = /^\s*([^\s\-;]+)(?:-([^\s;]+))?\s*(?:;(.*))?$/;
      },
    };
  },
);
/*!
 * Adapted directly from negotiator at https://github.com/jshttp/negotiator/
 * which is licensed as follows:
 *
 * (The MIT License)
 *
 * Copyright (c) 2012-2014 Federico Romero
 * Copyright (c) 2012-2014 Isaac Z. Schlueter
 * Copyright (c) 2014-2015 Douglas Christopher Wilson
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * 'Software'), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
System.register(
  "https://deno.land/x/oak/negotiation/mediaType",
  ["https://deno.land/x/oak/negotiation/common"],
  function (exports_43, context_43) {
    "use strict";
    var common_ts_5, simpleMediaTypeRegExp;
    var __moduleName = context_43 && context_43.id;
    function quoteCount(str) {
      let count = 0;
      let index = 0;
      while ((index = str.indexOf(`"`, index)) !== -1) {
        count++;
        index++;
      }
      return count;
    }
    function splitMediaTypes(accept) {
      const accepts = accept.split(",");
      let j = 0;
      for (let i = 1; i < accepts.length; i++) {
        if (quoteCount(accepts[j]) % 2 === 0) {
          accepts[++j] = accepts[i];
        } else {
          accepts[j] += `,${accepts[i]}`;
        }
      }
      accepts.length = j + 1;
      return accepts;
    }
    function splitParameters(str) {
      const parameters = str.split(";");
      let j = 0;
      for (let i = 1; i < parameters.length; i++) {
        if (quoteCount(parameters[j]) % 2 === 0) {
          parameters[++j] = parameters[i];
        } else {
          parameters[j] += `;${parameters[i]}`;
        }
      }
      parameters.length = j + 1;
      return parameters.map((p) => p.trim());
    }
    function splitKeyValuePair(str) {
      const [key, value] = str.split("=");
      return [key.toLowerCase(), value];
    }
    function parseMediaType(str, i) {
      const match = simpleMediaTypeRegExp.exec(str);
      if (!match) {
        return;
      }
      const params = Object.create(null);
      let q = 1;
      const [, type, subtype, parameters] = match;
      if (parameters) {
        const kvps = splitParameters(parameters).map(splitKeyValuePair);
        for (const [key, val] of kvps) {
          const value = val && val[0] === `"` && val[val.length - 1] === `"`
            ? val.substr(1, val.length - 2)
            : val;
          if (key === "q" && value) {
            q = parseFloat(value);
            break;
          }
          params[key] = value;
        }
      }
      return { type, subtype, params, q, i };
    }
    function parseAccept(accept) {
      const accepts = splitMediaTypes(accept);
      const mediaTypes = [];
      for (let i = 0; i < accepts.length; i++) {
        const mediaType = parseMediaType(accepts[i].trim(), i);
        if (mediaType) {
          mediaTypes.push(mediaType);
        }
      }
      return mediaTypes;
    }
    function getFullType(spec) {
      return `${spec.type}/${spec.subtype}`;
    }
    function specify(type, spec, index) {
      const p = parseMediaType(type, index);
      if (!p) {
        return;
      }
      let s = 0;
      if (spec.type.toLowerCase() === p.type.toLowerCase()) {
        s |= 4;
      } else if (spec.type !== "*") {
        return;
      }
      if (spec.subtype.toLowerCase() === p.subtype.toLowerCase()) {
        s |= 2;
      } else if (spec.subtype !== "*") {
        return;
      }
      const keys = Object.keys(spec.params);
      if (keys.length) {
        if (
          keys.every((key) =>
            (spec.params[key] || "").toLowerCase() ===
              (p.params[key] || "").toLowerCase()
          )
        ) {
          s |= 1;
        } else {
          return;
        }
      }
      return {
        i: index,
        o: spec.o,
        q: spec.q,
        s,
      };
    }
    function getMediaTypePriority(type, accepted, index) {
      let priority = { o: -1, q: 0, s: 0, i: index };
      for (const accepts of accepted) {
        const spec = specify(type, accepts, index);
        if (
          spec &&
          ((priority.s || 0) - (spec.s || 0) ||
              (priority.q || 0) - (spec.q || 0) ||
              (priority.o || 0) - (spec.o || 0)) < 0
        ) {
          priority = spec;
        }
      }
      return priority;
    }
    function preferredMediaTypes(accept, provided) {
      const accepts = parseAccept(accept === undefined ? "*/*" : accept || "");
      if (!provided) {
        return accepts
          .filter(common_ts_5.isQuality)
          .sort(common_ts_5.compareSpecs)
          .map(getFullType);
      }
      const priorities = provided.map((type, index) => {
        return getMediaTypePriority(type, accepts, index);
      });
      return priorities
        .filter(common_ts_5.isQuality)
        .sort(common_ts_5.compareSpecs)
        .map((priority) => provided[priorities.indexOf(priority)]);
    }
    exports_43("preferredMediaTypes", preferredMediaTypes);
    return {
      setters: [
        function (common_ts_5_1) {
          common_ts_5 = common_ts_5_1;
        },
      ],
      execute: function () {
        simpleMediaTypeRegExp = /^\s*([^\s\/;]+)\/([^;\s]+)\s*(?:;(.*))?$/;
      },
    };
  },
);
// Copyright 2018-2020 the oak authors. All rights reserved. MIT license.
System.register(
  "https://deno.land/x/oak/request",
  [
    "https://deno.land/x/oak/httpError",
    "https://deno.land/x/oak/isMediaType",
    "https://deno.land/x/oak/negotiation/charset",
    "https://deno.land/x/oak/negotiation/encoding",
    "https://deno.land/x/oak/negotiation/language",
    "https://deno.land/x/oak/negotiation/mediaType",
  ],
  function (exports_44, context_44) {
    "use strict";
    var httpError_ts_1,
      isMediaType_ts_1,
      charset_ts_1,
      encoding_ts_1,
      language_ts_1,
      mediaType_ts_1,
      decoder,
      defaultBodyContentTypes,
      Request;
    var __moduleName = context_44 && context_44.id;
    return {
      setters: [
        function (httpError_ts_1_1) {
          httpError_ts_1 = httpError_ts_1_1;
        },
        function (isMediaType_ts_1_1) {
          isMediaType_ts_1 = isMediaType_ts_1_1;
        },
        function (charset_ts_1_1) {
          charset_ts_1 = charset_ts_1_1;
        },
        function (encoding_ts_1_1) {
          encoding_ts_1 = encoding_ts_1_1;
        },
        function (language_ts_1_1) {
          language_ts_1 = language_ts_1_1;
        },
        function (mediaType_ts_1_1) {
          mediaType_ts_1 = mediaType_ts_1_1;
        },
      ],
      execute: function () {
        decoder = new TextDecoder();
        defaultBodyContentTypes = {
          json: ["json", "application/*+json", "application/csp-report"],
          form: ["urlencoded"],
          text: ["text"],
        };
        Request = class Request {
          constructor(serverRequest) {
            this.#serverRequest = serverRequest;
          }
          #body;
          #rawBodyPromise;
          #serverRequest;
          #url;
          /** Is `true` if the request has a body, otherwise `false`. */
          get hasBody() {
            return (this.headers.get("transfer-encoding") !== null ||
              !!parseInt(this.headers.get("content-length") ?? ""));
          }
          /** The `Headers` supplied in the request. */
          get headers() {
            return this.#serverRequest.headers;
          }
          /** The HTTP Method used by the request. */
          get method() {
            return this.#serverRequest.method;
          }
          /** Shortcut to `request.url.protocol === "https"`. */
          get secure() {
            return this.url.protocol === "https:";
          }
          /** Returns the _original_ Deno server request. */
          get serverRequest() {
            return this.#serverRequest;
          }
          /** A parsed URL for the request which complies with the browser standards. */
          get url() {
            if (!this.#url) {
              const serverRequest = this.#serverRequest;
              const proto = serverRequest.proto.split("/")[0].toLowerCase();
              this.#url = new URL(
                `${proto}://${
                  serverRequest.headers.get("host")
                }${serverRequest.url}`,
              );
            }
            return this.#url;
          }
          accepts(...types) {
            const acceptValue = this.#serverRequest.headers.get("Accept");
            if (!acceptValue) {
              return;
            }
            if (types.length) {
              return mediaType_ts_1.preferredMediaTypes(acceptValue, types)[0];
            }
            return mediaType_ts_1.preferredMediaTypes(acceptValue);
          }
          acceptsCharsets(...charsets) {
            const acceptCharsetValue = this.#serverRequest.headers.get(
              "Accept-Charset",
            );
            if (!acceptCharsetValue) {
              return;
            }
            if (charsets.length) {
              return charset_ts_1.preferredCharsets(
                acceptCharsetValue,
                charsets,
              )[0];
            }
            return charset_ts_1.preferredCharsets(acceptCharsetValue);
          }
          acceptsEncodings(...encodings) {
            const acceptEncodingValue = this.#serverRequest.headers.get(
              "Accept-Encoding",
            );
            if (!acceptEncodingValue) {
              return;
            }
            if (encodings.length) {
              return encoding_ts_1.preferredEncodings(
                acceptEncodingValue,
                encodings,
              )[0];
            }
            return encoding_ts_1.preferredEncodings(acceptEncodingValue);
          }
          acceptsLanguages(...langs) {
            const acceptLanguageValue = this.#serverRequest.headers.get(
              "Accept-Language",
            );
            if (!acceptLanguageValue) {
              return;
            }
            if (langs.length) {
              return language_ts_1.preferredLanguages(
                acceptLanguageValue,
                langs,
              )[0];
            }
            return language_ts_1.preferredLanguages(acceptLanguageValue);
          }
          async body({ asReader, contentTypes = {} } = {}) {
            if (this.#body) {
              if (asReader && this.#body.type !== "reader") {
                return Promise.reject(
                  new TypeError(
                    `Body already consumed as type: "${this.#body.type}".`,
                  ),
                );
              } else if (this.#body.type === "reader") {
                return Promise.reject(
                  new TypeError(`Body already consumed as type: "reader".`),
                );
              }
              return this.#body;
            }
            const encoding = this.headers.get("content-encoding") || "identity";
            if (encoding !== "identity") {
              throw new httpError_ts_1.httpErrors.UnsupportedMediaType(
                `Unsupported content-encoding: ${encoding}`,
              );
            }
            if (!this.hasBody) {
              return (this.#body = { type: "undefined", value: undefined });
            }
            const contentType = this.headers.get("content-type");
            if (contentType) {
              if (asReader) {
                return (this.#body = {
                  type: "reader",
                  value: this.#serverRequest.body,
                });
              }
              const rawBody = await (this.#rawBodyPromise ??
                (this.#rawBodyPromise = Deno.readAll(
                  this.#serverRequest.body,
                )));
              const value = decoder.decode(rawBody);
              const contentTypesRaw = contentTypes.raw;
              const contentTypesJson = [
                ...defaultBodyContentTypes.json,
                ...(contentTypes.json ?? []),
              ];
              const contentTypesForm = [
                ...defaultBodyContentTypes.form,
                ...(contentTypes.form ?? []),
              ];
              const contentTypesText = [
                ...defaultBodyContentTypes.text,
                ...(contentTypes.text ?? []),
              ];
              if (
                contentTypesRaw &&
                isMediaType_ts_1.isMediaType(contentType, contentTypesRaw)
              ) {
                return (this.#body = { type: "raw", value: rawBody });
              } else if (
                isMediaType_ts_1.isMediaType(contentType, contentTypesJson)
              ) {
                return (this.#body = {
                  type: "json",
                  value: JSON.parse(value),
                });
              } else if (
                isMediaType_ts_1.isMediaType(contentType, contentTypesForm)
              ) {
                return (this.#body = {
                  type: "form",
                  value: new URLSearchParams(value.replace(/\+/g, " ")),
                });
              } else if (
                isMediaType_ts_1.isMediaType(contentType, contentTypesText)
              ) {
                return (this.#body = { type: "text", value });
              } else {
                return (this.#body = { type: "raw", value: rawBody });
              }
            }
            throw new httpError_ts_1.httpErrors.UnsupportedMediaType(
              contentType
                ? `Unsupported content-type: ${contentType}`
                : "Missing content-type",
            );
          }
        };
        exports_44("Request", Request);
      },
    };
  },
);
// Copyright 2018-2020 the oak authors. All rights reserved. MIT license.
System.register(
  "https://deno.land/x/oak/util",
  ["https://deno.land/x/oak/deps", "https://deno.land/x/oak/httpError"],
  function (exports_45, context_45) {
    "use strict";
    var deps_ts_6,
      httpError_ts_2,
      ENCODE_CHARS_REGEXP,
      UNMATCHED_SURROGATE_PAIR_REGEXP,
      UNMATCHED_SURROGATE_PAIR_REPLACE,
      UP_PATH_REGEXP;
    var __moduleName = context_45 && context_45.id;
    /** Safely decode a URI component, where if it fails, instead of throwing,
     * just returns the original string
     */
    function decodeComponent(text) {
      try {
        return decodeURIComponent(text);
      } catch {
        return text;
      }
    }
    exports_45("decodeComponent", decodeComponent);
    /** Encodes the url preventing double enconding */
    function encodeUrl(url) {
      return String(url)
        .replace(
          UNMATCHED_SURROGATE_PAIR_REGEXP,
          UNMATCHED_SURROGATE_PAIR_REPLACE,
        )
        .replace(ENCODE_CHARS_REGEXP, encodeURI);
    }
    exports_45("encodeUrl", encodeUrl);
    /** Determines if a HTTP `Status` is an `ErrorStatus` (4XX or 5XX). */
    function isErrorStatus(value) {
      return [
        deps_ts_6.Status.BadRequest,
        deps_ts_6.Status.Unauthorized,
        deps_ts_6.Status.PaymentRequired,
        deps_ts_6.Status.Forbidden,
        deps_ts_6.Status.NotFound,
        deps_ts_6.Status.MethodNotAllowed,
        deps_ts_6.Status.NotAcceptable,
        deps_ts_6.Status.ProxyAuthRequired,
        deps_ts_6.Status.RequestTimeout,
        deps_ts_6.Status.Conflict,
        deps_ts_6.Status.Gone,
        deps_ts_6.Status.LengthRequired,
        deps_ts_6.Status.PreconditionFailed,
        deps_ts_6.Status.RequestEntityTooLarge,
        deps_ts_6.Status.RequestURITooLong,
        deps_ts_6.Status.UnsupportedMediaType,
        deps_ts_6.Status.RequestedRangeNotSatisfiable,
        deps_ts_6.Status.ExpectationFailed,
        deps_ts_6.Status.Teapot,
        deps_ts_6.Status.MisdirectedRequest,
        deps_ts_6.Status.UnprocessableEntity,
        deps_ts_6.Status.Locked,
        deps_ts_6.Status.FailedDependency,
        deps_ts_6.Status.UpgradeRequired,
        deps_ts_6.Status.PreconditionRequired,
        deps_ts_6.Status.TooManyRequests,
        deps_ts_6.Status.RequestHeaderFieldsTooLarge,
        deps_ts_6.Status.UnavailableForLegalReasons,
        deps_ts_6.Status.InternalServerError,
        deps_ts_6.Status.NotImplemented,
        deps_ts_6.Status.BadGateway,
        deps_ts_6.Status.ServiceUnavailable,
        deps_ts_6.Status.GatewayTimeout,
        deps_ts_6.Status.HTTPVersionNotSupported,
        deps_ts_6.Status.VariantAlsoNegotiates,
        deps_ts_6.Status.InsufficientStorage,
        deps_ts_6.Status.LoopDetected,
        deps_ts_6.Status.NotExtended,
        deps_ts_6.Status.NetworkAuthenticationRequired,
      ].includes(value);
    }
    exports_45("isErrorStatus", isErrorStatus);
    /** Determines if a HTTP `Status` is a `RedirectStatus` (3XX). */
    function isRedirectStatus(value) {
      return [
        deps_ts_6.Status.MultipleChoices,
        deps_ts_6.Status.MovedPermanently,
        deps_ts_6.Status.Found,
        deps_ts_6.Status.SeeOther,
        deps_ts_6.Status.UseProxy,
        deps_ts_6.Status.TemporaryRedirect,
        deps_ts_6.Status.PermanentRedirect,
      ].includes(value);
    }
    exports_45("isRedirectStatus", isRedirectStatus);
    /** Determines if a string "looks" like HTML */
    function isHtml(value) {
      return /^\s*<(?:!DOCTYPE|html|body)/i.test(value);
    }
    exports_45("isHtml", isHtml);
    function resolvePath(rootPath, relativePath) {
      let path = relativePath;
      let root = rootPath;
      // root is optional, similar to root.resolve
      if (arguments.length === 1) {
        path = rootPath;
        root = Deno.cwd();
      }
      if (path == null) {
        throw new TypeError("Argument relativePath is required.");
      }
      // containing NULL bytes is malicious
      if (path.includes("\0")) {
        throw httpError_ts_2.createHttpError(400, "Malicious Path");
      }
      // path should never be absolute
      if (deps_ts_6.isAbsolute(path)) {
        throw httpError_ts_2.createHttpError(400, "Malicious Path");
      }
      // path outside root
      if (
        UP_PATH_REGEXP.test(deps_ts_6.normalize("." + deps_ts_6.sep + path))
      ) {
        throw httpError_ts_2.createHttpError(403);
      }
      // join the relative path
      return deps_ts_6.normalize(deps_ts_6.join(deps_ts_6.resolve(root), path));
    }
    exports_45("resolvePath", resolvePath);
    return {
      setters: [
        function (deps_ts_6_1) {
          deps_ts_6 = deps_ts_6_1;
        },
        function (httpError_ts_2_1) {
          httpError_ts_2 = httpError_ts_2_1;
        },
      ],
      execute: function () {
        ENCODE_CHARS_REGEXP =
          /(?:[^\x21\x25\x26-\x3B\x3D\x3F-\x5B\x5D\x5F\x61-\x7A\x7E]|%(?:[^0-9A-Fa-f]|[0-9A-Fa-f][^0-9A-Fa-f]|$))+/g;
        UNMATCHED_SURROGATE_PAIR_REGEXP =
          /(^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]|[\uD800-\uDBFF]([^\uDC00-\uDFFF]|$)/g;
        UNMATCHED_SURROGATE_PAIR_REPLACE = "$1\uFFFD$2";
        /*!
             * Adapted directly from https://github.com/pillarjs/resolve-path
             * which is licensed as follows:
             *
             * The MIT License (MIT)
             *
             * Copyright (c) 2014 Jonathan Ong <me@jongleberry.com>
             * Copyright (c) 2015-2018 Douglas Christopher Wilson <doug@somethingdoug.com>
             *
             * Permission is hereby granted, free of charge, to any person obtaining
             * a copy of this software and associated documentation files (the
             * 'Software'), to deal in the Software without restriction, including
             * without limitation the rights to use, copy, modify, merge, publish,
             * distribute, sublicense, and/or sell copies of the Software, and to
             * permit persons to whom the Software is furnished to do so, subject to
             * the following conditions:
             *
             * The above copyright notice and this permission notice shall be
             * included in all copies or substantial portions of the Software.
             *
             * THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
             * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
             * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
             * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
             * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
             * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
             * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
             */
        UP_PATH_REGEXP = /(?:^|[\\/])\.\.(?:[\\/]|$)/;
      },
    };
  },
);
// Copyright 2018-2020 the oak authors. All rights reserved. MIT license.
System.register(
  "https://deno.land/x/oak/response",
  ["https://deno.land/x/oak/deps", "https://deno.land/x/oak/util"],
  function (exports_46, context_46) {
    "use strict";
    var deps_ts_7, util_ts_4, REDIRECT_BACK, BODY_TYPES, encoder, Response;
    var __moduleName = context_46 && context_46.id;
    /** Guard for `Deno.Reader`. */
    function isReader(value) {
      return typeof value === "object" && "read" in value &&
        typeof value.read === "function";
    }
    return {
      setters: [
        function (deps_ts_7_1) {
          deps_ts_7 = deps_ts_7_1;
        },
        function (util_ts_4_1) {
          util_ts_4 = util_ts_4_1;
        },
      ],
      execute: function () {
        exports_46(
          "REDIRECT_BACK",
          REDIRECT_BACK = Symbol("redirect backwards"),
        );
        BODY_TYPES = ["string", "number", "bigint", "boolean", "symbol"];
        encoder = new TextEncoder();
        Response = class Response {
          constructor(request) {
            this.#writable = true;
            this.#getBody = () => {
              const typeofBody = typeof this.body;
              let result;
              this.#writable = false;
              if (BODY_TYPES.includes(typeofBody)) {
                const bodyText = String(this.body);
                result = encoder.encode(bodyText);
                this.type = this.type ||
                  (util_ts_4.isHtml(bodyText) ? "html" : "text/plain");
              } else if (
                this.body instanceof Uint8Array || isReader(this.body)
              ) {
                result = this.body;
              } else if (typeofBody === "object" && this.body !== null) {
                result = encoder.encode(JSON.stringify(this.body));
                this.type = this.type || "json";
              }
              return result;
            };
            this.#setContentType = () => {
              if (this.type) {
                const contentTypeString = deps_ts_7.contentType(this.type);
                if (contentTypeString && !this.headers.has("Content-Type")) {
                  this.headers.append("Content-Type", contentTypeString);
                }
              }
            };
            /** Headers that will be returned in the response */
            this.headers = new Headers();
            this.#request = request;
          }
          #request;
          #writable;
          #getBody;
          #setContentType;
          get writable() {
            return this.#writable;
          }
          redirect(url, alt = "/") {
            if (url === REDIRECT_BACK) {
              url = this.#request.headers.get("Referrer") ?? String(alt);
            } else if (typeof url === "object") {
              url = String(url);
            }
            this.headers.set("Location", util_ts_4.encodeUrl(url));
            if (!this.status || !util_ts_4.isRedirectStatus(this.status)) {
              this.status = deps_ts_7.Status.Found;
            }
            if (this.#request.accepts("html")) {
              url = encodeURI(url);
              this.type = "text/html; charset=utf-8";
              this.body = `Redirecting to <a href="${url}">${url}</a>.`;
              return;
            }
            this.type = "text/plain; charset=utf-8";
            this.body = `Redirecting to ${url}.`;
          }
          /** Take this response and convert it to the response used by the Deno net
                 * server. */
          toServerResponse() {
            // Process the body
            const body = this.#getBody();
            // If there is a response type, set the content type header
            this.#setContentType();
            const { headers, status } = this;
            // If there is no body and no content type and no set length, then set the
            // content length to 0
            if (
              !(body ||
                headers.has("Content-Type") ||
                headers.has("Content-Length"))
            ) {
              headers.append("Content-Length", "0");
            }
            return {
              status: status ??
                (body ? deps_ts_7.Status.OK : deps_ts_7.Status.NotFound),
              body,
              headers,
            };
          }
        };
        exports_46("Response", Response);
      },
    };
  },
);
// Copyright 2018-2020 the oak authors. All rights reserved. MIT license.
System.register(
  "https://deno.land/x/oak/cookies",
  [],
  function (exports_47, context_47) {
    "use strict";
    var matchCache,
      FIELD_CONTENT_REGEXP,
      KEY_REGEXP,
      SAME_SITE_REGEXP,
      Cookie,
      Cookies;
    var __moduleName = context_47 && context_47.id;
    function getPattern(name) {
      if (name in matchCache) {
        return matchCache[name];
      }
      return matchCache[name] = new RegExp(
        `(?:^|;) *${name.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&")}=([^;]*)`,
      );
    }
    function pushCookie(headers, cookie) {
      if (cookie.overwrite) {
        for (let i = headers.length - 1; i >= 0; i--) {
          if (headers[i].indexOf(`${cookie.name}=`) === 0) {
            headers.splice(i, 1);
          }
        }
      }
      headers.push(cookie.toHeader());
    }
    function validateCookieProperty(key, value) {
      if (value && !FIELD_CONTENT_REGEXP.test(value)) {
        throw new TypeError(`The ${key} of the cookie (${value}) is invalid.`);
      }
    }
    return {
      setters: [],
      execute: function () {
        matchCache = {};
        FIELD_CONTENT_REGEXP = /^[\u0009\u0020-\u007e\u0080-\u00ff]+$/;
        KEY_REGEXP = /(?:^|;) *([^=]*)=[^;]*/g;
        SAME_SITE_REGEXP = /^(?:lax|none|strict)$/i;
        Cookie = class Cookie {
          /** A logical representation of a cookie, used to internally manage the
                 * cookie instances. */
          constructor(name, value, attributes) {
            this.httpOnly = true;
            this.overwrite = false;
            this.path = "/";
            this.sameSite = false;
            this.secure = false;
            validateCookieProperty("name", name);
            validateCookieProperty("value", value);
            this.name = name;
            this.value = value ?? "";
            Object.assign(this, attributes);
            if (!this.value) {
              this.expires = new Date(0);
              this.maxAge = undefined;
            }
            validateCookieProperty("path", this.path);
            validateCookieProperty("domain", this.domain);
            if (
              this.sameSite && typeof this.sameSite === "string" &&
              !SAME_SITE_REGEXP.test(this.sameSite)
            ) {
              throw new TypeError(
                `The sameSite of the cookie ("${this.sameSite}") is invalid.`,
              );
            }
          }
          toHeader() {
            let header = this.toString();
            if (this.maxAge) {
              this.expires = new Date(Date.now() + this.maxAge);
            }
            if (this.path) {
              header += `; path=${this.path}`;
            }
            if (this.expires) {
              header += `; expires=${this.expires.toUTCString()}`;
            }
            if (this.domain) {
              header += `; domain=${this.domain}`;
            }
            if (this.sameSite) {
              header += `; samesite=${
                this.sameSite === true ? "strict" : this.sameSite.toLowerCase()
              }`;
            }
            if (this.secure) {
              header += "; secure";
            }
            if (this.httpOnly) {
              header += "; httponly";
            }
            return header;
          }
          toString() {
            return `${this.name}=${this.value}`;
          }
        };
        Cookies = class Cookies {
          constructor(request, response, options = {}) {
            this.#requestKeys = () => {
              if (this.#cookieKeys) {
                return this.#cookieKeys;
              }
              const result = this.#cookieKeys = [];
              const header = this.#request.headers.get("cookie");
              if (!header) {
                return result;
              }
              let matches;
              while ((matches = KEY_REGEXP.exec(header))) {
                const [, key] = matches;
                result.push(key);
              }
              return result;
            };
            const { keys, secure } = options;
            this.#keys = keys;
            this.#request = request;
            this.#response = response;
            this.#secure = secure;
          }
          #cookieKeys;
          #keys;
          #request;
          #response;
          #secure;
          #requestKeys;
          /** Set a cookie to be deleted in the response.  This is a "shortcut" to
                 * `.set(name, null, options?)`. */
          delete(name, options = {}) {
            this.set(name, null, options);
            return true;
          }
          /** Iterate over the request's cookies, yielding up a tuple containing the
                 * key and the value.
                 *
                 * If there are keys set on the application, only keys and values that are
                 * properly signed will be returned. */
          *entries() {
            const keys = this.#requestKeys();
            for (const key of keys) {
              const value = this.get(key);
              if (value) {
                yield [key, value];
              }
            }
          }
          forEach(callback, thisArg = null) {
            const keys = this.#requestKeys();
            for (const key of keys) {
              const value = this.get(key);
              if (value) {
                callback.call(thisArg, key, value, this);
              }
            }
          }
          /** Get the value of a cookie from the request.
                 *
                 * If the cookie is signed, and the signature is invalid, the cookie will
                 * be set to be deleted in the the response.  If the signature uses an "old"
                 * key, the cookie will be re-signed with the current key and be added to the
                 * response to be updated. */
          get(name, options = {}) {
            const signed = options.signed ?? !!this.#keys;
            const nameSig = `${name}.sig`;
            const header = this.#request.headers.get("cookie");
            if (!header) {
              return;
            }
            const match = header.match(getPattern(name));
            if (!match) {
              return;
            }
            const [, value] = match;
            if (!signed) {
              return value;
            }
            const digest = this.get(nameSig, { signed: false });
            if (!digest) {
              return;
            }
            const data = `${name}=${value}`;
            if (!this.#keys) {
              throw new TypeError("keys required for signed cookies");
            }
            const index = this.#keys.indexOf(data, digest);
            if (index < 0) {
              this.delete(nameSig, { path: "/", signed: false });
            } else {
              if (index) {
                // the key has "aged" and needs to be re-signed
                this.set(nameSig, this.#keys.sign(data), { signed: false });
              }
              return value;
            }
          }
          /** Iterate over the request's cookies, yielding up the keys.
                 *
                 * If there are keys set on the application, only the keys that are properly
                 * signed will be returned. */
          *keys() {
            const keys = this.#requestKeys();
            for (const key of keys) {
              const value = this.get(key);
              if (value) {
                yield key;
              }
            }
          }
          /** Set a cookie in the response.
                 *
                 * If there are keys set in the application, cookies will be automatically
                 * signed, unless overridden by the set options.  Cookies can be deleted by
                 * setting the value to `null`. */
          set(name, value, options = {}) {
            const request = this.#request;
            const response = this.#response;
            let headers = response.headers.get("Set-Cookie") ?? [];
            if (typeof headers === "string") {
              headers = [headers];
            }
            const secure = this.#secure !== undefined ? this.#secure
            : request.secure;
            const signed = options.signed ?? !!this.#keys;
            if (!secure && options.secure) {
              throw new TypeError(
                "Cannot send secure cookie over unencrypted connection.",
              );
            }
            const cookie = new Cookie(name, value, options);
            cookie.secure = options.secure ?? secure;
            pushCookie(headers, cookie);
            if (signed) {
              if (!this.#keys) {
                throw new TypeError(".keys required for signed cookies.");
              }
              cookie.value = this.#keys.sign(cookie.toString());
              cookie.name += ".sig";
              pushCookie(headers, cookie);
            }
            for (const header of headers) {
              response.headers.append("Set-Cookie", header);
            }
            return this;
          }
          /** Iterate over the request's cookies, yielding up each value.
                 *
                 * If there are keys set on the application, only the values that are
                 * properly signed will be returned. */
          *values() {
            const keys = this.#requestKeys();
            for (const key of keys) {
              const value = this.get(key);
              if (value) {
                yield value;
              }
            }
          }
          /** Iterate over the request's cookies, yielding up a tuple containing the
                 * key and the value.
                 *
                 * If there are keys set on the application, only keys and values that are
                 * properly signed will be returned. */
          *[Symbol.iterator]() {
            const keys = this.#requestKeys();
            for (const key of keys) {
              const value = this.get(key);
              if (value) {
                yield [key, value];
              }
            }
          }
        };
        exports_47("Cookies", Cookies);
      },
    };
  },
);
/*!
 * Adapted from koa-send at https://github.com/koajs/send and which is licensed
 * with the MIT license.
 */
System.register(
  "https://deno.land/x/oak/send",
  [
    "https://deno.land/x/oak/httpError",
    "https://deno.land/x/oak/deps",
    "https://deno.land/x/oak/util",
  ],
  function (exports_48, context_48) {
    "use strict";
    var httpError_ts_3, deps_ts_8, util_ts_5;
    var __moduleName = context_48 && context_48.id;
    function isHidden(root, path) {
      const pathArr = path.substr(root.length).split(deps_ts_8.sep);
      for (const segment of pathArr) {
        if (segment[0] === ".") {
          return true;
        }
        return false;
      }
    }
    async function exists(path) {
      try {
        return (await Deno.stat(path)).isFile;
      } catch {
        return false;
      }
    }
    /** Asynchronously fulfill a response with a file from the local file
     * system.
     *
     * Requires Deno read permission. */
    async function send({ request, response }, path, options = { root: "" }) {
      const {
        brotli = true,
        extensions,
        format = true,
        gzip = true,
        index,
        hidden = false,
        immutable = false,
        maxage = 0,
        root,
      } = options;
      const trailingSlash = path[path.length - 1] === "/";
      path = util_ts_5.decodeComponent(
        path.substr(deps_ts_8.parse(path).root.length),
      );
      if (index && trailingSlash) {
        path += index;
      }
      path = util_ts_5.resolvePath(root, path);
      if (!hidden && isHidden(root, path)) {
        return;
      }
      let encodingExt = "";
      if (
        brotli &&
        request.acceptsEncodings("br", "identity") === "br" &&
        (await exists(`${path}.br`))
      ) {
        path = `${path}.br`;
        response.headers.set("Content-Encoding", "br");
        response.headers.delete("Content-Length");
        encodingExt = ".br";
      } else if (
        gzip &&
        request.acceptsEncodings("gzip", "identity") === "gzip" &&
        (await exists(`${path}.gz`))
      ) {
        path = `${path}.gz`;
        response.headers.set("Content-Encoding", "gzip");
        response.headers.delete("Content-Length");
        encodingExt = ".gz";
      }
      if (extensions && !/\.[^/]*$/.exec(path)) {
        for (let ext of extensions) {
          if (!/^\./.exec(ext)) {
            ext = `.${ext}`;
          }
          if (await exists(`${path}${ext}`)) {
            path += ext;
            break;
          }
        }
      }
      let stats;
      try {
        stats = await Deno.stat(path);
        if (stats.isDirectory) {
          if (format && index) {
            path += `/${index}`;
            stats = await Deno.stat(path);
          } else {
            return;
          }
        }
      } catch (err) {
        if (err instanceof Deno.errors.NotFound) {
          throw httpError_ts_3.createHttpError(404, err.message);
        }
        throw httpError_ts_3.createHttpError(500, err.message);
      }
      response.headers.set("Content-Length", String(stats.size));
      if (!response.headers.has("Last-Modified") && stats.mtime) {
        response.headers.set("Last-Modified", stats.mtime.toUTCString());
      }
      if (!response.headers.has("Cache-Control")) {
        const directives = [`max-age=${(maxage / 1000) | 0}`];
        if (immutable) {
          directives.push("immutable");
        }
        response.headers.set("Cache-Control", directives.join(","));
      }
      if (!response.type) {
        response.type = encodingExt !== ""
          ? deps_ts_8.extname(deps_ts_8.basename(path, encodingExt))
          : deps_ts_8.extname(path);
      }
      response.body = await Deno.readFile(path);
      return path;
    }
    exports_48("send", send);
    return {
      setters: [
        function (httpError_ts_3_1) {
          httpError_ts_3 = httpError_ts_3_1;
        },
        function (deps_ts_8_1) {
          deps_ts_8 = deps_ts_8_1;
        },
        function (util_ts_5_1) {
          util_ts_5 = util_ts_5_1;
        },
      ],
      execute: function () {
      },
    };
  },
);
// Copyright 2018-2020 the oak authors. All rights reserved. MIT license.
System.register(
  "https://deno.land/x/oak/context",
  [
    "https://deno.land/x/oak/cookies",
    "https://deno.land/x/oak/httpError",
    "https://deno.land/x/oak/request",
    "https://deno.land/x/oak/response",
    "https://deno.land/x/oak/send",
  ],
  function (exports_49, context_49) {
    "use strict";
    var cookies_ts_1,
      httpError_ts_4,
      request_ts_1,
      response_ts_1,
      send_ts_1,
      Context;
    var __moduleName = context_49 && context_49.id;
    return {
      setters: [
        function (cookies_ts_1_1) {
          cookies_ts_1 = cookies_ts_1_1;
        },
        function (httpError_ts_4_1) {
          httpError_ts_4 = httpError_ts_4_1;
        },
        function (request_ts_1_1) {
          request_ts_1 = request_ts_1_1;
        },
        function (response_ts_1_1) {
          response_ts_1 = response_ts_1_1;
        },
        function (send_ts_1_1) {
          send_ts_1 = send_ts_1_1;
        },
      ],
      execute: function () {
        Context = class Context {
          constructor(app, serverRequest) {
            this.app = app;
            this.state = app.state;
            this.request = new request_ts_1.Request(serverRequest);
            this.response = new response_ts_1.Response(this.request);
            this.cookies = new cookies_ts_1.Cookies(
              this.request,
              this.response,
              {
                keys: this.app.keys,
                secure: this.request.secure,
              },
            );
          }
          /** Asserts the condition and if the condition fails, creates an HTTP error
                 * with the provided status (which defaults to `500`).  The error status by
                 * default will be set on the `.response.status`.
                 */
          assert(condition, errorStatus = 500, message, props) {
            if (condition) {
              return;
            }
            const err = httpError_ts_4.createHttpError(errorStatus, message);
            if (props) {
              Object.assign(err, props);
            }
            throw err;
          }
          /** Asynchronously fulfill a response with a file from the local file
                 * system.
                 *
                 * If the `options.path` is not supplied, the file to be sent will default
                 * to this `.request.url.pathname`.
                 *
                 * Requires Deno read permission. */
          send(options) {
            const { path = this.request.url.pathname, ...sendOptions } =
              options;
            return send_ts_1.send(this, path, sendOptions);
          }
          /** Create and throw an HTTP Error, which can be used to pass status
                 * information which can be caught by other middleware to send more
                 * meaningful error messages back to the client.  The passed error status will
                 * be set on the `.response.status` by default as well.
                 */
          throw(errorStatus, message, props) {
            const err = httpError_ts_4.createHttpError(errorStatus, message);
            if (props) {
              Object.assign(err, props);
            }
            throw err;
          }
        };
        exports_49("Context", Context);
      },
    };
  },
);
// Copyright 2018-2020 the oak authors. All rights reserved. MIT license.
System.register(
  "https://deno.land/x/oak/middleware",
  [],
  function (exports_50, context_50) {
    "use strict";
    var __moduleName = context_50 && context_50.id;
    /** Compose multiple middleware functions into a single middleware function. */
    function compose(middleware) {
      return function composedMiddleware(context, next) {
        let index = -1;
        function dispatch(i) {
          if (i <= index) {
            Promise.reject(new Error("next() called multiple times."));
          }
          index = i;
          let fn = middleware[i];
          if (i === middleware.length) {
            fn = next;
          }
          if (!fn) {
            return Promise.resolve();
          }
          try {
            return Promise.resolve(fn(context, dispatch.bind(null, i + 1)));
          } catch (err) {
            return Promise.reject(err);
          }
        }
        return dispatch(0);
      };
    }
    exports_50("compose", compose);
    return {
      setters: [],
      execute: function () {
      },
    };
  },
);
// Copyright 2018-2020 the oak authors. All rights reserved. MIT license.
System.register(
  "https://deno.land/x/oak/application",
  [
    "https://deno.land/x/oak/context",
    "https://deno.land/x/oak/deps",
    "https://deno.land/x/oak/keyStack",
    "https://deno.land/x/oak/middleware",
  ],
  function (exports_51, context_51) {
    "use strict";
    var context_ts_1,
      deps_ts_9,
      keyStack_ts_1,
      middleware_ts_1,
      ADDR_REGEXP,
      ApplicationErrorEvent,
      Application;
    var __moduleName = context_51 && context_51.id;
    function isOptionsTls(options) {
      return options.secure === true;
    }
    return {
      setters: [
        function (context_ts_1_1) {
          context_ts_1 = context_ts_1_1;
        },
        function (deps_ts_9_1) {
          deps_ts_9 = deps_ts_9_1;
        },
        function (keyStack_ts_1_1) {
          keyStack_ts_1 = keyStack_ts_1_1;
        },
        function (middleware_ts_1_1) {
          middleware_ts_1 = middleware_ts_1_1;
        },
      ],
      execute: function () {
        ADDR_REGEXP = /^\[?([^\]]*)\]?:([0-9]{1,5})$/;
        ApplicationErrorEvent = class ApplicationErrorEvent extends ErrorEvent {
          constructor(type, eventInitDict) {
            super(type, eventInitDict);
            this.context = eventInitDict.context;
          }
        };
        exports_51("ApplicationErrorEvent", ApplicationErrorEvent);
        /** A class which registers middleware (via `.use()`) and then processes
             * inbound requests against that middleware (via `.listen()`).
             *
             * The `context.state` can be typed via passing a generic argument when
             * constructing an instance of `Application`.
             */
        Application = class Application extends EventTarget {
          constructor(options = {}) {
            super();
            this.#middleware = [];
            /** Deal with uncaught errors in either the middleware or sending the
                     * response. */
            this.#handleError = (context, error) => {
              if (!(error instanceof Error)) {
                error = new Error(`non-error thrown: ${JSON.stringify(error)}`);
              }
              const { message } = error;
              this.dispatchEvent(
                new ApplicationErrorEvent("error", { context, message, error }),
              );
              if (!context.response.writable) {
                return;
              }
              for (const key of context.response.headers.keys()) {
                context.response.headers.delete(key);
              }
              if (error.headers && error.headers instanceof Headers) {
                for (const [key, value] of error.headers) {
                  context.response.headers.set(key, value);
                }
              }
              context.response.type = "text";
              const status = context.response.status =
                error instanceof Deno.errors.NotFound ? 404
                : error.status && typeof error.status === "number"
                ? error.status
                : 500;
              context.response.body = error.expose
                ? error.message
                : deps_ts_9.STATUS_TEXT.get(status);
            };
            /** Processing registered middleware on each request. */
            this.#handleRequest = async (request, state) => {
              const context = new context_ts_1.Context(this, request);
              if (!state.closing && !state.closed) {
                state.handling = true;
                try {
                  await state.middleware(context);
                } catch (err) {
                  this.#handleError(context, err);
                } finally {
                  state.handling = false;
                }
              }
              try {
                await request.respond(context.response.toServerResponse());
                if (state.closing) {
                  state.server.close();
                  state.closed = true;
                }
              } catch (err) {
                this.#handleError(context, err);
              }
            };
            const {
              state,
              keys,
              serve = deps_ts_9.serve,
              serveTls = deps_ts_9.serveTLS,
            } = options;
            this.keys = keys;
            this.state = state ?? {};
            this.#serve = serve;
            this.#serveTls = serveTls;
          }
          #keys;
          #middleware;
          #serve;
          #serveTls;
          /** A set of keys, or an instance of `KeyStack` which will be used to sign
                 * cookies read and set by the application to avoid tampering with the
                 * cookies. */
          get keys() {
            return this.#keys;
          }
          set keys(keys) {
            if (!keys) {
              this.#keys = undefined;
              return;
            } else if (Array.isArray(keys)) {
              this.#keys = new keyStack_ts_1.KeyStack(keys);
            } else {
              this.#keys = keys;
            }
          }
          /** Deal with uncaught errors in either the middleware or sending the
                 * response. */
          #handleError;
          /** Processing registered middleware on each request. */
          #handleRequest;
          addEventListener(type, listener, options) {
            super.addEventListener(type, listener, options);
          }
          async listen(options) {
            if (!this.#middleware.length) {
              return Promise.reject(
                new TypeError("There is no middleware to process requests."),
              );
            }
            if (typeof options === "string") {
              const match = ADDR_REGEXP.exec(options);
              if (!match) {
                throw TypeError(`Invalid address passed: "${options}"`);
              }
              const [, hostname, portStr] = match;
              options = { hostname, port: parseInt(portStr, 10) };
            }
            const middleware = middleware_ts_1.compose(this.#middleware);
            const server = isOptionsTls(options)
              ? this.#serveTls(options)
              : this.#serve(options);
            const { signal } = options;
            const state = {
              closed: false,
              closing: false,
              handling: false,
              middleware,
              server,
            };
            if (signal) {
              signal.addEventListener("abort", () => {
                if (!state.handling) {
                  server.close();
                  state.closed = true;
                }
                state.closing = true;
              });
            }
            try {
              for await (const request of server) {
                this.#handleRequest(request, state);
              }
            } catch (error) {
              const message = error instanceof Error
                ? error.message
                : "Application Error";
              this.dispatchEvent(
                new ApplicationErrorEvent("error", { message, error }),
              );
            }
          }
          /** Register middleware to be used with the application. */
          use(...middleware) {
            this.#middleware.push(...middleware);
            return this;
          }
        };
        exports_51("Application", Application);
      },
    };
  },
);
/**
 * Adapted directly from @koa/router at
 * https://github.com/koajs/router/ which is licensed as:
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Alexander C. Mingoia
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
System.register(
  "https://deno.land/x/oak/router",
  [
    "https://deno.land/x/oak/deps",
    "https://deno.land/x/oak/httpError",
    "https://deno.land/x/oak/middleware",
    "https://deno.land/x/oak/util",
  ],
  function (exports_52, context_52) {
    "use strict";
    var deps_ts_10, httpError_ts_5, middleware_ts_2, util_ts_6, Layer, Router;
    var __moduleName = context_52 && context_52.id;
    /** Generate a URL from a string, potentially replace route params with
     * values. */
    function toUrl(url, params = {}, options) {
      const tokens = deps_ts_10.pathParse(url);
      let replace = {};
      if (tokens.some((token) => typeof token === "object")) {
        replace = params;
      } else {
        options = params;
      }
      const toPath = deps_ts_10.compile(url, options);
      let replaced = toPath(replace);
      if (options && options.query) {
        const url = new URL(replaced, "http://oak");
        if (typeof options.query === "string") {
          url.search = options.query;
        } else {
          url.search = String(
            options.query instanceof URLSearchParams
              ? options.query
              : new URLSearchParams(options.query),
          );
        }
        return `${url.pathname}${url.search}${url.hash}`;
      }
      return replaced;
    }
    return {
      setters: [
        function (deps_ts_10_1) {
          deps_ts_10 = deps_ts_10_1;
        },
        function (httpError_ts_5_1) {
          httpError_ts_5 = httpError_ts_5_1;
        },
        function (middleware_ts_2_1) {
          middleware_ts_2 = middleware_ts_2_1;
        },
        function (util_ts_6_1) {
          util_ts_6 = util_ts_6_1;
        },
      ],
      execute: function () {
        Layer = class Layer {
          constructor(path, methods, middleware, { name, ...opts } = {}) {
            this.#paramNames = [];
            this.#opts = opts;
            this.name = name;
            this.methods = [...methods];
            if (this.methods.includes("GET")) {
              this.methods.unshift("HEAD");
            }
            this.stack = Array.isArray(middleware) ? middleware : [middleware];
            this.path = path;
            this.#regexp = deps_ts_10.pathToRegexp(
              path,
              this.#paramNames,
              this.#opts,
            );
          }
          #opts;
          #paramNames;
          #regexp;
          match(path) {
            return this.#regexp.test(path);
          }
          params(captures, existingParams = {}) {
            const params = existingParams;
            for (let i = 0; i < captures.length; i++) {
              if (this.#paramNames[i]) {
                const c = captures[i];
                params[this.#paramNames[i].name] = c
                  ? util_ts_6.decodeComponent(c) : c;
              }
            }
            return params;
          }
          captures(path) {
            if (this.#opts.ignoreCaptures) {
              return [];
            }
            return path.match(this.#regexp)?.slice(1) ?? [];
          }
          url(params = {}, options) {
            const url = this.path.replace(/\(\.\*\)/g, "");
            return toUrl(url, params, options);
          }
          param(param, fn) {
            const stack = this.stack;
            const params = this.#paramNames;
            const middleware = function (ctx, next) {
              const p = ctx.params[param];
              deps_ts_10.assert(p);
              return fn.call(this, p, ctx, next);
            };
            middleware.param = param;
            const names = params.map((p) => p.name);
            const x = names.indexOf(param);
            if (x >= 0) {
              for (let i = 0; i < stack.length; i++) {
                const fn = stack[i];
                if (!fn.param || names.indexOf(fn.param) > x) {
                  stack.splice(i, 0, middleware);
                  break;
                }
              }
            }
            return this;
          }
          setPrefix(prefix) {
            if (this.path) {
              this.path = this.path !== "/" || this.#opts.strict === true
                ? `${prefix}${this.path}`
                : prefix;
              this.#paramNames = [];
              this.#regexp = deps_ts_10.pathToRegexp(
                this.path,
                this.#paramNames,
                this.#opts,
              );
            }
            return this;
          }
          toJSON() {
            return {
              methods: [...this.methods],
              middleware: [...this.stack],
              paramNames: this.#paramNames.map((key) => key.name),
              path: this.path,
              regexp: this.#regexp,
              options: { ...this.#opts },
            };
          }
        };
        Router = class Router {
          constructor(opts = {}) {
            this.#params = {};
            this.#stack = [];
            this.#match = (path, method) => {
              const matches = {
                path: [],
                pathAndMethod: [],
                route: false,
              };
              for (const route of this.#stack) {
                if (route.match(path)) {
                  matches.path.push(route);
                  if (
                    route.methods.length === 0 ||
                    route.methods.includes(method)
                  ) {
                    matches.pathAndMethod.push(route);
                    if (route.methods.length) {
                      matches.route = true;
                    }
                  }
                }
              }
              return matches;
            };
            this.#register = (path, middleware, methods, options = {}) => {
              if (Array.isArray(path)) {
                for (const p of path) {
                  this.#register(p, middleware, methods, options);
                }
                return;
              }
              const { end, name, sensitive, strict, ignoreCaptures } = options;
              const route = new Layer(path, methods, middleware, {
                end: end === false ? end : true,
                name,
                sensitive: sensitive ?? this.#opts.sensitive ?? false,
                strict: strict ?? this.#opts.strict ?? false,
                ignoreCaptures,
              });
              if (this.#opts.prefix) {
                route.setPrefix(this.#opts.prefix);
              }
              for (const [param, mw] of Object.entries(this.#params)) {
                route.param(param, mw);
              }
              this.#stack.push(route);
            };
            this.#route = (name) => {
              for (const route of this.#stack) {
                if (route.name === name) {
                  return route;
                }
              }
            };
            this.#useVerb = (
              nameOrPath,
              pathOrMiddleware,
              middleware,
              methods,
            ) => {
              let name = undefined;
              let path;
              if (typeof pathOrMiddleware === "string") {
                name = nameOrPath;
                path = pathOrMiddleware;
              } else {
                path = nameOrPath;
                middleware.unshift(pathOrMiddleware);
              }
              this.#register(path, middleware, methods, { name });
            };
            this.#opts = opts;
            this.#methods = opts.methods ?? [
              "DELETE",
              "GET",
              "HEAD",
              "OPTIONS",
              "PATCH",
              "POST",
              "PUT",
            ];
          }
          #opts;
          #methods;
          #params;
          #stack;
          #match;
          #register;
          #route;
          #useVerb;
          all(nameOrPath, pathOrMiddleware, ...middleware) {
            this.#useVerb(
              nameOrPath,
              pathOrMiddleware,
              middleware,
              ["DELETE", "GET", "POST", "PUT"],
            );
            return this;
          }
          /** Middleware that handles requests for HTTP methods registered with the
                 * router.  If none of the routes handle a method, then "not allowed" logic
                 * will be used.  If a method is supported by some routes, but not the
                 * particular matched router, then "not implemented" will be returned.
                 *
                 * The middleware will also automatically handle the `OPTIONS` method,
                 * responding with a `200 OK` when the `Allowed` header sent to the allowed
                 * methods for a given route.
                 *
                 * By default, a "not allowed" request will respond with a `405 Not Allowed`
                 * and a "not implemented" will respond with a `501 Not Implemented`. Setting
                 * the option `.throw` to `true` will cause the middleware to throw an
                 * `HTTPError` instead of setting the response status.  The error can be
                 * overridden by providing a `.notImplemented` or `.notAllowed` method in the
                 * options, of which the value will be returned will be thrown instead of the
                 * HTTP error. */
          allowedMethods(options = {}) {
            const implemented = this.#methods;
            const allowedMethods = async (context, next) => {
              const ctx = context;
              await next();
              if (
                !ctx.response.status ||
                ctx.response.status === deps_ts_10.Status.NotFound
              ) {
                deps_ts_10.assert(ctx.matched);
                const allowed = new Set();
                for (const route of ctx.matched) {
                  for (const method of route.methods) {
                    allowed.add(method);
                  }
                }
                const allowedStr = [...allowed].join(", ");
                if (!implemented.includes(ctx.request.method)) {
                  if (options.throw) {
                    throw options.notImplemented ? options.notImplemented()
                    : new httpError_ts_5.httpErrors.NotImplemented();
                  } else {
                    ctx.response.status = deps_ts_10.Status.NotImplemented;
                    ctx.response.headers.set("Allowed", allowedStr);
                  }
                } else if (allowed.size) {
                  if (ctx.request.method === "OPTIONS") {
                    ctx.response.status = deps_ts_10.Status.OK;
                    ctx.response.headers.set("Allowed", allowedStr);
                  } else if (!allowed.has(ctx.request.method)) {
                    if (options.throw) {
                      throw options.methodNotAllowed
                        ? options.methodNotAllowed()
                        : new httpError_ts_5.httpErrors.MethodNotAllowed();
                    } else {
                      ctx.response.status = deps_ts_10.Status.MethodNotAllowed;
                      ctx.response.headers.set("Allowed", allowedStr);
                    }
                  }
                }
              }
            };
            return allowedMethods;
          }
          delete(nameOrPath, pathOrMiddleware, ...middleware) {
            this.#useVerb(nameOrPath, pathOrMiddleware, middleware, ["DELETE"]);
            return this;
          }
          /** Iterate over the routes currently added to the router.  To be compatible
                 * with the iterable interfaces, both the key and value are set to the value
                 * of the route. */
          *entries() {
            for (const route of this.#stack) {
              const value = route.toJSON();
              yield [value, value];
            }
          }
          /** Iterate over the routes currently added to the router, calling the
                 * `callback` function for each value. */
          forEach(callback, thisArg = null) {
            for (const route of this.#stack) {
              const value = route.toJSON();
              callback.call(thisArg, value, value, this);
            }
          }
          get(nameOrPath, pathOrMiddleware, ...middleware) {
            this.#useVerb(nameOrPath, pathOrMiddleware, middleware, ["GET"]);
            return this;
          }
          head(nameOrPath, pathOrMiddleware, ...middleware) {
            this.#useVerb(nameOrPath, pathOrMiddleware, middleware, ["HEAD"]);
            return this;
          }
          /** Iterate over the routes currently added to the router.  To be compatible
                 * with the iterable interfaces, the key is set to the value of the route. */
          *keys() {
            for (const route of this.#stack) {
              yield route.toJSON();
            }
          }
          options(nameOrPath, pathOrMiddleware, ...middleware) {
            this.#useVerb(
              nameOrPath,
              pathOrMiddleware,
              middleware,
              ["OPTIONS"],
            );
            return this;
          }
          /** Register param middleware, which will be called when the particular param
                 * is parsed from the route. */
          param(param, middleware) {
            this.#params[param] = middleware;
            for (const route of this.#stack) {
              route.param(param, middleware);
            }
            return this;
          }
          patch(nameOrPath, pathOrMiddleware, ...middleware) {
            this.#useVerb(nameOrPath, pathOrMiddleware, middleware, ["PATCH"]);
            return this;
          }
          post(nameOrPath, pathOrMiddleware, ...middleware) {
            this.#useVerb(nameOrPath, pathOrMiddleware, middleware, ["POST"]);
            return this;
          }
          /** Set the router prefix for this router. */
          prefix(prefix) {
            prefix = prefix.replace(/\/$/, "");
            this.#opts.prefix = prefix;
            for (const route of this.#stack) {
              route.setPrefix(prefix);
            }
            return this;
          }
          put(nameOrPath, pathOrMiddleware, ...middleware) {
            this.#useVerb(nameOrPath, pathOrMiddleware, middleware, ["PUT"]);
            return this;
          }
          /** Register a direction middleware, where when the `source` path is matched
                 * the router will redirect the request to the `destination` path.  A `status`
                 * of `302 Found` will be set by default.
                 *
                 * The `source` and `destination` can be named routes. */
          redirect(source, destination, status = deps_ts_10.Status.Found) {
            if (source[0] !== "/") {
              const s = this.url(source);
              if (!s) {
                throw new RangeError(
                  `Could not resolve named route: "${source}"`,
                );
              }
              source = s;
            }
            if (destination[0] !== "/") {
              const d = this.url(destination);
              if (!d) {
                throw new RangeError(
                  `Could not resolve named route: "${source}"`,
                );
              }
              destination = d;
            }
            this.all(source, (ctx) => {
              ctx.response.redirect(destination);
              ctx.response.status = status;
            });
            return this;
          }
          /** Return middleware that will do all the route processing that the router
                 * has been configured to handle.  Typical usage would be something like this:
                 *
                 * ```ts
                 * import { Application, Router } from "https://deno.land/x/oak/mod.ts";
                 *
                 * const app = new Application();
                 * const router = new Router();
                 *
                 * // register routes
                 *
                 * app.use(router.routes());
                 * app.use(router.allowedMethods());
                 * await app.listen({ port: 80 });
                 * ```
                 */
          routes() {
            const dispatch = (context, next) => {
              const ctx = context;
              const { url: { pathname }, method } = ctx.request;
              const path = this.#opts.routerPath ?? ctx.routerPath ?? pathname;
              const matches = this.#match(path, method);
              if (ctx.matched) {
                ctx.matched.push(...matches.path);
              } else {
                ctx.matched = [...matches.path];
              }
              ctx.router = this;
              if (!matches.route) {
                return next();
              }
              const { pathAndMethod: matchedRoutes } = matches;
              const chain = matchedRoutes.reduce((prev, route) => [
                ...prev,
                (ctx, next) => {
                  ctx.captures = route.captures(path);
                  ctx.params = route.params(ctx.captures, ctx.params);
                  ctx.routeName = route.name;
                  return next();
                },
                ...route.stack,
              ], []);
              return middleware_ts_2.compose(chain)(ctx);
            };
            dispatch.router = this;
            return dispatch;
          }
          /** Generate a URL pathname for a named route, interpolating the optional
                 * params provided.  Also accepts an optional set of options. */
          url(name, params, options) {
            const route = this.#route(name);
            if (route) {
              return route.url(params, options);
            }
          }
          use(pathOrMiddleware, ...middleware) {
            let path;
            if (
              typeof pathOrMiddleware === "string" ||
              Array.isArray(pathOrMiddleware)
            ) {
              path = pathOrMiddleware;
            } else {
              middleware.unshift(pathOrMiddleware);
            }
            this.#register(
              path ?? "(.*)",
              middleware,
              [],
              { end: false, ignoreCaptures: !path },
            );
            return this;
          }
          /** Iterate over the routes currently added to the router. */
          *values() {
            for (const route of this.#stack) {
              yield route.toJSON();
            }
          }
          /** Provide an iterator interface that iterates over the routes registered
                 * with the router. */
          *[Symbol.iterator]() {
            for (const route of this.#stack) {
              yield route.toJSON();
            }
          }
          /** Generate a URL pathname based on the provided path, interpolating the
                 * optional params provided.  Also accepts an optional set of options. */
          static url(path, params, options) {
            return toUrl(path, params, options);
          }
        };
        exports_52("Router", Router);
      },
    };
  },
);
// Copyright 2018-2020 the oak authors. All rights reserved. MIT license.
System.register(
  "https://deno.land/x/oak/helpers",
  [],
  function (exports_53, context_53) {
    "use strict";
    var __moduleName = context_53 && context_53.id;
    function isRouterContext(value) {
      return "params" in value;
    }
    function getQuery(ctx, { mergeParams, asMap } = {}) {
      const result = {};
      if (mergeParams && isRouterContext(ctx)) {
        Object.assign(result, ctx.params);
      }
      for (const [key, value] of ctx.request.url.searchParams) {
        result[key] = value;
      }
      return asMap ? new Map(Object.entries(result)) : result;
    }
    exports_53("getQuery", getQuery);
    return {
      setters: [],
      execute: function () {
      },
    };
  },
);
// Copyright 2018-2020 the oak authors. All rights reserved. MIT license.
System.register(
  "https://deno.land/x/oak/mod",
  [
    "https://deno.land/x/oak/application",
    "https://deno.land/x/oak/context",
    "https://deno.land/x/oak/helpers",
    "https://deno.land/x/oak/cookies",
    "https://deno.land/x/oak/httpError",
    "https://deno.land/x/oak/middleware",
    "https://deno.land/x/oak/request",
    "https://deno.land/x/oak/response",
    "https://deno.land/x/oak/router",
    "https://deno.land/x/oak/send",
    "https://deno.land/x/oak/util",
    "https://deno.land/x/oak/deps",
  ],
  function (exports_54, context_54) {
    "use strict";
    var __moduleName = context_54 && context_54.id;
    return {
      setters: [
        function (application_ts_1_1) {
          exports_54({
            "Application": application_ts_1_1["Application"],
          });
        },
        function (context_ts_2_1) {
          exports_54({
            "Context": context_ts_2_1["Context"],
          });
        },
        function (helpers_1) {
          exports_54("helpers", helpers_1);
        },
        function (cookies_ts_2_1) {
          exports_54({
            "Cookies": cookies_ts_2_1["Cookies"],
          });
        },
        function (httpError_ts_6_1) {
          exports_54({
            "HttpError": httpError_ts_6_1["HttpError"],
            "httpErrors": httpError_ts_6_1["httpErrors"],
            "isHttpError": httpError_ts_6_1["isHttpError"],
          });
        },
        function (middleware_ts_3_1) {
          exports_54({
            "composeMiddleware": middleware_ts_3_1["compose"],
          });
        },
        function (request_ts_2_1) {
          exports_54({
            "Request": request_ts_2_1["Request"],
          });
        },
        function (response_ts_2_1) {
          exports_54({
            "Response": response_ts_2_1["Response"],
            "REDIRECT_BACK": response_ts_2_1["REDIRECT_BACK"],
          });
        },
        function (router_ts_1_1) {
          exports_54({
            "Router": router_ts_1_1["Router"],
          });
        },
        function (send_ts_2_1) {
          exports_54({
            "send": send_ts_2_1["send"],
          });
        },
        function (util_ts_7_1) {
          exports_54({
            "isErrorStatus": util_ts_7_1["isErrorStatus"],
            "isRedirectStatus": util_ts_7_1["isRedirectStatus"],
          });
        },
        function (deps_ts_11_1) {
          exports_54({
            "Status": deps_ts_11_1["Status"],
            "STATUS_TEXT": deps_ts_11_1["STATUS_TEXT"],
          });
        },
      ],
      execute: function () {
      },
    };
  },
);
System.register(
  "https://deno.land/x/cors/types",
  [],
  function (exports_55, context_55) {
    "use strict";
    var __moduleName = context_55 && context_55.id;
    return {
      setters: [],
      execute: function () {
      },
    };
  },
);
System.register(
  "https://deno.land/x/cors/cors",
  [],
  function (exports_56, context_56) {
    "use strict";
    var Cors;
    var __moduleName = context_56 && context_56.id;
    return {
      setters: [],
      execute: function () {
        Cors = /** @class */ (() => {
          class Cors {
            constructor(props) {
              this.props = props;
              this.configureHeaders = () => {
                const {
                  props: { corsOptions, requestMethod, setResponseHeader, setStatus, next },
                  configureOrigin,
                } = this;
                if (
                  typeof requestMethod === "string" &&
                  requestMethod.toUpperCase() === "OPTIONS"
                ) {
                  configureOrigin()
                    .configureCredentials()
                    .configureMethods()
                    .configureAllowedHeaders()
                    .configureMaxAge()
                    .configureExposedHeaders();
                  if (corsOptions.preflightContinue) {
                    return next();
                  } else {
                    setStatus(corsOptions.optionsSuccessStatus);
                    setResponseHeader("Content-Length", "0");
                    return next();
                  }
                } else {
                  configureOrigin().configureCredentials()
                    .configureExposedHeaders();
                  return next();
                }
              };
              this.configureOrigin = () => {
                const {
                  props: { corsOptions, getRequestHeader, setResponseHeader },
                  setVaryHeader,
                } = this;
                if (!corsOptions.origin || corsOptions.origin === "*") {
                  setResponseHeader("Access-Control-Allow-Origin", "*");
                } else if (typeof corsOptions.origin === "string") {
                  setResponseHeader(
                    "Access-Control-Allow-Origin",
                    corsOptions.origin,
                  );
                  setVaryHeader("Origin");
                } else {
                  const requestOrigin = getRequestHeader("origin") ??
                    getRequestHeader("Origin");
                  setResponseHeader(
                    "Access-Control-Allow-Origin",
                    Cors.isOriginAllowed(requestOrigin, corsOptions.origin)
                      ? requestOrigin
                      : "false",
                  );
                  setVaryHeader("Origin");
                }
                return this;
              };
              this.configureCredentials = () => {
                const { corsOptions, setResponseHeader } = this.props;
                if (corsOptions.credentials === true) {
                  setResponseHeader("Access-Control-Allow-Credentials", "true");
                }
                return this;
              };
              this.configureMethods = () => {
                const { corsOptions, setResponseHeader } = this.props;
                let methods = corsOptions.methods;
                setResponseHeader(
                  "Access-Control-Allow-Methods",
                  Array.isArray(methods) ? methods.join(",") : methods,
                );
                return this;
              };
              this.configureAllowedHeaders = () => {
                const {
                  props: { corsOptions, getRequestHeader, setResponseHeader },
                  setVaryHeader,
                } = this;
                let allowedHeaders = corsOptions.allowedHeaders;
                if (!allowedHeaders) {
                  allowedHeaders =
                    getRequestHeader("access-control-request-headers") ??
                      getRequestHeader("Access-Control-Request-Headers") ??
                      undefined;
                  setVaryHeader("Access-Control-request-Headers");
                }
                if (allowedHeaders?.length) {
                  setResponseHeader(
                    "Access-Control-Allow-Headers",
                    Array.isArray(allowedHeaders)
                      ? allowedHeaders.join(",")
                      : allowedHeaders,
                  );
                }
                return this;
              };
              this.configureMaxAge = () => {
                const { corsOptions, setResponseHeader } = this.props;
                const maxAge = (typeof corsOptions.maxAge === "number" ||
                  typeof corsOptions.maxAge === "string") &&
                  corsOptions.maxAge.toString();
                if (maxAge && maxAge.length) {
                  setResponseHeader("Access-Control-Max-Age", maxAge);
                }
                return this;
              };
              this.configureExposedHeaders = () => {
                const { corsOptions, setResponseHeader } = this.props;
                let exposedHeaders = corsOptions.exposedHeaders;
                if (exposedHeaders?.length) {
                  setResponseHeader(
                    "Access-Control-Expose-Headers",
                    Array.isArray(exposedHeaders)
                      ? exposedHeaders.join(",")
                      : exposedHeaders,
                  );
                }
                return this;
              };
              this.setVaryHeader = (field) => {
                const {
                  props: { getResponseHeader, setResponseHeader },
                  appendVaryHeader,
                } = this;
                let existingHeader = getResponseHeader("Vary") ?? "";
                if (
                  existingHeader &&
                  typeof existingHeader === "string" &&
                  (existingHeader = appendVaryHeader(existingHeader, field))
                ) {
                  setResponseHeader("Vary", existingHeader);
                }
              };
              this.appendVaryHeader = (header, field) => {
                const { parseVaryHeader } = this;
                if (header === "*") {
                  return header;
                }
                let varyHeader = header;
                const fields = parseVaryHeader(field);
                const headers = parseVaryHeader(header.toLocaleLowerCase());
                if (fields.includes("*") || headers.includes("*")) {
                  return "*";
                }
                fields.forEach((field) => {
                  const fld = field.toLowerCase();
                  if (headers.includes(fld)) {
                    headers.push(fld);
                    varyHeader = varyHeader ? `${varyHeader}, ${field}` : field;
                  }
                });
                return varyHeader;
              };
              this.parseVaryHeader = (header) => {
                let end = 0;
                const list = [];
                let start = 0;
                for (let i = 0, len = header.length; i < len; i++) {
                  switch (header.charCodeAt(i)) {
                    case 0x20 /*   */:
                      if (start === end) {
                        start = end = i + 1;
                      }
                      break;
                    case 0x2c /* , */:
                      list.push(header.substring(start, end));
                      start = end = i + 1;
                      break;
                    default:
                      end = i + 1;
                      break;
                  }
                }
                list.push(header.substring(start, end));
                return list;
              };
            }
          }
          Cors.produceCorsOptions = (corsOptions = {}, defaultCorsOptions = {
            origin: "*",
            methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
            preflightContinue: false,
            optionsSuccessStatus: 204,
          }) => ({
            ...defaultCorsOptions,
            ...corsOptions,
          });
          Cors.produceCorsOptionsDelegate = (o) =>
            typeof o === "function" ? o : ((_request) => o);
          Cors.produceOriginDelegate = (corsOptions) => {
            if (corsOptions.origin) {
              if (typeof corsOptions.origin === "function") {
                return corsOptions.origin;
              }
              return ((_requestOrigin) => corsOptions.origin);
            }
          };
          Cors.isOriginAllowed = (requestOrigin, allowedOrigin) => {
            if (Array.isArray(allowedOrigin)) {
              return allowedOrigin.some((ao) =>
                Cors.isOriginAllowed(requestOrigin, ao)
              );
            } else if (typeof allowedOrigin === "string") {
              return requestOrigin === allowedOrigin;
            } else if (
              allowedOrigin instanceof RegExp &&
              typeof requestOrigin === "string"
            ) {
              return allowedOrigin.test(requestOrigin);
            } else {
              return !!allowedOrigin;
            }
          };
          return Cors;
        })();
        exports_56("Cors", Cors);
      },
    };
  },
);
System.register(
  "https://deno.land/x/cors/oakCors",
  ["https://deno.land/x/cors/cors"],
  function (exports_57, context_57) {
    "use strict";
    var cors_ts_1, oakCors;
    var __moduleName = context_57 && context_57.id;
    return {
      setters: [
        function (cors_ts_1_1) {
          cors_ts_1 = cors_ts_1_1;
        },
      ],
      execute: function () {
        /**
             * oakCors middleware wrapper
             * @param o CorsOptions | CorsOptionsDelegate
             * @link https://github.com/tajpouria/cors/blob/master/README.md#cors
             */
        exports_57(
          "oakCors",
          oakCors = (o) => {
            const corsOptionsDelegate = cors_ts_1.Cors
              .produceCorsOptionsDelegate(o);
            return (async ({ request, response }, next) => {
              try {
                const options = await corsOptionsDelegate(request);
                const corsOptions = cors_ts_1.Cors.produceCorsOptions(
                  options || {},
                );
                const originDelegate = cors_ts_1.Cors.produceOriginDelegate(
                  corsOptions,
                );
                if (originDelegate) {
                  const requestMethod = request.method;
                  const getRequestHeader = (headerKey) =>
                    request.headers.get(headerKey);
                  const getResponseHeader = (headerKey) =>
                    response.headers.get(headerKey);
                  const setResponseHeader = (headerKey, headerValue) =>
                    response.headers.set(headerKey, headerValue);
                  const setStatus = (
                    statusCode,
                  ) => (response.status = statusCode);
                  const origin = await originDelegate(
                    getRequestHeader("origin"),
                  );
                  if (!origin) {
                    next();
                  } else {
                    corsOptions.origin = origin;
                    return new cors_ts_1.Cors({
                      corsOptions,
                      requestMethod,
                      getRequestHeader,
                      getResponseHeader,
                      setResponseHeader,
                      setStatus,
                      next,
                    }).configureHeaders();
                  }
                }
              } catch (error) {
                next();
              }
            });
          },
        );
      },
    };
  },
);
System.register(
  "https://deno.land/x/cors/abcCors",
  ["https://deno.land/x/cors/cors"],
  function (exports_58, context_58) {
    "use strict";
    var cors_ts_2, abcCors;
    var __moduleName = context_58 && context_58.id;
    return {
      setters: [
        function (cors_ts_2_1) {
          cors_ts_2 = cors_ts_2_1;
        },
      ],
      execute: function () {
        /**
             * abcCors middleware wrapper
             * @param o CorsOptions | CorsOptionsDelegate
             * @link https://github.com/tajpouria/cors/blob/master/README.md#cors
             */
        exports_58(
          "abcCors",
          abcCors = (o) => {
            const corsOptionsDelegate = cors_ts_2.Cors
              .produceCorsOptionsDelegate(o);
            return ((abcNext) =>
              async (context) => {
                const next = () => abcNext(context);
                try {
                  const { request, response } = context;
                  const options = await corsOptionsDelegate(request);
                  const corsOptions = cors_ts_2.Cors.produceCorsOptions(
                    options || {},
                  );
                  const originDelegate = cors_ts_2.Cors.produceOriginDelegate(
                    corsOptions,
                  );
                  if (originDelegate) {
                    const requestMethod = request.method;
                    const getRequestHeader = (headerKey) =>
                      request.headers.get(headerKey);
                    const getResponseHeader = (headerKey) =>
                      response.headers.get(headerKey);
                    const setResponseHeader = (headerKey, headerValue) =>
                      response.headers.set(headerKey, headerValue);
                    const setStatus = (
                      statusCode,
                    ) => (response.status = statusCode);
                    const origin = await originDelegate(
                      getRequestHeader("origin"),
                    );
                    if (!origin) {
                      return next();
                    } else {
                      corsOptions.origin = origin;
                      return new cors_ts_2.Cors({
                        corsOptions,
                        requestMethod,
                        getRequestHeader,
                        getResponseHeader,
                        setResponseHeader,
                        setStatus,
                        next,
                      }).configureHeaders();
                    }
                  }
                } catch (error) {
                  return next();
                }
              });
          },
        );
      },
    };
  },
);
System.register(
  "https://deno.land/x/cors/mithCors",
  ["https://deno.land/x/cors/cors"],
  function (exports_59, context_59) {
    "use strict";
    var cors_ts_3, mithCors;
    var __moduleName = context_59 && context_59.id;
    return {
      setters: [
        function (cors_ts_3_1) {
          cors_ts_3 = cors_ts_3_1;
        },
      ],
      execute: function () {
        /**
             * mithCors middleware wrapper
             * @param o CorsOptions | CorsOptionsDelegate
             * @link https://github.com/tajpouria/cors/blob/master/README.md#cors
             */
        exports_59(
          "mithCors",
          mithCors = (o) => {
            const corsOptionsDelegate = cors_ts_3.Cors
              .produceCorsOptionsDelegate(o);
            return (async (request, response, next) => {
              try {
                const options = await corsOptionsDelegate(request);
                const corsOptions = cors_ts_3.Cors.produceCorsOptions(
                  options || {},
                );
                const originDelegate = cors_ts_3.Cors.produceOriginDelegate(
                  corsOptions,
                );
                if (originDelegate) {
                  const requestMethod = request.method;
                  const getRequestHeader = (headerKey) =>
                    request.headers.get(headerKey);
                  const getResponseHeader = (headerKey) =>
                    response.headers.get(headerKey);
                  const setResponseHeader = (headerKey, headerValue) =>
                    response.headers.set(headerKey, headerValue);
                  const setStatus = (
                    statusCode,
                  ) => (response.status = statusCode);
                  const origin = await originDelegate(
                    getRequestHeader("origin"),
                  );
                  if (!origin) {
                    return next();
                  } else {
                    corsOptions.origin = origin;
                    return new cors_ts_3.Cors({
                      corsOptions,
                      requestMethod,
                      getRequestHeader,
                      getResponseHeader,
                      setResponseHeader,
                      setStatus,
                      next,
                    }).configureHeaders();
                  }
                }
              } catch (error) {
                return next();
              }
            });
          },
        );
      },
    };
  },
);
System.register(
  "https://deno.land/x/cors/attainCors",
  ["https://deno.land/x/cors/cors"],
  function (exports_60, context_60) {
    "use strict";
    var cors_ts_4, attainCors;
    var __moduleName = context_60 && context_60.id;
    return {
      setters: [
        function (cors_ts_4_1) {
          cors_ts_4 = cors_ts_4_1;
        },
      ],
      execute: function () {
        exports_60(
          "attainCors",
          attainCors = (o) => {
            const corsOptionsDelegate = cors_ts_4.Cors
              .produceCorsOptionsDelegate(o);
            return async function cors(request, response) {
              try {
                const fakeNext = () => undefined;
                const options = await corsOptionsDelegate(request);
                const corsOptions = cors_ts_4.Cors.produceCorsOptions(
                  options || {},
                );
                const originDelegate = cors_ts_4.Cors.produceOriginDelegate(
                  corsOptions,
                );
                if (originDelegate) {
                  const requestMethod = request.method;
                  const getRequestHeader = (headerKey) =>
                    request.headers.get(headerKey);
                  const getResponseHeader = (headerKey) =>
                    response.headers.get(headerKey);
                  const setResponseHeader = (headerKey, headerValue) =>
                    response.headers.set(headerKey, headerValue);
                  const setStatus = (statusCode) => response.status(statusCode);
                  const origin = await originDelegate(
                    getRequestHeader("origin"),
                  );
                  if (origin) {
                    corsOptions.origin = origin;
                    new cors_ts_4.Cors({
                      corsOptions,
                      requestMethod,
                      getRequestHeader,
                      getResponseHeader,
                      setResponseHeader,
                      setStatus,
                      next: fakeNext,
                    }).configureHeaders();
                  }
                }
              } catch (error) {
                throw error;
              }
            };
          },
        );
      },
    };
  },
);
System.register(
  "https://deno.land/x/cors/mod",
  [
    "https://deno.land/x/cors/types",
    "https://deno.land/x/cors/oakCors",
    "https://deno.land/x/cors/abcCors",
    "https://deno.land/x/cors/mithCors",
    "https://deno.land/x/cors/attainCors",
  ],
  function (exports_61, context_61) {
    "use strict";
    var __moduleName = context_61 && context_61.id;
    var exportedNames_2 = {
      "oakCors": true,
      "abcCors": true,
      "mithCors": true,
      "attainCors": true,
    };
    function exportStar_3(m) {
      var exports = {};
      for (var n in m) {
        if (n !== "default" && !exportedNames_2.hasOwnProperty(n)) {
          exports[n] = m[n];
        }
      }
      exports_61(exports);
    }
    return {
      setters: [
        function (types_ts_1_1) {
          exportStar_3(types_ts_1_1);
        },
        function (oakCors_ts_1_1) {
          exports_61({
            "oakCors": oakCors_ts_1_1["oakCors"],
          });
        },
        function (abcCors_ts_1_1) {
          exports_61({
            "abcCors": abcCors_ts_1_1["abcCors"],
          });
        },
        function (mithCors_ts_1_1) {
          exports_61({
            "mithCors": mithCors_ts_1_1["mithCors"],
          });
        },
        function (attainCors_ts_1_1) {
          exports_61({
            "attainCors": attainCors_ts_1_1["attainCors"],
          });
        },
      ],
      execute: function () {
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.51.0/path/interface",
  [],
  function (exports_62, context_62) {
    "use strict";
    var __moduleName = context_62 && context_62.id;
    return {
      setters: [],
      execute: function () {
      },
    };
  },
);
// Copyright the Browserify authors. MIT License.
// Ported from https://github.com/browserify/path-browserify/
System.register(
  "https://deno.land/std@0.51.0/path/_constants",
  [],
  function (exports_63, context_63) {
    "use strict";
    var build,
      CHAR_UPPERCASE_A,
      CHAR_LOWERCASE_A,
      CHAR_UPPERCASE_Z,
      CHAR_LOWERCASE_Z,
      CHAR_DOT,
      CHAR_FORWARD_SLASH,
      CHAR_BACKWARD_SLASH,
      CHAR_VERTICAL_LINE,
      CHAR_COLON,
      CHAR_QUESTION_MARK,
      CHAR_UNDERSCORE,
      CHAR_LINE_FEED,
      CHAR_CARRIAGE_RETURN,
      CHAR_TAB,
      CHAR_FORM_FEED,
      CHAR_EXCLAMATION_MARK,
      CHAR_HASH,
      CHAR_SPACE,
      CHAR_NO_BREAK_SPACE,
      CHAR_ZERO_WIDTH_NOBREAK_SPACE,
      CHAR_LEFT_SQUARE_BRACKET,
      CHAR_RIGHT_SQUARE_BRACKET,
      CHAR_LEFT_ANGLE_BRACKET,
      CHAR_RIGHT_ANGLE_BRACKET,
      CHAR_LEFT_CURLY_BRACKET,
      CHAR_RIGHT_CURLY_BRACKET,
      CHAR_HYPHEN_MINUS,
      CHAR_PLUS,
      CHAR_DOUBLE_QUOTE,
      CHAR_SINGLE_QUOTE,
      CHAR_PERCENT,
      CHAR_SEMICOLON,
      CHAR_CIRCUMFLEX_ACCENT,
      CHAR_GRAVE_ACCENT,
      CHAR_AT,
      CHAR_AMPERSAND,
      CHAR_EQUAL,
      CHAR_0,
      CHAR_9,
      isWindows,
      SEP,
      SEP_PATTERN;
    var __moduleName = context_63 && context_63.id;
    return {
      setters: [],
      execute: function () {
        build = Deno.build;
        // Alphabet chars.
        exports_63("CHAR_UPPERCASE_A", CHAR_UPPERCASE_A = 65); /* A */
        exports_63("CHAR_LOWERCASE_A", CHAR_LOWERCASE_A = 97); /* a */
        exports_63("CHAR_UPPERCASE_Z", CHAR_UPPERCASE_Z = 90); /* Z */
        exports_63("CHAR_LOWERCASE_Z", CHAR_LOWERCASE_Z = 122); /* z */
        // Non-alphabetic chars.
        exports_63("CHAR_DOT", CHAR_DOT = 46); /* . */
        exports_63("CHAR_FORWARD_SLASH", CHAR_FORWARD_SLASH = 47); /* / */
        exports_63("CHAR_BACKWARD_SLASH", CHAR_BACKWARD_SLASH = 92); /* \ */
        exports_63("CHAR_VERTICAL_LINE", CHAR_VERTICAL_LINE = 124); /* | */
        exports_63("CHAR_COLON", CHAR_COLON = 58); /* : */
        exports_63("CHAR_QUESTION_MARK", CHAR_QUESTION_MARK = 63); /* ? */
        exports_63("CHAR_UNDERSCORE", CHAR_UNDERSCORE = 95); /* _ */
        exports_63("CHAR_LINE_FEED", CHAR_LINE_FEED = 10); /* \n */
        exports_63("CHAR_CARRIAGE_RETURN", CHAR_CARRIAGE_RETURN = 13); /* \r */
        exports_63("CHAR_TAB", CHAR_TAB = 9); /* \t */
        exports_63("CHAR_FORM_FEED", CHAR_FORM_FEED = 12); /* \f */
        exports_63("CHAR_EXCLAMATION_MARK", CHAR_EXCLAMATION_MARK = 33); /* ! */
        exports_63("CHAR_HASH", CHAR_HASH = 35); /* # */
        exports_63("CHAR_SPACE", CHAR_SPACE = 32); /*   */
        exports_63(
          "CHAR_NO_BREAK_SPACE",
          CHAR_NO_BREAK_SPACE = 160,
        ); /* \u00A0 */
        exports_63(
          "CHAR_ZERO_WIDTH_NOBREAK_SPACE",
          CHAR_ZERO_WIDTH_NOBREAK_SPACE = 65279,
        ); /* \uFEFF */
        exports_63(
          "CHAR_LEFT_SQUARE_BRACKET",
          CHAR_LEFT_SQUARE_BRACKET = 91,
        ); /* [ */
        exports_63(
          "CHAR_RIGHT_SQUARE_BRACKET",
          CHAR_RIGHT_SQUARE_BRACKET = 93,
        ); /* ] */
        exports_63(
          "CHAR_LEFT_ANGLE_BRACKET",
          CHAR_LEFT_ANGLE_BRACKET = 60,
        ); /* < */
        exports_63(
          "CHAR_RIGHT_ANGLE_BRACKET",
          CHAR_RIGHT_ANGLE_BRACKET = 62,
        ); /* > */
        exports_63(
          "CHAR_LEFT_CURLY_BRACKET",
          CHAR_LEFT_CURLY_BRACKET = 123,
        ); /* { */
        exports_63(
          "CHAR_RIGHT_CURLY_BRACKET",
          CHAR_RIGHT_CURLY_BRACKET = 125,
        ); /* } */
        exports_63("CHAR_HYPHEN_MINUS", CHAR_HYPHEN_MINUS = 45); /* - */
        exports_63("CHAR_PLUS", CHAR_PLUS = 43); /* + */
        exports_63("CHAR_DOUBLE_QUOTE", CHAR_DOUBLE_QUOTE = 34); /* " */
        exports_63("CHAR_SINGLE_QUOTE", CHAR_SINGLE_QUOTE = 39); /* ' */
        exports_63("CHAR_PERCENT", CHAR_PERCENT = 37); /* % */
        exports_63("CHAR_SEMICOLON", CHAR_SEMICOLON = 59); /* ; */
        exports_63(
          "CHAR_CIRCUMFLEX_ACCENT",
          CHAR_CIRCUMFLEX_ACCENT = 94,
        ); /* ^ */
        exports_63("CHAR_GRAVE_ACCENT", CHAR_GRAVE_ACCENT = 96); /* ` */
        exports_63("CHAR_AT", CHAR_AT = 64); /* @ */
        exports_63("CHAR_AMPERSAND", CHAR_AMPERSAND = 38); /* & */
        exports_63("CHAR_EQUAL", CHAR_EQUAL = 61); /* = */
        // Digits
        exports_63("CHAR_0", CHAR_0 = 48); /* 0 */
        exports_63("CHAR_9", CHAR_9 = 57); /* 9 */
        isWindows = build.os == "windows";
        exports_63("SEP", SEP = isWindows ? "\\" : "/");
        exports_63("SEP_PATTERN", SEP_PATTERN = isWindows ? /[\\/]+/ : /\/+/);
      },
    };
  },
);
// Copyright the Browserify authors. MIT License.
// Ported from https://github.com/browserify/path-browserify/
System.register(
  "https://deno.land/std@0.51.0/path/_util",
  ["https://deno.land/std@0.51.0/path/_constants"],
  function (exports_64, context_64) {
    "use strict";
    var _constants_ts_4;
    var __moduleName = context_64 && context_64.id;
    function assertPath(path) {
      if (typeof path !== "string") {
        throw new TypeError(
          `Path must be a string. Received ${JSON.stringify(path)}`,
        );
      }
    }
    exports_64("assertPath", assertPath);
    function isPosixPathSeparator(code) {
      return code === _constants_ts_4.CHAR_FORWARD_SLASH;
    }
    exports_64("isPosixPathSeparator", isPosixPathSeparator);
    function isPathSeparator(code) {
      return isPosixPathSeparator(code) ||
        code === _constants_ts_4.CHAR_BACKWARD_SLASH;
    }
    exports_64("isPathSeparator", isPathSeparator);
    function isWindowsDeviceRoot(code) {
      return ((code >= _constants_ts_4.CHAR_LOWERCASE_A &&
        code <= _constants_ts_4.CHAR_LOWERCASE_Z) ||
        (code >= _constants_ts_4.CHAR_UPPERCASE_A &&
          code <= _constants_ts_4.CHAR_UPPERCASE_Z));
    }
    exports_64("isWindowsDeviceRoot", isWindowsDeviceRoot);
    // Resolves . and .. elements in a path with directory names
    function normalizeString(path, allowAboveRoot, separator, isPathSeparator) {
      let res = "";
      let lastSegmentLength = 0;
      let lastSlash = -1;
      let dots = 0;
      let code;
      for (let i = 0, len = path.length; i <= len; ++i) {
        if (i < len) {
          code = path.charCodeAt(i);
        } else if (isPathSeparator(code)) {
          break;
        } else {
          code = _constants_ts_4.CHAR_FORWARD_SLASH;
        }
        if (isPathSeparator(code)) {
          if (lastSlash === i - 1 || dots === 1) {
            // NOOP
          } else if (lastSlash !== i - 1 && dots === 2) {
            if (
              res.length < 2 ||
              lastSegmentLength !== 2 ||
              res.charCodeAt(res.length - 1) !== _constants_ts_4.CHAR_DOT ||
              res.charCodeAt(res.length - 2) !== _constants_ts_4.CHAR_DOT
            ) {
              if (res.length > 2) {
                const lastSlashIndex = res.lastIndexOf(separator);
                if (lastSlashIndex === -1) {
                  res = "";
                  lastSegmentLength = 0;
                } else {
                  res = res.slice(0, lastSlashIndex);
                  lastSegmentLength = res.length - 1 -
                    res.lastIndexOf(separator);
                }
                lastSlash = i;
                dots = 0;
                continue;
              } else if (res.length === 2 || res.length === 1) {
                res = "";
                lastSegmentLength = 0;
                lastSlash = i;
                dots = 0;
                continue;
              }
            }
            if (allowAboveRoot) {
              if (res.length > 0) {
                res += `${separator}..`;
              } else {
                res = "..";
              }
              lastSegmentLength = 2;
            }
          } else {
            if (res.length > 0) {
              res += separator + path.slice(lastSlash + 1, i);
            } else {
              res = path.slice(lastSlash + 1, i);
            }
            lastSegmentLength = i - lastSlash - 1;
          }
          lastSlash = i;
          dots = 0;
        } else if (code === _constants_ts_4.CHAR_DOT && dots !== -1) {
          ++dots;
        } else {
          dots = -1;
        }
      }
      return res;
    }
    exports_64("normalizeString", normalizeString);
    function _format(sep, pathObject) {
      const dir = pathObject.dir || pathObject.root;
      const base = pathObject.base ||
        (pathObject.name || "") + (pathObject.ext || "");
      if (!dir) {
        return base;
      }
      if (dir === pathObject.root) {
        return dir + base;
      }
      return dir + sep + base;
    }
    exports_64("_format", _format);
    return {
      setters: [
        function (_constants_ts_4_1) {
          _constants_ts_4 = _constants_ts_4_1;
        },
      ],
      execute: function () {
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.51.0/fmt/colors",
  [],
  function (exports_65, context_65) {
    "use strict";
    var noColor, enabled;
    var __moduleName = context_65 && context_65.id;
    function setColorEnabled(value) {
      if (noColor) {
        return;
      }
      enabled = value;
    }
    exports_65("setColorEnabled", setColorEnabled);
    function getColorEnabled() {
      return enabled;
    }
    exports_65("getColorEnabled", getColorEnabled);
    function code(open, close) {
      return {
        open: `\x1b[${open.join(";")}m`,
        close: `\x1b[${close}m`,
        regexp: new RegExp(`\\x1b\\[${close}m`, "g"),
      };
    }
    function run(str, code) {
      return enabled
        ? `${code.open}${str.replace(code.regexp, code.open)}${code.close}`
        : str;
    }
    function reset(str) {
      return run(str, code([0], 0));
    }
    exports_65("reset", reset);
    function bold(str) {
      return run(str, code([1], 22));
    }
    exports_65("bold", bold);
    function dim(str) {
      return run(str, code([2], 22));
    }
    exports_65("dim", dim);
    function italic(str) {
      return run(str, code([3], 23));
    }
    exports_65("italic", italic);
    function underline(str) {
      return run(str, code([4], 24));
    }
    exports_65("underline", underline);
    function inverse(str) {
      return run(str, code([7], 27));
    }
    exports_65("inverse", inverse);
    function hidden(str) {
      return run(str, code([8], 28));
    }
    exports_65("hidden", hidden);
    function strikethrough(str) {
      return run(str, code([9], 29));
    }
    exports_65("strikethrough", strikethrough);
    function black(str) {
      return run(str, code([30], 39));
    }
    exports_65("black", black);
    function red(str) {
      return run(str, code([31], 39));
    }
    exports_65("red", red);
    function green(str) {
      return run(str, code([32], 39));
    }
    exports_65("green", green);
    function yellow(str) {
      return run(str, code([33], 39));
    }
    exports_65("yellow", yellow);
    function blue(str) {
      return run(str, code([34], 39));
    }
    exports_65("blue", blue);
    function magenta(str) {
      return run(str, code([35], 39));
    }
    exports_65("magenta", magenta);
    function cyan(str) {
      return run(str, code([36], 39));
    }
    exports_65("cyan", cyan);
    function white(str) {
      return run(str, code([37], 39));
    }
    exports_65("white", white);
    function gray(str) {
      return run(str, code([90], 39));
    }
    exports_65("gray", gray);
    function bgBlack(str) {
      return run(str, code([40], 49));
    }
    exports_65("bgBlack", bgBlack);
    function bgRed(str) {
      return run(str, code([41], 49));
    }
    exports_65("bgRed", bgRed);
    function bgGreen(str) {
      return run(str, code([42], 49));
    }
    exports_65("bgGreen", bgGreen);
    function bgYellow(str) {
      return run(str, code([43], 49));
    }
    exports_65("bgYellow", bgYellow);
    function bgBlue(str) {
      return run(str, code([44], 49));
    }
    exports_65("bgBlue", bgBlue);
    function bgMagenta(str) {
      return run(str, code([45], 49));
    }
    exports_65("bgMagenta", bgMagenta);
    function bgCyan(str) {
      return run(str, code([46], 49));
    }
    exports_65("bgCyan", bgCyan);
    function bgWhite(str) {
      return run(str, code([47], 49));
    }
    exports_65("bgWhite", bgWhite);
    /* Special Color Sequences */
    function clampAndTruncate(n, max = 255, min = 0) {
      return Math.trunc(Math.max(Math.min(n, max), min));
    }
    /** Set text color using paletted 8bit colors.
     * https://en.wikipedia.org/wiki/ANSI_escape_code#8-bit */
    function rgb8(str, color) {
      return run(str, code([38, 5, clampAndTruncate(color)], 39));
    }
    exports_65("rgb8", rgb8);
    /** Set background color using paletted 8bit colors.
     * https://en.wikipedia.org/wiki/ANSI_escape_code#8-bit */
    function bgRgb8(str, color) {
      return run(str, code([48, 5, clampAndTruncate(color)], 49));
    }
    exports_65("bgRgb8", bgRgb8);
    /** Set text color using 24bit rgb. */
    function rgb24(str, color) {
      return run(
        str,
        code([
          38,
          2,
          clampAndTruncate(color.r),
          clampAndTruncate(color.g),
          clampAndTruncate(color.b),
        ], 39),
      );
    }
    exports_65("rgb24", rgb24);
    /** Set background color using 24bit rgb. */
    function bgRgb24(str, color) {
      return run(
        str,
        code([
          48,
          2,
          clampAndTruncate(color.r),
          clampAndTruncate(color.g),
          clampAndTruncate(color.b),
        ], 49),
      );
    }
    exports_65("bgRgb24", bgRgb24);
    return {
      setters: [],
      execute: function () {
        // Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
        /**
             * A module to print ANSI terminal colors. Inspired by chalk, kleur, and colors
             * on npm.
             *
             * ```
             * import { bgBlue, red, bold } from "https://deno.land/std/fmt/colors.ts";
             * console.log(bgBlue(red(bold("Hello world!"))));
             * ```
             *
             * This module supports `NO_COLOR` environmental variable disabling any coloring
             * if `NO_COLOR` is set.
             */
        noColor = Deno.noColor;
        enabled = !noColor;
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.51.0/testing/diff",
  [],
  function (exports_66, context_66) {
    "use strict";
    var DiffType, REMOVED, COMMON, ADDED;
    var __moduleName = context_66 && context_66.id;
    function createCommon(A, B, reverse) {
      const common = [];
      if (A.length === 0 || B.length === 0) {
        return [];
      }
      for (let i = 0; i < Math.min(A.length, B.length); i += 1) {
        if (
          A[reverse ? A.length - i - 1 : i] ===
            B[reverse ? B.length - i - 1 : i]
        ) {
          common.push(A[reverse ? A.length - i - 1 : i]);
        } else {
          return common;
        }
      }
      return common;
    }
    function diff(A, B) {
      const prefixCommon = createCommon(A, B);
      const suffixCommon = createCommon(
        A.slice(prefixCommon.length),
        B.slice(prefixCommon.length),
        true,
      ).reverse();
      A = suffixCommon.length
        ? A.slice(prefixCommon.length, -suffixCommon.length)
        : A.slice(prefixCommon.length);
      B = suffixCommon.length
        ? B.slice(prefixCommon.length, -suffixCommon.length)
        : B.slice(prefixCommon.length);
      const swapped = B.length > A.length;
      [A, B] = swapped ? [B, A] : [A, B];
      const M = A.length;
      const N = B.length;
      if (!M && !N && !suffixCommon.length && !prefixCommon.length) {
        return [];
      }
      if (!N) {
        return [
          ...prefixCommon.map((c) => ({ type: DiffType.common, value: c })),
          ...A.map((a) => ({
            type: swapped ? DiffType.added : DiffType.removed,
            value: a,
          })),
          ...suffixCommon.map((c) => ({ type: DiffType.common, value: c })),
        ];
      }
      const offset = N;
      const delta = M - N;
      const size = M + N + 1;
      const fp = new Array(size).fill({ y: -1 });
      /**
         * INFO:
         * This buffer is used to save memory and improve performance.
         * The first half is used to save route and last half is used to save diff
         * type.
         * This is because, when I kept new uint8array area to save type,performance
         * worsened.
         */
      const routes = new Uint32Array((M * N + size + 1) * 2);
      const diffTypesPtrOffset = routes.length / 2;
      let ptr = 0;
      let p = -1;
      function backTrace(A, B, current, swapped) {
        const M = A.length;
        const N = B.length;
        const result = [];
        let a = M - 1;
        let b = N - 1;
        let j = routes[current.id];
        let type = routes[current.id + diffTypesPtrOffset];
        while (true) {
          if (!j && !type) {
            break;
          }
          const prev = j;
          if (type === REMOVED) {
            result.unshift({
              type: swapped ? DiffType.removed : DiffType.added,
              value: B[b],
            });
            b -= 1;
          } else if (type === ADDED) {
            result.unshift({
              type: swapped ? DiffType.added : DiffType.removed,
              value: A[a],
            });
            a -= 1;
          } else {
            result.unshift({ type: DiffType.common, value: A[a] });
            a -= 1;
            b -= 1;
          }
          j = routes[prev];
          type = routes[prev + diffTypesPtrOffset];
        }
        return result;
      }
      function createFP(slide, down, k, M) {
        if (slide && slide.y === -1 && down && down.y === -1) {
          return { y: 0, id: 0 };
        }
        if (
          (down && down.y === -1) ||
          k === M ||
          (slide && slide.y) > (down && down.y) + 1
        ) {
          const prev = slide.id;
          ptr++;
          routes[ptr] = prev;
          routes[ptr + diffTypesPtrOffset] = ADDED;
          return { y: slide.y, id: ptr };
        } else {
          const prev = down.id;
          ptr++;
          routes[ptr] = prev;
          routes[ptr + diffTypesPtrOffset] = REMOVED;
          return { y: down.y + 1, id: ptr };
        }
      }
      function snake(k, slide, down, _offset, A, B) {
        const M = A.length;
        const N = B.length;
        if (k < -N || M < k) {
          return { y: -1, id: -1 };
        }
        const fp = createFP(slide, down, k, M);
        while (fp.y + k < M && fp.y < N && A[fp.y + k] === B[fp.y]) {
          const prev = fp.id;
          ptr++;
          fp.id = ptr;
          fp.y += 1;
          routes[ptr] = prev;
          routes[ptr + diffTypesPtrOffset] = COMMON;
        }
        return fp;
      }
      while (fp[delta + offset].y < N) {
        p = p + 1;
        for (let k = -p; k < delta; ++k) {
          fp[k + offset] = snake(
            k,
            fp[k - 1 + offset],
            fp[k + 1 + offset],
            offset,
            A,
            B,
          );
        }
        for (let k = delta + p; k > delta; --k) {
          fp[k + offset] = snake(
            k,
            fp[k - 1 + offset],
            fp[k + 1 + offset],
            offset,
            A,
            B,
          );
        }
        fp[delta + offset] = snake(
          delta,
          fp[delta - 1 + offset],
          fp[delta + 1 + offset],
          offset,
          A,
          B,
        );
      }
      return [
        ...prefixCommon.map((c) => ({ type: DiffType.common, value: c })),
        ...backTrace(A, B, fp[delta + offset], swapped),
        ...suffixCommon.map((c) => ({ type: DiffType.common, value: c })),
      ];
    }
    exports_66("default", diff);
    return {
      setters: [],
      execute: function () {
        (function (DiffType) {
          DiffType["removed"] = "removed";
          DiffType["common"] = "common";
          DiffType["added"] = "added";
        })(DiffType || (DiffType = {}));
        exports_66("DiffType", DiffType);
        REMOVED = 1;
        COMMON = 2;
        ADDED = 3;
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.51.0/testing/asserts",
  [
    "https://deno.land/std@0.51.0/fmt/colors",
    "https://deno.land/std@0.51.0/testing/diff",
  ],
  function (exports_67, context_67) {
    "use strict";
    var colors_ts_2, diff_ts_2, CAN_NOT_DISPLAY, AssertionError;
    var __moduleName = context_67 && context_67.id;
    function format(v) {
      let string = Deno.inspect(v);
      if (typeof v == "string") {
        string = `"${string.replace(/(?=["\\])/g, "\\")}"`;
      }
      return string;
    }
    function createColor(diffType) {
      switch (diffType) {
        case diff_ts_2.DiffType.added:
          return (s) => colors_ts_2.green(colors_ts_2.bold(s));
        case diff_ts_2.DiffType.removed:
          return (s) => colors_ts_2.red(colors_ts_2.bold(s));
        default:
          return colors_ts_2.white;
      }
    }
    function createSign(diffType) {
      switch (diffType) {
        case diff_ts_2.DiffType.added:
          return "+   ";
        case diff_ts_2.DiffType.removed:
          return "-   ";
        default:
          return "    ";
      }
    }
    function buildMessage(diffResult) {
      const messages = [];
      messages.push("");
      messages.push("");
      messages.push(
        `    ${colors_ts_2.gray(colors_ts_2.bold("[Diff]"))} ${
          colors_ts_2.red(colors_ts_2.bold("Actual"))
        } / ${colors_ts_2.green(colors_ts_2.bold("Expected"))}`,
      );
      messages.push("");
      messages.push("");
      diffResult.forEach((result) => {
        const c = createColor(result.type);
        messages.push(c(`${createSign(result.type)}${result.value}`));
      });
      messages.push("");
      return messages;
    }
    function isKeyedCollection(x) {
      return [Symbol.iterator, "size"].every((k) => k in x);
    }
    function equal(c, d) {
      const seen = new Map();
      return (function compare(a, b) {
        // Have to render RegExp & Date for string comparison
        // unless it's mistreated as object
        if (
          a &&
          b &&
          ((a instanceof RegExp && b instanceof RegExp) ||
            (a instanceof Date && b instanceof Date))
        ) {
          return String(a) === String(b);
        }
        if (Object.is(a, b)) {
          return true;
        }
        if (a && typeof a === "object" && b && typeof b === "object") {
          if (seen.get(a) === b) {
            return true;
          }
          if (Object.keys(a || {}).length !== Object.keys(b || {}).length) {
            return false;
          }
          if (isKeyedCollection(a) && isKeyedCollection(b)) {
            if (a.size !== b.size) {
              return false;
            }
            let unmatchedEntries = a.size;
            for (const [aKey, aValue] of a.entries()) {
              for (const [bKey, bValue] of b.entries()) {
                /* Given that Map keys can be references, we need
                             * to ensure that they are also deeply equal */
                if (
                  (aKey === aValue && bKey === bValue && compare(aKey, bKey)) ||
                  (compare(aKey, bKey) && compare(aValue, bValue))
                ) {
                  unmatchedEntries--;
                }
              }
            }
            return unmatchedEntries === 0;
          }
          const merged = { ...a, ...b };
          for (const key in merged) {
            if (!compare(a && a[key], b && b[key])) {
              return false;
            }
          }
          seen.set(a, b);
          return true;
        }
        return false;
      })(c, d);
    }
    exports_67("equal", equal);
    /** Make an assertion, if not `true`, then throw. */
    function assert(expr, msg = "") {
      if (!expr) {
        throw new AssertionError(msg);
      }
    }
    exports_67("assert", assert);
    /**
     * Make an assertion that `actual` and `expected` are equal, deeply. If not
     * deeply equal, then throw.
     */
    function assertEquals(actual, expected, msg) {
      if (equal(actual, expected)) {
        return;
      }
      let message = "";
      const actualString = format(actual);
      const expectedString = format(expected);
      try {
        const diffResult = diff_ts_2.default(
          actualString.split("\n"),
          expectedString.split("\n"),
        );
        message = buildMessage(diffResult).join("\n");
      } catch (e) {
        message = `\n${colors_ts_2.red(CAN_NOT_DISPLAY)} + \n\n`;
      }
      if (msg) {
        message = msg;
      }
      throw new AssertionError(message);
    }
    exports_67("assertEquals", assertEquals);
    /**
     * Make an assertion that `actual` and `expected` are not equal, deeply.
     * If not then throw.
     */
    function assertNotEquals(actual, expected, msg) {
      if (!equal(actual, expected)) {
        return;
      }
      let actualString;
      let expectedString;
      try {
        actualString = String(actual);
      } catch (e) {
        actualString = "[Cannot display]";
      }
      try {
        expectedString = String(expected);
      } catch (e) {
        expectedString = "[Cannot display]";
      }
      if (!msg) {
        msg = `actual: ${actualString} expected: ${expectedString}`;
      }
      throw new AssertionError(msg);
    }
    exports_67("assertNotEquals", assertNotEquals);
    /**
     * Make an assertion that `actual` and `expected` are strictly equal.  If
     * not then throw.
     */
    function assertStrictEq(actual, expected, msg) {
      if (actual !== expected) {
        let actualString;
        let expectedString;
        try {
          actualString = String(actual);
        } catch (e) {
          actualString = "[Cannot display]";
        }
        try {
          expectedString = String(expected);
        } catch (e) {
          expectedString = "[Cannot display]";
        }
        if (!msg) {
          msg = `actual: ${actualString} expected: ${expectedString}`;
        }
        throw new AssertionError(msg);
      }
    }
    exports_67("assertStrictEq", assertStrictEq);
    /**
     * Make an assertion that actual contains expected. If not
     * then thrown.
     */
    function assertStrContains(actual, expected, msg) {
      if (!actual.includes(expected)) {
        if (!msg) {
          msg = `actual: "${actual}" expected to contains: "${expected}"`;
        }
        throw new AssertionError(msg);
      }
    }
    exports_67("assertStrContains", assertStrContains);
    /**
     * Make an assertion that `actual` contains the `expected` values
     * If not then thrown.
     */
    function assertArrayContains(actual, expected, msg) {
      const missing = [];
      for (let i = 0; i < expected.length; i++) {
        let found = false;
        for (let j = 0; j < actual.length; j++) {
          if (equal(expected[i], actual[j])) {
            found = true;
            break;
          }
        }
        if (!found) {
          missing.push(expected[i]);
        }
      }
      if (missing.length === 0) {
        return;
      }
      if (!msg) {
        msg = `actual: "${actual}" expected to contains: "${expected}"`;
        msg += "\n";
        msg += `missing: ${missing}`;
      }
      throw new AssertionError(msg);
    }
    exports_67("assertArrayContains", assertArrayContains);
    /**
     * Make an assertion that `actual` match RegExp `expected`. If not
     * then thrown
     */
    function assertMatch(actual, expected, msg) {
      if (!expected.test(actual)) {
        if (!msg) {
          msg = `actual: "${actual}" expected to match: "${expected}"`;
        }
        throw new AssertionError(msg);
      }
    }
    exports_67("assertMatch", assertMatch);
    /**
     * Forcefully throws a failed assertion
     */
    function fail(msg) {
      // eslint-disable-next-line @typescript-eslint/no-use-before-define
      assert(false, `Failed assertion${msg ? `: ${msg}` : "."}`);
    }
    exports_67("fail", fail);
    /** Executes a function, expecting it to throw.  If it does not, then it
     * throws.  An error class and a string that should be included in the
     * error message can also be asserted.
     */
    function assertThrows(fn, ErrorClass, msgIncludes = "", msg) {
      let doesThrow = false;
      let error = null;
      try {
        fn();
      } catch (e) {
        if (
          ErrorClass && !(Object.getPrototypeOf(e) === ErrorClass.prototype)
        ) {
          msg =
            `Expected error to be instance of "${ErrorClass.name}", but was "${e.constructor.name}"${
              msg ? `: ${msg}` : "."
            }`;
          throw new AssertionError(msg);
        }
        if (msgIncludes && !e.message.includes(msgIncludes)) {
          msg =
            `Expected error message to include "${msgIncludes}", but got "${e.message}"${
              msg ? `: ${msg}` : "."
            }`;
          throw new AssertionError(msg);
        }
        doesThrow = true;
        error = e;
      }
      if (!doesThrow) {
        msg = `Expected function to throw${msg ? `: ${msg}` : "."}`;
        throw new AssertionError(msg);
      }
      return error;
    }
    exports_67("assertThrows", assertThrows);
    async function assertThrowsAsync(fn, ErrorClass, msgIncludes = "", msg) {
      let doesThrow = false;
      let error = null;
      try {
        await fn();
      } catch (e) {
        if (
          ErrorClass && !(Object.getPrototypeOf(e) === ErrorClass.prototype)
        ) {
          msg =
            `Expected error to be instance of "${ErrorClass.name}", but got "${e.name}"${
              msg ? `: ${msg}` : "."
            }`;
          throw new AssertionError(msg);
        }
        if (msgIncludes && !e.message.includes(msgIncludes)) {
          msg =
            `Expected error message to include "${msgIncludes}", but got "${e.message}"${
              msg ? `: ${msg}` : "."
            }`;
          throw new AssertionError(msg);
        }
        doesThrow = true;
        error = e;
      }
      if (!doesThrow) {
        msg = `Expected function to throw${msg ? `: ${msg}` : "."}`;
        throw new AssertionError(msg);
      }
      return error;
    }
    exports_67("assertThrowsAsync", assertThrowsAsync);
    /** Use this to stub out methods that will throw when invoked. */
    function unimplemented(msg) {
      throw new AssertionError(msg || "unimplemented");
    }
    exports_67("unimplemented", unimplemented);
    /** Use this to assert unreachable code. */
    function unreachable() {
      throw new AssertionError("unreachable");
    }
    exports_67("unreachable", unreachable);
    return {
      setters: [
        function (colors_ts_2_1) {
          colors_ts_2 = colors_ts_2_1;
        },
        function (diff_ts_2_1) {
          diff_ts_2 = diff_ts_2_1;
        },
      ],
      execute: function () {
        CAN_NOT_DISPLAY = "[Cannot display]";
        AssertionError = class AssertionError extends Error {
          constructor(message) {
            super(message);
            this.name = "AssertionError";
          }
        };
        exports_67("AssertionError", AssertionError);
      },
    };
  },
);
// Copyright the Browserify authors. MIT License.
// Ported from https://github.com/browserify/path-browserify/
System.register(
  "https://deno.land/std@0.51.0/path/win32",
  [
    "https://deno.land/std@0.51.0/path/_constants",
    "https://deno.land/std@0.51.0/path/_util",
    "https://deno.land/std@0.51.0/testing/asserts",
  ],
  function (exports_68, context_68) {
    "use strict";
    var cwd, env, _constants_ts_5, _util_ts_3, asserts_ts_9, sep, delimiter;
    var __moduleName = context_68 && context_68.id;
    function resolve(...pathSegments) {
      let resolvedDevice = "";
      let resolvedTail = "";
      let resolvedAbsolute = false;
      for (let i = pathSegments.length - 1; i >= -1; i--) {
        let path;
        if (i >= 0) {
          path = pathSegments[i];
        } else if (!resolvedDevice) {
          path = cwd();
        } else {
          // Windows has the concept of drive-specific current working
          // directories. If we've resolved a drive letter but not yet an
          // absolute path, get cwd for that drive, or the process cwd if
          // the drive cwd is not available. We're sure the device is not
          // a UNC path at this points, because UNC paths are always absolute.
          path = env.get(`=${resolvedDevice}`) || cwd();
          // Verify that a cwd was found and that it actually points
          // to our drive. If not, default to the drive's root.
          if (
            path === undefined ||
            path.slice(0, 3).toLowerCase() !==
              `${resolvedDevice.toLowerCase()}\\`
          ) {
            path = `${resolvedDevice}\\`;
          }
        }
        _util_ts_3.assertPath(path);
        const len = path.length;
        // Skip empty entries
        if (len === 0) {
          continue;
        }
        let rootEnd = 0;
        let device = "";
        let isAbsolute = false;
        const code = path.charCodeAt(0);
        // Try to match a root
        if (len > 1) {
          if (_util_ts_3.isPathSeparator(code)) {
            // Possible UNC root
            // If we started with a separator, we know we at least have an
            // absolute path of some kind (UNC or otherwise)
            isAbsolute = true;
            if (_util_ts_3.isPathSeparator(path.charCodeAt(1))) {
              // Matched double path separator at beginning
              let j = 2;
              let last = j;
              // Match 1 or more non-path separators
              for (; j < len; ++j) {
                if (_util_ts_3.isPathSeparator(path.charCodeAt(j))) {
                  break;
                }
              }
              if (j < len && j !== last) {
                const firstPart = path.slice(last, j);
                // Matched!
                last = j;
                // Match 1 or more path separators
                for (; j < len; ++j) {
                  if (!_util_ts_3.isPathSeparator(path.charCodeAt(j))) {
                    break;
                  }
                }
                if (j < len && j !== last) {
                  // Matched!
                  last = j;
                  // Match 1 or more non-path separators
                  for (; j < len; ++j) {
                    if (_util_ts_3.isPathSeparator(path.charCodeAt(j))) {
                      break;
                    }
                  }
                  if (j === len) {
                    // We matched a UNC root only
                    device = `\\\\${firstPart}\\${path.slice(last)}`;
                    rootEnd = j;
                  } else if (j !== last) {
                    // We matched a UNC root with leftovers
                    device = `\\\\${firstPart}\\${path.slice(last, j)}`;
                    rootEnd = j;
                  }
                }
              }
            } else {
              rootEnd = 1;
            }
          } else if (_util_ts_3.isWindowsDeviceRoot(code)) {
            // Possible device root
            if (path.charCodeAt(1) === _constants_ts_5.CHAR_COLON) {
              device = path.slice(0, 2);
              rootEnd = 2;
              if (len > 2) {
                if (_util_ts_3.isPathSeparator(path.charCodeAt(2))) {
                  // Treat separator following drive name as an absolute path
                  // indicator
                  isAbsolute = true;
                  rootEnd = 3;
                }
              }
            }
          }
        } else if (_util_ts_3.isPathSeparator(code)) {
          // `path` contains just a path separator
          rootEnd = 1;
          isAbsolute = true;
        }
        if (
          device.length > 0 &&
          resolvedDevice.length > 0 &&
          device.toLowerCase() !== resolvedDevice.toLowerCase()
        ) {
          // This path points to another device so it is not applicable
          continue;
        }
        if (resolvedDevice.length === 0 && device.length > 0) {
          resolvedDevice = device;
        }
        if (!resolvedAbsolute) {
          resolvedTail = `${path.slice(rootEnd)}\\${resolvedTail}`;
          resolvedAbsolute = isAbsolute;
        }
        if (resolvedAbsolute && resolvedDevice.length > 0) {
          break;
        }
      }
      // At this point the path should be resolved to a full absolute path,
      // but handle relative paths to be safe (might happen when process.cwd()
      // fails)
      // Normalize the tail path
      resolvedTail = _util_ts_3.normalizeString(
        resolvedTail,
        !resolvedAbsolute,
        "\\",
        _util_ts_3.isPathSeparator,
      );
      return resolvedDevice + (resolvedAbsolute ? "\\" : "") + resolvedTail ||
        ".";
    }
    exports_68("resolve", resolve);
    function normalize(path) {
      _util_ts_3.assertPath(path);
      const len = path.length;
      if (len === 0) {
        return ".";
      }
      let rootEnd = 0;
      let device;
      let isAbsolute = false;
      const code = path.charCodeAt(0);
      // Try to match a root
      if (len > 1) {
        if (_util_ts_3.isPathSeparator(code)) {
          // Possible UNC root
          // If we started with a separator, we know we at least have an absolute
          // path of some kind (UNC or otherwise)
          isAbsolute = true;
          if (_util_ts_3.isPathSeparator(path.charCodeAt(1))) {
            // Matched double path separator at beginning
            let j = 2;
            let last = j;
            // Match 1 or more non-path separators
            for (; j < len; ++j) {
              if (_util_ts_3.isPathSeparator(path.charCodeAt(j))) {
                break;
              }
            }
            if (j < len && j !== last) {
              const firstPart = path.slice(last, j);
              // Matched!
              last = j;
              // Match 1 or more path separators
              for (; j < len; ++j) {
                if (!_util_ts_3.isPathSeparator(path.charCodeAt(j))) {
                  break;
                }
              }
              if (j < len && j !== last) {
                // Matched!
                last = j;
                // Match 1 or more non-path separators
                for (; j < len; ++j) {
                  if (_util_ts_3.isPathSeparator(path.charCodeAt(j))) {
                    break;
                  }
                }
                if (j === len) {
                  // We matched a UNC root only
                  // Return the normalized version of the UNC root since there
                  // is nothing left to process
                  return `\\\\${firstPart}\\${path.slice(last)}\\`;
                } else if (j !== last) {
                  // We matched a UNC root with leftovers
                  device = `\\\\${firstPart}\\${path.slice(last, j)}`;
                  rootEnd = j;
                }
              }
            }
          } else {
            rootEnd = 1;
          }
        } else if (_util_ts_3.isWindowsDeviceRoot(code)) {
          // Possible device root
          if (path.charCodeAt(1) === _constants_ts_5.CHAR_COLON) {
            device = path.slice(0, 2);
            rootEnd = 2;
            if (len > 2) {
              if (_util_ts_3.isPathSeparator(path.charCodeAt(2))) {
                // Treat separator following drive name as an absolute path
                // indicator
                isAbsolute = true;
                rootEnd = 3;
              }
            }
          }
        }
      } else if (_util_ts_3.isPathSeparator(code)) {
        // `path` contains just a path separator, exit early to avoid unnecessary
        // work
        return "\\";
      }
      let tail;
      if (rootEnd < len) {
        tail = _util_ts_3.normalizeString(
          path.slice(rootEnd),
          !isAbsolute,
          "\\",
          _util_ts_3.isPathSeparator,
        );
      } else {
        tail = "";
      }
      if (tail.length === 0 && !isAbsolute) {
        tail = ".";
      }
      if (
        tail.length > 0 &&
        _util_ts_3.isPathSeparator(path.charCodeAt(len - 1))
      ) {
        tail += "\\";
      }
      if (device === undefined) {
        if (isAbsolute) {
          if (tail.length > 0) {
            return `\\${tail}`;
          } else {
            return "\\";
          }
        } else if (tail.length > 0) {
          return tail;
        } else {
          return "";
        }
      } else if (isAbsolute) {
        if (tail.length > 0) {
          return `${device}\\${tail}`;
        } else {
          return `${device}\\`;
        }
      } else if (tail.length > 0) {
        return device + tail;
      } else {
        return device;
      }
    }
    exports_68("normalize", normalize);
    function isAbsolute(path) {
      _util_ts_3.assertPath(path);
      const len = path.length;
      if (len === 0) {
        return false;
      }
      const code = path.charCodeAt(0);
      if (_util_ts_3.isPathSeparator(code)) {
        return true;
      } else if (_util_ts_3.isWindowsDeviceRoot(code)) {
        // Possible device root
        if (len > 2 && path.charCodeAt(1) === _constants_ts_5.CHAR_COLON) {
          if (_util_ts_3.isPathSeparator(path.charCodeAt(2))) {
            return true;
          }
        }
      }
      return false;
    }
    exports_68("isAbsolute", isAbsolute);
    function join(...paths) {
      const pathsCount = paths.length;
      if (pathsCount === 0) {
        return ".";
      }
      let joined;
      let firstPart = null;
      for (let i = 0; i < pathsCount; ++i) {
        const path = paths[i];
        _util_ts_3.assertPath(path);
        if (path.length > 0) {
          if (joined === undefined) {
            joined = firstPart = path;
          } else {
            joined += `\\${path}`;
          }
        }
      }
      if (joined === undefined) {
        return ".";
      }
      // Make sure that the joined path doesn't start with two slashes, because
      // normalize() will mistake it for an UNC path then.
      //
      // This step is skipped when it is very clear that the user actually
      // intended to point at an UNC path. This is assumed when the first
      // non-empty string arguments starts with exactly two slashes followed by
      // at least one more non-slash character.
      //
      // Note that for normalize() to treat a path as an UNC path it needs to
      // have at least 2 components, so we don't filter for that here.
      // This means that the user can use join to construct UNC paths from
      // a server name and a share name; for example:
      //   path.join('//server', 'share') -> '\\\\server\\share\\')
      let needsReplace = true;
      let slashCount = 0;
      asserts_ts_9.assert(firstPart != null);
      if (_util_ts_3.isPathSeparator(firstPart.charCodeAt(0))) {
        ++slashCount;
        const firstLen = firstPart.length;
        if (firstLen > 1) {
          if (_util_ts_3.isPathSeparator(firstPart.charCodeAt(1))) {
            ++slashCount;
            if (firstLen > 2) {
              if (_util_ts_3.isPathSeparator(firstPart.charCodeAt(2))) {
                ++slashCount;
              } else {
                // We matched a UNC path in the first part
                needsReplace = false;
              }
            }
          }
        }
      }
      if (needsReplace) {
        // Find any more consecutive slashes we need to replace
        for (; slashCount < joined.length; ++slashCount) {
          if (!_util_ts_3.isPathSeparator(joined.charCodeAt(slashCount))) {
            break;
          }
        }
        // Replace the slashes if needed
        if (slashCount >= 2) {
          joined = `\\${joined.slice(slashCount)}`;
        }
      }
      return normalize(joined);
    }
    exports_68("join", join);
    // It will solve the relative path from `from` to `to`, for instance:
    //  from = 'C:\\orandea\\test\\aaa'
    //  to = 'C:\\orandea\\impl\\bbb'
    // The output of the function should be: '..\\..\\impl\\bbb'
    function relative(from, to) {
      _util_ts_3.assertPath(from);
      _util_ts_3.assertPath(to);
      if (from === to) {
        return "";
      }
      const fromOrig = resolve(from);
      const toOrig = resolve(to);
      if (fromOrig === toOrig) {
        return "";
      }
      from = fromOrig.toLowerCase();
      to = toOrig.toLowerCase();
      if (from === to) {
        return "";
      }
      // Trim any leading backslashes
      let fromStart = 0;
      let fromEnd = from.length;
      for (; fromStart < fromEnd; ++fromStart) {
        if (
          from.charCodeAt(fromStart) !== _constants_ts_5.CHAR_BACKWARD_SLASH
        ) {
          break;
        }
      }
      // Trim trailing backslashes (applicable to UNC paths only)
      for (; fromEnd - 1 > fromStart; --fromEnd) {
        if (
          from.charCodeAt(fromEnd - 1) !== _constants_ts_5.CHAR_BACKWARD_SLASH
        ) {
          break;
        }
      }
      const fromLen = fromEnd - fromStart;
      // Trim any leading backslashes
      let toStart = 0;
      let toEnd = to.length;
      for (; toStart < toEnd; ++toStart) {
        if (to.charCodeAt(toStart) !== _constants_ts_5.CHAR_BACKWARD_SLASH) {
          break;
        }
      }
      // Trim trailing backslashes (applicable to UNC paths only)
      for (; toEnd - 1 > toStart; --toEnd) {
        if (to.charCodeAt(toEnd - 1) !== _constants_ts_5.CHAR_BACKWARD_SLASH) {
          break;
        }
      }
      const toLen = toEnd - toStart;
      // Compare paths to find the longest common path from root
      const length = fromLen < toLen ? fromLen : toLen;
      let lastCommonSep = -1;
      let i = 0;
      for (; i <= length; ++i) {
        if (i === length) {
          if (toLen > length) {
            if (
              to.charCodeAt(toStart + i) === _constants_ts_5.CHAR_BACKWARD_SLASH
            ) {
              // We get here if `from` is the exact base path for `to`.
              // For example: from='C:\\foo\\bar'; to='C:\\foo\\bar\\baz'
              return toOrig.slice(toStart + i + 1);
            } else if (i === 2) {
              // We get here if `from` is the device root.
              // For example: from='C:\\'; to='C:\\foo'
              return toOrig.slice(toStart + i);
            }
          }
          if (fromLen > length) {
            if (
              from.charCodeAt(fromStart + i) ===
                _constants_ts_5.CHAR_BACKWARD_SLASH
            ) {
              // We get here if `to` is the exact base path for `from`.
              // For example: from='C:\\foo\\bar'; to='C:\\foo'
              lastCommonSep = i;
            } else if (i === 2) {
              // We get here if `to` is the device root.
              // For example: from='C:\\foo\\bar'; to='C:\\'
              lastCommonSep = 3;
            }
          }
          break;
        }
        const fromCode = from.charCodeAt(fromStart + i);
        const toCode = to.charCodeAt(toStart + i);
        if (fromCode !== toCode) {
          break;
        } else if (fromCode === _constants_ts_5.CHAR_BACKWARD_SLASH) {
          lastCommonSep = i;
        }
      }
      // We found a mismatch before the first common path separator was seen, so
      // return the original `to`.
      if (i !== length && lastCommonSep === -1) {
        return toOrig;
      }
      let out = "";
      if (lastCommonSep === -1) {
        lastCommonSep = 0;
      }
      // Generate the relative path based on the path difference between `to` and
      // `from`
      for (i = fromStart + lastCommonSep + 1; i <= fromEnd; ++i) {
        if (
          i === fromEnd ||
          from.charCodeAt(i) === _constants_ts_5.CHAR_BACKWARD_SLASH
        ) {
          if (out.length === 0) {
            out += "..";
          } else {
            out += "\\..";
          }
        }
      }
      // Lastly, append the rest of the destination (`to`) path that comes after
      // the common path parts
      if (out.length > 0) {
        return out + toOrig.slice(toStart + lastCommonSep, toEnd);
      } else {
        toStart += lastCommonSep;
        if (
          toOrig.charCodeAt(toStart) === _constants_ts_5.CHAR_BACKWARD_SLASH
        ) {
          ++toStart;
        }
        return toOrig.slice(toStart, toEnd);
      }
    }
    exports_68("relative", relative);
    function toNamespacedPath(path) {
      // Note: this will *probably* throw somewhere.
      if (typeof path !== "string") {
        return path;
      }
      if (path.length === 0) {
        return "";
      }
      const resolvedPath = resolve(path);
      if (resolvedPath.length >= 3) {
        if (
          resolvedPath.charCodeAt(0) === _constants_ts_5.CHAR_BACKWARD_SLASH
        ) {
          // Possible UNC root
          if (
            resolvedPath.charCodeAt(1) === _constants_ts_5.CHAR_BACKWARD_SLASH
          ) {
            const code = resolvedPath.charCodeAt(2);
            if (
              code !== _constants_ts_5.CHAR_QUESTION_MARK &&
              code !== _constants_ts_5.CHAR_DOT
            ) {
              // Matched non-long UNC root, convert the path to a long UNC path
              return `\\\\?\\UNC\\${resolvedPath.slice(2)}`;
            }
          }
        } else if (_util_ts_3.isWindowsDeviceRoot(resolvedPath.charCodeAt(0))) {
          // Possible device root
          if (
            resolvedPath.charCodeAt(1) === _constants_ts_5.CHAR_COLON &&
            resolvedPath.charCodeAt(2) === _constants_ts_5.CHAR_BACKWARD_SLASH
          ) {
            // Matched device root, convert the path to a long UNC path
            return `\\\\?\\${resolvedPath}`;
          }
        }
      }
      return path;
    }
    exports_68("toNamespacedPath", toNamespacedPath);
    function dirname(path) {
      _util_ts_3.assertPath(path);
      const len = path.length;
      if (len === 0) {
        return ".";
      }
      let rootEnd = -1;
      let end = -1;
      let matchedSlash = true;
      let offset = 0;
      const code = path.charCodeAt(0);
      // Try to match a root
      if (len > 1) {
        if (_util_ts_3.isPathSeparator(code)) {
          // Possible UNC root
          rootEnd = offset = 1;
          if (_util_ts_3.isPathSeparator(path.charCodeAt(1))) {
            // Matched double path separator at beginning
            let j = 2;
            let last = j;
            // Match 1 or more non-path separators
            for (; j < len; ++j) {
              if (_util_ts_3.isPathSeparator(path.charCodeAt(j))) {
                break;
              }
            }
            if (j < len && j !== last) {
              // Matched!
              last = j;
              // Match 1 or more path separators
              for (; j < len; ++j) {
                if (!_util_ts_3.isPathSeparator(path.charCodeAt(j))) {
                  break;
                }
              }
              if (j < len && j !== last) {
                // Matched!
                last = j;
                // Match 1 or more non-path separators
                for (; j < len; ++j) {
                  if (_util_ts_3.isPathSeparator(path.charCodeAt(j))) {
                    break;
                  }
                }
                if (j === len) {
                  // We matched a UNC root only
                  return path;
                }
                if (j !== last) {
                  // We matched a UNC root with leftovers
                  // Offset by 1 to include the separator after the UNC root to
                  // treat it as a "normal root" on top of a (UNC) root
                  rootEnd = offset = j + 1;
                }
              }
            }
          }
        } else if (_util_ts_3.isWindowsDeviceRoot(code)) {
          // Possible device root
          if (path.charCodeAt(1) === _constants_ts_5.CHAR_COLON) {
            rootEnd = offset = 2;
            if (len > 2) {
              if (_util_ts_3.isPathSeparator(path.charCodeAt(2))) {
                rootEnd = offset = 3;
              }
            }
          }
        }
      } else if (_util_ts_3.isPathSeparator(code)) {
        // `path` contains just a path separator, exit early to avoid
        // unnecessary work
        return path;
      }
      for (let i = len - 1; i >= offset; --i) {
        if (_util_ts_3.isPathSeparator(path.charCodeAt(i))) {
          if (!matchedSlash) {
            end = i;
            break;
          }
        } else {
          // We saw the first non-path separator
          matchedSlash = false;
        }
      }
      if (end === -1) {
        if (rootEnd === -1) {
          return ".";
        } else {
          end = rootEnd;
        }
      }
      return path.slice(0, end);
    }
    exports_68("dirname", dirname);
    function basename(path, ext = "") {
      if (ext !== undefined && typeof ext !== "string") {
        throw new TypeError('"ext" argument must be a string');
      }
      _util_ts_3.assertPath(path);
      let start = 0;
      let end = -1;
      let matchedSlash = true;
      let i;
      // Check for a drive letter prefix so as not to mistake the following
      // path separator as an extra separator at the end of the path that can be
      // disregarded
      if (path.length >= 2) {
        const drive = path.charCodeAt(0);
        if (_util_ts_3.isWindowsDeviceRoot(drive)) {
          if (path.charCodeAt(1) === _constants_ts_5.CHAR_COLON) {
            start = 2;
          }
        }
      }
      if (ext !== undefined && ext.length > 0 && ext.length <= path.length) {
        if (ext.length === path.length && ext === path) {
          return "";
        }
        let extIdx = ext.length - 1;
        let firstNonSlashEnd = -1;
        for (i = path.length - 1; i >= start; --i) {
          const code = path.charCodeAt(i);
          if (_util_ts_3.isPathSeparator(code)) {
            // If we reached a path separator that was not part of a set of path
            // separators at the end of the string, stop now
            if (!matchedSlash) {
              start = i + 1;
              break;
            }
          } else {
            if (firstNonSlashEnd === -1) {
              // We saw the first non-path separator, remember this index in case
              // we need it if the extension ends up not matching
              matchedSlash = false;
              firstNonSlashEnd = i + 1;
            }
            if (extIdx >= 0) {
              // Try to match the explicit extension
              if (code === ext.charCodeAt(extIdx)) {
                if (--extIdx === -1) {
                  // We matched the extension, so mark this as the end of our path
                  // component
                  end = i;
                }
              } else {
                // Extension does not match, so our result is the entire path
                // component
                extIdx = -1;
                end = firstNonSlashEnd;
              }
            }
          }
        }
        if (start === end) {
          end = firstNonSlashEnd;
        } else if (end === -1) {
          end = path.length;
        }
        return path.slice(start, end);
      } else {
        for (i = path.length - 1; i >= start; --i) {
          if (_util_ts_3.isPathSeparator(path.charCodeAt(i))) {
            // If we reached a path separator that was not part of a set of path
            // separators at the end of the string, stop now
            if (!matchedSlash) {
              start = i + 1;
              break;
            }
          } else if (end === -1) {
            // We saw the first non-path separator, mark this as the end of our
            // path component
            matchedSlash = false;
            end = i + 1;
          }
        }
        if (end === -1) {
          return "";
        }
        return path.slice(start, end);
      }
    }
    exports_68("basename", basename);
    function extname(path) {
      _util_ts_3.assertPath(path);
      let start = 0;
      let startDot = -1;
      let startPart = 0;
      let end = -1;
      let matchedSlash = true;
      // Track the state of characters (if any) we see before our first dot and
      // after any path separator we find
      let preDotState = 0;
      // Check for a drive letter prefix so as not to mistake the following
      // path separator as an extra separator at the end of the path that can be
      // disregarded
      if (
        path.length >= 2 &&
        path.charCodeAt(1) === _constants_ts_5.CHAR_COLON &&
        _util_ts_3.isWindowsDeviceRoot(path.charCodeAt(0))
      ) {
        start = startPart = 2;
      }
      for (let i = path.length - 1; i >= start; --i) {
        const code = path.charCodeAt(i);
        if (_util_ts_3.isPathSeparator(code)) {
          // If we reached a path separator that was not part of a set of path
          // separators at the end of the string, stop now
          if (!matchedSlash) {
            startPart = i + 1;
            break;
          }
          continue;
        }
        if (end === -1) {
          // We saw the first non-path separator, mark this as the end of our
          // extension
          matchedSlash = false;
          end = i + 1;
        }
        if (code === _constants_ts_5.CHAR_DOT) {
          // If this is our first dot, mark it as the start of our extension
          if (startDot === -1) {
            startDot = i;
          } else if (preDotState !== 1) {
            preDotState = 1;
          }
        } else if (startDot !== -1) {
          // We saw a non-dot and non-path separator before our dot, so we should
          // have a good chance at having a non-empty extension
          preDotState = -1;
        }
      }
      if (
        startDot === -1 ||
        end === -1 ||
        // We saw a non-dot character immediately before the dot
        preDotState === 0 ||
        // The (right-most) trimmed path component is exactly '..'
        (preDotState === 1 && startDot === end - 1 &&
          startDot === startPart + 1)
      ) {
        return "";
      }
      return path.slice(startDot, end);
    }
    exports_68("extname", extname);
    function format(pathObject) {
      /* eslint-disable max-len */
      if (pathObject === null || typeof pathObject !== "object") {
        throw new TypeError(
          `The "pathObject" argument must be of type Object. Received type ${typeof pathObject}`,
        );
      }
      return _util_ts_3._format("\\", pathObject);
    }
    exports_68("format", format);
    function parse(path) {
      _util_ts_3.assertPath(path);
      const ret = { root: "", dir: "", base: "", ext: "", name: "" };
      const len = path.length;
      if (len === 0) {
        return ret;
      }
      let rootEnd = 0;
      let code = path.charCodeAt(0);
      // Try to match a root
      if (len > 1) {
        if (_util_ts_3.isPathSeparator(code)) {
          // Possible UNC root
          rootEnd = 1;
          if (_util_ts_3.isPathSeparator(path.charCodeAt(1))) {
            // Matched double path separator at beginning
            let j = 2;
            let last = j;
            // Match 1 or more non-path separators
            for (; j < len; ++j) {
              if (_util_ts_3.isPathSeparator(path.charCodeAt(j))) {
                break;
              }
            }
            if (j < len && j !== last) {
              // Matched!
              last = j;
              // Match 1 or more path separators
              for (; j < len; ++j) {
                if (!_util_ts_3.isPathSeparator(path.charCodeAt(j))) {
                  break;
                }
              }
              if (j < len && j !== last) {
                // Matched!
                last = j;
                // Match 1 or more non-path separators
                for (; j < len; ++j) {
                  if (_util_ts_3.isPathSeparator(path.charCodeAt(j))) {
                    break;
                  }
                }
                if (j === len) {
                  // We matched a UNC root only
                  rootEnd = j;
                } else if (j !== last) {
                  // We matched a UNC root with leftovers
                  rootEnd = j + 1;
                }
              }
            }
          }
        } else if (_util_ts_3.isWindowsDeviceRoot(code)) {
          // Possible device root
          if (path.charCodeAt(1) === _constants_ts_5.CHAR_COLON) {
            rootEnd = 2;
            if (len > 2) {
              if (_util_ts_3.isPathSeparator(path.charCodeAt(2))) {
                if (len === 3) {
                  // `path` contains just a drive root, exit early to avoid
                  // unnecessary work
                  ret.root = ret.dir = path;
                  return ret;
                }
                rootEnd = 3;
              }
            } else {
              // `path` contains just a drive root, exit early to avoid
              // unnecessary work
              ret.root = ret.dir = path;
              return ret;
            }
          }
        }
      } else if (_util_ts_3.isPathSeparator(code)) {
        // `path` contains just a path separator, exit early to avoid
        // unnecessary work
        ret.root = ret.dir = path;
        return ret;
      }
      if (rootEnd > 0) {
        ret.root = path.slice(0, rootEnd);
      }
      let startDot = -1;
      let startPart = rootEnd;
      let end = -1;
      let matchedSlash = true;
      let i = path.length - 1;
      // Track the state of characters (if any) we see before our first dot and
      // after any path separator we find
      let preDotState = 0;
      // Get non-dir info
      for (; i >= rootEnd; --i) {
        code = path.charCodeAt(i);
        if (_util_ts_3.isPathSeparator(code)) {
          // If we reached a path separator that was not part of a set of path
          // separators at the end of the string, stop now
          if (!matchedSlash) {
            startPart = i + 1;
            break;
          }
          continue;
        }
        if (end === -1) {
          // We saw the first non-path separator, mark this as the end of our
          // extension
          matchedSlash = false;
          end = i + 1;
        }
        if (code === _constants_ts_5.CHAR_DOT) {
          // If this is our first dot, mark it as the start of our extension
          if (startDot === -1) {
            startDot = i;
          } else if (preDotState !== 1) {
            preDotState = 1;
          }
        } else if (startDot !== -1) {
          // We saw a non-dot and non-path separator before our dot, so we should
          // have a good chance at having a non-empty extension
          preDotState = -1;
        }
      }
      if (
        startDot === -1 ||
        end === -1 ||
        // We saw a non-dot character immediately before the dot
        preDotState === 0 ||
        // The (right-most) trimmed path component is exactly '..'
        (preDotState === 1 && startDot === end - 1 &&
          startDot === startPart + 1)
      ) {
        if (end !== -1) {
          ret.base = ret.name = path.slice(startPart, end);
        }
      } else {
        ret.name = path.slice(startPart, startDot);
        ret.base = path.slice(startPart, end);
        ret.ext = path.slice(startDot, end);
      }
      // If the directory is the root, use the entire root as the `dir` including
      // the trailing slash if any (`C:\abc` -> `C:\`). Otherwise, strip out the
      // trailing slash (`C:\abc\def` -> `C:\abc`).
      if (startPart > 0 && startPart !== rootEnd) {
        ret.dir = path.slice(0, startPart - 1);
      } else {
        ret.dir = ret.root;
      }
      return ret;
    }
    exports_68("parse", parse);
    /** Converts a file URL to a path string.
     *
     *      fromFileUrl("file:///C:/Users/foo"); // "C:\\Users\\foo"
     *      fromFileUrl("file:///home/foo"); // "\\home\\foo"
     *
     * Note that non-file URLs are treated as file URLs and irrelevant components
     * are ignored.
     */
    function fromFileUrl(url) {
      return new URL(url).pathname
        .replace(/^\/*([A-Za-z]:)(\/|$)/, "$1/")
        .replace(/\//g, "\\");
    }
    exports_68("fromFileUrl", fromFileUrl);
    return {
      setters: [
        function (_constants_ts_5_1) {
          _constants_ts_5 = _constants_ts_5_1;
        },
        function (_util_ts_3_1) {
          _util_ts_3 = _util_ts_3_1;
        },
        function (asserts_ts_9_1) {
          asserts_ts_9 = asserts_ts_9_1;
        },
      ],
      execute: function () {
        cwd = Deno.cwd, env = Deno.env;
        exports_68("sep", sep = "\\");
        exports_68("delimiter", delimiter = ";");
      },
    };
  },
);
// Copyright the Browserify authors. MIT License.
// Ported from https://github.com/browserify/path-browserify/
System.register(
  "https://deno.land/std@0.51.0/path/posix",
  [
    "https://deno.land/std@0.51.0/path/_constants",
    "https://deno.land/std@0.51.0/path/_util",
  ],
  function (exports_69, context_69) {
    "use strict";
    var cwd, _constants_ts_6, _util_ts_4, sep, delimiter;
    var __moduleName = context_69 && context_69.id;
    // path.resolve([from ...], to)
    function resolve(...pathSegments) {
      let resolvedPath = "";
      let resolvedAbsolute = false;
      for (let i = pathSegments.length - 1; i >= -1 && !resolvedAbsolute; i--) {
        let path;
        if (i >= 0) {
          path = pathSegments[i];
        } else {
          path = cwd();
        }
        _util_ts_4.assertPath(path);
        // Skip empty entries
        if (path.length === 0) {
          continue;
        }
        resolvedPath = `${path}/${resolvedPath}`;
        resolvedAbsolute =
          path.charCodeAt(0) === _constants_ts_6.CHAR_FORWARD_SLASH;
      }
      // At this point the path should be resolved to a full absolute path, but
      // handle relative paths to be safe (might happen when process.cwd() fails)
      // Normalize the path
      resolvedPath = _util_ts_4.normalizeString(
        resolvedPath,
        !resolvedAbsolute,
        "/",
        _util_ts_4.isPosixPathSeparator,
      );
      if (resolvedAbsolute) {
        if (resolvedPath.length > 0) {
          return `/${resolvedPath}`;
        } else {
          return "/";
        }
      } else if (resolvedPath.length > 0) {
        return resolvedPath;
      } else {
        return ".";
      }
    }
    exports_69("resolve", resolve);
    function normalize(path) {
      _util_ts_4.assertPath(path);
      if (path.length === 0) {
        return ".";
      }
      const isAbsolute =
        path.charCodeAt(0) === _constants_ts_6.CHAR_FORWARD_SLASH;
      const trailingSeparator =
        path.charCodeAt(path.length - 1) === _constants_ts_6.CHAR_FORWARD_SLASH;
      // Normalize the path
      path = _util_ts_4.normalizeString(
        path,
        !isAbsolute,
        "/",
        _util_ts_4.isPosixPathSeparator,
      );
      if (path.length === 0 && !isAbsolute) {
        path = ".";
      }
      if (path.length > 0 && trailingSeparator) {
        path += "/";
      }
      if (isAbsolute) {
        return `/${path}`;
      }
      return path;
    }
    exports_69("normalize", normalize);
    function isAbsolute(path) {
      _util_ts_4.assertPath(path);
      return path.length > 0 &&
        path.charCodeAt(0) === _constants_ts_6.CHAR_FORWARD_SLASH;
    }
    exports_69("isAbsolute", isAbsolute);
    function join(...paths) {
      if (paths.length === 0) {
        return ".";
      }
      let joined;
      for (let i = 0, len = paths.length; i < len; ++i) {
        const path = paths[i];
        _util_ts_4.assertPath(path);
        if (path.length > 0) {
          if (!joined) {
            joined = path;
          } else {
            joined += `/${path}`;
          }
        }
      }
      if (!joined) {
        return ".";
      }
      return normalize(joined);
    }
    exports_69("join", join);
    function relative(from, to) {
      _util_ts_4.assertPath(from);
      _util_ts_4.assertPath(to);
      if (from === to) {
        return "";
      }
      from = resolve(from);
      to = resolve(to);
      if (from === to) {
        return "";
      }
      // Trim any leading backslashes
      let fromStart = 1;
      const fromEnd = from.length;
      for (; fromStart < fromEnd; ++fromStart) {
        if (from.charCodeAt(fromStart) !== _constants_ts_6.CHAR_FORWARD_SLASH) {
          break;
        }
      }
      const fromLen = fromEnd - fromStart;
      // Trim any leading backslashes
      let toStart = 1;
      const toEnd = to.length;
      for (; toStart < toEnd; ++toStart) {
        if (to.charCodeAt(toStart) !== _constants_ts_6.CHAR_FORWARD_SLASH) {
          break;
        }
      }
      const toLen = toEnd - toStart;
      // Compare paths to find the longest common path from root
      const length = fromLen < toLen ? fromLen : toLen;
      let lastCommonSep = -1;
      let i = 0;
      for (; i <= length; ++i) {
        if (i === length) {
          if (toLen > length) {
            if (
              to.charCodeAt(toStart + i) === _constants_ts_6.CHAR_FORWARD_SLASH
            ) {
              // We get here if `from` is the exact base path for `to`.
              // For example: from='/foo/bar'; to='/foo/bar/baz'
              return to.slice(toStart + i + 1);
            } else if (i === 0) {
              // We get here if `from` is the root
              // For example: from='/'; to='/foo'
              return to.slice(toStart + i);
            }
          } else if (fromLen > length) {
            if (
              from.charCodeAt(fromStart + i) ===
                _constants_ts_6.CHAR_FORWARD_SLASH
            ) {
              // We get here if `to` is the exact base path for `from`.
              // For example: from='/foo/bar/baz'; to='/foo/bar'
              lastCommonSep = i;
            } else if (i === 0) {
              // We get here if `to` is the root.
              // For example: from='/foo'; to='/'
              lastCommonSep = 0;
            }
          }
          break;
        }
        const fromCode = from.charCodeAt(fromStart + i);
        const toCode = to.charCodeAt(toStart + i);
        if (fromCode !== toCode) {
          break;
        } else if (fromCode === _constants_ts_6.CHAR_FORWARD_SLASH) {
          lastCommonSep = i;
        }
      }
      let out = "";
      // Generate the relative path based on the path difference between `to`
      // and `from`
      for (i = fromStart + lastCommonSep + 1; i <= fromEnd; ++i) {
        if (
          i === fromEnd ||
          from.charCodeAt(i) === _constants_ts_6.CHAR_FORWARD_SLASH
        ) {
          if (out.length === 0) {
            out += "..";
          } else {
            out += "/..";
          }
        }
      }
      // Lastly, append the rest of the destination (`to`) path that comes after
      // the common path parts
      if (out.length > 0) {
        return out + to.slice(toStart + lastCommonSep);
      } else {
        toStart += lastCommonSep;
        if (to.charCodeAt(toStart) === _constants_ts_6.CHAR_FORWARD_SLASH) {
          ++toStart;
        }
        return to.slice(toStart);
      }
    }
    exports_69("relative", relative);
    function toNamespacedPath(path) {
      // Non-op on posix systems
      return path;
    }
    exports_69("toNamespacedPath", toNamespacedPath);
    function dirname(path) {
      _util_ts_4.assertPath(path);
      if (path.length === 0) {
        return ".";
      }
      const hasRoot = path.charCodeAt(0) === _constants_ts_6.CHAR_FORWARD_SLASH;
      let end = -1;
      let matchedSlash = true;
      for (let i = path.length - 1; i >= 1; --i) {
        if (path.charCodeAt(i) === _constants_ts_6.CHAR_FORWARD_SLASH) {
          if (!matchedSlash) {
            end = i;
            break;
          }
        } else {
          // We saw the first non-path separator
          matchedSlash = false;
        }
      }
      if (end === -1) {
        return hasRoot ? "/" : ".";
      }
      if (hasRoot && end === 1) {
        return "//";
      }
      return path.slice(0, end);
    }
    exports_69("dirname", dirname);
    function basename(path, ext = "") {
      if (ext !== undefined && typeof ext !== "string") {
        throw new TypeError('"ext" argument must be a string');
      }
      _util_ts_4.assertPath(path);
      let start = 0;
      let end = -1;
      let matchedSlash = true;
      let i;
      if (ext !== undefined && ext.length > 0 && ext.length <= path.length) {
        if (ext.length === path.length && ext === path) {
          return "";
        }
        let extIdx = ext.length - 1;
        let firstNonSlashEnd = -1;
        for (i = path.length - 1; i >= 0; --i) {
          const code = path.charCodeAt(i);
          if (code === _constants_ts_6.CHAR_FORWARD_SLASH) {
            // If we reached a path separator that was not part of a set of path
            // separators at the end of the string, stop now
            if (!matchedSlash) {
              start = i + 1;
              break;
            }
          } else {
            if (firstNonSlashEnd === -1) {
              // We saw the first non-path separator, remember this index in case
              // we need it if the extension ends up not matching
              matchedSlash = false;
              firstNonSlashEnd = i + 1;
            }
            if (extIdx >= 0) {
              // Try to match the explicit extension
              if (code === ext.charCodeAt(extIdx)) {
                if (--extIdx === -1) {
                  // We matched the extension, so mark this as the end of our path
                  // component
                  end = i;
                }
              } else {
                // Extension does not match, so our result is the entire path
                // component
                extIdx = -1;
                end = firstNonSlashEnd;
              }
            }
          }
        }
        if (start === end) {
          end = firstNonSlashEnd;
        } else if (end === -1) {
          end = path.length;
        }
        return path.slice(start, end);
      } else {
        for (i = path.length - 1; i >= 0; --i) {
          if (path.charCodeAt(i) === _constants_ts_6.CHAR_FORWARD_SLASH) {
            // If we reached a path separator that was not part of a set of path
            // separators at the end of the string, stop now
            if (!matchedSlash) {
              start = i + 1;
              break;
            }
          } else if (end === -1) {
            // We saw the first non-path separator, mark this as the end of our
            // path component
            matchedSlash = false;
            end = i + 1;
          }
        }
        if (end === -1) {
          return "";
        }
        return path.slice(start, end);
      }
    }
    exports_69("basename", basename);
    function extname(path) {
      _util_ts_4.assertPath(path);
      let startDot = -1;
      let startPart = 0;
      let end = -1;
      let matchedSlash = true;
      // Track the state of characters (if any) we see before our first dot and
      // after any path separator we find
      let preDotState = 0;
      for (let i = path.length - 1; i >= 0; --i) {
        const code = path.charCodeAt(i);
        if (code === _constants_ts_6.CHAR_FORWARD_SLASH) {
          // If we reached a path separator that was not part of a set of path
          // separators at the end of the string, stop now
          if (!matchedSlash) {
            startPart = i + 1;
            break;
          }
          continue;
        }
        if (end === -1) {
          // We saw the first non-path separator, mark this as the end of our
          // extension
          matchedSlash = false;
          end = i + 1;
        }
        if (code === _constants_ts_6.CHAR_DOT) {
          // If this is our first dot, mark it as the start of our extension
          if (startDot === -1) {
            startDot = i;
          } else if (preDotState !== 1) {
            preDotState = 1;
          }
        } else if (startDot !== -1) {
          // We saw a non-dot and non-path separator before our dot, so we should
          // have a good chance at having a non-empty extension
          preDotState = -1;
        }
      }
      if (
        startDot === -1 ||
        end === -1 ||
        // We saw a non-dot character immediately before the dot
        preDotState === 0 ||
        // The (right-most) trimmed path component is exactly '..'
        (preDotState === 1 && startDot === end - 1 &&
          startDot === startPart + 1)
      ) {
        return "";
      }
      return path.slice(startDot, end);
    }
    exports_69("extname", extname);
    function format(pathObject) {
      /* eslint-disable max-len */
      if (pathObject === null || typeof pathObject !== "object") {
        throw new TypeError(
          `The "pathObject" argument must be of type Object. Received type ${typeof pathObject}`,
        );
      }
      return _util_ts_4._format("/", pathObject);
    }
    exports_69("format", format);
    function parse(path) {
      _util_ts_4.assertPath(path);
      const ret = { root: "", dir: "", base: "", ext: "", name: "" };
      if (path.length === 0) {
        return ret;
      }
      const isAbsolute =
        path.charCodeAt(0) === _constants_ts_6.CHAR_FORWARD_SLASH;
      let start;
      if (isAbsolute) {
        ret.root = "/";
        start = 1;
      } else {
        start = 0;
      }
      let startDot = -1;
      let startPart = 0;
      let end = -1;
      let matchedSlash = true;
      let i = path.length - 1;
      // Track the state of characters (if any) we see before our first dot and
      // after any path separator we find
      let preDotState = 0;
      // Get non-dir info
      for (; i >= start; --i) {
        const code = path.charCodeAt(i);
        if (code === _constants_ts_6.CHAR_FORWARD_SLASH) {
          // If we reached a path separator that was not part of a set of path
          // separators at the end of the string, stop now
          if (!matchedSlash) {
            startPart = i + 1;
            break;
          }
          continue;
        }
        if (end === -1) {
          // We saw the first non-path separator, mark this as the end of our
          // extension
          matchedSlash = false;
          end = i + 1;
        }
        if (code === _constants_ts_6.CHAR_DOT) {
          // If this is our first dot, mark it as the start of our extension
          if (startDot === -1) {
            startDot = i;
          } else if (preDotState !== 1) {
            preDotState = 1;
          }
        } else if (startDot !== -1) {
          // We saw a non-dot and non-path separator before our dot, so we should
          // have a good chance at having a non-empty extension
          preDotState = -1;
        }
      }
      if (
        startDot === -1 ||
        end === -1 ||
        // We saw a non-dot character immediately before the dot
        preDotState === 0 ||
        // The (right-most) trimmed path component is exactly '..'
        (preDotState === 1 && startDot === end - 1 &&
          startDot === startPart + 1)
      ) {
        if (end !== -1) {
          if (startPart === 0 && isAbsolute) {
            ret.base = ret.name = path.slice(1, end);
          } else {
            ret.base = ret.name = path.slice(startPart, end);
          }
        }
      } else {
        if (startPart === 0 && isAbsolute) {
          ret.name = path.slice(1, startDot);
          ret.base = path.slice(1, end);
        } else {
          ret.name = path.slice(startPart, startDot);
          ret.base = path.slice(startPart, end);
        }
        ret.ext = path.slice(startDot, end);
      }
      if (startPart > 0) {
        ret.dir = path.slice(0, startPart - 1);
      } else if (isAbsolute) {
        ret.dir = "/";
      }
      return ret;
    }
    exports_69("parse", parse);
    /** Converts a file URL to a path string.
     *
     *      fromFileUrl("file:///home/foo"); // "/home/foo"
     *
     * Note that non-file URLs are treated as file URLs and irrelevant components
     * are ignored.
     */
    function fromFileUrl(url) {
      return new URL(url).pathname;
    }
    exports_69("fromFileUrl", fromFileUrl);
    return {
      setters: [
        function (_constants_ts_6_1) {
          _constants_ts_6 = _constants_ts_6_1;
        },
        function (_util_ts_4_1) {
          _util_ts_4 = _util_ts_4_1;
        },
      ],
      execute: function () {
        cwd = Deno.cwd;
        exports_69("sep", sep = "/");
        exports_69("delimiter", delimiter = ":");
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.51.0/path/separator",
  [],
  function (exports_70, context_70) {
    "use strict";
    var isWindows, SEP, SEP_PATTERN;
    var __moduleName = context_70 && context_70.id;
    return {
      setters: [],
      execute: function () {
        // Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
        isWindows = Deno.build.os == "windows";
        exports_70("SEP", SEP = isWindows ? "\\" : "/");
        exports_70("SEP_PATTERN", SEP_PATTERN = isWindows ? /[\\/]+/ : /\/+/);
      },
    };
  },
);
// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
System.register(
  "https://deno.land/std@0.51.0/path/common",
  ["https://deno.land/std@0.51.0/path/separator"],
  function (exports_71, context_71) {
    "use strict";
    var separator_ts_4;
    var __moduleName = context_71 && context_71.id;
    /** Determines the common path from a set of paths, using an optional separator,
     * which defaults to the OS default separator.
     *
     *       import { common } from "https://deno.land/std/path/mod.ts";
     *       const p = common([
     *         "./deno/std/path/mod.ts",
     *         "./deno/std/fs/mod.ts",
     *       ]);
     *       console.log(p); // "./deno/std/"
     *
     */
    function common(paths, sep = separator_ts_4.SEP) {
      const [first = "", ...remaining] = paths;
      if (first === "" || remaining.length === 0) {
        return first.substring(0, first.lastIndexOf(sep) + 1);
      }
      const parts = first.split(sep);
      let endOfPrefix = parts.length;
      for (const path of remaining) {
        const compare = path.split(sep);
        for (let i = 0; i < endOfPrefix; i++) {
          if (compare[i] !== parts[i]) {
            endOfPrefix = i;
          }
        }
        if (endOfPrefix === 0) {
          return "";
        }
      }
      const prefix = parts.slice(0, endOfPrefix).join(sep);
      return prefix.endsWith(sep) ? prefix : `${prefix}${sep}`;
    }
    exports_71("common", common);
    return {
      setters: [
        function (separator_ts_4_1) {
          separator_ts_4 = separator_ts_4_1;
        },
      ],
      execute: function () {
      },
    };
  },
);
// This file is ported from globrex@0.1.2
// MIT License
// Copyright (c) 2018 Terkel Gjervig Nielsen
System.register(
  "https://deno.land/std@0.51.0/path/_globrex",
  [],
  function (exports_72, context_72) {
    "use strict";
    var isWin,
      SEP,
      SEP_ESC,
      SEP_RAW,
      GLOBSTAR,
      WILDCARD,
      GLOBSTAR_SEGMENT,
      WILDCARD_SEGMENT;
    var __moduleName = context_72 && context_72.id;
    /**
     * Convert any glob pattern to a JavaScript Regexp object
     * @param glob Glob pattern to convert
     * @param opts Configuration object
     * @returns Converted object with string, segments and RegExp object
     */
    function globrex(
      glob,
      {
        extended = false,
        globstar = false,
        strict = false,
        filepath = false,
        flags = "",
      } = {},
    ) {
      const sepPattern = new RegExp(`^${SEP}${strict ? "" : "+"}$`);
      let regex = "";
      let segment = "";
      let pathRegexStr = "";
      const pathSegments = [];
      // If we are doing extended matching, this boolean is true when we are inside
      // a group (eg {*.html,*.js}), and false otherwise.
      let inGroup = false;
      let inRange = false;
      // extglob stack. Keep track of scope
      const ext = [];
      // Helper function to build string and segments
      function add(str, options = { split: false, last: false, only: "" }) {
        const { split, last, only } = options;
        if (only !== "path") {
          regex += str;
        }
        if (filepath && only !== "regex") {
          pathRegexStr += str.match(sepPattern) ? SEP : str;
          if (split) {
            if (last) {
              segment += str;
            }
            if (segment !== "") {
              // change it 'includes'
              if (!flags.includes("g")) {
                segment = `^${segment}$`;
              }
              pathSegments.push(new RegExp(segment, flags));
            }
            segment = "";
          } else {
            segment += str;
          }
        }
      }
      let c, n;
      for (let i = 0; i < glob.length; i++) {
        c = glob[i];
        n = glob[i + 1];
        if (["\\", "$", "^", ".", "="].includes(c)) {
          add(`\\${c}`);
          continue;
        }
        if (c.match(sepPattern)) {
          add(SEP, { split: true });
          if (n != null && n.match(sepPattern) && !strict) {
            regex += "?";
          }
          continue;
        }
        if (c === "(") {
          if (ext.length) {
            add(`${c}?:`);
            continue;
          }
          add(`\\${c}`);
          continue;
        }
        if (c === ")") {
          if (ext.length) {
            add(c);
            const type = ext.pop();
            if (type === "@") {
              add("{1}");
            } else if (type === "!") {
              add(WILDCARD);
            } else {
              add(type);
            }
            continue;
          }
          add(`\\${c}`);
          continue;
        }
        if (c === "|") {
          if (ext.length) {
            add(c);
            continue;
          }
          add(`\\${c}`);
          continue;
        }
        if (c === "+") {
          if (n === "(" && extended) {
            ext.push(c);
            continue;
          }
          add(`\\${c}`);
          continue;
        }
        if (c === "@" && extended) {
          if (n === "(") {
            ext.push(c);
            continue;
          }
        }
        if (c === "!") {
          if (extended) {
            if (inRange) {
              add("^");
              continue;
            }
            if (n === "(") {
              ext.push(c);
              add("(?!");
              i++;
              continue;
            }
            add(`\\${c}`);
            continue;
          }
          add(`\\${c}`);
          continue;
        }
        if (c === "?") {
          if (extended) {
            if (n === "(") {
              ext.push(c);
            } else {
              add(".");
            }
            continue;
          }
          add(`\\${c}`);
          continue;
        }
        if (c === "[") {
          if (inRange && n === ":") {
            i++; // skip [
            let value = "";
            while (glob[++i] !== ":") {
              value += glob[i];
            }
            if (value === "alnum") {
              add("(?:\\w|\\d)");
            } else if (value === "space") {
              add("\\s");
            } else if (value === "digit") {
              add("\\d");
            }
            i++; // skip last ]
            continue;
          }
          if (extended) {
            inRange = true;
            add(c);
            continue;
          }
          add(`\\${c}`);
          continue;
        }
        if (c === "]") {
          if (extended) {
            inRange = false;
            add(c);
            continue;
          }
          add(`\\${c}`);
          continue;
        }
        if (c === "{") {
          if (extended) {
            inGroup = true;
            add("(?:");
            continue;
          }
          add(`\\${c}`);
          continue;
        }
        if (c === "}") {
          if (extended) {
            inGroup = false;
            add(")");
            continue;
          }
          add(`\\${c}`);
          continue;
        }
        if (c === ",") {
          if (inGroup) {
            add("|");
            continue;
          }
          add(`\\${c}`);
          continue;
        }
        if (c === "*") {
          if (n === "(" && extended) {
            ext.push(c);
            continue;
          }
          // Move over all consecutive "*"'s.
          // Also store the previous and next characters
          const prevChar = glob[i - 1];
          let starCount = 1;
          while (glob[i + 1] === "*") {
            starCount++;
            i++;
          }
          const nextChar = glob[i + 1];
          if (!globstar) {
            // globstar is disabled, so treat any number of "*" as one
            add(".*");
          } else {
            // globstar is enabled, so determine if this is a globstar segment
            const isGlobstar = starCount > 1 && // multiple "*"'s
              // from the start of the segment
              [SEP_RAW, "/", undefined].includes(prevChar) &&
              // to the end of the segment
              [SEP_RAW, "/", undefined].includes(nextChar);
            if (isGlobstar) {
              // it's a globstar, so match zero or more path segments
              add(GLOBSTAR, { only: "regex" });
              add(GLOBSTAR_SEGMENT, { only: "path", last: true, split: true });
              i++; // move over the "/"
            } else {
              // it's not a globstar, so only match one path segment
              add(WILDCARD, { only: "regex" });
              add(WILDCARD_SEGMENT, { only: "path" });
            }
          }
          continue;
        }
        add(c);
      }
      // When regexp 'g' flag is specified don't
      // constrain the regular expression with ^ & $
      if (!flags.includes("g")) {
        regex = `^${regex}$`;
        segment = `^${segment}$`;
        if (filepath) {
          pathRegexStr = `^${pathRegexStr}$`;
        }
      }
      const result = { regex: new RegExp(regex, flags) };
      // Push the last segment
      if (filepath) {
        pathSegments.push(new RegExp(segment, flags));
        result.path = {
          regex: new RegExp(pathRegexStr, flags),
          segments: pathSegments,
          globstar: new RegExp(
            !flags.includes("g") ? `^${GLOBSTAR_SEGMENT}$` : GLOBSTAR_SEGMENT,
            flags,
          ),
        };
      }
      return result;
    }
    exports_72("globrex", globrex);
    return {
      setters: [],
      execute: function () {
        isWin = Deno.build.os === "windows";
        SEP = isWin ? `(?:\\\\|\\/)` : `\\/`;
        SEP_ESC = isWin ? `\\\\` : `/`;
        SEP_RAW = isWin ? `\\` : `/`;
        GLOBSTAR = `(?:(?:[^${SEP_ESC}/]*(?:${SEP_ESC}|\/|$))*)`;
        WILDCARD = `(?:[^${SEP_ESC}/]*)`;
        GLOBSTAR_SEGMENT = `((?:[^${SEP_ESC}/]*(?:${SEP_ESC}|\/|$))*)`;
        WILDCARD_SEGMENT = `(?:[^${SEP_ESC}/]*)`;
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.51.0/path/glob",
  [
    "https://deno.land/std@0.51.0/path/separator",
    "https://deno.land/std@0.51.0/path/_globrex",
    "https://deno.land/std@0.51.0/path/mod",
    "https://deno.land/std@0.51.0/testing/asserts",
  ],
  function (exports_73, context_73) {
    "use strict";
    var separator_ts_5, _globrex_ts_2, mod_ts_9, asserts_ts_10;
    var __moduleName = context_73 && context_73.id;
    /**
     * Generate a regex based on glob pattern and options
     * This was meant to be using the the `fs.walk` function
     * but can be used anywhere else.
     * Examples:
     *
     *     Looking for all the `ts` files:
     *     walkSync(".", {
     *       match: [globToRegExp("*.ts")]
     *     })
     *
     *     Looking for all the `.json` files in any subfolder:
     *     walkSync(".", {
     *       match: [globToRegExp(join("a", "**", "*.json"),{
     *         flags: "g",
     *         extended: true,
     *         globstar: true
     *       })]
     *     })
     *
     * @param glob - Glob pattern to be used
     * @param options - Specific options for the glob pattern
     * @returns A RegExp for the glob pattern
     */
    function globToRegExp(glob, { extended = false, globstar = true } = {}) {
      const result = _globrex_ts_2.globrex(glob, {
        extended,
        globstar,
        strict: false,
        filepath: true,
      });
      asserts_ts_10.assert(result.path != null);
      return result.path.regex;
    }
    exports_73("globToRegExp", globToRegExp);
    /** Test whether the given string is a glob */
    function isGlob(str) {
      const chars = { "{": "}", "(": ")", "[": "]" };
      /* eslint-disable-next-line max-len */
      const regex =
        /\\(.)|(^!|\*|[\].+)]\?|\[[^\\\]]+\]|\{[^\\}]+\}|\(\?[:!=][^\\)]+\)|\([^|]+\|[^\\)]+\))/;
      if (str === "") {
        return false;
      }
      let match;
      while ((match = regex.exec(str))) {
        if (match[2]) {
          return true;
        }
        let idx = match.index + match[0].length;
        // if an open bracket/brace/paren is escaped,
        // set the index to the next closing character
        const open = match[1];
        const close = open ? chars[open] : null;
        if (open && close) {
          const n = str.indexOf(close, idx);
          if (n !== -1) {
            idx = n + 1;
          }
        }
        str = str.slice(idx);
      }
      return false;
    }
    exports_73("isGlob", isGlob);
    /** Like normalize(), but doesn't collapse "**\/.." when `globstar` is true. */
    function normalizeGlob(glob, { globstar = false } = {}) {
      if (!!glob.match(/\0/g)) {
        throw new Error(`Glob contains invalid characters: "${glob}"`);
      }
      if (!globstar) {
        return mod_ts_9.normalize(glob);
      }
      const s = separator_ts_5.SEP_PATTERN.source;
      const badParentPattern = new RegExp(
        `(?<=(${s}|^)\\*\\*${s})\\.\\.(?=${s}|$)`,
        "g",
      );
      return mod_ts_9.normalize(glob.replace(badParentPattern, "\0")).replace(
        /\0/g,
        "..",
      );
    }
    exports_73("normalizeGlob", normalizeGlob);
    /** Like join(), but doesn't collapse "**\/.." when `globstar` is true. */
    function joinGlobs(globs, { extended = false, globstar = false } = {}) {
      if (!globstar || globs.length == 0) {
        return mod_ts_9.join(...globs);
      }
      if (globs.length === 0) {
        return ".";
      }
      let joined;
      for (const glob of globs) {
        const path = glob;
        if (path.length > 0) {
          if (!joined) {
            joined = path;
          } else {
            joined += `${separator_ts_5.SEP}${path}`;
          }
        }
      }
      if (!joined) {
        return ".";
      }
      return normalizeGlob(joined, { extended, globstar });
    }
    exports_73("joinGlobs", joinGlobs);
    return {
      setters: [
        function (separator_ts_5_1) {
          separator_ts_5 = separator_ts_5_1;
        },
        function (_globrex_ts_2_1) {
          _globrex_ts_2 = _globrex_ts_2_1;
        },
        function (mod_ts_9_1) {
          mod_ts_9 = mod_ts_9_1;
        },
        function (asserts_ts_10_1) {
          asserts_ts_10 = asserts_ts_10_1;
        },
      ],
      execute: function () {
      },
    };
  },
);
// Copyright the Browserify authors. MIT License.
// Ported mostly from https://github.com/browserify/path-browserify/
System.register(
  "https://deno.land/std@0.51.0/path/mod",
  [
    "https://deno.land/std@0.51.0/path/win32",
    "https://deno.land/std@0.51.0/path/posix",
    "https://deno.land/std@0.51.0/path/common",
    "https://deno.land/std@0.51.0/path/separator",
    "https://deno.land/std@0.51.0/path/interface",
    "https://deno.land/std@0.51.0/path/glob",
  ],
  function (exports_74, context_74) {
    "use strict";
    var _win32,
      _posix,
      isWindows,
      path,
      win32,
      posix,
      basename,
      delimiter,
      dirname,
      extname,
      format,
      fromFileUrl,
      isAbsolute,
      join,
      normalize,
      parse,
      relative,
      resolve,
      sep,
      toNamespacedPath;
    var __moduleName = context_74 && context_74.id;
    var exportedNames_3 = {
      "win32": true,
      "posix": true,
      "basename": true,
      "delimiter": true,
      "dirname": true,
      "extname": true,
      "format": true,
      "fromFileUrl": true,
      "isAbsolute": true,
      "join": true,
      "normalize": true,
      "parse": true,
      "relative": true,
      "resolve": true,
      "sep": true,
      "toNamespacedPath": true,
      "SEP": true,
      "SEP_PATTERN": true,
    };
    function exportStar_4(m) {
      var exports = {};
      for (var n in m) {
        if (n !== "default" && !exportedNames_3.hasOwnProperty(n)) {
          exports[n] = m[n];
        }
      }
      exports_74(exports);
    }
    return {
      setters: [
        function (_win32_2) {
          _win32 = _win32_2;
        },
        function (_posix_2) {
          _posix = _posix_2;
        },
        function (common_ts_6_1) {
          exportStar_4(common_ts_6_1);
        },
        function (separator_ts_6_1) {
          exports_74({
            "SEP": separator_ts_6_1["SEP"],
            "SEP_PATTERN": separator_ts_6_1["SEP_PATTERN"],
          });
        },
        function (interface_ts_2_1) {
          exportStar_4(interface_ts_2_1);
        },
        function (glob_ts_2_1) {
          exportStar_4(glob_ts_2_1);
        },
      ],
      execute: function () {
        isWindows = Deno.build.os == "windows";
        path = isWindows ? _win32 : _posix;
        exports_74("win32", win32 = _win32);
        exports_74("posix", posix = _posix);
        exports_74("basename", basename = path.basename),
          exports_74("delimiter", delimiter = path.delimiter),
          exports_74("dirname", dirname = path.dirname),
          exports_74("extname", extname = path.extname),
          exports_74("format", format = path.format),
          exports_74("fromFileUrl", fromFileUrl = path.fromFileUrl),
          exports_74("isAbsolute", isAbsolute = path.isAbsolute),
          exports_74("join", join = path.join),
          exports_74("normalize", normalize = path.normalize),
          exports_74("parse", parse = path.parse),
          exports_74("relative", relative = path.relative),
          exports_74("resolve", resolve = path.resolve),
          exports_74("sep", sep = path.sep),
          exports_74(
            "toNamespacedPath",
            toNamespacedPath = path.toNamespacedPath,
          );
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.51.0/encoding/utf8",
  [],
  function (exports_75, context_75) {
    "use strict";
    var encoder, decoder;
    var __moduleName = context_75 && context_75.id;
    /** Shorthand for new TextEncoder().encode() */
    function encode(input) {
      return encoder.encode(input);
    }
    exports_75("encode", encode);
    /** Shorthand for new TextDecoder().decode() */
    function decode(input) {
      return decoder.decode(input);
    }
    exports_75("decode", decode);
    return {
      setters: [],
      execute: function () {
        /** A default TextEncoder instance */
        exports_75("encoder", encoder = new TextEncoder());
        /** A default TextDecoder instance */
        exports_75("decoder", decoder = new TextDecoder());
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.51.0/io/util",
  [
    "https://deno.land/std@0.51.0/path/mod",
    "https://deno.land/std@0.51.0/encoding/utf8",
  ],
  function (exports_76, context_76) {
    "use strict";
    var Buffer, mkdir, open, path, utf8_ts_5;
    var __moduleName = context_76 && context_76.id;
    /**
     * Copy bytes from one Uint8Array to another.  Bytes from `src` which don't fit
     * into `dst` will not be copied.
     *
     * @param src Source byte array
     * @param dst Destination byte array
     * @param off Offset into `dst` at which to begin writing values from `src`.
     * @return number of bytes copied
     */
    function copyBytes(src, dst, off = 0) {
      off = Math.max(0, Math.min(off, dst.byteLength));
      const dstBytesAvailable = dst.byteLength - off;
      if (src.byteLength > dstBytesAvailable) {
        src = src.subarray(0, dstBytesAvailable);
      }
      dst.set(src, off);
      return src.byteLength;
    }
    exports_76("copyBytes", copyBytes);
    function charCode(s) {
      return s.charCodeAt(0);
    }
    exports_76("charCode", charCode);
    function stringsReader(s) {
      return new Buffer(utf8_ts_5.encode(s).buffer);
    }
    exports_76("stringsReader", stringsReader);
    /** Create or open a temporal file at specified directory with prefix and
     *  postfix
     * */
    async function tempFile(dir, opts = { prefix: "", postfix: "" }) {
      const r = Math.floor(Math.random() * 1000000);
      const filepath = path.resolve(
        `${dir}/${opts.prefix || ""}${r}${opts.postfix || ""}`,
      );
      await mkdir(path.dirname(filepath), { recursive: true });
      const file = await open(filepath, {
        create: true,
        read: true,
        write: true,
        append: true,
      });
      return { file, filepath };
    }
    exports_76("tempFile", tempFile);
    return {
      setters: [
        function (path_2) {
          path = path_2;
        },
        function (utf8_ts_5_1) {
          utf8_ts_5 = utf8_ts_5_1;
        },
      ],
      execute: function () {
        // Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
        Buffer = Deno.Buffer, mkdir = Deno.mkdir, open = Deno.open;
      },
    };
  },
);
// Based on https://github.com/golang/go/blob/891682/src/bufio/bufio.go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
System.register(
  "https://deno.land/std@0.51.0/io/bufio",
  [
    "https://deno.land/std@0.51.0/io/util",
    "https://deno.land/std@0.51.0/testing/asserts",
  ],
  function (exports_77, context_77) {
    "use strict";
    var util_ts_8,
      asserts_ts_11,
      DEFAULT_BUF_SIZE,
      MIN_BUF_SIZE,
      MAX_CONSECUTIVE_EMPTY_READS,
      CR,
      LF,
      BufferFullError,
      PartialReadError,
      BufReader,
      AbstractBufBase,
      BufWriter,
      BufWriterSync;
    var __moduleName = context_77 && context_77.id;
    /** Generate longest proper prefix which is also suffix array. */
    function createLPS(pat) {
      const lps = new Uint8Array(pat.length);
      lps[0] = 0;
      let prefixEnd = 0;
      let i = 1;
      while (i < lps.length) {
        if (pat[i] == pat[prefixEnd]) {
          prefixEnd++;
          lps[i] = prefixEnd;
          i++;
        } else if (prefixEnd === 0) {
          lps[i] = 0;
          i++;
        } else {
          prefixEnd = pat[prefixEnd - 1];
        }
      }
      return lps;
    }
    /** Read delimited bytes from a Reader. */
    async function* readDelim(reader, delim) {
      // Avoid unicode problems
      const delimLen = delim.length;
      const delimLPS = createLPS(delim);
      let inputBuffer = new Deno.Buffer();
      const inspectArr = new Uint8Array(Math.max(1024, delimLen + 1));
      // Modified KMP
      let inspectIndex = 0;
      let matchIndex = 0;
      while (true) {
        const result = await reader.read(inspectArr);
        if (result === null) {
          // Yield last chunk.
          yield inputBuffer.bytes();
          return;
        }
        if (result < 0) {
          // Discard all remaining and silently fail.
          return;
        }
        const sliceRead = inspectArr.subarray(0, result);
        await Deno.writeAll(inputBuffer, sliceRead);
        let sliceToProcess = inputBuffer.bytes();
        while (inspectIndex < sliceToProcess.length) {
          if (sliceToProcess[inspectIndex] === delim[matchIndex]) {
            inspectIndex++;
            matchIndex++;
            if (matchIndex === delimLen) {
              // Full match
              const matchEnd = inspectIndex - delimLen;
              const readyBytes = sliceToProcess.subarray(0, matchEnd);
              // Copy
              const pendingBytes = sliceToProcess.slice(inspectIndex);
              yield readyBytes;
              // Reset match, different from KMP.
              sliceToProcess = pendingBytes;
              inspectIndex = 0;
              matchIndex = 0;
            }
          } else {
            if (matchIndex === 0) {
              inspectIndex++;
            } else {
              matchIndex = delimLPS[matchIndex - 1];
            }
          }
        }
        // Keep inspectIndex and matchIndex.
        inputBuffer = new Deno.Buffer(sliceToProcess);
      }
    }
    exports_77("readDelim", readDelim);
    /** Read delimited strings from a Reader. */
    async function* readStringDelim(reader, delim) {
      const encoder = new TextEncoder();
      const decoder = new TextDecoder();
      for await (const chunk of readDelim(reader, encoder.encode(delim))) {
        yield decoder.decode(chunk);
      }
    }
    exports_77("readStringDelim", readStringDelim);
    /** Read strings line-by-line from a Reader. */
    // eslint-disable-next-line require-await
    async function* readLines(reader) {
      yield* readStringDelim(reader, "\n");
    }
    exports_77("readLines", readLines);
    return {
      setters: [
        function (util_ts_8_1) {
          util_ts_8 = util_ts_8_1;
        },
        function (asserts_ts_11_1) {
          asserts_ts_11 = asserts_ts_11_1;
        },
      ],
      execute: function () {
        DEFAULT_BUF_SIZE = 4096;
        MIN_BUF_SIZE = 16;
        MAX_CONSECUTIVE_EMPTY_READS = 100;
        CR = util_ts_8.charCode("\r");
        LF = util_ts_8.charCode("\n");
        BufferFullError = class BufferFullError extends Error {
          constructor(partial) {
            super("Buffer full");
            this.partial = partial;
            this.name = "BufferFullError";
          }
        };
        exports_77("BufferFullError", BufferFullError);
        PartialReadError = class PartialReadError
          extends Deno.errors.UnexpectedEof {
          constructor() {
            super("Encountered UnexpectedEof, data only partially read");
            this.name = "PartialReadError";
          }
        };
        exports_77("PartialReadError", PartialReadError);
        /** BufReader implements buffering for a Reader object. */
        BufReader = class BufReader {
          constructor(rd, size = DEFAULT_BUF_SIZE) {
            this.r = 0; // buf read position.
            this.w = 0; // buf write position.
            this.eof = false;
            if (size < MIN_BUF_SIZE) {
              size = MIN_BUF_SIZE;
            }
            this._reset(new Uint8Array(size), rd);
          }
          // private lastByte: number;
          // private lastCharSize: number;
          /** return new BufReader unless r is BufReader */
          static create(r, size = DEFAULT_BUF_SIZE) {
            return r instanceof BufReader ? r : new BufReader(r, size);
          }
          /** Returns the size of the underlying buffer in bytes. */
          size() {
            return this.buf.byteLength;
          }
          buffered() {
            return this.w - this.r;
          }
          // Reads a new chunk into the buffer.
          async _fill() {
            // Slide existing data to beginning.
            if (this.r > 0) {
              this.buf.copyWithin(0, this.r, this.w);
              this.w -= this.r;
              this.r = 0;
            }
            if (this.w >= this.buf.byteLength) {
              throw Error("bufio: tried to fill full buffer");
            }
            // Read new data: try a limited number of times.
            for (let i = MAX_CONSECUTIVE_EMPTY_READS; i > 0; i--) {
              const rr = await this.rd.read(this.buf.subarray(this.w));
              if (rr === null) {
                this.eof = true;
                return;
              }
              asserts_ts_11.assert(rr >= 0, "negative read");
              this.w += rr;
              if (rr > 0) {
                return;
              }
            }
            throw new Error(
              `No progress after ${MAX_CONSECUTIVE_EMPTY_READS} read() calls`,
            );
          }
          /** Discards any buffered data, resets all state, and switches
                 * the buffered reader to read from r.
                 */
          reset(r) {
            this._reset(this.buf, r);
          }
          _reset(buf, rd) {
            this.buf = buf;
            this.rd = rd;
            this.eof = false;
            // this.lastByte = -1;
            // this.lastCharSize = -1;
          }
          /** reads data into p.
                 * It returns the number of bytes read into p.
                 * The bytes are taken from at most one Read on the underlying Reader,
                 * hence n may be less than len(p).
                 * To read exactly len(p) bytes, use io.ReadFull(b, p).
                 */
          async read(p) {
            let rr = p.byteLength;
            if (p.byteLength === 0) {
              return rr;
            }
            if (this.r === this.w) {
              if (p.byteLength >= this.buf.byteLength) {
                // Large read, empty buffer.
                // Read directly into p to avoid copy.
                const rr = await this.rd.read(p);
                const nread = rr ?? 0;
                asserts_ts_11.assert(nread >= 0, "negative read");
                // if (rr.nread > 0) {
                //   this.lastByte = p[rr.nread - 1];
                //   this.lastCharSize = -1;
                // }
                return rr;
              }
              // One read.
              // Do not use this.fill, which will loop.
              this.r = 0;
              this.w = 0;
              rr = await this.rd.read(this.buf);
              if (rr === 0 || rr === null) {
                return rr;
              }
              asserts_ts_11.assert(rr >= 0, "negative read");
              this.w += rr;
            }
            // copy as much as we can
            const copied = util_ts_8.copyBytes(
              this.buf.subarray(this.r, this.w),
              p,
              0,
            );
            this.r += copied;
            // this.lastByte = this.buf[this.r - 1];
            // this.lastCharSize = -1;
            return copied;
          }
          /** reads exactly `p.length` bytes into `p`.
                 *
                 * If successful, `p` is returned.
                 *
                 * If the end of the underlying stream has been reached, and there are no more
                 * bytes available in the buffer, `readFull()` returns `null` instead.
                 *
                 * An error is thrown if some bytes could be read, but not enough to fill `p`
                 * entirely before the underlying stream reported an error or EOF. Any error
                 * thrown will have a `partial` property that indicates the slice of the
                 * buffer that has been successfully filled with data.
                 *
                 * Ported from https://golang.org/pkg/io/#ReadFull
                 */
          async readFull(p) {
            let bytesRead = 0;
            while (bytesRead < p.length) {
              try {
                const rr = await this.read(p.subarray(bytesRead));
                if (rr === null) {
                  if (bytesRead === 0) {
                    return null;
                  } else {
                    throw new PartialReadError();
                  }
                }
                bytesRead += rr;
              } catch (err) {
                err.partial = p.subarray(0, bytesRead);
                throw err;
              }
            }
            return p;
          }
          /** Returns the next byte [0, 255] or `null`. */
          async readByte() {
            while (this.r === this.w) {
              if (this.eof) {
                return null;
              }
              await this._fill(); // buffer is empty.
            }
            const c = this.buf[this.r];
            this.r++;
            // this.lastByte = c;
            return c;
          }
          /** readString() reads until the first occurrence of delim in the input,
                 * returning a string containing the data up to and including the delimiter.
                 * If ReadString encounters an error before finding a delimiter,
                 * it returns the data read before the error and the error itself
                 * (often `null`).
                 * ReadString returns err != nil if and only if the returned data does not end
                 * in delim.
                 * For simple uses, a Scanner may be more convenient.
                 */
          async readString(delim) {
            if (delim.length !== 1) {
              throw new Error("Delimiter should be a single character");
            }
            const buffer = await this.readSlice(delim.charCodeAt(0));
            if (buffer === null) {
              return null;
            }
            return new TextDecoder().decode(buffer);
          }
          /** `readLine()` is a low-level line-reading primitive. Most callers should
                 * use `readString('\n')` instead or use a Scanner.
                 *
                 * `readLine()` tries to return a single line, not including the end-of-line
                 * bytes. If the line was too long for the buffer then `more` is set and the
                 * beginning of the line is returned. The rest of the line will be returned
                 * from future calls. `more` will be false when returning the last fragment
                 * of the line. The returned buffer is only valid until the next call to
                 * `readLine()`.
                 *
                 * The text returned from ReadLine does not include the line end ("\r\n" or
                 * "\n").
                 *
                 * When the end of the underlying stream is reached, the final bytes in the
                 * stream are returned. No indication or error is given if the input ends
                 * without a final line end. When there are no more trailing bytes to read,
                 * `readLine()` returns `null`.
                 *
                 * Calling `unreadByte()` after `readLine()` will always unread the last byte
                 * read (possibly a character belonging to the line end) even if that byte is
                 * not part of the line returned by `readLine()`.
                 */
          async readLine() {
            let line;
            try {
              line = await this.readSlice(LF);
            } catch (err) {
              let { partial } = err;
              asserts_ts_11.assert(
                partial instanceof Uint8Array,
                "bufio: caught error from `readSlice()` without `partial` property",
              );
              // Don't throw if `readSlice()` failed with `BufferFullError`, instead we
              // just return whatever is available and set the `more` flag.
              if (!(err instanceof BufferFullError)) {
                throw err;
              }
              // Handle the case where "\r\n" straddles the buffer.
              if (
                !this.eof &&
                partial.byteLength > 0 &&
                partial[partial.byteLength - 1] === CR
              ) {
                // Put the '\r' back on buf and drop it from line.
                // Let the next call to ReadLine check for "\r\n".
                asserts_ts_11.assert(
                  this.r > 0,
                  "bufio: tried to rewind past start of buffer",
                );
                this.r--;
                partial = partial.subarray(0, partial.byteLength - 1);
              }
              return { line: partial, more: !this.eof };
            }
            if (line === null) {
              return null;
            }
            if (line.byteLength === 0) {
              return { line, more: false };
            }
            if (line[line.byteLength - 1] == LF) {
              let drop = 1;
              if (line.byteLength > 1 && line[line.byteLength - 2] === CR) {
                drop = 2;
              }
              line = line.subarray(0, line.byteLength - drop);
            }
            return { line, more: false };
          }
          /** `readSlice()` reads until the first occurrence of `delim` in the input,
                 * returning a slice pointing at the bytes in the buffer. The bytes stop
                 * being valid at the next read.
                 *
                 * If `readSlice()` encounters an error before finding a delimiter, or the
                 * buffer fills without finding a delimiter, it throws an error with a
                 * `partial` property that contains the entire buffer.
                 *
                 * If `readSlice()` encounters the end of the underlying stream and there are
                 * any bytes left in the buffer, the rest of the buffer is returned. In other
                 * words, EOF is always treated as a delimiter. Once the buffer is empty,
                 * it returns `null`.
                 *
                 * Because the data returned from `readSlice()` will be overwritten by the
                 * next I/O operation, most clients should use `readString()` instead.
                 */
          async readSlice(delim) {
            let s = 0; // search start index
            let slice;
            while (true) {
              // Search buffer.
              let i = this.buf.subarray(this.r + s, this.w).indexOf(delim);
              if (i >= 0) {
                i += s;
                slice = this.buf.subarray(this.r, this.r + i + 1);
                this.r += i + 1;
                break;
              }
              // EOF?
              if (this.eof) {
                if (this.r === this.w) {
                  return null;
                }
                slice = this.buf.subarray(this.r, this.w);
                this.r = this.w;
                break;
              }
              // Buffer full?
              if (this.buffered() >= this.buf.byteLength) {
                this.r = this.w;
                throw new BufferFullError(this.buf);
              }
              s = this.w - this.r; // do not rescan area we scanned before
              // Buffer is not full.
              try {
                await this._fill();
              } catch (err) {
                err.partial = slice;
                throw err;
              }
            }
            // Handle last byte, if any.
            // const i = slice.byteLength - 1;
            // if (i >= 0) {
            //   this.lastByte = slice[i];
            //   this.lastCharSize = -1
            // }
            return slice;
          }
          /** `peek()` returns the next `n` bytes without advancing the reader. The
                 * bytes stop being valid at the next read call.
                 *
                 * When the end of the underlying stream is reached, but there are unread
                 * bytes left in the buffer, those bytes are returned. If there are no bytes
                 * left in the buffer, it returns `null`.
                 *
                 * If an error is encountered before `n` bytes are available, `peek()` throws
                 * an error with the `partial` property set to a slice of the buffer that
                 * contains the bytes that were available before the error occurred.
                 */
          async peek(n) {
            if (n < 0) {
              throw Error("negative count");
            }
            let avail = this.w - this.r;
            while (avail < n && avail < this.buf.byteLength && !this.eof) {
              try {
                await this._fill();
              } catch (err) {
                err.partial = this.buf.subarray(this.r, this.w);
                throw err;
              }
              avail = this.w - this.r;
            }
            if (avail === 0 && this.eof) {
              return null;
            } else if (avail < n && this.eof) {
              return this.buf.subarray(this.r, this.r + avail);
            } else if (avail < n) {
              throw new BufferFullError(this.buf.subarray(this.r, this.w));
            }
            return this.buf.subarray(this.r, this.r + n);
          }
        };
        exports_77("BufReader", BufReader);
        AbstractBufBase = class AbstractBufBase {
          constructor() {
            this.usedBufferBytes = 0;
            this.err = null;
          }
          /** Size returns the size of the underlying buffer in bytes. */
          size() {
            return this.buf.byteLength;
          }
          /** Returns how many bytes are unused in the buffer. */
          available() {
            return this.buf.byteLength - this.usedBufferBytes;
          }
          /** buffered returns the number of bytes that have been written into the
                 * current buffer.
                 */
          buffered() {
            return this.usedBufferBytes;
          }
          checkBytesWritten(numBytesWritten) {
            if (numBytesWritten < this.usedBufferBytes) {
              if (numBytesWritten > 0) {
                this.buf.copyWithin(0, numBytesWritten, this.usedBufferBytes);
                this.usedBufferBytes -= numBytesWritten;
              }
              this.err = new Error("Short write");
              throw this.err;
            }
          }
        };
        /** BufWriter implements buffering for an deno.Writer object.
             * If an error occurs writing to a Writer, no more data will be
             * accepted and all subsequent writes, and flush(), will return the error.
             * After all data has been written, the client should call the
             * flush() method to guarantee all data has been forwarded to
             * the underlying deno.Writer.
             */
        BufWriter = class BufWriter extends AbstractBufBase {
          constructor(writer, size = DEFAULT_BUF_SIZE) {
            super();
            this.writer = writer;
            if (size <= 0) {
              size = DEFAULT_BUF_SIZE;
            }
            this.buf = new Uint8Array(size);
          }
          /** return new BufWriter unless writer is BufWriter */
          static create(writer, size = DEFAULT_BUF_SIZE) {
            return writer instanceof BufWriter ? writer
            : new BufWriter(writer, size);
          }
          /** Discards any unflushed buffered data, clears any error, and
                 * resets buffer to write its output to w.
                 */
          reset(w) {
            this.err = null;
            this.usedBufferBytes = 0;
            this.writer = w;
          }
          /** Flush writes any buffered data to the underlying io.Writer. */
          async flush() {
            if (this.err !== null) {
              throw this.err;
            }
            if (this.usedBufferBytes === 0) {
              return;
            }
            let numBytesWritten = 0;
            try {
              numBytesWritten = await this.writer.write(
                this.buf.subarray(0, this.usedBufferBytes),
              );
            } catch (e) {
              this.err = e;
              throw e;
            }
            this.checkBytesWritten(numBytesWritten);
            this.usedBufferBytes = 0;
          }
          /** Writes the contents of `data` into the buffer.  If the contents won't fully
                 * fit into the buffer, those bytes that can are copied into the buffer, the
                 * buffer is the flushed to the writer and the remaining bytes are copied into
                 * the now empty buffer.
                 *
                 * @return the number of bytes written to the buffer.
                 */
          async write(data) {
            if (this.err !== null) {
              throw this.err;
            }
            if (data.length === 0) {
              return 0;
            }
            let totalBytesWritten = 0;
            let numBytesWritten = 0;
            while (data.byteLength > this.available()) {
              if (this.buffered() === 0) {
                // Large write, empty buffer.
                // Write directly from data to avoid copy.
                try {
                  numBytesWritten = await this.writer.write(data);
                } catch (e) {
                  this.err = e;
                  throw e;
                }
              } else {
                numBytesWritten = util_ts_8.copyBytes(
                  data,
                  this.buf,
                  this.usedBufferBytes,
                );
                this.usedBufferBytes += numBytesWritten;
                await this.flush();
              }
              totalBytesWritten += numBytesWritten;
              data = data.subarray(numBytesWritten);
            }
            numBytesWritten = util_ts_8.copyBytes(
              data,
              this.buf,
              this.usedBufferBytes,
            );
            this.usedBufferBytes += numBytesWritten;
            totalBytesWritten += numBytesWritten;
            return totalBytesWritten;
          }
        };
        exports_77("BufWriter", BufWriter);
        /** BufWriterSync implements buffering for a deno.WriterSync object.
             * If an error occurs writing to a WriterSync, no more data will be
             * accepted and all subsequent writes, and flush(), will return the error.
             * After all data has been written, the client should call the
             * flush() method to guarantee all data has been forwarded to
             * the underlying deno.WriterSync.
             */
        BufWriterSync = class BufWriterSync extends AbstractBufBase {
          constructor(writer, size = DEFAULT_BUF_SIZE) {
            super();
            this.writer = writer;
            if (size <= 0) {
              size = DEFAULT_BUF_SIZE;
            }
            this.buf = new Uint8Array(size);
          }
          /** return new BufWriterSync unless writer is BufWriterSync */
          static create(writer, size = DEFAULT_BUF_SIZE) {
            return writer instanceof BufWriterSync
              ? writer
              : new BufWriterSync(writer, size);
          }
          /** Discards any unflushed buffered data, clears any error, and
                 * resets buffer to write its output to w.
                 */
          reset(w) {
            this.err = null;
            this.usedBufferBytes = 0;
            this.writer = w;
          }
          /** Flush writes any buffered data to the underlying io.WriterSync. */
          flush() {
            if (this.err !== null) {
              throw this.err;
            }
            if (this.usedBufferBytes === 0) {
              return;
            }
            let numBytesWritten = 0;
            try {
              numBytesWritten = this.writer.writeSync(
                this.buf.subarray(0, this.usedBufferBytes),
              );
            } catch (e) {
              this.err = e;
              throw e;
            }
            this.checkBytesWritten(numBytesWritten);
            this.usedBufferBytes = 0;
          }
          /** Writes the contents of `data` into the buffer.  If the contents won't fully
                 * fit into the buffer, those bytes that can are copied into the buffer, the
                 * buffer is the flushed to the writer and the remaining bytes are copied into
                 * the now empty buffer.
                 *
                 * @return the number of bytes written to the buffer.
                 */
          writeSync(data) {
            if (this.err !== null) {
              throw this.err;
            }
            if (data.length === 0) {
              return 0;
            }
            let totalBytesWritten = 0;
            let numBytesWritten = 0;
            while (data.byteLength > this.available()) {
              if (this.buffered() === 0) {
                // Large write, empty buffer.
                // Write directly from data to avoid copy.
                try {
                  numBytesWritten = this.writer.writeSync(data);
                } catch (e) {
                  this.err = e;
                  throw e;
                }
              } else {
                numBytesWritten = util_ts_8.copyBytes(
                  data,
                  this.buf,
                  this.usedBufferBytes,
                );
                this.usedBufferBytes += numBytesWritten;
                this.flush();
              }
              totalBytesWritten += numBytesWritten;
              data = data.subarray(numBytesWritten);
            }
            numBytesWritten = util_ts_8.copyBytes(
              data,
              this.buf,
              this.usedBufferBytes,
            );
            this.usedBufferBytes += numBytesWritten;
            totalBytesWritten += numBytesWritten;
            return totalBytesWritten;
          }
        };
        exports_77("BufWriterSync", BufWriterSync);
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.51.0/async/deferred",
  [],
  function (exports_78, context_78) {
    "use strict";
    var __moduleName = context_78 && context_78.id;
    /** Creates a Promise with the `reject` and `resolve` functions
     * placed as methods on the promise object itself. It allows you to do:
     *
     *     const p = deferred<number>();
     *     // ...
     *     p.resolve(42);
     */
    function deferred() {
      let methods;
      const promise = new Promise((resolve, reject) => {
        methods = { resolve, reject };
      });
      return Object.assign(promise, methods);
    }
    exports_78("deferred", deferred);
    return {
      setters: [],
      execute: function () {
      },
    };
  },
);
System.register(
  "https://deno.land/x/checksum@1.2.0/sha1",
  [],
  function (exports_79, context_79) {
    "use strict";
    var Sha1Hash;
    var __moduleName = context_79 && context_79.id;
    /*
     * Calculate the SHA-1 of an array of big-endian words, and a bit length
     */
    function binb_sha1(x, len) {
      /* append padding */
      x[len >> 5] |= 0x80 << (24 - (len % 32));
      x[(((len + 64) >> 9) << 4) + 15] = len;
      const w = [];
      let a = 1732584193;
      let b = -271733879;
      let c = -1732584194;
      let d = 271733878;
      let e = -1009589776;
      for (let i = 0; i < x.length; i += 16) {
        const olda = a;
        const oldb = b;
        const oldc = c;
        const oldd = d;
        const olde = e;
        for (let j = 0; j < 80; j++) {
          if (j < 16) {
            w[j] = x[i + j];
          } else {
            w[j] = bit_rol(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
          }
          var t = safe_add(
            safe_add(bit_rol(a, 5), sha1_ft(j, b, c, d)),
            safe_add(safe_add(e, w[j]), sha1_kt(j)),
          );
          e = d;
          d = c;
          c = bit_rol(b, 30);
          b = a;
          a = t;
        }
        a = safe_add(a, olda);
        b = safe_add(b, oldb);
        c = safe_add(c, oldc);
        d = safe_add(d, oldd);
        e = safe_add(e, olde);
      }
      return [a, b, c, d, e];
    }
    /*
     * Perform the appropriate triplet combination function for the current
     * iteration
     */
    function sha1_ft(t, b, c, d) {
      if (t < 20) {
        return (b & c) | (~b & d);
      }
      if (t < 40) {
        return b ^ c ^ d;
      }
      if (t < 60) {
        return (b & c) | (b & d) | (c & d);
      }
      return b ^ c ^ d;
    }
    /*
     * Determine the appropriate additive constant for the current iteration
     */
    function sha1_kt(t) {
      return t < 20 ? 1518500249 : t < 40
      ? 1859775393
      : t < 60
      ? -1894007588
      : -899497514;
    }
    /*
     * Add integers, wrapping at 2^32. This uses 16-bit operations internally
     * to work around bugs in some JS interpreters.
     */
    function safe_add(x, y) {
      const lsw = (x & 0xffff) + (y & 0xffff);
      const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
      return (msw << 16) | (lsw & 0xffff);
    }
    /*
     * Bitwise rotate a 32-bit number to the left.
     */
    function bit_rol(num, cnt) {
      return (num << cnt) | (num >>> (32 - cnt));
    }
    return {
      setters: [],
      execute: function () {
        Sha1Hash = class Sha1Hash {
          digest(bytes) {
            let data = [];
            for (var i = 0; i < bytes.length * 8; i += 8) {
              data[i >> 5] |= (bytes[i / 8] & 0xff) << (24 - (i % 32));
            }
            data = binb_sha1(data, bytes.length * 8);
            return this.toStrBytes(data);
          }
          /*
                 * Convert an array of big-endian words to a string
                 */
          toStrBytes(input) {
            let pos = 0;
            const data = new Uint8Array(input.length * 4);
            for (let i = 0; i < input.length * 32; i += 8) {
              data[pos++] = (input[i >> 5] >> (24 - (i % 32))) & 0xff;
            }
            return data;
          }
        };
        exports_79("Sha1Hash", Sha1Hash);
      },
    };
  },
);
System.register(
  "https://deno.land/x/checksum@1.2.0/md5",
  [],
  function (exports_80, context_80) {
    "use strict";
    var Md5Hash;
    var __moduleName = context_80 && context_80.id;
    /*
     * Add integers, wrapping at 2^32. This uses 16-bit operations internally
     * to work around bugs in some JS interpreters.
     */
    function safeAdd(x, y) {
      const lsw = (x & 0xffff) + (y & 0xffff);
      const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
      return (msw << 16) | (lsw & 0xffff);
    }
    /*
     * Bitwise rotate a 32-bit number to the left.
     */
    function bitRotateLeft(num, cnt) {
      return (num << cnt) | (num >>> (32 - cnt));
    }
    /*
     * These functions implement the four basic operations the algorithm uses.
     */
    function md5cmn(q, a, b, x, s, t) {
      return safeAdd(
        bitRotateLeft(safeAdd(safeAdd(a, q), safeAdd(x, t)), s),
        b,
      );
    }
    function md5ff(a, b, c, d, x, s, t) {
      return md5cmn((b & c) | (~b & d), a, b, x, s, t);
    }
    function md5gg(a, b, c, d, x, s, t) {
      return md5cmn((b & d) | (c & ~d), a, b, x, s, t);
    }
    function md5hh(a, b, c, d, x, s, t) {
      return md5cmn(b ^ c ^ d, a, b, x, s, t);
    }
    function md5ii(a, b, c, d, x, s, t) {
      return md5cmn(c ^ (b | ~d), a, b, x, s, t);
    }
    /*
     * Calculate the MD5 of an array of little-endian words, and a bit length.
     */
    function binlMD5(x, len) {
      /* append padding */
      x[len >> 5] |= 0x80 << len % 32;
      x[(((len + 64) >>> 9) << 4) + 14] = len;
      let olda, oldb, oldc, oldd;
      let a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;
      for (let i = 0; i < x.length; i += 16) {
        olda = a;
        oldb = b;
        oldc = c;
        oldd = d;
        a = md5ff(a, b, c, d, x[i], 7, -680876936);
        d = md5ff(d, a, b, c, x[i + 1], 12, -389564586);
        c = md5ff(c, d, a, b, x[i + 2], 17, 606105819);
        b = md5ff(b, c, d, a, x[i + 3], 22, -1044525330);
        a = md5ff(a, b, c, d, x[i + 4], 7, -176418897);
        d = md5ff(d, a, b, c, x[i + 5], 12, 1200080426);
        c = md5ff(c, d, a, b, x[i + 6], 17, -1473231341);
        b = md5ff(b, c, d, a, x[i + 7], 22, -45705983);
        a = md5ff(a, b, c, d, x[i + 8], 7, 1770035416);
        d = md5ff(d, a, b, c, x[i + 9], 12, -1958414417);
        c = md5ff(c, d, a, b, x[i + 10], 17, -42063);
        b = md5ff(b, c, d, a, x[i + 11], 22, -1990404162);
        a = md5ff(a, b, c, d, x[i + 12], 7, 1804603682);
        d = md5ff(d, a, b, c, x[i + 13], 12, -40341101);
        c = md5ff(c, d, a, b, x[i + 14], 17, -1502002290);
        b = md5ff(b, c, d, a, x[i + 15], 22, 1236535329);
        a = md5gg(a, b, c, d, x[i + 1], 5, -165796510);
        d = md5gg(d, a, b, c, x[i + 6], 9, -1069501632);
        c = md5gg(c, d, a, b, x[i + 11], 14, 643717713);
        b = md5gg(b, c, d, a, x[i], 20, -373897302);
        a = md5gg(a, b, c, d, x[i + 5], 5, -701558691);
        d = md5gg(d, a, b, c, x[i + 10], 9, 38016083);
        c = md5gg(c, d, a, b, x[i + 15], 14, -660478335);
        b = md5gg(b, c, d, a, x[i + 4], 20, -405537848);
        a = md5gg(a, b, c, d, x[i + 9], 5, 568446438);
        d = md5gg(d, a, b, c, x[i + 14], 9, -1019803690);
        c = md5gg(c, d, a, b, x[i + 3], 14, -187363961);
        b = md5gg(b, c, d, a, x[i + 8], 20, 1163531501);
        a = md5gg(a, b, c, d, x[i + 13], 5, -1444681467);
        d = md5gg(d, a, b, c, x[i + 2], 9, -51403784);
        c = md5gg(c, d, a, b, x[i + 7], 14, 1735328473);
        b = md5gg(b, c, d, a, x[i + 12], 20, -1926607734);
        a = md5hh(a, b, c, d, x[i + 5], 4, -378558);
        d = md5hh(d, a, b, c, x[i + 8], 11, -2022574463);
        c = md5hh(c, d, a, b, x[i + 11], 16, 1839030562);
        b = md5hh(b, c, d, a, x[i + 14], 23, -35309556);
        a = md5hh(a, b, c, d, x[i + 1], 4, -1530992060);
        d = md5hh(d, a, b, c, x[i + 4], 11, 1272893353);
        c = md5hh(c, d, a, b, x[i + 7], 16, -155497632);
        b = md5hh(b, c, d, a, x[i + 10], 23, -1094730640);
        a = md5hh(a, b, c, d, x[i + 13], 4, 681279174);
        d = md5hh(d, a, b, c, x[i], 11, -358537222);
        c = md5hh(c, d, a, b, x[i + 3], 16, -722521979);
        b = md5hh(b, c, d, a, x[i + 6], 23, 76029189);
        a = md5hh(a, b, c, d, x[i + 9], 4, -640364487);
        d = md5hh(d, a, b, c, x[i + 12], 11, -421815835);
        c = md5hh(c, d, a, b, x[i + 15], 16, 530742520);
        b = md5hh(b, c, d, a, x[i + 2], 23, -995338651);
        a = md5ii(a, b, c, d, x[i], 6, -198630844);
        d = md5ii(d, a, b, c, x[i + 7], 10, 1126891415);
        c = md5ii(c, d, a, b, x[i + 14], 15, -1416354905);
        b = md5ii(b, c, d, a, x[i + 5], 21, -57434055);
        a = md5ii(a, b, c, d, x[i + 12], 6, 1700485571);
        d = md5ii(d, a, b, c, x[i + 3], 10, -1894986606);
        c = md5ii(c, d, a, b, x[i + 10], 15, -1051523);
        b = md5ii(b, c, d, a, x[i + 1], 21, -2054922799);
        a = md5ii(a, b, c, d, x[i + 8], 6, 1873313359);
        d = md5ii(d, a, b, c, x[i + 15], 10, -30611744);
        c = md5ii(c, d, a, b, x[i + 6], 15, -1560198380);
        b = md5ii(b, c, d, a, x[i + 13], 21, 1309151649);
        a = md5ii(a, b, c, d, x[i + 4], 6, -145523070);
        d = md5ii(d, a, b, c, x[i + 11], 10, -1120210379);
        c = md5ii(c, d, a, b, x[i + 2], 15, 718787259);
        b = md5ii(b, c, d, a, x[i + 9], 21, -343485551);
        a = safeAdd(a, olda);
        b = safeAdd(b, oldb);
        c = safeAdd(c, oldc);
        d = safeAdd(d, oldd);
      }
      return [a, b, c, d];
    }
    function md5(bytes) {
      let data = [];
      var length8 = bytes.length * 8;
      for (let i = 0; i < length8; i += 8) {
        data[i >> 5] |= (bytes[i / 8] & 0xff) << i % 32;
      }
      return binlMD5(data, bytes.length * 8);
    }
    return {
      setters: [],
      execute: function () {
        Md5Hash = class Md5Hash {
          digest(bytes) {
            const data = md5(bytes);
            return this.toStrBytes(data);
          }
          toStrBytes(input) {
            const buffer = new ArrayBuffer(16);
            new Uint32Array(buffer).set(input);
            return new Uint8Array(buffer);
          }
        };
        exports_80("Md5Hash", Md5Hash);
      },
    };
  },
);
System.register(
  "https://deno.land/x/checksum@1.2.0/hash",
  [
    "https://deno.land/x/checksum@1.2.0/sha1",
    "https://deno.land/x/checksum@1.2.0/md5",
  ],
  function (exports_81, context_81) {
    "use strict";
    var sha1_ts_1, md5_ts_1, Hash;
    var __moduleName = context_81 && context_81.id;
    function hex(bytes) {
      return Array.prototype.map
        .call(bytes, (x) => x.toString(16).padStart(2, "0"))
        .join("");
    }
    exports_81("hex", hex);
    return {
      setters: [
        function (sha1_ts_1_1) {
          sha1_ts_1 = sha1_ts_1_1;
        },
        function (md5_ts_1_1) {
          md5_ts_1 = md5_ts_1_1;
        },
      ],
      execute: function () {
        Hash = class Hash {
          constructor(algorithm) {
            this.algorithm = algorithm;
            const algorithms = {
              sha1: sha1_ts_1.Sha1Hash,
              md5: md5_ts_1.Md5Hash,
            };
            this.instance = new algorithms[algorithm]();
          }
          digest(bytes) {
            bytes = this.instance.digest(bytes);
            return {
              data: bytes,
              hex: () => hex(bytes),
            };
          }
        };
        exports_81("Hash", Hash);
      },
    };
  },
);
System.register(
  "https://deno.land/x/checksum@1.2.0/mod",
  ["https://deno.land/x/checksum@1.2.0/hash"],
  function (exports_82, context_82) {
    "use strict";
    var encoder, encode;
    var __moduleName = context_82 && context_82.id;
    return {
      setters: [
        function (hash_ts_1_1) {
          exports_82({
            "Hash": hash_ts_1_1["Hash"],
            "hex": hash_ts_1_1["hex"],
          });
        },
      ],
      execute: function () {
        encoder = new TextEncoder();
        exports_82("encode", encode = (str) => encoder.encode(str));
      },
    };
  },
);
System.register(
  "https://deno.land/x/postgres/deps",
  [
    "https://deno.land/std@0.51.0/io/bufio",
    "https://deno.land/std@0.51.0/io/util",
    "https://deno.land/std@0.51.0/async/deferred",
    "https://deno.land/x/checksum@1.2.0/mod",
  ],
  function (exports_83, context_83) {
    "use strict";
    var __moduleName = context_83 && context_83.id;
    return {
      setters: [
        function (bufio_ts_3_1) {
          exports_83({
            "BufReader": bufio_ts_3_1["BufReader"],
            "BufWriter": bufio_ts_3_1["BufWriter"],
          });
        },
        function (util_ts_9_1) {
          exports_83({
            "copyBytes": util_ts_9_1["copyBytes"],
          });
        },
        function (deferred_ts_3_1) {
          exports_83({
            "deferred": deferred_ts_3_1["deferred"],
          });
        },
        function (mod_ts_10_1) {
          exports_83({
            "Hash": mod_ts_10_1["Hash"],
          });
        },
      ],
      execute: function () {
      },
    };
  },
);
/*!
 * Adapted directly from https://github.com/brianc/node-buffer-writer
 * which is licensed as follows:
 *
 * The MIT License (MIT)
 *
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * 'Software'), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
System.register(
  "https://deno.land/x/postgres/packet_writer",
  ["https://deno.land/x/postgres/deps"],
  function (exports_84, context_84) {
    "use strict";
    var deps_ts_12, PacketWriter;
    var __moduleName = context_84 && context_84.id;
    return {
      setters: [
        function (deps_ts_12_1) {
          deps_ts_12 = deps_ts_12_1;
        },
      ],
      execute: function () {
        PacketWriter = class PacketWriter {
          constructor(size) {
            this.encoder = new TextEncoder();
            this.size = size || 1024;
            this.buffer = new Uint8Array(this.size + 5);
            this.offset = 5;
            this.headerPosition = 0;
          }
          _ensure(size) {
            const remaining = this.buffer.length - this.offset;
            if (remaining < size) {
              const oldBuffer = this.buffer;
              // exponential growth factor of around ~ 1.5
              // https://stackoverflow.com/questions/2269063/buffer-growth-strategy
              const newSize = oldBuffer.length + (oldBuffer.length >> 1) + size;
              this.buffer = new Uint8Array(newSize);
              deps_ts_12.copyBytes(oldBuffer, this.buffer);
            }
          }
          addInt32(num) {
            this._ensure(4);
            this.buffer[this.offset++] = (num >>> 24) & 0xff;
            this.buffer[this.offset++] = (num >>> 16) & 0xff;
            this.buffer[this.offset++] = (num >>> 8) & 0xff;
            this.buffer[this.offset++] = (num >>> 0) & 0xff;
            return this;
          }
          addInt16(num) {
            this._ensure(2);
            this.buffer[this.offset++] = (num >>> 8) & 0xff;
            this.buffer[this.offset++] = (num >>> 0) & 0xff;
            return this;
          }
          addCString(string) {
            // just write a 0 for empty or null strings
            if (!string) {
              this._ensure(1);
            } else {
              const encodedStr = this.encoder.encode(string);
              this._ensure(encodedStr.byteLength + 1); // +1 for null terminator
              deps_ts_12.copyBytes(encodedStr, this.buffer, this.offset);
              this.offset += encodedStr.byteLength;
            }
            this.buffer[this.offset++] = 0; // null terminator
            return this;
          }
          addChar(c) {
            if (c.length != 1) {
              throw new Error("addChar requires single character strings");
            }
            this._ensure(1);
            deps_ts_12.copyBytes(
              this.encoder.encode(c),
              this.buffer,
              this.offset,
            );
            this.offset++;
            return this;
          }
          addString(string) {
            string = string || "";
            const encodedStr = this.encoder.encode(string);
            this._ensure(encodedStr.byteLength);
            deps_ts_12.copyBytes(encodedStr, this.buffer, this.offset);
            this.offset += encodedStr.byteLength;
            return this;
          }
          add(otherBuffer) {
            this._ensure(otherBuffer.length);
            deps_ts_12.copyBytes(otherBuffer, this.buffer, this.offset);
            this.offset += otherBuffer.length;
            return this;
          }
          clear() {
            this.offset = 5;
            this.headerPosition = 0;
          }
          // appends a header block to all the written data since the last
          // subsequent header or to the beginning if there is only one data block
          addHeader(code, last) {
            const origOffset = this.offset;
            this.offset = this.headerPosition;
            this.buffer[this.offset++] = code;
            // length is everything in this packet minus the code
            this.addInt32(origOffset - (this.headerPosition + 1));
            // set next header position
            this.headerPosition = origOffset;
            // make space for next header
            this.offset = origOffset;
            if (!last) {
              this._ensure(5);
              this.offset += 5;
            }
            return this;
          }
          join(code) {
            if (code) {
              this.addHeader(code, true);
            }
            return this.buffer.slice(code ? 0 : 5, this.offset);
          }
          flush(code) {
            const result = this.join(code);
            this.clear();
            return result;
          }
        };
        exports_84("PacketWriter", PacketWriter);
      },
    };
  },
);
System.register(
  "https://deno.land/x/postgres/utils",
  ["https://deno.land/x/postgres/deps"],
  function (exports_85, context_85) {
    "use strict";
    var deps_ts_13, encoder;
    var __moduleName = context_85 && context_85.id;
    function readInt16BE(buffer, offset) {
      offset = offset >>> 0;
      const val = buffer[offset + 1] | (buffer[offset] << 8);
      return val & 0x8000 ? val | 0xffff0000 : val;
    }
    exports_85("readInt16BE", readInt16BE);
    function readUInt16BE(buffer, offset) {
      offset = offset >>> 0;
      return buffer[offset] | (buffer[offset + 1] << 8);
    }
    exports_85("readUInt16BE", readUInt16BE);
    function readInt32BE(buffer, offset) {
      offset = offset >>> 0;
      return ((buffer[offset] << 24) |
        (buffer[offset + 1] << 16) |
        (buffer[offset + 2] << 8) |
        buffer[offset + 3]);
    }
    exports_85("readInt32BE", readInt32BE);
    function readUInt32BE(buffer, offset) {
      offset = offset >>> 0;
      return (buffer[offset] * 0x1000000 +
        ((buffer[offset + 1] << 16) |
          (buffer[offset + 2] << 8) |
          buffer[offset + 3]));
    }
    exports_85("readUInt32BE", readUInt32BE);
    function md5(bytes) {
      return new deps_ts_13.Hash("md5").digest(bytes).hex();
    }
    // https://www.postgresql.org/docs/current/protocol-flow.html
    // AuthenticationMD5Password
    // The actual PasswordMessage can be computed in SQL as:
    //  concat('md5', md5(concat(md5(concat(password, username)), random-salt))).
    // (Keep in mind the md5() function returns its result as a hex string.)
    function hashMd5Password(password, username, salt) {
      const innerHash = md5(encoder.encode(password + username));
      const innerBytes = encoder.encode(innerHash);
      const outerBuffer = new Uint8Array(innerBytes.length + salt.length);
      outerBuffer.set(innerBytes);
      outerBuffer.set(salt, innerBytes.length);
      const outerHash = md5(outerBuffer);
      return "md5" + outerHash;
    }
    exports_85("hashMd5Password", hashMd5Password);
    function parseDsn(dsn) {
      //URL object won't parse the URL if it doesn't recognize the protocol
      //This line replaces the protocol with http and then leaves it up to URL
      const [protocol, stripped_url] = dsn.match(/(?:(?!:\/\/).)+/g) ??
        ["", ""];
      const url = new URL(`http:${stripped_url}`);
      return {
        driver: protocol,
        user: url.username,
        password: url.password,
        hostname: url.hostname,
        port: url.port,
        // remove leading slash from path
        database: url.pathname.slice(1),
        params: Object.fromEntries(url.searchParams.entries()),
      };
    }
    exports_85("parseDsn", parseDsn);
    function delay(ms, value) {
      return new Promise((resolve, reject) => {
        setTimeout(() => {
          resolve(value);
        }, ms);
      });
    }
    exports_85("delay", delay);
    return {
      setters: [
        function (deps_ts_13_1) {
          deps_ts_13 = deps_ts_13_1;
        },
      ],
      execute: function () {
        encoder = new TextEncoder();
      },
    };
  },
);
System.register(
  "https://deno.land/x/postgres/packet_reader",
  ["https://deno.land/x/postgres/utils"],
  function (exports_86, context_86) {
    "use strict";
    var utils_ts_1, PacketReader;
    var __moduleName = context_86 && context_86.id;
    return {
      setters: [
        function (utils_ts_1_1) {
          utils_ts_1 = utils_ts_1_1;
        },
      ],
      execute: function () {
        PacketReader = class PacketReader {
          constructor(buffer) {
            this.buffer = buffer;
            this.offset = 0;
            this.decoder = new TextDecoder();
          }
          readInt16() {
            const value = utils_ts_1.readInt16BE(this.buffer, this.offset);
            this.offset += 2;
            return value;
          }
          readInt32() {
            const value = utils_ts_1.readInt32BE(this.buffer, this.offset);
            this.offset += 4;
            return value;
          }
          readByte() {
            return this.readBytes(1)[0];
          }
          readBytes(length) {
            const start = this.offset;
            const end = start + length;
            const slice = this.buffer.slice(start, end);
            this.offset = end;
            return slice;
          }
          readString(length) {
            const bytes = this.readBytes(length);
            return this.decoder.decode(bytes);
          }
          readCString() {
            const start = this.offset;
            // find next null byte
            const end = this.buffer.indexOf(0, start);
            const slice = this.buffer.slice(start, end);
            // add +1 for null byte
            this.offset = end + 1;
            return this.decoder.decode(slice);
          }
        };
        exports_86("PacketReader", PacketReader);
      },
    };
  },
);
System.register(
  "https://deno.land/x/postgres/encode",
  [],
  function (exports_87, context_87) {
    "use strict";
    var __moduleName = context_87 && context_87.id;
    function pad(number, digits) {
      let padded = "" + number;
      while (padded.length < digits) {
        padded = "0" + padded;
      }
      return padded;
    }
    function encodeDate(date) {
      // Construct ISO date
      const year = pad(date.getFullYear(), 4);
      const month = pad(date.getMonth() + 1, 2);
      const day = pad(date.getDate(), 2);
      const hour = pad(date.getHours(), 2);
      const min = pad(date.getMinutes(), 2);
      const sec = pad(date.getSeconds(), 2);
      const ms = pad(date.getMilliseconds(), 3);
      const encodedDate = `${year}-${month}-${day}T${hour}:${min}:${sec}.${ms}`;
      // Construct timezone info
      //
      // Date.prototype.getTimezoneOffset();
      //
      // From MDN:
      // > The time-zone offset is the difference, in minutes, from local time to UTC.
      // > Note that this means that the offset is positive if the local timezone is
      // > behind UTC and negative if it is ahead. For example, for time zone UTC+10:00
      // > (Australian Eastern Standard Time, Vladivostok Time, Chamorro Standard Time),
      // > -600 will be returned.
      const offset = date.getTimezoneOffset();
      const tzSign = offset > 0 ? "-" : "+";
      const absOffset = Math.abs(offset);
      const tzHours = pad(Math.floor(absOffset / 60), 2);
      const tzMinutes = pad(Math.floor(absOffset % 60), 2);
      const encodedTz = `${tzSign}${tzHours}:${tzMinutes}`;
      return encodedDate + encodedTz;
    }
    function escapeArrayElement(value) {
      // deno-lint-ignore no-explicit-any
      let strValue = value.toString();
      const escapedValue = strValue.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
      return `"${escapedValue}"`;
    }
    function encodeArray(array) {
      let encodedArray = "{";
      array.forEach((element, index) => {
        if (index > 0) {
          encodedArray += ",";
        }
        if (element === null || typeof element === "undefined") {
          encodedArray += "NULL";
        } else if (Array.isArray(element)) {
          encodedArray += encodeArray(element);
        } else if (element instanceof Uint8Array) {
          // TODO: it should be encoded as bytea?
          throw new Error("Can't encode array of buffers.");
        } else {
          const encodedElement = encode(element);
          encodedArray += escapeArrayElement(encodedElement);
        }
      });
      encodedArray += "}";
      return encodedArray;
    }
    function encodeBytes(value) {
      let hex = Array.from(value)
        .map((val) => (val < 10 ? `0${val.toString(16)}` : val.toString(16)))
        .join("");
      return `\\x${hex}`;
    }
    function encode(value) {
      if (value === null || typeof value === "undefined") {
        return null;
      } else if (value instanceof Uint8Array) {
        return encodeBytes(value);
      } else if (value instanceof Date) {
        return encodeDate(value);
      } else if (value instanceof Array) {
        return encodeArray(value);
      } else if (value instanceof Object) {
        return JSON.stringify(value);
      } else {
        // deno-lint-ignore no-explicit-any
        return value.toString();
      }
    }
    exports_87("encode", encode);
    return {
      setters: [],
      execute: function () {
      },
    };
  },
);
System.register(
  "https://deno.land/x/postgres/oid",
  [],
  function (exports_88, context_88) {
    "use strict";
    var Oid;
    var __moduleName = context_88 && context_88.id;
    return {
      setters: [],
      execute: function () {
        exports_88(
          "Oid",
          Oid = {
            bool: 16,
            bytea: 17,
            char: 18,
            name: 19,
            int8: 20,
            int2: 21,
            int2vector: 22,
            int4: 23,
            regproc: 24,
            text: 25,
            oid: 26,
            tid: 27,
            xid: 28,
            cid: 29,
            oidvector: 30,
            pg_ddl_command: 32,
            pg_type: 71,
            pg_attribute: 75,
            pg_proc: 81,
            pg_class: 83,
            json: 114,
            xml: 142,
            _xml: 143,
            pg_node_tree: 194,
            _json: 199,
            smgr: 210,
            index_am_handler: 325,
            point: 600,
            lseg: 601,
            path: 602,
            box: 603,
            polygon: 604,
            line: 628,
            _line: 629,
            cidr: 650,
            _cidr: 651,
            float4: 700,
            float8: 701,
            abstime: 702,
            reltime: 703,
            tinterval: 704,
            unknown: 705,
            circle: 718,
            _circle: 719,
            money: 790,
            _money: 791,
            macaddr: 829,
            inet: 869,
            _bool: 1000,
            _bytea: 1001,
            _char: 1002,
            _name: 1003,
            _int2: 1005,
            _int2vector: 1006,
            _int4: 1007,
            _regproc: 1008,
            _text: 1009,
            _tid: 1010,
            _xid: 1011,
            _cid: 1012,
            _oidvector: 1013,
            _bpchar: 1014,
            _varchar: 1015,
            _int8: 1016,
            _point: 1017,
            _lseg: 1018,
            _path: 1019,
            _box: 1020,
            _float4: 1021,
            _float8: 1022,
            _abstime: 1023,
            _reltime: 1024,
            _tinterval: 1025,
            _polygon: 1027,
            _oid: 1028,
            aclitem: 1033,
            _aclitem: 1034,
            _macaddr: 1040,
            _inet: 1041,
            bpchar: 1042,
            varchar: 1043,
            date: 1082,
            time: 1083,
            timestamp: 1114,
            _timestamp: 1115,
            _date: 1182,
            _time: 1183,
            timestamptz: 1184,
            _timestamptz: 1185,
            interval: 1186,
            _interval: 1187,
            _numeric: 1231,
            pg_database: 1248,
            _cstring: 1263,
            timetz: 1266,
            _timetz: 1270,
            bit: 1560,
            _bit: 1561,
            varbit: 1562,
            _varbit: 1563,
            numeric: 1700,
            refcursor: 1790,
            _refcursor: 2201,
            regprocedure: 2202,
            regoper: 2203,
            regoperator: 2204,
            regclass: 2205,
            regtype: 2206,
            _regprocedure: 2207,
            _regoper: 2208,
            _regoperator: 2209,
            _regclass: 2210,
            _regtype: 2211,
            record: 2249,
            cstring: 2275,
            any: 2276,
            anyarray: 2277,
            void: 2278,
            trigger: 2279,
            language_handler: 2280,
            internal: 2281,
            opaque: 2282,
            anyelement: 2283,
            _record: 2287,
            anynonarray: 2776,
            pg_authid: 2842,
            pg_auth_members: 2843,
            _txid_snapshot: 2949,
            uuid: 2950,
            _uuid: 2951,
            txid_snapshot: 2970,
            fdw_handler: 3115,
            pg_lsn: 3220,
            _pg_lsn: 3221,
            tsm_handler: 3310,
            anyenum: 3500,
            tsvector: 3614,
            tsquery: 3615,
            gtsvector: 3642,
            _tsvector: 3643,
            _gtsvector: 3644,
            _tsquery: 3645,
            regconfig: 3734,
            _regconfig: 3735,
            regdictionary: 3769,
            _regdictionary: 3770,
            jsonb: 3802,
            _jsonb: 3807,
            anyrange: 3831,
            event_trigger: 3838,
            int4range: 3904,
            _int4range: 3905,
            numrange: 3906,
            _numrange: 3907,
            tsrange: 3908,
            _tsrange: 3909,
            tstzrange: 3910,
            _tstzrange: 3911,
            daterange: 3912,
            _daterange: 3913,
            int8range: 3926,
            _int8range: 3927,
            pg_shseclabel: 4066,
            regnamespace: 4089,
            _regnamespace: 4090,
            regrole: 4096,
            _regrole: 4097,
          },
        );
      },
    };
  },
);
System.register(
  "https://deno.land/x/postgres/decode",
  [
    "https://deno.land/x/postgres/oid",
    "https://deno.land/x/postgres/connection",
  ],
  function (exports_89, context_89) {
    "use strict";
    var oid_ts_1,
      connection_ts_1,
      DATETIME_RE,
      DATE_RE,
      TIMEZONE_RE,
      BC_RE,
      HEX,
      BACKSLASH_BYTE_VALUE,
      HEX_PREFIX_REGEX,
      decoder;
    var __moduleName = context_89 && context_89.id;
    function decodeDate(dateStr) {
      const matches = DATE_RE.exec(dateStr);
      if (!matches) {
        return null;
      }
      const year = parseInt(matches[1], 10);
      // remember JS dates are 0-based
      const month = parseInt(matches[2], 10) - 1;
      const day = parseInt(matches[3], 10);
      const date = new Date(year, month, day);
      // use `setUTCFullYear` because if date is from first
      // century `Date`'s compatibility for millenium bug
      // would set it as 19XX
      date.setUTCFullYear(year);
      return date;
    }
    /**
     * Decode numerical timezone offset from provided date string.
     *
     * Matched these kinds:
     * - `Z (UTC)`
     * - `-05`
     * - `+06:30`
     * - `+06:30:10`
     *
     * Returns offset in miliseconds.
     */
    function decodeTimezoneOffset(dateStr) {
      // get rid of date part as TIMEZONE_RE would match '-MM` part
      const timeStr = dateStr.split(" ")[1];
      const matches = TIMEZONE_RE.exec(timeStr);
      if (!matches) {
        return null;
      }
      const type = matches[1];
      if (type === "Z") {
        // Zulu timezone === UTC === 0
        return 0;
      }
      // in JS timezone offsets are reversed, ie. timezones
      // that are "positive" (+01:00) are represented as negative
      // offsets and vice-versa
      const sign = type === "-" ? 1 : -1;
      const hours = parseInt(matches[2], 10);
      const minutes = parseInt(matches[3] || "0", 10);
      const seconds = parseInt(matches[4] || "0", 10);
      const offset = hours * 3600 + minutes * 60 + seconds;
      return sign * offset * 1000;
    }
    function decodeDatetime(dateStr) {
      /**
         * Postgres uses ISO 8601 style date output by default:
         * 1997-12-17 07:37:16-08
         */
      // there are special `infinity` and `-infinity`
      // cases representing out-of-range dates
      if (dateStr === "infinity") {
        return Number(Infinity);
      } else if (dateStr === "-infinity") {
        return Number(-Infinity);
      }
      const matches = DATETIME_RE.exec(dateStr);
      if (!matches) {
        return decodeDate(dateStr);
      }
      const isBC = BC_RE.test(dateStr);
      const year = parseInt(matches[1], 10) * (isBC ? -1 : 1);
      // remember JS dates are 0-based
      const month = parseInt(matches[2], 10) - 1;
      const day = parseInt(matches[3], 10);
      const hour = parseInt(matches[4], 10);
      const minute = parseInt(matches[5], 10);
      const second = parseInt(matches[6], 10);
      // ms are written as .007
      const msMatch = matches[7];
      const ms = msMatch ? 1000 * parseFloat(msMatch) : 0;
      let date;
      const offset = decodeTimezoneOffset(dateStr);
      if (offset === null) {
        date = new Date(year, month, day, hour, minute, second, ms);
      } else {
        // This returns miliseconds from 1 January, 1970, 00:00:00,
        // adding decoded timezone offset will construct proper date object.
        const utc = Date.UTC(year, month, day, hour, minute, second, ms);
        date = new Date(utc + offset);
      }
      // use `setUTCFullYear` because if date is from first
      // century `Date`'s compatibility for millenium bug
      // would set it as 19XX
      date.setUTCFullYear(year);
      return date;
    }
    function decodeBinary() {
      throw new Error("Not implemented!");
    }
    function decodeBytea(byteaStr) {
      if (HEX_PREFIX_REGEX.test(byteaStr)) {
        return decodeByteaHex(byteaStr);
      } else {
        return decodeByteaEscape(byteaStr);
      }
    }
    function decodeByteaHex(byteaStr) {
      let bytesStr = byteaStr.slice(2);
      let bytes = new Uint8Array(bytesStr.length / 2);
      for (let i = 0, j = 0; i < bytesStr.length; i += 2, j++) {
        bytes[j] = parseInt(bytesStr[i] + bytesStr[i + 1], HEX);
      }
      return bytes;
    }
    function decodeByteaEscape(byteaStr) {
      let bytes = [];
      let i = 0;
      while (i < byteaStr.length) {
        if (byteaStr[i] !== "\\") {
          bytes.push(byteaStr.charCodeAt(i));
          ++i;
        } else {
          if (/[0-7]{3}/.test(byteaStr.substr(i + 1, 3))) {
            bytes.push(parseInt(byteaStr.substr(i + 1, 3), 8));
            i += 4;
          } else {
            let backslashes = 1;
            while (
              i + backslashes < byteaStr.length &&
              byteaStr[i + backslashes] === "\\"
            ) {
              backslashes++;
            }
            for (var k = 0; k < Math.floor(backslashes / 2); ++k) {
              bytes.push(BACKSLASH_BYTE_VALUE);
            }
            i += Math.floor(backslashes / 2) * 2;
          }
        }
      }
      return new Uint8Array(bytes);
    }
    // deno-lint-ignore no-explicit-any
    function decodeText(value, typeOid) {
      const strValue = decoder.decode(value);
      switch (typeOid) {
        case oid_ts_1.Oid.char:
        case oid_ts_1.Oid.varchar:
        case oid_ts_1.Oid.text:
        case oid_ts_1.Oid.time:
        case oid_ts_1.Oid.timetz:
        case oid_ts_1.Oid.inet:
        case oid_ts_1.Oid.cidr:
        case oid_ts_1.Oid.macaddr:
        case oid_ts_1.Oid.name:
        case oid_ts_1.Oid.uuid:
        case oid_ts_1.Oid.oid:
        case oid_ts_1.Oid.regproc:
        case oid_ts_1.Oid.regprocedure:
        case oid_ts_1.Oid.regoper:
        case oid_ts_1.Oid.regoperator:
        case oid_ts_1.Oid.regclass:
        case oid_ts_1.Oid.regtype:
        case oid_ts_1.Oid.regrole:
        case oid_ts_1.Oid.regnamespace:
        case oid_ts_1.Oid.regconfig:
        case oid_ts_1.Oid.regdictionary:
        case oid_ts_1.Oid.int8: // @see https://github.com/buildondata/deno-postgres/issues/91.
        case oid_ts_1.Oid.numeric:
        case oid_ts_1.Oid.void:
        case oid_ts_1.Oid.bpchar:
          return strValue;
        case oid_ts_1.Oid.bool:
          return strValue[0] === "t";
        case oid_ts_1.Oid.int2:
        case oid_ts_1.Oid.int4:
          return parseInt(strValue, 10);
        case oid_ts_1.Oid._int4:
          return strValue.replace("{", "").replace("}", "").split(",").map((
            x,
          ) => Number(x));
        case oid_ts_1.Oid.float4:
        case oid_ts_1.Oid.float8:
          return parseFloat(strValue);
        case oid_ts_1.Oid.timestamptz:
        case oid_ts_1.Oid.timestamp:
          return decodeDatetime(strValue);
        case oid_ts_1.Oid.date:
          return decodeDate(strValue);
        case oid_ts_1.Oid.json:
        case oid_ts_1.Oid.jsonb:
          return JSON.parse(strValue);
        case oid_ts_1.Oid.bytea:
          return decodeBytea(strValue);
        default:
          throw new Error(`Don't know how to parse column type: ${typeOid}`);
      }
    }
    function decode(value, column) {
      if (column.format === connection_ts_1.Format.BINARY) {
        return decodeBinary();
      } else if (column.format === connection_ts_1.Format.TEXT) {
        return decodeText(value, column.typeOid);
      } else {
        throw new Error(`Unknown column format: ${column.format}`);
      }
    }
    exports_89("decode", decode);
    return {
      setters: [
        function (oid_ts_1_1) {
          oid_ts_1 = oid_ts_1_1;
        },
        function (connection_ts_1_1) {
          connection_ts_1 = connection_ts_1_1;
        },
      ],
      execute: function () {
        // Datetime parsing based on:
        // https://github.com/bendrucker/postgres-date/blob/master/index.js
        DATETIME_RE =
          /^(\d{1,})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})(\.\d{1,})?/;
        DATE_RE = /^(\d{1,})-(\d{2})-(\d{2})$/;
        TIMEZONE_RE = /([Z+-])(\d{2})?:?(\d{2})?:?(\d{2})?/;
        BC_RE = /BC$/;
        HEX = 16;
        BACKSLASH_BYTE_VALUE = 92;
        HEX_PREFIX_REGEX = /^\\x/;
        decoder = new TextDecoder();
      },
    };
  },
);
System.register(
  "https://deno.land/x/postgres/query",
  [
    "https://deno.land/x/postgres/encode",
    "https://deno.land/x/postgres/decode",
  ],
  function (exports_90, context_90) {
    "use strict";
    var encode_ts_1, decode_ts_1, commandTagRegexp, QueryResult, Query;
    var __moduleName = context_90 && context_90.id;
    return {
      setters: [
        function (encode_ts_1_1) {
          encode_ts_1 = encode_ts_1_1;
        },
        function (decode_ts_1_1) {
          decode_ts_1 = decode_ts_1_1;
        },
      ],
      execute: function () {
        commandTagRegexp = /^([A-Za-z]+)(?: (\d+))?(?: (\d+))?/;
        QueryResult = class QueryResult {
          constructor(query) {
            this.query = query;
            this._done = false;
            // deno-lint-ignore no-explicit-any
            this.rows = []; // actual results
          }
          handleRowDescription(description) {
            this.rowDescription = description;
          }
          // deno-lint-ignore no-explicit-any
          _parseDataRow(dataRow) {
            const parsedRow = [];
            for (let i = 0, len = dataRow.length; i < len; i++) {
              const column = this.rowDescription.columns[i];
              const rawValue = dataRow[i];
              if (rawValue === null) {
                parsedRow.push(null);
              } else {
                parsedRow.push(decode_ts_1.decode(rawValue, column));
              }
            }
            return parsedRow;
          }
          // deno-lint-ignore no-explicit-any
          handleDataRow(dataRow) {
            if (this._done) {
              throw new Error("New data row, after result if done.");
            }
            const parsedRow = this._parseDataRow(dataRow);
            this.rows.push(parsedRow);
          }
          handleCommandComplete(commandTag) {
            const match = commandTagRegexp.exec(commandTag);
            if (match) {
              this.command = match[1];
              if (match[3]) {
                // COMMAND OID ROWS
                this.rowCount = parseInt(match[3], 10);
              } else {
                // COMMAND ROWS
                this.rowCount = parseInt(match[2], 10);
              }
            }
          }
          rowsOfObjects() {
            return this.rows.map((row) => {
              // deno-lint-ignore no-explicit-any
              const rv = {};
              this.rowDescription.columns.forEach((column, index) => {
                rv[column.name] = row[index];
              });
              return rv;
            });
          }
          done() {
            this._done = true;
          }
        };
        exports_90("QueryResult", QueryResult);
        Query = class Query {
          // TODO: can we use more specific type for args?
          constructor(text, ...args) {
            let config;
            if (typeof text === "string") {
              config = { text, args };
            } else {
              config = text;
            }
            this.text = config.text;
            this.args = this._prepareArgs(config);
            this.result = new QueryResult(this);
          }
          _prepareArgs(config) {
            const encodingFn = config.encoder ? config.encoder
            : encode_ts_1.encode;
            return (config.args || []).map(encodingFn);
          }
        };
        exports_90("Query", Query);
      },
    };
  },
);
System.register(
  "https://deno.land/x/postgres/error",
  [],
  function (exports_91, context_91) {
    "use strict";
    var PostgresError;
    var __moduleName = context_91 && context_91.id;
    function parseError(msg) {
      // https://www.postgresql.org/docs/current/protocol-error-fields.html
      // deno-lint-ignore no-explicit-any
      const errorFields = {};
      let byte;
      let char;
      let errorMsg;
      while ((byte = msg.reader.readByte())) {
        char = String.fromCharCode(byte);
        errorMsg = msg.reader.readCString();
        switch (char) {
          case "S":
            errorFields.severity = errorMsg;
            break;
          case "C":
            errorFields.code = errorMsg;
            break;
          case "M":
            errorFields.message = errorMsg;
            break;
          case "D":
            errorFields.detail = errorMsg;
            break;
          case "H":
            errorFields.hint = errorMsg;
            break;
          case "P":
            errorFields.position = errorMsg;
            break;
          case "p":
            errorFields.internalPosition = errorMsg;
            break;
          case "q":
            errorFields.internalQuery = errorMsg;
            break;
          case "W":
            errorFields.where = errorMsg;
            break;
          case "s":
            errorFields.schema = errorMsg;
            break;
          case "t":
            errorFields.table = errorMsg;
            break;
          case "c":
            errorFields.column = errorMsg;
            break;
          case "d":
            errorFields.dataTypeName = errorMsg;
            break;
          case "n":
            errorFields.constraint = errorMsg;
            break;
          case "F":
            errorFields.file = errorMsg;
            break;
          case "L":
            errorFields.line = errorMsg;
            break;
          case "R":
            errorFields.routine = errorMsg;
            break;
          default:
            // from Postgres docs
            // > Since more field types might be added in future,
            // > frontends should silently ignore fields of unrecognized type.
            break;
        }
      }
      return new PostgresError(errorFields);
    }
    exports_91("parseError", parseError);
    return {
      setters: [],
      execute: function () {
        PostgresError = class PostgresError extends Error {
          constructor(fields) {
            super(fields.message);
            this.fields = fields;
            this.name = "PostgresError";
          }
        };
        exports_91("PostgresError", PostgresError);
      },
    };
  },
);
System.register(
  "https://deno.land/x/postgres/connection_params",
  ["https://deno.land/x/postgres/utils"],
  function (exports_92, context_92) {
    "use strict";
    var utils_ts_2, ConnectionParamsError, DEFAULT_OPTIONS;
    var __moduleName = context_92 && context_92.id;
    function getPgEnv() {
      try {
        const env = Deno.env;
        const port = env.get("PGPORT");
        return {
          database: env.get("PGDATABASE"),
          hostname: env.get("PGHOST"),
          port: port !== undefined ? parseInt(port, 10) : undefined,
          user: env.get("PGUSER"),
          password: env.get("PGPASSWORD"),
          applicationName: env.get("PGAPPNAME"),
        };
      } catch (e) {
        // PermissionDenied (--allow-env not passed)
        return {};
      }
    }
    function isDefined(value) {
      return value !== undefined && value !== null;
    }
    function select(sources, key) {
      return sources.map((s) => s[key]).find(isDefined);
    }
    function selectRequired(sources, key) {
      const result = select(sources, key);
      if (!isDefined(result)) {
        throw new ConnectionParamsError(
          `Required parameter ${key} not provided`,
        );
      }
      return result;
    }
    function assertRequiredOptions(sources, requiredKeys) {
      const missingParams = [];
      for (const key of requiredKeys) {
        if (!isDefined(select(sources, key))) {
          missingParams.push(key);
        }
      }
      if (missingParams.length) {
        throw new ConnectionParamsError(formatMissingParams(missingParams));
      }
    }
    function formatMissingParams(missingParams) {
      return `Missing connection parameters: ${
        missingParams.join(", ")
      }. Connection parameters can be read from environment only if Deno is run with env permission (deno run --allow-env)`;
    }
    function parseOptionsFromDsn(connString) {
      const dsn = utils_ts_2.parseDsn(connString);
      if (dsn.driver !== "postgres") {
        throw new Error(`Supplied DSN has invalid driver: ${dsn.driver}.`);
      }
      return {
        ...dsn,
        port: dsn.port ? parseInt(dsn.port, 10) : undefined,
        applicationName: dsn.params.application_name,
      };
    }
    function createParams(config = {}) {
      if (typeof config === "string") {
        const dsn = parseOptionsFromDsn(config);
        return createParams(dsn);
      }
      const pgEnv = getPgEnv();
      const sources = [config, pgEnv, DEFAULT_OPTIONS];
      assertRequiredOptions(
        sources,
        ["database", "hostname", "port", "user", "applicationName"],
      );
      const params = {
        database: selectRequired(sources, "database"),
        hostname: selectRequired(sources, "hostname"),
        port: selectRequired(sources, "port"),
        applicationName: selectRequired(sources, "applicationName"),
        user: selectRequired(sources, "user"),
        password: select(sources, "password"),
      };
      if (isNaN(params.port)) {
        throw new ConnectionParamsError(`Invalid port ${params.port}`);
      }
      return params;
    }
    exports_92("createParams", createParams);
    return {
      setters: [
        function (utils_ts_2_1) {
          utils_ts_2 = utils_ts_2_1;
        },
      ],
      execute: function () {
        ConnectionParamsError = class ConnectionParamsError extends Error {
          constructor(message) {
            super(message);
            this.name = "ConnectionParamsError";
          }
        };
        DEFAULT_OPTIONS = {
          hostname: "127.0.0.1",
          port: 5432,
          applicationName: "deno_postgres",
        };
      },
    };
  },
);
System.register(
  "https://deno.land/x/postgres/deferred",
  ["https://deno.land/x/postgres/deps"],
  function (exports_93, context_93) {
    "use strict";
    var deps_ts_14, DeferredStack;
    var __moduleName = context_93 && context_93.id;
    return {
      setters: [
        function (deps_ts_14_1) {
          deps_ts_14 = deps_ts_14_1;
        },
      ],
      execute: function () {
        DeferredStack = class DeferredStack {
          constructor(max, ls, _creator) {
            this._creator = _creator;
            this._maxSize = max || 10;
            this._array = ls ? [...ls] : [];
            this._size = this._array.length;
            this._queue = [];
          }
          async pop() {
            if (this._array.length > 0) {
              return this._array.pop();
            } else if (this._size < this._maxSize && this._creator) {
              this._size++;
              return await this._creator();
            }
            const d = deps_ts_14.deferred();
            this._queue.push(d);
            await d;
            return this._array.pop();
          }
          push(value) {
            this._array.push(value);
            if (this._queue.length > 0) {
              const d = this._queue.shift();
              d.resolve();
            }
          }
          get size() {
            return this._size;
          }
          get available() {
            return this._array.length;
          }
        };
        exports_93("DeferredStack", DeferredStack);
      },
    };
  },
);
/*!
 * Substantial parts adapted from https://github.com/brianc/node-postgres
 * which is licensed as follows:
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2010 - 2019 Brian Carlson
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * 'Software'), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
System.register(
  "https://deno.land/x/postgres/connection",
  [
    "https://deno.land/x/postgres/deps",
    "https://deno.land/x/postgres/packet_writer",
    "https://deno.land/x/postgres/utils",
    "https://deno.land/x/postgres/packet_reader",
    "https://deno.land/x/postgres/query",
    "https://deno.land/x/postgres/error",
    "https://deno.land/x/postgres/deferred",
  ],
  function (exports_94, context_94) {
    "use strict";
    var deps_ts_15,
      packet_writer_ts_1,
      utils_ts_3,
      packet_reader_ts_1,
      query_ts_1,
      error_ts_1,
      deferred_ts_4,
      Format,
      TransactionStatus,
      Message,
      Column,
      RowDescription,
      Connection;
    var __moduleName = context_94 && context_94.id;
    return {
      setters: [
        function (deps_ts_15_1) {
          deps_ts_15 = deps_ts_15_1;
        },
        function (packet_writer_ts_1_1) {
          packet_writer_ts_1 = packet_writer_ts_1_1;
        },
        function (utils_ts_3_1) {
          utils_ts_3 = utils_ts_3_1;
        },
        function (packet_reader_ts_1_1) {
          packet_reader_ts_1 = packet_reader_ts_1_1;
        },
        function (query_ts_1_1) {
          query_ts_1 = query_ts_1_1;
        },
        function (error_ts_1_1) {
          error_ts_1 = error_ts_1_1;
        },
        function (deferred_ts_4_1) {
          deferred_ts_4 = deferred_ts_4_1;
        },
      ],
      execute: function () {
        (function (Format) {
          Format[Format["TEXT"] = 0] = "TEXT";
          Format[Format["BINARY"] = 1] = "BINARY";
        })(Format || (Format = {}));
        exports_94("Format", Format);
        (function (TransactionStatus) {
          TransactionStatus["Idle"] = "I";
          TransactionStatus["IdleInTransaction"] = "T";
          TransactionStatus["InFailedTransaction"] = "E";
        })(TransactionStatus || (TransactionStatus = {}));
        Message = class Message {
          constructor(type, byteCount, body) {
            this.type = type;
            this.byteCount = byteCount;
            this.body = body;
            this.reader = new packet_reader_ts_1.PacketReader(body);
          }
        };
        exports_94("Message", Message);
        Column = class Column {
          constructor(
            name,
            tableOid,
            index,
            typeOid,
            columnLength,
            typeModifier,
            format,
          ) {
            this.name = name;
            this.tableOid = tableOid;
            this.index = index;
            this.typeOid = typeOid;
            this.columnLength = columnLength;
            this.typeModifier = typeModifier;
            this.format = format;
          }
        };
        exports_94("Column", Column);
        RowDescription = class RowDescription {
          constructor(columnCount, columns) {
            this.columnCount = columnCount;
            this.columns = columns;
          }
        };
        exports_94("RowDescription", RowDescription);
        Connection = class Connection {
          constructor(connParams) {
            this.connParams = connParams;
            this.decoder = new TextDecoder();
            this.encoder = new TextEncoder();
            this._parameters = {};
            this._queryLock = new deferred_ts_4.DeferredStack(1, [undefined]);
          }
          /** Read single message sent by backend */
          async readMessage() {
            // TODO: reuse buffer instead of allocating new ones each for each read
            const header = new Uint8Array(5);
            await this.bufReader.readFull(header);
            const msgType = this.decoder.decode(header.slice(0, 1));
            const msgLength = utils_ts_3.readUInt32BE(header, 1) - 4;
            const msgBody = new Uint8Array(msgLength);
            await this.bufReader.readFull(msgBody);
            return new Message(msgType, msgLength, msgBody);
          }
          async _sendStartupMessage() {
            const writer = this.packetWriter;
            writer.clear();
            // protocol version - 3.0, written as
            writer.addInt16(3).addInt16(0);
            const connParams = this.connParams;
            // TODO: recognize other parameters
            writer.addCString("user").addCString(connParams.user);
            writer.addCString("database").addCString(connParams.database);
            writer.addCString("application_name").addCString(
              connParams.applicationName,
            );
            // eplicitly set utf-8 encoding
            writer.addCString("client_encoding").addCString("'utf-8'");
            // terminator after all parameters were writter
            writer.addCString("");
            const bodyBuffer = writer.flush();
            const bodyLength = bodyBuffer.length + 4;
            writer.clear();
            const finalBuffer = writer
              .addInt32(bodyLength)
              .add(bodyBuffer)
              .join();
            await this.bufWriter.write(finalBuffer);
          }
          async startup() {
            const { port, hostname } = this.connParams;
            this.conn = await Deno.connect({ port, hostname });
            this.bufReader = new deps_ts_15.BufReader(this.conn);
            this.bufWriter = new deps_ts_15.BufWriter(this.conn);
            this.packetWriter = new packet_writer_ts_1.PacketWriter();
            await this._sendStartupMessage();
            await this.bufWriter.flush();
            let msg;
            msg = await this.readMessage();
            await this.handleAuth(msg);
            while (true) {
              msg = await this.readMessage();
              switch (msg.type) {
                // backend key data
                case "K":
                  this._processBackendKeyData(msg);
                  break;
                // parameter status
                case "S":
                  this._processParameterStatus(msg);
                  break;
                // ready for query
                case "Z":
                  this._processReadyForQuery(msg);
                  return;
                default:
                  throw new Error(`Unknown response for startup: ${msg.type}`);
              }
            }
          }
          async handleAuth(msg) {
            const code = msg.reader.readInt32();
            switch (code) {
              case 0:
                // pass
                break;
              case 3:
                // cleartext password
                await this._authCleartext();
                await this._readAuthResponse();
                break;
              case 5: {
                // md5 password
                const salt = msg.reader.readBytes(4);
                await this._authMd5(salt);
                await this._readAuthResponse();
                break;
              }
              default:
                throw new Error(`Unknown auth message code ${code}`);
            }
          }
          async _readAuthResponse() {
            const msg = await this.readMessage();
            if (msg.type === "E") {
              throw error_ts_1.parseError(msg);
            } else if (msg.type !== "R") {
              throw new Error(`Unexpected auth response: ${msg.type}.`);
            }
            const responseCode = msg.reader.readInt32();
            if (responseCode !== 0) {
              throw new Error(
                `Unexpected auth response code: ${responseCode}.`,
              );
            }
          }
          async _authCleartext() {
            this.packetWriter.clear();
            const password = this.connParams.password || "";
            const buffer = this.packetWriter.addCString(password).flush(0x70);
            await this.bufWriter.write(buffer);
            await this.bufWriter.flush();
          }
          async _authMd5(salt) {
            this.packetWriter.clear();
            if (!this.connParams.password) {
              throw new Error(
                "Auth Error: attempting MD5 auth with password unset",
              );
            }
            const password = utils_ts_3.hashMd5Password(
              this.connParams.password,
              this.connParams.user,
              salt,
            );
            const buffer = this.packetWriter.addCString(password).flush(0x70);
            await this.bufWriter.write(buffer);
            await this.bufWriter.flush();
          }
          _processBackendKeyData(msg) {
            this._pid = msg.reader.readInt32();
            this._secretKey = msg.reader.readInt32();
          }
          _processParameterStatus(msg) {
            // TODO: should we save all parameters?
            const key = msg.reader.readCString();
            const value = msg.reader.readCString();
            this._parameters[key] = value;
          }
          _processReadyForQuery(msg) {
            const txStatus = msg.reader.readByte();
            this._transactionStatus = String.fromCharCode(txStatus);
          }
          async _readReadyForQuery() {
            const msg = await this.readMessage();
            if (msg.type !== "Z") {
              throw new Error(
                `Unexpected message type: ${msg.type}, expected "Z" (ReadyForQuery)`,
              );
            }
            this._processReadyForQuery(msg);
          }
          async _simpleQuery(query) {
            this.packetWriter.clear();
            const buffer = this.packetWriter.addCString(query.text).flush(0x51);
            await this.bufWriter.write(buffer);
            await this.bufWriter.flush();
            const result = query.result;
            let msg;
            msg = await this.readMessage();
            switch (msg.type) {
              // row description
              case "T":
                result.handleRowDescription(this._processRowDescription(msg));
                break;
              // no data
              case "n":
                break;
              // error response
              case "E":
                await this._processError(msg);
                break;
              // notice response
              case "N":
                // TODO:
                console.log("TODO: handle notice");
                break;
              // command complete
              // TODO: this is duplicated in next loop
              case "C": {
                const commandTag = this._readCommandTag(msg);
                result.handleCommandComplete(commandTag);
                result.done();
                break;
              }
              default:
                throw new Error(`Unexpected frame: ${msg.type}`);
            }
            while (true) {
              msg = await this.readMessage();
              switch (msg.type) {
                // data row
                case "D": {
                  // this is actually packet read
                  const foo = this._readDataRow(msg);
                  result.handleDataRow(foo);
                  break;
                }
                // command complete
                case "C": {
                  const commandTag = this._readCommandTag(msg);
                  result.handleCommandComplete(commandTag);
                  result.done();
                  break;
                }
                // ready for query
                case "Z":
                  this._processReadyForQuery(msg);
                  return result;
                // error response
                case "E":
                  await this._processError(msg);
                  break;
                default:
                  throw new Error(`Unexpected frame: ${msg.type}`);
              }
            }
          }
          async _sendPrepareMessage(query) {
            this.packetWriter.clear();
            const buffer = this.packetWriter
              .addCString("") // TODO: handle named queries (config.name)
              .addCString(query.text)
              .addInt16(0)
              .flush(0x50);
            await this.bufWriter.write(buffer);
          }
          async _sendBindMessage(query) {
            this.packetWriter.clear();
            const hasBinaryArgs = query.args.reduce((prev, curr) => {
              return prev || curr instanceof Uint8Array;
            }, false);
            // bind statement
            this.packetWriter.clear();
            this.packetWriter
              .addCString("") // TODO: unnamed portal
              .addCString(""); // TODO: unnamed prepared statement
            if (hasBinaryArgs) {
              this.packetWriter.addInt16(query.args.length);
              query.args.forEach((arg) => {
                this.packetWriter.addInt16(arg instanceof Uint8Array ? 1 : 0);
              });
            } else {
              this.packetWriter.addInt16(0);
            }
            this.packetWriter.addInt16(query.args.length);
            query.args.forEach((arg) => {
              if (arg === null || typeof arg === "undefined") {
                this.packetWriter.addInt32(-1);
              } else if (arg instanceof Uint8Array) {
                this.packetWriter.addInt32(arg.length);
                this.packetWriter.add(arg);
              } else {
                const byteLength = this.encoder.encode(arg).length;
                this.packetWriter.addInt32(byteLength);
                this.packetWriter.addString(arg);
              }
            });
            this.packetWriter.addInt16(0);
            const buffer = this.packetWriter.flush(0x42);
            await this.bufWriter.write(buffer);
          }
          async _sendDescribeMessage() {
            this.packetWriter.clear();
            const buffer = this.packetWriter.addCString("P").flush(0x44);
            await this.bufWriter.write(buffer);
          }
          async _sendExecuteMessage() {
            this.packetWriter.clear();
            const buffer = this.packetWriter
              .addCString("") // unnamed portal
              .addInt32(0)
              .flush(0x45);
            await this.bufWriter.write(buffer);
          }
          async _sendFlushMessage() {
            this.packetWriter.clear();
            const buffer = this.packetWriter.flush(0x48);
            await this.bufWriter.write(buffer);
          }
          async _sendSyncMessage() {
            this.packetWriter.clear();
            const buffer = this.packetWriter.flush(0x53);
            await this.bufWriter.write(buffer);
          }
          async _processError(msg) {
            const error = error_ts_1.parseError(msg);
            await this._readReadyForQuery();
            throw error;
          }
          async _readParseComplete() {
            const msg = await this.readMessage();
            switch (msg.type) {
              // parse completed
              case "1":
                // TODO: add to already parsed queries if
                // query has name, so it's not parsed again
                break;
              // error response
              case "E":
                await this._processError(msg);
                break;
              default:
                throw new Error(`Unexpected frame: ${msg.type}`);
            }
          }
          async _readBindComplete() {
            const msg = await this.readMessage();
            switch (msg.type) {
              // bind completed
              case "2":
                // no-op
                break;
              // error response
              case "E":
                await this._processError(msg);
                break;
              default:
                throw new Error(`Unexpected frame: ${msg.type}`);
            }
          }
          // TODO: I believe error handling here is not correct, shouldn't 'sync' message be
          //  sent after error response is received in prepared statements?
          async _preparedQuery(query) {
            await this._sendPrepareMessage(query);
            await this._sendBindMessage(query);
            await this._sendDescribeMessage();
            await this._sendExecuteMessage();
            await this._sendSyncMessage();
            // send all messages to backend
            await this.bufWriter.flush();
            await this._readParseComplete();
            await this._readBindComplete();
            const result = query.result;
            let msg;
            msg = await this.readMessage();
            switch (msg.type) {
              // row description
              case "T": {
                const rowDescription = this._processRowDescription(msg);
                result.handleRowDescription(rowDescription);
                break;
              }
              // no data
              case "n":
                break;
              // error
              case "E":
                await this._processError(msg);
                break;
              default:
                throw new Error(`Unexpected frame: ${msg.type}`);
            }
            outerLoop:
            while (true) {
              msg = await this.readMessage();
              switch (msg.type) {
                // data row
                case "D": {
                  // this is actually packet read
                  const rawDataRow = this._readDataRow(msg);
                  result.handleDataRow(rawDataRow);
                  break;
                }
                // command complete
                case "C": {
                  const commandTag = this._readCommandTag(msg);
                  result.handleCommandComplete(commandTag);
                  result.done();
                  break outerLoop;
                }
                // error response
                case "E":
                  await this._processError(msg);
                  break;
                default:
                  throw new Error(`Unexpected frame: ${msg.type}`);
              }
            }
            await this._readReadyForQuery();
            return result;
          }
          async query(query) {
            await this._queryLock.pop();
            try {
              if (query.args.length === 0) {
                return await this._simpleQuery(query);
              } else {
                return await this._preparedQuery(query);
              }
            } finally {
              this._queryLock.push(undefined);
            }
          }
          _processRowDescription(msg) {
            const columnCount = msg.reader.readInt16();
            const columns = [];
            for (let i = 0; i < columnCount; i++) {
              // TODO: if one of columns has 'format' == 'binary',
              //  all of them will be in same format?
              const column = new Column(
                msg.reader.readCString(), // name
                msg.reader.readInt32(), // tableOid
                msg.reader.readInt16(), // index
                msg.reader.readInt32(), // dataTypeOid
                msg.reader.readInt16(), // column
                msg.reader.readInt32(), // typeModifier
                msg.reader.readInt16(),
              );
              columns.push(column);
            }
            return new RowDescription(columnCount, columns);
          }
          // deno-lint-ignore no-explicit-any
          _readDataRow(msg) {
            const fieldCount = msg.reader.readInt16();
            const row = [];
            for (let i = 0; i < fieldCount; i++) {
              const colLength = msg.reader.readInt32();
              if (colLength == -1) {
                row.push(null);
                continue;
              }
              // reading raw bytes here, they will be properly parsed later
              row.push(msg.reader.readBytes(colLength));
            }
            return row;
          }
          _readCommandTag(msg) {
            return msg.reader.readString(msg.byteCount);
          }
          async initSQL() {
            const config = { text: "select 1;", args: [] };
            const query = new query_ts_1.Query(config);
            await this.query(query);
          }
          async end() {
            const terminationMessage = new Uint8Array(
              [0x58, 0x00, 0x00, 0x00, 0x04],
            );
            await this.bufWriter.write(terminationMessage);
            await this.bufWriter.flush();
            this.conn.close();
            delete this.conn;
            delete this.bufReader;
            delete this.bufWriter;
            delete this.packetWriter;
          }
        };
        exports_94("Connection", Connection);
      },
    };
  },
);
System.register(
  "https://deno.land/x/postgres/client",
  [
    "https://deno.land/x/postgres/connection",
    "https://deno.land/x/postgres/connection_params",
    "https://deno.land/x/postgres/query",
  ],
  function (exports_95, context_95) {
    "use strict";
    var connection_ts_2, connection_params_ts_1, query_ts_2, Client, PoolClient;
    var __moduleName = context_95 && context_95.id;
    return {
      setters: [
        function (connection_ts_2_1) {
          connection_ts_2 = connection_ts_2_1;
        },
        function (connection_params_ts_1_1) {
          connection_params_ts_1 = connection_params_ts_1_1;
        },
        function (query_ts_2_1) {
          query_ts_2 = query_ts_2_1;
        },
      ],
      execute: function () {
        Client = class Client {
          constructor(config) {
            // Support `using` module
            this._aenter = this.connect;
            this._aexit = this.end;
            const connectionParams = connection_params_ts_1.createParams(
              config,
            );
            this._connection = new connection_ts_2.Connection(connectionParams);
          }
          async connect() {
            await this._connection.startup();
            await this._connection.initSQL();
          }
          // TODO: can we use more specific type for args?
          async query(
            text,
            // deno-lint-ignore no-explicit-any
            ...args
          ) {
            const query = new query_ts_2.Query(text, ...args);
            return await this._connection.query(query);
          }
          async multiQuery(queries) {
            const result = [];
            for (const query of queries) {
              result.push(await this.query(query));
            }
            return result;
          }
          async end() {
            await this._connection.end();
          }
        };
        exports_95("Client", Client);
        PoolClient = class PoolClient {
          constructor(connection, releaseCallback) {
            this._connection = connection;
            this._releaseCallback = releaseCallback;
          }
          async query(
            text,
            // deno-lint-ignore no-explicit-any
            ...args
          ) {
            const query = new query_ts_2.Query(text, ...args);
            return await this._connection.query(query);
          }
          async release() {
            await this._releaseCallback();
          }
        };
        exports_95("PoolClient", PoolClient);
      },
    };
  },
);
System.register(
  "https://deno.land/x/postgres/pool",
  [
    "https://deno.land/x/postgres/client",
    "https://deno.land/x/postgres/connection",
    "https://deno.land/x/postgres/connection_params",
    "https://deno.land/x/postgres/deferred",
    "https://deno.land/x/postgres/query",
  ],
  function (exports_96, context_96) {
    "use strict";
    var client_ts_1,
      connection_ts_3,
      connection_params_ts_2,
      deferred_ts_5,
      query_ts_3,
      Pool;
    var __moduleName = context_96 && context_96.id;
    return {
      setters: [
        function (client_ts_1_1) {
          client_ts_1 = client_ts_1_1;
        },
        function (connection_ts_3_1) {
          connection_ts_3 = connection_ts_3_1;
        },
        function (connection_params_ts_2_1) {
          connection_params_ts_2 = connection_params_ts_2_1;
        },
        function (deferred_ts_5_1) {
          deferred_ts_5 = deferred_ts_5_1;
        },
        function (query_ts_3_1) {
          query_ts_3 = query_ts_3_1;
        },
      ],
      execute: function () {
        Pool = class Pool {
          constructor(connectionParams, maxSize, lazy) {
            // Support `using` module
            this._aenter = () => {};
            this._aexit = this.end;
            this._connectionParams = connection_params_ts_2.createParams(
              connectionParams,
            );
            this._maxSize = maxSize;
            this._lazy = !!lazy;
            this._ready = this._startup();
          }
          async _createConnection() {
            const connection = new connection_ts_3.Connection(
              this._connectionParams,
            );
            await connection.startup();
            await connection.initSQL();
            return connection;
          }
          /** pool max size */
          get maxSize() {
            return this._maxSize;
          }
          /** number of connections created */
          get size() {
            if (this._availableConnections == null) {
              return 0;
            }
            return this._availableConnections.size;
          }
          /** number of available connections */
          get available() {
            if (this._availableConnections == null) {
              return 0;
            }
            return this._availableConnections.available;
          }
          async _startup() {
            const initSize = this._lazy ? 1 : this._maxSize;
            const connecting = [...Array(initSize)].map(async () =>
              await this._createConnection()
            );
            this._connections = await Promise.all(connecting);
            this._availableConnections = new deferred_ts_5.DeferredStack(
              this._maxSize,
              this._connections,
              this._createConnection.bind(this),
            );
          }
          async _execute(query) {
            await this._ready;
            const connection = await this._availableConnections.pop();
            try {
              const result = await connection.query(query);
              return result;
            } catch (error) {
              throw error;
            } finally {
              this._availableConnections.push(connection);
            }
          }
          async connect() {
            await this._ready;
            const connection = await this._availableConnections.pop();
            const release = () => this._availableConnections.push(connection);
            return new client_ts_1.PoolClient(connection, release);
          }
          // TODO: can we use more specific type for args?
          async query(
            text,
            // deno-lint-ignore no-explicit-any
            ...args
          ) {
            const query = new query_ts_3.Query(text, ...args);
            return await this._execute(query);
          }
          async end() {
            await this._ready;
            while (this.available > 0) {
              const conn = await this._availableConnections.pop();
              await conn.end();
            }
          }
        };
        exports_96("Pool", Pool);
      },
    };
  },
);
System.register(
  "https://deno.land/x/postgres/mod",
  [
    "https://deno.land/x/postgres/client",
    "https://deno.land/x/postgres/error",
    "https://deno.land/x/postgres/pool",
  ],
  function (exports_97, context_97) {
    "use strict";
    var __moduleName = context_97 && context_97.id;
    return {
      setters: [
        function (client_ts_2_1) {
          exports_97({
            "Client": client_ts_2_1["Client"],
          });
        },
        function (error_ts_2_1) {
          exports_97({
            "PostgresError": error_ts_2_1["PostgresError"],
          });
        },
        function (pool_ts_1_1) {
          exports_97({
            "Pool": pool_ts_1_1["Pool"],
          });
        },
      ],
      execute: function () {
      },
    };
  },
);
System.register(
  "https://deno.land/std/uuid/_common",
  [],
  function (exports_98, context_98) {
    "use strict";
    var __moduleName = context_98 && context_98.id;
    // Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
    function bytesToUuid(bytes) {
      const bits = [...bytes].map((bit) => {
        const s = bit.toString(16);
        return bit < 0x10 ? "0" + s : s;
      });
      return [
        ...bits.slice(0, 4),
        "-",
        ...bits.slice(4, 6),
        "-",
        ...bits.slice(6, 8),
        "-",
        ...bits.slice(8, 10),
        "-",
        ...bits.slice(10, 16),
      ].join("");
    }
    exports_98("bytesToUuid", bytesToUuid);
    function uuidToBytes(uuid) {
      const bytes = [];
      uuid.replace(/[a-fA-F0-9]{2}/g, (hex) => {
        bytes.push(parseInt(hex, 16));
        return "";
      });
      return bytes;
    }
    exports_98("uuidToBytes", uuidToBytes);
    function stringToBytes(str) {
      str = unescape(encodeURIComponent(str));
      const bytes = new Array(str.length);
      for (let i = 0; i < str.length; i++) {
        bytes[i] = str.charCodeAt(i);
      }
      return bytes;
    }
    exports_98("stringToBytes", stringToBytes);
    function createBuffer(content) {
      const arrayBuffer = new ArrayBuffer(content.length);
      const uint8Array = new Uint8Array(arrayBuffer);
      for (let i = 0; i < content.length; i++) {
        uint8Array[i] = content[i];
      }
      return arrayBuffer;
    }
    exports_98("createBuffer", createBuffer);
    return {
      setters: [],
      execute: function () {
      },
    };
  },
);
// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
System.register(
  "https://deno.land/std/uuid/v1",
  ["https://deno.land/std/uuid/_common"],
  function (exports_99, context_99) {
    "use strict";
    var _common_ts_1, UUID_RE, _nodeId, _clockseq, _lastMSecs, _lastNSecs;
    var __moduleName = context_99 && context_99.id;
    function validate(id) {
      return UUID_RE.test(id);
    }
    exports_99("validate", validate);
    function generate(options, buf, offset) {
      let i = (buf && offset) || 0;
      const b = buf || [];
      options = options || {};
      let node = options.node || _nodeId;
      let clockseq = options.clockseq !== undefined ? options.clockseq
      : _clockseq;
      if (node == null || clockseq == null) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const seedBytes = options.random ||
          options.rng ||
          crypto.getRandomValues(new Uint8Array(16));
        if (node == null) {
          node = _nodeId = [
            seedBytes[0] | 0x01,
            seedBytes[1],
            seedBytes[2],
            seedBytes[3],
            seedBytes[4],
            seedBytes[5],
          ];
        }
        if (clockseq == null) {
          clockseq = _clockseq = ((seedBytes[6] << 8) | seedBytes[7]) & 0x3fff;
        }
      }
      let msecs = options.msecs !== undefined
        ? options.msecs
        : new Date().getTime();
      let nsecs = options.nsecs !== undefined ? options.nsecs : _lastNSecs + 1;
      const dt = msecs - _lastMSecs + (nsecs - _lastNSecs) / 10000;
      if (dt < 0 && options.clockseq === undefined) {
        clockseq = (clockseq + 1) & 0x3fff;
      }
      if ((dt < 0 || msecs > _lastMSecs) && options.nsecs === undefined) {
        nsecs = 0;
      }
      if (nsecs >= 10000) {
        throw new Error("Can't create more than 10M uuids/sec");
      }
      _lastMSecs = msecs;
      _lastNSecs = nsecs;
      _clockseq = clockseq;
      msecs += 12219292800000;
      const tl = ((msecs & 0xfffffff) * 10000 + nsecs) % 0x100000000;
      b[i++] = (tl >>> 24) & 0xff;
      b[i++] = (tl >>> 16) & 0xff;
      b[i++] = (tl >>> 8) & 0xff;
      b[i++] = tl & 0xff;
      const tmh = ((msecs / 0x100000000) * 10000) & 0xfffffff;
      b[i++] = (tmh >>> 8) & 0xff;
      b[i++] = tmh & 0xff;
      b[i++] = ((tmh >>> 24) & 0xf) | 0x10;
      b[i++] = (tmh >>> 16) & 0xff;
      b[i++] = (clockseq >>> 8) | 0x80;
      b[i++] = clockseq & 0xff;
      for (let n = 0; n < 6; ++n) {
        b[i + n] = node[n];
      }
      return buf ? buf : _common_ts_1.bytesToUuid(b);
    }
    exports_99("generate", generate);
    return {
      setters: [
        function (_common_ts_1_1) {
          _common_ts_1 = _common_ts_1_1;
        },
      ],
      execute: function () {
        UUID_RE = new RegExp(
          "^[0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
          "i",
        );
        _lastMSecs = 0;
        _lastNSecs = 0;
      },
    };
  },
);
// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
System.register(
  "https://deno.land/std/uuid/v4",
  ["https://deno.land/std/uuid/_common"],
  function (exports_100, context_100) {
    "use strict";
    var _common_ts_2, UUID_RE;
    var __moduleName = context_100 && context_100.id;
    function validate(id) {
      return UUID_RE.test(id);
    }
    exports_100("validate", validate);
    function generate() {
      const rnds = crypto.getRandomValues(new Uint8Array(16));
      rnds[6] = (rnds[6] & 0x0f) | 0x40; // Version 4
      rnds[8] = (rnds[8] & 0x3f) | 0x80; // Variant 10
      return _common_ts_2.bytesToUuid(rnds);
    }
    exports_100("generate", generate);
    return {
      setters: [
        function (_common_ts_2_1) {
          _common_ts_2 = _common_ts_2_1;
        },
      ],
      execute: function () {
        UUID_RE = new RegExp(
          "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
          "i",
        );
      },
    };
  },
);
/*
 * [js-sha1]{@link https://github.com/emn178/js-sha1}
 *
 * @version 0.6.0
 * @author Chen, Yi-Cyuan [emn178@gmail.com]
 * @copyright Chen, Yi-Cyuan 2014-2017
 * @license MIT
 */
System.register(
  "https://deno.land/std/hash/sha1",
  [],
  function (exports_101, context_101) {
    "use strict";
    var HEX_CHARS, EXTRA, SHIFT, blocks, Sha1;
    var __moduleName = context_101 && context_101.id;
    return {
      setters: [],
      execute: function () {
        HEX_CHARS = "0123456789abcdef".split("");
        EXTRA = [-2147483648, 8388608, 32768, 128];
        SHIFT = [24, 16, 8, 0];
        blocks = [];
        Sha1 = class Sha1 {
          constructor(sharedMemory = false) {
            this.#h0 = 0x67452301;
            this.#h1 = 0xefcdab89;
            this.#h2 = 0x98badcfe;
            this.#h3 = 0x10325476;
            this.#h4 = 0xc3d2e1f0;
            this.#lastByteIndex = 0;
            if (sharedMemory) {
              blocks[0] = blocks[16] = blocks[1] = blocks[2] = blocks[3] =
                blocks[4] = blocks[5] = blocks[6] = blocks[7] = blocks[8] =
                  blocks[9] = blocks[10] = blocks[11] = blocks[12] =
                    blocks[13] = blocks[14] = blocks[15] = 0;
              this.#blocks = blocks;
            } else {
              this.#blocks = [
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
              ];
            }
            this.#h0 = 0x67452301;
            this.#h1 = 0xefcdab89;
            this.#h2 = 0x98badcfe;
            this.#h3 = 0x10325476;
            this.#h4 = 0xc3d2e1f0;
            this.#block = this.#start = this.#bytes = this.#hBytes = 0;
            this.#finalized = this.#hashed = false;
          }
          #blocks;
          #block;
          #start;
          #bytes;
          #hBytes;
          #finalized;
          #hashed;
          #h0;
          #h1;
          #h2;
          #h3;
          #h4;
          #lastByteIndex;
          update(message) {
            if (this.#finalized) {
              return this;
            }
            let msg;
            if (message instanceof ArrayBuffer) {
              msg = new Uint8Array(message);
            } else {
              msg = message;
            }
            let index = 0;
            const length = msg.length;
            const blocks = this.#blocks;
            while (index < length) {
              let i;
              if (this.#hashed) {
                this.#hashed = false;
                blocks[0] = this.#block;
                blocks[16] = blocks[1] = blocks[2] = blocks[3] = blocks[4] =
                  blocks[5] = blocks[6] = blocks[7] = blocks[8] = blocks[9] =
                    blocks[10] = blocks[11] = blocks[12] = blocks[13] =
                      blocks[14] = blocks[15] = 0;
              }
              if (typeof msg !== "string") {
                for (i = this.#start; index < length && i < 64; ++index) {
                  blocks[i >> 2] |= msg[index] << SHIFT[i++ & 3];
                }
              } else {
                for (i = this.#start; index < length && i < 64; ++index) {
                  let code = msg.charCodeAt(index);
                  if (code < 0x80) {
                    blocks[i >> 2] |= code << SHIFT[i++ & 3];
                  } else if (code < 0x800) {
                    blocks[i >> 2] |= (0xc0 | (code >> 6)) << SHIFT[i++ & 3];
                    blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
                  } else if (code < 0xd800 || code >= 0xe000) {
                    blocks[i >> 2] |= (0xe0 | (code >> 12)) << SHIFT[i++ & 3];
                    blocks[i >> 2] |= (0x80 | ((code >> 6) & 0x3f)) <<
                      SHIFT[i++ & 3];
                    blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
                  } else {
                    code = 0x10000 +
                      (((code & 0x3ff) << 10) |
                        (msg.charCodeAt(++index) & 0x3ff));
                    blocks[i >> 2] |= (0xf0 | (code >> 18)) << SHIFT[i++ & 3];
                    blocks[i >> 2] |= (0x80 | ((code >> 12) & 0x3f)) <<
                      SHIFT[i++ & 3];
                    blocks[i >> 2] |= (0x80 | ((code >> 6) & 0x3f)) <<
                      SHIFT[i++ & 3];
                    blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
                  }
                }
              }
              this.#lastByteIndex = i;
              this.#bytes += i - this.#start;
              if (i >= 64) {
                this.#block = blocks[16];
                this.#start = i - 64;
                this.hash();
                this.#hashed = true;
              } else {
                this.#start = i;
              }
            }
            if (this.#bytes > 4294967295) {
              this.#hBytes += (this.#bytes / 4294967296) >>> 0;
              this.#bytes = this.#bytes >>> 0;
            }
            return this;
          }
          finalize() {
            if (this.#finalized) {
              return;
            }
            this.#finalized = true;
            const blocks = this.#blocks;
            const i = this.#lastByteIndex;
            blocks[16] = this.#block;
            blocks[i >> 2] |= EXTRA[i & 3];
            this.#block = blocks[16];
            if (i >= 56) {
              if (!this.#hashed) {
                this.hash();
              }
              blocks[0] = this.#block;
              blocks[16] = blocks[1] = blocks[2] = blocks[3] = blocks[4] =
                blocks[5] = blocks[6] = blocks[7] = blocks[8] = blocks[9] =
                  blocks[10] = blocks[11] = blocks[12] = blocks[13] =
                    blocks[14] = blocks[15] = 0;
            }
            blocks[14] = (this.#hBytes << 3) | (this.#bytes >>> 29);
            blocks[15] = this.#bytes << 3;
            this.hash();
          }
          hash() {
            let a = this.#h0;
            let b = this.#h1;
            let c = this.#h2;
            let d = this.#h3;
            let e = this.#h4;
            let f;
            let j;
            let t;
            const blocks = this.#blocks;
            for (j = 16; j < 80; ++j) {
              t = blocks[j - 3] ^ blocks[j - 8] ^ blocks[j - 14] ^
                blocks[j - 16];
              blocks[j] = (t << 1) | (t >>> 31);
            }
            for (j = 0; j < 20; j += 5) {
              f = (b & c) | (~b & d);
              t = (a << 5) | (a >>> 27);
              e = (t + f + e + 1518500249 + blocks[j]) >>> 0;
              b = (b << 30) | (b >>> 2);
              f = (a & b) | (~a & c);
              t = (e << 5) | (e >>> 27);
              d = (t + f + d + 1518500249 + blocks[j + 1]) >>> 0;
              a = (a << 30) | (a >>> 2);
              f = (e & a) | (~e & b);
              t = (d << 5) | (d >>> 27);
              c = (t + f + c + 1518500249 + blocks[j + 2]) >>> 0;
              e = (e << 30) | (e >>> 2);
              f = (d & e) | (~d & a);
              t = (c << 5) | (c >>> 27);
              b = (t + f + b + 1518500249 + blocks[j + 3]) >>> 0;
              d = (d << 30) | (d >>> 2);
              f = (c & d) | (~c & e);
              t = (b << 5) | (b >>> 27);
              a = (t + f + a + 1518500249 + blocks[j + 4]) >>> 0;
              c = (c << 30) | (c >>> 2);
            }
            for (; j < 40; j += 5) {
              f = b ^ c ^ d;
              t = (a << 5) | (a >>> 27);
              e = (t + f + e + 1859775393 + blocks[j]) >>> 0;
              b = (b << 30) | (b >>> 2);
              f = a ^ b ^ c;
              t = (e << 5) | (e >>> 27);
              d = (t + f + d + 1859775393 + blocks[j + 1]) >>> 0;
              a = (a << 30) | (a >>> 2);
              f = e ^ a ^ b;
              t = (d << 5) | (d >>> 27);
              c = (t + f + c + 1859775393 + blocks[j + 2]) >>> 0;
              e = (e << 30) | (e >>> 2);
              f = d ^ e ^ a;
              t = (c << 5) | (c >>> 27);
              b = (t + f + b + 1859775393 + blocks[j + 3]) >>> 0;
              d = (d << 30) | (d >>> 2);
              f = c ^ d ^ e;
              t = (b << 5) | (b >>> 27);
              a = (t + f + a + 1859775393 + blocks[j + 4]) >>> 0;
              c = (c << 30) | (c >>> 2);
            }
            for (; j < 60; j += 5) {
              f = (b & c) | (b & d) | (c & d);
              t = (a << 5) | (a >>> 27);
              e = (t + f + e - 1894007588 + blocks[j]) >>> 0;
              b = (b << 30) | (b >>> 2);
              f = (a & b) | (a & c) | (b & c);
              t = (e << 5) | (e >>> 27);
              d = (t + f + d - 1894007588 + blocks[j + 1]) >>> 0;
              a = (a << 30) | (a >>> 2);
              f = (e & a) | (e & b) | (a & b);
              t = (d << 5) | (d >>> 27);
              c = (t + f + c - 1894007588 + blocks[j + 2]) >>> 0;
              e = (e << 30) | (e >>> 2);
              f = (d & e) | (d & a) | (e & a);
              t = (c << 5) | (c >>> 27);
              b = (t + f + b - 1894007588 + blocks[j + 3]) >>> 0;
              d = (d << 30) | (d >>> 2);
              f = (c & d) | (c & e) | (d & e);
              t = (b << 5) | (b >>> 27);
              a = (t + f + a - 1894007588 + blocks[j + 4]) >>> 0;
              c = (c << 30) | (c >>> 2);
            }
            for (; j < 80; j += 5) {
              f = b ^ c ^ d;
              t = (a << 5) | (a >>> 27);
              e = (t + f + e - 899497514 + blocks[j]) >>> 0;
              b = (b << 30) | (b >>> 2);
              f = a ^ b ^ c;
              t = (e << 5) | (e >>> 27);
              d = (t + f + d - 899497514 + blocks[j + 1]) >>> 0;
              a = (a << 30) | (a >>> 2);
              f = e ^ a ^ b;
              t = (d << 5) | (d >>> 27);
              c = (t + f + c - 899497514 + blocks[j + 2]) >>> 0;
              e = (e << 30) | (e >>> 2);
              f = d ^ e ^ a;
              t = (c << 5) | (c >>> 27);
              b = (t + f + b - 899497514 + blocks[j + 3]) >>> 0;
              d = (d << 30) | (d >>> 2);
              f = c ^ d ^ e;
              t = (b << 5) | (b >>> 27);
              a = (t + f + a - 899497514 + blocks[j + 4]) >>> 0;
              c = (c << 30) | (c >>> 2);
            }
            this.#h0 = (this.#h0 + a) >>> 0;
            this.#h1 = (this.#h1 + b) >>> 0;
            this.#h2 = (this.#h2 + c) >>> 0;
            this.#h3 = (this.#h3 + d) >>> 0;
            this.#h4 = (this.#h4 + e) >>> 0;
          }
          hex() {
            this.finalize();
            const h0 = this.#h0;
            const h1 = this.#h1;
            const h2 = this.#h2;
            const h3 = this.#h3;
            const h4 = this.#h4;
            return (HEX_CHARS[(h0 >> 28) & 0x0f] +
              HEX_CHARS[(h0 >> 24) & 0x0f] +
              HEX_CHARS[(h0 >> 20) & 0x0f] +
              HEX_CHARS[(h0 >> 16) & 0x0f] +
              HEX_CHARS[(h0 >> 12) & 0x0f] +
              HEX_CHARS[(h0 >> 8) & 0x0f] +
              HEX_CHARS[(h0 >> 4) & 0x0f] +
              HEX_CHARS[h0 & 0x0f] +
              HEX_CHARS[(h1 >> 28) & 0x0f] +
              HEX_CHARS[(h1 >> 24) & 0x0f] +
              HEX_CHARS[(h1 >> 20) & 0x0f] +
              HEX_CHARS[(h1 >> 16) & 0x0f] +
              HEX_CHARS[(h1 >> 12) & 0x0f] +
              HEX_CHARS[(h1 >> 8) & 0x0f] +
              HEX_CHARS[(h1 >> 4) & 0x0f] +
              HEX_CHARS[h1 & 0x0f] +
              HEX_CHARS[(h2 >> 28) & 0x0f] +
              HEX_CHARS[(h2 >> 24) & 0x0f] +
              HEX_CHARS[(h2 >> 20) & 0x0f] +
              HEX_CHARS[(h2 >> 16) & 0x0f] +
              HEX_CHARS[(h2 >> 12) & 0x0f] +
              HEX_CHARS[(h2 >> 8) & 0x0f] +
              HEX_CHARS[(h2 >> 4) & 0x0f] +
              HEX_CHARS[h2 & 0x0f] +
              HEX_CHARS[(h3 >> 28) & 0x0f] +
              HEX_CHARS[(h3 >> 24) & 0x0f] +
              HEX_CHARS[(h3 >> 20) & 0x0f] +
              HEX_CHARS[(h3 >> 16) & 0x0f] +
              HEX_CHARS[(h3 >> 12) & 0x0f] +
              HEX_CHARS[(h3 >> 8) & 0x0f] +
              HEX_CHARS[(h3 >> 4) & 0x0f] +
              HEX_CHARS[h3 & 0x0f] +
              HEX_CHARS[(h4 >> 28) & 0x0f] +
              HEX_CHARS[(h4 >> 24) & 0x0f] +
              HEX_CHARS[(h4 >> 20) & 0x0f] +
              HEX_CHARS[(h4 >> 16) & 0x0f] +
              HEX_CHARS[(h4 >> 12) & 0x0f] +
              HEX_CHARS[(h4 >> 8) & 0x0f] +
              HEX_CHARS[(h4 >> 4) & 0x0f] +
              HEX_CHARS[h4 & 0x0f]);
          }
          toString() {
            return this.hex();
          }
          digest() {
            this.finalize();
            const h0 = this.#h0;
            const h1 = this.#h1;
            const h2 = this.#h2;
            const h3 = this.#h3;
            const h4 = this.#h4;
            return [
              (h0 >> 24) & 0xff,
              (h0 >> 16) & 0xff,
              (h0 >> 8) & 0xff,
              h0 & 0xff,
              (h1 >> 24) & 0xff,
              (h1 >> 16) & 0xff,
              (h1 >> 8) & 0xff,
              h1 & 0xff,
              (h2 >> 24) & 0xff,
              (h2 >> 16) & 0xff,
              (h2 >> 8) & 0xff,
              h2 & 0xff,
              (h3 >> 24) & 0xff,
              (h3 >> 16) & 0xff,
              (h3 >> 8) & 0xff,
              h3 & 0xff,
              (h4 >> 24) & 0xff,
              (h4 >> 16) & 0xff,
              (h4 >> 8) & 0xff,
              h4 & 0xff,
            ];
          }
          array() {
            return this.digest();
          }
          arrayBuffer() {
            this.finalize();
            const buffer = new ArrayBuffer(20);
            const dataView = new DataView(buffer);
            dataView.setUint32(0, this.#h0);
            dataView.setUint32(4, this.#h1);
            dataView.setUint32(8, this.#h2);
            dataView.setUint32(12, this.#h3);
            dataView.setUint32(16, this.#h4);
            return buffer;
          }
        };
        exports_101("Sha1", Sha1);
      },
    };
  },
);
// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
//
// Adapted from Node.js. Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.
System.register(
  "https://deno.land/std/node/_util/_util_callbackify",
  [],
  function (exports_102, context_102) {
    "use strict";
    var NodeFalsyValueRejectionError, NodeInvalidArgTypeError;
    var __moduleName = context_102 && context_102.id;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    function callbackify(original) {
      if (typeof original !== "function") {
        throw new NodeInvalidArgTypeError('"original"');
      }
      const callbackified = function (...args) {
        const maybeCb = args.pop();
        if (typeof maybeCb !== "function") {
          throw new NodeInvalidArgTypeError("last");
        }
        const cb = (...args) => {
          maybeCb.apply(this, args);
        };
        original.apply(this, args).then((ret) => {
          setTimeout(cb.bind(this, null, ret), 0);
        }, (rej) => {
          rej = rej || new NodeFalsyValueRejectionError(rej);
          queueMicrotask(cb.bind(this, rej));
        });
      };
      const descriptors = Object.getOwnPropertyDescriptors(original);
      // It is possible to manipulate a functions `length` or `name` property. This
      // guards against the manipulation.
      if (typeof descriptors.length.value === "number") {
        descriptors.length.value++;
      }
      if (typeof descriptors.name.value === "string") {
        descriptors.name.value += "Callbackified";
      }
      Object.defineProperties(callbackified, descriptors);
      return callbackified;
    }
    exports_102("callbackify", callbackify);
    return {
      setters: [],
      execute: function () {
        // These are simplified versions of the "real" errors in Node.
        NodeFalsyValueRejectionError = class NodeFalsyValueRejectionError
          extends Error {
          constructor(reason) {
            super("Promise was rejected with falsy value");
            this.code = "ERR_FALSY_VALUE_REJECTION";
            this.reason = reason;
          }
        };
        NodeInvalidArgTypeError = class NodeInvalidArgTypeError
          extends TypeError {
          constructor(argumentName) {
            super(`The ${argumentName} argument must be of type function.`);
            this.code = "ERR_INVALID_ARG_TYPE";
          }
        };
      },
    };
  },
);
System.register(
  "https://deno.land/std/node/_utils",
  [],
  function (exports_103, context_103) {
    "use strict";
    var _TextDecoder, _TextEncoder;
    var __moduleName = context_103 && context_103.id;
    function notImplemented(msg) {
      const message = msg ? `Not implemented: ${msg}` : "Not implemented";
      throw new Error(message);
    }
    exports_103("notImplemented", notImplemented);
    function intoCallbackAPI(
      /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
      func,
      cb,
      /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
      ...args
    ) {
      func(...args)
        .then((value) => cb && cb(null, value))
        .catch((err) => cb && cb(err, null));
    }
    exports_103("intoCallbackAPI", intoCallbackAPI);
    function intoCallbackAPIWithIntercept(
      /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
      func,
      interceptor,
      cb,
      /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
      ...args
    ) {
      func(...args)
        .then((value) => cb && cb(null, interceptor(value)))
        .catch((err) => cb && cb(err, null));
    }
    exports_103("intoCallbackAPIWithIntercept", intoCallbackAPIWithIntercept);
    function spliceOne(list, index) {
      for (; index + 1 < list.length; index++) {
        list[index] = list[index + 1];
      }
      list.pop();
    }
    exports_103("spliceOne", spliceOne);
    return {
      setters: [],
      execute: function () {
        exports_103("_TextDecoder", _TextDecoder = TextDecoder);
        exports_103("_TextEncoder", _TextEncoder = TextEncoder);
      },
    };
  },
);
System.register(
  "https://deno.land/std/node/util",
  [
    "https://deno.land/std/node/_util/_util_callbackify",
    "https://deno.land/std/node/_utils",
  ],
  function (exports_104, context_104) {
    "use strict";
    var _utils_ts_1, TextDecoder, TextEncoder;
    var __moduleName = context_104 && context_104.id;
    function isArray(value) {
      return Array.isArray(value);
    }
    exports_104("isArray", isArray);
    function isBoolean(value) {
      return typeof value === "boolean" || value instanceof Boolean;
    }
    exports_104("isBoolean", isBoolean);
    function isNull(value) {
      return value === null;
    }
    exports_104("isNull", isNull);
    function isNullOrUndefined(value) {
      return value === null || value === undefined;
    }
    exports_104("isNullOrUndefined", isNullOrUndefined);
    function isNumber(value) {
      return typeof value === "number" || value instanceof Number;
    }
    exports_104("isNumber", isNumber);
    function isString(value) {
      return typeof value === "string" || value instanceof String;
    }
    exports_104("isString", isString);
    function isSymbol(value) {
      return typeof value === "symbol";
    }
    exports_104("isSymbol", isSymbol);
    function isUndefined(value) {
      return value === undefined;
    }
    exports_104("isUndefined", isUndefined);
    function isObject(value) {
      return value !== null && typeof value === "object";
    }
    exports_104("isObject", isObject);
    function isError(e) {
      return e instanceof Error;
    }
    exports_104("isError", isError);
    function isFunction(value) {
      return typeof value === "function";
    }
    exports_104("isFunction", isFunction);
    function isRegExp(value) {
      return value instanceof RegExp;
    }
    exports_104("isRegExp", isRegExp);
    function isPrimitive(value) {
      return (value === null ||
        (typeof value !== "object" && typeof value !== "function"));
    }
    exports_104("isPrimitive", isPrimitive);
    function validateIntegerRange(
      value,
      name,
      min = -2147483648,
      max = 2147483647,
    ) {
      // The defaults for min and max correspond to the limits of 32-bit integers.
      if (!Number.isInteger(value)) {
        throw new Error(`${name} must be 'an integer' but was ${value}`);
      }
      if (value < min || value > max) {
        throw new Error(
          `${name} must be >= ${min} && <= ${max}.  Value was ${value}`,
        );
      }
    }
    exports_104("validateIntegerRange", validateIntegerRange);
    return {
      setters: [
        function (_util_callbackify_ts_1_1) {
          exports_104({
            "callbackify": _util_callbackify_ts_1_1["callbackify"],
          });
        },
        function (_utils_ts_1_1) {
          _utils_ts_1 = _utils_ts_1_1;
        },
      ],
      execute: function () {
        exports_104("TextDecoder", TextDecoder = _utils_ts_1._TextDecoder);
        exports_104("TextEncoder", TextEncoder = _utils_ts_1._TextEncoder);
      },
    };
  },
);
// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
/** A module to print ANSI terminal colors. Inspired by chalk, kleur, and colors
 * on npm.
 *
 * ```
 * import { bgBlue, red, bold } from "https://deno.land/std/fmt/colors.ts";
 * console.log(bgBlue(red(bold("Hello world!"))));
 * ```
 *
 * This module supports `NO_COLOR` environmental variable disabling any coloring
 * if `NO_COLOR` is set.
 *
 * This module is browser compatible. */
System.register(
  "https://deno.land/std/fmt/colors",
  [],
  function (exports_105, context_105) {
    "use strict";
    var noColor, enabled, ANSI_PATTERN;
    var __moduleName = context_105 && context_105.id;
    function setColorEnabled(value) {
      if (noColor) {
        return;
      }
      enabled = value;
    }
    exports_105("setColorEnabled", setColorEnabled);
    function getColorEnabled() {
      return enabled;
    }
    exports_105("getColorEnabled", getColorEnabled);
    function code(open, close) {
      return {
        open: `\x1b[${open.join(";")}m`,
        close: `\x1b[${close}m`,
        regexp: new RegExp(`\\x1b\\[${close}m`, "g"),
      };
    }
    function run(str, code) {
      return enabled
        ? `${code.open}${str.replace(code.regexp, code.open)}${code.close}`
        : str;
    }
    function reset(str) {
      return run(str, code([0], 0));
    }
    exports_105("reset", reset);
    function bold(str) {
      return run(str, code([1], 22));
    }
    exports_105("bold", bold);
    function dim(str) {
      return run(str, code([2], 22));
    }
    exports_105("dim", dim);
    function italic(str) {
      return run(str, code([3], 23));
    }
    exports_105("italic", italic);
    function underline(str) {
      return run(str, code([4], 24));
    }
    exports_105("underline", underline);
    function inverse(str) {
      return run(str, code([7], 27));
    }
    exports_105("inverse", inverse);
    function hidden(str) {
      return run(str, code([8], 28));
    }
    exports_105("hidden", hidden);
    function strikethrough(str) {
      return run(str, code([9], 29));
    }
    exports_105("strikethrough", strikethrough);
    function black(str) {
      return run(str, code([30], 39));
    }
    exports_105("black", black);
    function red(str) {
      return run(str, code([31], 39));
    }
    exports_105("red", red);
    function green(str) {
      return run(str, code([32], 39));
    }
    exports_105("green", green);
    function yellow(str) {
      return run(str, code([33], 39));
    }
    exports_105("yellow", yellow);
    function blue(str) {
      return run(str, code([34], 39));
    }
    exports_105("blue", blue);
    function magenta(str) {
      return run(str, code([35], 39));
    }
    exports_105("magenta", magenta);
    function cyan(str) {
      return run(str, code([36], 39));
    }
    exports_105("cyan", cyan);
    function white(str) {
      return run(str, code([37], 39));
    }
    exports_105("white", white);
    function gray(str) {
      return run(str, code([90], 39));
    }
    exports_105("gray", gray);
    function bgBlack(str) {
      return run(str, code([40], 49));
    }
    exports_105("bgBlack", bgBlack);
    function bgRed(str) {
      return run(str, code([41], 49));
    }
    exports_105("bgRed", bgRed);
    function bgGreen(str) {
      return run(str, code([42], 49));
    }
    exports_105("bgGreen", bgGreen);
    function bgYellow(str) {
      return run(str, code([43], 49));
    }
    exports_105("bgYellow", bgYellow);
    function bgBlue(str) {
      return run(str, code([44], 49));
    }
    exports_105("bgBlue", bgBlue);
    function bgMagenta(str) {
      return run(str, code([45], 49));
    }
    exports_105("bgMagenta", bgMagenta);
    function bgCyan(str) {
      return run(str, code([46], 49));
    }
    exports_105("bgCyan", bgCyan);
    function bgWhite(str) {
      return run(str, code([47], 49));
    }
    exports_105("bgWhite", bgWhite);
    /* Special Color Sequences */
    function clampAndTruncate(n, max = 255, min = 0) {
      return Math.trunc(Math.max(Math.min(n, max), min));
    }
    /** Set text color using paletted 8bit colors.
     * https://en.wikipedia.org/wiki/ANSI_escape_code#8-bit */
    function rgb8(str, color) {
      return run(str, code([38, 5, clampAndTruncate(color)], 39));
    }
    exports_105("rgb8", rgb8);
    /** Set background color using paletted 8bit colors.
     * https://en.wikipedia.org/wiki/ANSI_escape_code#8-bit */
    function bgRgb8(str, color) {
      return run(str, code([48, 5, clampAndTruncate(color)], 49));
    }
    exports_105("bgRgb8", bgRgb8);
    /** Set text color using 24bit rgb.
     * `color` can be a number in range `0x000000` to `0xffffff` or
     * an `Rgb`.
     *
     * To produce the color magenta:
     *
     *      rgba24("foo", 0xff00ff);
     *      rgba24("foo", {r: 255, g: 0, b: 255});
     */
    function rgb24(str, color) {
      if (typeof color === "number") {
        return run(
          str,
          code(
            [38, 2, (color >> 16) & 0xff, (color >> 8) & 0xff, color & 0xff],
            39,
          ),
        );
      }
      return run(
        str,
        code([
          38,
          2,
          clampAndTruncate(color.r),
          clampAndTruncate(color.g),
          clampAndTruncate(color.b),
        ], 39),
      );
    }
    exports_105("rgb24", rgb24);
    /** Set background color using 24bit rgb.
     * `color` can be a number in range `0x000000` to `0xffffff` or
     * an `Rgb`.
     *
     * To produce the color magenta:
     *
     *      bgRgba24("foo", 0xff00ff);
     *      bgRgba24("foo", {r: 255, g: 0, b: 255});
     */
    function bgRgb24(str, color) {
      if (typeof color === "number") {
        return run(
          str,
          code(
            [48, 2, (color >> 16) & 0xff, (color >> 8) & 0xff, color & 0xff],
            49,
          ),
        );
      }
      return run(
        str,
        code([
          48,
          2,
          clampAndTruncate(color.r),
          clampAndTruncate(color.g),
          clampAndTruncate(color.b),
        ], 49),
      );
    }
    exports_105("bgRgb24", bgRgb24);
    function stripColor(string) {
      return string.replace(ANSI_PATTERN, "");
    }
    exports_105("stripColor", stripColor);
    return {
      setters: [],
      execute: function () {
        noColor = globalThis.Deno?.noColor ?? true;
        enabled = !noColor;
        // https://github.com/chalk/ansi-regex/blob/2b56fb0c7a07108e5b54241e8faec160d393aedb/index.js
        ANSI_PATTERN = new RegExp(
          [
            "[\\u001B\\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[-a-zA-Z\\d\\/#&.:=?%@~_]*)*)?\\u0007)",
            "(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PR-TZcf-ntqry=><~]))",
          ].join("|"),
          "g",
        );
      },
    };
  },
);
// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
/** This module is browser compatible. */
System.register(
  "https://deno.land/std/testing/diff",
  [],
  function (exports_106, context_106) {
    "use strict";
    var DiffType, REMOVED, COMMON, ADDED;
    var __moduleName = context_106 && context_106.id;
    function createCommon(A, B, reverse) {
      const common = [];
      if (A.length === 0 || B.length === 0) {
        return [];
      }
      for (let i = 0; i < Math.min(A.length, B.length); i += 1) {
        if (
          A[reverse ? A.length - i - 1 : i] ===
            B[reverse ? B.length - i - 1 : i]
        ) {
          common.push(A[reverse ? A.length - i - 1 : i]);
        } else {
          return common;
        }
      }
      return common;
    }
    function diff(A, B) {
      const prefixCommon = createCommon(A, B);
      const suffixCommon = createCommon(
        A.slice(prefixCommon.length),
        B.slice(prefixCommon.length),
        true,
      ).reverse();
      A = suffixCommon.length
        ? A.slice(prefixCommon.length, -suffixCommon.length)
        : A.slice(prefixCommon.length);
      B = suffixCommon.length
        ? B.slice(prefixCommon.length, -suffixCommon.length)
        : B.slice(prefixCommon.length);
      const swapped = B.length > A.length;
      [A, B] = swapped ? [B, A] : [A, B];
      const M = A.length;
      const N = B.length;
      if (!M && !N && !suffixCommon.length && !prefixCommon.length) {
        return [];
      }
      if (!N) {
        return [
          ...prefixCommon.map((c) => ({ type: DiffType.common, value: c })),
          ...A.map((a) => ({
            type: swapped ? DiffType.added : DiffType.removed,
            value: a,
          })),
          ...suffixCommon.map((c) => ({ type: DiffType.common, value: c })),
        ];
      }
      const offset = N;
      const delta = M - N;
      const size = M + N + 1;
      const fp = new Array(size).fill({ y: -1 });
      /**
         * INFO:
         * This buffer is used to save memory and improve performance.
         * The first half is used to save route and last half is used to save diff
         * type.
         * This is because, when I kept new uint8array area to save type,performance
         * worsened.
         */
      const routes = new Uint32Array((M * N + size + 1) * 2);
      const diffTypesPtrOffset = routes.length / 2;
      let ptr = 0;
      let p = -1;
      function backTrace(A, B, current, swapped) {
        const M = A.length;
        const N = B.length;
        const result = [];
        let a = M - 1;
        let b = N - 1;
        let j = routes[current.id];
        let type = routes[current.id + diffTypesPtrOffset];
        while (true) {
          if (!j && !type) {
            break;
          }
          const prev = j;
          if (type === REMOVED) {
            result.unshift({
              type: swapped ? DiffType.removed : DiffType.added,
              value: B[b],
            });
            b -= 1;
          } else if (type === ADDED) {
            result.unshift({
              type: swapped ? DiffType.added : DiffType.removed,
              value: A[a],
            });
            a -= 1;
          } else {
            result.unshift({ type: DiffType.common, value: A[a] });
            a -= 1;
            b -= 1;
          }
          j = routes[prev];
          type = routes[prev + diffTypesPtrOffset];
        }
        return result;
      }
      function createFP(slide, down, k, M) {
        if (slide && slide.y === -1 && down && down.y === -1) {
          return { y: 0, id: 0 };
        }
        if (
          (down && down.y === -1) ||
          k === M ||
          (slide && slide.y) > (down && down.y) + 1
        ) {
          const prev = slide.id;
          ptr++;
          routes[ptr] = prev;
          routes[ptr + diffTypesPtrOffset] = ADDED;
          return { y: slide.y, id: ptr };
        } else {
          const prev = down.id;
          ptr++;
          routes[ptr] = prev;
          routes[ptr + diffTypesPtrOffset] = REMOVED;
          return { y: down.y + 1, id: ptr };
        }
      }
      function snake(k, slide, down, _offset, A, B) {
        const M = A.length;
        const N = B.length;
        if (k < -N || M < k) {
          return { y: -1, id: -1 };
        }
        const fp = createFP(slide, down, k, M);
        while (fp.y + k < M && fp.y < N && A[fp.y + k] === B[fp.y]) {
          const prev = fp.id;
          ptr++;
          fp.id = ptr;
          fp.y += 1;
          routes[ptr] = prev;
          routes[ptr + diffTypesPtrOffset] = COMMON;
        }
        return fp;
      }
      while (fp[delta + offset].y < N) {
        p = p + 1;
        for (let k = -p; k < delta; ++k) {
          fp[k + offset] = snake(
            k,
            fp[k - 1 + offset],
            fp[k + 1 + offset],
            offset,
            A,
            B,
          );
        }
        for (let k = delta + p; k > delta; --k) {
          fp[k + offset] = snake(
            k,
            fp[k - 1 + offset],
            fp[k + 1 + offset],
            offset,
            A,
            B,
          );
        }
        fp[delta + offset] = snake(
          delta,
          fp[delta - 1 + offset],
          fp[delta + 1 + offset],
          offset,
          A,
          B,
        );
      }
      return [
        ...prefixCommon.map((c) => ({ type: DiffType.common, value: c })),
        ...backTrace(A, B, fp[delta + offset], swapped),
        ...suffixCommon.map((c) => ({ type: DiffType.common, value: c })),
      ];
    }
    exports_106("default", diff);
    return {
      setters: [],
      execute: function () {
        (function (DiffType) {
          DiffType["removed"] = "removed";
          DiffType["common"] = "common";
          DiffType["added"] = "added";
        })(DiffType || (DiffType = {}));
        exports_106("DiffType", DiffType);
        REMOVED = 1;
        COMMON = 2;
        ADDED = 3;
      },
    };
  },
);
// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
/** This module is browser compatible. Do not rely on good formatting of values
 * for AssertionError messages in browsers. */
System.register(
  "https://deno.land/std/testing/asserts",
  ["https://deno.land/std/fmt/colors", "https://deno.land/std/testing/diff"],
  function (exports_107, context_107) {
    "use strict";
    var colors_ts_3, diff_ts_3, CAN_NOT_DISPLAY, AssertionError;
    var __moduleName = context_107 && context_107.id;
    function format(v) {
      let string = globalThis.Deno ? Deno.inspect(v) : String(v);
      if (typeof v == "string") {
        string = `"${string.replace(/(?=["\\])/g, "\\")}"`;
      }
      return string;
    }
    function createColor(diffType) {
      switch (diffType) {
        case diff_ts_3.DiffType.added:
          return (s) => colors_ts_3.green(colors_ts_3.bold(s));
        case diff_ts_3.DiffType.removed:
          return (s) => colors_ts_3.red(colors_ts_3.bold(s));
        default:
          return colors_ts_3.white;
      }
    }
    function createSign(diffType) {
      switch (diffType) {
        case diff_ts_3.DiffType.added:
          return "+   ";
        case diff_ts_3.DiffType.removed:
          return "-   ";
        default:
          return "    ";
      }
    }
    function buildMessage(diffResult) {
      const messages = [];
      messages.push("");
      messages.push("");
      messages.push(
        `    ${colors_ts_3.gray(colors_ts_3.bold("[Diff]"))} ${
          colors_ts_3.red(colors_ts_3.bold("Actual"))
        } / ${colors_ts_3.green(colors_ts_3.bold("Expected"))}`,
      );
      messages.push("");
      messages.push("");
      diffResult.forEach((result) => {
        const c = createColor(result.type);
        messages.push(c(`${createSign(result.type)}${result.value}`));
      });
      messages.push("");
      return messages;
    }
    function isKeyedCollection(x) {
      return [Symbol.iterator, "size"].every((k) => k in x);
    }
    function equal(c, d) {
      const seen = new Map();
      return (function compare(a, b) {
        // Have to render RegExp & Date for string comparison
        // unless it's mistreated as object
        if (
          a &&
          b &&
          ((a instanceof RegExp && b instanceof RegExp) ||
            (a instanceof Date && b instanceof Date))
        ) {
          return String(a) === String(b);
        }
        if (Object.is(a, b)) {
          return true;
        }
        if (a && typeof a === "object" && b && typeof b === "object") {
          if (seen.get(a) === b) {
            return true;
          }
          if (Object.keys(a || {}).length !== Object.keys(b || {}).length) {
            return false;
          }
          if (isKeyedCollection(a) && isKeyedCollection(b)) {
            if (a.size !== b.size) {
              return false;
            }
            let unmatchedEntries = a.size;
            for (const [aKey, aValue] of a.entries()) {
              for (const [bKey, bValue] of b.entries()) {
                /* Given that Map keys can be references, we need
                             * to ensure that they are also deeply equal */
                if (
                  (aKey === aValue && bKey === bValue && compare(aKey, bKey)) ||
                  (compare(aKey, bKey) && compare(aValue, bValue))
                ) {
                  unmatchedEntries--;
                }
              }
            }
            return unmatchedEntries === 0;
          }
          const merged = { ...a, ...b };
          for (const key in merged) {
            if (!compare(a && a[key], b && b[key])) {
              return false;
            }
          }
          seen.set(a, b);
          return true;
        }
        return false;
      })(c, d);
    }
    exports_107("equal", equal);
    /** Make an assertion, if not `true`, then throw. */
    function assert(expr, msg = "") {
      if (!expr) {
        throw new AssertionError(msg);
      }
    }
    exports_107("assert", assert);
    /**
     * Make an assertion that `actual` and `expected` are equal, deeply. If not
     * deeply equal, then throw.
     */
    function assertEquals(actual, expected, msg) {
      if (equal(actual, expected)) {
        return;
      }
      let message = "";
      const actualString = format(actual);
      const expectedString = format(expected);
      try {
        const diffResult = diff_ts_3.default(
          actualString.split("\n"),
          expectedString.split("\n"),
        );
        const diffMsg = buildMessage(diffResult).join("\n");
        message = `Values are not equal:\n${diffMsg}`;
      } catch (e) {
        message = `\n${colors_ts_3.red(CAN_NOT_DISPLAY)} + \n\n`;
      }
      if (msg) {
        message = msg;
      }
      throw new AssertionError(message);
    }
    exports_107("assertEquals", assertEquals);
    /**
     * Make an assertion that `actual` and `expected` are not equal, deeply.
     * If not then throw.
     */
    function assertNotEquals(actual, expected, msg) {
      if (!equal(actual, expected)) {
        return;
      }
      let actualString;
      let expectedString;
      try {
        actualString = String(actual);
      } catch (e) {
        actualString = "[Cannot display]";
      }
      try {
        expectedString = String(expected);
      } catch (e) {
        expectedString = "[Cannot display]";
      }
      if (!msg) {
        msg = `actual: ${actualString} expected: ${expectedString}`;
      }
      throw new AssertionError(msg);
    }
    exports_107("assertNotEquals", assertNotEquals);
    /**
     * Make an assertion that `actual` and `expected` are strictly equal.  If
     * not then throw.
     */
    function assertStrictEq(actual, expected, msg) {
      if (actual === expected) {
        return;
      }
      let message;
      if (msg) {
        message = msg;
      } else {
        const actualString = format(actual);
        const expectedString = format(expected);
        if (actualString === expectedString) {
          const withOffset = actualString
            .split("\n")
            .map((l) => `     ${l}`)
            .join("\n");
          message =
            `Values have the same structure but are not reference-equal:\n\n${
              colors_ts_3.red(withOffset)
            }\n`;
        } else {
          try {
            const diffResult = diff_ts_3.default(
              actualString.split("\n"),
              expectedString.split("\n"),
            );
            const diffMsg = buildMessage(diffResult).join("\n");
            message = `Values are not strictly equal:\n${diffMsg}`;
          } catch (e) {
            message = `\n${colors_ts_3.red(CAN_NOT_DISPLAY)} + \n\n`;
          }
        }
      }
      throw new AssertionError(message);
    }
    exports_107("assertStrictEq", assertStrictEq);
    /**
     * Make an assertion that actual contains expected. If not
     * then thrown.
     */
    function assertStrContains(actual, expected, msg) {
      if (!actual.includes(expected)) {
        if (!msg) {
          msg = `actual: "${actual}" expected to contain: "${expected}"`;
        }
        throw new AssertionError(msg);
      }
    }
    exports_107("assertStrContains", assertStrContains);
    /**
     * Make an assertion that `actual` contains the `expected` values
     * If not then thrown.
     */
    function assertArrayContains(actual, expected, msg) {
      const missing = [];
      for (let i = 0; i < expected.length; i++) {
        let found = false;
        for (let j = 0; j < actual.length; j++) {
          if (equal(expected[i], actual[j])) {
            found = true;
            break;
          }
        }
        if (!found) {
          missing.push(expected[i]);
        }
      }
      if (missing.length === 0) {
        return;
      }
      if (!msg) {
        msg = `actual: "${actual}" expected to contain: "${expected}"`;
        msg += "\n";
        msg += `missing: ${missing}`;
      }
      throw new AssertionError(msg);
    }
    exports_107("assertArrayContains", assertArrayContains);
    /**
     * Make an assertion that `actual` match RegExp `expected`. If not
     * then thrown
     */
    function assertMatch(actual, expected, msg) {
      if (!expected.test(actual)) {
        if (!msg) {
          msg = `actual: "${actual}" expected to match: "${expected}"`;
        }
        throw new AssertionError(msg);
      }
    }
    exports_107("assertMatch", assertMatch);
    /**
     * Forcefully throws a failed assertion
     */
    function fail(msg) {
      // eslint-disable-next-line @typescript-eslint/no-use-before-define
      assert(false, `Failed assertion${msg ? `: ${msg}` : "."}`);
    }
    exports_107("fail", fail);
    /** Executes a function, expecting it to throw.  If it does not, then it
     * throws.  An error class and a string that should be included in the
     * error message can also be asserted.
     */
    function assertThrows(fn, ErrorClass, msgIncludes = "", msg) {
      let doesThrow = false;
      let error = null;
      try {
        fn();
      } catch (e) {
        if (
          ErrorClass && !(Object.getPrototypeOf(e) === ErrorClass.prototype)
        ) {
          msg =
            `Expected error to be instance of "${ErrorClass.name}", but was "${e.constructor.name}"${
              msg ? `: ${msg}` : "."
            }`;
          throw new AssertionError(msg);
        }
        if (msgIncludes && !e.message.includes(msgIncludes)) {
          msg =
            `Expected error message to include "${msgIncludes}", but got "${e.message}"${
              msg ? `: ${msg}` : "."
            }`;
          throw new AssertionError(msg);
        }
        doesThrow = true;
        error = e;
      }
      if (!doesThrow) {
        msg = `Expected function to throw${msg ? `: ${msg}` : "."}`;
        throw new AssertionError(msg);
      }
      return error;
    }
    exports_107("assertThrows", assertThrows);
    async function assertThrowsAsync(fn, ErrorClass, msgIncludes = "", msg) {
      let doesThrow = false;
      let error = null;
      try {
        await fn();
      } catch (e) {
        if (
          ErrorClass && !(Object.getPrototypeOf(e) === ErrorClass.prototype)
        ) {
          msg =
            `Expected error to be instance of "${ErrorClass.name}", but got "${e.name}"${
              msg ? `: ${msg}` : "."
            }`;
          throw new AssertionError(msg);
        }
        if (msgIncludes && !e.message.includes(msgIncludes)) {
          msg =
            `Expected error message to include "${msgIncludes}", but got "${e.message}"${
              msg ? `: ${msg}` : "."
            }`;
          throw new AssertionError(msg);
        }
        doesThrow = true;
        error = e;
      }
      if (!doesThrow) {
        msg = `Expected function to throw${msg ? `: ${msg}` : "."}`;
        throw new AssertionError(msg);
      }
      return error;
    }
    exports_107("assertThrowsAsync", assertThrowsAsync);
    /** Use this to stub out methods that will throw when invoked. */
    function unimplemented(msg) {
      throw new AssertionError(msg || "unimplemented");
    }
    exports_107("unimplemented", unimplemented);
    /** Use this to assert unreachable code. */
    function unreachable() {
      throw new AssertionError("unreachable");
    }
    exports_107("unreachable", unreachable);
    return {
      setters: [
        function (colors_ts_3_1) {
          colors_ts_3 = colors_ts_3_1;
        },
        function (diff_ts_3_1) {
          diff_ts_3 = diff_ts_3_1;
        },
      ],
      execute: function () {
        CAN_NOT_DISPLAY = "[Cannot display]";
        AssertionError = class AssertionError extends Error {
          constructor(message) {
            super(message);
            this.name = "AssertionError";
          }
        };
        exports_107("AssertionError", AssertionError);
      },
    };
  },
);
// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
System.register(
  "https://deno.land/std/uuid/v5",
  [
    "https://deno.land/std/uuid/_common",
    "https://deno.land/std/hash/sha1",
    "https://deno.land/std/node/util",
    "https://deno.land/std/testing/asserts",
  ],
  function (exports_108, context_108) {
    "use strict";
    var _common_ts_3, sha1_ts_2, util_ts_10, asserts_ts_12, UUID_RE;
    var __moduleName = context_108 && context_108.id;
    function validate(id) {
      return UUID_RE.test(id);
    }
    exports_108("validate", validate);
    function generate(options, buf, offset) {
      const i = (buf && offset) || 0;
      let { value, namespace } = options;
      if (util_ts_10.isString(value)) {
        value = _common_ts_3.stringToBytes(value);
      }
      if (util_ts_10.isString(namespace)) {
        namespace = _common_ts_3.uuidToBytes(namespace);
      }
      asserts_ts_12.assert(
        namespace.length === 16,
        "namespace must be uuid string or an Array of 16 byte values",
      );
      const content = namespace.concat(value);
      const bytes = new sha1_ts_2.Sha1().update(
        _common_ts_3.createBuffer(content),
      ).digest();
      bytes[6] = (bytes[6] & 0x0f) | 0x50;
      bytes[8] = (bytes[8] & 0x3f) | 0x80;
      if (buf) {
        for (let idx = 0; idx < 16; ++idx) {
          buf[i + idx] = bytes[idx];
        }
      }
      return buf || _common_ts_3.bytesToUuid(bytes);
    }
    exports_108("generate", generate);
    return {
      setters: [
        function (_common_ts_3_1) {
          _common_ts_3 = _common_ts_3_1;
        },
        function (sha1_ts_2_1) {
          sha1_ts_2 = sha1_ts_2_1;
        },
        function (util_ts_10_1) {
          util_ts_10 = util_ts_10_1;
        },
        function (asserts_ts_12_1) {
          asserts_ts_12 = asserts_ts_12_1;
        },
      ],
      execute: function () {
        UUID_RE =
          /^[0-9a-f]{8}-[0-9a-f]{4}-[5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      },
    };
  },
);
System.register(
  "https://deno.land/std/uuid/mod",
  [
    "https://deno.land/std/uuid/v1",
    "https://deno.land/std/uuid/v4",
    "https://deno.land/std/uuid/v5",
  ],
  function (exports_109, context_109) {
    "use strict";
    var v1, v4, v5, NIL_UUID, NOT_IMPLEMENTED, v3;
    var __moduleName = context_109 && context_109.id;
    function isNil(val) {
      return val === NIL_UUID;
    }
    exports_109("isNil", isNil);
    return {
      setters: [
        function (v1_1) {
          v1 = v1_1;
        },
        function (v4_1) {
          v4 = v4_1;
        },
        function (v5_1) {
          v5 = v5_1;
        },
      ],
      execute: function () {
        exports_109("v1", v1);
        exports_109("v4", v4);
        exports_109("v5", v5);
        exports_109(
          "NIL_UUID",
          NIL_UUID = "00000000-0000-0000-0000-000000000000",
        );
        NOT_IMPLEMENTED = {
          generate() {
            throw new Error("Not implemented");
          },
          validate() {
            throw new Error("Not implemented");
          },
        };
        // TODO Implement
        exports_109("v3", v3 = NOT_IMPLEMENTED);
      },
    };
  },
);
System.register(
  "file:///C:/Users/danst/OneDrive/Documents/webdev/miscellaneous/Goals/goals-be/config",
  [],
  function (exports_110, context_110) {
    "use strict";
    var dbCreds;
    var __moduleName = context_110 && context_110.id;
    return {
      setters: [],
      execute: function () {
        dbCreds = {
          user: "daniel",
          database: "GoalsApp",
          password: "123456",
          hostname: "localhost",
          port: 5432,
        };
        exports_110("dbCreds", dbCreds);
      },
    };
  },
);
System.register(
  "file:///C:/Users/danst/OneDrive/Documents/webdev/miscellaneous/Goals/goals-be/controllers/users",
  [
    "https://deno.land/x/postgres/mod",
    "file:///C:/Users/danst/OneDrive/Documents/webdev/miscellaneous/Goals/goals-be/config",
  ],
  function (exports_111, context_111) {
    "use strict";
    var mod_ts_11,
      config_ts_1,
      client,
      getUsers,
      getUser,
      addUser,
      updateUser,
      deleteUser;
    var __moduleName = context_111 && context_111.id;
    return {
      setters: [
        function (mod_ts_11_1) {
          mod_ts_11 = mod_ts_11_1;
        },
        function (config_ts_1_1) {
          config_ts_1 = config_ts_1_1;
        },
      ],
      execute: function () {
        //init client
        client = new mod_ts_11.Client(config_ts_1.dbCreds);
        // @desc get user list
        // @route GET /api/v1/users
        getUsers = async ({ response }) => {
          try {
            await client.connect();
            const result = await client.query("SELECT * FROM users");
            const users = new Array();
            result.rows.map((p) => {
              let obj = new Object();
              result.rowDescription.columns.map((el, i) => {
                obj[el.name] = p[i];
              });
              users.push(obj);
            });
            response.body = {
              success: true,
              data: users,
            };
          } catch (err) {
            response.status = 500;
            response.body = {
              success: false,
              msg: err.toString(),
            };
          } finally {
            await client.end();
          }
        };
        exports_111("getUsers", getUsers);
        // @desc get user
        // @route GET /api/v1/users/:id
        getUser = async ({ params, response }) => {
          try {
            await client.connect();
            const result = await client.query(
              `SELECT * FROM users WHERE id = ${params.id}`,
            );
            if (result.rows.toString() === "") {
              response.status = 404;
              response.body = {
                success: false,
                msg: `no user with id ${params.id} found`,
              };
              return;
            } else {
              const user = new Object();
              result.rows.map((p) => {
                result.rowDescription.columns.map((el, i) => {
                  user[el.name] = p[i];
                });
                response.body = {
                  success: true,
                  data: user,
                };
              });
            }
          } catch (err) {
            response.status = 500;
            response.body = {
              success: false,
              msg: err.toString(),
            };
          } finally {
            await client.end();
          }
        };
        exports_111("getUser", getUser);
        // @desc add user
        // @route Post /api/v1/users
        addUser = async ({ request, response }) => {
          const body = await request.body();
          const user = body.value;
          console.log(user);
          if (!request.hasBody) {
            response.status = 404;
            response.body = {
              success: false,
              msg: "no data",
            };
          } else {
            try {
              await client.connect();
              const result = await client.query(
                `INSERT INTO users(name, email, birthday, password)
      VALUES('${user.name}', '${user.email}','${user.birthday}','${user.password}')`,
              );
              response.status = 201;
              response.body = {
                success: true,
                data: user,
              };
            } catch (err) {
              response.status = 500;
              response.body = {
                success: false,
                msg: err.toString(),
              };
            } finally {
              await client.end();
            }
          }
        };
        exports_111("addUser", addUser);
        // @desc update user
        // @route put /api/v1/users/:id
        updateUser = async ({ params, request, response }) => {
          await getUser({ params: { "id": params.id }, response });
          if (response.status === 404) {
            response.status = 404;
            response.body = {
              success: false,
              msg: response.body,
            };
            return;
          } else {
            const body = await request.body();
            const user = body.value;
            if (!request.hasBody) {
              response.status = 404;
              response.body = {
                success: false,
                msg: "we messed up",
              };
            } else {
              try {
                await client.connect();
                const result = await client.query(`UPDATE users SET
          name='${user.name}',
          email='${user.email}',
          birth='${user.birth}'
          WHERE id=${params.id}`);
                response.status = 200;
                response.body = {
                  success: true,
                  data: user,
                };
              } catch (err) {
                response.status = 500;
                response.body = {
                  success: false,
                  msg: err.toString(),
                };
              } finally {
                await client.end();
              }
            }
          }
        };
        exports_111("updateUser", updateUser);
        // @desc delete user
        // @route delete /api/v1/users/:id
        deleteUser = async ({ params, response }) => {
          await getUser({ params: { "id": params.id }, response });
          if (response.status === 404) {
            response.status = 404;
            response.body = {
              success: false,
              msg: response.body,
            };
            return;
          } else {
            try {
              await client.connect();
              const result = await client.query(
                `DELETE FROM users WHERE id = ${params.id}`,
              );
              response.status = 204;
              response.body = {
                success: true,
                msg: `User ${params.id} has been deleted`,
              };
            } catch (err) {
              response.status = 500;
              response.body = {
                success: false,
                msg: err.toString(),
              };
            } finally {
              await client.end();
            }
          }
        };
        exports_111("deleteUser", deleteUser);
      },
    };
  },
);
System.register(
  "https://deno.land/std/encoding/utf8",
  [],
  function (exports_112, context_112) {
    "use strict";
    var encoder, decoder;
    var __moduleName = context_112 && context_112.id;
    /** Shorthand for new TextEncoder().encode() */
    function encode(input) {
      return encoder.encode(input);
    }
    exports_112("encode", encode);
    /** Shorthand for new TextDecoder().decode() */
    function decode(input) {
      return decoder.decode(input);
    }
    exports_112("decode", decode);
    return {
      setters: [],
      execute: function () {
        /** A default TextEncoder instance */
        exports_112("encoder", encoder = new TextEncoder());
        /** A default TextDecoder instance */
        exports_112("decoder", decoder = new TextDecoder());
      },
    };
  },
);
System.register(
  "https://deno.land/x/bcrypt/bcrypt/base64",
  [],
  function (exports_113, context_113) {
    "use strict";
    var base64_code, index_64;
    var __moduleName = context_113 && context_113.id;
    function encode(d, len) {
      let off = 0;
      let rs = [];
      let c1 = 0;
      let c2 = 0;
      while (off < len) {
        c1 = d[off++] & 0xff;
        rs.push(base64_code[(c1 >> 2) & 0x3f]);
        c1 = (c1 & 0x03) << 4;
        if (off >= len) {
          rs.push(base64_code[c1 & 0x3f]);
          break;
        }
        c2 = d[off++] & 0xff;
        c1 |= (c2 >> 4) & 0x0f;
        rs.push(base64_code[c1 & 0x3f]);
        c1 = (c2 & 0x0f) << 2;
        if (off >= len) {
          rs.push(base64_code[c1 & 0x3f]);
          break;
        }
        c2 = d[off++] & 0xff;
        c1 |= (c2 >> 6) & 0x03;
        rs.push(base64_code[c1 & 0x3f]);
        rs.push(base64_code[c2 & 0x3f]);
      }
      return rs.join("");
    }
    exports_113("encode", encode);
    // x is a single character
    function char64(x) {
      if (x.length > 1) {
        throw new Error("Expected a single character");
      }
      let characterAsciiCode = x.charCodeAt(0);
      if (characterAsciiCode < 0 || characterAsciiCode > index_64.length) {
        return -1;
      }
      return index_64[characterAsciiCode];
    }
    function decode(s, maxolen) {
      let rs = [];
      let off = 0;
      let slen = s.length;
      let olen = 0;
      let ret;
      let c1, c2, c3, c4, o;
      if (maxolen <= 0) {
        throw new Error("Invalid maxolen");
      }
      while (off < slen - 1 && olen < maxolen) {
        c1 = char64(s.charAt(off++));
        c2 = char64(s.charAt(off++));
        if (c1 === -1 || c2 === -1) {
          break;
        }
        o = c1 << 2;
        o |= (c2 & 0x30) >> 4;
        rs.push(o);
        if (++olen >= maxolen || off >= slen) {
          break;
        }
        c3 = char64(s.charAt(off++));
        if (c3 === -1) {
          break;
        }
        o = (c2 & 0x0f) << 4;
        o |= (c3 & 0x3c) >> 2;
        rs.push(o);
        if (++olen >= maxolen || off >= slen) {
          break;
        }
        c4 = char64(s.charAt(off++));
        o = (c3 & 0x03) << 6;
        o |= c4;
        rs.push(o);
        ++olen;
      }
      ret = new Uint8Array(olen);
      for (off = 0; off < olen; off++) {
        ret[off] = rs[off];
      }
      return ret;
    }
    exports_113("decode", decode);
    return {
      setters: [],
      execute: function () {
        base64_code =
          "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            .split("");
        index_64 = new Uint8Array([
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          0,
          1,
          54,
          55,
          56,
          57,
          58,
          59,
          60,
          61,
          62,
          63,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          2,
          3,
          4,
          5,
          6,
          7,
          8,
          9,
          10,
          11,
          12,
          13,
          14,
          15,
          16,
          17,
          18,
          19,
          20,
          21,
          22,
          23,
          24,
          25,
          26,
          27,
          -1,
          -1,
          -1,
          -1,
          -1,
          -1,
          28,
          29,
          30,
          31,
          32,
          33,
          34,
          35,
          36,
          37,
          38,
          39,
          40,
          41,
          42,
          43,
          44,
          45,
          46,
          47,
          48,
          49,
          50,
          51,
          52,
          53,
          -1,
          -1,
          -1,
          -1,
          -1,
        ]);
      },
    };
  },
);
System.register(
  "https://deno.land/x/bcrypt/bcrypt/bcrypt",
  [
    "https://deno.land/std/encoding/utf8",
    "https://deno.land/x/bcrypt/bcrypt/base64",
  ],
  function (exports_114, context_114) {
    "use strict";
    var utf8_ts_6,
      base64,
      crypto,
      GENSALT_DEFAULT_LOG2_ROUNDS,
      BCRYPT_SALT_LEN,
      BLOWFISH_NUM_ROUNDS,
      P_orig,
      S_orig,
      bf_crypt_ciphertext,
      P,
      S;
    var __moduleName = context_114 && context_114.id;
    function encipher(lr, off) {
      let i = 0;
      let n = 0;
      let l = lr[off];
      let r = lr[off + 1];
      l ^= P[0];
      for (i = 0; i <= BLOWFISH_NUM_ROUNDS - 2;) {
        // Feistel substitution on left word
        n = S[(l >> 24) & 0xff];
        n += S[0x100 | ((l >> 16) & 0xff)];
        n ^= S[0x200 | ((l >> 8) & 0xff)];
        n += S[0x300 | (l & 0xff)];
        r ^= n ^ P[++i];
        // Feistel substitution on right word
        n = S[(r >> 24) & 0xff];
        n += S[0x100 | ((r >> 16) & 0xff)];
        n ^= S[0x200 | ((r >> 8) & 0xff)];
        n += S[0x300 | (r & 0xff)];
        l ^= n ^ P[++i];
      }
      lr[off] = r ^ P[BLOWFISH_NUM_ROUNDS + 1];
      lr[off + 1] = l;
    }
    function streamtoword(data, offp) {
      let word = 0;
      let off = offp[0];
      for (let i = 0; i < 4; i++) {
        word = (word << 8) | (data[off] & 0xff);
        off = (off + 1) % data.length;
      }
      offp[0] = off;
      return word;
    }
    function init_key() {
      P = P_orig.slice();
      S = S_orig.slice();
    }
    function key(key) {
      let i;
      let koffp = new Int32Array([0]);
      let lr = new Int32Array([0, 0]);
      let plen = P.length, slen = S.length;
      for (i = 0; i < plen; i++) {
        P[i] = P[i] ^ streamtoword(key, koffp);
      }
      for (i = 0; i < plen; i += 2) {
        encipher(lr, 0);
        P[i] = lr[0];
        P[i + 1] = lr[1];
      }
      for (i = 0; i < slen; i += 2) {
        encipher(lr, 0);
        S[i] = lr[0];
        S[i + 1] = lr[1];
      }
    }
    function ekskey(data, key) {
      let i = 0;
      let koffp = new Int32Array([0]);
      let doffp = new Int32Array([0]);
      let lr = new Int32Array([0, 0]);
      let plen = P.length, slen = S.length;
      for (i = 0; i < plen; i++) {
        P[i] = P[i] ^ streamtoword(key, koffp);
      }
      for (i = 0; i < plen; i += 2) {
        lr[0] ^= streamtoword(data, doffp);
        lr[1] ^= streamtoword(data, doffp);
        encipher(lr, 0);
        P[i] = lr[0];
        P[i + 1] = lr[1];
      }
      for (i = 0; i < slen; i += 2) {
        lr[0] ^= streamtoword(data, doffp);
        lr[1] ^= streamtoword(data, doffp);
        encipher(lr, 0);
        S[i] = lr[0];
        S[i + 1] = lr[1];
      }
    }
    function crypt_raw(password, salt, log_rounds, cdata) {
      let rounds = 0;
      let i = 0;
      let j = 0;
      let clen = cdata.length;
      let ret;
      if (log_rounds < 4 || log_rounds > 30) {
        throw new Error("Bad number of rounds");
      }
      rounds = 1 << log_rounds;
      if (salt.length !== BCRYPT_SALT_LEN) {
        throw new Error("Bad salt length");
      }
      init_key();
      ekskey(salt, password);
      for (i = 0; i !== rounds; i++) {
        key(password);
        key(salt);
      }
      for (i = 0; i < 64; i++) {
        for (j = 0; j < clen >> 1; j++) {
          encipher(cdata, j << 1);
        }
      }
      ret = new Uint8Array(clen * 4);
      for (i = 0, j = 0; i < clen; i++) {
        ret[j++] = (cdata[i] >> 24) & 0xff;
        ret[j++] = (cdata[i] >> 16) & 0xff;
        ret[j++] = (cdata[i] >> 8) & 0xff;
        ret[j++] = cdata[i] & 0xff;
      }
      return ret;
    }
    function hashpw(password, salt = gensalt()) {
      let real_salt;
      let passwordb;
      let saltb;
      let hashed;
      let minor = "";
      let rounds = 0;
      let off = 0;
      let rs = [];
      if (salt.charAt(0) !== "$" || salt.charAt(1) !== "2") {
        throw new Error("Invalid salt version");
      }
      if (salt.charAt(2) === "$") {
        off = 3;
      } else {
        minor = salt.charAt(2);
        if (
          (minor.charCodeAt(0) >= "a".charCodeAt(0) &&
            minor.charCodeAt(0) >= "z".charCodeAt(0)) ||
          salt.charAt(3) !== "$"
        ) {
          throw new Error("Invalid salt revision");
        }
        off = 4;
      }
      // Extract number of rounds
      if (salt.charAt(off + 2) > "$") {
        throw new Error("Missing salt rounds");
      }
      rounds = parseInt(salt.substring(off, off + 2));
      real_salt = salt.substring(off + 3, off + 25);
      passwordb = utf8_ts_6.encode(
        password + (minor.charCodeAt(0) >= "a".charCodeAt(0) ? "\u0000" : ""),
      );
      saltb = base64.decode(real_salt, BCRYPT_SALT_LEN);
      hashed = crypt_raw(passwordb, saltb, rounds, bf_crypt_ciphertext.slice());
      rs.push("$2");
      if (minor.charCodeAt(0) >= "a".charCodeAt(0)) {
        rs.push(minor);
      }
      rs.push("$");
      if (rounds < 10) {
        rs.push("0");
      }
      if (rounds > 30) {
        throw new Error("rounds exceeds maximum (30)");
      }
      rs.push(rounds.toString());
      rs.push("$");
      rs.push(base64.encode(saltb, saltb.length));
      rs.push(base64.encode(hashed, bf_crypt_ciphertext.length * 4 - 1));
      return rs.join("");
    }
    exports_114("hashpw", hashpw);
    function gensalt(log_rounds = GENSALT_DEFAULT_LOG2_ROUNDS) {
      let rs = [];
      let rnd = new Uint8Array(BCRYPT_SALT_LEN);
      crypto.getRandomValues(rnd);
      rs.push("$2a$");
      if (log_rounds < 10) {
        rs.push("0");
      }
      if (log_rounds > 30) {
        throw new Error("log_rounds exceeds maximum (30)");
      }
      rs.push(log_rounds.toString());
      rs.push("$");
      rs.push(base64.encode(rnd, rnd.length));
      return rs.join("");
    }
    exports_114("gensalt", gensalt);
    function checkpw(plaintext, hashed) {
      let hashed_bytes;
      let try_bytes;
      let try_pw = hashpw(plaintext, hashed);
      hashed_bytes = utf8_ts_6.encode(hashed);
      try_bytes = utf8_ts_6.encode(try_pw);
      if (hashed_bytes.length !== try_bytes.length) {
        return false;
      }
      let ret = 0;
      for (let i = 0; i < try_bytes.length; i++) {
        ret |= hashed_bytes[i] ^ try_bytes[i];
      }
      return ret === 0;
    }
    exports_114("checkpw", checkpw);
    return {
      setters: [
        function (utf8_ts_6_1) {
          utf8_ts_6 = utf8_ts_6_1;
        },
        function (base64_1) {
          base64 = base64_1;
        },
      ],
      execute: function () {
        crypto = globalThis.crypto;
        // BCrypt parameters
        GENSALT_DEFAULT_LOG2_ROUNDS = 10;
        BCRYPT_SALT_LEN = 16;
        // Blowfish parameters
        BLOWFISH_NUM_ROUNDS = 16;
        P_orig = new Int32Array([
          0x243f6a88,
          0x85a308d3,
          0x13198a2e,
          0x03707344,
          0xa4093822,
          0x299f31d0,
          0x082efa98,
          0xec4e6c89,
          0x452821e6,
          0x38d01377,
          0xbe5466cf,
          0x34e90c6c,
          0xc0ac29b7,
          0xc97c50dd,
          0x3f84d5b5,
          0xb5470917,
          0x9216d5d9,
          0x8979fb1b,
        ]);
        S_orig = new Int32Array([
          0xd1310ba6,
          0x98dfb5ac,
          0x2ffd72db,
          0xd01adfb7,
          0xb8e1afed,
          0x6a267e96,
          0xba7c9045,
          0xf12c7f99,
          0x24a19947,
          0xb3916cf7,
          0x0801f2e2,
          0x858efc16,
          0x636920d8,
          0x71574e69,
          0xa458fea3,
          0xf4933d7e,
          0x0d95748f,
          0x728eb658,
          0x718bcd58,
          0x82154aee,
          0x7b54a41d,
          0xc25a59b5,
          0x9c30d539,
          0x2af26013,
          0xc5d1b023,
          0x286085f0,
          0xca417918,
          0xb8db38ef,
          0x8e79dcb0,
          0x603a180e,
          0x6c9e0e8b,
          0xb01e8a3e,
          0xd71577c1,
          0xbd314b27,
          0x78af2fda,
          0x55605c60,
          0xe65525f3,
          0xaa55ab94,
          0x57489862,
          0x63e81440,
          0x55ca396a,
          0x2aab10b6,
          0xb4cc5c34,
          0x1141e8ce,
          0xa15486af,
          0x7c72e993,
          0xb3ee1411,
          0x636fbc2a,
          0x2ba9c55d,
          0x741831f6,
          0xce5c3e16,
          0x9b87931e,
          0xafd6ba33,
          0x6c24cf5c,
          0x7a325381,
          0x28958677,
          0x3b8f4898,
          0x6b4bb9af,
          0xc4bfe81b,
          0x66282193,
          0x61d809cc,
          0xfb21a991,
          0x487cac60,
          0x5dec8032,
          0xef845d5d,
          0xe98575b1,
          0xdc262302,
          0xeb651b88,
          0x23893e81,
          0xd396acc5,
          0x0f6d6ff3,
          0x83f44239,
          0x2e0b4482,
          0xa4842004,
          0x69c8f04a,
          0x9e1f9b5e,
          0x21c66842,
          0xf6e96c9a,
          0x670c9c61,
          0xabd388f0,
          0x6a51a0d2,
          0xd8542f68,
          0x960fa728,
          0xab5133a3,
          0x6eef0b6c,
          0x137a3be4,
          0xba3bf050,
          0x7efb2a98,
          0xa1f1651d,
          0x39af0176,
          0x66ca593e,
          0x82430e88,
          0x8cee8619,
          0x456f9fb4,
          0x7d84a5c3,
          0x3b8b5ebe,
          0xe06f75d8,
          0x85c12073,
          0x401a449f,
          0x56c16aa6,
          0x4ed3aa62,
          0x363f7706,
          0x1bfedf72,
          0x429b023d,
          0x37d0d724,
          0xd00a1248,
          0xdb0fead3,
          0x49f1c09b,
          0x075372c9,
          0x80991b7b,
          0x25d479d8,
          0xf6e8def7,
          0xe3fe501a,
          0xb6794c3b,
          0x976ce0bd,
          0x04c006ba,
          0xc1a94fb6,
          0x409f60c4,
          0x5e5c9ec2,
          0x196a2463,
          0x68fb6faf,
          0x3e6c53b5,
          0x1339b2eb,
          0x3b52ec6f,
          0x6dfc511f,
          0x9b30952c,
          0xcc814544,
          0xaf5ebd09,
          0xbee3d004,
          0xde334afd,
          0x660f2807,
          0x192e4bb3,
          0xc0cba857,
          0x45c8740f,
          0xd20b5f39,
          0xb9d3fbdb,
          0x5579c0bd,
          0x1a60320a,
          0xd6a100c6,
          0x402c7279,
          0x679f25fe,
          0xfb1fa3cc,
          0x8ea5e9f8,
          0xdb3222f8,
          0x3c7516df,
          0xfd616b15,
          0x2f501ec8,
          0xad0552ab,
          0x323db5fa,
          0xfd238760,
          0x53317b48,
          0x3e00df82,
          0x9e5c57bb,
          0xca6f8ca0,
          0x1a87562e,
          0xdf1769db,
          0xd542a8f6,
          0x287effc3,
          0xac6732c6,
          0x8c4f5573,
          0x695b27b0,
          0xbbca58c8,
          0xe1ffa35d,
          0xb8f011a0,
          0x10fa3d98,
          0xfd2183b8,
          0x4afcb56c,
          0x2dd1d35b,
          0x9a53e479,
          0xb6f84565,
          0xd28e49bc,
          0x4bfb9790,
          0xe1ddf2da,
          0xa4cb7e33,
          0x62fb1341,
          0xcee4c6e8,
          0xef20cada,
          0x36774c01,
          0xd07e9efe,
          0x2bf11fb4,
          0x95dbda4d,
          0xae909198,
          0xeaad8e71,
          0x6b93d5a0,
          0xd08ed1d0,
          0xafc725e0,
          0x8e3c5b2f,
          0x8e7594b7,
          0x8ff6e2fb,
          0xf2122b64,
          0x8888b812,
          0x900df01c,
          0x4fad5ea0,
          0x688fc31c,
          0xd1cff191,
          0xb3a8c1ad,
          0x2f2f2218,
          0xbe0e1777,
          0xea752dfe,
          0x8b021fa1,
          0xe5a0cc0f,
          0xb56f74e8,
          0x18acf3d6,
          0xce89e299,
          0xb4a84fe0,
          0xfd13e0b7,
          0x7cc43b81,
          0xd2ada8d9,
          0x165fa266,
          0x80957705,
          0x93cc7314,
          0x211a1477,
          0xe6ad2065,
          0x77b5fa86,
          0xc75442f5,
          0xfb9d35cf,
          0xebcdaf0c,
          0x7b3e89a0,
          0xd6411bd3,
          0xae1e7e49,
          0x00250e2d,
          0x2071b35e,
          0x226800bb,
          0x57b8e0af,
          0x2464369b,
          0xf009b91e,
          0x5563911d,
          0x59dfa6aa,
          0x78c14389,
          0xd95a537f,
          0x207d5ba2,
          0x02e5b9c5,
          0x83260376,
          0x6295cfa9,
          0x11c81968,
          0x4e734a41,
          0xb3472dca,
          0x7b14a94a,
          0x1b510052,
          0x9a532915,
          0xd60f573f,
          0xbc9bc6e4,
          0x2b60a476,
          0x81e67400,
          0x08ba6fb5,
          0x571be91f,
          0xf296ec6b,
          0x2a0dd915,
          0xb6636521,
          0xe7b9f9b6,
          0xff34052e,
          0xc5855664,
          0x53b02d5d,
          0xa99f8fa1,
          0x08ba4799,
          0x6e85076a,
          0x4b7a70e9,
          0xb5b32944,
          0xdb75092e,
          0xc4192623,
          0xad6ea6b0,
          0x49a7df7d,
          0x9cee60b8,
          0x8fedb266,
          0xecaa8c71,
          0x699a17ff,
          0x5664526c,
          0xc2b19ee1,
          0x193602a5,
          0x75094c29,
          0xa0591340,
          0xe4183a3e,
          0x3f54989a,
          0x5b429d65,
          0x6b8fe4d6,
          0x99f73fd6,
          0xa1d29c07,
          0xefe830f5,
          0x4d2d38e6,
          0xf0255dc1,
          0x4cdd2086,
          0x8470eb26,
          0x6382e9c6,
          0x021ecc5e,
          0x09686b3f,
          0x3ebaefc9,
          0x3c971814,
          0x6b6a70a1,
          0x687f3584,
          0x52a0e286,
          0xb79c5305,
          0xaa500737,
          0x3e07841c,
          0x7fdeae5c,
          0x8e7d44ec,
          0x5716f2b8,
          0xb03ada37,
          0xf0500c0d,
          0xf01c1f04,
          0x0200b3ff,
          0xae0cf51a,
          0x3cb574b2,
          0x25837a58,
          0xdc0921bd,
          0xd19113f9,
          0x7ca92ff6,
          0x94324773,
          0x22f54701,
          0x3ae5e581,
          0x37c2dadc,
          0xc8b57634,
          0x9af3dda7,
          0xa9446146,
          0x0fd0030e,
          0xecc8c73e,
          0xa4751e41,
          0xe238cd99,
          0x3bea0e2f,
          0x3280bba1,
          0x183eb331,
          0x4e548b38,
          0x4f6db908,
          0x6f420d03,
          0xf60a04bf,
          0x2cb81290,
          0x24977c79,
          0x5679b072,
          0xbcaf89af,
          0xde9a771f,
          0xd9930810,
          0xb38bae12,
          0xdccf3f2e,
          0x5512721f,
          0x2e6b7124,
          0x501adde6,
          0x9f84cd87,
          0x7a584718,
          0x7408da17,
          0xbc9f9abc,
          0xe94b7d8c,
          0xec7aec3a,
          0xdb851dfa,
          0x63094366,
          0xc464c3d2,
          0xef1c1847,
          0x3215d908,
          0xdd433b37,
          0x24c2ba16,
          0x12a14d43,
          0x2a65c451,
          0x50940002,
          0x133ae4dd,
          0x71dff89e,
          0x10314e55,
          0x81ac77d6,
          0x5f11199b,
          0x043556f1,
          0xd7a3c76b,
          0x3c11183b,
          0x5924a509,
          0xf28fe6ed,
          0x97f1fbfa,
          0x9ebabf2c,
          0x1e153c6e,
          0x86e34570,
          0xeae96fb1,
          0x860e5e0a,
          0x5a3e2ab3,
          0x771fe71c,
          0x4e3d06fa,
          0x2965dcb9,
          0x99e71d0f,
          0x803e89d6,
          0x5266c825,
          0x2e4cc978,
          0x9c10b36a,
          0xc6150eba,
          0x94e2ea78,
          0xa5fc3c53,
          0x1e0a2df4,
          0xf2f74ea7,
          0x361d2b3d,
          0x1939260f,
          0x19c27960,
          0x5223a708,
          0xf71312b6,
          0xebadfe6e,
          0xeac31f66,
          0xe3bc4595,
          0xa67bc883,
          0xb17f37d1,
          0x018cff28,
          0xc332ddef,
          0xbe6c5aa5,
          0x65582185,
          0x68ab9802,
          0xeecea50f,
          0xdb2f953b,
          0x2aef7dad,
          0x5b6e2f84,
          0x1521b628,
          0x29076170,
          0xecdd4775,
          0x619f1510,
          0x13cca830,
          0xeb61bd96,
          0x0334fe1e,
          0xaa0363cf,
          0xb5735c90,
          0x4c70a239,
          0xd59e9e0b,
          0xcbaade14,
          0xeecc86bc,
          0x60622ca7,
          0x9cab5cab,
          0xb2f3846e,
          0x648b1eaf,
          0x19bdf0ca,
          0xa02369b9,
          0x655abb50,
          0x40685a32,
          0x3c2ab4b3,
          0x319ee9d5,
          0xc021b8f7,
          0x9b540b19,
          0x875fa099,
          0x95f7997e,
          0x623d7da8,
          0xf837889a,
          0x97e32d77,
          0x11ed935f,
          0x16681281,
          0x0e358829,
          0xc7e61fd6,
          0x96dedfa1,
          0x7858ba99,
          0x57f584a5,
          0x1b227263,
          0x9b83c3ff,
          0x1ac24696,
          0xcdb30aeb,
          0x532e3054,
          0x8fd948e4,
          0x6dbc3128,
          0x58ebf2ef,
          0x34c6ffea,
          0xfe28ed61,
          0xee7c3c73,
          0x5d4a14d9,
          0xe864b7e3,
          0x42105d14,
          0x203e13e0,
          0x45eee2b6,
          0xa3aaabea,
          0xdb6c4f15,
          0xfacb4fd0,
          0xc742f442,
          0xef6abbb5,
          0x654f3b1d,
          0x41cd2105,
          0xd81e799e,
          0x86854dc7,
          0xe44b476a,
          0x3d816250,
          0xcf62a1f2,
          0x5b8d2646,
          0xfc8883a0,
          0xc1c7b6a3,
          0x7f1524c3,
          0x69cb7492,
          0x47848a0b,
          0x5692b285,
          0x095bbf00,
          0xad19489d,
          0x1462b174,
          0x23820e00,
          0x58428d2a,
          0x0c55f5ea,
          0x1dadf43e,
          0x233f7061,
          0x3372f092,
          0x8d937e41,
          0xd65fecf1,
          0x6c223bdb,
          0x7cde3759,
          0xcbee7460,
          0x4085f2a7,
          0xce77326e,
          0xa6078084,
          0x19f8509e,
          0xe8efd855,
          0x61d99735,
          0xa969a7aa,
          0xc50c06c2,
          0x5a04abfc,
          0x800bcadc,
          0x9e447a2e,
          0xc3453484,
          0xfdd56705,
          0x0e1e9ec9,
          0xdb73dbd3,
          0x105588cd,
          0x675fda79,
          0xe3674340,
          0xc5c43465,
          0x713e38d8,
          0x3d28f89e,
          0xf16dff20,
          0x153e21e7,
          0x8fb03d4a,
          0xe6e39f2b,
          0xdb83adf7,
          0xe93d5a68,
          0x948140f7,
          0xf64c261c,
          0x94692934,
          0x411520f7,
          0x7602d4f7,
          0xbcf46b2e,
          0xd4a20068,
          0xd4082471,
          0x3320f46a,
          0x43b7d4b7,
          0x500061af,
          0x1e39f62e,
          0x97244546,
          0x14214f74,
          0xbf8b8840,
          0x4d95fc1d,
          0x96b591af,
          0x70f4ddd3,
          0x66a02f45,
          0xbfbc09ec,
          0x03bd9785,
          0x7fac6dd0,
          0x31cb8504,
          0x96eb27b3,
          0x55fd3941,
          0xda2547e6,
          0xabca0a9a,
          0x28507825,
          0x530429f4,
          0x0a2c86da,
          0xe9b66dfb,
          0x68dc1462,
          0xd7486900,
          0x680ec0a4,
          0x27a18dee,
          0x4f3ffea2,
          0xe887ad8c,
          0xb58ce006,
          0x7af4d6b6,
          0xaace1e7c,
          0xd3375fec,
          0xce78a399,
          0x406b2a42,
          0x20fe9e35,
          0xd9f385b9,
          0xee39d7ab,
          0x3b124e8b,
          0x1dc9faf7,
          0x4b6d1856,
          0x26a36631,
          0xeae397b2,
          0x3a6efa74,
          0xdd5b4332,
          0x6841e7f7,
          0xca7820fb,
          0xfb0af54e,
          0xd8feb397,
          0x454056ac,
          0xba489527,
          0x55533a3a,
          0x20838d87,
          0xfe6ba9b7,
          0xd096954b,
          0x55a867bc,
          0xa1159a58,
          0xcca92963,
          0x99e1db33,
          0xa62a4a56,
          0x3f3125f9,
          0x5ef47e1c,
          0x9029317c,
          0xfdf8e802,
          0x04272f70,
          0x80bb155c,
          0x05282ce3,
          0x95c11548,
          0xe4c66d22,
          0x48c1133f,
          0xc70f86dc,
          0x07f9c9ee,
          0x41041f0f,
          0x404779a4,
          0x5d886e17,
          0x325f51eb,
          0xd59bc0d1,
          0xf2bcc18f,
          0x41113564,
          0x257b7834,
          0x602a9c60,
          0xdff8e8a3,
          0x1f636c1b,
          0x0e12b4c2,
          0x02e1329e,
          0xaf664fd1,
          0xcad18115,
          0x6b2395e0,
          0x333e92e1,
          0x3b240b62,
          0xeebeb922,
          0x85b2a20e,
          0xe6ba0d99,
          0xde720c8c,
          0x2da2f728,
          0xd0127845,
          0x95b794fd,
          0x647d0862,
          0xe7ccf5f0,
          0x5449a36f,
          0x877d48fa,
          0xc39dfd27,
          0xf33e8d1e,
          0x0a476341,
          0x992eff74,
          0x3a6f6eab,
          0xf4f8fd37,
          0xa812dc60,
          0xa1ebddf8,
          0x991be14c,
          0xdb6e6b0d,
          0xc67b5510,
          0x6d672c37,
          0x2765d43b,
          0xdcd0e804,
          0xf1290dc7,
          0xcc00ffa3,
          0xb5390f92,
          0x690fed0b,
          0x667b9ffb,
          0xcedb7d9c,
          0xa091cf0b,
          0xd9155ea3,
          0xbb132f88,
          0x515bad24,
          0x7b9479bf,
          0x763bd6eb,
          0x37392eb3,
          0xcc115979,
          0x8026e297,
          0xf42e312d,
          0x6842ada7,
          0xc66a2b3b,
          0x12754ccc,
          0x782ef11c,
          0x6a124237,
          0xb79251e7,
          0x06a1bbe6,
          0x4bfb6350,
          0x1a6b1018,
          0x11caedfa,
          0x3d25bdd8,
          0xe2e1c3c9,
          0x44421659,
          0x0a121386,
          0xd90cec6e,
          0xd5abea2a,
          0x64af674e,
          0xda86a85f,
          0xbebfe988,
          0x64e4c3fe,
          0x9dbc8057,
          0xf0f7c086,
          0x60787bf8,
          0x6003604d,
          0xd1fd8346,
          0xf6381fb0,
          0x7745ae04,
          0xd736fccc,
          0x83426b33,
          0xf01eab71,
          0xb0804187,
          0x3c005e5f,
          0x77a057be,
          0xbde8ae24,
          0x55464299,
          0xbf582e61,
          0x4e58f48f,
          0xf2ddfda2,
          0xf474ef38,
          0x8789bdc2,
          0x5366f9c3,
          0xc8b38e74,
          0xb475f255,
          0x46fcd9b9,
          0x7aeb2661,
          0x8b1ddf84,
          0x846a0e79,
          0x915f95e2,
          0x466e598e,
          0x20b45770,
          0x8cd55591,
          0xc902de4c,
          0xb90bace1,
          0xbb8205d0,
          0x11a86248,
          0x7574a99e,
          0xb77f19b6,
          0xe0a9dc09,
          0x662d09a1,
          0xc4324633,
          0xe85a1f02,
          0x09f0be8c,
          0x4a99a025,
          0x1d6efe10,
          0x1ab93d1d,
          0x0ba5a4df,
          0xa186f20f,
          0x2868f169,
          0xdcb7da83,
          0x573906fe,
          0xa1e2ce9b,
          0x4fcd7f52,
          0x50115e01,
          0xa70683fa,
          0xa002b5c4,
          0x0de6d027,
          0x9af88c27,
          0x773f8641,
          0xc3604c06,
          0x61a806b5,
          0xf0177a28,
          0xc0f586e0,
          0x006058aa,
          0x30dc7d62,
          0x11e69ed7,
          0x2338ea63,
          0x53c2dd94,
          0xc2c21634,
          0xbbcbee56,
          0x90bcb6de,
          0xebfc7da1,
          0xce591d76,
          0x6f05e409,
          0x4b7c0188,
          0x39720a3d,
          0x7c927c24,
          0x86e3725f,
          0x724d9db9,
          0x1ac15bb4,
          0xd39eb8fc,
          0xed545578,
          0x08fca5b5,
          0xd83d7cd3,
          0x4dad0fc4,
          0x1e50ef5e,
          0xb161e6f8,
          0xa28514d9,
          0x6c51133c,
          0x6fd5c7e7,
          0x56e14ec4,
          0x362abfce,
          0xddc6c837,
          0xd79a3234,
          0x92638212,
          0x670efa8e,
          0x406000e0,
          0x3a39ce37,
          0xd3faf5cf,
          0xabc27737,
          0x5ac52d1b,
          0x5cb0679e,
          0x4fa33742,
          0xd3822740,
          0x99bc9bbe,
          0xd5118e9d,
          0xbf0f7315,
          0xd62d1c7e,
          0xc700c47b,
          0xb78c1b6b,
          0x21a19045,
          0xb26eb1be,
          0x6a366eb4,
          0x5748ab2f,
          0xbc946e79,
          0xc6a376d2,
          0x6549c2c8,
          0x530ff8ee,
          0x468dde7d,
          0xd5730a1d,
          0x4cd04dc6,
          0x2939bbdb,
          0xa9ba4650,
          0xac9526e8,
          0xbe5ee304,
          0xa1fad5f0,
          0x6a2d519a,
          0x63ef8ce2,
          0x9a86ee22,
          0xc089c2b8,
          0x43242ef6,
          0xa51e03aa,
          0x9cf2d0a4,
          0x83c061ba,
          0x9be96a4d,
          0x8fe51550,
          0xba645bd6,
          0x2826a2f9,
          0xa73a3ae1,
          0x4ba99586,
          0xef5562e9,
          0xc72fefd3,
          0xf752f7da,
          0x3f046f69,
          0x77fa0a59,
          0x80e4a915,
          0x87b08601,
          0x9b09e6ad,
          0x3b3ee593,
          0xe990fd5a,
          0x9e34d797,
          0x2cf0b7d9,
          0x022b8b51,
          0x96d5ac3a,
          0x017da67d,
          0xd1cf3ed6,
          0x7c7d2d28,
          0x1f9f25cf,
          0xadf2b89b,
          0x5ad6b472,
          0x5a88f54c,
          0xe029ac71,
          0xe019a5e6,
          0x47b0acfd,
          0xed93fa9b,
          0xe8d3c48d,
          0x283b57cc,
          0xf8d56629,
          0x79132e28,
          0x785f0191,
          0xed756055,
          0xf7960e44,
          0xe3d35e8c,
          0x15056dd4,
          0x88f46dba,
          0x03a16125,
          0x0564f0bd,
          0xc3eb9e15,
          0x3c9057a2,
          0x97271aec,
          0xa93a072a,
          0x1b3f6d9b,
          0x1e6321f5,
          0xf59c66fb,
          0x26dcf319,
          0x7533d928,
          0xb155fdf5,
          0x03563482,
          0x8aba3cbb,
          0x28517711,
          0xc20ad9f8,
          0xabcc5167,
          0xccad925f,
          0x4de81751,
          0x3830dc8e,
          0x379d5862,
          0x9320f991,
          0xea7a90c2,
          0xfb3e7bce,
          0x5121ce64,
          0x774fbe32,
          0xa8b6e37e,
          0xc3293d46,
          0x48de5369,
          0x6413e680,
          0xa2ae0810,
          0xdd6db224,
          0x69852dfd,
          0x09072166,
          0xb39a460a,
          0x6445c0dd,
          0x586cdecf,
          0x1c20c8ae,
          0x5bbef7dd,
          0x1b588d40,
          0xccd2017f,
          0x6bb4e3bb,
          0xdda26a7e,
          0x3a59ff45,
          0x3e350a44,
          0xbcb4cdd5,
          0x72eacea8,
          0xfa6484bb,
          0x8d6612ae,
          0xbf3c6f47,
          0xd29be463,
          0x542f5d9e,
          0xaec2771b,
          0xf64e6370,
          0x740e0d8d,
          0xe75b1357,
          0xf8721671,
          0xaf537d5d,
          0x4040cb08,
          0x4eb4e2cc,
          0x34d2466a,
          0x0115af84,
          0xe1b00428,
          0x95983a1d,
          0x06b89fb4,
          0xce6ea048,
          0x6f3f3b82,
          0x3520ab82,
          0x011a1d4b,
          0x277227f8,
          0x611560b1,
          0xe7933fdc,
          0xbb3a792b,
          0x344525bd,
          0xa08839e1,
          0x51ce794b,
          0x2f32c9b7,
          0xa01fbac9,
          0xe01cc87e,
          0xbcc7d1f6,
          0xcf0111c3,
          0xa1e8aac7,
          0x1a908749,
          0xd44fbd9a,
          0xd0dadecb,
          0xd50ada38,
          0x0339c32a,
          0xc6913667,
          0x8df9317c,
          0xe0b12b4f,
          0xf79e59b7,
          0x43f5bb3a,
          0xf2d519ff,
          0x27d9459c,
          0xbf97222c,
          0x15e6fc2a,
          0x0f91fc71,
          0x9b941525,
          0xfae59361,
          0xceb69ceb,
          0xc2a86459,
          0x12baa8d1,
          0xb6c1075e,
          0xe3056a0c,
          0x10d25065,
          0xcb03a442,
          0xe0ec6e0e,
          0x1698db3b,
          0x4c98a0be,
          0x3278e964,
          0x9f1f9532,
          0xe0d392df,
          0xd3a0342b,
          0x8971f21e,
          0x1b0a7441,
          0x4ba3348c,
          0xc5be7120,
          0xc37632d8,
          0xdf359f8d,
          0x9b992f2e,
          0xe60b6f47,
          0x0fe3f11d,
          0xe54cda54,
          0x1edad891,
          0xce6279cf,
          0xcd3e7e6f,
          0x1618b166,
          0xfd2c1d05,
          0x848fd2c5,
          0xf6fb2299,
          0xf523f357,
          0xa6327623,
          0x93a83531,
          0x56cccd02,
          0xacf08162,
          0x5a75ebb5,
          0x6e163697,
          0x88d273cc,
          0xde966292,
          0x81b949d0,
          0x4c50901b,
          0x71c65614,
          0xe6c6c7bd,
          0x327a140a,
          0x45e1d006,
          0xc3f27b9a,
          0xc9aa53fd,
          0x62a80f00,
          0xbb25bfe2,
          0x35bdd2f6,
          0x71126905,
          0xb2040222,
          0xb6cbcf7c,
          0xcd769c2b,
          0x53113ec0,
          0x1640e3d3,
          0x38abbd60,
          0x2547adf0,
          0xba38209c,
          0xf746ce76,
          0x77afa1c5,
          0x20756060,
          0x85cbfe4e,
          0x8ae88dd8,
          0x7aaaf9b0,
          0x4cf9aa7e,
          0x1948c25c,
          0x02fb8a8c,
          0x01c36ae4,
          0xd6ebe1f9,
          0x90d4f869,
          0xa65cdea0,
          0x3f09252d,
          0xc208e69f,
          0xb74e6132,
          0xce77e25b,
          0x578fdfe3,
          0x3ac372e6,
        ]);
        // bcrypt IV: "OrpheanBeholderScryDoubt". The C implementation calls
        // this "ciphertext", but it is really plaintext or an IV. We keep
        // the name to make code comparison easier.
        bf_crypt_ciphertext = new Int32Array([
          0x4f727068,
          0x65616e42,
          0x65686f6c,
          0x64657253,
          0x63727944,
          0x6f756274,
        ]);
      },
    };
  },
);
System.register(
  "https://deno.land/x/bcrypt/main",
  ["https://deno.land/x/bcrypt/bcrypt/bcrypt"],
  function (exports_115, context_115) {
    "use strict";
    var bcrypt;
    var __moduleName = context_115 && context_115.id;
    /**
     * Generate a hash for the plaintext password
     * Requires --allow-net and --unstable flags
     *
     * @export
     * @param {string} plaintext The password to hash
     * @param {(string | undefined)} [salt=undefined] The salt to use when hashing. Recommended to leave this undefined.
     * @returns {Promise<string>} The hashed password
     */
    async function hash(plaintext, salt = undefined) {
      let worker = new Worker(
        new URL("worker.ts", context_115.meta.url).toString(),
        { type: "module", deno: true },
      );
      worker.postMessage({
        action: "hash",
        payload: {
          plaintext,
          salt,
        },
      });
      return new Promise((resolve) => {
        worker.onmessage = (event) => {
          resolve(event.data);
          worker.terminate();
        };
      });
    }
    exports_115("hash", hash);
    /**
     * Generates a salt using a number of log rounds
     * Requires --allow-net and --unstable flags
     *
     * @export
     * @param {(number | undefined)} [log_rounds=undefined] Number of log rounds to use. Recommended to leave this undefined.
     * @returns {Promise<string>} The generated salt
     */
    async function genSalt(log_rounds = undefined) {
      let worker = new Worker(
        new URL("worker.ts", context_115.meta.url).toString(),
        { type: "module", deno: true },
      );
      worker.postMessage({
        action: "genSalt",
        payload: {
          log_rounds,
        },
      });
      return new Promise((resolve) => {
        worker.onmessage = (event) => {
          resolve(event.data);
          worker.terminate();
        };
      });
    }
    exports_115("genSalt", genSalt);
    /**
     * Check if a plaintext password matches a hash
     * Requires --allow-net and --unstable flags
     *
     * @export
     * @param {string} plaintext The plaintext password to check
     * @param {string} hash The hash to compare to
     * @returns {Promise<boolean>} Whether the password matches the hash
     */
    async function compare(plaintext, hash) {
      let worker = new Worker(
        new URL("worker.ts", context_115.meta.url).toString(),
        { type: "module", deno: true },
      );
      worker.postMessage({
        action: "compare",
        payload: {
          plaintext,
          hash,
        },
      });
      return new Promise((resolve) => {
        worker.onmessage = (event) => {
          resolve(event.data);
          worker.terminate();
        };
      });
    }
    exports_115("compare", compare);
    /**
     * Check if a plaintext password matches a hash
     * This function is blocking and computationally expensive but requires no additonal flags.
     * Using the async variant is highly recommended.
     *
     * @export
     * @param {string} plaintext The plaintext password to check
     * @param {string} hash The hash to compare to
     * @returns {boolean} Whether the password matches the hash
     */
    function compareSync(plaintext, hash) {
      try {
        return bcrypt.checkpw(plaintext, hash);
      } catch {
        return false;
      }
    }
    exports_115("compareSync", compareSync);
    /**
     * Generates a salt using a number of log rounds
     * This function is blocking and computationally expensive but requires no additonal flags.
     * Using the async variant is highly recommended.
     *
     * @export
     * @param {(number | undefined)} [log_rounds=undefined] Number of log rounds to use. Recommended to leave this undefined.
     * @returns {string} The generated salt
     */
    function genSaltSync(log_rounds = undefined) {
      return bcrypt.gensalt(log_rounds);
    }
    exports_115("genSaltSync", genSaltSync);
    /**
     * Generate a hash for the plaintext password
     * This function is blocking and computationally expensive but requires no additonal flags.
     * Using the async variant is highly recommended.
     *
     * @export
     * @param {string} plaintext The password to hash
     * @param {(string | undefined)} [salt=undefined] The salt to use when hashing. Recommended to leave this undefined.
     * @returns {string} The hashed password
     */
    function hashSync(plaintext, salt = undefined) {
      return bcrypt.hashpw(plaintext, salt);
    }
    exports_115("hashSync", hashSync);
    return {
      setters: [
        function (bcrypt_1) {
          bcrypt = bcrypt_1;
        },
      ],
      execute: function () {
      },
    };
  },
);
System.register(
  "https://deno.land/x/bcrypt/mod",
  ["https://deno.land/x/bcrypt/main"],
  function (exports_116, context_116) {
    "use strict";
    var __moduleName = context_116 && context_116.id;
    return {
      setters: [
        function (main_ts_1_1) {
          exports_116({
            "genSalt": main_ts_1_1["genSalt"],
            "compare": main_ts_1_1["compare"],
            "hash": main_ts_1_1["hash"],
            "genSaltSync": main_ts_1_1["genSaltSync"],
            "compareSync": main_ts_1_1["compareSync"],
            "hashSync": main_ts_1_1["hashSync"],
          });
        },
      ],
      execute: function () {
      },
    };
  },
);
System.register(
  "file:///C:/Users/danst/OneDrive/Documents/webdev/miscellaneous/Goals/goals-be/controllers/usersAdv",
  [
    "https://deno.land/x/postgres/mod",
    "https://deno.land/x/bcrypt/mod",
    "file:///C:/Users/danst/OneDrive/Documents/webdev/miscellaneous/Goals/goals-be/config",
  ],
  function (exports_117, context_117) {
    "use strict";
    var mod_ts_12, bcrypt, config_ts_2, client, signIn, signUp, forgotPassword;
    var __moduleName = context_117 && context_117.id;
    return {
      setters: [
        function (mod_ts_12_1) {
          mod_ts_12 = mod_ts_12_1;
        },
        function (bcrypt_2) {
          bcrypt = bcrypt_2;
        },
        function (config_ts_2_1) {
          config_ts_2 = config_ts_2_1;
        },
      ],
      execute: function () {
        //init client
        client = new mod_ts_12.Client(config_ts_2.dbCreds);
        signIn = async ({ request, response }) => {
          const body = await request.body();
          console.log(request);
          if (!request.hasBody) {
            response.status = 404;
            response.body = {
              success: false,
              msg: "no data",
            };
          } else {
            try {
              await client.connect();
              const { email, password } = body.value;
              const result = await client.query(
                `SELECT * FROM users WHERE email = '${email}'`,
              );
              if (result.rows.toString() === "") {
                response.status = 404;
                response.body = {
                  success: false,
                  msg: `no user with email ${email} found`,
                };
                return;
              } else {
                const user = new Object();
                result.rows.map((p) => {
                  result.rowDescription.columns.map((el, i) => {
                    user[el.name] = p[i];
                  });
                });
                const comp = await bcrypt.compare(password, user.password);
                if (comp) {
                  response.body = {
                    success: true,
                    data: user,
                  };
                } else {
                  response.status = 403;
                  response.body = {
                    success: false,
                    msg: "Wrong password",
                  };
                }
              }
            } catch (err) {
              response.status = 500;
              response.body = {
                success: false,
                msg: err.toString(),
              };
            } finally {
              await client.end();
            }
          }
        };
        exports_117("signIn", signIn);
        signUp = async ({ request, response }) => {
          const body = await request.body();
          const user = body.value;
          const hash = bcrypt.hashSync(user.password);
          if (!request.hasBody) {
            console.log("aint no body");
            response.status = 404;
            response.body = {
              success: false,
              msg: "no data",
            };
          } else {
            try {
              await client.connect();
              const search = await client.query(
                `SELECT * FROM users WHERE email = '${user.email}'`,
              );
              //check if user already in DB
              if (search.rows.toString() === "") {
                const result = await client.query(
                  `INSERT INTO users(name, email, birthday, password)
        VALUES('${user.name}', '${user.email}','${user.birthday}','${hash}')`,
                );
                response.status = 201;
                response.body = {
                  success: true,
                  data: user,
                };
              } else {
                response.status = 409;
                response.body = {
                  data: {
                    msg:
                      "Sorry Bud, that email is already being used by someone",
                  },
                };
              }
              return;
            } catch (err) {
              response.status = 500;
              response.body = {
                success: false,
                msg: err.toString(),
              };
            } finally {
              await client.end();
            }
          }
        };
        exports_117("signUp", signUp);
        forgotPassword = null;
        exports_117("forgotPassword", forgotPassword);
      },
    };
  },
);
System.register(
  "file:///C:/Users/danst/OneDrive/Documents/webdev/miscellaneous/Goals/goals-be/routes/users",
  [
    "https://deno.land/x/oak/mod",
    "file:///C:/Users/danst/OneDrive/Documents/webdev/miscellaneous/Goals/goals-be/controllers/users",
    "file:///C:/Users/danst/OneDrive/Documents/webdev/miscellaneous/Goals/goals-be/controllers/usersAdv",
  ],
  function (exports_118, context_118) {
    "use strict";
    var mod_ts_13, users_ts_1, usersAdv_ts_1, userRouter;
    var __moduleName = context_118 && context_118.id;
    return {
      setters: [
        function (mod_ts_13_1) {
          mod_ts_13 = mod_ts_13_1;
        },
        function (users_ts_1_1) {
          users_ts_1 = users_ts_1_1;
        },
        function (usersAdv_ts_1_1) {
          usersAdv_ts_1 = usersAdv_ts_1_1;
        },
      ],
      execute: function () {
        userRouter = new mod_ts_13.Router();
        userRouter
          .get("/api/users", users_ts_1.getUsers)
          .post("/api/signIn", usersAdv_ts_1.signIn)
          .post("/api/signUp", usersAdv_ts_1.signUp)
          .get("/api/users/:id", users_ts_1.getUser)
          .put("/api/users/:id", users_ts_1.updateUser)
          .delete("/api/users/:id", users_ts_1.deleteUser);
        exports_118("default", userRouter);
      },
    };
  },
);
System.register(
  "file:///C:/Users/danst/OneDrive/Documents/webdev/miscellaneous/Goals/goals-be/controllers/goals",
  [
    "https://deno.land/x/postgres/mod",
    "file:///C:/Users/danst/OneDrive/Documents/webdev/miscellaneous/Goals/goals-be/config",
  ],
  function (exports_119, context_119) {
    "use strict";
    var mod_ts_14,
      config_ts_3,
      client,
      getGoals,
      getGoal,
      addGoal,
      updateGoal,
      deleteGoal;
    var __moduleName = context_119 && context_119.id;
    return {
      setters: [
        function (mod_ts_14_1) {
          mod_ts_14 = mod_ts_14_1;
        },
        function (config_ts_3_1) {
          config_ts_3 = config_ts_3_1;
        },
      ],
      execute: function () {
        //init client
        client = new mod_ts_14.Client(config_ts_3.dbCreds);
        // @desc get goal list
        // @route GET /api/v1/goals
        getGoals = async ({ response }) => {
          try {
            await client.connect();
            const result = await client.query("SELECT * FROM goals");
            const goals = new Array();
            result.rows.map((p) => {
              let obj = new Object();
              result.rowDescription.columns.map((el, i) => {
                obj[el.name] = p[i];
              });
              goals.push(obj);
            });
            response.body = {
              success: true,
              data: goals,
            };
            console.log(goals);
          } catch (err) {
            response.status = 500;
            response.body = {
              success: false,
              msg: err.toString(),
            };
          } finally {
            await client.end();
          }
        };
        exports_119("getGoals", getGoals);
        // @desc get goal
        // @route GET /api/v1/goals/:id
        getGoal = async ({ params, response }) => {
          try {
            await client.connect();
            const result = await client.query(
              `SELECT * FROM goals WHERE id = ${params.id}`,
            );
            if (result.rows.toString() === "") {
              response.status = 404;
              response.body = {
                success: false,
                msg: `no goal with id ${params.id} found`,
              };
              return;
            } else {
              const goal = new Object();
              result.rows.map((p) => {
                result.rowDescription.columns.map((el, i) => {
                  goal[el.name] = p[i];
                });
                response.body = {
                  success: true,
                  data: goal,
                };
              });
            }
          } catch (err) {
            response.status = 500;
            response.body = {
              success: false,
              msg: err.toString(),
            };
          } finally {
            await client.end();
          }
        };
        exports_119("getGoal", getGoal);
        // @desc add goal
        // @route Post /api/v1/goals
        addGoal = async ({ request, response }) => {
          const body = await request.body();
          const goal = body.value;
          if (!request.hasBody) {
            response.status = 404;
            response.body = {
              success: false,
              msg: "no data",
            };
          } else {
            try {
              await client.connect();
              const result = await client.query(
                `INSERT INTO goals(user_id, goal, completed, target_date)
      VALUES('${goal.user_id}', '${goal.goal}',false,'${goal.target_date}')`,
              );
              response.status = 201;
              response.body = {
                success: true,
                data: goal,
              };
            } catch (err) {
              response.status = 500;
              response.body = {
                success: false,
                msg: err.toString(),
              };
            } finally {
              await client.end();
            }
          }
        };
        exports_119("addGoal", addGoal);
        // @desc update goal
        // @route put /api/v1/goals/:id
        updateGoal = async ({ params, request, response }) => {
          await getGoal({ params: { "id": params.id }, response });
          if (response.status === 404) {
            response.status = 404;
            response.body = {
              success: false,
              msg: response.body,
            };
            return;
          } else {
            const body = await request.body();
            const goal = body.value;
            if (!request.hasBody) {
              response.status = 404;
              response.body = {
                success: false,
                msg: "we messed up",
              };
            } else {
              try {
                await client.connect();
                const result = await client.query(`UPDATE goals SET
          goal='${goal.goal}',
          target_date='${goal.target_date}',
          completed='${goal.completed}'
          WHERE id=${params.id}`);
                response.status = 200;
                response.body = {
                  success: true,
                  data: goal,
                };
              } catch (err) {
                response.status = 500;
                response.body = {
                  success: false,
                  msg: err.toString(),
                };
              } finally {
                await client.end();
              }
            }
          }
        };
        exports_119("updateGoal", updateGoal);
        // @desc delete goal
        // @route delete /api/v1/goals/:id
        deleteGoal = async ({ params, response }) => {
          await getGoal({ params: { "id": params.id }, response });
          console.log(params.id, response);
          if (response.status === 404) {
            response.status = 404;
            response.body = {
              success: false,
              msg: response.body,
            };
            return;
          } else {
            try {
              await client.connect();
              const result = await client.query(
                `DELETE FROM goals WHERE id = ${params.id}`,
              );
              response.status = 204;
              response.body = {
                success: true,
                msg: `Goal ${params.id} has been deleted`,
              };
            } catch (err) {
              response.status = 500;
              response.body = {
                success: false,
                msg: err.toString(),
              };
            } finally {
              await client.end();
            }
          }
        };
        exports_119("deleteGoal", deleteGoal);
      },
    };
  },
);
System.register(
  "file:///C:/Users/danst/OneDrive/Documents/webdev/miscellaneous/Goals/goals-be/controllers/goalsAdv",
  [
    "https://deno.land/x/postgres/mod",
    "file:///C:/Users/danst/OneDrive/Documents/webdev/miscellaneous/Goals/goals-be/config",
  ],
  function (exports_120, context_120) {
    "use strict";
    var mod_ts_15, config_ts_4, client, getGoalList;
    var __moduleName = context_120 && context_120.id;
    return {
      setters: [
        function (mod_ts_15_1) {
          mod_ts_15 = mod_ts_15_1;
        },
        function (config_ts_4_1) {
          config_ts_4 = config_ts_4_1;
        },
      ],
      execute: function () {
        //init client
        client = new mod_ts_15.Client(config_ts_4.dbCreds);
        // @desc get goal
        // @route GET /api/v1/goals/:id
        getGoalList = async ({ params, response }) => {
          try {
            await client.connect();
            const result = await client.query(
              `SELECT * FROM goals where user_id = ${params.id}`,
            );
            const goals = new Array();
            result.rows.map((p) => {
              let obj = new Object();
              result.rowDescription.columns.map((el, i) => {
                obj[el.name] = p[i];
              });
              goals.push(obj);
            });
            response.body = {
              success: true,
              data: goals,
            };
            console.log("goals", goals);
          } catch (err) {
            response.status = 500;
            response.body = {
              success: false,
              msg: err.toString(),
            };
          } finally {
            await client.end();
          }
        };
        exports_120("getGoalList", getGoalList);
      },
    };
  },
);
System.register(
  "file:///C:/Users/danst/OneDrive/Documents/webdev/miscellaneous/Goals/goals-be/routes/goals",
  [
    "https://deno.land/x/oak/mod",
    "file:///C:/Users/danst/OneDrive/Documents/webdev/miscellaneous/Goals/goals-be/controllers/goals",
    "file:///C:/Users/danst/OneDrive/Documents/webdev/miscellaneous/Goals/goals-be/controllers/goalsAdv",
  ],
  function (exports_121, context_121) {
    "use strict";
    var mod_ts_16, goals_ts_1, goalsAdv_ts_1, goalsRouter;
    var __moduleName = context_121 && context_121.id;
    return {
      setters: [
        function (mod_ts_16_1) {
          mod_ts_16 = mod_ts_16_1;
        },
        function (goals_ts_1_1) {
          goals_ts_1 = goals_ts_1_1;
        },
        function (goalsAdv_ts_1_1) {
          goalsAdv_ts_1 = goalsAdv_ts_1_1;
        },
      ],
      execute: function () {
        goalsRouter = new mod_ts_16.Router();
        goalsRouter
          .get("/api/goals", goals_ts_1.getGoals)
          .get("/api/goals/:id", goalsAdv_ts_1.getGoalList)
          // .get("/api/goals/:id",getGoal)
          .post("/api/goals", goals_ts_1.addGoal)
          .put("/api/goals/:id", goals_ts_1.updateGoal)
          .delete("/api/goals/:id", goals_ts_1.deleteGoal);
        exports_121("default", goalsRouter);
      },
    };
  },
);
System.register(
  "file:///C:/Users/danst/OneDrive/Documents/webdev/miscellaneous/Goals/goals-be/controllers/habits",
  [
    "https://deno.land/x/postgres/mod",
    "file:///C:/Users/danst/OneDrive/Documents/webdev/miscellaneous/Goals/goals-be/config",
  ],
  function (exports_122, context_122) {
    "use strict";
    var mod_ts_17,
      config_ts_5,
      client,
      getHabits,
      getHabit,
      getHabitList,
      addHabit,
      updateHabit,
      deleteHabit;
    var __moduleName = context_122 && context_122.id;
    return {
      setters: [
        function (mod_ts_17_1) {
          mod_ts_17 = mod_ts_17_1;
        },
        function (config_ts_5_1) {
          config_ts_5 = config_ts_5_1;
        },
      ],
      execute: function () {
        //init client
        client = new mod_ts_17.Client(config_ts_5.dbCreds);
        // get all habits
        getHabits = async ({ response }) => {
          try {
            await client.connect();
            const result = await client.query("SELECT * FROM habits");
            const habits = new Array();
            result.rows.map((p) => {
              let obj = new Object();
              result.rowDescription.columns.map((el, i) => {
                obj[el.name] = p[i];
              });
              habits.push(obj);
            });
            response.body = {
              success: true,
              data: habits,
            };
          } catch (err) {
            response.status = 500;
            response.body = {
              success: false,
              msg: err.toString(),
            };
          } finally {
            await client.end();
          }
        };
        exports_122("getHabits", getHabits);
        // get habit by id
        getHabit = async ({ params, response }) => {
          try {
            await client.connect();
            const result = await client.query(
              `SELECT * FROM habits WHERE id = ${params.id}`,
            );
            if (result.rows.toString() === "") {
              response.status = 404;
              response.body = {
                success: false,
                msg: `no habit with id ${params.id} found`,
              };
              return;
            } else {
              const habit = new Object();
              result.rows.map((p) => {
                result.rowDescription.columns.map((el, i) => {
                  habit[el.name] = p[i];
                });
                response.body = {
                  success: true,
                  data: habit,
                };
              });
            }
          } catch (err) {
            response.status = 500;
            response.body = {
              success: false,
              msg: err.toString(),
            };
          } finally {
            await client.end();
          }
        };
        exports_122("getHabit", getHabit);
        // get habitlist by goal_id
        getHabitList = async ({ params, response }) => {
          try {
            await client.connect();
            const result = await client.query(
              `SELECT * FROM habits WHERE goal_id = ${params.id}`,
            );
            const habits = new Array();
            result.rows.map((p) => {
              let obj = new Object();
              result.rowDescription.columns.map((el, i) => {
                obj[el.name] = p[i];
              });
              habits.push(obj);
            });
            response.body = {
              success: true,
              data: habits,
            };
          } catch (err) {
            response.status = 500;
            response.body = {
              success: false,
              msg: err.toString(),
            };
          } finally {
            await client.end();
          }
        };
        exports_122("getHabitList", getHabitList);
        // @desc add habit
        // @route Post /api/v1/habits
        addHabit = async ({ request, response }) => {
          const body = await request.body();
          const habit = body.value;
          if (!request.hasBody) {
            response.status = 404;
            response.body = {
              success: false,
              msg: "no data",
            };
          } else {
            try {
              await client.connect();
              const result = await client.query(
                `INSERT INTO habits(goal_id, habit, amount, freq)
      VALUES('${habit.goal_id}','${habit.habit}','${habit.amount}','${habit.freq}')`,
              );
              response.status = 201;
              response.body = {
                success: true,
                data: habit,
              };
            } catch (err) {
              //console.log(err)
              response.status = 500;
              response.body = {
                success: false,
                msg: err.toString(),
              };
            } finally {
              await client.end();
            }
          }
        };
        exports_122("addHabit", addHabit);
        // @desc update habit
        // @route put /api/v1/habits/:id
        updateHabit = async ({ params, request, response }) => {
          await getHabit({ params: { "id": params.id }, response });
          if (response.status === 404) {
            response.status = 404;
            response.body = {
              success: false,
              msg: response.body,
            };
            return;
          } else {
            const body = await request.body();
            const habit = body.value;
            if (!request.hasBody) {
              response.status = 404;
              response.body = {
                success: false,
                msg: "we messed up",
              };
            } else {
              try {
                await client.connect();
                const result = await client.query(`UPDATE habits SET
          habit='${habit.habit}',
          amount='${habit.amount}',
          freq='${habit.freq}'
          WHERE id=${params.id}`);
                response.status = 200;
                response.body = {
                  success: true,
                  data: habit,
                };
              } catch (err) {
                response.status = 500;
                response.body = {
                  success: false,
                  msg: err.toString(),
                };
              } finally {
                await client.end();
              }
            }
          }
        };
        exports_122("updateHabit", updateHabit);
        // @desc delete habit
        // @route delete /api/v1/habits/:id
        deleteHabit = async ({ params, response }) => {
          await getHabit({ params: { "id": params.id }, response });
          if (response.status === 404) {
            response.status = 404;
            response.body = {
              success: false,
              msg: response.body,
            };
            return;
          } else {
            try {
              await client.connect();
              const result = await client.query(
                `DELETE FROM habits WHERE id = ${params.id}`,
              );
              response.status = 204;
              response.body = {
                success: true,
                msg: `Habit ${params.id} has been deleted`,
              };
            } catch (err) {
              response.status = 500;
              response.body = {
                success: false,
                msg: err.toString(),
              };
            } finally {
              await client.end();
            }
          }
        };
        exports_122("deleteHabit", deleteHabit);
      },
    };
  },
);
System.register(
  "file:///C:/Users/danst/OneDrive/Documents/webdev/miscellaneous/Goals/goals-be/routes/habits",
  [
    "https://deno.land/x/oak/mod",
    "file:///C:/Users/danst/OneDrive/Documents/webdev/miscellaneous/Goals/goals-be/controllers/habits",
  ],
  function (exports_123, context_123) {
    "use strict";
    var mod_ts_18, habits_ts_1, habitsRouter;
    var __moduleName = context_123 && context_123.id;
    return {
      setters: [
        function (mod_ts_18_1) {
          mod_ts_18 = mod_ts_18_1;
        },
        function (habits_ts_1_1) {
          habits_ts_1 = habits_ts_1_1;
        },
      ],
      execute: function () {
        habitsRouter = new mod_ts_18.Router();
        habitsRouter.get("/habits", habits_ts_1.getHabits)
          //.get("/habitList/:id",getHabitList)  //get single habit
          .get("/habits/:id", habits_ts_1.getHabitList)
          .post("/habits", habits_ts_1.addHabit)
          .put("/habits/:id", habits_ts_1.updateHabit)
          .delete("/habits/:id", habits_ts_1.deleteHabit);
        exports_123("default", habitsRouter);
      },
    };
  },
);
System.register(
  "file:///C:/Users/danst/OneDrive/Documents/webdev/miscellaneous/Goals/goals-be/server",
  [
    "https://deno.land/x/oak/mod",
    "https://deno.land/x/cors/mod",
    "file:///C:/Users/danst/OneDrive/Documents/webdev/miscellaneous/Goals/goals-be/routes/users",
    "file:///C:/Users/danst/OneDrive/Documents/webdev/miscellaneous/Goals/goals-be/routes/goals",
    "file:///C:/Users/danst/OneDrive/Documents/webdev/miscellaneous/Goals/goals-be/routes/habits",
  ],
  function (exports_124, context_124) {
    "use strict";
    var mod_ts_19, mod_ts_20, users_ts_2, goals_ts_2, habits_ts_2, port, app;
    var __moduleName = context_124 && context_124.id;
    return {
      setters: [
        function (mod_ts_19_1) {
          mod_ts_19 = mod_ts_19_1;
        },
        function (mod_ts_20_1) {
          mod_ts_20 = mod_ts_20_1;
        },
        function (users_ts_2_1) {
          users_ts_2 = users_ts_2_1;
        },
        function (goals_ts_2_1) {
          goals_ts_2 = goals_ts_2_1;
        },
        function (habits_ts_2_1) {
          habits_ts_2 = habits_ts_2_1;
        },
      ],
      execute: async function () {
        port = 8000;
        app = new mod_ts_19.Application();
        app.use(mod_ts_20.oakCors({
          origin: "http://localhost:3000",
        }));
        // app.use(oakCors())
        app.use(goals_ts_2.default.routes());
        app.use(habits_ts_2.default.routes());
        app.use(users_ts_2.default.routes());
        app.use(goals_ts_2.default.allowedMethods());
        app.use(habits_ts_2.default.allowedMethods());
        app.use(users_ts_2.default.allowedMethods());
        console.log(`\n\n server live on port ${port} \n\n`);
        await app.listen({ port });
      },
    };
  },
);

await __instantiateAsync(
  "file:///C:/Users/danst/OneDrive/Documents/webdev/miscellaneous/Goals/goals-be/server",
);
