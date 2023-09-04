import { Ok } from "@hazae41/result";
import { tryCrypto } from "libs/crypto/crypto.js";
import { Adapter, Copied } from "./x25519.js";

export async function isSafeSupported() {
  return await tryCrypto(() => crypto.subtle.generateKey("X25519", false, ["deriveKey", "deriveBits"])).then(r => r.isOk())
}

export function fromSafe(): Adapter {

  class PrivateKey {

    constructor(
      readonly key: CryptoKeyPair
    ) { }

    [Symbol.dispose]() { }

    static new(key: CryptoKeyPair) {
      return new PrivateKey(key)
    }

    static from(key: CryptoKey | CryptoKeyPair) {
      return new PrivateKey(key as CryptoKeyPair)
    }

    static async tryRandom() {
      return await tryCrypto(() => crypto.subtle.generateKey("X25519", true, ["deriveKey", "deriveBits"])).then(r => r.mapSync(PrivateKey.from))
    }

    static async tryImport(bytes: Uint8Array) {
      return await tryCrypto(() => crypto.subtle.importKey("raw", bytes, "X25519", true, ["deriveKey", "deriveBits"])).then(r => r.mapSync(PrivateKey.from))
    }

    tryGetPublicKey() {
      return new Ok(new PublicKey(this.key.publicKey))
    }

    async tryCompute(public_key: PublicKey) {
      return await tryCrypto(() => crypto.subtle.deriveBits({ name: "X25519", public: public_key.key }, this.key.privateKey, 256)).then(r => r.mapSync(SharedSecret.from))
    }

    async tryExport() {
      return await tryCrypto(() => crypto.subtle.exportKey("raw", this.key.privateKey)).then(r => r.mapSync(Copied.from))
    }

  }

  class PublicKey {

    constructor(
      readonly key: CryptoKey
    ) { }

    [Symbol.dispose]() { }

    static new(key: CryptoKey) {
      return new PublicKey(key)
    }

    static async tryImport(bytes: Uint8Array) {
      return await tryCrypto(() => crypto.subtle.importKey("raw", bytes, "X25519", true, ["deriveKey", "deriveBits"])).then(r => r.mapSync(PublicKey.new))
    }

    async tryExport() {
      return await tryCrypto(() => crypto.subtle.exportKey("raw", this.key)).then(r => r.mapSync(Copied.from))
    }

  }

  class SharedSecret {

    constructor(
      readonly bytes: Uint8Array
    ) { }

    [Symbol.dispose]() { }

    static new(bytes: Uint8Array) {
      return new SharedSecret(bytes)
    }

    static from(buffer: ArrayBuffer) {
      return new SharedSecret(new Uint8Array(buffer))
    }

    tryExport() {
      return new Ok(new Copied(this.bytes))
    }

  }

  return { PrivateKey, PublicKey }
}