import { Ok } from "@hazae41/result";
import { tryCrypto } from "libs/crypto/crypto.js";
import { Adapter } from "./x25519.js";

export async function isSafeSupported() {
  return await tryCrypto(() => crypto.subtle.generateKey("X25519", false, ["deriveKey", "deriveBits"])).then(r => r.isOk())
}

export function fromSafe(): Adapter {

  class PublicKey {

    constructor(
      readonly key: CryptoKey
    ) { }

    static new(key: CryptoKey) {
      return new PublicKey(key)
    }

    static async tryImport(bytes: Uint8Array) {
      return await tryCrypto(() => crypto.subtle.importKey("raw", bytes, "X25519", true, ["deriveBits"])).then(r => r.mapSync(PublicKey.new))
    }

    async tryExport() {
      return await tryCrypto(async () => new Uint8Array(await crypto.subtle.exportKey("raw", this.key)))
    }

  }

  class SharedSecret {

    constructor(
      readonly bytes: Uint8Array
    ) { }

    static new(bytes: Uint8Array) {
      return new SharedSecret(bytes)
    }

    tryExport() {
      return new Ok(this.bytes)
    }

  }

  class StaticSecret {

    constructor(
      readonly key: CryptoKeyPair
    ) { }

    static new(key: CryptoKeyPair) {
      return new StaticSecret(key)
    }

    static async tryCreate() {
      return await tryCrypto(async () => await crypto.subtle.generateKey("X25519", true, ["deriveBits"]) as CryptoKeyPair).then(r => r.mapSync(StaticSecret.new))
    }

    tryGetPublicKey() {
      return new Ok(new PublicKey(this.key.publicKey))
    }

    async tryComputeDiffieHellman(public_key: PublicKey) {
      return await tryCrypto(async () => new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: public_key.key }, this.key.privateKey, 256))).then(r => r.mapSync(SharedSecret.new))
    }

  }

  return { PublicKey, StaticSecret }
}