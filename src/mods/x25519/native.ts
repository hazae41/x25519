import { Result } from "@hazae41/result";
import { BytesOrCopiable, Copied } from "libs/copiable/index.js";
import { Adapter } from "./adapter.js";

export async function isNativeSupported() {
  return await Result.runAndWrap(async () => {
    return await crypto.subtle.generateKey("X25519", false, ["deriveKey", "deriveBits"])
  }).then(r => r.isOk())
}

export async function fromNativeOrNull() {
  const native = await isNativeSupported()

  if (!native)
    return

  return fromNative()
}

export function fromNative() {

  function getBytes(bytes: BytesOrCopiable) {
    return "bytes" in bytes ? bytes.bytes : bytes
  }

  class PrivateKey {

    constructor(
      readonly key: CryptoKeyPair
    ) { }

    [Symbol.dispose]() { }

    static create(key: CryptoKeyPair) {
      return new PrivateKey(key)
    }

    static async randomOrThrow() {
      return new PrivateKey(await crypto.subtle.generateKey("X25519", true, ["deriveKey", "deriveBits"]) as CryptoKeyPair)
    }

    static async importOrThrow(bytes: BytesOrCopiable) {
      return new PrivateKey(await crypto.subtle.importKey("raw", getBytes(bytes), "X25519", true, ["deriveKey", "deriveBits"]) as unknown as CryptoKeyPair)
    }

    getPublicKeyOrThrow() {
      return new PublicKey(this.key.publicKey)
    }

    async computeOrThrow(publicKey: PublicKey) {
      return new SharedSecret(new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: publicKey.key }, this.key.privateKey, 256)))
    }

    async exportOrThrow() {
      return new Copied(new Uint8Array(await crypto.subtle.exportKey("raw", this.key.privateKey)))
    }

  }

  class PublicKey {

    constructor(
      readonly key: CryptoKey
    ) { }

    [Symbol.dispose]() { }

    static create(key: CryptoKey) {
      return new PublicKey(key)
    }

    static async importOrThrow(bytes: BytesOrCopiable) {
      return new PublicKey(await crypto.subtle.importKey("raw", getBytes(bytes), "X25519", true, ["deriveKey", "deriveBits"]))
    }

    async exportOrThrow() {
      return new Copied(new Uint8Array(await crypto.subtle.exportKey("raw", this.key)))
    }

  }

  class SharedSecret {

    constructor(
      readonly bytes: Uint8Array
    ) { }

    [Symbol.dispose]() { }

    static create(bytes: Uint8Array) {
      return new SharedSecret(bytes)
    }

    exportOrThrow() {
      return new Copied(this.bytes)
    }

  }

  return { PrivateKey, PublicKey } satisfies Adapter
}