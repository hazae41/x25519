import { Ok } from "@hazae41/result"
import type { x25519 } from "@noble/curves/ed25519"
import { tryCryptoSync } from "libs/crypto/crypto.js"
import { fromSafe, isSafeSupported } from "./safe.js"
import { Adapter, Copied } from "./x25519.js"

export async function fromNativeOrNoble(noble: typeof x25519) {
  if (await isSafeSupported())
    return fromSafe()
  return fromNoble(noble)
}

export function fromNoble(noble: typeof x25519): Adapter {

  class PrivateKey {

    constructor(
      readonly bytes: Uint8Array
    ) { }

    [Symbol.dispose]() { }

    static new(bytes: Uint8Array) {
      return new PrivateKey(bytes)
    }

    static tryRandom() {
      return tryCryptoSync(() => noble.utils.randomPrivateKey()).mapSync(PrivateKey.new)
    }

    static tryImport(bytes: Uint8Array) {
      return new Ok(new PrivateKey(bytes))
    }

    tryGetPublicKey() {
      return tryCryptoSync(() => noble.getPublicKey(this.bytes)).mapSync(PublicKey.new)
    }

    tryCompute(other: PublicKey) {
      return tryCryptoSync(() => noble.getSharedSecret(this.bytes, other.bytes)).mapSync(SharedSecret.new)
    }

    tryExport() {
      return new Ok(new Copied(this.bytes))
    }

  }

  class PublicKey {

    constructor(
      readonly bytes: Uint8Array
    ) { }

    [Symbol.dispose]() { }

    static new(bytes: Uint8Array) {
      return new PublicKey(bytes)
    }

    static tryImport(bytes: Uint8Array) {
      return new Ok(new PublicKey(bytes))
    }

    tryExport() {
      return new Ok(new Copied(this.bytes))
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

    tryExport() {
      return new Ok(new Copied(this.bytes))
    }

  }

  return { PublicKey, PrivateKey }
}