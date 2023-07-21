import { Ok } from "@hazae41/result"
import type { x25519 } from "@noble/curves/ed25519"
import { tryCryptoSync } from "libs/crypto/crypto.js"
import { fromSafe, isSafeSupported } from "./safe.js"
import { Adapter } from "./x25519.js"

export async function fromSafeOrNoble(noble: typeof x25519) {
  if (await isSafeSupported())
    return fromSafe()
  return fromNoble(noble)
}

export function fromNoble(noble: typeof x25519): Adapter {

  class PublicKey {

    constructor(
      readonly bytes: Uint8Array
    ) { }

    static new(bytes: Uint8Array) {
      return new PublicKey(bytes)
    }

    static tryImport(bytes: Uint8Array) {
      return new Ok(new PublicKey(bytes))
    }

    tryExport() {
      return new Ok(this.bytes)
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
      readonly bytes: Uint8Array
    ) { }

    static new(bytes: Uint8Array) {
      return new StaticSecret(bytes)
    }

    static tryCreate() {
      return tryCryptoSync(() => noble.utils.randomPrivateKey()).mapSync(StaticSecret.new)
    }

    tryGetPublicKey() {
      return tryCryptoSync(() => noble.getPublicKey(this.bytes)).mapSync(PublicKey.new)
    }

    tryComputeDiffieHellman(public_key: PublicKey) {
      return tryCryptoSync(() => noble.getSharedSecret(this.bytes, public_key.bytes)).mapSync(SharedSecret.new)
    }

  }

  return { PublicKey, StaticSecret }
}