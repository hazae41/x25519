import type { Berith } from "@hazae41/berith"
import { tryCryptoSync } from "libs/crypto/crypto.js"
import { fromSafe, isSafeSupported } from "./safe.js"
import { Adapter } from "./x25519.js"

export async function fromSafeOrBerith(berith: typeof Berith) {
  if (await isSafeSupported())
    return fromSafe()

  await berith.initBundledOnce()
  return fromBerith(berith)
}

export function fromBerith(berith: typeof Berith): Adapter {

  class PublicKey {

    constructor(
      readonly inner: Berith.X25519PublicKey
    ) { }

    static new(inner: Berith.X25519PublicKey) {
      return new PublicKey(inner)
    }

    static tryImport(bytes: Uint8Array) {
      return tryCryptoSync(() => new berith.X25519PublicKey(bytes)).mapSync(PublicKey.new)
    }

    tryExport() {
      return tryCryptoSync(() => this.inner.to_bytes())
    }

  }

  class SharedSecret {

    constructor(
      readonly inner: Berith.X25519SharedSecret
    ) { }

    static new(inner: Berith.X25519SharedSecret) {
      return new SharedSecret(inner)
    }

    tryExport() {
      return tryCryptoSync(() => this.inner.to_bytes())
    }

  }

  class StaticSecret {

    constructor(
      readonly inner: Berith.X25519StaticSecret
    ) { }

    static new(inner: Berith.X25519StaticSecret) {
      return new StaticSecret(inner)
    }

    static tryCreate() {
      return tryCryptoSync(() => new berith.X25519StaticSecret()).mapSync(StaticSecret.new)
    }

    tryGetPublicKey() {
      return tryCryptoSync(() => this.inner.to_public()).mapSync(PublicKey.new)
    }

    tryComputeDiffieHellman(public_key: PublicKey) {
      return tryCryptoSync(() => this.inner.diffie_hellman(public_key.inner)).mapSync(SharedSecret.new)
    }

  }

  return { PublicKey, StaticSecret }
}