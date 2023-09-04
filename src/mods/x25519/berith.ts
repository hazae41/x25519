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

  class PrivateKey {

    constructor(
      readonly inner: Berith.X25519StaticSecret
    ) { }

    [Symbol.dispose]() {
      this.inner.free()
    }

    static new(inner: Berith.X25519StaticSecret) {
      return new PrivateKey(inner)
    }

    static tryRandom() {
      return tryCryptoSync(() => new berith.X25519StaticSecret()).mapSync(PrivateKey.new)
    }

    static tryImport(bytes: Uint8Array) {
      return tryCryptoSync(() => berith.X25519StaticSecret.from_bytes(bytes)).mapSync(PrivateKey.new)
    }

    tryGetPublicKey() {
      return tryCryptoSync(() => this.inner.to_public()).mapSync(PublicKey.new)
    }

    tryCompute(other: PublicKey) {
      return tryCryptoSync(() => this.inner.diffie_hellman(other.inner)).mapSync(SharedSecret.new)
    }

    tryExport() {
      return tryCryptoSync(() => this.inner.to_bytes())
    }

  }

  class PublicKey {

    constructor(
      readonly inner: Berith.X25519PublicKey
    ) { }

    [Symbol.dispose]() {
      this.inner.free()
    }

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

    [Symbol.dispose]() {
      this.inner.free()
    }

    static new(inner: Berith.X25519SharedSecret) {
      return new SharedSecret(inner)
    }

    tryExport() {
      return tryCryptoSync(() => this.inner.to_bytes())
    }

  }

  return { PublicKey, PrivateKey }
}