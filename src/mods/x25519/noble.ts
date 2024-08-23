import type { x25519 } from "@noble/curves/ed25519"
import { BytesOrCopiable, Copied } from "libs/copiable/index.js"
import { Adapter } from "./adapter.js"
import { fromNative, isNativeSupported } from "./native.js"

export async function fromNativeOrNoble(noble: typeof x25519) {
  const native = await isNativeSupported()

  if (!native)
    return fromNoble(noble)

  return fromNative()
}

export function fromNoble(noble: typeof x25519) {
  const { utils, getPublicKey, getSharedSecret } = noble

  function getBytes(bytes: BytesOrCopiable) {
    return "bytes" in bytes ? bytes.bytes : bytes
  }

  class PrivateKey {

    constructor(
      readonly bytes: Uint8Array
    ) { }

    [Symbol.dispose]() { }

    static create(bytes: Uint8Array) {
      return new PrivateKey(bytes)
    }

    static async randomOrThrow() {
      return new PrivateKey(utils.randomPrivateKey())
    }

    static async importOrThrow(bytes: BytesOrCopiable) {
      return new PrivateKey(getBytes(bytes).slice())
    }

    getPublicKeyOrThrow() {
      return new PublicKey(getPublicKey(this.bytes))
    }

    async computeOrThrow(other: PublicKey) {
      return new SharedSecret(getSharedSecret(this.bytes, other.bytes))
    }

    async exportOrThrow() {
      return new Copied(this.bytes)
    }

  }

  class PublicKey {

    constructor(
      readonly bytes: Uint8Array
    ) { }

    [Symbol.dispose]() { }

    static create(bytes: Uint8Array) {
      return new PublicKey(bytes)
    }

    static async importOrThrow(bytes: BytesOrCopiable) {
      return new PublicKey(getBytes(bytes).slice())
    }

    async exportOrThrow() {
      return new Copied(this.bytes)
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

  return { PublicKey, PrivateKey } satisfies Adapter
}