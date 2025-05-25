import { Pin, Ref } from "@hazae41/box"
import type { X25519PublicKey, X25519SharedSecret, X25519StaticSecret, X25519Wasm } from "@hazae41/x25519.wasm"
import { BytesOrCopiable } from "libs/copiable/index.js"
import * as Abstract from "./abstract.js"
import { Adapter } from "./adapter.js"
import { fromNative, isNativeSupported } from "./native.js"

export async function fromNativeOrWasm(wasm: typeof X25519Wasm) {
  const native = await isNativeSupported()

  if (!native)
    return fromWasm(wasm)

  return fromNative()
}

export function fromWasm(wasm: typeof X25519Wasm) {
  const { Memory, X25519StaticSecret, X25519PublicKey } = wasm

  function getMemory(bytesOrCopiable: BytesOrCopiable) {
    if (bytesOrCopiable instanceof Memory)
      return new Ref(bytesOrCopiable)

    if (bytesOrCopiable instanceof Uint8Array)
      return Pin.from(new Memory(bytesOrCopiable))

    return Pin.from(new Memory(bytesOrCopiable.bytes))
  }

  class PrivateKey extends Abstract.PrivateKey {

    constructor(
      readonly inner: X25519StaticSecret
    ) {
      super()
    }

    [Symbol.dispose]() {
      using _ = this.inner
    }

    static create(inner: X25519StaticSecret) {
      return new PrivateKey(inner)
    }

    static async randomOrThrow() {
      return new PrivateKey(new X25519StaticSecret())
    }

    static async importOrThrow(bytes: BytesOrCopiable) {
      using memory = getMemory(bytes)

      return new PrivateKey(X25519StaticSecret.from_bytes(memory.value))
    }

    getPublicKeyOrThrow() {
      return new PublicKey(this.inner.to_public())
    }

    async computeOrThrow(other: PublicKey) {
      return new SharedSecret(this.inner.diffie_hellman(other.inner))
    }

    async exportOrThrow() {
      return this.inner.to_bytes()
    }

  }

  class PublicKey extends Abstract.PublicKey {

    constructor(
      readonly inner: X25519PublicKey
    ) {
      super()
    }

    [Symbol.dispose]() {
      using _ = this.inner
    }

    static create(inner: X25519PublicKey) {
      return new PublicKey(inner)
    }

    static async importOrThrow(bytes: BytesOrCopiable) {
      using memory = getMemory(bytes)

      return new PublicKey(new X25519PublicKey(memory.value))
    }

    async exportOrThrow() {
      return this.inner.to_bytes()
    }

  }

  class SharedSecret extends Abstract.SharedSecret {

    constructor(
      readonly inner: X25519SharedSecret
    ) {
      super()
    }

    [Symbol.dispose]() {
      using _ = this.inner
    }

    static create(inner: X25519SharedSecret) {
      return new SharedSecret(inner)
    }

    exportOrThrow() {
      return this.inner.to_bytes()
    }

  }

  return { PublicKey, PrivateKey } satisfies Adapter
}