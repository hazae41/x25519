import { BytesOrCopiable, Copied } from "@hazae41/box"
import { Ok, Result } from "@hazae41/result"
import { x25519 } from "@noble/curves/ed25519"
import { Adapter } from "./adapter.js"
import { ComputeError, ConvertError, GenerateError } from "./errors.js"
import { fromSafe, isSafeSupported } from "./safe.js"

export async function fromNativeOrNoble() {
  if (await isSafeSupported())
    return fromSafe()
  return fromNoble()
}

export function fromNoble(): Adapter {

  function getBytes(bytes: BytesOrCopiable) {
    return "bytes" in bytes ? bytes.bytes : bytes
  }

  class PrivateKey {

    constructor(
      readonly bytes: Uint8Array
    ) { }

    [Symbol.dispose]() { }

    static new(bytes: Uint8Array) {
      return new PrivateKey(bytes)
    }

    static async tryRandom() {
      return await Result.runAndWrap(() => {
        return x25519.utils.randomPrivateKey()
      }).then(r => r.mapErrSync(GenerateError.from).mapSync(PrivateKey.new))
    }

    static async tryImport(bytes: BytesOrCopiable) {
      return new Ok(new PrivateKey(getBytes(bytes).slice()))
    }

    tryGetPublicKey() {
      return Result.runAndWrapSync(() => {
        return x25519.getPublicKey(this.bytes)
      }).mapErrSync(ConvertError.from).mapSync(PublicKey.new)
    }

    async tryCompute(other: PublicKey) {
      return await Result.runAndWrap(() => {
        return x25519.getSharedSecret(this.bytes, other.bytes)
      }).then(r => r.mapErrSync(ComputeError.from).mapSync(SharedSecret.new))
    }

    async tryExport() {
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

    static async tryImport(bytes: BytesOrCopiable) {
      return new Ok(new PublicKey(getBytes(bytes).slice()))
    }

    async tryExport() {
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