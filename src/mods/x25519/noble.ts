import { Box, Copiable, Copied } from "@hazae41/box"
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

  class PrivateKey {

    constructor(
      readonly bytes: Box<Copiable>
    ) { }

    [Symbol.dispose]() {
      this.bytes[Symbol.dispose]()
    }

    static new(bytes: Box<Copiable>) {
      return new PrivateKey(bytes)
    }

    static async tryRandom() {
      return await Result.runAndWrap(() => {
        return new Box(new Copied(x25519.utils.randomPrivateKey()))
      }).then(r => r.mapErrSync(GenerateError.from).mapSync(PrivateKey.new))
    }

    static async tryImport(bytes: Box<Copiable>) {
      return new Ok(new PrivateKey(bytes))
    }

    tryGetPublicKey() {
      return Result.runAndWrapSync(() => {
        return new Box(new Copied(x25519.getPublicKey(this.bytes.get().bytes)))
      }).mapErrSync(ConvertError.from).mapSync(PublicKey.new)
    }

    async tryCompute(other: PublicKey) {
      return await Result.runAndWrap(() => {
        return new Box(new Copied(x25519.getSharedSecret(this.bytes.get().bytes, other.bytes.get().bytes)))
      }).then(r => r.mapErrSync(ComputeError.from).mapSync(SharedSecret.new))
    }

    async tryExport() {
      return new Ok(this.bytes.unwrap())
    }

  }

  class PublicKey {

    constructor(
      readonly bytes: Box<Copiable>
    ) { }

    [Symbol.dispose]() {
      this.bytes[Symbol.dispose]()
    }

    static new(bytes: Box<Copiable>) {
      return new PublicKey(bytes)
    }

    static async tryImport(bytes: Box<Copiable>) {
      return new Ok(new PublicKey(bytes))
    }

    async tryExport() {
      return new Ok(this.bytes.unwrap())
    }

  }

  class SharedSecret {

    constructor(
      readonly bytes: Box<Copiable>
    ) { }

    [Symbol.dispose]() {
      this.bytes[Symbol.dispose]()
    }

    static new(bytes: Box<Copiable>) {
      return new SharedSecret(bytes)
    }

    tryExport() {
      return new Ok(this.bytes.unwrap())
    }

  }

  return { PublicKey, PrivateKey }
}