import { Berith } from "@hazae41/berith"
import { Box, BytesOrCopiable } from "@hazae41/box"
import { Result } from "@hazae41/result"
import { Adapter } from "./adapter.js"
import { ComputeError, ConvertError, ExportError, GenerateError, ImportError } from "./errors.js"
import { fromSafe, isSafeSupported } from "./safe.js"

export async function fromSafeOrBerith() {
  if (await isSafeSupported())
    return fromSafe()
  return await fromBerith()
}

export async function fromBerith(): Promise<Adapter> {
  await Berith.initBundledOnce()

  function getMemory(bytesOrCopiable: BytesOrCopiable) {
    if (bytesOrCopiable instanceof Berith.Memory)
      return Box.greedy(bytesOrCopiable)
    if (bytesOrCopiable instanceof Uint8Array)
      return Box.new(new Berith.Memory(bytesOrCopiable))
    return Box.new(new Berith.Memory(bytesOrCopiable.bytes))
  }

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

    static async tryRandom() {
      return await Result.runAndWrap(() => {
        return new Berith.X25519StaticSecret()
      }).then(r => r.mapErrSync(GenerateError.from).mapSync(PrivateKey.new))
    }

    static async tryImport(bytes: BytesOrCopiable) {
      using memory = getMemory(bytes)

      return await Result.runAndWrap(() => {
        return Berith.X25519StaticSecret.from_bytes(memory.inner)
      }).then(r => r.mapErrSync(ImportError.from).mapSync(PrivateKey.new))
    }

    tryGetPublicKey() {
      return Result.runAndWrapSync(() => {
        return this.inner.to_public()
      }).mapErrSync(ConvertError.from).mapSync(PublicKey.new)
    }

    async tryCompute(other: PublicKey) {
      return await Result.runAndWrap(() => {
        return this.inner.diffie_hellman(other.inner)
      }).then(r => r.mapErrSync(ComputeError.from).mapSync(SharedSecret.new))
    }

    async tryExport() {
      return await Result.runAndWrap(() => {
        return this.inner.to_bytes()
      }).then(r => r.mapErrSync(ExportError.from))
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

    static async tryImport(bytes: BytesOrCopiable) {
      using memory = getMemory(bytes)

      return await Result.runAndWrap(() => {
        return new Berith.X25519PublicKey(memory.inner)
      }).then(r => r.mapErrSync(ImportError.from).mapSync(PublicKey.new))
    }

    async tryExport() {
      return await Result.runAndWrap(() => {
        return this.inner.to_bytes()
      }).then(r => r.mapErrSync(ExportError.from))
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
      return Result.runAndWrapSync(() => {
        return this.inner.to_bytes()
      }).mapErrSync(ExportError.from)
    }

  }

  return { PublicKey, PrivateKey }
}