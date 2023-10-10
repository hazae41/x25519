import { Box, Copiable, Copied } from "@hazae41/box";
import { Ok, Result } from "@hazae41/result";
import { Adapter } from "./adapter.js";
import { ComputeError, ExportError, GenerateError, ImportError } from "./errors.js";

export async function isSafeSupported() {
  return await Result.runAndWrap(() => {
    return crypto.subtle.generateKey("X25519", false, ["deriveKey", "deriveBits"])
  }).then(r => r.isOk())
}

export function fromSafe(): Adapter {

  class PrivateKey {

    constructor(
      readonly key: CryptoKeyPair
    ) { }

    [Symbol.dispose]() { }

    static new(key: CryptoKeyPair) {
      return new PrivateKey(key)
    }

    static from(key: CryptoKey | CryptoKeyPair) {
      return new PrivateKey(key as CryptoKeyPair)
    }

    static async tryRandom() {
      return await Result.runAndWrap(() => {
        return crypto.subtle.generateKey("X25519", true, ["deriveKey", "deriveBits"])
      }).then(r => r.mapErrSync(GenerateError.from).mapSync(PrivateKey.from))
    }

    static async tryImport(bytes: Box<Copiable>) {
      return await Result.runAndWrap(() => {
        return crypto.subtle.importKey("raw", bytes.get().bytes, "X25519", true, ["deriveKey", "deriveBits"])
      }).then(r => r.mapErrSync(ImportError.from).mapSync(PrivateKey.from))
    }

    tryGetPublicKey() {
      return new Ok(new PublicKey(this.key.publicKey))
    }

    async tryCompute(public_key: PublicKey) {
      return await Result.runAndWrap(() => {
        return crypto.subtle.deriveBits({ name: "X25519", public: public_key.key }, this.key.privateKey, 256)
      }).then(r => r.mapErrSync(ComputeError.from).mapSync(SharedSecret.create))
    }

    async tryExport() {
      return await Result.runAndWrap(async () => {
        return new Uint8Array(await crypto.subtle.exportKey("raw", this.key.privateKey))
      }).then(r => r.mapErrSync(ExportError.from).mapSync(Copied.new))
    }

  }

  class PublicKey {

    constructor(
      readonly key: CryptoKey
    ) { }

    [Symbol.dispose]() { }

    static new(key: CryptoKey) {
      return new PublicKey(key)
    }

    static async tryImport(bytes: Box<Copiable>) {
      return await Result.runAndWrap(() => {
        return crypto.subtle.importKey("raw", bytes.get().bytes, "X25519", true, ["deriveKey", "deriveBits"])
      }).then(r => r.mapErrSync(ImportError.from).mapSync(PublicKey.new))
    }

    async tryExport() {
      return await Result.runAndWrap(async () => {
        return new Uint8Array(await crypto.subtle.exportKey("raw", this.key))
      }).then(r => r.mapErrSync(ExportError.from).mapSync(Copied.new))
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

    static create(buffer: ArrayBuffer) {
      return new SharedSecret(new Box(new Copied(new Uint8Array(buffer))))
    }

    tryExport() {
      return new Ok(this.bytes.unwrap())
    }

  }

  return { PrivateKey, PublicKey }
}