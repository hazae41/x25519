import { Cursor, CursorWriteError } from "@hazae41/cursor"
import { OptionInit } from "@hazae41/option"
import { Ok, Result } from "@hazae41/result"
import { CryptoError } from "libs/crypto/crypto.js"
import { Promiseable } from "libs/promises/promiseable.js"
import { fromSafe } from "./safe.js"

export const global: OptionInit<Adapter> = { inner: fromSafe() }

export interface Copiable extends Disposable {
  readonly bytes: Uint8Array

  copy(): Uint8Array

  trySize(): Result<number, never>

  tryWrite(cursor: Cursor): Result<void, CursorWriteError>
}

export class Copied implements Copiable {

  /**
   * A copiable that's already copied
   * @param bytes 
   */
  constructor(
    readonly bytes: Uint8Array
  ) { }

  [Symbol.dispose]() { }

  static new(bytes: Uint8Array) {
    return new Copied(bytes)
  }

  static from(buffer: ArrayBuffer) {
    return new Copied(new Uint8Array(buffer))
  }

  copy() {
    return this.bytes
  }

  trySize(): Result<number, never> {
    return new Ok(this.bytes.length)
  }

  tryWrite(cursor: Cursor): Result<void, CursorWriteError> {
    return cursor.tryWrite(this.bytes)
  }

}

export interface PrivateKey extends Disposable {
  tryGetPublicKey(): Promiseable<Result<PublicKey, CryptoError>>
  tryCompute(other: PublicKey): Promiseable<Result<SharedSecret, CryptoError>>
  tryExport(): Promiseable<Result<Copiable, CryptoError>>
}

export interface PublicKey extends Disposable {
  tryExport(): Promiseable<Result<Copiable, CryptoError>>
}

export interface SharedSecret extends Disposable {
  tryExport(): Promiseable<Result<Copiable, CryptoError>>
}

export interface PrivateKeyFactory {
  tryRandom(): Promiseable<Result<PrivateKey, CryptoError>>
  tryImport(bytes: Uint8Array): Promiseable<Result<PrivateKey, CryptoError>>
}

export interface PublicKeyFactory {
  tryImport(bytes: Uint8Array): Promiseable<Result<PublicKey, CryptoError>>
}

export interface Adapter {
  readonly PrivateKey: PrivateKeyFactory
  readonly PublicKey: PublicKeyFactory
}

