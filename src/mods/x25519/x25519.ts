import { Result } from "@hazae41/result"
import { CryptoError } from "libs/crypto/crypto.js"
import { Promiseable } from "libs/promises/promiseable.js"

export interface PublicKey {
  tryExport(): Promiseable<Result<Uint8Array, CryptoError>>
}

export interface SharedSecret {
  tryExport(): Promiseable<Result<Uint8Array, CryptoError>>
}

export interface StaticSecret {
  tryGetPublicKey(): Promiseable<Result<PublicKey, CryptoError>>
  tryComputeDiffieHellman(public_key: PublicKey): Promiseable<Result<SharedSecret, CryptoError>>
}

export interface StaticSecretFactory {
  tryCreate(): Promiseable<Result<StaticSecret, CryptoError>>
}

export interface PublicKeyFactory {
  tryImport(bytes: Uint8Array): Promiseable<Result<PublicKey, CryptoError>>
}

export interface Adapter {
  StaticSecret: StaticSecretFactory
  PublicKey: PublicKeyFactory
}

