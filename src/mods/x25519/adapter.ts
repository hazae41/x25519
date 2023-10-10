import { Box, Copiable } from "@hazae41/box"
import { None, Option } from "@hazae41/option"
import { Result } from "@hazae41/result"
import { ComputeError, ConvertError, ExportError, GenerateError, ImportError } from "./errors.js"

let global: Option<Adapter> = new None()

export function get() {
  return global.unwrap()
}

export function set(value?: Adapter) {
  global = Option.wrap(value)
}

export interface PrivateKey extends Disposable {
  tryGetPublicKey(): Result<PublicKey, ConvertError>

  tryCompute(other: PublicKey): Promise<Result<SharedSecret, ComputeError>>
  tryExport(): Promise<Result<Copiable, ExportError>>
}

export interface PublicKey extends Disposable {
  tryExport(): Promise<Result<Copiable, ExportError>>
}

export interface SharedSecret extends Disposable {
  tryExport(): Result<Copiable, ExportError>
}

export interface PrivateKeyFactory {
  tryRandom(): Promise<Result<PrivateKey, GenerateError>>
  tryImport(bytes: Box<Copiable>): Promise<Result<PrivateKey, ImportError>>
}

export interface PublicKeyFactory {
  tryImport(bytes: Box<Copiable>): Promise<Result<PublicKey, ImportError>>
}

export interface Adapter {
  readonly PrivateKey: PrivateKeyFactory
  readonly PublicKey: PublicKeyFactory
}

