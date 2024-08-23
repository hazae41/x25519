import { None, Nullable, Option } from "@hazae41/option"
import { BytesOrCopiable, Copiable } from "libs/copiable/index.js"

let global: Option<Adapter> = new None()

export function get() {
  return global
}

export function set(value: Nullable<Adapter>) {
  global = Option.wrap(value)
}

export interface PrivateKey extends Disposable {
  getPublicKeyOrThrow(): PublicKey

  computeOrThrow(other: PublicKey): Promise<SharedSecret>

  exportOrThrow(): Promise<Copiable>
}

export interface PublicKey extends Disposable {
  exportOrThrow(): Promise<Copiable>
}

export interface SharedSecret extends Disposable {
  exportOrThrow(): Copiable
}

export interface PrivateKeyFactory {
  randomOrThrow(): Promise<PrivateKey>

  importOrThrow(bytes: BytesOrCopiable): Promise<PrivateKey>
}

export interface PublicKeyFactory {
  importOrThrow(bytes: BytesOrCopiable): Promise<PublicKey>
}

export interface Adapter {
  readonly PrivateKey: PrivateKeyFactory
  readonly PublicKey: PublicKeyFactory
}

