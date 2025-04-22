import { BytesOrCopiable, Copiable } from "libs/copiable/index.js"

export abstract class PrivateKey implements Disposable {

  constructor(..._: any[]) { }

  static randomOrThrow(): Promise<PrivateKey> {
    throw new Error("Method not implemented.")
  }

  abstract [Symbol.dispose](): void

  abstract getPublicKeyOrThrow(): PublicKey

  abstract computeOrThrow(other: PublicKey): Promise<SharedSecret>
}

export abstract class PublicKey implements Disposable {

  constructor(..._: any[]) { }

  static importOrThrow(bytes: BytesOrCopiable): Promise<PublicKey> {
    throw new Error("Method not implemented.")
  }

  abstract [Symbol.dispose](): void

  abstract exportOrThrow(): Promise<Copiable>
}

export abstract class SharedSecret implements Disposable {

  constructor(..._: any[]) { }

  abstract [Symbol.dispose](): void

  abstract exportOrThrow(): Copiable

}
