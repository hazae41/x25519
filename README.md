# X25519

X25519 adapter for WebAssembly and JS implementations

```bash
npm i @hazae41/x25519
```

[**Node Package 📦**](https://www.npmjs.com/package/@hazae41/x25519)

## Features

### Current features
- 100% TypeScript and ESM
- No external dependencies

## Usage

### Native (WebCrypto)

https://github.com/tQsW/webcrypto-curve25519/blob/master/explainer.md

```typescript
import { X25519 } from "@hazae41/x25519"

X25519.set(await X25519.fromNative())
```

### WebAssembly

```bash
npm i @hazae41/x25519.wasm
```

```typescript
import { X25519 } from "@hazae41/x25519"
import { X25519Wasm } from "@hazae41/x25519.wasm"

await X25519Wasm.initBundled()

X25519.set(await X25519.fromNativeOrWasm(X25519Wasm))
```

### Noble (JavaScript)

```bash
npm i @noble/curves
```

```typescript
import { X25519 } from "@hazae41/x25519"
import * as Ed25519Noble from "@noble/curves/ed25519"

X25519.set(await X25519.fromNativeOrNoble(Ed25519Noble))
```
