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

### Safe (WebCrypto)

https://github.com/tQsW/webcrypto-curve25519/blob/master/explainer.md

```typescript
import { X25519 } from "@hazae41/x25519"

X25519.set(await X25519.fromSafe())
```

### Berith (WebAssembly)

```bash
npm i @hazae41/berith
```

```typescript
import { X25519 } from "@hazae41/x25519"

X25519.set(await X25519.fromSafeOrBerith())
```

### Noble (JavaScript)

```bash
npm i @noble/curves
```

```typescript
import { X25519 } from "@hazae41/x25519"

X25519.set(await X25519.fromSafeOrNoble())
```
