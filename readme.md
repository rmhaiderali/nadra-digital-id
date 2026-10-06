# 📘 NADRA Digital ID

A JavaScript library for decoding, decrypting, validating, and verifying NADRA Digital ID QR / VC (Verifiable Credential) data.

It supports:

- Base45 + CBOR + GZIP encoding and decoding
- PIN-based AES encryption and decryption
- Time-window brute-range decryption
- SHA-256 hashing
- RSA signing and verification (RS256)
- Text normalization (Urdu/RTL safe)

# 🚀 Installation

```bash
npm install nadra-digital-id
```

(Or local import in your project)

# 📦 Main Exports

```js
import nadraDigitalId from "nadra-digital-id"
```

OR

```js
import nadraDigitalId from "https://cdn.jsdelivr.net/npm/nadra-digital-id/+esm"
```

OR

```js
import {
  encode,
  decode,
  encrypt,
  decrypt,
  sign,
  verify,
  sha256,
  sha384,
  timeRange,
  normalizeText,
  testKeyPair,
} from "nadra-digital-id"
```

# 🧭 Typical Verification Flow

### Step-by-step process

1. Decode QR payload
2. Verify PIN hash
3. Generate time range
4. Try decrypting VC + date
5. Verify RSA signature
6. Normalize text fields

# 🧩 API Reference

## 🔹 `setDebug(value)`

Enable or disable debug logging.

### Parameters

| Name  | Type    | Description       |
| ----- | ------- | ----------------- |
| value | boolean | Enable debug mode |

### Example

```js
nadraDigitalId.setDebug(true)
```

## 🔹 `encode(data)`

Encodes NADRA Digital ID QR payload.

### Process

```
Value → CBOR → GZIP → Base45 String
```

### Parameters

| Name | Type | Description                                      |
| ---- | ---- | ------------------------------------------------ |
| data | any  | CBOR-encodable payload (e.g. VC envelope object) |

### Returns

`{ error: string }` OR `{ data: string }` (QR-compatible base45 string)

### Example

```js
const { data: encoded, error } = encode(payload)
```

## 🔹 `decode(data)`

Decodes NADRA Digital ID QR payload.

### Process

```
Base45 String → GZIP → CBOR → decoded value
```

`decode` strips an optional `URN:VC1:` prefix before Base45 decoding.

### Parameters

| Name | Type   | Description                                  |
| ---- | ------ | -------------------------------------------- |
| data | string | Base45 string (QR payload) must be non-empty |

### Returns

`{ error: string }` OR `{ data: unknown }` (whatever CBOR decodes to)

### Example

```js
const { data: decoded, error } = decode(base45String)
```

## 🔹 `sha256(data)` `sha384(data)`

Generates SHA hash (hex format).

Used for PIN validation.

### Parameters

| Name | Type   |
| ---- | ------ |
| data | string |

### Returns

`{ error: string }` OR `{ data: string }`

### Example

```js
const { data: pinHash, error } = sha256("0000")
```

## 🔹 `timeRange(options?)`

Generates possible time values used for decryption.

NADRA encryption uses **time-based salt**, so you must try a small range.

### Parameters

```ts
options?: {
  bounds?: {
    start: Date
    end: Date
    greedy?: boolean
  }
  step?: number // milliseconds
  now?: Date
}
```

### Default Behavior

Without `bounds`: generates **3** `Date` values at `now - step`, `now` (rounded to `step`), and `now + step`, with default `step` of **5 minutes** (`ms("5m")`).

With `bounds`: you get every tick between your `start` and `end` (snapped to `step`). Normally that's the smallest sensible list. If you turn on `bounds.greedy` it ticks _just_ before and after that range.

If `options` is provided, it must be a plain object. `options.step` must be a positive integer (milliseconds).

### Returns

`{ error: string }` OR `{ data: Date[] }`

### Example

```js
const { data: timeValues, error } = timeRange()
```

## 🔹 `encrypt(data, pin, date)`

Encrypts a string using the same algorithm as `decrypt` (for building payloads or testing round-trips).

### Algorithm

```
Salt = UTC date formatted as ddMMyyyyHHmm
Key = PBKDF2(SHA256, pin, salt, 1000 iterations, 16 bytes)
Cipher = AES-128-ECB
Output = base64 ciphertext
```

### Parameters

| Name | Type   | Description        |
| ---- | ------ | ------------------ |
| data | string | Plain text to seal |
| pin  | string | PIN                |
| date | Date   | Salt time (UTC)    |

### Returns

`{ error: string }` OR `{ data: string }` (base64)

### Example

```js
const { data: ciphertext, error } = encrypt(text, pin, saltDate)
```

## 🔹 `decrypt(data, pin, date)`

Decrypts encrypted NADRA fields.

### Algorithm

```
Salt = UTC date formatted as ddMMyyyyHHmm (same as encrypt)
Key = PBKDF2(SHA256, pin, salt, 1000 iterations, 16 bytes)
Cipher = AES-128-ECB
```

### Parameters

| Name | Type            |
| ---- | --------------- |
| data | string (base64) |
| pin  | string          |
| date | Date            |

### Returns

`{ error: string }` OR `{ data: string }`

### Example

```js
const { data: text, error } = decrypt(ciphertext, pin, time)
```

## 🔹 `sign(vc, options?)`

Signs Verifiable Credential.

### Parameters

```ts
vc: object // plain object; same shape as a VC but without `proof`

options?: {
  privateKeyPem?: string // defaults to bundled `testKeyPair.private`
}
```

`vc` must be a plain object. If `privateKeyPem` is omitted, the bundled test private key is used.

### Returns

`{ error: string }` OR `{ data: string }` (base64 signature bytes, not JWS)

### Example

```js
const { data: signature, error } = await sign(vcWithoutProof)
```

## 🔹 `verify(vc, options?)`

Verifies Verifiable Credential RSA signature.

### Default public keys

The library picks a bundled SPKI PEM unless `publicKeyPem` is set:

| Condition in `vc.type` (string array) | Key          |
| ------------------------------------- | ------------ |
| includes `NATIONAL_ID` or `FRC`       | NADRA        |
| includes `ARMS_LICENSE`               | ARMS_LICENSE |
| includes `VEHICLE_REGISTRATION_CARD`  | ETD          |
| otherwise                             | NIMS         |

`vc` must be a plain object with `proof` a plain object, `proof.jws` a base64 string, and `vc.type` an array. The signed payload is `JSON.stringify` of the VC **without** the `proof` property; `proof.jws` must be the base64 RSASSA-PKCS1-v1_5 (SHA-256) signature over that UTF-8 string.

### Parameters

```ts
vc: object // full VC including `proof` with base64 `jws`

options?: {
  publicKeyPem?: string
}
```

### Returns

`{ error: string }` OR `{ data: true }`

### Example

```js
const { error } = await verify(vc)

if (!error) console.log("Signature is valid")
```

## 🔹 `normalizeText(text)`

Strips bidirectional / direction Unicode controls, then normalizes comma–separated segments.

Important for Urdu RTL text validation.

### Cleans:

- RTL/LTR marks
- Arabic control chars
- Direction overrides

### Returns

`{ error: string }` OR `{ data: string }`

### Example

```js
const { data, error } = normalizeText(address)
```

# 🔐 Security Notes

### Encryption

- AES-128-ECB
- PBKDF2 iterations: 1000
- Salt: Time-derived

### Signature

- RSASSA-PKCS1-v1_5
- SHA-256 hash

# 🧪 Full Usage Example

[Full Usage Example](https://github.com/rmhaiderali/nadra-digital-id-usage)

### Code

```js
import nadraDigitalId from "nadra-digital-id"
import console from "./utils/betterConsoleLog.js"
import decrypt from "./utils/matchSaltDateAndDecrypt.js"

// nadraDigitalId.setDebug(true)

console.log("NADRA Digital ID Test")

async function main(data, pin, date) {
  const { data: decoded, error: decodeError } = nadraDigitalId.decode(data)

  if (decodeError) {
    console.log(decodeError)
    return
  }

  let decodedObject
  try {
    decodedObject = JSON.parse(decoded)
  } catch (e) {
    console.log("Failed to parse decoded data")
    return
  }

  console.log("Decoded Data", decodedObject)

  let decryptedObject = decodedObject

  const isUnencrypted = "credentialSubject" in decodedObject

  if (!isUnencrypted) {
    const { data, error, notfound } = await decrypt(decodedObject, pin, date)

    if (error) {
      console.log(error)
      return
    }

    if (notfound) {
      console.log("Wrong Creation Date")
      return
    }

    decryptedObject = data.vc

    console.log("Decrypted Data", data)
  }

  // Uncomment following lines to test forged VC scenario
  // if (decryptedObject.credentialSubject?.id) {
  //   decryptedObject.credentialSubject.id += " "
  // } else {
  //   console.log(
  //     "Cannot forge VC as vc.credentialSubject.id is missing. Try some other field",
  //   )
  // }

  const { error: verificationError } =
    await nadraDigitalId.verify(decryptedObject)

  const verificationStatus = verificationError ? "Failed" : "Passed"

  console.log("Cryptographic Verification: " + verificationStatus)

  if (decryptedObject.credentialSubject?.temporaryAddress?.value) {
    const { data: normalizedAddress, error: normalizationError } =
      nadraDigitalId.normalizeText(
        decryptedObject.credentialSubject.temporaryAddress.value,
      )

    if (normalizationError) {
      console.log(normalizationError)
      return
    }

    console.log("Normalized Address", normalizedAddress)
  } else {
    console.log(
      "Cannot normalize text as vc.credentialSubject.temporaryAddress.value is missing. Try some other field",
    )
  }
}

const data = "<REDACTED>"

const pin = "1234"

const date = new Date("2026-01-01")

await main(data, pin, date)
```

### Output

```
┌───────────────────────┐
│ NADRA Digital ID Test │
└───────────────────────┘
┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Decoded Data                                                                                                         │
├──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ {                                                                                                                    │
│   v: "1.0ce",                                                                                                        │
│   hash: "<REDACTED>",                                                                                                │
│   date: "<REDACTED>",                                                                                                │
│   fields: [ -1 ]                                                                                                     │
│ }                                                                                                                    │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Decrypted Data                                                                                                       │
├──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ {                                                                                                                    │
│   salt: 2026-01-01T00:00:00.000Z,                                                                                    │
│   date: 2026-01-01T00:00:00.000Z,                                                                                    │
│   vc: {                                                                                                              │
│     "@context": [                                                                                                    │
│       "https://www.w3.org/2018/credentials/v1",                                                                      │
│       "https://www.w3.org/2018/credentials/examples/v1"                                                              │
│     ],                                                                                                               │
│     type: [ "VerifiableCredential", "NATIONAL_ID" ],                                                                 │
│     id: "100000000000",                                                                                              │
│     issuer: "NADRA, Pakistan",                                                                                       │
│     issuanceDate: "2026-01-01T00:00:00.000Z",                                                                        │
│     expirationDate: "2036-01-01T00:00:00.000Z",                                                                      │
│     credentialSubject: {                                                                                             │
│       id: "did:nadra:1000000000000",                                                                                 │
│       nameEnglish: { label: "Name", value: "<REDACTED>" },                                                           │
│       nameUrdu: { label: "Name (Urdu)", value: "<REDACTED>" },                                                       │
│       fatherHusbandNameEnglish: { label: "Father/Husband Name", value: "<REDACTED>" },                               │
│       fatherHusbandName: { label: "Father/Husband Name (Urdu)", value: "<REDACTED>" },                               │
│       gender: { label: "Gender", value: "M" },                                                                       │
│       countryOfStay: { label: "Country", value: "Pakistan" },                                                        │
│       cnic: { label: "Identity Number", value: "12345-1234567-1" },                                                  │
│       dob: { label: "Date of Birth", value: "01.01.2000" },                                                          │
│       issueDate: { label: "Issue Date", value: "01.01.2025" },                                                       │
│       expiryDate: { label: "Expiry Date", value: "01.01.2035" },                                                     │
│       temporaryAddress: { label: "Temporary Address", value: "<REDACTED>" },                                         │
│       permanenetAddress: { label: "Permanent Address", value: "<REDACTED>" }                                         │
│     },                                                                                                               │
│     proof: {                                                                                                         │
│       type: "RsaSignature2018",                                                                                      │
│       created: "2026-01-01T00:00:00.000Z",                                                                           │
│       proofPurpose: "assertionMethod",                                                                               │
│       verificationMethod: "did:nadra:issuer#keys-1",                                                                 │
│       jws: "<REDACTED>"                                                                                              │
│     }                                                                                                                │
│   }                                                                                                                  │
│ }                                                                                                                    │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌────────────────────────────────────┐
│ Cryptographic Verification: Passed │
└────────────────────────────────────┘
┌────────────────────┐
│ Normalized Address │
├────────────────────┤
│ <REDACTED>         │
└────────────────────┘
```

# ⚠️ Common Errors

| Error                          | Cause                                                       |
| ------------------------------ | ----------------------------------------------------------- |
| Failed to decode data          | Wrong format / corrupted payload / invalid Base45 or CBOR   |
| Failed to decrypt data         | Wrong PIN / salt time / corrupted ciphertext                |
| Invalid signature              | Tampered VC or wrong key                                    |
| Failed to verify signature     | Bad key PEM, missing Web Crypto, or verify operation failed |
| Crypto engine is not available | No `SubtleCrypto` for RSA (e.g. some restricted runtimes)   |

# Flow after QR Code Scan in PAK ID

![Flow Diagram](https://raw.githubusercontent.com/rmhaiderali/nadra-digital-id/refs/heads/main/flow.svg)

# 📄 License

MIT
