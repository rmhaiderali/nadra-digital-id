# 📘 NADRA Digital ID

A JavaScript library for **decoding, decrypting, validating, and verifying NADRA Digital ID QR / VC (Verifiable Credential) data**.

It supports:

- Base45 + CBOR + GZIP decoding
- PIN-based AES decryption
- Time-window brute-range decryption
- SHA-256 hashing
- RSA signature verification (RS256)
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
  decode,
  decrypt,
  verify,
  sha256,
  timeRange,
  normalizeText
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

## 🔹 `decode(data)`

Decodes NADRA Digital ID QR payload.

### Process

```
Base45 → GZIP → CBOR → JSON
```

### Parameters

| Name | Type   | Description |
| ---- | ------ | ----------- |
| data | string | QR string   |

### Returns

`{ error: string }` OR `{ data: object }`

### Example

```js
const { data: decoded, error } = decode(qrString)
```

## 🔹 `sha256(data)`

Generates SHA-256 hash (hex format).

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

---

## 🔹 `timeRange(options)`

Generates possible time values used for decryption.

NADRA encryption uses **time-based salt**, so you must try a small range.

### Parameters

```ts
options?: {
  bounds?: {
    start: Date
    end: Date
  }
  step?: number  // milliseconds
  now?: Date
}
```

### Default Behavior

Generates **3 timestamps** around current (now) time, with **5 minute** step.

### Returns

`{ error: string }` OR `{ data: Date[] }`

### Example

```js
const { data: timeValues, error } = timeRange()
```

## 🔹 `decrypt(data, pin, date)`

Decrypts encrypted NADRA fields.

### Algorithm

```
Salt = formatted date (UTC)
Key = PBKDF2(SHA256, pin)
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
const { data, error } = decrypt(encryptedVC, pin, time)
```

## 🔹 `verify(vc, options?)`

Verifies Verifiable Credential RSA signature.

### Supported Authorities

The library auto-selects public key based on VC type:

| VC Type              | Authority |
| -------------------- | --------- |
| NATIONAL_ID / FRC    | NADRA     |
| ARMS_LICENSE         | MOI       |
| VEHICLE_REGISTRATION | ETD       |
| Others               | NIMS      |

### Parameters

```ts
vc: object

options?: {
  publicKeyPem?: string
}
```

### Returns

`{ error: string }` OR `{ data: true }`

### Example

```js
const { error } = await verify(vc)

if (!error) console.log("Signature valid")
```

## 🔹 `normalizeText(text)`

Removes invisible Unicode control characters.

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

---

# 🔐 Security Notes

### Encryption

- AES-128-ECB
- PBKDF2 iterations: 1000
- Salt: Time-derived

### Signature

- RSASSA-PKCS1-v1_5
- SHA-256 hash

# 🧪 Full Usage Example

```js
import nadraDigitalId from "./index.js"

async function main() {
  // nadraDigitalId.setDebug(true)

  const data = "..."
  const pin = "0000"
  const now = new Date("2026-01-01T00:00:00+05:00")

  const { data: decoded, error: decodeError } = nadraDigitalId.decode(data)

  if (decodeError) {
    console.log(decodeError)
    return
  }

  const { data: pinHash, error: pinHashError } = nadraDigitalId.sha256(pin)

  if (pinHashError) {
    console.log(pinHashError)
    return
  }

  if (decoded.hash !== pinHash) {
    console.log("Invalid PIN")
    return
  }

  const { data: timeValues, timeRangeError } = nadraDigitalId.timeRange({
    now
  })

  if (timeRangeError) {
    console.log(timeRangeError)
    return
  }

  let date = null
  let vc = null

  for (const time of timeValues) {
    if (!date) {
      const result = nadraDigitalId.decrypt(decoded.date, pin, time)
      if (result.data) date = new Date(result.data + "Z")
    }
    if (!vc) {
      const result = nadraDigitalId.decrypt(decoded.vc, pin, time)
      if (result.data) vc = JSON.parse(result.data)
    }
    if (date && vc) break
  }

  if (!date || !vc) {
    console.log("Decryption failed: Incorrect time range")
    return
  }

  console.log("Decrypted VC:", vc)
  console.log("Decrypted Date:", date)

  // Uncomment following line to test forged VC scenario
  // vc.credentialSubject.permanenetAddress.value += " "

  const { error: verificationError } = await nadraDigitalId.verify(vc)

  if (verificationError) {
    console.log(verificationError)
    return
  }

  console.log("VC verification successful")

  const { data: normalizedAddress, error: normalizationError } =
    nadraDigitalId.normalizeText(vc.credentialSubject.temporaryAddress.value)

  if (normalizationError) {
    console.log(normalizationError)
    return
  }

  console.log("Normalized Address:", normalizedAddress)
}

main()
```

# ⚠️ Common Errors

| Error                    | Cause                              |
| ------------------------ | ---------------------------------- |
| Failed to decode data    | QR corrupted                       |
| Failed to decrypt data   | Wrong PIN / time                   |
| Signature does not match | Tampered VC / Incorrect Public Key |

# 🏗️ Internal Architecture

```
QR DATA
   ↓
decode()
   ↓
verify PIN hash
   ↓
timeRange()
   ↓
decrypt()
   ↓
verify()
```

# Flow after QR Scan in PAK ID

![Flow](flow.svg)

# 📄 License

LGPL 2.0 only
