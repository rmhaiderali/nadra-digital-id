import ms from "ms"
import pako from "pako"
import * as cbor2 from "cbor2"
import * as pkijs from "pkijs"
import * as asn1js from "asn1js"
import { Buffer } from "buffer"
import { DateTime } from "luxon"
import base45 from "@rmhaiderali/base45"
import { ecb } from "@noble/ciphers/aes.js"
import { pbkdf2 } from "@noble/hashes/pbkdf2.js"
import * as sha2Raw from "@noble/hashes/sha2.js"
import { bytesToHex, utf8ToBytes, type CHash } from "@noble/hashes/utils.js"

function createHasher(fn: CHash) {
  return Object.assign(
    (data: string | Uint8Array) => {
      const type = typeof data === "string"
      const bytes: any = fn(type ? utf8ToBytes(data) : data)
      bytes.toHex ??= () => bytesToHex(bytes)
      return bytes as Uint8Array
    },
    { blockLen: fn.blockLen, outputLen: fn.outputLen, oid: fn.oid },
  )
}

const sha2 = {
  sha224: createHasher(sha2Raw.sha224),
  sha256: createHasher(sha2Raw.sha256),
  sha384: createHasher(sha2Raw.sha384),
  sha512: createHasher(sha2Raw.sha512),
  sha512_224: createHasher(sha2Raw.sha512_224),
  sha512_256: createHasher(sha2Raw.sha512_256),
}

type VC = {
  "@context": string[]
  type: string[]
  id: string
  issuer: string
  issuanceDate: string | { seconds: number; nanos: number }
  expirationDate: string | { seconds: number; nanos: number }
  credentialSubject: unknown
  proof: {
    type: string
    created: string
    proofPurpose: string
    verificationMethod: string
    jws: string
  }
}

function successResult(data: any) {
  return { data }
}

function errorResult(message: string) {
  return { error: message }
}

type Result = ReturnType<typeof successResult> | ReturnType<typeof errorResult>

function fullPublicKey(...args: string[]) {
  args.unshift("-----BEGIN PUBLIC KEY-----")
  args.push("-----END PUBLIC KEY-----")
  return args.join("\n")
}

function fullPrivateKey(...args: string[]) {
  args.unshift("-----BEGIN PRIVATE KEY-----")
  args.push("-----END PRIVATE KEY-----")
  return args.join("\n")
}

// ETD = Excise & Taxation Department
// NIMS = National Immunization Management System

const keys = {
  public: {
    RSA: {
      FEDERAL_ARMS_LICENSE: fullPublicKey(
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5XnC/PCR/YPhnryC310g",
        "C+XegNogbd69LvoI8/BycF4grgNHoNmIiGDDKwrJ+fXrA6/irP15WiliVzc09r00",
        "U3FfTxVZD6Btg7VBwYrp0HID8FBd1KTvRoelIBiciukcZ/ERPmyNJlHKvIyUdVFY",
        "ED1YI17Tvu4bsZBY1WFOXt5irKxQpc5zAhf64xbcyIRA7tSZDx7M7tKRsTL4EqzM",
        "hwjoKjx4zJG2B44HE/fVIbI40NP+I2HwNQqDonHltGRntiJllaUau5rWmtLQLFdp",
        "GrTGIlQ6bnfVidbz5KaRPpCh9NIEYkQczvfh60QtcBDU7gQ6KWPoaHjAkD2MFGkH",
        "MQIDAQAB",
      ),
      BALOCHISTAN_AND_PUNJAB_ARMS_LICENSE: fullPublicKey(
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA28dc1Tw7To//89HjvW1n",
        "x98RlyyypoF1JpRL06IKM+vwAZwFo+xvr7/GR1QHsMzivKuVswKOC6DhPzUwAj1o",
        "Aojvcx43BTHGsYQkyrcILiSBpPH0PxMqfb4VeaGIy6sKcVrJzUeUDJ3PVceVBTtq",
        "tb42BnEu+NdBvEvIRfBf71enDVdm+h//RXBvL/EBpmC8yS/UI22B90PX6vM6GSaP",
        "0wocHQhioFKhU1/2d3XKwvjVvDousf+JzxK7EcKerriZRdwZ/BMs/ATiqpw3v9dJ",
        "cXCTasezZFrPWPHc4ChHF5Gy+18Gu0Gopkilg1m7OBygGOeSsef3QcheIAX32TUR",
        "GQIDAQAB",
      ),
      ISB_VEHICLE_REGISTRATION_CARD: fullPublicKey(
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwgJocupiEWUDu1/JkI5I",
        "3cVH5jLNcDpYVXlzQlBoX0DeS5eeUzTshqPaEKe1PO/LMXPgY1K9Goig7n/S7vFr",
        "6GDbviT3BbDGhuG669iscj0yLZDsXMUCChKM5hzz0H2sXIK3sUzpN7nhRkgpfMLm",
        "L3Hr2ZVehSlHco4rAgj5Q/4SN8gBkPyNa+quOcNSfPFqA8LWtuBAK+S1objlQM/W",
        "F/EctchUg5VT4wvW+ywHXi8a1ZdEzuDp4e1FgJkmrKtHVoZB7ktUbes3Kv0uf0wk",
        "lVHs5B0KyWIODBiXMbFR4VcEHFEMzoRAwGwJ9S10SROVq/JAmu4ymsV0NdMdUmRf",
        "9wIDAQAB",
      ),
      SINDH_VEHICLE_REGISTRATION_CARD: fullPublicKey(
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwSEeBNYSfTJXetgnrcfQ",
        "28csqd7k9cHtIVOmTjbUJpvtjfvqmglDQY8jXGASU4FY/wMzIww/VZ85zPr/98hs",
        "H4G2LJqo+uIFNBBdZYGEX3dkB4D/YKW6fkP27kIHC9i7wNp1DWg77EoOck+nF6zp",
        "0va2PKeU9nMtF49XJTw2E78I5bADwn1dpaSMTYMAQpt8ndJxiYiPn4GGykUkbu/a",
        "73D97djVHzPsYpvyGAwnYK0GTdqCmOl1B8EiJ/2qOm4SXsPc2SMw5Hdb3vOrK922",
        "2p5AOlwapHF/NcOqaQ4YcHob+omX1HFOo7sQFJecmwanb7GMBYeK52uasfGVP6jf",
        "0wIDAQAB",
      ),
      PAK_SURVEY: fullPublicKey(
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6NuQki3PefFExbYDxW5I",
        "R1cPLC3I8daDFjLFFkyh0AnrCapTyf4l66s4+Py6L48WEjh4KOvB2OtW5h4xJfCE",
        "hEjhOcd0Ssdkb9NeejZuY0RA7tgaV1J3iW4znuWrmZKs+WZ+o12QApPewMt/Dslh",
        "QR1IhY7DISH9aMcNgzg4/78EX4xprRAbeaR9dAurSmaB2cozc6gJeY17LpR/U8f0",
        "iBTtBhVB2LZLv4xFrvyIIgZ0sCt45/QmIMogJUg0EdKh+m42HU2mHWxYzipx/Z7e",
        "xBlBKRLF2ERW3n5OVd0VaGvZ81b6ByS74MXJofkVIeI1JR1EKfSAZP83uM8w1YpL",
        "KQIDAQAB",
      ),
      NADRA: fullPublicKey(
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo2FG4ZCwxYRdWEkHrmvO",
        "s/58ra/ekTaoB/9jM6vyg0l0R4yoKLQSSfKuBMt0ONp179lyp3qaKPvDK2XhV14O",
        "KFKfHTdBJ9NjgFs0fsaMWpMBgR+DU/wmmQqei0H8cB0xnGWsDaKZDdFnHmgpxpHH",
        "QJf3CHJzGfwex7pCBuAamMS6SOAKQWNyOt6p8pan/d7hvVA7ghvXS1c81I+o+V2b",
        "g3uPjwh9+pEN8ZI4qKq1wrNLBKk4oexHXZbR6EU5dUek/DP9y3k5iXkTrDfzOQDz",
        "Li9WlEWV9M+7Rf1O727ku1qg7gyF0WBOZeoTVVOjEwGHpz7p5/dK9zWpGrF9G/TL",
        "aQIDAQAB",
      ),
      NIMS: fullPublicKey(
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmdtreKdXsUEVPjSK5qD+",
        "ginPM58uVo7xvlUP7gXWVq06U87KhTM0heJn+mpOMc7Qts8G8xNkEwLpXPdwUfxH",
        "TrwMnSyNx/C023JsvWuO2YevXJq+aBwgSjLcmL2zGhJk/H4S4pDUMLdRlWTXL/aw",
        "qZJbmk2yTbX66n6pAUPQEnvQ90F4itVJcup0nmdtbcTbZW1QcaPXSmfddab/xjjV",
        "ddsbbTp7P6g3ngJ+6pmi4c3s6G9MVsGaCuiHP19KE2CKaMF3VExKzigX6zzSaHx/",
        "yBd9C540zmYPNpLHeVZXcI33HOh4o2yz57sd/dUd7ksl0YtrPO4dhmpt13Z/6cWN",
        "zwIDAQAB",
      ),
      TEST: fullPublicKey(
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA470Dr/fUsOtu4b7Qwsqp",
        "4+12fUAzMUNHsihgTACs0nBR3ugtGr/Vw0rO0tgFT5Led+7Y+f8YE5LKgCVMKvEj",
        "1XvR8IVGY/ar6nexhCsb252ijTX+Daujy4XPmojUkvr5FPZ/CLVGW0+o+HRnc+73",
        "tRBuIufeUFwlNavwcn/QlMRnr5U6unYpZsfjLQ2FW30EfTVpD1Qc7RHVGs4t+ms/",
        "xwdXnOXYj3CRszpqbZwnwOdb3ycHOrwdPCrEdte4R59qP/6CEGljX2TfTlDTAEcU",
        "Sb6ozCbRIoa6bq5M3dJFQTTazOBGn9SlwdmRaVmu4zlJzERO6ytu8KltE1lhh6ST",
        "NQIDAQAB",
      ),
    },
    Ed25519: {
      NADRA: fullPublicKey(
        "MCowBQYDK2VwAyEAJdqkaYVJKGNKv5/sPPOgI2hB+KHaPhO6v+wJ7TShvi8=",
      ),
      NADRA2: fullPublicKey(
        "MCowBQYDK2VwAyEAL4U2596C+k3KAe8f+YaoJkEDzc9vhBjBVQKlPOty4W4=",
      ),
      TEST: fullPublicKey(
        "MCowBQYDK2VwAyEAZuqWK63qZNS4o0GBsyBAJW27pDctMbO3kkdZWlZokSA=",
      ),
    },
  },
  private: {
    RSA: {
      TEST: fullPrivateKey(
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDjvQOv99Sw627h",
        "vtDCyqnj7XZ9QDMxQ0eyKGBMAKzScFHe6C0av9XDSs7S2AVPkt537tj5/xgTksqA",
        "JUwq8SPVe9HwhUZj9qvqd7GEKxvbnaKNNf4Nq6PLhc+aiNSS+vkU9n8ItUZbT6j4",
        "dGdz7ve1EG4i595QXCU1q/Byf9CUxGevlTq6dilmx+MtDYVbfQR9NWkPVBztEdUa",
        "zi36az/HB1ec5diPcJGzOmptnCfA51vfJwc6vB08KsR217hHn2o//oIQaWNfZN9O",
        "UNMARxRJvqjMJtEihrpurkzd0kVBNNrM4Eaf1KXB2ZFpWa7jOUnMRE7rK27wqW0T",
        "WWGHpJM1AgMBAAECggEAGeE3Y45WybofciDkiVZNgxzPm8EpcB40rg6/jrN+8DUa",
        "YKniwkjtilFceoJY7CeFB30JhDNUcZj7UR+r7a9UgqSdAWerzZ1RAQaUEjBx7H2X",
        "5NMvaS9JoE22/1kwSvmhR5wRaJRtB+BgE8fqn7aWyKky0t2lml02T0iYPPLAab9H",
        "Ixn6CodlNyHV/zqbz3aF8pTFQWfp0yAWlgeKhLSu3BNiR6eFy0fDRQQElw8ft5h1",
        "g8KzR41YlG/+TswFTBT+QDovKKWLrKI+bQGC7gxQ7t82svvTztg976+sRkRaWesZ",
        "dH5oVm8rQDI3Wo8Zgd7ZKjAakt5kJ4T4Jz0jplYfEQKBgQD2tJMZQ1BYVq7XPT6y",
        "yLghG8D5rfV5K2V0UrIY64nAY/IoQzDU6fsRZDuqlUtUhT1Eb4weZBp0yNvfLwGR",
        "8AKuZ8udrvg9GJ88geHF0rtJSzyOQmSoE8CaXWAJ4Dlq7r1JIVmI5J8mMDqizIH8",
        "wZlKGl8frzd9BOTHb0swfIjb7QKBgQDsUYGnNtp6TVVRIRi1P/fMkeojGTaEcMb5",
        "6eCzGd+joB9dV2krfhTon7rJ2FwkUEzHmEvmTaE5SuHEX/BFT0Q+aAnwgNXn3Uf6",
        "2yXjg79awbrjEaeqTEABcWCMyyYgLYixDNxjvudpWcgPDV4G5gaI+7Q+g6zkrEIN",
        "8QI3UUX7aQKBgF0r/24IFRz3x9p0P+ynj5q5b50cTNvxPsS6wpZUxlaJqJf6IEQZ",
        "BgAgecRH1AZct7HT6vhDWBaJETjt+MrT+T9C5gxsW0Y/uUvRxaG/n4njxz/25Srx",
        "IslpwG6aZzTyazxmQvlHVq/GgS6gy+rYdvsckJZXxz4JDhof9yadsdZVAoGAPJM7",
        "97/Qyu7NwskIC1XFUBPK/4oz9kjuSBtSNLaaI9gkkgmY9MQR2fsvpxOlss0+kR8R",
        "vYwCmqv+KRcqgKmr5Y9HlPWBXzjSfZP1J1ebEkl8fT4GS1nWQkhspkpgkHj7g963",
        "E35Y1SFlba5QftYxsKVMc4XPKKKbH/W6SrGzjZkCgYEAnjAC8jkzLv3BbaZr76PO",
        "1nPOJcD3pFtC+r6TQoTPVJ5ek8/lX7GMk74VLQTf5rgyo1rhhb87O8w0tKMV4aHX",
        "cP97YrDg1N9GkCqV9Gxnaj5ZWI+0ikT3qaOu59lwjQoVxxXw0lMeCKQEt+1H79zv",
        "Z65V1+fkOMZzbi5hJAa4LNY=",
      ),
    },
    Ed25519: {
      TEST: fullPrivateKey(
        "MC4CAQAwBQYDK2VwBCIEID0oaSlX/AjCKqQYRRdyRNfA4PC9hu8OV3Ecx/VdmDuB",
      ),
    },
  },
}

let debug = false

function setDebug(value: boolean) {
  debug = value
}

function removeBidiControls(text: string) {
  // \u061c: Arabic Letter Mark (ALM)
  // \u200e-\u200f: Left-to-Right / Right-to-Left Marks
  // \u202a-\u202e: Embedding and Override controls (LRE, RLE, PDF, LRO, RLO)
  // \u2066-\u2069: Isolate controls (LRI, RLI, FSI, PDI)
  return text.replace(/[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, "")
}

function normalizeText(text: string): Result {
  if (typeof text !== "string") return errorResult("text must be a string")

  const data = removeBidiControls(text)
    .split("،")
    .map((s) => s.trim())
    .filter(Boolean)
    .join("، ")

  return successResult(data)
}

function isPlainObject(value: unknown): boolean {
  if (Object.prototype.toString.call(value) !== "[object Object]") return false
  const proto = Object.getPrototypeOf(value)
  return proto === Object.prototype || proto === null
}

function range(start: number, end: number, step = 1): number[] {
  const result: number[] = []
  for (let i = start; i <= end; i += step) result.push(i)
  return result
}

function ceilStep(value: number, step: number): number {
  return Math.ceil(value / step) * step
}

function roundStep(value: number, step: number): number {
  return Math.round(value / step) * step
}

function floorStep(value: number, step: number): number {
  return Math.floor(value / step) * step
}

// https://stackoverflow.com/questions/1353684/detecting-an-invalid-date-date-instance-in-javascript
function isValidDate(d: unknown): boolean {
  return d instanceof Date && !isNaN(d.getTime())
}

function encode(data: any): Result {
  try {
    const cborBuffer = cbor2.encode(data)
    const gzipBuffer = pako.gzip(cborBuffer)
    gzipBuffer[9] = 0xff
    return successResult(base45.encode(gzipBuffer))
  } catch (e) {
    if (debug) console.log(e)
    return errorResult("Failed to encode data")
  }
}

function decode(data: string): Result {
  if (typeof data !== "string") return errorResult("data must be a string")
  if (!data) return errorResult("data must not be an empty string")

  const prefix = "URN:VC1:"
  const base45String = data.startsWith(prefix)
    ? data.slice(prefix.length)
    : data

  try {
    const gzipBuffer = base45.decode(base45String)
    const cborBuffer = pako.ungzip(gzipBuffer)
    return successResult(cbor2.decode(cborBuffer))
  } catch (e) {
    if (debug) console.log(e)
    return errorResult("Failed to decode data")
  }
}

type TimeRangeOptions = {
  bounds?: {
    start: Date
    end: Date
    greedy?: boolean
  }
  step?: number // milliseconds
  now?: Date
}

function timeRange(options: TimeRangeOptions = {}): Result {
  if (options && !isPlainObject(options))
    return errorResult("options must be a plain object")

  const bounds = options.bounds
  const step = options.step ?? ms("5m")
  const now = options.now ?? new Date()

  if (!Number.isInteger(step))
    return errorResult("options.step must be an integer")
  if (step <= 0) return errorResult("options.step must be greater than 0")

  if (bounds) {
    if (!isPlainObject(bounds))
      return errorResult("options.bounds must be a plain object")
    if (!isValidDate(bounds.start))
      return errorResult("options.bounds.start must be a valid date")
    if (!isValidDate(bounds.end))
      return errorResult("options.bounds.end must be a valid date")
    if (bounds.start >= bounds.end)
      return errorResult(
        "options.bounds.start must be less than options.bounds.end",
      )
    if ("greedy" in bounds && typeof bounds.greedy !== "boolean")
      return errorResult("options.bounds.greedy must be a boolean")

    const startFn = bounds.greedy ? floorStep : ceilStep
    const endFn = bounds.greedy ? ceilStep : floorStep

    const start = startFn(Number(bounds.start), step)
    const end = endFn(Number(bounds.end), step)
    const dateRange = range(start, end, step)
    return successResult(dateRange.map((t) => new Date(t)))
  } else {
    if (!isValidDate(now))
      return errorResult("options.now must be a valid date")

    const closest = roundStep(Number(now), step)
    const dateRange = range(closest - step, closest + step, step)
    return successResult(dateRange.map((t) => new Date(t)))
  }
}

function encrypt(data: string, pin: string, date: Date): Result {
  try {
    const salt = Buffer.from(
      DateTime.fromJSDate(date).setZone("utc").toFormat("ddMMyyyyHHmm"),
    )

    const key = pbkdf2(sha2Raw.sha256, pin, salt, { c: 1000, dkLen: 16 })
    const bytes = new TextEncoder().encode(data)
    const encryptedBytes = ecb(key).encrypt(bytes)
    const encrypted = Buffer.from(encryptedBytes).toString("base64")

    return successResult(encrypted)
  } catch (e) {
    if (debug) console.log(e)
    return errorResult("Failed to encrypt data")
  }
}

function decrypt(data: string, pin: string, date: Date): Result {
  try {
    const salt = Buffer.from(
      DateTime.fromJSDate(date).setZone("utc").toFormat("ddMMyyyyHHmm"),
    )

    const key = pbkdf2(sha2Raw.sha256, pin, salt, { c: 1000, dkLen: 16 })
    const bytes = Buffer.from(data, "base64")
    const decryptedBytes = ecb(key).decrypt(bytes)
    const decrypted = new TextDecoder().decode(decryptedBytes)

    return successResult(decrypted)
  } catch (e) {
    if (debug) console.log(e)
    return errorResult("Failed to decrypt data")
  }
}

function pemToBytes(pem: string): Buffer {
  const base64 = pem.trim().split("\n").slice(1, -1).join("")
  return Buffer.from(base64, "base64")
}

const cryptoEngine = pkijs.getCrypto()

type AlgorithmInternal =
  | AlgorithmIdentifier
  | RsaHashedImportParams
  | EcKeyImportParams
  | HmacImportParams
  | AesKeyAlgorithm

async function signInternal(
  data: Uint8Array,
  privateKey: Uint8Array,
  algorithm: AlgorithmInternal,
): Promise<Result> {
  try {
    if (!cryptoEngine) return errorResult("Crypto engine is not available")

    const asn1 = asn1js.fromBER(privateKey)

    if (asn1.offset === -1) return errorResult("Failed to parse private key")

    const cryptoKey = await cryptoEngine.subtle.importKey(
      "pkcs8",
      privateKey as BufferSource,
      algorithm,
      true,
      ["sign"],
    )

    const signature = await cryptoEngine.subtle.sign(
      algorithm,
      cryptoKey,
      data as BufferSource,
    )

    return successResult(Buffer.from(signature).toString("base64"))
  } catch (e) {
    if (debug) console.log(e)
    return errorResult("Failed to sign data")
  }
}

async function verifyInternal(
  data: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
  algorithm: AlgorithmInternal,
): Promise<Result> {
  try {
    if (!cryptoEngine) return errorResult("Crypto engine is not available")

    const asn1 = asn1js.fromBER(publicKey)

    if (asn1.offset === -1) return errorResult("Failed to parse public key")

    // const publicKeyInfo = new pkijs.PublicKeyInfo({
    //   schema: asn1.result
    // }).toSchema()
    // console.log("Parsed Public Key Info", publicKeyInfo)

    const cryptoKey = await cryptoEngine.subtle.importKey(
      "spki",
      publicKey as BufferSource,
      algorithm,
      true,
      ["verify"],
    )

    const isValid = await cryptoEngine.subtle.verify(
      algorithm,
      cryptoKey,
      signature as BufferSource,
      data as BufferSource,
    )

    if (!isValid) return errorResult("Invalid signature")

    return successResult(true)
  } catch (e) {
    if (debug) console.log(e)
    return errorResult("Failed to verify signature")
  }
}

type Algorithm = keyof typeof algorithms

const algorithms = {
  RS256: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
  Ed25519: { name: "Ed25519" },
}

const algoNames = Object.keys(algorithms)

const testPrivateKeys = {
  RS256: keys.private.RSA.TEST,
  Ed25519: keys.private.Ed25519.TEST,
}

type SignOptions = {
  privateKeyPem?: string
  algorithm?: Algorithm
}

async function sign(
  vc: Omit<VC, "proof">,
  options: SignOptions = {},
): Promise<Result> {
  if (!isPlainObject(vc)) {
    return errorResult("vc must be a plain object")
  }

  const algorithm = options.algorithm || "RS256"

  if (typeof algorithm !== "string") {
    return errorResult("options.algorithm must be a string")
  }

  if (!algoNames.includes(algorithm)) {
    return errorResult("options.algorithm must be " + algoNames.join(" or "))
  }

  const privateKeyPem = options.privateKeyPem || testPrivateKeys[algorithm]

  if (typeof privateKeyPem !== "string") {
    return errorResult("options.privateKeyPem must be a string")
  }

  const vcWithoutProofStringified = JSON.stringify(vc)

  const data = vcWithoutProofStringified

  const dataBuffer = Buffer.from(data, "utf8")
  const privateKeyBuffer = pemToBytes(privateKeyPem)

  const chosenAlgorithm = algorithms[algorithm]

  return await signInternal(dataBuffer, privateKeyBuffer, chosenAlgorithm)
}

function getInferredPublicKeyAndAlgorithm(vcType: string[], proofType: string) {
  const inferredAlgorithm: Algorithm = /Ed25519/i.test(proofType)
    ? "Ed25519"
    : "RS256"

  const keyTypes = { RS256: "RSA", Ed25519: "Ed25519" } as const
  const keyType = keyTypes[inferredAlgorithm]

  let keyRSA: keyof typeof keys.public.RSA | null = null
  let keyEd25519: keyof typeof keys.public.Ed25519 | null = null

  if (
    (vcType.includes("NATIONAL_ID") && vcType.includes("PHYSICAL_ID")) ||
    (vcType.includes("NATIONAL_ID") && vcType.includes("FACE_ID")) ||
    vcType.includes("NATIONAL_ID") ||
    vcType.includes("FRC") ||
    vcType.includes("CRC") ||
    vcType.includes("NID_CANCEL_CERTIFICATE")
  ) {
    keyRSA = "NADRA"
    keyEd25519 = "NADRA"
    //
  } else if (
    vcType.includes("BALOCHISTAN_ARMS_LICENSE") ||
    vcType.includes("PUNJAB_ARMS_LICENSE")
  )
    keyRSA = "BALOCHISTAN_AND_PUNJAB_ARMS_LICENSE"
  //
  else if (vcType.includes("FEDERAL_ARMS_LICENSE"))
    keyRSA = "FEDERAL_ARMS_LICENSE"
  //
  else if (vcType.includes("ISB_VEHICLE_REGISTRATION_CARD"))
    keyRSA = "ISB_VEHICLE_REGISTRATION_CARD"
  //
  else if (vcType.includes("SINDH_VEHICLE_REGISTRATION_CARD")) {
    keyRSA = "SINDH_VEHICLE_REGISTRATION_CARD"
  }
  //
  else if (vcType.includes("PAK_SURVEY") && vcType.includes("EMPLOYEE_CARD"))
    keyRSA = "PAK_SURVEY"
  //
  else if (
    vcType.includes("NADRA_EMPLOYEE") &&
    vcType.includes("EMPLOYEE_CARD")
  )
    keyRSA = "NADRA"
  //
  else if (
    vcType.includes("POLIO_VACCINATION_PASS") ||
    vcType.includes("YELLOW_FEVER_VACCINATION_PASS") ||
    vcType.includes("COVID_VACCINATION_PASS") ||
    vcType.includes("COVID") ||
    vcType.includes("YELLOW_FEVER") ||
    vcType.includes("POLIO") ||
    vcType.includes("POLIO_IPV") ||
    vcType.includes("INFLUENZA") ||
    vcType.includes("MENINGITIS")
  )
    keyRSA = "NIMS"
  //
  else if (
    vcType.includes("BIRTH_CERTIFICATE") ||
    vcType.includes("DEATH_CERTIFICATE") ||
    vcType.includes("MARRIAGE_CERTIFICATE") ||
    vcType.includes("DIVORCE_CERTIFICATE") ||
    vcType.includes("CANCELLATION_CERTIFICATE")
  )
    keyEd25519 = "NADRA2"

  let inferredPublicKeyPem: string | null = null

  if (keyType === "RSA" && keyRSA)
    inferredPublicKeyPem = keys.public[keyType][keyRSA]

  if (keyType === "Ed25519" && keyEd25519)
    inferredPublicKeyPem = keys.public[keyType][keyEd25519]

  return { inferredPublicKeyPem, inferredAlgorithm }
}

type VerifyOptions = {
  publicKeyPem?: string
  algorithm?: Algorithm
}

async function verify(vc: VC, options: VerifyOptions = {}): Promise<Result> {
  if (!isPlainObject(vc)) {
    return errorResult("vc must be a plain object")
  }

  if (!isPlainObject(vc.proof)) {
    return errorResult("vc.proof must be a plain object")
  }

  if (typeof vc.proof.jws !== "string") {
    return errorResult("vc.proof.jws must be a string")
  }

  if (typeof vc.proof.type !== "string") {
    return errorResult("vc.proof.type must be a string")
  }

  const vcType = vc.type ?? ["NATIONAL_ID"]

  if (!Array.isArray(vcType)) {
    return errorResult("vc.type must be an array")
  }

  const { inferredPublicKeyPem, inferredAlgorithm } =
    getInferredPublicKeyAndAlgorithm(vcType, vc.proof.type)

  const algorithm = options.algorithm || inferredAlgorithm

  if (typeof algorithm !== "string") {
    return errorResult("options.algorithm must be a string")
  }

  if (!algoNames.includes(algorithm)) {
    return errorResult("options.algorithm must be " + algoNames.join(" or "))
  }

  const publicKeyPem = options.publicKeyPem || inferredPublicKeyPem

  if (typeof publicKeyPem !== "string") {
    return errorResult("options.publicKeyPem must be a string")
  }

  const { proof, ...vcWithoutProof } = vc

  const vcWithoutProofStringified = JSON.stringify(vcWithoutProof)

  const data = vcWithoutProofStringified

  const dataBuffer = Buffer.from(data, "utf8")
  const signatureBuffer = Buffer.from(proof.jws, "base64")
  const publicKeyBuffer = pemToBytes(publicKeyPem)

  const chosenAlgorithm = algorithms[algorithm]

  return await verifyInternal(
    dataBuffer,
    signatureBuffer,
    publicKeyBuffer,
    chosenAlgorithm,
  )
}

// prettier-ignore
export { /*   */ sha2, keys, setDebug, normalizeText, encode, decode, timeRange, encrypt, decrypt, sign, verify }

// prettier-ignore
export default { sha2, keys, setDebug, normalizeText, encode, decode, timeRange, encrypt, decrypt, sign, verify }
