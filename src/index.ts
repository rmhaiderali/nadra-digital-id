// import crypto from "crypto"
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
import { sha256 as sha256Raw } from "@noble/hashes/sha2.js"
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js"

type VC = {
  "@context": string[]
  type: string[]
  id: string
  issuer: string
  issuanceDate: string
  expirationDate: string
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

// prettier-ignore
const testKeyPair = {
  private: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDjvQOv99Sw627h\nvtDCyqnj7XZ9QDMxQ0eyKGBMAKzScFHe6C0av9XDSs7S2AVPkt537tj5/xgTksqA\nJUwq8SPVe9HwhUZj9qvqd7GEKxvbnaKNNf4Nq6PLhc+aiNSS+vkU9n8ItUZbT6j4\ndGdz7ve1EG4i595QXCU1q/Byf9CUxGevlTq6dilmx+MtDYVbfQR9NWkPVBztEdUa\nzi36az/HB1ec5diPcJGzOmptnCfA51vfJwc6vB08KsR217hHn2o//oIQaWNfZN9O\nUNMARxRJvqjMJtEihrpurkzd0kVBNNrM4Eaf1KXB2ZFpWa7jOUnMRE7rK27wqW0T\nWWGHpJM1AgMBAAECggEAGeE3Y45WybofciDkiVZNgxzPm8EpcB40rg6/jrN+8DUa\nYKniwkjtilFceoJY7CeFB30JhDNUcZj7UR+r7a9UgqSdAWerzZ1RAQaUEjBx7H2X\n5NMvaS9JoE22/1kwSvmhR5wRaJRtB+BgE8fqn7aWyKky0t2lml02T0iYPPLAab9H\nIxn6CodlNyHV/zqbz3aF8pTFQWfp0yAWlgeKhLSu3BNiR6eFy0fDRQQElw8ft5h1\ng8KzR41YlG/+TswFTBT+QDovKKWLrKI+bQGC7gxQ7t82svvTztg976+sRkRaWesZ\ndH5oVm8rQDI3Wo8Zgd7ZKjAakt5kJ4T4Jz0jplYfEQKBgQD2tJMZQ1BYVq7XPT6y\nyLghG8D5rfV5K2V0UrIY64nAY/IoQzDU6fsRZDuqlUtUhT1Eb4weZBp0yNvfLwGR\n8AKuZ8udrvg9GJ88geHF0rtJSzyOQmSoE8CaXWAJ4Dlq7r1JIVmI5J8mMDqizIH8\nwZlKGl8frzd9BOTHb0swfIjb7QKBgQDsUYGnNtp6TVVRIRi1P/fMkeojGTaEcMb5\n6eCzGd+joB9dV2krfhTon7rJ2FwkUEzHmEvmTaE5SuHEX/BFT0Q+aAnwgNXn3Uf6\n2yXjg79awbrjEaeqTEABcWCMyyYgLYixDNxjvudpWcgPDV4G5gaI+7Q+g6zkrEIN\n8QI3UUX7aQKBgF0r/24IFRz3x9p0P+ynj5q5b50cTNvxPsS6wpZUxlaJqJf6IEQZ\nBgAgecRH1AZct7HT6vhDWBaJETjt+MrT+T9C5gxsW0Y/uUvRxaG/n4njxz/25Srx\nIslpwG6aZzTyazxmQvlHVq/GgS6gy+rYdvsckJZXxz4JDhof9yadsdZVAoGAPJM7\n97/Qyu7NwskIC1XFUBPK/4oz9kjuSBtSNLaaI9gkkgmY9MQR2fsvpxOlss0+kR8R\nvYwCmqv+KRcqgKmr5Y9HlPWBXzjSfZP1J1ebEkl8fT4GS1nWQkhspkpgkHj7g963\nE35Y1SFlba5QftYxsKVMc4XPKKKbH/W6SrGzjZkCgYEAnjAC8jkzLv3BbaZr76PO\n1nPOJcD3pFtC+r6TQoTPVJ5ek8/lX7GMk74VLQTf5rgyo1rhhb87O8w0tKMV4aHX\ncP97YrDg1N9GkCqV9Gxnaj5ZWI+0ikT3qaOu59lwjQoVxxXw0lMeCKQEt+1H79zv\nZ65V1+fkOMZzbi5hJAa4LNY=\n-----END PRIVATE KEY-----",
  public: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA470Dr/fUsOtu4b7Qwsqp\n4+12fUAzMUNHsihgTACs0nBR3ugtGr/Vw0rO0tgFT5Led+7Y+f8YE5LKgCVMKvEj\n1XvR8IVGY/ar6nexhCsb252ijTX+Daujy4XPmojUkvr5FPZ/CLVGW0+o+HRnc+73\ntRBuIufeUFwlNavwcn/QlMRnr5U6unYpZsfjLQ2FW30EfTVpD1Qc7RHVGs4t+ms/\nxwdXnOXYj3CRszpqbZwnwOdb3ycHOrwdPCrEdte4R59qP/6CEGljX2TfTlDTAEcU\nSb6ozCbRIoa6bq5M3dJFQTTazOBGn9SlwdmRaVmu4zlJzERO6ytu8KltE1lhh6ST\nNQIDAQAB\n-----END PUBLIC KEY-----"
}

// prettier-ignore
const pubKeys = {
  // Balochistan, Punjab and Federal Arms License
  ARMS_LICENSE: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA28dc1Tw7To//89HjvW1n\nx98RlyyypoF1JpRL06IKM+vwAZwFo+xvr7/GR1QHsMzivKuVswKOC6DhPzUwAj1o\nAojvcx43BTHGsYQkyrcILiSBpPH0PxMqfb4VeaGIy6sKcVrJzUeUDJ3PVceVBTtq\ntb42BnEu+NdBvEvIRfBf71enDVdm+h//RXBvL/EBpmC8yS/UI22B90PX6vM6GSaP\n0wocHQhioFKhU1/2d3XKwvjVvDousf+JzxK7EcKerriZRdwZ/BMs/ATiqpw3v9dJ\ncXCTasezZFrPWPHc4ChHF5Gy+18Gu0Gopkilg1m7OBygGOeSsef3QcheIAX32TUR\nGQIDAQAB\n-----END PUBLIC KEY-----",
  // National Database and Registration Authority
  NADRA: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo2FG4ZCwxYRdWEkHrmvO\ns/58ra/ekTaoB/9jM6vyg0l0R4yoKLQSSfKuBMt0ONp179lyp3qaKPvDK2XhV14O\nKFKfHTdBJ9NjgFs0fsaMWpMBgR+DU/wmmQqei0H8cB0xnGWsDaKZDdFnHmgpxpHH\nQJf3CHJzGfwex7pCBuAamMS6SOAKQWNyOt6p8pan/d7hvVA7ghvXS1c81I+o+V2b\ng3uPjwh9+pEN8ZI4qKq1wrNLBKk4oexHXZbR6EU5dUek/DP9y3k5iXkTrDfzOQDz\nLi9WlEWV9M+7Rf1O727ku1qg7gyF0WBOZeoTVVOjEwGHpz7p5/dK9zWpGrF9G/TL\naQIDAQAB\n-----END PUBLIC KEY-----",
  // Excise and Taxation Department
  ETD: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwgJocupiEWUDu1/JkI5I\n3cVH5jLNcDpYVXlzQlBoX0DeS5eeUzTshqPaEKe1PO/LMXPgY1K9Goig7n/S7vFr\n6GDbviT3BbDGhuG669iscj0yLZDsXMUCChKM5hzz0H2sXIK3sUzpN7nhRkgpfMLm\nL3Hr2ZVehSlHco4rAgj5Q/4SN8gBkPyNa+quOcNSfPFqA8LWtuBAK+S1objlQM/W\nF/EctchUg5VT4wvW+ywHXi8a1ZdEzuDp4e1FgJkmrKtHVoZB7ktUbes3Kv0uf0wk\nlVHs5B0KyWIODBiXMbFR4VcEHFEMzoRAwGwJ9S10SROVq/JAmu4ymsV0NdMdUmRf\n9wIDAQAB\n-----END PUBLIC KEY-----",
  // National Immunization Management System
  NIMS: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmdtreKdXsUEVPjSK5qD+\nginPM58uVo7xvlUP7gXWVq06U87KhTM0heJn+mpOMc7Qts8G8xNkEwLpXPdwUfxH\nTrwMnSyNx/C023JsvWuO2YevXJq+aBwgSjLcmL2zGhJk/H4S4pDUMLdRlWTXL/aw\nqZJbmk2yTbX66n6pAUPQEnvQ90F4itVJcup0nmdtbcTbZW1QcaPXSmfddab/xjjV\nddsbbTp7P6g3ngJ+6pmi4c3s6G9MVsGaCuiHP19KE2CKaMF3VExKzigX6zzSaHx/\nyBd9C540zmYPNpLHeVZXcI33HOh4o2yz57sd/dUd7ksl0YtrPO4dhmpt13Z/6cWN\nzwIDAQAB\n-----END PUBLIC KEY-----",
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

function sha256(data: string): Result {
  if (typeof data !== "string") return errorResult("data must be a string")

  // Platform independent
  return successResult(bytesToHex(sha256Raw(utf8ToBytes(data))))

  // Platforms with node:crypto support
  // const hash = crypto.createHash("sha256")
  // hash.update(data, "utf8")
  // return successResult(hash.digest("hex"))
}

function encode(data: any): Result {
  const prefix = "URN:VC1:"

  try {
    const cborBuffer = cbor2.encode(data)
    const gzipBuffer = pako.deflate(cborBuffer)
    return successResult(prefix + base45.encode(gzipBuffer))
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
    const cborBuffer = pako.inflate(gzipBuffer)
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
      DateTime.fromJSDate(date, { zone: "utc" }).toFormat("ddMMyyyyHHmm"),
    )

    // Platform independent
    const key = pbkdf2(sha256Raw, pin, salt, { c: 1000, dkLen: 16 })
    const bytes = new TextEncoder().encode(data)
    const encryptedBytes = ecb(key).encrypt(bytes)
    const encrypted = Buffer.from(encryptedBytes).toString("base64")

    // Platforms with node:crypto support
    // const key = crypto.pbkdf2Sync(pin, salt, 1000, 16, "sha256")
    // const cipher = crypto.createCipheriv("aes-128-ecb", key, null)
    // let encrypted = cipher.update(data, "utf8", "base64")
    // encrypted += cipher.final("base64")

    return successResult(encrypted)
  } catch (e) {
    if (debug) console.log(e)
    return errorResult("Failed to encrypt data")
  }
}

function decrypt(data: string, pin: string, date: Date): Result {
  try {
    const salt = Buffer.from(
      DateTime.fromJSDate(date, { zone: "utc" }).toFormat("ddMMyyyyHHmm"),
    )

    // Platform independent
    const key = pbkdf2(sha256Raw, pin, salt, { c: 1000, dkLen: 16 })
    const bytes = Buffer.from(data, "base64")
    const decryptedBytes = ecb(key).decrypt(bytes)
    const decrypted = new TextDecoder().decode(decryptedBytes)

    // Platforms with node:crypto support
    // const key = crypto.pbkdf2Sync(pin, salt, 1000, 16, "sha256")
    // const decipher = crypto.createDecipheriv("aes-128-ecb", key, null)
    // let decrypted = decipher.update(data, "base64", "utf8")
    // decrypted += decipher.final("utf8")

    return successResult(decrypted)
  } catch (e) {
    if (debug) console.log(e)
    return errorResult("Failed to decrypt data")
  }
}

function pemToBytes(pem: string): Buffer {
  const base64 = pem.split("\n").slice(1, -1).join("")
  return Buffer.from(base64, "base64")
}

const cryptoEngine = pkijs.getCrypto()

async function signRS256(
  data: Uint8Array,
  privateKey: Uint8Array,
): Promise<Result> {
  try {
    if (!cryptoEngine) return errorResult("Crypto engine is not available")

    const asn1 = asn1js.fromBER(privateKey)

    if (asn1.offset === -1) return errorResult("Failed to parse private key")

    const algorithm = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }

    const cryptoKey = await cryptoEngine.subtle.importKey(
      "pkcs8",
      privateKey,
      algorithm,
      true,
      ["sign"],
    )

    const signature = await cryptoEngine.subtle.sign(algorithm, cryptoKey, data)

    return successResult(Buffer.from(signature).toString("base64"))
  } catch (e) {
    if (debug) console.log(e)
    return errorResult("Failed to sign data")
  }
}

async function verifyRS256(
  data: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
): Promise<Result> {
  try {
    if (!cryptoEngine) return errorResult("Crypto engine is not available")

    const asn1 = asn1js.fromBER(publicKey)

    if (asn1.offset === -1) return errorResult("Failed to parse public key")

    // const publicKeyInfo = new pkijs.PublicKeyInfo({
    //   schema: asn1.result
    // }).toSchema()
    // console.log("Parsed Public Key Info", publicKeyInfo)

    const algorithm = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }

    const cryptoKey = await cryptoEngine.subtle.importKey(
      "spki",
      publicKey,
      algorithm,
      true,
      ["verify"],
    )

    const isValid = await cryptoEngine.subtle.verify(
      algorithm,
      cryptoKey,
      signature,
      data,
    )

    if (!isValid) return errorResult("Invalid signature")

    return successResult(true)
  } catch (e) {
    if (debug) console.log(e)
    return errorResult("Failed to verify signature")
  }
}

type SignOptions = {
  privateKeyPem?: string
}

async function sign(
  vc: Omit<VC, "proof">,
  options: SignOptions = {},
): Promise<Result> {
  if (!isPlainObject(vc)) {
    return errorResult("vc must be a plain object")
  }

  const privateKeyPem = options.privateKeyPem || testKeyPair.private

  if (typeof privateKeyPem !== "string") {
    return errorResult("options.privateKeyPem must be a string")
  }

  const vcWithoutProofStringified = JSON.stringify(vc)

  const data = vcWithoutProofStringified

  const dataBuffer = Buffer.from(data, "utf8")
  const privateKeyBuffer = pemToBytes(privateKeyPem)

  // Platform independent
  return await signRS256(dataBuffer, privateKeyBuffer)

  // Platforms with node:crypto support
  // const privateKey = crypto.createPrivateKey(privateKeyPem)
  // const signer = crypto.createSign("SHA256")
  // signer.update(dataBuffer)
  // signer.end()
  // return successResult(signer.sign(privateKey).toString("base64"))
}

type VerifyOptions = {
  publicKeyPem?: string
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

  if (!Array.isArray(vc.type)) {
    return errorResult("vc.type must be an array")
  }

  let defaultPublicKeyPem = pubKeys.NIMS

  if (vc.type.includes("NATIONAL_ID") || vc.type.includes("FRC"))
    defaultPublicKeyPem = pubKeys.NADRA

  if (vc.type.join(",").includes("ARMS_LICENSE"))
    defaultPublicKeyPem = pubKeys.ARMS_LICENSE

  if (vc.type.includes("VEHICLE_REGISTRATION_CARD"))
    defaultPublicKeyPem = pubKeys.ETD

  const publicKeyPem = options.publicKeyPem || defaultPublicKeyPem

  if (typeof publicKeyPem !== "string") {
    return errorResult("options.publicKeyPem must be a string")
  }

  const { proof, ...vcWithoutProof } = vc

  const vcWithoutProofStringified = JSON.stringify(vcWithoutProof)

  const data = vcWithoutProofStringified

  const dataBuffer = Buffer.from(data, "utf8")
  const signatureBuffer = Buffer.from(proof.jws, "base64")
  const publicKeyBuffer = pemToBytes(publicKeyPem)

  // Platform independent
  return await verifyRS256(dataBuffer, signatureBuffer, publicKeyBuffer)

  // Platforms with node:crypto support
  // const publicKey = crypto.createPublicKey(publicKeyPem)
  // const verifier = crypto.createVerify("SHA256")
  // verifier.update(dataBuffer)
  // verifier.end()
  // return verifier.verify(publicKey, signatureBuffer)
  //   ? successResult(true)
  //   : errorResult("Failed to verify signature")
}

// prettier-ignore
export { /*   */ testKeyPair, setDebug, normalizeText, encode, decode, sha256, timeRange, encrypt, decrypt, sign, verify }

// prettier-ignore
export default { testKeyPair, setDebug, normalizeText, encode, decode, sha256, timeRange, encrypt, decrypt, sign, verify }
