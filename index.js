// import crypto from "crypto"
import ms from "ms"
import cbor from "cbor"
import pako from "pako"
import base45 from "base45"
import * as pkijs from "pkijs"
import * as asn1js from "asn1js"
import { Buffer } from "buffer"
import { DateTime } from "luxon"
import { ecb } from "@noble/ciphers/aes.js"
import { pbkdf2 } from "@noble/hashes/pbkdf2.js"
import { sha256 as sha256Raw } from "@noble/hashes/sha2.js"
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js"

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

/**
 * @param {boolean} value
 */
function setDebug(value) {
  debug = value
}

/**
 * @param {string} message
 */
function error(message) {
  return { error: message }
}

/**
 * @param {string} text
 * @returns {{data: string} | {error: string}}
 */
function removeBidiControls(text) {
  if (typeof text !== "string") return error("text must be a string")

  // \u061c: Arabic Letter Mark (ALM)
  // \u200e-\u200f: Left-to-Right / Right-to-Left Marks
  // \u202a-\u202e: Embedding and Override controls (LRE, RLE, PDF, LRO, RLO)
  // \u2066-\u2069: Isolate controls (LRI, RLI, FSI, PDI)
  return text.replace(/[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, "")
}

/**
 * @param {string} text
 * @returns {{data: string} | {error: string}}
 */
function normalizeText(text) {
  if (typeof text !== "string") return error("text must be a string")

  const data = removeBidiControls(text)
    .split("،")
    .map((s) => s.trim())
    .join("، ")

  return { data }
}

function isPlainObject(value) {
  if (Object.prototype.toString.call(value) !== "[object Object]") return false
  const proto = Object.getPrototypeOf(value)
  return proto === Object.prototype || proto === null
}

function range(start, end, step = 1) {
  const result = []
  for (let i = start; i <= end; i += step) result.push(i)
  return result
}

function ceilStep(value, step) {
  return Math.ceil(value / step) * step
}

function roundStep(value, step) {
  return Math.round(value / step) * step
}

function floorStep(value, step) {
  return Math.floor(value / step) * step
}

// https://stackoverflow.com/questions/1353684/detecting-an-invalid-date-date-instance-in-javascript
function isValidDate(d) {
  return d instanceof Date && !isNaN(d)
}

/**
 * Generates SHA-256 hash of a string
 * @param {string} data - The data to hash
 * @returns {{data: string} | {error: string}} Hexadecimal representation of the hash
 */
function sha256(data) {
  if (typeof data !== "string") return error("data must be a string")
  // const hash = crypto.createHash("sha256")
  // hash.update(data, "utf8")
  // return { data: hash.digest("hex") }
  return { data: bytesToHex(sha256Raw(utf8ToBytes(data))) }
}

/**
 * @param {string} data - the digital ID data to decode
 * @returns {{data: string} | {error: string}} result of the decoding process
 */
function decode(data) {
  if (typeof data !== "string") return error("data must be a string")
  if (!data) return error("data must not be an empty string")

  const prefix = "URN:VC1:"
  const base45String = data.startsWith(prefix)
    ? data.slice(prefix.length)
    : data

  try {
    const gzipBuffer = base45.decode(base45String)
    const cborBuffer = pako.inflate(gzipBuffer)
    const jsonString = cbor.decodeFirstSync(cborBuffer)
    return { data: JSON.parse(jsonString) }
  } catch (e) {
    if (debug) console.log(e)
    return error("Failed to decode data")
  }
}

/**
 * @param {Object} [options]
 * @param {Object} [options.bounds]
 * @param {Date} [options.bounds.start]
 * @param {Date} [options.bounds.end]
 * @param {number} [options.step] - step in milliseconds (default: 5 minutes)
 * @param {Date} [options.now] - reference date for generating time range (default: current date)
 * @returns {{data: Date[]} | {error: string}} array of Date objects representing the time range
 */
function timeRange(options = {}) {
  if (options && !isPlainObject(options))
    return error("options must be a plain object")

  const bounds = options.bounds
  const step = options.step ?? ms("5m")
  const now = options.now ?? new Date()

  if (!Number.isInteger(step)) return error("options.step must be an integer")
  if (step <= 0) return error("options.step must be greater than 0")

  if (bounds) {
    if (!isPlainObject(bounds))
      return error("options.bounds must be a plain object")
    if (!isValidDate(bounds.start))
      return error("options.bounds.start must be a valid date")
    if (!isValidDate(bounds.end))
      return error("options.bounds.end must be a valid date")
    if (bounds.start >= bounds.end)
      return error("options.bounds.start must be less than options.bounds.end")

    const start = floorStep(bounds.start, step)
    const end = ceilStep(bounds.end, step)
    const dateRange = range(start, end, step)
    return { data: dateRange.map((t) => new Date(t)) }
  } else {
    if (!isValidDate(now)) return error("options.now must be a valid date")

    const closest = roundStep(now, step)
    const dateRange = range(closest - step, closest + step, step)
    return { data: dateRange.map((t) => new Date(t)) }
  }
}

/**
 * @param {string} data - the digital ID data to decrypt
 * @param {string} pin - the PIN code to use for decryption
 * @param {Date} date - the date to use for generating the salt
 * @returns {{data: string} | {error: string}} result of the decryption process
 */
function decrypt(data, pin, date) {
  try {
    const salt = Buffer.from(
      DateTime.fromJSDate(date, { zone: "utc" }).toFormat("ddMMyyyyHHmm")
    )

    const encryptedBytes = Buffer.from(data, "base64")
    const key = pbkdf2(sha256Raw, pin, salt, { c: 1000, dkLen: 16 })
    const decrypted = new TextDecoder().decode(ecb(key).decrypt(encryptedBytes))

    // const key = crypto.pbkdf2Sync(pin, salt, 1000, 16, "sha256")
    // const decipher = crypto.createDecipheriv("aes-128-ecb", key, null)
    // let decrypted = decipher.update(data, "base64", "utf8")
    // decrypted += decipher.final("utf8")

    return { data: decrypted }
  } catch (e) {
    if (debug) console.log(e)
    return error("Failed to decrypt data")
  }
}

/**
 * Convert PEM to bytes
 * @param {string} pem - PEM formatted string
 */
function pemToBytes(pem) {
  const base64 = pem.split("\n").slice(1, -1).join("")
  return Buffer.from(base64, "base64")
}

/**
 * Raw RS256 signature verification
 * @param {Uint8Array} data - Signed message bytes
 * @param {Uint8Array} signature - Raw signature bytes
 * @param {Uint8Array} publicKey - Public key bytes
 * @returns {Promise<{data: true} | {error: string}>}
 */
async function verifyRS256(data, signature, publicKey) {
  try {
    const asn1 = asn1js.fromBER(publicKey)

    if (asn1.offset === -1) throw new Error("Failed to parse public key")

    // const publicKeyInfo = new pkijs.PublicKeyInfo({
    //   schema: asn1.result
    // }).toSchema(true)
    // console.log("Parsed Public Key Info", publicKeyInfo)

    const algorithm = { hash: "SHA-256", name: "RSASSA-PKCS1-v1_5" }

    const cryptoKey = await pkijs
      .getCrypto()
      .subtle.importKey("spki", publicKey, algorithm, true, ["verify"])

    const isValid = await pkijs
      .getCrypto()
      .subtle.verify(algorithm, cryptoKey, signature, data)

    if (!isValid) throw new Error("Invalid signature")

    return { data: true }
  } catch (e) {
    if (debug) console.log(e)
    return error("Signature does not match data")
  }
}

/**
 * Verifies a Signed Verifiable Credential.
 * @param {Object} vc - The Verifiable Credential.
 * @param {Object} [options] - Optional parameters for verification.
 * @param {string} [options.publicKeyPem] - The RSA Public Key (PEM format).
 * @returns {Promise<{data: true} | {error: string}>} Returns true if the signature is valid.
 */
async function verify(vc, options = {}) {
  if (!isPlainObject(vc)) {
    return error("vc must be a plain object")
  }

  if (!isPlainObject(vc.proof)) {
    return error("vc.proof must be a plain object")
  }

  if (typeof vc.proof.jws !== "string") {
    return error("vc.proof.jws must be a string")
  }

  if (!Array.isArray(vc.type)) {
    return error("vc.type must be an array")
  }

  let defaultPublicKeyPem = pubKeys.NIMS

  if (vc.type.includes("NATIONAL_ID") || vc.type.includes("FRC"))
    defaultPublicKeyPem = pubKeys.NADRA

  if (vc.type.join(",").includes("ARMS_LICENSE"))
    defaultPublicKeyPem = pubKeys.ARMS_LICENSE

  if (vc.type.includes("VEHICLE_REGISTRATION_CARD"))
    defaultPublicKeyPem = pubKeys.ETD

  const publicKeyPem = options.publicKeyPem || defaultPublicKeyPem

  if (publicKeyPem && typeof publicKeyPem !== "string") {
    return error("options.publicKeyPem must be a string")
  }

  const vcWithoutProof = { ...vc }
  delete vcWithoutProof.proof

  const vcWithoutProofStringified = JSON.stringify(vcWithoutProof)

  const data = vcWithoutProofStringified

  const signatureBuffer = Buffer.from(vc.proof.jws, "base64")
  const dataBuffer = Buffer.from(data, "utf8")
  const publicKeyBuffer = pemToBytes(publicKeyPem)

  // const publicKey = crypto.createPublicKey(publicKeyPem)
  // const verifier = crypto.createVerify("SHA256")
  // verifier.update(dataBuffer)
  // verifier.end()
  // return { data: verifier.verify(publicKey, signatureBuffer) }

  return await verifyRS256(dataBuffer, signatureBuffer, publicKeyBuffer)
}

// prettier-ignore
export { /*   */ setDebug, normalizeText, decode, sha256, timeRange, decrypt, verify }

// prettier-ignore
export default { setDebug, normalizeText, decode, sha256, timeRange, decrypt, verify }
