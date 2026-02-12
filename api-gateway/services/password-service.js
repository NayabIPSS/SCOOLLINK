const crypto = require('crypto')

const ITERATIONS = Number.parseInt(process.env.PASSWORD_HASH_ITERATIONS || '120000', 10)
const KEY_LENGTH = 64
const DIGEST = 'sha512'

function scryptAsync(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, KEY_LENGTH, (error, derivedKey) => {
      if (error) {
        reject(error)
      } else {
        resolve(derivedKey)
      }
    })
  })
}

async function hashPassword(plainTextPassword) {
  const salt = crypto.randomBytes(16).toString('hex')
  const derived = await scryptAsync(plainTextPassword, salt)
  return `${salt}:${ITERATIONS}:${DIGEST}:${derived.toString('hex')}`
}

async function verifyPassword(plainTextPassword, passwordHash) {
  const [salt, iterations, digest, hash] = passwordHash.split(':')
  if (!salt || !iterations || !digest || !hash) {
    return false
  }

  const derived = await scryptAsync(plainTextPassword, salt)
  const originalBuffer = Buffer.from(hash, 'hex')
  return crypto.timingSafeEqual(derived, originalBuffer)
}

module.exports = {
  hashPassword,
  verifyPassword,
}
