const crypto = require('crypto')

const ACCESS_TOKEN_TTL_MS = Number.parseInt(process.env.ACCESS_TOKEN_TTL_MS || `${15 * 60 * 1000}`, 10)
const REFRESH_TOKEN_TTL_MS = Number.parseInt(process.env.REFRESH_TOKEN_TTL_MS || `${7 * 24 * 60 * 60 * 1000}`, 10)

function getAccessSecret() {
  return process.env.JWT_ACCESS_SECRET || 'dev-access-secret-change-me'
}

function getRefreshSecret() {
  return process.env.JWT_REFRESH_SECRET || 'dev-refresh-secret-change-me'
}

function encode(payload) {
  return Buffer.from(JSON.stringify(payload)).toString('base64url')
}

function decode(value) {
  return JSON.parse(Buffer.from(value, 'base64url').toString('utf8'))
}

function sign(rawPayload, secret, ttlMs) {
  const payload = {
    ...rawPayload,
    iat: Date.now(),
    exp: Date.now() + ttlMs,
  }
  const encodedPayload = encode(payload)
  const signature = crypto.createHmac('sha256', secret).update(encodedPayload).digest('base64url')
  return `${encodedPayload}.${signature}`
}

function verify(token, secret) {
  const [encodedPayload, signature] = token.split('.')
  if (!encodedPayload || !signature) {
    throw new Error('Malformed token')
  }

  const expectedSignature = crypto.createHmac('sha256', secret).update(encodedPayload).digest('base64url')
  if (expectedSignature !== signature) {
    throw new Error('Invalid signature')
  }

  const payload = decode(encodedPayload)
  if (!payload.exp || payload.exp < Date.now()) {
    throw new Error('Token expired')
  }

  return payload
}

function signAccessToken(payload) {
  return sign(payload, getAccessSecret(), ACCESS_TOKEN_TTL_MS)
}

function signRefreshToken(payload) {
  return sign(payload, getRefreshSecret(), REFRESH_TOKEN_TTL_MS)
}

function verifyAccessToken(token) {
  return verify(token, getAccessSecret())
}

function verifyRefreshToken(token) {
  return verify(token, getRefreshSecret())
}

module.exports = {
  signAccessToken,
  signRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
}
