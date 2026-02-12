const express = require('express')
const crypto = require('crypto')
const { hashPassword, verifyPassword } = require('../api-gateway/services/password-service')
const {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
} = require('../api-gateway/services/token-service')

const app = express()
app.use(express.json())

const refreshTokenStore = new Map()

const users = [
  {
    id: 'user-school-admin-1',
    schoolId: 'school-1',
    role: 'SchoolAdmin',
    email: 'admin@greenwood.edu',
    passwordHash: '',
  },
]

async function boot() {
  users[0].passwordHash = await hashPassword(process.env.DEMO_ADMIN_PASSWORD || 'ChangeMe123!')
}

function userPayload(user) {
  return {
    sub: user.id,
    email: user.email,
    role: user.role,
    school_id: user.schoolId,
  }
}

app.post('/login', async (req, res) => {
  const { email, password } = req.body
  const user = users.find((entry) => entry.email === email)

  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' })
  }

  const passwordIsValid = await verifyPassword(password, user.passwordHash)
  if (!passwordIsValid) {
    return res.status(401).json({ message: 'Invalid credentials' })
  }

  const payload = userPayload(user)
  const accessToken = signAccessToken(payload)
  const refreshToken = signRefreshToken(payload)
  const refreshTokenId = crypto.createHash('sha256').update(refreshToken).digest('hex')

  refreshTokenStore.set(refreshTokenId, {
    userId: user.id,
    schoolId: user.schoolId,
  })

  return res.json({ accessToken, refreshToken })
})

app.post('/refresh', (req, res) => {
  const { refreshToken } = req.body

  if (!refreshToken) {
    return res.status(400).json({ message: 'refreshToken is required' })
  }

  try {
    const decoded = verifyRefreshToken(refreshToken)
    const refreshTokenId = crypto.createHash('sha256').update(refreshToken).digest('hex')

    if (!refreshTokenStore.has(refreshTokenId)) {
      return res.status(401).json({ message: 'Refresh token not recognized' })
    }

    const accessToken = signAccessToken({
      sub: decoded.sub,
      email: decoded.email,
      role: decoded.role,
      school_id: decoded.school_id,
    })

    return res.json({ accessToken })
  } catch {
    return res.status(401).json({ message: 'Invalid refresh token' })
  }
})

app.get('/health', (_, res) => {
  res.json({ status: 'OK', service: 'auth-service', timestamp: new Date().toISOString() })
})

const PORT = process.env.AUTH_SERVICE_PORT || 3001

boot().then(() => {
  app.listen(PORT, () => {
    console.log(`Auth service running on port ${PORT}`)
  })
})
