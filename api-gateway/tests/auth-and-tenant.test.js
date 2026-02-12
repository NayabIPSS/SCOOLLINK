const test = require('node:test')
const assert = require('node:assert/strict')

const {
  signAccessToken,
  signRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
} = require('../services/token-service')
const { authenticateToken, tenantMiddleware } = require('../middleware/auth')
const { authorizeRoles } = require('../middleware/roles')

function createMockReqRes(headers = {}, user = null) {
  const req = { headers, user }
  const res = {
    statusCode: 200,
    payload: null,
    status(code) {
      this.statusCode = code
      return this
    },
    json(payload) {
      this.payload = payload
      return this
    },
  }
  return { req, res }
}

test('token validation: access and refresh tokens are signed and verified', () => {
  const payload = {
    sub: 'user-1',
    school_id: 'school-1',
    role: 'SchoolAdmin',
    email: 'admin@greenwood.edu',
  }

  const access = signAccessToken(payload)
  const refresh = signRefreshToken(payload)

  const decodedAccess = verifyAccessToken(access)
  const decodedRefresh = verifyRefreshToken(refresh)

  assert.equal(decodedAccess.sub, payload.sub)
  assert.equal(decodedAccess.school_id, payload.school_id)
  assert.equal(decodedRefresh.role, payload.role)
})

test('auth login chain: authenticateToken attaches user context', () => {
  const token = signAccessToken({
    sub: 'user-2',
    school_id: 'school-2',
    role: 'Teacher',
    email: 'teacher@school.edu',
  })

  const { req, res } = createMockReqRes({ authorization: `Bearer ${token}` })
  let nextCalled = false

  authenticateToken(req, res, () => {
    nextCalled = true
  })

  assert.equal(nextCalled, true)
  assert.equal(req.user.schoolId, 'school-2')
  assert.equal(req.user.role, 'Teacher')
})

test('school isolation: tenant middleware blocks cross-school header mismatch', () => {
  const { req, res } = createMockReqRes({ 'x-school-id': 'school-999' }, { schoolId: 'school-1' })
  let nextCalled = false

  tenantMiddleware(req, res, () => {
    nextCalled = true
  })

  assert.equal(nextCalled, false)
  assert.equal(res.statusCode, 403)
  assert.equal(res.payload.message, 'Tenant mismatch detected')
})

test('role guard: allows SchoolAdmin but blocks Student on admin route', () => {
  const adminGuard = authorizeRoles('SchoolAdmin')

  const allowCase = createMockReqRes({}, { role: 'SchoolAdmin' })
  let allowNext = false
  adminGuard(allowCase.req, allowCase.res, () => {
    allowNext = true
  })

  const denyCase = createMockReqRes({}, { role: 'Student' })
  let denyNext = false
  adminGuard(denyCase.req, denyCase.res, () => {
    denyNext = true
  })

  assert.equal(allowNext, true)
  assert.equal(denyNext, false)
  assert.equal(denyCase.res.statusCode, 403)
})
