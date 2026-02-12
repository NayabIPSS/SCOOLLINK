const { signAccessToken } = require('./services/token-service')
const { authenticateToken, tenantMiddleware } = require('./middleware/auth')
const { authorizeRoles } = require('./middleware/roles')

function makeReqRes(headers = {}, user = null) {
  return {
    req: { headers, user },
    res: {
      statusCode: 200,
      body: null,
      status(code) {
        this.statusCode = code
        return this
      },
      json(payload) {
        this.body = payload
        return this
      },
    },
  }
}

function runMiddleware(label, middleware, req, res) {
  let allowed = false
  middleware(req, res, () => {
    allowed = true
  })

  if (allowed) {
    console.log(`✅ ${label}: allowed`)
  } else {
    console.log(`⛔ ${label}: blocked with ${res.statusCode}`, res.body)
  }

  return allowed
}

function preview() {
  console.log('--- Scoollink multi-tenant auth/RBAC preview ---')

  const accessToken = signAccessToken({
    sub: 'user-school-admin-1',
    email: 'admin@greenwood.edu',
    role: 'SchoolAdmin',
    school_id: 'school-1',
  })

  const happyPath = makeReqRes({
    authorization: `Bearer ${accessToken}`,
    'x-school-id': 'school-1',
  })

  const canAuth = runMiddleware('authenticateToken', authenticateToken, happyPath.req, happyPath.res)
  if (!canAuth) return

  const canScope = runMiddleware('tenantMiddleware', tenantMiddleware, happyPath.req, happyPath.res)
  if (!canScope) return

  const schoolAdminGuard = authorizeRoles('SchoolAdmin', 'SuperAdmin')
  runMiddleware('authorizeRoles(SchoolAdmin,SuperAdmin)', schoolAdminGuard, happyPath.req, happyPath.res)

  const mismatchPath = makeReqRes(
    {
      authorization: `Bearer ${accessToken}`,
      'x-school-id': 'school-999',
    },
    null,
  )

  if (runMiddleware('authenticateToken (mismatch demo)', authenticateToken, mismatchPath.req, mismatchPath.res)) {
    runMiddleware('tenantMiddleware (mismatch demo)', tenantMiddleware, mismatchPath.req, mismatchPath.res)
  }

  const studentToken = signAccessToken({
    sub: 'student-1',
    email: 'student@greenwood.edu',
    role: 'Student',
    school_id: 'school-1',
  })

  const rolePath = makeReqRes({
    authorization: `Bearer ${studentToken}`,
    'x-school-id': 'school-1',
  })

  if (runMiddleware('authenticateToken (role demo)', authenticateToken, rolePath.req, rolePath.res)) {
    if (runMiddleware('tenantMiddleware (role demo)', tenantMiddleware, rolePath.req, rolePath.res)) {
      runMiddleware('authorizeRoles(SchoolAdmin,SuperAdmin) with Student token', schoolAdminGuard, rolePath.req, rolePath.res)
    }
  }

  console.log('--- End preview ---')
}

preview()
