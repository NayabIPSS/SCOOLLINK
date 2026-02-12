const http = require('http')
const { signAccessToken } = require('./services/token-service')
const { authenticateToken, tenantMiddleware } = require('./middleware/auth')
const { authorizeRoles } = require('./middleware/roles')

function attachHelpers(res) {
  res.status = function status(code) {
    res.statusCode = code
    return res
  }
  res.json = function json(payload) {
    res.setHeader('content-type', 'application/json')
    res.end(JSON.stringify(payload))
    return res
  }
  return res
}

function runMiddlewares(req, res, middlewares, done) {
  let index = 0
  function next() {
    const middleware = middlewares[index]
    index += 1
    if (!middleware) {
      done()
      return
    }
    middleware(req, res, next)
  }
  next()
}

function createServer() {
  return http.createServer((req, res) => {
    attachHelpers(res)

    if (req.method === 'GET' && req.url === '/health') {
      return res.status(200).json({ status: 'OK' })
    }

    if (req.method === 'GET' && req.url === '/api/students') {
      return runMiddlewares(
        req,
        res,
        [authenticateToken, tenantMiddleware, authorizeRoles('SchoolAdmin', 'Teacher', 'Parent', 'Student')],
        () => res.status(200).json({ schoolId: req.tenant.schoolId, data: [{ id: 'stu-1', name: 'Aarav' }] }),
      )
    }

    if (req.method === 'GET' && req.url === '/api/schools') {
      return runMiddlewares(req, res, [authenticateToken, tenantMiddleware, authorizeRoles('SchoolAdmin', 'SuperAdmin')], () =>
        res.status(200).json({ schoolId: req.tenant.schoolId, message: 'school admin access granted' }),
      )
    }

    return res.status(404).json({ message: 'Not found' })
  })
}

async function run() {
  const server = createServer()
  await new Promise((resolve) => server.listen(0, resolve))
  const { port } = server.address()
  const baseUrl = `http://127.0.0.1:${port}`

  const adminToken = signAccessToken({
    sub: 'admin-1',
    email: 'admin@greenwood.edu',
    role: 'SchoolAdmin',
    school_id: 'school-1',
  })

  const studentToken = signAccessToken({
    sub: 'student-1',
    email: 'student@greenwood.edu',
    role: 'Student',
    school_id: 'school-1',
  })

  async function call(label, path, token, schoolId) {
    const response = await fetch(`${baseUrl}${path}`, {
      headers: {
        authorization: `Bearer ${token}`,
        'x-school-id': schoolId,
      },
    })
    const payload = await response.json()
    console.log(`${response.ok ? '✅' : '⛔'} ${label} -> ${response.status}`, payload)
  }

  console.log('--- HTTP preview: real endpoint calls ---')
  await call('Admin can access /api/students', '/api/students', adminToken, 'school-1')
  await call('Tenant mismatch is blocked', '/api/students', adminToken, 'school-999')
  await call('Student blocked from /api/schools', '/api/schools', studentToken, 'school-1')
  await call('Admin can access /api/schools', '/api/schools', adminToken, 'school-1')
  console.log('--- End HTTP preview ---')

  await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())))
}

run().catch((error) => {
  console.error(error)
  process.exit(1)
})
