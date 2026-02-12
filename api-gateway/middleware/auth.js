const { verifyAccessToken } = require('../services/token-service')

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization
  const token = authHeader && authHeader.split(' ')[1]

  if (!token) {
    return res.status(401).json({ message: 'Missing bearer token' })
  }

  try {
    const payload = verifyAccessToken(token)
    req.user = {
      id: payload.sub,
      email: payload.email,
      role: payload.role,
      schoolId: payload.school_id,
    }
    return next()
  } catch {
    return res.status(401).json({ message: 'Invalid or expired token' })
  }
}

function tenantMiddleware(req, res, next) {
  const schoolIdFromHeader = req.headers['x-school-id']
  const schoolIdFromToken = req.user?.schoolId

  if (!schoolIdFromToken) {
    return res.status(403).json({ message: 'Missing school scope in token' })
  }

  if (schoolIdFromHeader && schoolIdFromHeader !== schoolIdFromToken) {
    return res.status(403).json({ message: 'Tenant mismatch detected' })
  }

  req.tenant = { schoolId: schoolIdFromToken }
  return next()
}

module.exports = {
  authenticateToken,
  tenantMiddleware,
}
