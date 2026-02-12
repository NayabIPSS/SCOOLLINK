function authorizeRoles(...allowedRoles) {
  return function rolesGuard(req, res, next) {
    const currentRole = req.user?.role

    if (!currentRole) {
      return res.status(403).json({ message: 'Role missing in token payload' })
    }

    if (!allowedRoles.includes(currentRole)) {
      return res.status(403).json({
        message: 'Insufficient permissions',
        required: allowedRoles,
        current: currentRole,
      })
    }

    return next()
  }
}

module.exports = {
  authorizeRoles,
}
