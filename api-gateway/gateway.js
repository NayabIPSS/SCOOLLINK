const express = require('express')
const { createProxyMiddleware } = require('http-proxy-middleware')
const rateLimit = require('express-rate-limit')
const helmet = require('helmet')
const cors = require('cors')
const { authenticateToken, tenantMiddleware } = require('./middleware/auth')
const { authorizeRoles } = require('./middleware/roles')

const app = express()

app.use(helmet())
app.use(
  cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
    credentials: true,
  }),
)

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP',
})
app.use(limiter)

const coreGuards = [authenticateToken, tenantMiddleware]

app.use(
  '/api/auth',
  createProxyMiddleware({
    target: process.env.AUTH_SERVICE_URL || 'http://localhost:3001',
    changeOrigin: true,
    pathRewrite: { '^/api/auth': '' },
  }),
)

app.use(
  '/api/schools',
  ...coreGuards,
  authorizeRoles('SuperAdmin', 'SchoolAdmin'),
  createProxyMiddleware({
    target: process.env.SCHOOL_SERVICE_URL || 'http://localhost:3007',
    changeOrigin: true,
    pathRewrite: { '^/api/schools': '' },
  }),
)

app.use(
  '/api/students',
  ...coreGuards,
  authorizeRoles('SchoolAdmin', 'Teacher', 'Parent', 'Student'),
  createProxyMiddleware({
    target: process.env.STUDENT_SERVICE_URL || 'http://localhost:3002',
    changeOrigin: true,
    pathRewrite: { '^/api/students': '' },
  }),
)

app.use(
  '/api/tracking',
  ...coreGuards,
  authorizeRoles('SchoolAdmin', 'TransportAdmin', 'Parent', 'Student'),
  createProxyMiddleware({
    target: process.env.TRACKING_SERVICE_URL || 'http://localhost:3003',
    changeOrigin: true,
    pathRewrite: { '^/api/tracking': '' },
  }),
)

app.use(
  '/api/communication',
  ...coreGuards,
  createProxyMiddleware({
    target: process.env.COMMUNICATION_SERVICE_URL || 'http://localhost:3004',
    changeOrigin: true,
    pathRewrite: { '^/api/communication': '' },
  }),
)

app.use(
  '/api/shopping',
  ...coreGuards,
  createProxyMiddleware({
    target: process.env.SHOPPING_SERVICE_URL || 'http://localhost:3005',
    changeOrigin: true,
    pathRewrite: { '^/api/shopping': '' },
  }),
)

app.use(
  '/api/wellness',
  ...coreGuards,
  createProxyMiddleware({
    target: process.env.WELLNESS_SERVICE_URL || 'http://localhost:3006',
    changeOrigin: true,
    pathRewrite: { '^/api/wellness': '' },
  }),
)

app.use(
  '/api/ai/chat',
  ...coreGuards,
  createProxyMiddleware({
    target: process.env.AI_CHAT_SERVICE_URL || 'http://localhost:4001',
    changeOrigin: true,
    pathRewrite: { '^/api/ai/chat': '' },
  }),
)

app.use(
  '/api/ai/predictions',
  ...coreGuards,
  authorizeRoles('SuperAdmin', 'SchoolAdmin'),
  createProxyMiddleware({
    target: process.env.AI_PREDICTION_SERVICE_URL || 'http://localhost:4002',
    changeOrigin: true,
    pathRewrite: { '^/api/ai/predictions': '' },
  }),
)

app.get('/health', (_, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() })
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`API Gateway running on port ${PORT}`)
})
