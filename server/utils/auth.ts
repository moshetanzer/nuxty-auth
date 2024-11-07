import crypto from 'crypto'
import pg from 'pg'
import argon2 from 'argon2'
import type { H3Event } from 'h3'
import type { User, Session } from '#shared/types'

const { Pool } = pg
const config = useRuntimeConfig()

const connectionString = config.authConnectionString
const authDB = new Pool({
  connectionString
})

const AUTH_TABLE_NAME = escapeTableName(config.authUserTableName)
const SESSION_TABLE_NAME = escapeTableName(config.authSessionTableName)
const MFA_TABLE_NAME = escapeTableName(config.authMfaTableName)
// const EMAIL_VERIFICATION_TABLE_NAME = escapeTableName(config.authEmailVerificationTableName)
const EMAIL_OTP_EXPIRY = 15 // mins

const MAX_FAILED_ATTEMPTS = config.maxFailedAttempts || 10 as number

const RATE_LIMIT = 100
const RATE_LIMIT_WINDOW = 60

const SESSION_TOTAL_DURATION = 43200 // mins (30 days)
const SESSION_REFRESH_INTERVAL = 720 // mins (12 hours)
const SESSION_EXTENSION_DURATION = 10080 // mins (7 days)

const ARGON2_CONFIG = {
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 4,
  parallelism: 1
}

if (!connectionString) {
  console.error('No connection string provided for auth table')
  process.exit(1)
}
if (!AUTH_TABLE_NAME) {
  console.error('No auth table name provided')
  process.exit(1)
}
if (!SESSION_TABLE_NAME) {
  console.error('No session table name provided')
  process.exit(1)
}

function escapeTableName(val: string): string {
  if (val.includes('.')) return val
  return `"${val}"`
}
async function hashPassword(password: string): Promise<string | false> {
  try {
    return await argon2.hash(password, ARGON2_CONFIG)
  } catch (error) {
    await auditLogger('unknown', 'hashPassword', String((error as Error).message), 'unknown', 'unknown', 'error')
    return false
  }
}
async function verifyPassword(email: string, password: string, hash: string): Promise<boolean> {
  try {
    if (await argon2.verify(hash, password)) {
      return true
    } else {
      await auditLogger(email, 'verifyPassword', 'Password does not match', 'unknown', 'unknown', 'error')
      return false
    }
  } catch (error) {
    await auditLogger(email, 'verifyPassword', String((error as Error).message), 'unknown', 'unknown', 'error')
    return false
  }
}

async function checkIfLocked(email: string): Promise<boolean> {
  try {
    if (!email) {
      throw createError({
        statusMessage: 'Email is required',
        statusCode: 400
      })
    }

    const result = await authDB.query<User>(`SELECT email, failed_attempts FROM ${AUTH_TABLE_NAME} WHERE email = $1`, [email])

    if (!result?.rows?.[0]) {
      await auditLogger(email, 'checkIfLocked', 'Account not found', 'unknown', 'unknown', 'error')
      return false
    }
    const isLocked = result.rows[0].failed_attempts >= MAX_FAILED_ATTEMPTS

    if (isLocked) {
      await auditLogger(email, 'checkIfLocked', 'Account locked', 'unknown', 'unknown', 'error')
      return true
    } else {
      return false
    }
  } catch (error) {
    await auditLogger(email, 'checkIfLocked', String((error as Error).message), 'unknown', 'unknown', 'error')
    return false
  }
}
async function incrementFailedAttempts(email: string): Promise<void> {
  try {
    await authDB.query(`UPDATE ${AUTH_TABLE_NAME} SET failed_attempts = failed_attempts + 1 WHERE email = $1`, [email])
  } catch (error) {
    await auditLogger(email, 'incrementFailedAttempts', String((error as Error).message), 'unknown', 'unknown', 'error')
  }
}
async function resetFailedAttempts(email: string): Promise<void> {
  try {
    await authDB.query(`UPDATE ${AUTH_TABLE_NAME} SET failed_attempts = 0 WHERE email = $1`, [email])
  } catch (error) {
    await auditLogger(email, 'resetFailedAttempts', String((error as Error).message), 'unknown', 'unknown', 'error')
  }
}

/**
   * Authenticates a user using their email and password.
   * @param email - The email address of the user to authenticate.
   * @param password - The password of the user to authenticate.
   * @returns The user data if the authentication is successful, otherwise null.
   * @throws {Error} If the user is locked.
   * @throws {Error} If the email or password is invalid.
   */
export async function authenticateUser(event: H3Event): Promise<User | null> {
  const { email, password } = await readBody(event)
  try {
    const result = await authDB.query(`SELECT * FROM ${AUTH_TABLE_NAME} WHERE email = $1`, [email])

    if (result.rows.length === 0) {
      await verifyPassword(email, password, '$argon2id$v=19$m=16,t=2,p=1$d050OUJMT1RzckoxbGdxYQ$+CQAgx/TccW9Ul/85vo7tg')
      return null
    }

    const user = result.rows[0]

    const locked = await checkIfLocked(user.email)
    if (locked) {
      throw createError({
        statusCode: 401,
        statusMessage: 'Account locked'
      })
    }

    const isValid = await verifyPassword(user.email, password, user.password)
    if (!isValid) {
      await incrementFailedAttempts(user.email)
      throw createError({
        statusCode: 401,
        statusMessage: 'Invalid email or password'
      })
    }
    await resetFailedAttempts(user.email)
    return user
  } catch (error) {
    await auditLogger(email, 'authenticateUser', String((error as Error).message), 'unknown', 'unknown', 'error')
    return null
  }
}

/**
   * Creates a new user.
   *
   * @param fname - The first name of the new user.
   * @param lname - The last name of the new user.
   * @param email - The email address of the new user.
   * @param password - The password of the new user.
   * @param role - The role of the new user (e.g. 'user', 'admin').
   *
   * @returns The id of the created user, or null if there was an error.
   */
export async function createUser(event: H3Event): Promise<string | null> {
  const { fname, lname, email, password } = await readBody(event)
  const role = useRuntimeConfig(event).defaultUserRole || 'user'
  try {
    const userId = crypto.randomUUID()
    const hashedPassword = await hashPassword(password)

    const result = await authDB.query(`
      INSERT INTO ${AUTH_TABLE_NAME} (id, fname, lname, email, password, role, failed_attempts)
      VALUES ($1, $2, $3, $4, $5, $6, 0)
      RETURNING id
    `, [userId, fname, lname, email, hashedPassword, role])
    return result.rows[0].id
  } catch (error) {
    await auditLogger(email, 'createUser', String((error as Error).message), 'unknown', 'unknown', 'error')
    return null
  }
}

export async function createSession(event: H3Event, userId: string): Promise<void> {
  const sessionId = crypto.randomUUID()

  const { email } = await readBody(event)
  try {
    await authDB.query<Session>(`
      INSERT INTO ${SESSION_TABLE_NAME} (
        id,
        user_id,
        expires_at,
        mfa_verified
      )
      VALUES (
        $1,
        $2,
        NOW() + (INTERVAL '1 minute' * $3),
        false
      )
      RETURNING *
    `,
    [sessionId, userId, SESSION_TOTAL_DURATION]
    )
    setCookie(event, 'mediCloudID', sessionId, {
      path: '/',
      maxAge: SESSION_TOTAL_DURATION * 60,
      httpOnly: true,
      sameSite: 'lax',
      secure: true
    })
  } catch (error) {
    await auditLogger(email, 'createSession', String((error as Error).message), 'unknown', 'unknown', 'error')
  }
}
export async function handleSession(event: H3Event): Promise<boolean> {
  const sessionId = getCookie(event, 'mediCloudID')
  if (!sessionId) {
    event.context.session = null
    event.context.user = null
    return false
  }

  try {
    const query = `
    SELECT 
      s.*, 
      u.role, 
      u.fname, 
      u.lname, 
      u.email, 
      u.email_verified, 
      u.mfa,
      (s.created_at + INTERVAL '${Number(SESSION_TOTAL_DURATION) / 1000} seconds') AS absolute_expiration
    FROM sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.id = $1 
      AND s.expires_at > NOW() 
      AND (s.created_at + INTERVAL '${Number(SESSION_TOTAL_DURATION) / 1000} seconds') > NOW()
  `

    const result = await authDB.query(query, [sessionId])

    if (result.rows.length === 0) {
      return false
    }

    const sessionRow = result.rows[0]
    const currentTime = new Date()
    const expiresAt = new Date(sessionRow.expires_at)
    const slidingWindowThreshold = new Date(currentTime.getTime() - Number(SESSION_REFRESH_INTERVAL))

    if (expiresAt <= slidingWindowThreshold) {
      try {
      // Extend session expiration
        await refreshSession(sessionId)
      } catch (refreshError) {
        await auditLogger(
          sessionRow.email,
          'sessionRefresh',
          `Automatic session refresh failed: ${String(refreshError)}`,
          'unknown',
          'unknown',
          'warning'
        )
      // Continue with existing session even if refresh fails
      }
    }

    const session: Session = {
      id: sessionRow.id,
      user_id: sessionRow.user_id,
      expires_at: sessionRow.expires_at,
      mfa_verified: sessionRow.mfa_verified
    }

    const user: Partial<User> = {
      role: sessionRow.role,
      fname: sessionRow.fname,
      lname: sessionRow.lname,
      email: sessionRow.email,
      email_verified: sessionRow.email_verified,
      id: sessionRow.user_id,
      mfa: sessionRow.mfa
    }

    const sessionData = { session, user }

    if (sessionData) {
      const { session, user } = sessionData
      event.context.session = session
      event.context.user = user
      return true
    } else {
      event.context.session = null
      event.context.user = null
      await deleteSession(event)
      return false
    }
  } catch (error) {
    console.error('Session handling error:', error)
    event.context.session = null
    event.context.user = null
    await deleteSession(event)
    await auditLogger('unknown', 'handleSession', String((error as Error).message), 'unknown', 'unknown', 'error')
    return false
  }
}

export async function refreshSession(sessionId: string): Promise<void> {
  try {
    await authDB.query(`
      UPDATE ${SESSION_TABLE_NAME}
      SET expires_at = NOW() + (INTERVAL '1 minute' * $1)
      WHERE id = $2
    `, [SESSION_TOTAL_DURATION, sessionId])
  } catch (error) {
    await auditLogger('unknown', 'refreshSession', String((error as Error).message), 'unknown', 'unknown', 'error')
    console.error('Failed to refresh session:', error)
  }
}
export async function handleRateLimit(event: H3Event): Promise<void> {
  const storage = useStorage()
  const ip = getClientIP(event)
  const userAgent = event.node.req.headers['user-agent'] as string
  const key = `rate-limit:${ip}`

  const [current, ttl] = await storage.getItem<[number, number]>(key) || [0, 0]

  if (current >= RATE_LIMIT) {
    setRateLimitHeaders(event, current, ttl)
    await auditLogger('unknown', 'handleRateLimit', 'Too many requests', ip, userAgent, 'error')
    throw createError({
      statusCode: 429,
      statusMessage: 'Too Many Requests'
    })
  }

  const newCount = current + 1
  if (newCount === 1) {
    await storage.setItem(key, [newCount, RATE_LIMIT_WINDOW], { ttl: RATE_LIMIT_WINDOW })
  } else {
    await storage.setItem(key, [newCount, ttl])
  }

  setRateLimitHeaders(event, newCount, ttl)

  function getClientIP(event: H3Event): string {
    return event.node.req.headers['x-forwarded-for'] as string
      || event.node.req.connection.remoteAddress as string
  }

  function setRateLimitHeaders(event: H3Event, current: number, ttl: number): void {
    event.node.res.setHeader('X-RateLimit-Limit', RATE_LIMIT)
    event.node.res.setHeader('X-RateLimit-Remaining', Math.max(0, RATE_LIMIT - current))
    event.node.res.setHeader('X-RateLimit-Reset', Math.ceil(Date.now() / 1000 + ttl))
  }
}
export async function deleteSession(event: H3Event): Promise<void> {
  const sessionId = event.context.session?.id
  try {
    await authDB.query(`DELETE FROM ${SESSION_TABLE_NAME} WHERE id = $1`, [sessionId])
    deleteCookie(event, 'mediCloudID')
  } catch (error) {
    await auditLogger('unknown', 'deleteSession', String((error as Error).message), 'unknown', 'unknown', 'error')
  }
}
export async function cleanupExpiredSessions(): Promise<void> {
  try {
    await authDB.query(`
          DELETE FROM ${SESSION_TABLE_NAME}
          WHERE expires_at <= NOW()
          OR created_at + (INTERVAL '1 minute' * $1) <= NOW()`,
    [SESSION_TOTAL_DURATION + SESSION_EXTENSION_DURATION]
    )
  } catch (error) {
    await auditLogger('system', 'cleanupExpiredSessions', String((error as Error).message), 'unknown', 'unknown', 'error')
  }
}

export async function resetPasswordRequest(event: H3Event) {
  try {
    const { email } = await readBody(event)

    if (!email) {
      throw createError({
        statusCode: 400,
        statusMessage: 'Email is required'
      })
    }
    const user = await authDB.query<User>(`SELECT id, email, reset_token, reset_token_expires_at FROM users WHERE email = $1`, [email]).catch(async (error) => {
      await auditLogger(
        email,
        'resetPasswordRequest',
        `Database error: ${String((error as Error).message)}`,
        'unknown',
        'unknown',
        'error'
      )
      throw createError({
        statusCode: 500,
        statusMessage: 'An error occurred processing your request'
      })
    })
    let resetToken: string
    let resetTokenExpiry: Date
    let hashedToken: string

    if (user.rows.length === 0) {
      // Still generate a token to prevent timing attacks, but don't save it
      resetToken = crypto.randomUUID()
      resetTokenExpiry = new Date(Date.now() + 60 * 60 * 1000)
      hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex')
      const errorEmailAddress = useRuntimeConfig().emailUser
      await auditLogger(email, 'resetPasswordRequest', 'Email not found', 'unknown', 'unknown', 'error')
      await sendEmail(errorEmailAddress, 'Password reset failed - ensure no timing attack', `Click <a href="${useRuntimeConfig().baseUrl}/reset-password/${resetToken}">here</a> to reset your password.`)

      return true
    }

    const existingToken = user.rows[0].reset_token
    const existingTokenExpiry = user.rows[0].reset_token_expires_at

    if (existingToken && existingTokenExpiry && new Date(existingTokenExpiry) > new Date()) {
      resetToken = existingToken
      resetTokenExpiry = new Date(existingTokenExpiry)
      hashedToken = existingToken
    } else {
    // Invalidate existing tokens and generate a new one
      resetToken = crypto.randomUUID()
      resetTokenExpiry = new Date(Date.now() + 60 * 60 * 1000) // 1 hour from now
      hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex')
    }

    await authDB.query(`
      UPDATE users
      SET reset_token = $1, reset_token_expires_at = $2
      WHERE email = $3
    `, [hashedToken, resetTokenExpiry, email]).catch(async (error) => {
      await auditLogger(
        email,
        'resetPasswordRequest',
        `Token update failed: ${String((error as Error).message)}`,
        'unknown',
        'unknown',
        'error'
      )
      throw createError({
        statusCode: 500,
        statusMessage: 'An error occurred processing your request'
      })
    })

    await sendEmail(email, 'Password Reset Request', `Click <a href="${useRuntimeConfig().baseUrl}/reset-password/${resetToken}">here</a> to reset your password.`).catch(async (error) => {
      await auditLogger(
        email,
        'resetPasswordRequest',
        `Email sending failed: ${String((error as Error).message)}`,
        'unknown',
        'unknown',
        'error'
      )
      throw createError({
        statusCode: 500,
        statusMessage: 'An error occurred processing your request'
      })
    })
    return true
  } catch (error) {
    await auditLogger('unknown', 'resetPasswordRequest', String((error as Error).message), 'unknown', 'unknown', 'error')
    throw createError({
      statusCode: 500,
      statusMessage: 'An unexpected error occurred'
    })
  }
}

export async function verifyResetToken(event: H3Event) {
  try {
    const { resetToken: token } = getRouterParams(event)

    if (!token) {
      throw createError({
        statusCode: 400,
        statusMessage: 'Reset token is required'
      })
    }
    let hashedToken: string
    try {
      hashedToken = crypto.createHash('sha256').update(token).digest('hex')
    } catch (error) {
      await auditLogger('unknown', 'verifyResetToken', String((error as Error).message), 'unknown', 'unknown', 'error')
      throw createError({
        statusCode: 500,
        statusMessage: 'Failed to process reset token'
      })
    }
    const result = await authDB.query<User>(`SELECT * FROM users WHERE reset_token = $1 AND reset_token_expires_at > NOW()`, [hashedToken]).catch(async (error) => {
      await auditLogger('unknown', 'verifyResetToken', String((error as Error).message), 'unknown', 'unknown', 'error')
      throw createError({
        statusCode: 500,
        statusMessage: 'Error verifying reset token'
      })
    })
    if (result.rows.length === 0) {
      await auditLogger('unknown', 'verifyResetToken', 'Invalid token', 'unknown', 'unknown', 'error')
      return false
    } else if (result.rows.length === 1) {
      await auditLogger(result.rows[0].email, 'verifyResetToken', 'Token verified', 'unknown', 'unknown', 'success')
      return true
    }
  } catch (error) {
    await auditLogger('unknown', 'verifyResetToken', String((error as Error).message), 'unknown', 'unknown', 'error')
    throw createError({
      statusCode: 500,
      statusMessage: 'An unexpected error occurred'
    })
  }
}

export async function resetPassword(event: H3Event) {
  try {
    const { resetToken, password, confirmPassword } = await readBody(event)

    if (!resetToken || !password || !confirmPassword) {
      throw createError({
        statusCode: 400,
        statusMessage: 'Missing required fields'
      })
    }

    if (password !== confirmPassword) {
      throw createError({
        statusCode: 400,
        statusMessage: 'Passwords do not match'
      })
    }
    let hashedToken: string
    try {
      hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex')
    } catch (error) {
      await auditLogger('unknown', 'resetPassword', String((error as Error).message), 'unknown', 'unknown', 'error')
      throw createError({
        statusCode: 500,
        statusMessage: 'Failed to process reset token'
      })
    }
    const result = await authDB.query<User>(`SELECT * FROM users WHERE reset_token = $1 AND reset_token_expires_at > NOW()`, [hashedToken]).catch(async (error) => {
      await auditLogger('unknown', 'resetPassword', String((error as Error).message), 'unknown', 'unknown', 'error')
      throw createError({
        statusCode: 500,
        statusMessage: 'Database error while checking reset token'
      })
    })
    const user = result.rows[0]
    if (!user) {
      throw createError({
        statusCode: 400,
        statusMessage: 'Invalid token'
      })
    }

    const hashedPassword = await hashPassword(password)

    await authDB.query(`UPDATE users SET password = $1, reset_token = NULL, reset_token_expires_at = NULL WHERE id = $2`, [hashedPassword, user.id]).catch(async (error) => {
      await auditLogger(
        user.email,
        'resetPassword',
        String((error as Error).message),
        'unknown',
        'unknown',
        'error'
      )
      throw createError({
        statusCode: 500,
        statusMessage: 'Failed to update password'
      })
    })

    await auditLogger(
      user.email,
      'resetPassword',
      'Password reset successful',
      'unknown',
      'unknown',
      'success'
    ).catch(() => {
      console.error('Failed to log password reset success')
    })

    return true
  } catch (error) {
    await auditLogger('unknown', 'resetPassword', String((error as Error).message), 'unknown', 'unknown', 'error')
    throw createError({
      statusCode: 500,
      statusMessage: 'An unexpected error occurred'
    })
  }
}

export async function roleBasedAuth(event: H3Event) {
  const rules = getRouteRules(event).nuxtyAuth?.roles as string[]
  const to = event.node.req.url

  if (!rules || rules.length === 0) {
    return // No rules defined, allow access
  }

  if (!event.context.user?.role) {
    const ip = getRequestIP(event) as string
    const userAgent = event.node.req.headers['user-agent'] as string
    await auditLogger('unknown', 'roleBasedAuth', 'Unauthorized', ip, userAgent, 'error')
    console.log('Unauthorized: No role')
    return event.node.res.writeHead(403).end('Unauthorized: No role')
  }

  const userRole = event.context.user?.role as string
  if (!hasRequiredRole(userRole, rules)) {
    const ip = getRequestIP(event) as string
    const userAgent = event.node.req.headers['user-agent'] as string
    auditLogger(event.context.user?.email ?? 'unknown', 'roleBasedAuth', 'Unauthorized', ip, userAgent, 'error')
    console.log('Unauthorized: Insufficient role')
    return event.node.res.writeHead(403).end('Unauthorized: Insufficient role')
  }

  if (to && !checkAccess(userRole, to, rules)) {
    const ip = getRequestIP(event) as string
    const userAgent = event.node.req.headers['user-agent'] as string
    auditLogger(event.context.user?.email ?? 'unknown', 'roleBasedAuth', 'Unauthorized', ip, userAgent, 'error')
    console.log('Unauthorized: No access to this route')
    return event.node.res.writeHead(403).end('Unauthorized: No access to this route')
  }
}

function hasRequiredRole(userRole: string, requiredRoles: string[]): boolean {
  return requiredRoles.some(role => userRole === role)
}

function checkAccess(userRole: string, to: string, rules: string[]): boolean {
  return rules.some((rule) => {
    const [roleName, routePattern] = rule.split(':')
    const regex = new RegExp(routePattern)
    return regex.test(to) && userRole === roleName
  })
}
export async function emailVerification(event: H3Event) {
  const rules = getRouteRules(event).nuxtyAuth?.emailVerification as boolean
  const to = event.node.req.url
  if (rules && to && !event.context.user?.email_verified) {
    throw createError({
      statusCode: 401,
      statusMessage: 'Email not verified'
    })
  }
}

export async function handleCsrf(event: H3Event) {
  // only in production since for some reason on ssr fetch origin is null and host is localhost
  if (process.env.NODE_ENV === 'production') {
    if (event.node.req.method !== 'GET') {
      const originHeader = getHeader(event, 'Origin') ?? null
      const hostHeader = getHeader(event, 'Host') ?? null
      console.log('originHeader', originHeader)
      console.log('hostHeader', hostHeader)
      if (!originHeader || !hostHeader || !verifyRequestOrigin(originHeader, [hostHeader])) {
        console.log('Invalid origin')
        return event.node.res.writeHead(403).end('Invalid origin')
      }
    }
  }
}

function generateOTP() {
  return crypto.randomInt(10000000, 100000000).toString()
}

export async function saveAndSendOTP(email: string) {
  const otp = generateOTP()
  await authDB.query(`INSERT INTO ${MFA_TABLE_NAME} (email, otp, expires_at) VALUES($1, $2, NOW() + INTERVAL '$3 minutes')`, [email, otp, EMAIL_OTP_EXPIRY]).catch(async (error) => {
    await auditLogger(
      email,
      'saveAndSendOTP',
      String((error as Error).message),
      'unknown',
      'unknown',
      'error'
    )
  })
  await sendEmail(email, 'Your OTP', `Your OTP is: ${otp}`).catch(async (error) => {
    await auditLogger(
      email,
      'saveAndSendOTP',
      `Email sending failed: ${String((error as Error).message)}`,
      'unknown',
      'unknown',
      'error'
    )
  })
}

export async function verifyOTP(email: string, otp: string) {
  const result = await authDB.query(`SELECT * FROM ${MFA_TABLE_NAME} WHERE email = $1 AND otp = $2 AND expires_at > NOW()`, [email, otp])
  if (result.rows.length === 0) {
    return false
  }
  await authDB.query(`DELETE FROM ${MFA_TABLE_NAME} WHERE email = $1`, [email])
  return true
}

export async function auditLogger(email: string, action: string, message: string, ip: string, userAgent: string, status: string) {
  try {
    await authDB.query(`INSERT INTO audit_logs(email, action, message, ip, user_agent, status) VALUES($1, $2, $3, $4, $5, $6)`, [email, action, message, ip, userAgent, status])
  } catch (error) {
    console.error(error)
  }
}
export function verifyRequestOrigin(origin: string, allowedDomains: string[]): boolean {
  if (!origin || allowedDomains.length === 0) {
    auditLogger('origin: ' + origin, 'verifyRequestOrigin', 'Invalid origin or allowedDomains', 'unknown', 'unknown', 'error')
    return false
  }
  const originHost = safeURL(origin)?.host ?? null
  if (!originHost) {
    auditLogger('origin: ' + origin, 'verifyRequestOrigin', 'Invalid origin host', 'unknown', 'unknown', 'error')
    return false
  }
  for (const domain of allowedDomains) {
    let host: string | null
    if (domain.startsWith('http://') || domain.startsWith('https://')) {
      host = safeURL(domain)?.host ?? null
    } else {
      host = safeURL('https://' + domain)?.host ?? null
    }
    if (originHost === host) return true
  }
  auditLogger('origin: ' + origin, 'verifyRequestOrigin', 'Origin not allowed', 'unknown', 'unknown', 'error')
  return false
}

function safeURL(url: URL | string): URL | null {
  try {
    return new URL(url)
  } catch {
    auditLogger('url: ' + url, 'safeURL', 'Invalid URL', 'unknown', 'unknown', 'error')
    return null
  }
}
