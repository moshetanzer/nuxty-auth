import crypto from 'crypto'
import pg from 'pg'
import argon2 from 'argon2'
import type { H3Event, NodeIncomingMessage } from 'h3'
import type { User, Session } from '#shared/types'

const { Pool } = pg
const config = useRuntimeConfig()
const storage = useStorage()
const connectionString = config.authConnectionString
const authDB = new Pool({
  connectionString
})

const AUTH_TABLE_NAME = escapeTableName(config.authUserTableName)
const SESSION_TABLE_NAME = escapeTableName(config.authSessionTableName)
const MFA_TABLE_NAME = escapeTableName(config.authMfaTableName)
const EMAIL_OTP_EXPIRY = 15 // mins

const MAX_FAILED_ATTEMPTS = config.maxFailedAttempts || 10 as number

const RATE_LIMIT = 100
const RATE_LIMIT_WINDOW = 60 // seconds

const SESSION_TOTAL_DURATION = config.sessionTotalDuration || 43200 as number // mins (30 days)
const SESSION_REFRESH_INTERVAL = config.sessionRefreshInterval || 720 as number // mins (12 hours)
const SESSION_EXTENSION_DURATION = config.sessionExtensionDuration || 10080 as number // mins (7 days)

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
if (!MFA_TABLE_NAME) {
  console.error('No MFA table name provided')
  process.exit(1)
}

function escapeTableName(val: string): string {
  if (val.includes('.')) return val
  return `"${val}"`
}
async function hashPassword(event: H3Event, password: string): Promise<string | false> {
  try {
    return await argon2.hash(password, ARGON2_CONFIG)
  } catch (error) {
    await auditLogger(event, 'unknown', 'hashPassword', String((error as Error).message), 'error')
    return false
  }
}
async function verifyPassword(event: H3Event, email: string, password: string, hash: string): Promise<boolean> {
  try {
    if (await argon2.verify(hash, password)) {
      return true
    } else {
      await auditLogger(event, email, 'verifyPassword', 'Password match hash failed', 'error')
      return false
    }
  } catch (error) {
    await auditLogger(event, email, 'verifyPassword', String((error as Error).message), 'error')
    return false
  }
}

async function checkIfLocked(event: H3Event, email: string): Promise<boolean> {
  try {
    if (!email) {
      throw createError({
        statusMessage: 'Email is required',
        statusCode: 400
      })
    }

    const result = await authDB.query<User>(`SELECT email, failed_attempts FROM ${AUTH_TABLE_NAME} WHERE email = $1`, [email])

    if (!result?.rows?.[0]) {
      await auditLogger(event, email, 'checkIfLocked', 'Account not found', 'error')
      return false
    }
    const isLocked = result.rows[0].failed_attempts >= Number(MAX_FAILED_ATTEMPTS)

    if (isLocked) {
      await auditLogger(event, email, 'checkIfLocked', 'Account locked', 'error')
      return true
    } else {
      return false
    }
  } catch (error) {
    await auditLogger(event, email, 'checkIfLocked', String((error as Error).message), 'error')
    return false
  }
}
async function incrementFailedAttempts(event: H3Event, email: string): Promise<void> {
  try {
    await authDB.query(`UPDATE ${AUTH_TABLE_NAME} SET failed_attempts = failed_attempts + 1 WHERE email = $1`, [email])
    await auditLogger(event, email, 'incrementFailedAttempts', 'Failed attempts incremented', 'info')
  } catch (error) {
    await auditLogger(event, email, 'incrementFailedAttempts', String((error as Error).message), 'error')
  }
}
async function resetFailedAttempts(event: H3Event, email: string): Promise<void> {
  try {
    await authDB.query(`UPDATE ${AUTH_TABLE_NAME} SET failed_attempts = 0 WHERE email = $1`, [email])
    await auditLogger(event, email, 'resetFailedAttempts', 'Failed attempts reset', 'info')
  } catch (error) {
    await auditLogger(event, email, 'resetFailedAttempts', String((error as Error).message), 'error')
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
export async function authenticateUser(event: H3Event): Promise<User> {
  const { email, password } = await readBody(event)
  console.log(email)
  try {
    const result = await authDB.query(`SELECT * FROM ${AUTH_TABLE_NAME} WHERE email = $1`, [email])

    if (result.rows.length === 0) {
      await verifyPassword(event, email, password, '$argon2id$v=19$m=16,t=2,p=1$d050OUJMT1RzckoxbGdxYQ$+CQAgx/TccW9Ul/85vo7tg')
      await auditLogger(event, email, 'authenticateUser', 'Account not found', 'error')
      throw createError({
        statusCode: 401,
        statusMessage: 'Invalid email or password'
      })
    }

    const user = result.rows[0]

    const locked = await checkIfLocked(event, user.email)
    if (locked) {
      await auditLogger(event, email, 'authenticateUser', 'Account locked', 'error')
      throw createError({
        statusCode: 401,
        statusMessage: 'Account locked'
      })
    }

    const isValid = await verifyPassword(event, user.email, password, user.password)
    if (!isValid) {
      await incrementFailedAttempts(event, user.email)
      await auditLogger(event, email, 'authenticateUser', 'Invalid email or password', 'error')
      throw createError({
        statusCode: 401,
        statusMessage: 'Invalid email or password'
      })
    }
    await auditLogger(event, email, 'authenticateUser', 'User authenticated', 'success')
    await resetFailedAttempts(event, user.email)
    return user
  } catch (error) {
    await auditLogger(event, email, 'authenticateUser', String((error as Error).message), 'error')
    throw error
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
export async function createUser(event: H3Event): Promise<void> {
  const { fname, lname, email, password } = await readBody(event)
  try {
    const existingUser = await authDB.query<User>(`SELECT * FROM ${AUTH_TABLE_NAME} WHERE email = $1`, [email])
    if (existingUser.rows.length > 0) {
      await auditLogger(event, email, 'createUser', 'User already exists', 'error')
      throw createError({
        statusCode: 400,
        statusMessage: 'User already exists'
      })
    }
    const role = useRuntimeConfig(event).defaultUserRole || 'user'
    const userId = crypto.randomUUID()
    const hashedPassword = await hashPassword(event, password)

    const result = await authDB.query(`
      INSERT INTO ${AUTH_TABLE_NAME} (id, fname, lname, email, password, role, failed_attempts)
      VALUES ($1, $2, $3, $4, $5, $6, 0) RETURNING id
    `, [userId, fname, lname, email, hashedPassword, role])

    if (result.rows.length === 0) {
      await auditLogger(event, email, 'createUser', 'User not created', 'error')
      throw createError({
        statusCode: 500,
        statusMessage: 'Failed to create user'
      })
    }
    await auditLogger(event, email, 'createUser', 'User created', 'success')
  } catch (error) {
    await auditLogger(event, email, 'createUser', String((error as Error).message), 'error')
    throw error
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
    await auditLogger(event, email, 'createSession', 'Session created', 'success')
    setCookie(event, 'mediCloudID', sessionId, {
      path: '/',
      maxAge: Number(SESSION_TOTAL_DURATION) * 60,
      httpOnly: true,
      sameSite: 'lax',
      secure: true
    })
  } catch (error) {
    await auditLogger(event, email, 'createSession', String((error as Error).message), 'error')
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
      (s.created_at + INTERVAL '${Number(SESSION_TOTAL_DURATION) * 60} seconds') AS absolute_expiration
    FROM sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.id = $1 
      AND s.expires_at > NOW() 
      AND (s.created_at + INTERVAL '${Number(SESSION_TOTAL_DURATION) * 60} seconds') > NOW()
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
        await refreshSession(event, sessionId)
      } catch (refreshError) {
        await auditLogger(
          event,
          sessionRow.email,
          'sessionRefresh',
          `Automatic session refresh failed: ${String(refreshError)}`,
          'error'
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
    await auditLogger(event, 'unknown', 'handleSession', String((error as Error).message), 'error')
    return false
  }
}

export async function refreshSession(event: H3Event, sessionId: string): Promise<void> {
  try {
    await authDB.query(`
      UPDATE ${SESSION_TABLE_NAME}
      SET expires_at = NOW() + (INTERVAL '1 minute' * $1)
      WHERE id = $2
    `, [SESSION_TOTAL_DURATION, sessionId])
  } catch (error) {
    await auditLogger(event, 'unknown', 'refreshSession', String((error as Error).message), 'error')
    console.error('Failed to refresh session:', error)
  }
}
export async function handleRateLimit(event: H3Event): Promise<void> {
  const ip = getClientIP(event)
  const key = `rate-limit:${ip}`

  const [current, ttl] = await storage.getItem<[number, number]>(key) || [0, 0]

  if (current >= RATE_LIMIT) {
    setRateLimitHeaders(event, current, ttl)
    await auditLogger(event, event.context.user?.email || 'unknown', 'handleRateLimit', 'Too many requests', 'error')
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
      || event.node.req.socket.remoteAddress as string
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
    await auditLogger(event, 'unknown', 'deleteSession', String((error as Error).message), 'error')
  }
}
export async function getUserIdFromEmail(event: H3Event, email: string): Promise<string | null> {
  try {
    const result = await authDB.query<User>(`SELECT id FROM ${AUTH_TABLE_NAME} WHERE email = $1`, [email])
    if (result.rows.length === 0) {
      await auditLogger(event, email, 'getUserIdFromEmail', 'User not found', 'error')
      return null
    }
    return result.rows[0].id
  } catch (error) {
    await auditLogger(event, email, 'getUserIdFromEmail', String((error as Error).message), 'error')
    return null
  }
}
export async function deleteAllSessions(event: H3Event, userId: string): Promise<void> {
  try {
    await authDB.query(`DELETE FROM ${SESSION_TABLE_NAME} WHERE user_id = $1`, [userId])
  } catch (error) {
    await auditLogger(event, 'unknown', 'deleteAllSessions', String((error as Error).message), 'error')
  }
}
export async function cleanupExpiredSessions(event: H3Event): Promise<void> {
  try {
    await authDB.query(`
          DELETE FROM ${SESSION_TABLE_NAME}
          WHERE expires_at <= NOW()
          OR created_at + (INTERVAL '1 minute' * $1) <= NOW()`,
    [Number(SESSION_TOTAL_DURATION) + Number(SESSION_EXTENSION_DURATION)]
    )
  } catch (error) {
    await auditLogger(event, 'system', 'cleanupExpiredSessions', String((error as Error).message), 'error')
  }
}

export async function resetPasswordRequest(event: H3Event) {
  try {
    const { email } = await readBody(event)

    if (!email) {
      await auditLogger(event, '', 'resetPasswordRequest', 'Email is required', 'error')
      throw createError({
        statusCode: 400,
        statusMessage: 'Email is required'
      })
    }
    const user = await authDB.query<User>(`SELECT id, email, reset_token, reset_token_expires_at FROM users WHERE email = $1`, [email]).catch(async (error) => {
      await auditLogger(
        event,
        email,
        'resetPasswordRequest',
        `Database error: ${String((error as Error).message)}`,
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
      await auditLogger(event, email, 'resetPasswordRequest', 'Email not found', 'error')
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
        event,
        email,
        'resetPasswordRequest',
        `Token update failed: ${String((error as Error).message)}`,
        'error'
      )
      throw createError({
        statusCode: 500,
        statusMessage: 'An error occurred processing your request'
      })
    })

    await sendEmail(email, 'Password Reset Request', `Click <a href="${useRuntimeConfig().baseUrl}/reset-password/${resetToken}">here</a> to reset your password.`).catch(async (error) => {
      await auditLogger(
        event,
        email,
        'resetPasswordRequest',
        `Email sending failed: ${String((error as Error).message)}`,
        'error'
      )
      throw createError({
        statusCode: 500,
        statusMessage: 'An error occurred processing your request'
      })
    })
    await auditLogger(event, email, 'resetPasswordRequest', 'Password reset email sent', 'success')
    return true
  } catch (error) {
    await auditLogger(event, 'unknown', 'resetPasswordRequest', String((error as Error).message), 'error')
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
      await auditLogger(event, 'unknown', 'verifyResetToken', 'Reset token is required', 'error')
      throw createError({
        statusCode: 400,
        statusMessage: 'Reset token is required'
      })
    }
    let hashedToken: string
    try {
      hashedToken = crypto.createHash('sha256').update(token).digest('hex')
    } catch (error) {
      await auditLogger(event, 'unknown', 'verifyResetToken', String((error as Error).message), 'error')
      throw createError({
        statusCode: 500,
        statusMessage: 'Failed to process reset token'
      })
    }
    const result = await authDB.query<User>(`SELECT * FROM users WHERE reset_token = $1 AND reset_token_expires_at > NOW()`, [hashedToken]).catch(async (error) => {
      await auditLogger(event, 'unknown', 'verifyResetToken', String((error as Error).message), 'error')
      throw createError({
        statusCode: 500,
        statusMessage: 'Error verifying reset token'
      })
    })
    if (result.rows.length === 0) {
      await auditLogger(event, 'unknown', 'verifyResetToken', 'Invalid token', 'error')
      return false
    } else if (result.rows.length === 1) {
      await auditLogger(event, result.rows[0].email, 'verifyResetToken', 'Token verified', 'success')
      return true
    }
  } catch (error) {
    await auditLogger(event, 'unknown', 'verifyResetToken', String((error as Error).message), 'error')
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
      await auditLogger(event, 'unknown', 'resetPassword', 'Missing required fields', 'error')
      throw createError({
        statusCode: 400,
        statusMessage: `Missing required fields (${!resetToken ? 'resetToken' : ''} ${!password ? 'password' : ''} ${!confirmPassword ? 'confirmPassword' : ''})`
      })
    }

    if (password !== confirmPassword) {
      await auditLogger(event, 'unknown', 'resetPassword', 'Passwords do not match', 'error')
      throw createError({
        statusCode: 400,
        statusMessage: 'Passwords do not match'
      })
    }
    let hashedToken: string
    try {
      hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex')
    } catch (error) {
      await auditLogger(event, 'unknown', 'resetPassword', String((error as Error).message), 'error')
      throw createError({
        statusCode: 500,
        statusMessage: 'Failed to process reset token'
      })
    }
    const result = await authDB.query<User>(`SELECT * FROM users WHERE reset_token = $1 AND reset_token_expires_at > NOW()`, [hashedToken]).catch(async (error) => {
      await auditLogger(event, 'unknown', 'resetPassword', String((error as Error).message), 'error')
      throw createError({
        statusCode: 500,
        statusMessage: 'Database error while checking reset token'
      })
    })
    const user = result.rows[0]
    if (!user) {
      await auditLogger(event, 'unknown', 'resetPassword', 'Invalid token', 'error')
      throw createError({
        statusCode: 400,
        statusMessage: 'Invalid token'
      })
    }

    const hashedPassword = await hashPassword(event, password)

    await authDB.query(`UPDATE users SET password = $1, reset_token = NULL, reset_token_expires_at = NULL WHERE id = $2`, [hashedPassword, user.id]).catch(async (error) => {
      await auditLogger(
        event,
        user.email,
        'resetPassword',
        String((error as Error).message),
        'error'
      )
      throw createError({
        statusCode: 500,
        statusMessage: 'Failed to update password'
      })
    })

    await auditLogger(
      event,
      user.email,
      'resetPassword',
      'Password reset successful',
      'success'
    ).catch(() => {
      console.error('Failed to log password reset success')
    })
    await deleteAllSessions(event, user.id)
    return true
  } catch (error) {
    await auditLogger(event, 'unknown', 'resetPassword', String((error as Error).message), 'error')
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
    await auditLogger(event, 'unknown', 'roleBasedAuth', 'Unauthorized', 'error')
    console.log('Unauthorized: No role')
    return event.node.res.writeHead(403).end('Unauthorized: No role')
  }

  const userRole = event.context.user?.role as string
  if (!hasRequiredRole(userRole, rules)) {
    auditLogger(event, event.context.user?.email ?? 'unknown', 'roleBasedAuth', 'Unauthorized', 'error')
    console.log('Unauthorized: Insufficient role')
    return event.node.res.writeHead(403).end('Unauthorized: Insufficient role')
  }

  if (to && !checkAccess(userRole, to, rules)) {
    auditLogger(event, event.context.user?.email ?? 'unknown', 'roleBasedAuth', 'Unauthorized', 'error')
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
      if (!originHeader || !hostHeader || !verifyRequestOrigin(event, originHeader, [hostHeader])) {
        console.log('Invalid origin')
        return event.node.res.writeHead(403).end('Invalid origin')
      }
    }
  }
}

function generateOTP(): string {
  const buffer = crypto.randomBytes(4)
  const num = buffer.readUInt32BE(0) % 1000000
  return num.toString().padStart(6, '0')
}

export async function saveAndSendOTP(event: H3Event): Promise<boolean> {
  const email = event.context.user?.email
  const userId = event.context.user?.id
  if (!email || !userId) {
    await auditLogger(event, '', 'saveAndSendOTP', 'Email or user ID not found', 'error')
    throw createError({
      statusCode: 400,
      statusMessage: 'Email or user ID not found'
    })
  }
  const otp = generateOTP()
  await authDB.query(
    `INSERT INTO ${MFA_TABLE_NAME} (user_id, secret) VALUES ($1, $2)`,
    [userId, otp]
  ).catch(async (error) => {
    await auditLogger(
      event,
      email,
      'saveAndSendOTP',
      String((error as Error).message),
      'error'
    )
  })
  await sendEmail(email, 'Your OTP', `Your OTP is: ${otp}`).catch(async (error) => {
    await auditLogger(
      event,
      email,
      'saveAndSendOTP',
      `Email sending failed: ${String((error as Error).message)}`,
      'error'
    )
  })

  await auditLogger(event, email, 'saveAndSendOTP', 'OTP saved and sent', 'success')

  return true
}
export async function verifyOTP(event: H3Event) {
  const { otp } = await readBody(event)
  const userId = event.context.user?.id
  const email = event.context.user?.email

  if (!userId || !email) {
    await auditLogger(event, '', 'verifyOTP', 'User ID or email not found', 'error')
    throw createError({
      statusCode: 400,
      statusMessage: 'User ID or email not found'
    })
  }
  try {
    // Check if valid OTP exists
    const result = await authDB.query(
      `SELECT * FROM ${MFA_TABLE_NAME} 
       WHERE user_id = $1 
       AND secret = $2 
       AND created_at > NOW() - (INTERVAL '1 minute' * $3)`,
      [userId, otp, EMAIL_OTP_EXPIRY]
    )

    // If no valid OTP found, return false
    if (!result.rows || result.rows.length === 0) {
      await auditLogger(
        event,
        email,
        'verifyOTP',
        'Invalid or expired OTP',
        'error'
      )
      return false
    }

    // Update session to mark MFA as verified
    await authDB.query(
      `UPDATE ${SESSION_TABLE_NAME} SET mfa_verified = true WHERE user_id = $1`,
      [userId]
    )

    // Clean up used OTP
    await authDB.query(
      `DELETE FROM ${MFA_TABLE_NAME} WHERE user_id = $1`,
      [userId]
    )

    await auditLogger(
      event,
      email,
      'verifyOTP',
      'OTP verified successfully',
      'info'
    )

    return true
  } catch (error) {
    await auditLogger(
      event,
      email,
      'verifyOTP',
      String((error as Error).message),
      'error'
    )
    return false
  }
}
export async function activateMFA(event: H3Event): Promise<boolean> {
  const email = event.context.user?.email
  const userId = event.context.user?.id
  if (!userId) {
    await auditLogger(event, '', 'activateMFA', 'User ID not found', 'error')
    throw createError({
      statusCode: 400,
      statusMessage: 'User ID not found'
    })
  }
  if (!email) {
    await auditLogger(event, '', 'activateMFA', 'Email not found', 'error')
    throw createError({
      statusCode: 400,
      statusMessage: 'Email not found'
    })
  }

  await authDB.query(`UPDATE ${AUTH_TABLE_NAME} SET mfa = true WHERE id = $1`, [userId]).catch(async (error) => {
    await auditLogger(
      event,
      email,
      'activateMFA',
      String((error as Error).message),
      'error'
    )
    return false
  })
  return true
}

export async function deactivateMFA(event: H3Event): Promise<boolean> {
  const email = event.context.user?.email
  const userId = event.context.user?.id
  if (!userId) {
    await auditLogger(event, '', 'deactivateMFA', 'User ID not found', 'error')
    throw createError({
      statusCode: 400,
      statusMessage: 'User ID not found'
    })
  }
  if (!email) {
    await auditLogger(event, '', 'deactivateMFA', 'Email not found', 'error')
    throw createError({
      statusCode: 400,
      statusMessage: 'Email not found'
    })
  }

  await authDB.query(`UPDATE ${AUTH_TABLE_NAME} SET mfa = false WHERE id = $1`, [userId]).catch(async (error) => {
    await auditLogger(
      event,
      email,
      'deactivateMFA',
      String((error as Error).message),
      'error'
    )
    return false
  })
  return true
}
export async function auditLogger(event: H3Event | null, email: string, action: string, message: string, status: string) {
  let ip: string
  let userAgent: string
  if (event) {
    const req = event?.node.req
    ip = getClientInfo(req).ip
    userAgent = getClientInfo(req).userAgent
  } else {
    ip = 'unknown'
    userAgent = 'unknown'
  }
  try {
    await authDB.query(`INSERT INTO audit_logs(email, action, message, ip, user_agent, status) VALUES($1, $2, $3, $4, $5, $6)`, [email, action, message, ip, userAgent, status])
  } catch (error) {
    console.error(error)
  }
}
export function verifyRequestOrigin(event: H3Event, origin: string, allowedDomains: string[]): boolean {
  if (!origin || allowedDomains.length === 0) {
    auditLogger(event, 'origin: ' + origin, 'verifyRequestOrigin', 'Invalid origin or allowedDomains', 'error')
    return false
  }
  const originHost = safeURL(event, origin)?.host ?? null
  if (!originHost) {
    auditLogger(event, 'origin: ' + origin, 'verifyRequestOrigin', 'Invalid origin host', 'error')
    return false
  }
  for (const domain of allowedDomains) {
    let host: string | null
    if (domain.startsWith('http://') || domain.startsWith('https://')) {
      host = safeURL(event, domain)?.host ?? null
    } else {
      host = safeURL(event, 'https://' + domain)?.host ?? null
    }
    if (originHost === host) return true
  }
  auditLogger(event, 'origin: ' + origin, 'verifyRequestOrigin', 'Origin not allowed', 'error')
  return false
}

function safeURL(event: H3Event, url: URL | string): URL | null {
  try {
    return new URL(url)
  } catch {
    auditLogger(event, 'url: ' + url, 'safeURL', 'Invalid URL', 'error')
    return null
  }
}

export const getClientInfo = (req: NodeIncomingMessage) => {
  const ipHeader = req.headers['x-forwarded-for'] || req.headers['x-real-ip']
  const ip = Array.isArray(ipHeader) ? ipHeader[0] : ipHeader || req.socket.remoteAddress || 'Unknown'
  const userAgent = req.headers['user-agent'] || 'Unknown'
  return { ip, userAgent }
}
