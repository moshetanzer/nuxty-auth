import crypto from 'crypto'
import pg from 'pg'
import argon2 from 'argon2'
import type { H3Event } from 'h3'
export interface User {
  id: string
  email: string
  fname: string
  lname: string
  failed_attempts: number
  email_verified: boolean
  reset_token: string
  reset_token_expires_at: Date
  email_mfa: boolean
  role: string[]
}
export interface Session {
  id: string
  user_id: string
  expires_at: Date
  two_factor_verified: boolean
}

const { Pool } = pg
const config = useRuntimeConfig()

const connectionString = config.authConnectionString
const authDB = new Pool({
  connectionString
})

const AUTH_TABLE_NAME = escapeTableName(config.authUserTableName)
const SESSION_TABLE_NAME = escapeTableName(config.authSessionTableName)
const MAX_FAILED_ATTEMPTS = config.maxFailedAttempts || 10 as number

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
  const { fname, lname, email, password, role } = await readBody(event)
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

async function createSession(event: H3Event, userId: string): Promise<Session | null> {
  const sessionId = crypto.randomUUID()
  const {email} = await readBody(event)
  try {
    const result = await authDB.query(`INSERT INTO ${SESSION_TABLE_NAME} (id, user_id, expires_at, two_factor_verified) VALUES ($1, (SELECT id FROM ${AUTH_TABLE_NAME} WHERE email = $2), NOW() + INTERVAL '1 day', false)`, [sessionId, email])
    return result.rows[0]
  } catch (error) {
    await auditLogger(email, 'createSession', String((error as Error).message), 'unknown', 'unknown', 'error')
    return null
  }
}
async function deleteSession(sessionId: string): Promise<void> {
  try {
    await authDB.query(`DELETE FROM ${SESSION_TABLE_NAME} WHERE id = $1`, [sessionId])
  } catch (error) {
    await auditLogger('unknown', 'deleteSession', String((error as Error).message), 'unknown', 'unknown', 'error')
  }
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
