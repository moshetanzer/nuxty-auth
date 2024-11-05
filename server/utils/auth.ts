import crypto from 'crypto'
import pg from 'pg'
import argon2 from 'argon2'

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

const AUTH_TABLE_NAME = escapeTableName(config.authTable)
const SESSION_TABLE_NAME = escapeTableName(config.sessionTable)
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

const userId = () => crypto.randomUUID()
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

async function incrementFailedAttempts(email: string) {
  try {
    await authDB.query(`UPDATE ${AUTH_TABLE_NAME} SET failed_attempts = failed_attempts + 1 WHERE email = $1`, [email])
  } catch (error) {
    await auditLogger(email, 'incrementFailedAttempts', String((error as Error).message), 'unknown', 'unknown', 'error')
  }
}
async function deleteSession(sessionId: string): Promise<void> {
  await authDB.query(`DELETE FROM ${SESSION_TABLE_NAME} WHERE id = $1`, [sessionId])
}
export async function auditLogger(email: string, action: string, message: string, ip: string, userAgent: string, status: string) {
  try {
    await authDB.query(`INSERT INTO audit_logs(email, action, message, ip, user_agent, status) VALUES($1, $2, $3, $4, $5, $6)`, [email, action, message, ip, userAgent, status])
  } catch (error) {
    console.error(error)
  }
}
