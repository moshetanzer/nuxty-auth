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
