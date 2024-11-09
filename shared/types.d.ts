export interface User {
  id: string
  email: string
  fname: string
  lname: string
  failed_attempts: number
  email_verified: boolean
  reset_token: string
  reset_token_expires_at: Date
  mfa: boolean
  role: string
}
export interface Session {
  id: string
  user_id: string
  expires_at: Date
  mfa_verified: boolean
}

export interface UserWithSession extends User {
  mfa_verified: boolean
}
