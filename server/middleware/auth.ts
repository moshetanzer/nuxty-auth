import type { User, Session } from '#shared/types'
import { handleRateLimit, roleBasedAuth, emailVerification, handleSession, handleCsrf } from '~~/server/utils/auth'

export default defineEventHandler(async (event) => {
  // CSRF Protection
  await handleCsrf(event)

  // Rate Limit
  await handleRateLimit(event)

  // Session Management
  await handleSession(event)

  // const requiresAuth = getRouteRules(event).nuxtyAuth?.roles || getRouteRules(event).nuxtyAuth?.emailVerification
  // if (requiresAuth) {
  //   throw createError({
  //     statusCode: 401,
  //     statusMessage: 'Authentication required'
  //   })
  // }
  // Role-Based Authorization
  await roleBasedAuth(event)

  // Email Verification
  await emailVerification(event)
})

declare module 'h3' {
  interface H3EventContext {
    user: Partial<User> | null
    session: Session | null
  }
}
