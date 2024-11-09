export default defineEventHandler(async (event) => {
  return {
    ...event.context.user,
    mfa_verified: event.context.session?.mfa_verified || false
  }
})
