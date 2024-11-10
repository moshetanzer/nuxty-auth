export default defineEventHandler(async (event) => {
  if (event.context.user) {
    return {
      ...event.context.user,
      mfa_verified: event.context.session?.mfa_verified
    }
  }
})
