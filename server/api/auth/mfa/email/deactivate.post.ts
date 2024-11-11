export default defineEventHandler(async (event) => {
  try {
    const result = await verifyOTP(event)
    if (!result) {
      return {
        success: false,
        message: 'Failed to verify OTP and deactivate MFA'
      }
    }
    const result2 = await deactivateMFA(event)
    if (result2) {
      return {
        success: true,
        message: 'Successfully verified OTP and deactivated MFA'
      }
    }
  } catch (err) {
    await auditLogger(event, event.context.user?.email || 'unknown', 'verifyOTP', String((err as Error).message), 'error')
    throw createError({
      statusCode: 500,
      statusMessage: 'An error occurred processing your request'
    })
  }
})
