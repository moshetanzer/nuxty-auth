export default defineEventHandler(async (event) => {
  try {
    const result = await verifyOTP(event)
    if (!result) {
      return createError({
        statusCode: 400,
        statusMessage: 'Failed to verify OTP'
      })
    }
    try {
      const result = await deactivateMFA(event)
      if (!result) {
        await auditLogger('', 'deactivateMFA', 'Failed to deactivate MFA', 'unknown', 'unknown', 'error')
        return createError({
          statusCode: 400,
          statusMessage: 'Failed to deactivate MFA'
        })
      }
      return {
        success: true,
        message: 'Successfully verified OTP'
      }
    } catch (err) {
      await auditLogger('', 'activateMFA', String((err as Error).message), 'unknown', 'unknown', 'error')
      throw createError({
        statusCode: 500,
        statusMessage: 'An error occurred processing your request'
      })
    }
  } catch (err) {
    await auditLogger('', 'verifyOTP', String((err as Error).message), 'unknown', 'unknown', 'error')
    throw createError({
      statusCode: 500,
      statusMessage: 'An error occurred processing your request'
    })
  }
})
