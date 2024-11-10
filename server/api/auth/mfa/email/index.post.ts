export default defineEventHandler(async (event) => {
  try {
    const result = await verifyOTP(event)
    if (result) {
      return {
        success: true,
        message: 'Successfully verified OTP'
      }
    } else {
      throw createError({
        statusCode: 400,
        statusMessage: 'Failed to verify OTP'
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
