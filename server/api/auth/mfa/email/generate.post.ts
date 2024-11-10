export default defineEventHandler(async (event) => {
  try {
    const result = await saveAndSendOTP(event)
    return {
      success: true,
      message: 'Successfully sent OTP'
    }
  } catch (err) {
    await auditLogger('', 'saveAndSendOTP', String((err as Error).message), 'unknown', 'unknown', 'error')
    throw createError({
      statusCode: 500,
      statusMessage: 'An error occurred processing your request'
    })
  }
})
