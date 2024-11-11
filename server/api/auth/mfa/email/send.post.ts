export default defineEventHandler(async (event) => {
  try {
    const result = await saveAndSendOTP(event)
    if (!result) {
      await auditLogger(event, event.context.user?.email || 'unknown', 'saveAndSendOTP', 'Failed to save and send OTP', 'error')
      throw createError({
        statusCode: 500,
        statusMessage: 'An error occurred processing your request'
      })
    }
    return {
      success: true,
      message: 'OTP sent successfully'
    }
  } catch (err) {
    await auditLogger(event, event.context.user?.email || 'unknown', 'saveAndSendOTP', String((err as Error).message), 'error')
    throw createError({
      statusCode: 500,
      statusMessage: 'An error occurred processing your request'
    })
  }
})
