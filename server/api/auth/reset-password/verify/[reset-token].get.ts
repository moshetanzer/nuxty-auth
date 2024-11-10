export default defineEventHandler(async (event) => {
  try {
    const verified = await verifyResetToken(event)
    if (verified) {
      return { success: true, message: 'Reset token verified' }
    } else {
      return { success: false, message: 'Reset token verification failed' }
    }
  } catch (error) {
    await auditLogger('', 'verifyResetToken', String((error as Error).message), 'unknown', 'unknown', 'error')
    throw createError({
      statusCode: 500,
      statusMessage: 'An error occurred processing your request'
    })
  }
})
