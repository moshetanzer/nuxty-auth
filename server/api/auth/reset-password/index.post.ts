import { resetPasswordRequest } from '~~/server/utils/auth'

export default defineEventHandler(async (event) => {
  try {
    await resetPasswordRequest(event)
    return { success: true, message: 'If the email exists in our system, we will send a password reset link to the email address' }
  } catch (error) {
    await auditLogger(event, 'unknown', 'resetPasswordRequest', String((error as Error).message), 'error')
    throw createError({
      statusCode: 500,
      statusMessage: 'An error occurred processing your request'
    })
  }
})
