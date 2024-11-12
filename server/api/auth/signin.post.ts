import { H3Error } from 'h3'
import { validateEmail, validatePassword } from '#shared/validation'

export default defineEventHandler(async (event) => {
  try {
    const body = await readBody(event)
    if (!body.email || !body.password) {
      await auditLogger(event, '', 'signIn', 'Missing email or password', 'error')
      throw createError({
        statusCode: 400,
        statusMessage: 'Missing email or password'
      })
    }
    if (!validateEmail(body.email)) {
      await auditLogger(event, '', 'signUp', 'Invalid email', 'error')
      return createError({
        statusCode: 400,
        statusMessage: 'Invalid email'
      })
    }
    if (validatePassword(body.password) === false) {
      await auditLogger(event, '', 'signUp', 'Password does not meet requirements', 'error')
      return createError({
        statusCode: 400,
        statusMessage: 'Password does not meet requirements'
      })
    }
    const user = await authenticateUser(event)
    await createSession(event, user.id)
    return {
      success: true,
      message: 'Successfully signed in'
    }
  } catch (error) {
    await auditLogger(event, '', 'signIn', String((error as Error).message), 'error')
    if (error instanceof H3Error) {
      throw error
    }
    throw createError({
      statusCode: 500,
      statusMessage: 'Internal server error'
    })
  }
})
