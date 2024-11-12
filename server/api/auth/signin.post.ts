import { H3Error } from 'h3'

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
