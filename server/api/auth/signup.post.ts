import { H3Error } from 'h3'

export default defineEventHandler(async (event) => {
  const body = await readBody(event)
  try {
    if (!body.fname || !body.lname || !body.email || !body.password) {
      await auditLogger(event, '', 'signUp', 'Missing firstname, lastname, email or password', 'error')
      return createError({
        statusCode: 400,
        statusMessage: 'Missing firstname, lastname, email or password'
      })
    }
    if (body.password !== body.confirmPassword) {
      await auditLogger(event, '', 'signUp', 'Password and confirm password do not match', 'error')
      return createError({
        statusCode: 400,
        statusMessage: 'Password and confirm password do not match'
      })
    }
    await createUser(event)
    return {
      success: true,
      message: 'Successfully signed up'
    }
  } catch (error) {
    await auditLogger(event, '', 'signUp', String((error as Error).message), 'error')
    if (error instanceof H3Error) {
      throw error
    }
    throw createError({
      statusCode: 500,
      statusMessage: 'Internal server error'
    })
  }
})
