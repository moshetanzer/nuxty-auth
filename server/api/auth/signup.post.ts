export default defineEventHandler(async (event) => {
  const body = await readBody(event)

  if (!body.fname || !body.lname || !body.email || !body.password) {
    await auditLogger(event, '', 'signUp', 'Missing firstname, lastname, email or password', 'error')
    return createError({
      statusCode: 400,
      statusMessage: 'Missing firstname, lastname, email or password'
    })
  }
  const user = await createUser(event)
  if (!user) {
    await auditLogger(event, '', 'signUp', 'Failed to create user', 'error')
    return createError({
      statusCode: 400,
      statusMessage: 'Failed to create user'
    })
  }
  return {
    success: true,
    message: 'Successfully signed up'
  }
})
