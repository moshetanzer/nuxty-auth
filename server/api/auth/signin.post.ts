export default defineEventHandler(async (event) => {
  const body = await readBody(event)

  if (!body.email || !body.password) {
    auditLogger(event, '', 'signIn', 'Missing email or password', 'error')
    return createError({
      statusCode: 400,
      statusMessage: 'Missing email or password'
    })
  }
  const user = await authenticateUser(event)
  if (!user) {
    auditLogger(event, '', 'signIn', 'Invalid email or password', 'error')
    return createError({
      statusCode: 401,
      statusMessage: 'Invalid email or password'
    })
  }
  await createSession(event, user.id)
  return {
    success: true,
    message: 'Successfully signed in'
  }
})
