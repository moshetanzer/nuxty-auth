export default defineEventHandler(async (event) => {
  const body = await readBody(event)

  if (!body.fname || !body.lname || !body.email || !body.password) {
    return createError({
      statusCode: 400,
      statusMessage: 'Missing firstname, lastname, email or password'
    })
  }
  const user = await createUser(event)
  if (!user) {
    return createError({
      statusCode: 400,
      statusMessage: 'Failed to create user here'
    })
  }

  return {
    success: true,
    message: 'Successfully signed up'
  }
})
