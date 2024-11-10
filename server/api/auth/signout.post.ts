import { deleteSession } from '~~/server/utils/auth'

export default defineEventHandler(async (event) => {
  if (!event.context.session) {
    return {
      message: 'Logged out'
    }
  }

  await deleteSession(event)

  return {
    success: true,
    message: 'Successfully signed out'
  }
})
