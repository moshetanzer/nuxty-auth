import { deleteSession } from '~~/server/utils/auth'

export default defineEventHandler(async (event) => {
  if (!event.context.session) {
    await auditLogger(event, '', 'signOut', 'User is not signed in', 'error')
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
