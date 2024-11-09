export default defineEventHandler(async (event) => {
  try {
    await saveAndSendOTP(event)
    return true
  } catch (err) {
    await auditLogger('', 'saveAndSendOTP', String((err as Error).message), 'unknown', 'unknown', 'error')
    return false
  }
})
