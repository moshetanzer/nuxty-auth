export default defineEventHandler(async (event) => {
  try {
    await verifyOTP(event)
    return true
  } catch (err) {
    await auditLogger('', 'verifyOTP', String((err as Error).message), 'unknown', 'unknown', 'error')
    return false
  }
})
