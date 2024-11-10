export default defineEventHandler(async (event) => {
  try {
    const result = await verifyOTP(event)
    if (result) {
      return true
    } else {
      return false
    }
  } catch (err) {
    await auditLogger('', 'verifyOTP', String((err as Error).message), 'unknown', 'unknown', 'error')
    return false
  }
})
