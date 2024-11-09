export default defineEventHandler(async (event) => {
  try {
    const result = await verifyOTP(event)
    if (!result) {
      return false
    }
    await activateMFA(event).catch(async (err) => {
      await auditLogger('', 'activateMFA', String((err as Error).message), 'unknown', 'unknown', 'error')
    })
    return true
  } catch (err) {
    await auditLogger('', 'verifyOTP', String((err as Error).message), 'unknown', 'unknown', 'error')
    return false
  }
})
