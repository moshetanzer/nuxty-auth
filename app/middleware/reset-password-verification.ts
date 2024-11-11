export default defineNuxtRouteMiddleware(async (to) => {
  const { verifyResetPasswordToken } = useAuth()
  const verify = await verifyResetPasswordToken(to.params.resetToken as string)
  if (!verify) {
    return abortNavigation()
  }
})
