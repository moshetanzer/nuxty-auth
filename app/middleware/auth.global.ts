export default defineNuxtRouteMiddleware(async (to) => {
  const { user } = useAuth()
  const data = user.value ||= await useRequestFetch()('/api/auth/session')
  if (data) {
    user.value = data
  }
  if (to.path === '/multi-factor') {
    if (user.value?.mfa)
      if (user.value?.mfa_verified) {
        return abortNavigation()
      }
  }
})
