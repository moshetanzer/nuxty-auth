export default defineNuxtRouteMiddleware(async (to) => {
  const user = useUser()
  const data = user.value ||= await useRequestFetch()('/api/auth/session')
  if (data) {
    user.value = data
  }
  if (to.path === '/multi-factor') {
    if (user.value?.mfa_verified || !user.value?.mfa) {
      return abortNavigation()
    }
  }
})
