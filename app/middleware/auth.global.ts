export default defineNuxtRouteMiddleware(async () => {
  const user = useUser()
  const data = user.value ||= await useRequestFetch()('/api/auth/session')
  if (data) {
    user.value = data
  }
})
