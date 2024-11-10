export default defineNuxtRouteMiddleware(() => {
  const { user } = useAuth()
  console.log('protected-from-logged-in', user.value)
  if (user.value) {
    return navigateTo('/')
  }
})
