export default defineNuxtRouteMiddleware((to, from) => {
  const user = useUser()
  if (!user.value) {
    return navigateTo({
      path: '/signin',
      query: to.fullPath !== '/' ? { redirect: to.fullPath } : {}
    })
  }
  if (to.meta.auth) {
    const requiredRoles = (to.meta.auth as { roles: string[] }).roles || []
    if (!user.value?.role || !requiredRoles.includes(user.value.role)) {
      // home page should be available to all users to avoid infinite redirect loops
      if (from.path === to.path) return navigateTo('/')
      //   return navigateTo(from.path)
      return abortNavigation()
    }
  }
  if (to.meta.emailVerification && !user.value.email_verified) {
    return navigateTo('/verify-email')
  }
})
