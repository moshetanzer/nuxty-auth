import type { UserWithSession } from '#shared/types'

export const useAuth = () => {
  const user = useState<UserWithSession | null>('user', () => null)

  async function signIn(email: string, password: string) {
    const status = ref('')
    const route = useRoute()
    try {
      await $fetch('/api/auth/signin', {
        method: 'POST',
        body: {
          email: email,
          password: password
        }
      })
      if (route.query.redirect) {
        // this is safe since nuxt will throw error if redirect is out of app
        navigateTo(route.query.redirect as string)
      } else {
        navigateTo('/')
      }
    } catch (error: unknown) {
      if (error instanceof Error) {
        status.value = error.message
      } else {
        status.value = 'Unknown error'
      }
      throw error
    }
  }
  const signOut = async () => {
    try {
      await $fetch('/api/auth/signout', { method: 'POST' })
      user.value = null
      return await navigateTo('/signin')
    } catch (err) {
      console.error(err)
    }
  }

  const verifyToken = async (resetToken: string) => {
    try {
      const response = await $fetch(`/api/auth/reset-password/verify/${resetToken}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json'
        } })
      if (response.success) {
        return true
      } else {
        return false
      }
    } catch (err) {
      console.error(err)
      return false
    }
  }

  return {
    user,
    signOut,
    verifyToken,
    signIn
  }
}
