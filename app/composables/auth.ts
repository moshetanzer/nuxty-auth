import type { UserWithSession } from '#shared/types'

export const useAuth = () => {
  const user = useState<UserWithSession | null>('user', () => null)
  const route = useRoute()

  async function signIn(email: string, password: string) {
    const status = ref('')
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
  async function sendOtp() {
    try {
      await $fetch('/api/auth/mfa/email/generate',
        { method: 'POST' }
      )
    } catch (error) {
      console.error(error)
      throw error
    }
  }
  async function verifyOtp(otp: string): Promise<void> {
    const status = ref('')
    try {
      const result = await $fetch('/api/auth/mfa/email', {
        method: 'POST',
        body: JSON.stringify({
          otp
        })
      })
      if (result.success) {
        if (route.query.redirect) {
          status.value = 'MFA verification successful'
          await navigateTo(route.query.redirect as string)
        } else {
          await navigateTo('/')
        }
      } else {
        status.value = 'MFA verification failed'
        console.log('error: MFA verification failed')
      }
    } catch (error) {
      console.error('Navigation error:', error)
      throw error
    }
  }
  async function verifyToken(token: string) {
    try {
      const response = await $fetch(`/api/auth/reset-password/verify/${token}`, {
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
    signIn,
    sendOtp,
    verifyOtp
  }
}
