import type { UserWithSession } from '#shared/types'

export const useAuth = () => {
  const user = useState<UserWithSession | null>('user', () => null)

  async function updateUser() {
    try {
      const data = await useRequestFetch()('/api/auth/session')
      if (data) {
        user.value = data
      }
    } catch (error) {
      console.error(error)
    }
  }
  async function signIn(email: string, password: string) {
    const route = useRoute()

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
      await $fetch('/api/auth/mfa/email/send',
        { method: 'POST' }
      )
    } catch (error) {
      console.error(error)
      throw error
    }
  }
  async function verifyOtp(otp: string): Promise<void> {
    const route = useRoute()
    const status = ref('')
    try {
      const result = await $fetch('/api/auth/mfa/email/verify', {
        method: 'POST',
        body: JSON.stringify({
          otp
        })
      })
      if (result.success) {
        await updateUser()
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
  async function activateMFA(otp: string) {
    try {
      const result = await $fetch('/api/auth/mfa/email/activate', {
        method: 'POST',
        body: JSON.stringify({
          otp
        })
      })
      if (result.success) {
        await updateUser()

        return true
      } else {
        return false
      }
    } catch (error) {
      console.error(error)
      throw error
    }
  }
  async function deactivateMFA(otp: string) {
    try {
      const result = await $fetch('/api/auth/mfa/email/deactivate', {
        method: 'POST',
        body: JSON.stringify({
          otp
        })
      })
      if (result.success) {
        await updateUser()
        return true
      } else {
        return false
      }
    } catch (error) {
      console.error(error)
      throw error
    }
  }
  async function verifyResetPasswordToken(token: string) {
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

  async function requestPasswordReset(email: string) {
    try {
      const response = await $fetch('/api/auth/reset-password', {
        method: 'POST',
        body: {
          email: email
        }
      })
      return response.message
    } catch (error) {
      return (error as Error).message
    }
  }
  return {
    user,
    signOut,
    verifyResetPasswordToken,
    signIn,
    sendOtp,
    verifyOtp,
    activateMFA,
    deactivateMFA,
    requestPasswordReset
  }
}
