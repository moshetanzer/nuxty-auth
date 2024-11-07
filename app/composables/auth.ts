import type { User } from '#shared/types'

export const useUser = () => {
  const user = useState<User | null>('user', () => null)
  return user
}

export const useSignOut = async () => {
  try {
    await $fetch('/api/auth/signout', { method: 'POST' })
    const user = useUser()
    user.value = null
    return await navigateTo('/signin')
  } catch (err) {
    console.error(err)
  }
}

export async function verifyToken(resetToken: string) {
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
