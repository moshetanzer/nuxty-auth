<template>
  <div>
    <button @click="handleSubmit">
      Request Password Reset
    </button>
  </div>
</template>

<script lang="ts" setup>
const { requestPasswordReset, user, signOut } = useAuth()
const status = ref('')
async function handleSubmit() {
  if (!user.value?.email) {
    status.value = 'Not logged in'
    return await signOut()
  }
  try {
    const result = await requestPasswordReset(user.value.email)
    status.value = result
  } catch (error) {
    status.value = error as string || (error as Error).message
    console.error('Request password reset error:', error)
  }
}
</script>
