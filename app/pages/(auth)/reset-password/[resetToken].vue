<script setup lang="ts">
useHead({
  title: 'Reset Password'
})
definePageMeta({
  middleware: ['reset-password-verification']
})
const password = ref('')
const confirmPassword = ref('')
const status = ref('')

const { resetPassword } = useAuth()
async function handleSubmit() {
  const route = useRoute()
  try {
    const result = await resetPassword(password.value, confirmPassword.value, route.params.resetToken as string)
    status.value = result
  } catch (error) {
    status.value = (error as Error).message
  }
}
</script>

<template>
  <div>
    <h1>Forgot Password</h1>
    <form
      method="post"
      @submit.prevent="handleSubmit"
    >
      <label for="new-password">New Password</label>
      <input
        id="new-password"
        v-model="password"
        type="password"
        name="password"
        autocomplete="new-password"
      >
      <label for="confirm-password">Confirm Password</label>
      <input
        id="confirm-password"
        v-model="confirmPassword"
        type="password"
        name="confirmPassword"
        autocomplete="new-password"
      >

      <button type="submit">
        reset password
      </button>
    </form>
    {{ status }}
  </div>
</template>
