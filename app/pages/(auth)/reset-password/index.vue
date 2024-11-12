<script setup lang="ts">
useHead({
  title: 'Forgot Password'
})
const email = ref('')
const status = ref('')
const { requestPasswordReset } = useAuth()

async function handleSubmit() {
  try {
    const result = await requestPasswordReset(email.value)
    status.value = result
  } catch (error) {
    status.value = error as string || (error as Error).message
    console.error('Request password reset error:', error)
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
      <label for="email">Email</label>
      <input
        id="email"
        v-model="email"
        type="email"
        name="email"
      >
      <button type="submit">
        Submit
      </button>
    </form>
    {{ status }}
  </div>
</template>
