<script setup lang="ts">
useHead({
  title: 'Sign In'
})
definePageMeta({
  middleware: ['protected-from-logged-in']
})
const email = ref('')
const password = ref('')
const status = ref('')

const { signIn } = useAuth()

async function handleSubmit() {
  try {
    await signIn(email.value, password.value)
  } catch (error) {
    status.value = error as string || (error as Error).message
    console.error('Sign in error:', error)
  }
}
</script>

<template>
  <div>
    <h1>Sign In</h1>
    <form
      method="post"
      @submit.prevent="handleSubmit"
    >
      <label for="email">Email</label>
      <input
        id="email"
        v-model="email"
        type="email"
        autocomplete="username"
        name="email"
      >
      <label for="password">Password</label>
      <input
        id="password"
        v-model="password"
        type="password"
        autocomplete="current-password"
        name="password"
      >
      <div>{{ status }}</div>

      <button type="submit">
        Sign In
      </button>
    </form>
    <NuxtLink
      to="/reset-password"
      role="button"
    >
      forgot password
    </NuxtLink>

    <NuxtLink
      to="/signup"
      role="button"
    >
      signup
    </NuxtLink>
  </div>
</template>
