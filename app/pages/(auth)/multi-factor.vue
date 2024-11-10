<template>
  <div>
    multi-factor

    <form
      method="post"
      @submit.prevent="useVerifyMfa()"
    >
      <input
        v-model="otp"
        type="text"
        placeholder="Code"
      >
      <button>Submit</button>
    </form>
  </div>
</template>

<script setup lang="ts">
async function sendOtp() {
  try {
    await $fetch('/api/auth/mfa/email/generate',
      { method: 'POST' }
    )
  } catch (error) {
    console.error(error)
  }
}
await sendOtp()
const otp = ref('')
const route = useRoute()
async function useVerifyMfa() {
  try {
    const result = await $fetch('/api/auth/mfa/email', {
      method: 'POST',
      body: JSON.stringify({
        otp: otp.value
      })
    })
    if (result === true) {
      if (route.query.redirect) {
        await navigateTo(route.query.redirect as string)
      } else {
        await navigateTo('/')
      }
    } else {
      console.log('error: MFA verification failed')
    }
  } catch (error) {
    console.error('Navigation error:', error)
  }
}
</script>
