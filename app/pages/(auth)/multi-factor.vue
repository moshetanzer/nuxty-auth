<template>
  <div>
    Multi-Factor

    <form
      method="post"
      @submit.prevent="handleSubmit"
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
const { sendOtp, verifyOtp } = useAuth()
onMounted(async () => {
  await sendOtp()
})
const status = ref('')
const otp = ref('')
async function handleSubmit() {
  try {
    const result = await verifyOtp(otp.value)
    if (result.success) {
      status.value = 'MFA verified'
    } else {
      status.value = 'MFA verification failed'
    }
  } catch (error) {
    console.error(error)
  }
}
</script>
