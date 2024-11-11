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
const otp = ref('')
onMounted(async () => {
  await sendOtp()
})
async function handleSubmit() {
  try {
    await verifyOtp(otp.value)
  } catch (error) {
    console.error(error)
  }
}
</script>
