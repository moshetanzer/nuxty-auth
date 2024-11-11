<script setup lang="ts">
const { sendOtp, user, deactivateMFA, activateMFA } = useAuth()
const mfaActive = user.value?.mfa
const otp = ref('')

const createOtp = async (action: string) => {
  await sendOtp()
  if (action === 'activate') activateStart.value = true
  if (action === 'deactivate') deactivateStart.value = true
}

const handleSubmit = async (action: 'activate' | 'deactivate') => {
  try {
    if (action === 'activate') {
      await activateMFA(otp.value)
    } else if (action === 'deactivate') {
      await deactivateMFA(otp.value)
    }
  } catch (e) {
    console.log(e)
  }
}
const activateStart = ref(false)
const deactivateStart = ref(false)
</script>

<template>
  <div>
    <div v-if="!mfaActive">
      <h1>Activate MFA</h1>
      <button @click="createOtp('activate')">
        Activate Email MFA
      </button>
      <form
        v-if="activateStart"
        @submit.prevent="handleSubmit('activate')"
      >
        <input
          v-model="otp"
          type="text"
          name="otp"
        >
        <button type="submit">
          Activate Mfa
        </button>
      </form>
    </div>
    <div v-else>
      <h1>MFA is active</h1>
      <button @click="createOtp('deactivate')">
        Deactivate MFA
      </button>
      <form
        v-if="deactivateStart"
        @submit.prevent="handleSubmit('deactivate')"
      >
        <input
          v-model="otp"
          type="text"
          name="otp"
        >
        <button type="submit">
          Deactivate MFA
        </button>
      </form>
    </div>
  </div>
</template>
