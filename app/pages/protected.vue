<script setup lang="ts">
useHead({
  title: 'Protected Page'
})
definePageMeta({
  middleware: ['protected'],
  auth: {
    roles: ['user']
  }
})
const { user, signOut } = useAuth()
</script>

<template>
  <div>
    {{ user?.fname }} {{ user?.lname }}
    <NuxtLink to="/">
      Home
    </NuxtLink>
    <ManageMfa />
    <ResetPassword />
    <button @click="signOut()">
      Sign Out
    </button>
  </div>
</template>
