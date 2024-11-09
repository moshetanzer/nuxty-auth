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
const user = useUser()
</script>

<template>
  <div>
    {{ user?.fname }} {{ user?.lname }}
    <NuxtLink to="/">
      Home
    </NuxtLink>
    <ActivateMfa />
    <button @click="useSignOut()">
      Sign Out
    </button>
  </div>
</template>
