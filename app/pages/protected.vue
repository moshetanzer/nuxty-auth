<script setup lang="ts">
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
    <button @click="useSignOut()">
      Sign Out
    </button>
  </div>
</template>
