<script setup lang="ts">
useHead({
  title: 'Home'
})
</script>

<template>
  <div>
    <h1>Home Page</h1>
    <h2>Nuxty Auth</h2>
    <NuxtLink to="/protected">
      Protected Page
    </NuxtLink>
  </div>
</template>
