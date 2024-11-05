export default defineNuxtConfig({
  modules: ['@nuxt/eslint'],
  ssr: true,
  devtools: { enabled: false },
  runtimeConfig: {
    authDb: '',
    emailHost: '',
    emailPort: '',
    emailUser: '',
    emailPassword: '',
    sessionTotalDuration: '',
    sessionSlidingWindow: '',
    sessionRefreshInterval: '',
    baseUrl: 'http://localhost:3000'
  },
  routeRules: {
    '/api/admin/**': {
      nuxtyAuth: {
        roles: ['admin'],
        emailVerification: true,
        auth: true
      }
    },
    '/api/user/**': {
      nuxtyAuth: {
        auth: true,
        roles: ['user', 'admin']
      }
    }
  },
  future: {
    compatibilityVersion: 4
  },
  compatibilityDate: '2024-04-03',
  telemetry: false,
  eslint: {
    config: {
      stylistic: {
        commaDangle: 'never',
        braceStyle: '1tbs'
      }
    } }
})
