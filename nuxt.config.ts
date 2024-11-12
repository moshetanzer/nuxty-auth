export default defineNuxtConfig({
  modules: ['@nuxt/eslint'],
  ssr: true,
  devtools: { enabled: false },
  runtimeConfig: {
    authConnectionString: '',
    authUserTableName: '',
    authSessionTableName: '',
    authMfaTableName: '',
    defaultUserRole: '',
    sessionRefreshInterval: '',
    sessionTotalDuration: '',
    sessionExtensionDuration: '',
    rateLimit: '',
    rateLimitWindow: '',
    otpExpiry: '',
    maxFailedAttempts: '',
    emailHost: '',
    emailPort: '',
    emailUser: '',
    emailPassword: '',
    baseUrl: 'http://localhost:3000'
  },
  routeRules: {
    '/api/admin/**': {
      nuxtyAuth: {
        roles: ['admin'],
        emailVerification: true,
        auth: true,
        rateLimit: {
          requests: 10,
          window: 60
        }
      }
    },
    '/api/user/**': {
      nuxtyAuth: {
        auth: true,
        roles: ['user', 'admin'],
        rateLimit: false
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
