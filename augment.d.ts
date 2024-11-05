export {}

interface NuxtAuthConfig {
  roles: string[]
  emailVerification?: boolean
  auth?: boolean
  multiFactor?: boolean
  rateLimit?: {
    max: number
    duration: number
  } | boolean
}

declare module 'nitropack' {
  interface NitroRouteConfig {
    nuxtyAuth?: NuxtAuthConfig
  }
}
