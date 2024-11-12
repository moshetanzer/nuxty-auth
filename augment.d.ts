export {}

interface NuxtAuthConfig {
  roles: string[]
  emailVerification?: boolean
  auth?: boolean
  multiFactor?: boolean
  rateLimit?: {
    requests: number
    window: number
  } | boolean
}

declare module 'nitropack' {
  interface NitroRouteConfig {
    nuxtyAuth?: NuxtAuthConfig
  }
}

declare module '#app' {
  interface PageMeta {
    auth?: { roles: string[]
      emailVerification?: boolean
      multiFactor?: boolean
    } | boolean
  }
}

declare module 'vue-router' {
  interface RouteMeta {
    auth?: { roles: string[]
      emailVerification?: boolean
      multiFactor?: boolean
    } | boolean
  }
}
