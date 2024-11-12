interface PasswordValidationOptions {
  minUppercase?: number
  minNumbers?: number
  minSpecialChars?: number
  minLength?: number
}

const defaultOptions: PasswordValidationOptions = {
  minUppercase: 1,
  minNumbers: 1,
  minSpecialChars: 1,
  minLength: 8
}

export function validatePassword(password: string, options: PasswordValidationOptions = {}): boolean {
  const { minUppercase, minNumbers, minSpecialChars, minLength } = { ...defaultOptions, ...options }

  const uppercasePattern = new RegExp(`(?=(?:.*[A-Z]){${minUppercase},})`)
  const numberPattern = new RegExp(`(?=(?:.*\\d){${minNumbers},})`)
  const specialCharPattern = new RegExp(`(?=(?:.*[!@#$%^&*()_+\\-=[\\]{};':"\\|,.<>/?]){${minSpecialChars},})`)
  const lengthPattern = new RegExp(`.{${minLength},}`)

  return (
    uppercasePattern.test(password)
    && numberPattern.test(password)
    && specialCharPattern.test(password)
    && lengthPattern.test(password)
  )
}

interface NameValidationOptions {
  minLength?: number
}

const defaultNameOptions: NameValidationOptions = {
  minLength: 2
}

export function validateName(name: string, options: NameValidationOptions = {}): boolean {
  const { minLength } = { ...defaultNameOptions, ...options }
  const lengthPattern = new RegExp(`.{${minLength},}`)
  return lengthPattern.test(name)
}

export function validateEmail(email: string): boolean {
  return /^.+@.+\..+$/.test(email) && email.length < 256
}
