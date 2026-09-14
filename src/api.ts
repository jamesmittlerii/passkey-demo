import { startAuthentication, startRegistration } from '@simplewebauthn/browser'
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/browser'

export type PasskeyInfo = {
  id: string
  deviceType: string
  backedUp: boolean
  transports: string[]
  counter: number
  createdAt: string
}

export type UserInfo = {
  id: string
  username: string
  passkeys: PasskeyInfo[]
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers)
  if (!headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }
  const response = await fetch(`/api${path}`, {
    credentials: 'same-origin',
    ...init,
    headers,
  })
  const data = (await response.json()) as T & { error?: string }
  if (!response.ok) {
    throw new Error(data.error || `Request failed (${response.status})`)
  }
  return data
}

export function getMe() {
  return request<{ user: UserInfo | null }>('/me')
}

export type DemoConfig = {
  rpName: string
  rpID: string
  origin: string
  phoneOrigin: string
  caPath: string
  passkeysOk: boolean
  hint: string | null
  users: string[]
}

export function getConfig() {
  return request<DemoConfig>('/config')
}

export function logout() {
  return request<{ ok: boolean }>('/logout', { method: 'POST', body: '{}' })
}

export function resetDemo() {
  return request<{ ok: boolean }>('/reset', { method: 'POST', body: '{}' })
}

export async function registerPasskey(username: string) {
  const options = await request<PublicKeyCredentialCreationOptionsJSON>(
    '/register/options',
    { method: 'POST', body: JSON.stringify({ username }) },
  )
  const attestation = await startRegistration({ optionsJSON: options })
  return finishRegistration(attestation)
}

export function finishRegistration(attestation: RegistrationResponseJSON) {
  return request<{ verified: boolean; user: UserInfo }>('/register/verify', {
    method: 'POST',
    body: JSON.stringify(attestation),
  })
}

export async function loginWithPasskey(username?: string) {
  const options = await request<PublicKeyCredentialRequestOptionsJSON>(
    '/login/options',
    { method: 'POST', body: JSON.stringify({ username: username || undefined }) },
  )
  const assertion = await startAuthentication({ optionsJSON: options })
  return finishLogin(assertion)
}

export function finishLogin(assertion: AuthenticationResponseJSON) {
  return request<{ verified: boolean; user: UserInfo }>('/login/verify', {
    method: 'POST',
    body: JSON.stringify(assertion),
  })
}

export function deletePasskey(id: string) {
  return request<{ ok: boolean; user: UserInfo }>(`/passkeys/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  })
}
