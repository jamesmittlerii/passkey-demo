import { randomUUID } from 'node:crypto'
import type {
  CredentialDeviceType,
  WebAuthnCredential,
} from '@simplewebauthn/server'

export type PasskeyRecord = WebAuthnCredential & {
  deviceType: CredentialDeviceType
  backedUp: boolean
  createdAt: string
}

export type UserRecord = {
  id: string
  username: string
  webauthnUserID: Uint8Array<ArrayBuffer>
  passkeys: PasskeyRecord[]
}

export type SessionRecord = {
  id: string
  userId?: string
  challenge?: string
  rpID?: string
  origin?: string
  pendingUserId?: string
}

const usersById = new Map<string, UserRecord>()
const usersByName = new Map<string, UserRecord>()
const passkeysById = new Map<string, { userId: string; passkey: PasskeyRecord }>()
const sessions = new Map<string, SessionRecord>()

function normalizeUsername(username: string) {
  return username.trim().toLowerCase()
}

export function createSession(): SessionRecord {
  const session: SessionRecord = { id: randomUUID() }
  sessions.set(session.id, session)
  return session
}

export function getSession(id: string | undefined) {
  if (!id) return undefined
  return sessions.get(id)
}

export function destroySession(id: string) {
  sessions.delete(id)
}

export function getUserById(id: string) {
  return usersById.get(id)
}

export function getUserByName(username: string) {
  return usersByName.get(normalizeUsername(username))
}

export function createUser(username: string): UserRecord {
  const key = normalizeUsername(username)
  const existing = usersByName.get(key)
  if (existing) return existing

  const id = randomUUID()
  const user: UserRecord = {
    id,
    username: username.trim(),
    webauthnUserID: new TextEncoder().encode(id) as Uint8Array<ArrayBuffer>,
    passkeys: [],
  }
  usersById.set(id, user)
  usersByName.set(key, user)
  return user
}

export function getPasskey(credentialId: string) {
  return passkeysById.get(credentialId)
}

export function addPasskey(userId: string, passkey: PasskeyRecord) {
  const user = usersById.get(userId)
  if (!user) throw new Error('User not found')
  if (passkeysById.has(passkey.id)) return user
  user.passkeys.push(passkey)
  passkeysById.set(passkey.id, { userId, passkey })
  return user
}

export function updatePasskeyCounter(credentialId: string, counter: number) {
  const found = passkeysById.get(credentialId)
  if (!found) return
  found.passkey.counter = counter
}

export function removePasskey(userId: string, credentialId: string) {
  const user = usersById.get(userId)
  if (!user) return false
  const before = user.passkeys.length
  user.passkeys = user.passkeys.filter((passkey) => passkey.id !== credentialId)
  passkeysById.delete(credentialId)
  return user.passkeys.length !== before
}

export function resetStore() {
  usersById.clear()
  usersByName.clear()
  passkeysById.clear()
  sessions.clear()
}

export function listUsernames() {
  return [...usersByName.values()].map((user) => user.username)
}
