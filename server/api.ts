import type { IncomingMessage, ServerResponse } from 'node:http'
import { parseCookie, stringifySetCookie } from 'cookie'
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server'
import {
  addPasskey,
  createSession,
  createUser,
  destroySession,
  getPasskey,
  getSession,
  getUserById,
  getUserByName,
  listUsernames,
  removePasskey,
  resetStore,
  updatePasskeyCounter,
  type SessionRecord,
} from './store.ts'
import {
  hostnameFromHost,
  isPasskeyOrigin,
  originFromRequest,
  passkeyBlockReason,
  phoneOrigin,
  requestHost,
  requestProto,
} from './lan.ts'

const COOKIE = 'sid'
const RP_NAME = 'Passkey demo'

type Handler = (req: IncomingMessage, res: ServerResponse, path: string) => Promise<void> | void

function rpIDFromRequest(req: IncomingMessage) {
  return hostnameFromHost(requestHost(req))
}

function readCookies(req: IncomingMessage) {
  return parseCookie(req.headers.cookie ?? '')
}

function setSessionCookie(req: IncomingMessage, res: ServerResponse, sessionId: string) {
  res.setHeader(
    'Set-Cookie',
    stringifySetCookie({
      name: COOKIE,
      value: sessionId,
      httpOnly: true,
      sameSite: 'lax',
      secure: requestProto(req) === 'https',
      path: '/',
      maxAge: 60 * 60 * 24 * 7,
    }),
  )
}

function clearSessionCookie(res: ServerResponse) {
  res.setHeader(
    'Set-Cookie',
    stringifySetCookie({
      name: COOKIE,
      value: '',
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 0,
    }),
  )
}

function send(res: ServerResponse, status: number, body: unknown) {
  const payload = JSON.stringify(body)
  res.statusCode = status
  res.setHeader('Content-Type', 'application/json')
  res.setHeader('Cache-Control', 'no-store')
  res.end(payload)
}

function readJson<T>(req: IncomingMessage): Promise<T> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    req.on('data', (chunk) => {
      chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk)
    })
    req.on('end', () => {
      if (chunks.length === 0) {
        resolve({} as T)
        return
      }
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')) as T)
      } catch (error) {
        reject(error)
      }
    })
    req.on('error', reject)
  })
}

function publicUser(userId: string) {
  const user = getUserById(userId)
  if (!user) return null
  return {
    id: user.id,
    username: user.username,
    passkeys: user.passkeys.map((passkey) => ({
      id: passkey.id,
      deviceType: passkey.deviceType,
      backedUp: passkey.backedUp,
      transports: passkey.transports ?? [],
      counter: passkey.counter,
      createdAt: passkey.createdAt,
    })),
  }
}

function getOrCreateSession(req: IncomingMessage, res: ServerResponse): SessionRecord {
  const sid = readCookies(req)[COOKIE]
  const existing = getSession(sid)
  if (existing) return existing
  const session = createSession()
  setSessionCookie(req, res, session.id)
  return session
}

function rejectIfNotPasskeyOrigin(req: IncomingMessage, res: ServerResponse, rpID: string) {
  const origin = originFromRequest(req)
  const phoneUrl = phoneOrigin(req)
  const error = passkeyBlockReason(rpID, origin, phoneUrl)
  if (!error) return false
  send(res, 400, { error })
  return true
}

function rememberCeremony(
  session: SessionRecord,
  req: IncomingMessage,
  rpID: string,
  challenge: string,
  pendingUserId?: string,
) {
  session.challenge = challenge
  session.rpID = rpID
  session.origin = originFromRequest(req)
  session.pendingUserId = pendingUserId
}

function clearCeremony(session: SessionRecord) {
  session.challenge = undefined
  session.origin = undefined
  session.rpID = undefined
  session.pendingUserId = undefined
}

function sendConfig(req: IncomingMessage, res: ServerResponse) {
  const rpID = rpIDFromRequest(req)
  const origin = originFromRequest(req)
  const phoneUrl = phoneOrigin(req)
  send(res, 200, {
    rpName: RP_NAME,
    rpID,
    origin,
    phoneOrigin: phoneUrl,
    caPath: '/ca.cer',
    passkeysOk: isPasskeyOrigin(rpID, origin),
    hint: passkeyBlockReason(rpID, origin, phoneUrl),
    users: listUsernames(),
  })
}

function sendMe(req: IncomingMessage, res: ServerResponse) {
  const session = getOrCreateSession(req, res)
  send(res, 200, {
    user: session.userId ? publicUser(session.userId) : null,
  })
}

function handleLogout(req: IncomingMessage, res: ServerResponse) {
  const sid = readCookies(req)[COOKIE]
  if (sid) destroySession(sid)
  clearSessionCookie(res)
  send(res, 200, { ok: true })
}

function handleReset(_req: IncomingMessage, res: ServerResponse) {
  resetStore()
  clearSessionCookie(res)
  send(res, 200, { ok: true })
}

function userForRegistration(session: SessionRecord, username: string, res: ServerResponse) {
  if (session.userId) {
    const signedIn = getUserById(session.userId)
    if (!signedIn) {
      send(res, 401, { error: 'Session expired. Sign in again.' })
      return undefined
    }
    return signedIn
  }

  const existing = getUserByName(username)
  if (existing && existing.passkeys.length > 0) {
    send(res, 409, { error: 'That username already has a passkey. Sign in instead.' })
    return undefined
  }
  return existing ?? createUser(username)
}

async function registerOptions(req: IncomingMessage, res: ServerResponse) {
  const body = await readJson<{ username?: string }>(req)
  const username = body.username?.trim() ?? ''
  if (username.length < 2) {
    send(res, 400, { error: 'Pick a username with at least 2 characters.' })
    return
  }

  const session = getOrCreateSession(req, res)
  const user = userForRegistration(session, username, res)
  if (!user) return

  const rpID = rpIDFromRequest(req)
  if (rejectIfNotPasskeyOrigin(req, res, rpID)) return

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID,
    userName: user.username,
    userDisplayName: user.username,
    userID: user.webauthnUserID,
    attestationType: 'none',
    excludeCredentials: user.passkeys.map((passkey) => ({
      id: passkey.id,
      transports: passkey.transports,
    })),
    authenticatorSelection: {
      residentKey: 'required',
      userVerification: 'preferred',
    },
    supportedAlgorithmIDs: [-7, -257],
  })

  rememberCeremony(session, req, rpID, options.challenge, user.id)
  send(res, 200, options)
}

async function registerVerify(req: IncomingMessage, res: ServerResponse) {
  const session = getOrCreateSession(req, res)
  if (!session.challenge || !session.pendingUserId || !session.rpID || !session.origin) {
    send(res, 400, { error: 'No registration in progress. Start again.' })
    return
  }

  const user = getUserById(session.pendingUserId)
  if (!user) {
    send(res, 400, { error: 'User disappeared. Start again.' })
    return
  }

  const response = await readJson<RegistrationResponseJSON>(req)
  const verification = await verifyRegistrationResponse({
    response,
    expectedChallenge: session.challenge,
    expectedOrigin: session.origin,
    expectedRPID: session.rpID,
    requireUserVerification: false,
  })

  clearCeremony(session)

  if (!verification.verified || !verification.registrationInfo) {
    send(res, 400, { error: 'Registration could not be verified.' })
    return
  }

  const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo
  addPasskey(user.id, {
    id: credential.id,
    publicKey: credential.publicKey,
    counter: credential.counter,
    deviceType: credentialDeviceType,
    backedUp: credentialBackedUp,
    transports: credential.transports,
    createdAt: new Date().toISOString(),
  })

  session.userId = user.id
  send(res, 200, { verified: true, user: publicUser(user.id) })
}

async function loginOptions(req: IncomingMessage, res: ServerResponse) {
  const body = await readJson<{ username?: string }>(req)
  const username = body.username?.trim() ?? ''
  const session = getOrCreateSession(req, res)
  const rpID = rpIDFromRequest(req)
  if (rejectIfNotPasskeyOrigin(req, res, rpID)) return

  const namedUser = username ? getUserByName(username) : undefined
  if (username && !namedUser) {
    send(res, 404, { error: 'No account with that username.' })
    return
  }

  const allowCredentials = namedUser?.passkeys.map((passkey) => ({
    id: passkey.id,
    transports: passkey.transports,
  }))
  if (username && allowCredentials?.length === 0) {
    send(res, 400, { error: 'That account has no passkeys yet.' })
    return
  }

  const options = await generateAuthenticationOptions({
    rpID,
    userVerification: 'preferred',
    allowCredentials,
  })

  rememberCeremony(session, req, rpID, options.challenge)
  send(res, 200, options)
}

async function loginVerify(req: IncomingMessage, res: ServerResponse) {
  const session = getOrCreateSession(req, res)
  if (!session.challenge || !session.rpID || !session.origin) {
    send(res, 400, { error: 'No sign-in in progress. Start again.' })
    return
  }

  const response = await readJson<AuthenticationResponseJSON>(req)
  const found = getPasskey(response.id)
  if (!found) {
    send(res, 400, { error: 'This passkey is not registered here.' })
    return
  }

  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge: session.challenge,
    expectedOrigin: session.origin,
    expectedRPID: session.rpID,
    credential: found.passkey,
    requireUserVerification: false,
  })

  clearCeremony(session)

  if (!verification.verified) {
    send(res, 400, { error: 'Sign-in could not be verified.' })
    return
  }

  updatePasskeyCounter(found.passkey.id, verification.authenticationInfo.newCounter)
  session.userId = found.userId
  send(res, 200, { verified: true, user: publicUser(found.userId) })
}

function deleteUserPasskey(req: IncomingMessage, res: ServerResponse, path: string) {
  const session = getOrCreateSession(req, res)
  if (!session.userId) {
    send(res, 401, { error: 'Sign in first.' })
    return
  }
  const credentialId = decodeURIComponent(path.slice('/passkeys/'.length))
  const removed = removePasskey(session.userId, credentialId)
  send(res, removed ? 200 : 404, {
    ok: removed,
    user: publicUser(session.userId),
    error: removed ? undefined : 'Passkey not found.',
  })
}

const routes: Record<string, Handler> = {
  'GET /config': sendConfig,
  'GET /me': sendMe,
  'POST /logout': handleLogout,
  'POST /reset': handleReset,
  'POST /register/options': registerOptions,
  'POST /register/verify': registerVerify,
  'POST /login/options': loginOptions,
  'POST /login/verify': loginVerify,
}

async function handle(req: IncomingMessage, res: ServerResponse, method: string, path: string) {
  const handler = routes[`${method} ${path}`]
  if (handler) {
    await handler(req, res, path)
    return
  }
  if (method === 'DELETE' && path.startsWith('/passkeys/')) {
    deleteUserPasskey(req, res, path)
    return
  }
  send(res, 404, { error: `No route for ${method} ${path}` })
}

export function createPasskeyApi() {
  return function passkeyApi(req: IncomingMessage, res: ServerResponse) {
    const url = new URL(req.url ?? '/', 'http://localhost')
    let path = url.pathname
    if (path.startsWith('/api')) path = path.slice(4) || '/'
    const method = req.method ?? 'GET'

    void handle(req, res, method, path).catch((error: unknown) => {
      const message = error instanceof Error ? error.message : 'Unexpected error'
      if (!res.headersSent) send(res, 400, { error: message })
    })
  }
}
