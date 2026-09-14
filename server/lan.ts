import type { IncomingMessage } from 'node:http'
import os from 'node:os'

export function bonjourHostname() {
  const host = os.hostname()
  return host.endsWith('.local') ? host : `${host}.local`
}

export function requestHost(req: IncomingMessage) {
  const host = req.headers.host ?? req.headers[':authority']
  if (typeof host === 'string' && host.length > 0) return host
  return 'localhost:5173'
}

export function hostnameFromHost(host: string | undefined) {
  const raw = (host ?? 'localhost').trim()
  if (raw.startsWith('[')) {
    const end = raw.indexOf(']')
    return end === -1 ? raw : raw.slice(1, end)
  }
  return raw.split(':')[0] || 'localhost'
}

export function isIpHostname(hostname: string) {
  return hostname === '::1' || hostname.includes(':') || /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname)
}

export function requestProto(req: IncomingMessage) {
  const forwarded = req.headers['x-forwarded-proto']
  if (typeof forwarded === 'string' && forwarded.length > 0) {
    return forwarded.split(',')[0]?.trim() || 'http'
  }
  if ((req.socket as { encrypted?: boolean }).encrypted) return 'https'
  return 'http'
}

export function originFromRequest(req: IncomingMessage) {
  const origin = req.headers.origin
  if (typeof origin === 'string' && origin.length > 0) return origin
  return `${requestProto(req)}://${requestHost(req)}`
}

export function phoneOrigin(req: IncomingMessage) {
  const hostHeader = requestHost(req)
  let port = '5173'
  if (hostHeader.startsWith('[')) {
    const idx = hostHeader.lastIndexOf(']:')
    if (idx !== -1) port = hostHeader.slice(idx + 2)
  } else {
    const idx = hostHeader.lastIndexOf(':')
    if (idx !== -1) port = hostHeader.slice(idx + 1)
  }
  return `https://${bonjourHostname()}:${port}`
}

export function isPasskeyOrigin(rpID: string, origin: string) {
  if (isIpHostname(rpID)) return false
  if (origin.startsWith('https://')) return true
  return rpID === 'localhost' && origin.startsWith('http://')
}

export function passkeyBlockReason(rpID: string, origin: string, phoneUrl: string) {
  if (isPasskeyOrigin(rpID, origin)) return null
  if (isIpHostname(rpID)) {
    return `Passkeys cannot use an IP as the RP ID. On a Face ID phone, open ${phoneUrl} instead of ${origin}.`
  }
  return `Passkeys need HTTPS (or http://localhost). On a Face ID phone, open ${phoneUrl}.`
}
