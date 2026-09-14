import { useEffect, useMemo, useState } from 'react'
import {
  deletePasskey,
  getConfig,
  getMe,
  loginWithPasskey,
  logout,
  registerPasskey,
  resetDemo,
  type DemoConfig,
  type UserInfo,
} from './api.ts'
import './App.css'

type LogEntry = {
  id: number
  tone: 'ok' | 'error' | 'info'
  message: string
}

type Caps = {
  webauthn: boolean
  platform: boolean | null
  conditional: boolean | null
}

type RunFn = (label: string, action: () => Promise<unknown>) => Promise<void>

type PhoneSetupStepsProps = Readonly<{ config: DemoConfig }>
type OriginBannerProps = Readonly<{ config: DemoConfig | null }>
type SignedOutFormProps = Readonly<{
  username: string
  setUsername: (value: string) => void
  busy: string | null
  disableAuth: boolean
  run: RunFn
}>
type SignedInPanelProps = Readonly<{
  user: UserInfo
  busy: string | null
  disableAuth: boolean
  run: RunFn
}>
type LabNotesProps = Readonly<{
  caps: Caps
  config: DemoConfig | null
  busy: string | null
  logs: LogEntry[]
  run: RunFn
  onReset: () => Promise<void>
}>

let logSeq = 0

function flagLabel(value: boolean | null) {
  if (value === null) return '…'
  return value ? 'yes' : 'no'
}

function originHint(config: DemoConfig | null) {
  if (config?.passkeysOk) return <span> · {config.origin}</span>
  return <span> · use <code>localhost</code> or the phone HTTPS hostname, not a raw IP</span>
}

function PhoneSetupSteps({ config }: PhoneSetupStepsProps) {
  const restartFirst = config.origin.startsWith('http:')
  return (
    <p className="banner-steps">
      {restartFirst ? (
        <>
          Restart with <code>npm run dev:lan</code>, then{' '}
        </>
      ) : null}
      open <code>{config.phoneOrigin}</code> on the phone, then{' '}
      <a href={config.caPath} download>download the local CA</a>
      {' '}and install the profile, then enable full trust in Settings → General → About →
      Certificate Trust Settings.
    </p>
  )
}

function OriginBanner({ config }: OriginBannerProps) {
  const showPhoneSetup = Boolean(config && !config.passkeysOk && config.phoneOrigin)
  return (
    <>
      <p className="meta">
        RP ID <code>{config?.rpID ?? '…'}</code>
        {originHint(config)}
      </p>
      {config?.hint ? <p className="banner">{config.hint}</p> : null}
      {showPhoneSetup && config ? <PhoneSetupSteps config={config} /> : null}
    </>
  )
}

function SignedOutForm({
  username,
  setUsername,
  busy,
  disableAuth,
  run,
}: SignedOutFormProps) {
  return (
    <form
      className="stack"
      onSubmit={(event) => {
        event.preventDefault()
        void run('Registered passkey', () => registerPasskey(username))
      }}
    >
      <label>
        <span>Username</span>
        <input
          autoComplete="username webauthn"
          value={username}
          onChange={(event) => setUsername(event.target.value)}
          placeholder="ada"
        />
      </label>
      <div className="actions">
        <button type="submit" disabled={disableAuth}>
          {busy === 'Registered passkey' ? 'Waiting on authenticator…' : 'Create passkey'}
        </button>
        <button
          type="button"
          className="secondary"
          disabled={disableAuth}
          onClick={() => void run('Signed in with username', () => loginWithPasskey(username))}
        >
          Sign in with username
        </button>
        <button
          type="button"
          className="secondary"
          disabled={disableAuth}
          onClick={() => void run('Signed in with passkey', () => loginWithPasskey())}
        >
          Sign in without username
        </button>
      </div>
    </form>
  )
}

function SignedInPanel({
  user,
  busy,
  disableAuth,
  run,
}: SignedInPanelProps) {
  const passkeyWord = user.passkeys.length === 1 ? 'passkey' : 'passkeys'
  return (
    <div className="stack">
      <p>
        {user.passkeys.length} {passkeyWord} on this account.
      </p>
      <div className="actions">
        <button
          type="button"
          disabled={disableAuth}
          onClick={() => void run('Added another passkey', () => registerPasskey(user.username))}
        >
          Add another passkey
        </button>
        <button
          type="button"
          className="secondary"
          disabled={Boolean(busy)}
          onClick={() => void run('Signed out', () => logout())}
        >
          Sign out
        </button>
      </div>
      <ul className="passkeys">
        {user.passkeys.map((passkey) => (
          <li key={passkey.id}>
            <div>
              <strong>{passkey.deviceType}</strong>
              <span>
                {passkey.backedUp ? 'synced / backed up' : 'device-bound'} · counter{' '}
                {passkey.counter}
              </span>
              <code>{passkey.id}</code>
            </div>
            <button
              type="button"
              className="ghost"
              disabled={Boolean(busy)}
              onClick={() => void run('Removed passkey', () => deletePasskey(passkey.id))}
            >
              Remove
            </button>
          </li>
        ))}
      </ul>
    </div>
  )
}

function LabNotes({
  caps,
  config,
  busy,
  logs,
  run,
  onReset,
}: LabNotesProps) {
  const knownUsers = config?.users.length ? config.users.join(', ') : 'none yet'
  const phoneUrl = config?.phoneOrigin
  const showCa = Boolean(config?.origin.startsWith('https://'))
  return (
    <article className="card">
      <h2>Lab notes</h2>
      <ul className="notes">
        <li>
          WebAuthn: <strong>{flagLabel(caps.webauthn)}</strong>
        </li>
        <li>
          Platform authenticator: <strong>{flagLabel(caps.platform)}</strong>
        </li>
        <li>
          Conditional UI: <strong>{flagLabel(caps.conditional)}</strong>
        </li>
        <li>
          Known users: <strong>{knownUsers}</strong>
        </li>
        <li>
          Phone URL:{' '}
          <strong>{phoneUrl ? <a href={phoneUrl}>{phoneUrl}</a> : '…'}</strong>
        </li>
        {showCa && config ? (
          <li>
            iPhone CA:{' '}
            <a href={config.caPath} download>download and install</a>
            {' '}then enable full trust
          </li>
        ) : null}
      </ul>
      <button
        type="button"
        className="secondary"
        disabled={Boolean(busy)}
        onClick={() => void run('Reset demo data', onReset)}
      >
        Reset in-memory users
      </button>
      <ol className="log">
        {logs.length === 0 ? <li className="muted">Events will show up here.</li> : null}
        {logs.map((entry) => (
          <li key={entry.id} className={entry.tone}>
            {entry.message}
          </li>
        ))}
      </ol>
    </article>
  )
}

function authenticatorStatus(blocked: boolean, caps: Caps) {
  if (blocked) return 'This origin cannot create or use passkeys.'
  if (!caps.webauthn) return 'This browser does not expose WebAuthn.'
  if (caps.platform) return 'Platform authenticator available (Touch ID, Face ID, Windows Hello).'
  if (caps.platform === false) {
    return 'No platform authenticator. A security key or phone passkey can still work.'
  }
  return 'Checking authenticator support…'
}

export default function App() {
  const [username, setUsername] = useState('')
  const [user, setUser] = useState<UserInfo | null>(null)
  const [config, setConfig] = useState<DemoConfig | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [caps, setCaps] = useState<Caps>({
    webauthn: false,
    platform: null,
    conditional: null,
  })

  const log = (tone: LogEntry['tone'], message: string) => {
    setLogs((current) => [{ id: ++logSeq, tone, message }, ...current].slice(0, 12))
  }

  const refresh = async () => {
    const [me, nextConfig] = await Promise.all([getMe(), getConfig()])
    setUser(me.user)
    setConfig(nextConfig)
  }

  useEffect(() => {
    const webauthn = typeof PublicKeyCredential !== 'undefined'
    setCaps({ webauthn, platform: null, conditional: null })
    if (webauthn) {
      void PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().then(
        (platform) => setCaps((current) => ({ ...current, platform })),
      )
      if ('isConditionalMediationAvailable' in PublicKeyCredential) {
        void PublicKeyCredential.isConditionalMediationAvailable().then((conditional) =>
          setCaps((current) => ({ ...current, conditional })),
        )
      }
    }
    void refresh().catch((error: unknown) => {
      log('error', error instanceof Error ? error.message : 'Could not load session')
    })
  }, [])

  const run: RunFn = async (label, action) => {
    setBusy(label)
    try {
      await action()
      log('ok', label)
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      log('error', message)
    } finally {
      setBusy(null)
      await refresh().catch(() => undefined)
    }
  }

  const blocked = config?.passkeysOk === false
  const disableAuth = Boolean(busy) || !caps.webauthn || blocked
  const status = useMemo(() => authenticatorStatus(blocked, caps), [blocked, caps])

  return (
    <main className="page">
      <header className="hero">
        <p className="kicker">Local experiment</p>
        <h1>Passkey demo</h1>
        <p className="lede">
          Register a discoverable credential, then sign back in with the device prompt.
          Users live in memory on the Vite server, so a restart wipes the lab.
        </p>
        <OriginBanner config={config} />
      </header>

      <section className="grid">
        <article className="card">
          <h2>{user ? `Signed in as ${user.username}` : 'Create or sign in'}</h2>
          <p className="status">{status}</p>
          {user ? (
            <SignedInPanel user={user} busy={busy} disableAuth={disableAuth} run={run} />
          ) : (
            <SignedOutForm
              username={username}
              setUsername={setUsername}
              busy={busy}
              disableAuth={disableAuth}
              run={run}
            />
          )}
        </article>
        <LabNotes
          caps={caps}
          config={config}
          busy={busy}
          logs={logs}
          run={run}
          onReset={async () => {
            await resetDemo()
            setUsername('')
          }}
        />
      </section>
    </main>
  )
}
