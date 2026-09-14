import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { X509Certificate } from 'node:crypto'
import { defineConfig, type Connect, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import { generate } from 'selfsigned'
import { createPasskeyApi } from './server/api.ts'
import { bonjourHostname } from './server/lan.ts'

const lan = process.argv.includes('--host')
const certDir = path.resolve('.certs')
const keyPath = path.join(certDir, 'dev-key.pem')
const certPath = path.join(certDir, 'dev-cert.pem')
const caKeyPath = path.join(certDir, 'ca-key.pem')
const caCertPath = path.join(certDir, 'ca-cert.pem')
const sansPath = path.join(certDir, 'sans.json')

function lanNames() {
  const host = os.hostname()
  return [...new Set(['localhost', host, bonjourHostname()])]
}

function lanIps() {
  const ips = new Set(['127.0.0.1', '::1'])
  try {
    for (const addrs of Object.values(os.networkInterfaces())) {
      for (const addr of addrs ?? []) {
        if (addr.internal || addr.family !== 'IPv4') continue
        ips.add(addr.address)
      }
    }
  } catch {
    // Some sandboxes cannot enumerate interfaces; SANs still cover localhost.
  }
  return [...ips]
}

function expiry() {
  const notAfterDate = new Date()
  notAfterDate.setFullYear(notAfterDate.getFullYear() + 2)
  return notAfterDate
}

async function loadOrCreateCerts() {
  const names = lanNames()
  const ips = lanIps()
  const sans = JSON.stringify({ names, ips })
  if (
    fs.existsSync(keyPath) &&
    fs.existsSync(certPath) &&
    fs.existsSync(caCertPath) &&
    fs.existsSync(sansPath) &&
    fs.readFileSync(sansPath, 'utf8') === sans
  ) {
    return {
      key: fs.readFileSync(keyPath),
      cert: `${fs.readFileSync(certPath, 'utf8')}\n${fs.readFileSync(caCertPath, 'utf8')}`,
    }
  }

  fs.mkdirSync(certDir, { recursive: true })
  const ca = await generate([{ name: 'commonName', value: 'Passkey demo CA' }], {
    keySize: 2048,
    algorithm: 'sha256',
    notAfterDate: expiry(),
    extensions: [
      { name: 'basicConstraints', cA: true, critical: true },
      { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true },
    ],
  })
  const pems = await generate([{ name: 'commonName', value: bonjourHostname() }], {
    keySize: 2048,
    algorithm: 'sha256',
    notAfterDate: expiry(),
    ca: { key: ca.private, cert: ca.cert },
    extensions: [
      { name: 'basicConstraints', cA: false },
      { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
      { name: 'extKeyUsage', serverAuth: true },
      {
        name: 'subjectAltName',
        altNames: [
          ...names.map((value) => ({ type: 2 as const, value })),
          ...ips.map((ip) => ({ type: 7 as const, ip })),
        ],
      },
    ],
  })
  fs.writeFileSync(caKeyPath, ca.private)
  fs.writeFileSync(caCertPath, ca.cert)
  fs.writeFileSync(keyPath, pems.private)
  fs.writeFileSync(certPath, pems.cert)
  fs.writeFileSync(sansPath, sans)
  return { key: pems.private, cert: `${pems.cert}\n${ca.cert}` }
}

function passkeyApiPlugin(): Plugin {
  const api = createPasskeyApi()
  const mount = (middlewares: Connect.Server) => {
    middlewares.use('/api', (req, res) => {
      api(req, res)
    })
  }

  return {
    name: 'passkey-api',
    configureServer(server) {
      mount(server.middlewares)
    },
    configurePreviewServer(server) {
      mount(server.middlewares)
    },
  }
}

function missingCa(res: ServerResponse) {
  res.statusCode = 404
  res.end('No local CA yet. Start the LAN HTTPS server first.')
}

function sendCaDer(_req: IncomingMessage, res: ServerResponse) {
  if (!fs.existsSync(caCertPath)) {
    missingCa(res)
    return
  }
  const pem = fs.readFileSync(caCertPath)
  res.statusCode = 200
  res.setHeader('Content-Type', 'application/x-x509-ca-cert')
  res.setHeader('Content-Disposition', 'attachment; filename="passkey-demo-ca.cer"')
  res.end(new X509Certificate(pem).raw)
}

function sendCaPem(_req: IncomingMessage, res: ServerResponse) {
  if (!fs.existsSync(caCertPath)) {
    missingCa(res)
    return
  }
  res.statusCode = 200
  res.setHeader('Content-Type', 'application/x-pem-file')
  res.setHeader('Content-Disposition', 'attachment; filename="passkey-demo-ca.pem"')
  res.end(fs.readFileSync(caCertPath))
}

function caDownloadPlugin(): Plugin {
  return {
    name: 'passkey-ca',
    configureServer(server) {
      server.middlewares.use('/ca.cer', sendCaDer)
      server.middlewares.use('/ca.pem', sendCaPem)
    },
  }
}

export default defineConfig(async () => ({
  plugins: [react(), passkeyApiPlugin(), ...(lan ? [caDownloadPlugin()] : [])],
  server: lan
    ? {
        host: true,
        allowedHosts: true as const,
        https: await loadOrCreateCerts(),
      }
    : undefined,
}))
