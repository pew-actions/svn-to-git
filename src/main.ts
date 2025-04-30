import { promises as fs } from 'fs'
import * as core from '@actions/core'
import * as tls from 'tls'
import * as path from 'path'
import * as os from 'os'
import * as https from 'https'
import * as http from 'http'
import * as exec from '@actions/exec'
import { v4 as uuidv4 } from 'uuid'
import { X509Certificate } from "@peculiar/x509"
import { createHash } from 'crypto'
import nodeGypBuild from 'node-gyp-build'

const addon = nodeGypBuild(path.resolve(__dirname, '..'));


function urlToRealm(uri: URL): string {
  const scheme = uri.protocol
  const hostname = uri.hostname
  const port = uri.port

  const portPart = port ? `:${port}` : (scheme === 'https:' ? ':443' : ':80')
  return `${scheme}//${hostname}${portPart}`
}

// Get the Base64-encoded certificate for a URL
async function getCert(uri: URL): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host: uri.hostname,
        port: uri.port ? parseInt(uri.port) : 443,
        rejectUnauthorized: false,
      },
      () => {
        const cert = socket.getPeerCertificate();
        socket.end()

        if (!cert || !cert.raw) {
          return reject(new Error('No certificate retrieved'))
        }

        const base64Cert = cert.raw.toString('base64')
        resolve(base64Cert)
      }
    )

    socket.on('error', (err) => reject(err))
  })
}

async function getRealmName(uri: URL): Promise<string | null> {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: uri.hostname,
      port: uri.port || (uri.protocol === 'https:' ? 443 : 80),
      path: uri.pathname,
      method: 'GET',
      rejectUnauthorized: false,
    }

    const reqFunc = (uri.protocol === 'https:' ? https.request : http.request)

    const req = reqFunc(options, (res) => {
        const auth = res.headers['www-authenticate']
        if (auth && typeof auth === 'string') {
          const match = auth.match(/realm="([^"]+)"/)
          if (match) {
            resolve(match[1])
            return
          }
        }

        resolve(null)
    })

    req.on('error', (err) => reject(err))
    req.end()
  })
}

function makeSvnConfig(obj: Object): string {
  const lines: string[] = []
  for (const key in obj) {
    lines.push(`K ${key.length}`)
    lines.push(key)

    const value = obj[key]
    lines.push(`V ${value.length}`)
    lines.push(value)
  }

  lines.push('END')

  return lines.join('\n')
}

function toU16Buffer(str: string): Buffer {
  const array = new Uint16Array(str.length)

  for (let ii = 0; ii != str.length; ++ii) {
    array[ii] = str.charCodeAt(ii)
  }

  return Buffer.from(array)
}

async function populateSvnConfig(svnUrl: URL, configDir: string): Promise<void> {
  const authDir = path.join(configDir, 'auth')
  const simpleDir = path.join(authDir, 'svn.simple')
  const sslServer = path.join(authDir, 'svn.ssl.server')

  await fs.mkdir(authDir, {recursive: true})
  await fs.mkdir(simpleDir, {recursive: true})
  await fs.mkdir(sslServer, {recursive: true})

  const username = core.getInput('username')
  if (!username) {
    throw Error('No username passed to action')
  }

  const password = core.getInput('password')
  if (!password) {
    throw Error('No password passed to action')
  }

  const realm = urlToRealm(svnUrl)

  const realmName = await getRealmName(svnUrl)
  const fullRealm = realmName ? `<${realm}> ${realmName}` : realm

  if (svnUrl.protocol === 'https:') {
    const fingerprint = core.getInput('fingerprint')
    if (!fingerprint) {
      throw new Error('No fingerprint passed to action')
    }

    const rawCert = await getCert(svnUrl)
    const certDer = Buffer.from(rawCert, 'base64')
    const sha1 = createHash("sha1").update(certDer).digest("hex").toUpperCase();
    const serverFingerprint = sha1.match(/.{2}/g)?.join(':')
    if (serverFingerprint !== fingerprint) {
      throw new Error(`Server fingerprint mismatch: ${serverFingerprint} != ${fingerprint}`)
    }

    // build server SSL config
    const sslConfig = makeSvnConfig({
      ascii_cert: rawCert,
      failures: '12',
      "svn:realmstring": realm,
    })

    const md5 = createHash('md5')
    md5.update(realm, 'utf8')
    const filename = md5.digest('hex')

    await fs.writeFile(path.join(sslServer, filename), sslConfig, 'utf8')
  }

  const serverConfig = makeSvnConfig({
    passtype: 'wincrypt',
    username: username,
    password: addon.encrypt(password),
    'svn:realmstring': fullRealm,
  })

  const md5 = createHash('md5')
  md5.update(fullRealm, 'utf8')
  const filename = md5.digest('hex')

  await fs.writeFile(path.join(simpleDir, filename), serverConfig, 'utf8')

  const config = `
[global]
store-passwords = yes
  `.trim()

  await fs.writeFile(path.join(configDir, 'servers'), config, 'utf8')
}

async function run(): Promise<void> {

  const homeDir = process.env.APPDATA!
  const configDir = path.join(homeDir, 'Subversion')
  const userConfigDir = path.join(os.homedir(), ".subversion")

  const fullSvnUrl = core.getInput('svn-url')
  if (!fullSvnUrl) {
    throw Error('No svn-url passed to action')
  }
  const svnUrl = new URL(fullSvnUrl)

  const repositoryPath = core.getInput('path') || '.'
  process.chdir(repositoryPath)

  core.startGroup('Create temporary branch')
  const tempBranchName = uuidv4().replace('-', '')
  await exec.exec('git', ['checkout', '-b', tempBranchName])
  core.endGroup()

  await fs.rm(configDir, {recursive: true, force: true})
  await fs.rm(userConfigDir, {recursive: true, force: true})
  await fs.mkdir(configDir, {recursive: true})
  try {
    core.startGroup('Generating SVN configuration')
      await populateSvnConfig(svnUrl, configDir)
      await fs.symlink(configDir, userConfigDir, 'dir')
      await exec.exec('svn', ['info', svnUrl.toString()])
    core.endGroup()

    core.startGroup('Remove existing branches')
      await exec.exec('git', ['branch', '-D', 'svn/trunk', 'svn/staging'], {
        ignoreReturnCode: true,
      })
    core.endGroup()

    core.startGroup('Create svn branches')
      await exec.exec('git', ['branch', 'svn/staging', 'origin/svn/staging'])
      await exec.exec('git', ['checkout', '-b', 'svn/trunk', 'origin/svn/trunk'])
      await exec.exec('git', ['reset', '--hard'])
      await exec.exec('git', ['clean', '-fddx'])
    core.endGroup()

    core.startGroup('Configure git-svn')
      await exec.exec('git', ['config', '--local', 'svn-remote.svn.url', svnUrl.toString()])
      await exec.exec('git', ['config', '--local', 'svn-remote.svn.fetch', ':refs/remotes/git-svn'])
      await exec.exec('git', ['config', '--local', 'user.email', core.getInput('git-email')])
      await exec.exec('git', ['config', '--local', 'user.name', core.getInput('git-username')])
    core.endGroup()

    core.startGroup('Get most recent SVN commit')
      let svnCommitOutput = ''
      await exec.exec('git', ['log', '-1', 'origin/svn/trunk'], {
        listeners: {
          stdout: (data: Buffer) => {
            svnCommitOutput += data.toString()
          },
        },
      })

      const svnCommitMatch = svnCommitOutput.match(/git-svn-id: [^@]+@([0-9]+)/)
      if (!svnCommitMatch) {
        throw Error('Failed to find git-svn-id in svn/trunk commit')
      }
    core.endGroup()

    const latestSvnRevision = svnCommitMatch[1]
    core.startGroup(`Resetting git-svn to revision ${latestSvnRevision}`)
      await exec.exec('git', ['update-ref', 'refs/remotes/git-svn', 'origin/svn/trunk'])
      await exec.exec('git', ['svn', 'reset', '-r', latestSvnRevision])
    core.endGroup()

    core.startGroup('Fetching upstream SVN changes')
      await exec.exec('git', ['svn', 'fetch'], {
        env: {
          ...process.env,
          SVN_CONIFG_DIR: configDir,
        }
      })

      await exec.exec('git', ['merge', '--ff-only', 'git-svn'])
    core.endGroup()

    core.startGroup('Merge svn/trunk into svn/staging')
      await exec.exec('git', ['checkout', 'svn/staging'])
      const commitMessage = "Merge remote-tracking branch 'origin/svn/trunk' into svn/staging"
      await exec.exec('git', ['merge', '--no-ff', 'svn/trunk', '-m', commitMessage])
    core.endGroup()

    core.startGroup('Push svn branches to Git')
      await exec.exec('git', ['push', 'origin', 'svn/trunk', 'svn/staging'])
    core.endGroup()

  } finally {
    core.startGroup('Delete temporary branch')
      await exec.exec('git', ['branch', '-D', tempBranchName], {
        ignoreReturnCode: true,
      })
    core.endGroup()
  }
}

run()
