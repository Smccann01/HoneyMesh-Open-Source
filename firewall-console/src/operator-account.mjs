import { createCipheriv, createDecipheriv, createHmac, randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, readFile, rename, rm } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCallback);
const SESSION_MS = 30 * 24 * 60 * 60 * 1_000;
const SESSION_RENEW_MS = 7 * 24 * 60 * 60 * 1_000;
const COOKIE = 'hm_operator_session';
const COOKIE_PATTERN = /^v1\.([A-Za-z0-9_-]{100,160})$/;
const SCRYPT_OPTIONS = { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

function safePassword(value) {
  return typeof value === 'string' && value.length >= 16 && value.length <= 128 && !/[\u0000-\u001f\u007f]/.test(value);
}

function safeEqual(a, b) {
  return a.length === b.length && timingSafeEqual(a, b);
}

function seal(key, plain) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString('base64url');
}

function unseal(key, value) {
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length < 29 || bytes.length > 4096) throw new Error('invalid_sealed_value');
  const decipher = createDecipheriv('aes-256-gcm', key, bytes.subarray(0, 12));
  decipher.setAuthTag(bytes.subarray(12, 28));
  return Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]);
}

async function derive(password, salt) {
  return scrypt(password, salt, 32, SCRYPT_OPTIONS);
}

function verifier(key) {
  return createHmac('sha256', key).update('honeymesh-local-operator-v1').digest();
}

function validateAccount(value) {
  if (value?.version !== 1 || value.username !== 'admin' ||
      !/^[a-f0-9]{64}$/.test(value.salt) || !/^[a-f0-9]{64}$/.test(value.verifier) ||
      !/^[a-f0-9]{64}$/.test(value.session_secret) || !/^[a-f0-9]{32}$/.test(value.session_epoch) ||
      (value.agent_token !== null && (typeof value.agent_token !== 'string' || value.agent_token.length > 2048))) {
    throw new Error('invalid_operator_account_file');
  }
  return value;
}

async function privateFile(path) {
  const info = await lstat(path);
  if (!info.isFile() || info.nlink !== 1 || (info.mode & 0o077) !== 0 ||
      (typeof process.getuid === 'function' && info.uid !== process.getuid())) {
    throw new Error('operator account file must be owner-only (0600)');
  }
}

async function atomicWrite(path, value) {
  const temp = join(dirname(path), `.operator-${randomBytes(8).toString('hex')}`);
  const file = await open(temp, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  try {
    await file.writeFile(JSON.stringify(value));
    await file.sync();
  } finally { await file.close(); }
  try { await rename(temp, path); }
  catch (error) { await rm(temp, { force: true }); throw error; }
}

export async function createOperatorAccount(path, now = Date.now) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const directory = await lstat(dirname(path));
  if (!directory.isDirectory() || (directory.mode & 0o077) !== 0 ||
      (typeof process.getuid === 'function' && directory.uid !== process.getuid())) {
    throw new Error('operator directory must be owner-only (0700)');
  }
  let account = null;
  try {
    await privateFile(path);
    account = validateAccount(JSON.parse(await readFile(path, 'utf8')));
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  let writes = Promise.resolve();
  const mutate = (change) => {
    const next = writes.then(change);
    writes = next.catch(() => {});
    return next;
  };

  function issueSession(key) {
    const expiresAt = now() + SESSION_MS;
    const plain = Buffer.alloc(56);
    plain.writeBigUInt64BE(BigInt(expiresAt), 0);
    Buffer.from(account.session_epoch, 'hex').copy(plain, 8);
    key.copy(plain, 24);
    const value = `v1.${seal(Buffer.from(account.session_secret, 'hex'), plain)}`;
    return { cookie: `${COOKIE}=${value}; HttpOnly; SameSite=Strict; Path=/api; Max-Age=${SESSION_MS / 1_000}`,
      expiresAt, key };
  }

  function readSession(cookieHeader) {
    if (!account || typeof cookieHeader !== 'string') return null;
    const raw = cookieHeader.split(';').map((part) => part.trim()).find((part) => part.startsWith(`${COOKIE}=`))?.slice(COOKIE.length + 1);
    const match = COOKIE_PATTERN.exec(raw ?? '');
    if (!match) return null;
    try {
      const plain = unseal(Buffer.from(account.session_secret, 'hex'), match[1]);
      if (plain.length !== 56 || !safeEqual(plain.subarray(8, 24), Buffer.from(account.session_epoch, 'hex'))) return null;
      const expiresAt = Number(plain.readBigUInt64BE(0));
      if (!Number.isSafeInteger(expiresAt) || expiresAt <= now() || expiresAt > now() + SESSION_MS) return null;
      return { username: 'admin', expiresAt, key: plain.subarray(24, 56), epoch: plain.subarray(8, 24) };
    } catch { return null; }
  }

  return {
    configured: () => account !== null,
    clearCookie: () => `${COOKIE}=; HttpOnly; SameSite=Strict; Path=/api; Max-Age=0`,
    async setup(bootstrapValid, username, password) {
      if (account) throw new Error('account_already_configured');
      if (!bootstrapValid || username !== 'admin' || !safePassword(password)) throw new Error('invalid_account_setup');
      const salt = randomBytes(32);
      const key = await derive(password, salt);
      const value = validateAccount({ version: 1, username: 'admin', salt: salt.toString('hex'),
        verifier: verifier(key).toString('hex'), session_secret: randomBytes(32).toString('hex'),
        session_epoch: randomBytes(16).toString('hex'), agent_token: null });
      return mutate(async () => {
        if (account) throw new Error('account_already_configured');
        const file = await open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
        try { await file.writeFile(JSON.stringify(value)); await file.sync(); }
        finally { await file.close(); }
        account = value;
        return issueSession(key);
      });
    },
    async login(username, password) {
      if (!account || username !== 'admin' || typeof password !== 'string') throw new Error('invalid_credentials');
      const key = await derive(password, Buffer.from(account.salt, 'hex'));
      if (!safeEqual(verifier(key), Buffer.from(account.verifier, 'hex'))) throw new Error('invalid_credentials');
      return issueSession(key);
    },
    session: readSession,
    renew(session) {
      return session.expiresAt - now() <= SESSION_RENEW_MS ? issueSession(session.key) : null;
    },
    async logout() {
      if (!account) return;
      await mutate(async () => {
        const next = { ...account, session_epoch: randomBytes(16).toString('hex') };
        await atomicWrite(path, next);
        account = next;
      });
    },
    async changePassword(session, currentPassword, newPassword) {
      if (!account || !session || !safePassword(newPassword) || typeof currentPassword !== 'string') {
        throw new Error('invalid_password_change');
      }
      return mutate(async () => {
        if (!safeEqual(session.epoch, Buffer.from(account.session_epoch, 'hex'))) throw new Error('operator_session_required');
        const currentKey = await derive(currentPassword, Buffer.from(account.salt, 'hex'));
        if (!safeEqual(verifier(currentKey), Buffer.from(account.verifier, 'hex')) || !safeEqual(currentKey, session.key)) {
          throw new Error('invalid_credentials');
        }
        const token = account.agent_token ? unseal(currentKey, account.agent_token) : null;
        const salt = randomBytes(32);
        const nextKey = await derive(newPassword, salt);
        const next = { ...account, salt: salt.toString('hex'), verifier: verifier(nextKey).toString('hex'),
          session_epoch: randomBytes(16).toString('hex'), agent_token: token ? seal(nextKey, token) : null };
        await atomicWrite(path, next);
        account = next;
        return issueSession(nextKey);
      });
    },
    async saveAgentToken(session, token, agentControl) {
      if (!account || !session || !agentControl) throw new Error('operator_session_required');
      await agentControl.authenticate(token);
      await mutate(async () => {
        if (!safeEqual(session.epoch, Buffer.from(account.session_epoch, 'hex'))) throw new Error('operator_session_required');
        const next = { ...account, agent_token: seal(session.key, Buffer.from(token)) };
        await atomicWrite(path, next);
        account = next;
      });
    },
    agentTokenSaved: () => Boolean(account?.agent_token),
    agentToken(session) {
      if (!account?.agent_token || !session) return null;
      try { return unseal(session.key, account.agent_token).toString('utf8'); }
      catch { return null; }
    },
  };
}
