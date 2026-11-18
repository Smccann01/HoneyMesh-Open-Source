import { randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, readFile, rename, rm } from 'node:fs/promises';
import { dirname, join } from 'node:path';

const MONTH_MS = 30 * 24 * 60 * 60 * 1_000;
const token = () => randomBytes(32).toString('hex');

async function writePrivate(path, values, exclusive = false) {
  const temporary = exclusive ? path : join(dirname(path), `.credentials-${randomBytes(8).toString('hex')}`);
  const file = await open(temporary, constants.O_CREAT | constants.O_EXCL |
    constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  try {
    await file.writeFile(JSON.stringify(values));
    await file.sync();
  } finally { await file.close(); }
  if (!exclusive) {
    try { await rename(temporary, path); }
    catch (error) { await rm(temporary, { force: true }); throw error; }
  }
}

export async function loadLocalCredentials(path, now = Date.now) {
  const directory = dirname(path);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const dirInfo = await lstat(directory);
  if (!dirInfo.isDirectory() || (dirInfo.mode & 0o077) !== 0) {
    throw new Error('credential directory must be owner-only (0700)');
  }
  try {
    await writePrivate(path, {
      adminToken: token(), webhookSecret: token(),
      adminTokenExpiresAt: new Date(now() + MONTH_MS).toISOString(),
    }, true);
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
  }
  const info = await lstat(path);
  if (!info.isFile() || (info.mode & 0o077) !== 0) {
    throw new Error('credentials file must be owner-only (0600)');
  }
  const values = JSON.parse(await readFile(path, 'utf8'));
  if (!/^[a-f0-9]{64}$/.test(values.adminToken) ||
      !/^[a-f0-9]{64}$/.test(values.webhookSecret)) {
    throw new Error('invalid local credentials file');
  }
  const expiry = Date.parse(values.adminTokenExpiresAt);
  if (!Number.isFinite(expiry) || expiry <= now()) {
    const updated = {
      adminToken: Number.isFinite(expiry) ? token() : values.adminToken,
      webhookSecret: values.webhookSecret,
      adminTokenExpiresAt: new Date(now() + MONTH_MS).toISOString(),
    };
    await writePrivate(path, updated);
    return updated;
  }
  return values;
}
