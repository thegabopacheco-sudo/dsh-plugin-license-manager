// Test end-to-end de license-manager (local, HMAC).
import path from 'node:path';
import { mkdirSync, rmSync } from 'node:fs';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

const packageDir = path.resolve(import.meta.dirname, '..');
const tmpDir = path.join(packageDir, 'test', 'tmp');
rmSync(tmpDir, { recursive: true, force: true });
mkdirSync(path.join(tmpDir, 'dsh-home'), { recursive: true });

function makeClient(extraEnv = {}) {
  const entry = process.env.LICENSE_SERVER ? path.resolve(process.env.LICENSE_SERVER) : path.join(packageDir, 'server.mjs');
  const transport = new StdioClientTransport({ command: process.execPath, args: [entry], env: { SystemRoot: process.env.SystemRoot || 'C:\\Windows', PATH: process.env.PATH, USERPROFILE: process.env.USERPROFILE, HOME: process.env.HOME || process.env.USERPROFILE, TEMP: process.env.TEMP, TMP: process.env.TMP, DSH_HOME: path.join(tmpDir, 'dsh-home'), ...extraEnv }, stderr: 'pipe' });
  transport.stderr?.on('data', (c) => process.stderr.write(`[server] ${c}`));
  const client = new Client({ name: 'licenses-test', version: '1.0.0' }, { capabilities: {}, versionNegotiation: { mode: 'auto' } });
  return client.connect(transport).then(() => ({ client, transport }));
}
const textOf = (r) => (r.content || []).filter((b) => b.type === 'text').map((b) => b.text).join('\n');

const { client, transport } = await makeClient();
console.log('tools:', (await client.listTools()).tools.map((t) => t.name).join(', '));
console.log('--- status ---'); console.log(textOf(await client.callTool({ name: 'status', arguments: {} })));
const noConfirm = await client.callTool({ name: 'generate', arguments: { customer: 'Gabriel', product: 'Bot Tickets' } });
console.log('generate sin confirm isError:', noConfirm.isError === true);
const gen = await client.callTool({ name: 'generate', arguments: { customer: 'Gabriel', product: 'Bot Tickets', plan: 'pro', days: 30, features: ['tickets', 'logs'], confirm: true } });
console.log('--- generate ---'); console.log(textOf(gen));
const key = (textOf(gen).match(/WEND-[A-Za-z0-9_-]+-[A-Za-z0-9_-]+/) || [])[0];
const id = (textOf(gen).match(/ID: ([a-f0-9]+)/) || [])[1];
const verify = await client.callTool({ name: 'verify', arguments: { key } });
console.log('--- verify ---'); console.log(textOf(verify));
console.log('válida:', textOf(verify).includes('✅'));
const tampered = key.slice(0, -4) + (key.endsWith('aaaa') ? 'bbbb' : 'aaaa');
const verifyBad = await client.callTool({ name: 'verify', arguments: { key: tampered } });
console.log('firma alterada inválida:', textOf(verifyBad).includes('❌'));
console.log('--- list ---'); console.log(textOf(await client.callTool({ name: 'list', arguments: {} })));
const revoke = await client.callTool({ name: 'revoke', arguments: { id, confirm: true } });
console.log('--- revoke ---'); console.log(textOf(revoke));
const verifyRevoked = await client.callTool({ name: 'verify', arguments: { key } });
console.log('revocada detectada:', textOf(verifyRevoked).includes('revocada'));
await client.close(); try { await transport.close?.(); } catch {}
const { client: roClient, transport: roTransport } = await makeClient({ DSH_LICENSE_MODE: 'read-only' });
const roGen = await roClient.callTool({ name: 'generate', arguments: { customer: 'x', product: 'y', confirm: true } });
console.log('read-only generate isError:', roGen.isError === true);
await roClient.close(); try { await roTransport.close?.(); } catch {}
console.log('OK');
