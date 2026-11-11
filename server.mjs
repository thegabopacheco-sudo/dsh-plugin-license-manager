#!/usr/bin/env node
// dsh-plugin-license-manager — licencias HMAC locales para apps/bots de WENDIGO.
// Tools: status, generate, verify, list, revoke.

import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync } from 'node:fs';
import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod';

const VERSION = '0.1.0';
const DSH_HOME = (() => {
  const v = process.env.DSH_HOME && process.env.DSH_HOME.trim();
  return v || path.join(process.env.USERPROFILE || process.env.HOME || os.homedir(), '.dsh');
})();
const CONFIG_FILE = path.join(DSH_HOME, 'license-manager', 'config.json');
const DATA_FILE = path.join(DSH_HOME, 'license-manager', 'licenses.json');
const AUDIT_FILE = path.join(DSH_HOME, 'cache', 'license-manager', 'audit.jsonl');
const READ_ONLY = String(process.env.DSH_LICENSE_MODE || '').toLowerCase() === 'read-only';
const PREFIX = 'WEND';
const log = (m) => process.stderr.write(`[licenses] ${m}\n`);

function loadConfig() {
  let config = {};
  try { if (existsSync(CONFIG_FILE)) config = JSON.parse(readFileSync(CONFIG_FILE, 'utf8')) || {}; } catch (e) { log(`config: ${e.message}`); }
  if (!config.secret) {
    config.secret = crypto.randomBytes(32).toString('hex');
    saveConfig(config);
  }
  return config;
}
function saveConfig(config) { mkdirSync(path.dirname(CONFIG_FILE), { recursive: true }); writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2) + '\n', 'utf8'); }
function loadData() {
  try { if (existsSync(DATA_FILE)) { const d = JSON.parse(readFileSync(DATA_FILE, 'utf8')) || {}; return { licenses: Array.isArray(d.licenses) ? d.licenses : [] }; } } catch (e) { log(`datos: ${e.message}`); }
  return { licenses: [] };
}
function saveData(data) { mkdirSync(path.dirname(DATA_FILE), { recursive: true }); writeFileSync(DATA_FILE, JSON.stringify(data, null, 2) + '\n', 'utf8'); }
function audit(entry) { try { mkdirSync(path.dirname(AUDIT_FILE), { recursive: true }); appendFileSync(AUDIT_FILE, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n'); } catch { /* best effort */ } }

function b64url(buffer) { return Buffer.from(buffer).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function unb64url(value) { return Buffer.from(String(value).replace(/-/g, '+').replace(/_/g, '/'), 'base64'); }

function sign(secret, payloadB64) { return b64url(crypto.createHmac('sha256', secret).update(payloadB64).digest()); }
function makeKey(secret, payload) {
  const payloadB64 = b64url(JSON.stringify(payload));
  return `${PREFIX}-${payloadB64}-${sign(secret, payloadB64)}`;
}
function parseKey(secret, key) {
  const parts = String(key || '').trim().split('-');
  if (parts.length !== 3 || parts[0] !== PREFIX) return { valid: false, error: 'formato inválido' };
  const [, payloadB64, signature] = parts;
  const expected = sign(secret, payloadB64);
  if (signature.length !== expected.length) return { valid: false, error: 'firma inválida' };
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return { valid: false, error: 'firma inválida' };
  let payload;
  try { payload = JSON.parse(unb64url(payloadB64).toString('utf8')); } catch { return { valid: false, error: 'payload corrupto' }; }
  const record = loadData().licenses.find((l) => l.id === payload.id);
  if (record?.revoked) return { valid: false, error: 'licencia revocada', payload };
  if (payload.expiresAt && Date.now() > Date.parse(payload.expiresAt)) return { valid: false, error: 'licencia vencida', payload };
  return { valid: true, payload };
}

function textResult(t) { return { content: [{ type: 'text', text: t }] }; }
function mask(key) { return `${key.slice(0, 12)}…${key.slice(-6)}`; }

function buildInstructions() {
  return [
    'License Manager: genera y verifica licencias HMAC locales para apps y bots de WENDIGO.',
    '',
    'Herramientas: status, generate, verify, list, revoke.',
    '',
    'Reglas:',
    '- generate/revoke requieren confirm:true y pedido explícito.',
    '- La clave secreta vive en config y NUNCA se muestra ni se registra.',
    '- verify es local y sin red; reporta vencida/revocada con honestidad.',
    '- No inventes licencias: toda clave emitida queda registrada.',
  ].join('\n');
}

function buildServer() {
  const server = new McpServer({ name: 'dsh-plugin-license-manager', version: VERSION }, { capabilities: { tools: {} }, instructions: buildInstructions() });

  server.registerTool(
    'status',
    { title: 'Estado', description: 'Secret configurado (sin mostrarlo), licencias emitidas y ruta de datos.', inputSchema: z.object({}) },
    async () => {
      const data = loadData();
      const active = data.licenses.filter((l) => !l.revoked).length;
      return textResult([`Modo: ${READ_ONLY ? 'read-only' : 'normal'}`, `Config: ${CONFIG_FILE}`, `Licencias: ${data.licenses.length} (activas ${active})`, `Datos: ${DATA_FILE}`].join('\n'));
    },
  );

  server.registerTool(
    'generate',
    {
      title: 'Generar licencia',
      description: 'Emite una licencia firmada para un cliente/producto. Requiere confirm:true.',
      inputSchema: z.object({
        customer: z.string().min(1).max(120),
        product: z.string().min(1).max(120),
        plan: z.enum(['basic', 'pro', 'lifetime']).optional(),
        days: z.number().int().min(0).max(3650).optional().describe('Días de validez (0 = vence hoy; omitido = sin vencimiento).'),
        features: z.array(z.string()).max(20).optional(),
        confirm: z.boolean().optional(),
      }),
    },
    async (args) => {
      if (READ_ONLY) throw new Error('modo read-only: generate deshabilitado');
      if (args.confirm !== true) throw new Error('generate requiere confirm:true y confirmación explícita');
      const config = loadConfig();
      const id = crypto.randomBytes(6).toString('hex');
      const issuedAt = new Date().toISOString();
      const expiresAt = args.days === undefined ? null : new Date(Date.now() + args.days * 86400_000).toISOString();
      const payload = { id, customer: args.customer, product: args.product, plan: args.plan || 'basic', issuedAt, expiresAt, features: args.features || [] };
      const key = makeKey(config.secret, payload);
      const data = loadData();
      data.licenses.push({ id, key: mask(key), customer: payload.customer, product: payload.product, plan: payload.plan, issuedAt, expiresAt, revoked: false });
      saveData(data);
      audit({ tool: 'generate', id, product: payload.product, ok: true });
      return textResult([`Licencia generada para ${payload.customer} · ${payload.product} (${payload.plan})`, `ID: ${id}`, `Vence: ${expiresAt || 'sin vencimiento'}`, '', key].join('\n'));
    },
  );

  server.registerTool(
    'verify',
    {
      title: 'Verificar licencia',
      description: 'Valida la firma, el vencimiento y la revocación de una licencia.',
      inputSchema: z.object({ key: z.string().min(10) }),
    },
    async (args) => {
      const config = loadConfig();
      const result = parseKey(config.secret, args.key);
      if (!result.valid) return textResult(`❌ Licencia inválida: ${result.error}${result.payload ? ` (id ${result.payload.id})` : ''}`);
      const p = result.payload;
      return textResult([`✅ Licencia válida`, `ID: ${p.id}`, `Cliente: ${p.customer}`, `Producto: ${p.product} (${p.plan})`, `Emitida: ${p.issuedAt}`, `Vence: ${p.expiresAt || 'sin vencimiento'}`, `Features: ${(p.features || []).join(', ') || 'ninguna'}`].join('\n'));
    },
  );

  server.registerTool(
    'list',
    { title: 'Listar licencias', description: 'Lista licencias emitidas (clave enmascarada).', inputSchema: z.object({ limit: z.number().int().min(1).max(200).optional() }) },
    async (args) => {
      const data = loadData();
      const licenses = data.licenses.slice(-(args.limit ?? 50));
      if (licenses.length === 0) return textResult('Sin licencias emitidas.');
      return textResult(licenses.map((l) => `${l.revoked ? '⛔' : '✅'} ${l.id} · ${l.customer} · ${l.product} (${l.plan}) · ${l.expiresAt ? `vence ${l.expiresAt}` : 'sin vencimiento'} · ${l.key}`).join('\n'));
    },
  );

  server.registerTool(
    'revoke',
    { title: 'Revocar licencia', description: 'Marca una licencia como revocada localmente. Requiere confirm:true.', inputSchema: z.object({ id: z.string().min(1), confirm: z.boolean().optional() }) },
    async (args) => {
      if (READ_ONLY) throw new Error('modo read-only: revoke deshabilitado');
      if (args.confirm !== true) throw new Error('revoke requiere confirm:true');
      const data = loadData();
      const license = data.licenses.find((l) => l.id === args.id);
      if (!license) throw new Error(`licencia no encontrada: ${args.id}`);
      license.revoked = true;
      saveData(data);
      audit({ tool: 'revoke', id: args.id, ok: true });
      return textResult(`Licencia ${args.id} revocada.`);
    },
  );

  return server;
}

try {
  loadConfig();
  if (!existsSync(DATA_FILE)) saveData({ licenses: [] });
} catch (e) { log(`init: ${e.message}`); }
log(`modo ${READ_ONLY ? 'read-only' : 'normal'} · datos: ${DATA_FILE}`);
serveStdio(buildServer, { onerror: (e) => log(`serveStdio: ${e.message}`) });
process.on('uncaughtException', (e) => log(`excepción: ${e.message}`));
process.on('unhandledRejection', (e) => log(`rechazo: ${e && e.message ? e.message : String(e)}`));
