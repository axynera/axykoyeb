const crypto = require('crypto');
const { PassThrough } = require('stream');
const pty = require('node-pty');
const os = require('os');

const sessions = new Map();

function jsonRpcError(id, code, message) {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

function jsonRpcResult(id, result) {
  return { jsonrpc: '2.0', id, result };
}

function createTerminalSession() {
  const id = crypto.randomBytes(16).toString('hex');
  const shell = os.platform() === 'win32' ? 'powershell.exe' : 'bash';
  const ptyProcess = pty.spawn(shell, [], {
    name: 'xterm-color',
    cols: 120,
    rows: 30,
    cwd: process.env.HOME || '/app',
    env: process.env
  });

  const output = [];
  const waiters = [];
  ptyProcess.onData(data => {
    output.push(data);
    while (waiters.length) waiters.shift()(data);
    if (output.length > 200) output.shift();
  });
  ptyProcess.onExit(() => sessions.delete(id));

  const session = { id, ptyProcess, output, waiters, createdAt: Date.now() };
  sessions.set(id, session);
  return session;
}

function getSession(id) {
  return sessions.get(id);
}

function textResult(text) {
  return { content: [{ type: 'text', text }] };
}

async function callTool(name, args = {}) {
  if (name === 'terminal_create') {
    const session = createTerminalSession();
    return textResult(JSON.stringify({ session_id: session.id, message: 'Terminal session created' }));
  }

  if (name === 'terminal_write') {
    const session = getSession(args.session_id);
    if (!session) throw new Error('Unknown terminal session');
    if (typeof args.input !== 'string') throw new Error('input must be a string');
    session.ptyProcess.write(args.input);
    return textResult(JSON.stringify({ session_id: session.id, written: args.input.length }));
  }

  if (name === 'terminal_read') {
    const session = getSession(args.session_id);
    if (!session) throw new Error('Unknown terminal session');
    const maxChars = Math.min(Math.max(Number(args.max_chars) || 12000, 1), 30000);
    return textResult(session.output.join('').slice(-maxChars));
  }

  if (name === 'terminal_resize') {
    const session = getSession(args.session_id);
    if (!session) throw new Error('Unknown terminal session');
    const cols = Math.min(Math.max(Number(args.cols) || 120, 20), 300);
    const rows = Math.min(Math.max(Number(args.rows) || 30, 5), 100);
    session.ptyProcess.resize(cols, rows);
    return textResult(JSON.stringify({ session_id: session.id, cols, rows }));
  }

  if (name === 'terminal_close') {
    const session = getSession(args.session_id);
    if (!session) throw new Error('Unknown terminal session');
    session.ptyProcess.kill();
    sessions.delete(session.id);
    return textResult(JSON.stringify({ session_id: session.id, closed: true }));
  }

  throw new Error(`Unknown tool: ${name}`);
}

const TOOLS = [
  { name: 'terminal_create', description: 'Create an isolated shell terminal session.', inputSchema: { type: 'object', properties: {}, additionalProperties: false } },
  { name: 'terminal_write', description: 'Write input to an existing terminal session. Include a newline to execute a shell command.', inputSchema: { type: 'object', properties: { session_id: { type: 'string' }, input: { type: 'string' } }, required: ['session_id', 'input'], additionalProperties: false } },
  { name: 'terminal_read', description: 'Read recent output from a terminal session.', inputSchema: { type: 'object', properties: { session_id: { type: 'string' }, max_chars: { type: 'integer', minimum: 1, maximum: 30000 } }, required: ['session_id'], additionalProperties: false } },
  { name: 'terminal_resize', description: 'Resize a terminal session.', inputSchema: { type: 'object', properties: { session_id: { type: 'string' }, cols: { type: 'integer' }, rows: { type: 'integer' } }, required: ['session_id'], additionalProperties: false } },
  { name: 'terminal_close', description: 'Close a terminal session.', inputSchema: { type: 'object', properties: { session_id: { type: 'string' } }, required: ['session_id'], additionalProperties: false } }
];

async function handleMessage(message) {
  const { id, method, params = {} } = message;
  if (method === 'initialize') {
    return jsonRpcResult(id, {
      protocolVersion: params.protocolVersion || '2025-06-18',
      capabilities: { tools: {} },
      serverInfo: { name: 'koyeb-web-terminal', version: '1.0.0' }
    });
  }
  if (method === 'notifications/initialized') return null;
  if (method === 'ping') return jsonRpcResult(id, {});
  if (method === 'tools/list') return jsonRpcResult(id, { tools: TOOLS });
  if (method === 'tools/call') {
    try { return jsonRpcResult(id, await callTool(params.name, params.arguments || {})); }
    catch (err) { return jsonRpcError(id, -32000, err.message); }
  }
  return jsonRpcError(id, -32601, `Method not found: ${method}`);
}

function attachSse(req, res) {
  const sessionId = crypto.randomBytes(16).toString('hex');
  res.status(200);
  res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
  res.flushHeaders();
  res.write(`event: endpoint\ndata: /mcp/message?sessionId=${sessionId}\n\n`);
  req.app.locals.mcpSseSessions = req.app.locals.mcpSseSessions || new Map();
  req.app.locals.mcpSseSessions.set(sessionId, res);
  const cleanup = () => req.app.locals.mcpSseSessions.delete(sessionId);
  req.on('close', cleanup);
  return sessionId;
}

function createMcpRouter() {
  const express = require('express');
  const router = express.Router();

  router.get('/sse', (req, res) => attachSse(req, res));

  router.post('/message', express.json(), async (req, res) => {
    const sessionId = req.query.sessionId;
    const sse = req.app.locals.mcpSseSessions && req.app.locals.mcpSseSessions.get(sessionId);
    if (!sse) return res.status(404).json({ error: 'MCP session not found' });
    const result = await handleMessage(req.body);
    if (result) sse.write(`data: ${JSON.stringify(result)}\n\n`);
    res.status(202).end();
  });

  return router;
}

module.exports = { createMcpRouter, handleMessage, TOOLS };