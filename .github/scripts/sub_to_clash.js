#!/usr/bin/env node
// 把机场的「通用订阅」（base64 编码的节点 URI 列表）转成 mihomo 的代理列表。
//
// 为什么不直接用机场给的 clash 订阅：拿 clash 类 UA 去请求，回来的 proxies 全是占位货
//（名字写着「不支持您的代理软件」，server 是 127.0.0.1:6666），一个真节点都没有；
// 换成 mihomo / Shadowrocket 的 UA，回来的才是 base64 的真实节点。所以这里自己转。
//
// 用法：node sub_to_clash.js <订阅文件> > clash-subscription.yaml
// 只输出 proxies 段 —— 端口、规则那些由服务器上的 config.yaml 定死，不接受订阅里带的。

const fs = require('fs');

const file = process.argv[2];
if (!file) {
  console.error('用法: node sub_to_clash.js <订阅文件>');
  process.exit(1);
}

const raw = fs.readFileSync(file, 'utf8').trim();
// 通用订阅正常是 base64；万一机场直接给纯文本，也认。
const text = /^[A-Za-z0-9+/=\r\n]+$/.test(raw) ? Buffer.from(raw, 'base64').toString('utf8') : raw;

const uris = text
  .split(/\r?\n/)
  .map((l) => l.trim())
  .filter(Boolean);

const proxies = [];
const skipped = new Map();

for (const uri of uris) {
  const p = parseNode(uri);
  if (p) proxies.push(p);
  else {
    const scheme = (uri.split('://')[0] || '?').toLowerCase();
    skipped.set(scheme, (skipped.get(scheme) || 0) + 1);
  }
}

if (!proxies.length) {
  console.error('一个节点都没转出来，订阅格式可能变了');
  process.exit(2);
}

process.stdout.write('proxies:\n' + emit(proxies, 2) + '\n');
console.error(`转换完成：${proxies.length} 个节点` + (skipped.size ? `，跳过 ${[...skipped].map(([k, v]) => `${k}x${v}`).join(' ')}` : ''));

// ---------------------------------------------------------------- 解析

function parseNode(uri) {
  const m = /^([A-Za-z0-9]+):\/\/(.*)$/.exec(uri);
  if (!m) return null;
  const scheme = m[1].toLowerCase();
  let rest = m[2];

  // 尾部的 #名字 是节点名
  let name = '';
  const hash = rest.indexOf('#');
  if (hash >= 0) {
    name = safeDecode(rest.slice(hash + 1));
    rest = rest.slice(0, hash);
  }
  const qIdx = rest.indexOf('?');
  const q = new URLSearchParams(qIdx >= 0 ? rest.slice(qIdx + 1) : '');
  let head = qIdx >= 0 ? rest.slice(0, qIdx) : rest;
  // 有的客户端会在 URL 里带 /path，vless 的 ws path 不走这儿，去掉免得出乱子
  head = head.replace(/\/+$/, '');

  const at = head.lastIndexOf('@');
  if (at < 0) return null;
  const user = safeDecode(head.slice(0, at));
  const hp = splitHostPort(head.slice(at + 1));
  if (!hp) return null;
  const { host, port } = hp;
  const fp = q.get('fp') || '';

  if (scheme === 'vless') {
    const node = {
      name: name || `${host}:${port}`,
      type: 'vless',
      server: host,
      port,
      uuid: user,
      udp: true,
    };
    const net = q.get('type') || 'tcp';
    node.network = net === 'ws' ? 'ws' : net === 'grpc' ? 'grpc' : 'tcp';
    const security = (q.get('security') || '').toLowerCase();
    if (security === 'tls' || security === 'reality') node.tls = true;
    const sni = q.get('sni') || q.get('host') || '';
    if (sni) node.servername = sni;
    if (fp) node['client-fingerprint'] = fp;
    if (q.get('insecure') === '1' || /^true$/i.test(q.get('insecure') || '')) node['skip-cert-verify'] = true;
    if (q.get('flow')) node.flow = q.get('flow');
    if (node.network === 'ws') {
      const path = q.get('path') || '/';
      const hostHeader = q.get('host') || '';
      node['ws-opts'] = { path };
      if (hostHeader) node['ws-opts'].headers = { Host: hostHeader };
    }
    if (node.network === 'grpc') {
      node['grpc-opts'] = { 'grpc-service-name': q.get('serviceName') || '' };
    }
    if (security === 'reality') {
      node['reality-opts'] = {};
      if (q.get('pbk')) node['reality-opts']['public-key'] = q.get('pbk');
      if (q.get('sid')) node['reality-opts']['short-id'] = q.get('sid');
    }
    return node;
  }

  if (scheme === 'hysteria2' || scheme === 'hy2') {
    const node = {
      name: name || `${host}:${port}`,
      type: 'hysteria2',
      server: host,
      port,
      password: user,
    };
    if (q.get('sni')) node.sni = q.get('sni');
    if (q.get('insecure') === '1' || /^true$/i.test(q.get('insecure') || '')) node['skip-cert-verify'] = true;
    // 机场把端口范围写在 mport（有时候拼成 mpord）里，对应 mihomo 的 ports
    const range = q.get('mport') || q.get('mpord') || q.get('ports');
    if (range) node.ports = range;
    const pin = q.get('pinSHA256');
    if (pin) node.fingerprint = pin;
    if (q.get('obfs')) {
      node.obfs = q.get('obfs');
      if (q.get('obfs-password')) node['obfs-password'] = q.get('obfs-password');
    }
    return node;
  }

  return null;
}

function splitHostPort(s) {
  if (s.startsWith('[')) {
    const end = s.indexOf(']');
    if (end < 0) return null;
    const host = s.slice(1, end);
    const port = Number(s.slice(end + 2));
    return port ? { host, port } : null;
  }
  const i = s.lastIndexOf(':');
  if (i <= 0) return null;
  const host = s.slice(0, i);
  const port = Number(s.slice(i + 1));
  return host && port ? { host, port } : null;
}

function safeDecode(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

// ---------------------------------------------------------------- 输出

function emit(v, indent) {
  const pad = ' '.repeat(indent);
  if (Array.isArray(v)) {
    return v
      .map((item) => {
        if (item && typeof item === 'object') {
          // `- ` 后面接第一行，剩下的缩进对齐
          const body = emit(item, indent + 2).replace(/^\s+/, '');
          return `${pad}- ${body}`;
        }
        return `${pad}- ${scalar(item)}`;
      })
      .join('\n');
  }
  if (v && typeof v === 'object') {
    return Object.entries(v)
      .map(([k, val]) => {
        if (val && typeof val === 'object') return `${pad}${k}:\n${emit(val, indent + 2)}`;
        return `${pad}${k}: ${scalar(val)}`;
      })
      .join('\n');
  }
  return `${pad}${scalar(v)}`;
}

function scalar(v) {
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  const s = String(v);
  if (s === '') return '""';
  if (/^[A-Za-z0-9._/-]+$/.test(s)) return s;
  return JSON.stringify(s);
}
