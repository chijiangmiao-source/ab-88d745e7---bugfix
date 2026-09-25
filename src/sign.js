'use strict';

// 离线签发辅助：生成 P-256 密钥、按规范 JSON 字节签发委托/命令。
// 生产场景中这些步骤在离线环境完成；此处供测试与 verify 验收服务复现完整链路。

import crypto from 'node:crypto';
import { canonicalize } from './canonical.js';
import { b64urlEncode } from './chain.js';

export function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const pub = publicKey.export({ format: 'jwk' });
  const prv = privateKey.export({ format: 'jwk' });
  return {
    publicJwk: { crv: pub.crv, kty: pub.kty, x: pub.x, y: pub.y },
    privateJwk: { kty: prv.kty, crv: prv.crv, x: prv.x, y: prv.y, d: prv.d },
  };
}

export function rootKeyDocument(publicJwk) {
  // 根公钥文档：值班员粘贴的规范 JSON
  return canonicalize({ crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x, y: publicJwk.y });
}

function signPayload(payload, privateJwk) {
  const key = crypto.createPrivateKey({ key: privateJwk, format: 'jwk' });
  const data = Buffer.from(canonicalize(payload), 'utf8');
  const sig = crypto.sign('sha256', data, { key, dsaEncoding: 'ieee-p1363' });
  return b64urlEncode(sig);
}

// 构造一份委托对象并返回其规范 JSON 文本
export function issueDelegation({ iss, sub, nbf, exp, aud, maxSamples }, privateJwk) {
  const payload = {
    aud: [...aud],
    exp,
    iss: { crv: iss.crv, kty: iss.kty, x: iss.x, y: iss.y },
    maxSamples,
    nbf,
    sub: { crv: sub.crv, kty: sub.kty, x: sub.x, y: sub.y },
    typ: 'delegation',
  };
  const sig = signPayload(payload, privateJwk);
  return canonicalize({ ...payload, sig });
}

// 构造末端命令对象并返回其规范 JSON 文本
export function issueCommand({ iss, sub, nbf, exp, aud, maxSamples, buoy, samples }, privateJwk) {
  const payload = {
    aud: [...aud],
    buoy,
    exp,
    iss: { crv: iss.crv, kty: iss.kty, x: iss.x, y: iss.y },
    maxSamples,
    nbf,
    samples,
    sub: { crv: sub.crv, kty: sub.kty, x: sub.x, y: sub.y },
    typ: 'command',
  };
  const sig = signPayload(payload, privateJwk);
  return canonicalize({ ...payload, sig });
}

// 便捷：生成一条 root -> 中间人 -> 命令 的合法链
export function buildValidChain({ now, buoys = ['buoy-01', 'buoy-02'], maxSamples = 100, samples = 10, buoy } = {}) {
  const t = now ?? Math.floor(Date.now() / 1000);
  const root = generateKeyPair();
  const mid = generateKeyPair();
  const targetBuoy = buoy ?? buoys[0];
  const delegation = issueDelegation({
    iss: root.publicJwk,
    sub: mid.publicJwk,
    nbf: t - 3600,
    exp: t + 3600,
    aud: buoys,
    maxSamples,
  }, root.privateJwk);
  const command = issueCommand({
    iss: mid.publicJwk,
    sub: mid.publicJwk, // 命令的 sub 无下游，自指即可
    nbf: t - 1800,
    exp: t + 1800,
    aud: [targetBuoy],
    maxSamples: Math.min(maxSamples, 50),
    buoy: targetBuoy,
    samples,
  }, mid.privateJwk);
  return {
    root,
    mid,
    rootKeyText: rootKeyDocument(root.publicJwk),
    objectTexts: [delegation, command],
    now: t,
  };
}

// 构造主体回环链：root -> A -> B -> A -> C -> 末端命令（共 5 跳）。
// 默认前三跳：root 授予 A 两个浮标/上限 100；A 向 B 保持同样范围；
// B 向 A 收紧为仅 buoy-01/上限 10。tighten 可覆盖收紧跳参数；
// redelegate 给出 A 再次下放给 C 的约束；terminal 给出末端命令
// （nbf/exp 默认 t-1000/t+1000）。供回环越权场景的测试与验收复现。
export function buildLoopChain({ now, tighten = {}, redelegate, terminal } = {}) {
  const t = now ?? Math.floor(Date.now() / 1000);
  const root = generateKeyPair();
  const a = generateKeyPair();
  const b = generateKeyPair();
  const c = generateKeyPair();
  const wide = {
    nbf: t - 3600, exp: t + 3600,
    aud: ['buoy-01', 'buoy-02'], maxSamples: 100,
  };
  const tight = {
    nbf: t - 3000, exp: t + 3000,
    aud: ['buoy-01'], maxSamples: 10,
    ...tighten,
  };
  const d1 = issueDelegation({ iss: root.publicJwk, sub: a.publicJwk, ...wide }, root.privateJwk);
  const d2 = issueDelegation({ iss: a.publicJwk, sub: b.publicJwk, ...wide }, a.privateJwk);
  const d3 = issueDelegation({ iss: b.publicJwk, sub: a.publicJwk, ...tight }, b.privateJwk);
  const d4 = issueDelegation({ iss: a.publicJwk, sub: c.publicJwk, ...redelegate }, a.privateJwk);
  const term = {
    nbf: t - 1000, exp: t + 1000,
    aud: redelegate.aud, maxSamples: redelegate.maxSamples,
    ...terminal,
  };
  const cmd = issueCommand({ iss: c.publicJwk, sub: c.publicJwk, ...term }, c.privateJwk);
  return {
    root, a, b, c,
    rootKeyText: rootKeyDocument(root.publicJwk),
    objectTexts: [d1, d2, d3, d4, cmd],
    now: t,
  };
}
