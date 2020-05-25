'use strict';

const fs = require('fs');
const assert = require('assert');
const crypto = require('crypto');

const pemPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQCRlCB0cYeHDTNB/EcCDVCiSbeCFSTnr4j2YO6IwYntTz8a35Y3
56qEBDgk2Vbm751zZlzYuf/tKSugBvuBZKYE34HkHHLunlt33dIUVSIGtkBFkazD
R1niEw68GUPd3YScmWnHNUx/Us/0m6HWt0sv4giwRx2b1klQnAYiG4iC1wIDAQAB
AoGAEjXbUXWaJHSsQsbSAxmzSnm6MNWARlMY6Oj7LbQ4Eq1lEXGCkv+xvs3gUAu3
6S90HKljV+D8eKg7wsrczzTN54EMcZi+9f79N6yRklwyhRGg1n+NjkrTu+kts0AE
bJN9RdHv1aQCNeYU3YXVtNITEOT1YKWhMqzycFUE3IDTkbECQQDnlNURBFEIoSc9
x2I8TuLyRH2c8rDPiz2IBUl4adY6yJf6CuacCyPG5TceVZFNXcfe1xinACopyYZr
32lXTeU1AkEAoO3JvuiAy4aFB+1AMAe/xYw7295M6ckPr6Wx5z9v3+HDEfwmfWfF
FcrGpfrPcczWXk5VZHnd5wvlr1VT2aYFWwJBANPKKZIGgJWDzH+TeSPugV9PhBGl
Yk5s6TkcnLSjFmlsSpFCpuTOy0l7F42Gc/xtZ/1EeidA306YH3dIOu69LoECQQCS
2ouY8BjgIWBybFl/uwKQZjkVmhW73aO32M+ww932gtF9Lwl8tN5P1ZxTSL5XDeKt
anRYXTFXLy8pQgdjfTIzAkEAhgrfGkm3CtTupZ6XyactX3ipTndwiuqGHXkYp0rN
LgmFvxfpk/boXSDzIToeDh7Olh++NnoFTAPF2KmmFzZ3+w==
-----END RSA PRIVATE KEY-----
`;

const privateKey = crypto.createPrivateKey(pemPrivateKey);

function sign(data) {
  assert(data);
  const singer = crypto.createSign('RSA-SHA256');
  singer.update(data);
  return singer.sign(privateKey);
}

function createToken(options) {
  assert(options.type);

  const tokenssoxmlbuffer = fs.readFileSync('./resources/sso.internal.test.xml');
  var tokenssoxml = tokenssoxmlbuffer.toString();

  tokenssoxml = tokenssoxml.replace(/{{SERVICE}}/g, options.service || 'unknow-service');
  tokenssoxml = tokenssoxml.replace(/{{UID}}/g, options.uid || '20000000028');
  tokenssoxml = tokenssoxml.replace('{{EXP_TIME}}', options.expirationTime || Math.ceil((new Date()).getTime() / 1000));

  const tokenssoxmlbase64 = Buffer.from(tokenssoxml).toString('base64');
  expect.anything(tokenssoxmlbase64);

  const signature = sign(tokenssoxml);
  const signbase64 = signature.toString('base64');
  expect.anything(signbase64);

  return { token: tokenssoxmlbase64, sign: signbase64 };
}

const publicKey = crypto.createPublicKey(pemPrivateKey).export({type: 'pkcs1', format: 'pem'});

module.exports = { createToken, sign, publicKey };
