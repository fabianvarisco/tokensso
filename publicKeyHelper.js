
'use strict';

require('dotenv').config();
const assert = require('assert');
const fs = require('fs');
const pki = require('node-forge').pki;
const crypto = require('crypto');

function fromEnv() {
  const name = process.env.AUTH_NAME;
  const file = process.env.AUTH_CERT;

  assert(name, 'env var AUTH_CERT must be configured');
  assert(file, 'env var AUTH_NAME must be configured');

  console.log('env AUTH_NAME:', name);
  console.log('env AUTH_CERT:', file);

  var pem;
  try {
    pem = fs.readFileSync(file);
    assert(pem);
  } catch (pem) {
    throw Error(`file [${file}] (from env var AUTH_CERT) not found`);
  }

  var cn;
  try {
    const cert = pki.certificateFromPem(pem);
    cn = cert.subject.getField('CN').value;
    console.log('Auth Cert SN:', cert.serialNumber);
    console.log('Auth Cert CN:', cn);
    console.log('Auth Cert validity.notAfter:', cert.validity.notAfter);
  } catch (err) {
    console.error(err);
    throw Error(`error reading [${file}] (from env var AUTH_CERT) - ${err}`);
  }
  assert.equal(name, cn,
    `env var AUTH_NAME [${name}] mismatchs cert.subject.CN [${cn}] from env var AUTH_CERT [${file}]`);

  const publicKey = crypto.createPublicKey(pem);
  assert(publicKey, `empty key from env var AUTH_CERT [${file}]`);

  return publicKey;
}

module.exports = { fromEnv };
