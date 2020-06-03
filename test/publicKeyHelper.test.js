
'use strict';

require('dotenv').config();
const pkh = require('../publicKeyHelper.js');

test('fromEnv', () => {
  const publicKey = pkh.fromEnv();
  expect.anything(publicKey);
  expect(publicKey.asymmetricKeyType).toBe('rsa');
});

test('fromEnv invalid AUTH_NAME', () => {
  expect(() => {
    process.env.AUTH_NAME = 'pepito.com.ar';
    pkh.fromEnv();
  }).toThrowError();
});
