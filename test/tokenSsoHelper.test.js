'use strict';

require('dotenv').config();
const tsh = require('../tokenSsoHelper.js');
const auth = require('./auth.mock.js');

const SERVICE_NAME = process.env.SERVICE_NAME;
const TOKEN_SSO_TYPE = process.env.TOKEN_SSO_TYPE;

const uid = 20000000028;

test('validate', () => {
  expect.anything(SERVICE_NAME);
  expect.anything(TOKEN_SSO_TYPE);

  const result = auth.createToken({type: TOKEN_SSO_TYPE, service: SERVICE_NAME, uid});
  expect.anything(result.token);
  expect.anything(result.sign);

  const tokensso = tsh.validate(result.token,
    {
      type: TOKEN_SSO_TYPE,
      service: SERVICE_NAME,
      sign: result.sign,
      publicKey: auth.publicKey,
    });
  console.log('tokensso:', tokensso);

  expect(tokensso.service).toBe(SERVICE_NAME);
  expect(tokensso.cuil).toBe(uid);
  expect.anything(tokensso.codigoLegajo);
});

test('throw errors expired', () => {
  expect(() => {
    const oneDay = 1000 * 60 * 60 * 24; // number of milliseconds in a day
    const expirationTime = Math.ceil((new Date()).getTime() / 1000) - oneDay;

    const result = auth.createToken({type: TOKEN_SSO_TYPE, service: SERVICE_NAME, uid, expirationTime});

    tsh.validate(result.token,
      {
        type: TOKEN_SSO_TYPE,
        service: SERVICE_NAME,
        sign: result.sign,
        publicKey: auth.publicKey,
      });
  }).toThrowError(/^token expired/);
});

test('throw errors service name', () => {
  expect(() => {
    const result = auth.createToken({type: TOKEN_SSO_TYPE, service: SERVICE_NAME});
    tsh.validate(result.token,
      {
        type: TOKEN_SSO_TYPE,
        service: 'pepito',
        sign: result.sign,
        publicKey: auth.publicKey,
      });
  }).toThrowError(/pepito/);
});
