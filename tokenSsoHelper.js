'use strict';

const assert = require('assert');
const XmlDocument = require('xmldoc').XmlDocument;
const verify = require('./verify.js');

const TOKEN_SSO_TYPE_INTERNAL = 'internal';
const TOKEN_SSO_TYPE_EXTERNAL = 'external';

const CUIT_AFIP = 33693450239; // AFIP

function validateExpiration(expirationTime, toleranceInSeconds) {
  assert.ok(expirationTime);
  const tolerance = (toleranceInSeconds || 0) * 1000;
  const notAfter = expirationTime + tolerance;
  const now = Math.ceil((new Date()).getTime() / 1000);
  const diff = now - notAfter;
  if (diff > 1) {
    const message = `token expired: [${diff}] seconds, now [${now}], token.expirationTime [${expirationTime}], env.toleranceInSeconds [${toleranceInSeconds}]`;
    console.error(message);
    throw Error(message);
  }
}

function validateCuil(cuil) {
  return;
}

function validate(token, options) {
  assert(token);
  assert(options.type);
  assert(options.service);

  const tokensso = parse(token, options.type);

  assert(tokensso);
  assert.equal(tokensso.entity, CUIT_AFIP);
  assert.equal(tokensso.service, options.service,
    `token to access [${tokensso.service}] but this service is [${options.service}]`);
  validateCuil(tokensso.cuil);

  if (options.sign) {
    assert(options.publicKey);
    const tokenraw = Buffer.from(token, 'base64').toString();
    const signbuffer = Buffer.from(options.sign, 'base64');
    if (!verify.verify(options.publicKey, tokenraw, signbuffer)) {
      const message = 'unverified signature';
      console.error(message);
      throw Error(message);
    }
  }
  validateExpiration(tokensso.expirationTime, options.toleranceInSeconds);

  return tokensso;
}

/**
 * Parse a token (internal or external)
 * @param token {string} Base 64 token
 * @param type {string} Token type (internal, external)
 */
function parse(token, type) {
  const xml = Buffer.from(token, 'base64').toString();

  var document;
  try {
    document = new XmlDocument(xml);
  } catch (err) {
    throw Error('Token malformado - ' + err);
  }

  switch (type) {
    case TOKEN_SSO_TYPE_INTERNAL: return parseInternal(document);
    case TOKEN_SSO_TYPE_EXTERNAL: return parseExternal(document);
    default: throw Error(`Tipo de token [${type}] desconocido`);
  }
}

function commonParse(document) {
  const idElement = document.childNamed('id');
  const operationElement = document.childNamed('operation');
  const loginElement = operationElement.childNamed('login');

  return {
    sourceService: idElement.attr.src,
    destinationService: idElement.attr.dst,
    uniqueId: Number(idElement.attr.unique_id),
    generationTime: Number(idElement.attr.gen_time),
    expirationTime: Number(idElement.attr.exp_time),
    service: loginElement.attr.service,
    entity: Number(loginElement.attr.entity), // AFIP cuit
    uid: loginElement.attr.uid,
    authmethod: loginElement.attr.authmethod,
    regmethod: loginElement.attr.regmethod,
  };
}

function getValueFromLogin(loginElement, name) {
  const child = loginElement.childWithAttribute('name', name);
  return child ? child.attr.value : null;
}

function parseInternal(document) {
  const token = commonParse(document);

  const loginElement = document.childNamed('operation').childNamed('login');
  const groupsElement = loginElement.childNamed('groups');
  const groups = [];
  groupsElement.eachChild(el => groups.push(el.attr.name));

  token.groups = groups;
  token.cuil = Number(loginElement.childWithAttribute('name', 'cuil').attr.value);

  token.departmentNumber = getValueFromLogin(loginElement, 'departmentNumber');
  token.commonName = getValueFromLogin(loginElement, 'cn');
  token.organizationalUnit = getValueFromLogin(loginElement, 'ou');
  token.codigoLegajo = getValueFromLogin(loginElement, 'codigoLegajo');
  token.username = getValueFromLogin(loginElement, 'username');

  return token;
}

function parseExternal(document) {
  let token = commonParse(document);
  let loginElement = document.childNamed('operation').childNamed('login');
  let relationElement = loginElement.childNamed('relations');
  let relations = [];

  relationElement.eachChild(el => {
    relations.push({
      key: el.attr.key,
      reltype: el.attr.reltype,
    });
  });

  token.relations = relations;

  return token;
}

module.exports = {
  validate,
};
