'use strict';

// https://github.com/csquared/fernet.js

const fernet = require('fernet');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcrypt');

const HASH_METHOD = 'sha256';

let fernetToken;
fs.readFile('secret.txt', 'utf8', (error, data) => {
  if (error) {
    console.log(error);
  } else {
    const SECRET = new fernet.Secret(data);
    fernetToken = new fernet.Token({secret: SECRET});
  }
});

let privateKey;
fs.readFile('private.pem', 'utf8', (error, data) => {
  if (error) {
    console.log(error);
  } else {
    privateKey = data;
  }
});

var getPrivateKey = function() {
  return privateKey;
}

var encodeToken = function(str) {
  return fernetToken.encode(str);
}

var bcryptCompare = function(password, existingPW) {
  return bcrypt.compare(password, existingPW);
}

var encodeManager = {
  encodedCode: "",
  hash: function(code) {
    this.encodedCode = crypto.createHash(HASH_METHOD)
                            .update(code)
                            .digest()
                            .toString('base64')
    return this;
  },
  toBase64URL: function() {
    this.encodedCode = this.encodedCode.replace(/\+/g, '-')
                                      .replace(/\//g, '_')
                                      .replace(/=/g, '');
    return this.encodedCode;
  }
};
/*
var encodeHashBase64url = function(code) {
  let encodedCode = crypto.createHash(HASH_METHOD)
  .update(code)
  .digest()
  .toString('base64')
  .replace(/\+/g, '-')
  .replace(/\//g, '_')
  .replace(/=/g, '');
  return encodedCode;
}
*/

module.exports = {encodeToken, getPrivateKey, bcryptCompare, encodeManager}