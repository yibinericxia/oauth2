'use strict';

const bcrypt = require('bcrypt');
const crypto = require('crypto');

function generate_codes() {
  const code_verifier = crypto.randomBytes(64)
                        .toString('base64')
                        .replace(/\+/g, '-')
                        .replace(/\//g, '_')
                        .replace(/=/g, '');
  const code_challenge = crypto.createHash('sha256')
                        .update(code_verifier)
                        .digest()
                        .toString('base64')
                        .replace(/\+/g, '-')
                        .replace(/\//g, '_')
                        .replace(/=/g, '');

  console.log("code verifier: ", code_verifier);
  console.log("code challenge: ", code_challenge);
}

generate_codes();

const password = 'sample-password';

async function encrypt_password(password) {
  const SALTROUNDS = 5;
  const encryptedPW = await bcrypt.hash(password, SALTROUNDS);
  console.log(`encrypted password (${password}): ${encryptedPW}`);
}

encrypt_password(password);
