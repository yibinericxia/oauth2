'use strict';

const { Datastore } = require('@google-cloud/datastore');
const pug = require('pug');
const path = require('path');
const appendQuery = require('append-query');
const jwt = require('jsonwebtoken');

const {encodeToken, getPrivateKey, encodeManager, bcryptCompare} = require('./token');

const JWT_LIFE_SPAN = 20 * 60 * 1000;
const CODE_LIFE_SPAN = 10 * 60 * 1000; // max 10 minutes
const ISSUER = 'sample-issuer';

const JWT_ALG = 'RS256';

const ERR_ACCESS_DENIED = 'access_denied';
const ERR_INVALID_REQUEST = 'invalid_request';
const ERR_GRANT_TYPE = 'Grant type is invalid or missing';
const ERR_MISSING_PARAMETERS = 'required parameters are missing in the request';
const ERR_INVALID_CLIENT_REDIRECT_URI = 'Invalid client/redirect URI';
const ERR_INVALID_CLIENT_CREDENTIALS = 'Invalid client credentials';
const ERR_INVALID_USER_CREDENTIALS = 'Invalid user credentials';
const ERR_INVALID_AUTH_CODE = 'Invalid authorization code';
const ERR_CLIENT_ID_NOT_MATCH = 'Client ID does not match the record';
const ERR_AUTHORIZATION_CODE_EXPIRED = 'Authorization code expired';
const ERR_REDIRECT_URI_NOT_MATCH = 'Redirect URI does not match the record';
const ERR_CODE_VERIFIER_NOT_MATCH = 'Code verifier does not match code challenge';

const projectId = 'oauth2-257016';
const datastore = new Datastore(
  /*
  {
    projectId: projectId,
//    keyFilename: 'oauth2-2a4caffcabe8.json'
  }
  */
);

exports.oauth2 = (req, res) => {
  switch(req.path) {
    case '/oauth2/auth':
      return oauth2_auth(req, res);
    case '/oauth2/login':
      return oauth2_login(req, res);
    case '/oauth2/token':
      return oauth2_token(req, res);
    default:
      res.send(`Function for ${req.path} not defined`);
  }
}

exports.auth = (req, res) => {
  oauth2_auth(req, res);
}

exports.login = (req, res) => {
  oauth2_login(req, res);
}

exports.token = (req, res) => {
  oauth2_token(req, res);
}

function oauth2_auth(req, res) {
  switch (req.query.response_type) {
    case 'code':
      if (req.query.client_id && req.query.redirect_uri) {
        if (req.query.code_challenge) {
          authACPKCE(req, res);
        } else {
          authAC(req, res);
        }
      } else {
        res.status(400).send(JSON.stringify({
          'error': ERR_INVALID_REQUEST,
          'error_description': ERR_MISSING_PARAMETERS
        }));
      }
      break;
    case 'token':
      authImplicit(req, res);
      break;
    default:
      res.status(400).send(JSON.stringify({
        'error': ERR_INVALID_REQUEST,
        'error_description': ERR_GRANT_TYPE
      }));
      break;
  }
};

function oauth2_login(req, res) {
  switch (req.body.response_type) {
    case ('code'):
      if (!req.body.code_challenge) {
        loginAC(req, res);
      } else {
        loginACPKCE(req, res);
      }
      break;
    case ('token'):
      loginImplicit(req, res);
      break;
    default:
      res.status(400).send(JSON.stringify({
        'error': ERR_INVALID_REQUEST,
        'error_description': ERR_GRANT_TYPE
      }));
      break;
  }
}

function oauth2_token(req, res) {
  switch (req.body.grant_type) {
    case 'password':
      tokenROPC(req, res);
      break;
    case 'authorization_code':
      if (req.body.client_secret && !req.body.code_verifier) {
        tokenAC(req, res);
        break;
      }
      if (req.body.code_verifier) {
        tokenACPKCE(req, res);
        break;
      }
      res.status(400).send(JSON.stringify({
        'error': ERR_INVALID_REQUEST,
        'error_description': 'Client secret and code verifier are exclusive to each other'
      }));
      break;
    case 'client_credentials':
      tokenCC(req, res);
      break;
    default:
      res.status(400).send(JSON.stringify({
        'error': ERR_INVALID_REQUEST,
        'error_description': ERR_GRANT_TYPE
      }));
      break;
  }
}

function authACPKCE(req, res) {
  // need to support scope
  if ( req.query.client_id === undefined
    || req.query.redirect_uri === undefined
    || req.query.code_challenge === undefined) {
    return res.status(400).send(JSON.stringify({
      'error': ERR_INVALID_REQUEST,
      'error_description': ERR_MISSING_PARAMETERS
    }));
  }
  const clientQuery = datastore.createQuery('client')
    .filter('client-id', '=', req.query.client_id)
    .filter('redirect-uri', '=', req.query.redirect_uri)
    .filter('acpkce-enabled', '=', true);
  
  datastore.runQuery(clientQuery)
    .then(result => {
      if (result[0].length === 0) {
        return Promise.reject(new Error(ERR_INVALID_CLIENT_REDIRECT_URI));
      }
    })
    .then(() => {
      const html = pug.renderFile(path.join(__dirname, 'auth.pug'), {
        response_type: 'code',
        client_id: req.query.client_id,
        redirect_uri: req.query.redirect_uri,
        code_challenge: req.query.code_challenge
      });
      res.status(200).send(html);
    })
    .catch(error => {
      if (error.message === ERR_INVALID_CLIENT_REDIRECT_URI) {
        res.status(400).send(JSON.stringify({
          'error': ERR_ACCESS_DENIED,
          'error_description': error.message
        }));
      } else {
        throw error;
      }
    });
}

function authAC(req, res) {
  // need to support scope
  if ( req.query.client_id === undefined
    || req.query.redirect_uri === undefined) {
      return res.status(400).send(JSON.stringify({
        'error': ERR_INVALID_REQUEST,
        'error_description': ERR_MISSING_PARAMETERS
      }));
  }
  const clientQuery = datastore.createQuery('client')
    .filter('client-id', '=', req.query.client_id)
    .filter('redirect-uri', '=', req.query.redirect_uri)
    .filter('ac-enabled', '=', true);

  datastore.runQuery(clientQuery)
    .then(result => {
      if (result[0].length === 0) {
        return Promise.reject(new Error(ERR_INVALID_CLIENT_REDIRECT_URI))
      }
    })
    .then(() => {
      const html = pug.renderFile(path.join(__dirname, 'auth.pug'), {
        response_type: 'code',
        client_id: req.query.client_id,
        redirect_uri: req.query.redirect_uri,
        code_challenge: req.query.code_challenge
      });
      res.status(200).send(html);
    })
    .catch(error => {
      if (error.message === ERR_INVALID_CLIENT_REDIRECT_URI) {
        res.status(400).send(JSON.stringify({
          'error': ERR_ACCESS_DENIED,
          'error_description': error.message
        }));
      } else {
        throw error;
      }
    });
}

function authImplicit(req, res) {
  if ( req.query.client_id === undefined
    || req.query.redirect_uri === undefined) {
      return res.status(400).send(JSON.stringify({
        'error': ERR_INVALID_REQUEST,
        'error_description': ERR_MISSING_PARAMETERS
      }));
  }
  const clientQuery = datastore.createQuery('client')
    .filter('client-id', '=', req.query.client_id)
    .filter('redirect-uri', '=', req.query.redirect_uri)
    .filter('implicit-enabled', '=', true);
  datastore.runQuery(clientQuery)
    .then(result => {
      if (result[0].length === 0) {
        return Promise.reject(new Error(ERR_INVALID_CLIENT_REDIRECT_URI));
      }
    })
    .then(() => {
      const html = pug.renderFile(path.join(__dirname, 'auth.pug'), {
        response_type: 'token',
        client_id: req.query.client_id,
        redirect_uri: req.query.redirect_uri,
        code_challenge: req.query.code_challenge
      });
      res.status(200).send(html);
    })
    .catch(error => {
      if (error.message === ERR_INVALID_CLIENT_REDIRECT_URI) {
        res.status(400).send(JSON.stringify({
          'error': ERR_ACCESS_DENIED,
          'error_description': error.message
        }))
      } else {
        throw error;
      }
    });
}

function loginACPKCE (req, res) {
  if ( req.body.username === undefined
    || req.body.password === undefined
    || req.body.client_id === undefined
    || req.body.redirect_uri === undefined
    || req.body.code_challenge === undefined) {
    return res.status(400).send(JSON.stringify({
      'error': ERR_INVALID_REQUEST,
      'error_description': ERR_MISSING_PARAMETERS
    }));
  }
  const userQuery = datastore.createQuery('user')
    .filter('username', '=', req.body.username);

  const clientQuery = datastore.createQuery('client')
    .filter('client-id', '=', req.body.client_id)
    .filter('redirect-uri', '=', req.body.redirect_uri)
    .filter('acpkce-enabled', '=', true);

  datastore.runQuery(userQuery)
    .then(result => {
      return verifyPassword(req.body.password, result);
    })
    .then(() => {
      return datastore.runQuery(clientQuery);
    })
    .then(result => {
      if (result[0].length === 0) {
        return Promise.reject(new Error(ERR_INVALID_CLIENT_REDIRECT_URI))
      }
    })
    .then(() => {
      const authorizationCode = encodeToken(JSON.stringify({
        'client_id': req.body.client_id,
        'redirect_uri': req.body.redirect_uri
      }))
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
      const exp = Date.now() + CODE_LIFE_SPAN;
      const codeKey = datastore.key(['authorization_code', authorizationCode]);
      const data = {
        'client_id': req.body.client_id,
        'redirect_uri': req.body.redirect_uri,
        'exp': exp,
        'code_challenge': req.body.code_challenge
      };
      return Promise.all([
        datastore.upsert({key: codeKey, data: data}), 
        Promise.resolve(authorizationCode)
      ]);
    })
    .then(results => {
      res.redirect(appendQuery(req.body.redirect_uri, {
        code: results[1]
      }));
    })
    .catch(error => {
      if (error.message === ERR_INVALID_USER_CREDENTIALS) {
        res.status(400).send(error.message);
      } else {
        throw error;
      }
    });
}

function loginAC (req, res) {
  //console.log(req.body);
  if ( req.body.username === undefined
    || req.body.password === undefined
    || req.body.client_id === undefined
    || req.body.redirect_uri === undefined) {
    return res.status(400).send(JSON.stringify({
      'error': ERR_INVALID_REQUEST,
      'error_description': ERR_MISSING_PARAMETERS
    }));
  }
  const userQuery = datastore.createQuery('user')
    .filter('username', '=', req.body.username);

  const clientQuery = datastore.createQuery('client')
    .filter('client-id', '=', req.body.client_id)
    .filter('redirect-uri', '=', req.body.redirect_uri)
    .filter('ac-enabled', '=', true);

  datastore.runQuery(userQuery)
    .then(result => {
      return verifyPassword(req.body.password, result);
    })
    .then(() => {
      return datastore.runQuery(clientQuery);
    })
    .then(result => {
      if (result[0].length === 0) {
        return Promise.reject(new Error(ERR_INVALID_CLIENT_REDIRECT_URI))
      }
    })
    .then(() => {
      const authorizationCode = encodeToken(JSON.stringify({
        'client_id': req.body.client_id,
        'redirect_uri': req.body.redirect_uri
      }));
      const exp = Date.now() + CODE_LIFE_SPAN;
      const codeKey = datastore.key(['authorization_code', authorizationCode]);
      const data = {
        'client_id': req.body.client_id,
        'redirect_uri': req.body.redirect_uri,
        'exp': exp
      };
      return Promise.all([
        datastore.upsert({key: codeKey, data: data}), 
        Promise.resolve(authorizationCode)
      ]);
    })
    .then(results => {
      /*
      const html = pug.renderFile(path.join(__dirname, 'grant.pug'), {
        scope: 'openID',
        grant_type: 'authorization_code',
        client_id: req.body.client_id,
        redirect_uri: req.body.redirect_uri,
        client_secret: 'sample-client-secret',
        authorization_code: results[1]
      });
      res.status(200).send(html);
      */
      res.redirect(appendQuery(req.body.redirect_uri, {
        code: results[1]
      }));
      
    })
    .catch(error => {
      if (error.message == ERR_INVALID_USER_CREDENTIALS
        ||error.message == ERR_INVALID_CLIENT_REDIRECT_URI) {
        res.status(400).send(error.message);
      } else {
        throw error;
      }
    });
}

function loginImplicit (req, res) {
  if (req.body.username === undefined
    ||req.body.password === undefined
    ||req.body.client_id === undefined
    ||req.body.redirect_uri === undefined) {
    return res.status(400).send(JSON.stringify({
      'error': ERR_INVALID_REQUEST,
      'error_description': ERR_MISSING_PARAMETERS
    }));
  }
  const userQuery = datastore.createQuery('user')
    .filter('username', '=', req.body.username);

  const clientQuery = datastore.createQuery('client')
    .filter('client-id', '=', req.body.client_id)
    .filter('redirect-uri', '=', req.body.redirect_uri)
    .filter('implicit-enabled', '=', true);

  datastore.runQuery(userQuery)
    .then(result => {
      return verifyPassword(req.body.password, result);
    })
    .then(() => {
      return datastore.runQuery(clientQuery);
    })
    .then(result => {
      if (result[0].length === 0) {
        return Promise.reject(new Error(ERR_INVALID_CLIENT_REDIRECT_URI))
      }
    })
    .then(() => {
      const privateKey = getPrivateKey();
      const token = jwt.sign({}, privateKey, {
        algorithm: JWT_ALG,
        expiresIn: JWT_LIFE_SPAN,
        issuer: ISSUER
      });
      res.redirect(appendQuery(req.body.redirect_uri, {
        token_type: 'JWT',
        expires_in: JWT_LIFE_SPAN,
        access_token: token
      }));
    })
    .catch(error => {
      if (error.message == ERR_INVALID_USER_CREDENTIALS
        ||error.message == ERR_INVALID_CLIENT_REDIRECT_URI) {
        res.status(400).send(error.message);
      } else {
        throw error;
      }
    });
}

function tokenROPC (req, res) {
  // need to support scope
  if (req.body.username === undefined 
    || req.body.password === undefined 
    || req.body.client_id === undefined 
    || req.body.client_secret === undefined) {
    return res.status(400).send(JSON.stringify({
      'error': ERR_INVALID_REQUEST,
      'error_description': ERR_MISSING_PARAMETERS
    }));
  }

  const clientQuery = datastore
    .createQuery('client')
    .filter('client-id', '=', req.body.client_id)
    .filter('client-secret', '=', req.body.client_secret)
    .filter('ropc-enabled', '=', true);

  const userQuery = datastore
    .createQuery('user')
    .filter('username', '=', req.body.username);

  datastore.runQuery(clientQuery)
    .then(clientQueryResult => {
      if (clientQueryResult[0].length === 0) {
        return Promise.reject(new Error(ERR_INVALID_CLIENT_CREDENTIALS));
      }
    })
    .then(() => datastore.runQuery(userQuery))
    .then(userQueryResult => {
      return verifyPassword(req.body.password, userQueryResult);
    })
    .then(() => {
      const privateKey = getPrivateKey();
      const token = jwt.sign({}, privateKey, {
        algorithm: JWT_ALG,
        expiresIn: JWT_LIFE_SPAN,
        issuer: ISSUER
      });
      res.status(200).send(JSON.stringify({
        access_token: token,
        token_type: 'JWT',
        expires_in: JWT_LIFE_SPAN
      }));
    })
    .catch(error => {
      if (error.message === ERR_INVALID_CLIENT_CREDENTIALS 
        ||error.message === ERR_INVALID_USER_CREDENTIALS) {
        res.status(400).send(JSON.stringify({
          'error': ERR_ACCESS_DENIED,
          'error_description': error.message
        }));
      } else {
        throw error;
      }
    });
}

function tokenAC (req, res) {
  if (req.body.client_id === undefined 
    ||req.body.client_secret === undefined 
    ||req.body.authorization_code === undefined 
    ||req.body.redirect_uri === undefined) {
    return res.status(400).send(JSON.stringify({
      'error': ERR_INVALID_REQUEST,
      'error_description': ERR_MISSING_PARAMETERS
    }));
  }

  const clientQuery = datastore.createQuery('client')
    .filter('client-id', '=', req.body.client_id)
    .filter('redirect-uri', '=', req.body.redirect_uri)
    .filter('ac-enabled', '=', true);

  datastore.runQuery(clientQuery)
    .then(clientQueryResult => {
      if (clientQueryResult[0].length === 0) {
        return Promise.reject(new Error(ERR_INVALID_CLIENT_CREDENTIALS));
      }
    })
    .then(() => {
      return verifyAuthorizationCode(req.body.authorization_code,
      req.body.client_id, req.body.redirect_uri);
    })
    .then(() => {
      const privateKey = getPrivateKey();
      const token = jwt.sign({}, privateKey, {
        algorithm: JWT_ALG,
        expiresIn: JWT_LIFE_SPAN,
        issuer: ISSUER
      });
      res.status(200).send(JSON.stringify({
        access_token: token,
        token_type: 'JWT',
        expires_in: JWT_LIFE_SPAN,
        client_id: req.body.client_id
      }));
    })
    .catch(error => {
      if (error.message === ERR_INVALID_CLIENT_CREDENTIALS 
        ||error.message === ERR_INVALID_AUTH_CODE 
        ||error.message === ERR_CLIENT_ID_NOT_MATCH 
        ||error.message === ERR_REDIRECT_URI_NOT_MATCH
        ||error.message === ERR_AUTHORIZATION_CODE_EXPIRED) {
          res.status(400).send(JSON.stringify({
            'error': ERR_ACCESS_DENIED,
            'error_description': error.message
        }));
      } else {
        throw error;
      }
    });
}

function tokenACPKCE (req, res) {
  if ( req.body.client_id === undefined 
    || req.body.authorization_code === undefined 
    || req.body.redirect_uri === undefined 
    || req.body.code_verifier === undefined) {
    return res.status(400).send(JSON.stringify({
      'error': ERR_INVALID_REQUEST,
      'error_description': ERR_MISSING_PARAMETERS
    }));
  }

  verifyAuthorizationCode(req.body.authorization_code, req.body.client_id,
      req.body.redirect_uri, req.body.code_verifier)
    .then(() => {
      const privateKey = getPrivateKey();
      const token = jwt.sign({}, privateKey, {
        algorithm: JWT_ALG,
        expiresIn: JWT_LIFE_SPAN,
        issuer: ISSUER
      });
      res.status(200).send(JSON.stringify({
        access_token: token,
        token_type: 'JWT',
        expires_in: JWT_LIFE_SPAN
      }));
    })
    .catch(error => {
      if ( error.message === ERR_INVALID_AUTH_CODE 
        || error.message === ERR_CLIENT_ID_NOT_MATCH 
        || error.message === ERR_REDIRECT_URI_NOT_MATCH 
        || error.message === ERR_AUTHORIZATION_CODE_EXPIRED 
        || error.message === ERR_CODE_VERIFIER_NOT_MATCH) {
        res.status(400).send(JSON.stringify({
          'error': ERR_ACCESS_DENIED,
          'error_description': error.message
        }));
      } else if (error.msg === 'Code challenge does not exist.') {
        res.status(400).send(JSON.stringify({
          'error': ERR_INVALID_REQUEST,
          'error_description': error.message
        }));
      } else {
        throw error;
      }
    });
}

function tokenCC (req, res) {
  // need to support scope
  if ( req.body.client_id === undefined 
    || req.body.client_secret === undefined) {
    return res.status(400).send(JSON.stringify({
      error: ERR_INVALID_REQUEST,
      error_description: ERR_MISSING_PARAMETERS
    }));
  }

  const clientQuery = datastore.createQuery('client')
    .filter('client-id', '=', req.body.client_id)
    .filter('client-secret', '=', req.body.client_secret)
    .filter('cc-enabled', '=', true);

  datastore.runQuery(clientQuery)
    .then(result => {
      if (result[0].length === 0) {
        return res.status(400).send(JSON.stringify({
          error: ERR_ACCESS_DENIED,
          error_description: ERR_INVALID_CLIENT_CREDENTIALS
        }));
      } else {
        const privateKey = getPrivateKey();
        const token = jwt.sign({}, privateKey, {
          algorithm: JWT_ALG,
          expiresIn: JWT_LIFE_SPAN,
          issuer: ISSUER
        });
        res.status(200).send(JSON.stringify({
          access_token: token,
          token_type: 'JWT',
          expires_in: JWT_LIFE_SPAN
        }));
      }
    });
}

async function verifyPassword(password, userQueryResult) {
  if (userQueryResult[0].length === 0) {
    return Promise.reject(new Error(ERR_INVALID_USER_CREDENTIALS))
  }
  let userVerified = false;
  for(const userData of userQueryResult[0]) {
    const match = await bcryptCompare(password, userData.password);
    if(match) {
      userVerified = true;
      break;
    }
  }
  if (!userVerified) {
    return Promise.reject(new Error(ERR_INVALID_USER_CREDENTIALS));
  }
}

function verifyAuthorizationCode (authorizationCode, clientId, redirectUrl,
          codeVerifier = undefined) {
  const transaction = datastore.transaction();
  const key = datastore.key(['authorization_code', authorizationCode]);
  console.log("here")
  return transaction.run()
    .then(() => transaction.get(key))
    .then(result => {
      const entry = result[0];
      if (entry === undefined) {
        return Promise.reject(new Error(ERR_INVALID_AUTH_CODE));
      }

      if (entry.client_id !== clientId) {
        return Promise.reject(new Error(ERR_CLIENT_ID_NOT_MATCH));
      }

      if (entry.redirect_uri !== redirectUrl) {
        return Promise.reject(new Error(ERR_REDIRECT_URI_NOT_MATCH));
      }

      if (entry.exp <= Date.now()) {
        return Promise.reject(new Error(ERR_AUTHORIZATION_CODE_EXPIRED));
      }

      if ( codeVerifier !== undefined 
        && entry.code_challenge !== undefined) {
        let codeVerifierBuffer = Buffer.from(codeVerifier);
        let codeChallenge = encodeManager.hash(codeVerifierBuffer).toBase64URL();
          
        console.log('final code: ', codeChallenge);
        if (codeChallenge !== entry.code_challenge) {
          return Promise.reject(new Error(ERR_CODE_VERIFIER_NOT_MATCH));
        }
      } else if (codeVerifier === undefined 
              && entry.code_challenge === undefined) {
        // Pass
      } else {
        return Promise.reject(new Error('Code challenge or code verifier does not exist.'));
      }

      return transaction.delete(key);
    })
    .then(() => transaction.commit())
    .catch(error => {
      transaction.rollback();
      throw error;
    });
}

