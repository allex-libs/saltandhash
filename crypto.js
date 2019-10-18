var crypto = require('crypto');

function _saltAndHash512(password,salt,cb){
  return _saltAndHash(password,salt,10000,512,'sha512',cb); 
  //The supplied callback function is called with two arguments: err and derivedKey.
  //If an error occurs, err will be set; otherwise err will be null.
  //The successfully generated derivedKey will be passed as a Buffer.
}

function _saltAndHash(password,salt,iterations,keylen,digest,cb){
  crypto.pbkdf2(password,salt,iterations,keylen,digest,cb);
  //Genric method
}

function _saltAndHashSync512(password,salt){
  return _saltAndHashSync(password,salt,10000,512,'sha512');
  //If an error occurs an Error will be thrown,
  //otherwise the derived key will be returned as a Buffer.
}

function _saltAndHashSync(password,salt,iterations,keylen,digest){
  return crypto.pbkdf2Sync(password,salt,iterations,keylen,digest);
  //Genric method
}

function _salt () {
  return crypto.randomBytes(128).toString('base64');
}

module.exports = {
  saltAndHash512: _saltAndHash512,
  saltAndHash: _saltAndHash,
  saltAndHashSync512: _saltAndHashSync512,
  saltAndHashSync: _saltAndHashSync,
  salt: _salt
};
