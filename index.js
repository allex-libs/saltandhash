function createLib(execlib){
  'use strict';
  var crypto = require('crypto');
  var lib = execlib.lib,
    q = lib.q,
    qlib = lib.qlib;

  function _saltAndHash(password,salt,iterations,keylen,digest,cb){
    crypto.pbkdf2(password,salt,iterations,keylen,digest,cb);
    //The supplied callback function is called with two arguments: err and derivedKey.
    //If an error occurs, err will be set; otherwise err will be null.
    //The successfully generated derivedKey will be passed as a Buffer.
  }

  function _saltAndHashSync(password,salt,iterations,keylen,digest){
    return crypto.pbkdf2Sync(password,salt,iterations,keylen,digest);
    //If an error occurs an Error will be thrown,
    //otherwise the derived key will be returned as a Buffer.
  }

  function onSaltAndHash(salt,defer,error,derivedKey){
    if (!!error){
      defer.reject(error);
      return;
    }
    var ret = {
      cryptedPassword : derivedKey,
      salt : salt
    };
    defer.resolve(ret);
  }

  function saltAndHash(password){
    var d = q.defer();
    var salt = crypto.randomBytes(128).toString('base64');
    _saltAndHash(password,salt,10000,512,'sha512',onSaltAndHash.bind(null,salt,d));
    return d.promise;
  }
  
  function saltAndHashSync(password){
    var salt = crypto.randomBytes(128).toString('base64');
    var cryptedPassword = _saltAndHashSync(password,salt,10000,512,'sha512');
    return {
      cryptedPassword : cryptedPassword,
      salt : salt
    };
  }

  function onVerifiedPassword(cryptedPassword,defer,error,derivedKey){
    if (!!error){
      defer.reject(error);
      return;
    }
    if (cryptedPassword.equals(derivedKey)){
      defer.resolve(true);
      return;
    }else{
      defer.resolve(false);
      return;
    }
  }

  function verifyPassword(password,salt,cryptedPassword){
    //acepts buffers as password and cryptedPassword
    var d = q.defer();
    _saltAndHash(password,salt,10000,512,'sha512',onVerifiedPassword.bind(null,cryptedPassword,d));
    return d.promise;
  }

  function verifyPasswordSync(password,salt,cryptedPassword){
    var newCryptedPassword = _saltAndHashSync(password,salt,10000,512,'sha512');
    return newCryptedPassword.equals(cryptedPassword);
  }


  return {
    saltAndHash : saltAndHash,
    saltAndHashSync : saltAndHashSync,
    verifyPassword : verifyPassword,
    verifyPasswordSync : verifyPasswordSync
  };
}

module.exports = createLib;
