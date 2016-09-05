function createLib(execlib){
  'use strict';
  var crypto = require('crypto');
  var lib = execlib.lib,
    q = lib.q,
    qlib = lib.qlib;

  function _saltAndHash512(password,salt,cb){
    crypto.pbkdf2(password,salt,10000,512,'sha512',cb);
    //The supplied callback function is called with two arguments: err and derivedKey.
    //If an error occurs, err will be set; otherwise err will be null.
    //The successfully generated derivedKey will be passed as a Buffer.
  }

  function _saltAndHash(password,salt,iterations,keylen,digest,cb){
    crypto.pbkdf2(password,salt,iterations,keylen,digest,cb);
    //Genric method
  }

  function _saltAndHashSync512(password,salt){
    return crypto.pbkdf2Sync(password,salt,10000,512,'sha512');
    //If an error occurs an Error will be thrown,
    //otherwise the derived key will be returned as a Buffer.
  }

  function _saltAndHashSync(password,salt,iterations,keylen,digest){
    return crypto.pbkdf2Sync(password,salt,iterations,keylen,digest);
    //Genric method
  }

  function onSaltAndHash(salt,defer,ret,passwordField,error,derivedKey){
    if (!!error){
      defer.reject(error);
      salt = null;
      defer = null;
      return;
    }
    ret[passwordField] = derivedKey;
    ret.salt = salt;
    defer.resolve(ret);
    salt = null;
    defer = null;
  }

  function saltAndHash(password,retObj,passwordFieldName){
    var d,salt,ret,passwordField;
    if (!lib.isString(password)){
      throw new lib.Error('PASSWORD_NOT_STRING','Given password is not string');
    }
    if (lib.defined(retObj) && 'object' !== typeof retObj){
      throw new lib.Error('RETOBJ_NOT_OBJECT','Given retObj is not an object');
    }
    passwordField = passwordFieldName || 'cryptedPassword';
    d = q.defer();
    salt = crypto.randomBytes(128).toString('base64');
    ret = retObj || {};
    _saltAndHash512(password,salt,onSaltAndHash.bind(null,salt,d,ret,passwordField));
    return d.promise;
  }
  
  function saltAndHashSync(password,retObj,passwordFieldName){
    var salt,cryptedPassword,ret,passwordField;
    if (!lib.isString(password)){
      throw new lib.Error('PASSWORD_NOT_STRING','Given password is not string');
    }
    if (lib.defined(retObj) && 'object' !== typeof retObj){
      throw new lib.Error('RETOBJ_NOT_OBJECT','Given retObj is not an object');
    }
    passwordField = passwordFieldName || 'cryptedPassword';
    salt = crypto.randomBytes(128).toString('base64');
    cryptedPassword = _saltAndHashSync512(password,salt);
    ret = retObj || {};
    ret[passwordField] = cryptedPassword;
    ret.salt = salt;
    return ret;
  }

  function onVerifiedPassword(cryptedPassword,defer,error,derivedKey){
    if (!!error){
      defer.reject(error);
      cryptedPassword = null;
      defer = null;
      return;
    }
    if (cryptedPassword.equals(derivedKey)){
      defer.resolve(true);
      cryptedPassword = null;
      defer = null;
      return;
    }else{
      defer.resolve(false);
      cryptedPassword = null;
      defer = null;
      return;
    }
  }

  function verifyPassword(password,salt,cryptedPassword){
    //acepts buffers as password and cryptedPassword
    var d = q.defer();
    _saltAndHash512(password,salt,onVerifiedPassword.bind(null,cryptedPassword,d));
    return d.promise;
  }

  function verifyPasswordSync(password,salt,cryptedPassword){
    var newCryptedPassword = _saltAndHashSync512(password,salt);
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
