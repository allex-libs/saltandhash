function createLib(execlib){
  'use strict';
  var crypto = require('./crypto');
  var outerFunctionality = require('./outerfunctionalitycreator')(execlib);
  var lib = execlib.lib,
    q = lib.q,
    qlib = lib.qlib;

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

  function saltAndHashOuter(password,retObj,passwordFieldName){
    var d,salt,ret,passwordField;
    if (!lib.isString(password)){
      throw new lib.Error('PASSWORD_NOT_STRING','Given password is not string');
    }
    if (lib.defined(retObj) && 'object' !== typeof retObj){
      throw new lib.Error('RETOBJ_NOT_OBJECT','Given retObj is not an object');
    }
    passwordField = passwordFieldName || 'cryptedPassword';
    d = q.defer();
    salt = crypto.salt();
    ret = retObj || {};
    outerFunctionality.saltAndHash512Outer(password,salt,onSaltAndHash.bind(null,salt,d,ret,passwordField));
    return d.promise;
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
    salt = crypto.salt();
    ret = retObj || {};
    crypto.saltAndHash512(password,salt,onSaltAndHash.bind(null,salt,d,ret,passwordField));
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
    salt = crypto.salt();
    cryptedPassword = crypto.saltAndHashSync512(password,salt);
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

  function verifyPasswordOuter(password,salt,cryptedPassword){
    //acepts buffers as password and cryptedPassword
    var d = q.defer();
    outerFunctionality.saltAndHash512Outer(password,salt,onVerifiedPassword.bind(null,cryptedPassword,d));
    return d.promise;
  }

  function verifyPassword(password,salt,cryptedPassword){
    //acepts buffers as password and cryptedPassword
    var d = q.defer();
    crypto.saltAndHash512(password,salt,onVerifiedPassword.bind(null,cryptedPassword,d));
    return d.promise;
  }

  function verifyPasswordSync(password,salt,cryptedPassword){
    var newCryptedPassword = crypto.saltAndHashSync512(password,salt);
    return newCryptedPassword.equals(cryptedPassword);
  }


  return {
    saltAndHashOuter : saltAndHashOuter,
    saltAndHash : saltAndHash,
    saltAndHashSync : saltAndHashSync,
    verifyPasswordOuter : verifyPasswordOuter,
    verifyPassword : verifyPassword,
    verifyPasswordSync : verifyPasswordSync,
    release : outerFunctionality.release
  };
}

module.exports = createLib;
