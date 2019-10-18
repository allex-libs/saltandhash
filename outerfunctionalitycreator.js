var child_process = require('child_process');
var _outerprocess;
var _activejob;

function createOuterProcess () {
  _outerprocess = child_process.fork(require('path').join(__dirname,'process.js'), null, {stdio:'inherit'});
  _outerprocess.on('message', onChildProcMessage);
}

function onChildProcMessage (msg) {
  if (_activejob) {
    _activejob.onResult(msg);
  }
}

function createOuterFunctionality (execlib) {
  var lib = execlib.lib,
    qlib = lib.qlib,
    JobBase = qlib.JobBase,
    jobs = new qlib.JobCollection();

  function OuterJob (password, salt, iterations, keylen, digest, defer) {
    JobBase.call(this, defer);
    this.password = password;
    this.salt = salt;
    this.iterations = iterations;
    this.keylen = keylen;
    this.digest = digest;
  }
  lib.inherit(OuterJob, JobBase);
  OuterJob.prototype.destroy = function () {
    _activejob = null;
    this.digest = null;
    this.keylen = null;
    this.iterations = null;
    this.salt = null;
    this.password = null;
    JobBase.prototype.destroy.call(this);
  };
  OuterJob.prototype.go = function () {
    _activejob = this;
    if(!_outerprocess) {
      createOuterProcess();
    }
    _outerprocess.send({
      password: this.password,
      salt: this.salt,
      iterations: this.iterations,
      keylen: this.keylen,
      digest: this.digest
    });
  };
  OuterJob.prototype.onResult = function (msg) {
    if (!msg) {
      this.reject(new lib.Error('INTERNAL_ERROR'));
      return;
    }
    if (msg.e) {
      this.reject(msg.e)
      return;
    }
    this.resolve(pack(msg.r));
  };
  function pack (thingy) {
    if (Buffer.isBuffer(thingy)) {
      return thingy;
    }
    if ('object' === typeof(thingy) && lib.isVal(thingy) && thingy.type==='Buffer' && lib.isArray(thingy.data)) {
      return Buffer.from(thingy.data);
    }
    return null;
  };



  function _saltAndHash512Outer(password,salt,cb){
    return _saltAndHashOuter(password,salt,1000,512,'sha512',cb); 
  }
  function _saltAndHashOuter(password,salt,iterations,keylen,digest,cb){
    var ret = jobs.run('.', new OuterJob(password,salt,iterations,keylen,digest,cb)).then(
      cb.bind(null, null),
      cb.bind(null)
    );
    cb = null;
    return ret;
  }

  function release () {
    if (_outerprocess) {
      _outerprocess.kill();
    }
  }
  
  return {
    saltAndHash512Outer: _saltAndHash512Outer,
    saltAndHashOuter: _saltAndHashOuter,
    release: release
  };
}
module.exports = createOuterFunctionality;
