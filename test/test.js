var expect = require('chai').expect,
  execlib = require('allex'),
  lib = require('..')(execlib),
  buf = require('buffer');

var myPassword = 'GREAT_PASSWORD';

describe('Testing Sync SaltAndHash lib',function(){
  var myCryptedPassword, mySalt;

  it('saltAndHashSync', function(){
    var retObj = lib.saltAndHashSync(myPassword);
    myCryptedPassword = retObj.cryptedPassword;
    mySalt = retObj.salt;
    expect(buf.Buffer.isBuffer(myCryptedPassword)).to.be.equal.true;
    expect(buf.Buffer.byteLength(myCryptedPassword)).to.be.equal(512);
    expect(mySalt.length).to.be.equal(172);
  });
  it('saltAndHashSync (for other password)', function(){
    var retObj = lib.saltAndHashSync('OTHER_PASSWORD_123456789');
    var cryptedPass = retObj.cryptedPassword;
    var salt = retObj.salt;
    expect(buf.Buffer.isBuffer(cryptedPass)).to.be.equal.true;
    expect(buf.Buffer.byteLength(cryptedPass)).to.be.equal(512);
    expect(salt.length).to.be.equal(172);
  });
  it('verifyPasswordSync (successfully)', function(){
    expect(lib.verifyPasswordSync(myPassword,mySalt,myCryptedPassword)).to.be.true;
  });
  it('verifyPasswordSync (unsuccessfully, bad password)', function(){
    expect(lib.verifyPasswordSync('BAD_PASSWORD',mySalt,myCryptedPassword)).to.be.false;
  });
  it('verifyPasswordSync (unsuccessfully, bad salt)', function(){
    expect(lib.verifyPasswordSync(myPassword,'BAD_SALT',myCryptedPassword)).to.be.false;
  });
});

describe('Testing Async SaltAndHash lib',function(){
  var myCryptedPassword, mySalt;

  function onSuccess(done,retObj){
    myCryptedPassword = retObj.cryptedPassword;
    mySalt = retObj.salt;
    expect(buf.Buffer.isBuffer(myCryptedPassword)).to.be.equal.true;
    expect(buf.Buffer.byteLength(myCryptedPassword)).to.be.equal(512);
    expect(mySalt.length).to.be.equal(172);
    done();
  }

  function onSuccess2(done,retObj){
    var myCryptedPassword = retObj.cryptedPassword;
    var mySalt = retObj.salt;
    expect(buf.Buffer.isBuffer(myCryptedPassword)).to.be.equal.true;
    expect(buf.Buffer.byteLength(myCryptedPassword)).to.be.equal(512);
    expect(mySalt.length).to.be.equal(172);
    done();
  }

  function onVerifySuccess(done,retVal){
    expect(retVal).to.be.true;
    done();
  }

  function onVerifyUnsuccess(done,retVal){
    expect(retVal).to.be.false;
    done();
  }

  function onError(done,error){
    console.error(error);
    done();
  }

  it('saltAndHash', function(done){
    var p = lib.saltAndHash(myPassword);
    p.then(
      onSuccess.bind(null,done),
      onError.bind(null,done)
    );
  });

  it('saltAndHash (for other password)', function(done){
    var p = lib.saltAndHash('OTHER_PASSWORD_123456789');
    p.then(
      onSuccess2.bind(null,done),
      onError.bind(null,done)
    );
  });

  it('verifyPassword (successfully)', function(done){
    var p = lib.verifyPassword(myPassword,mySalt,myCryptedPassword);
    p.then(
      onVerifySuccess.bind(null,done),
      onError.bind(null,done)
    );
  });

  it('verifyPassword (unsuccessfully, bad password)', function(done){
    var p = lib.verifyPassword('BAD_PASSWORD',mySalt,myCryptedPassword);
    p.then(
      onVerifyUnsuccess.bind(null,done),
      onError.bind(null,done)
    );
  });

  it('verifyPassword (unsuccessfully, bad salt)', function(done){
    var p = lib.verifyPassword(myPassword,'BAD_SALT',myCryptedPassword);
    p.then(
      onVerifyUnsuccess.bind(null,done),
      onError.bind(null,done)
    );
  });
});
