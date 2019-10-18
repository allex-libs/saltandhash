var expect = require('chai').expect,
  execlib = require('allex'),
  lib = require('..')(execlib),
  buf = require('buffer');

var myPassword = 'GREAT_PASSWORD';


var myCryptedPassword, mySalt;

function onSuccess(done,retObj){
  myCryptedPassword = retObj.cryptedPassword;
  mySalt = retObj.salt;
  expect(buf.Buffer.isBuffer(myCryptedPassword)).to.be.equal.true;
  expect(buf.Buffer.byteLength(myCryptedPassword)).to.be.equal(512);
  expect(mySalt.length).to.be.equal(172);
  done();
}

function onSuccessPFN(done,pfn,retObj){
  myCryptedPassword = retObj[pfn];
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



describe('Testing Sync SaltAndHash lib',function(){
  it('saltAndHashSync', function(){
    var retObj = lib.saltAndHashSync(myPassword);
    myCryptedPassword = retObj.cryptedPassword;
    mySalt = retObj.salt;
    expect(buf.Buffer.isBuffer(myCryptedPassword)).to.be.equal.true;
    expect(buf.Buffer.byteLength(myCryptedPassword)).to.be.equal(512);
    expect(mySalt.length).to.be.equal(172);
  });

  it('saltAndHashSync (with retObj)', function(){
    var retObj = lib.saltAndHashSync(myPassword,{});
    myCryptedPassword = retObj.cryptedPassword;
    mySalt = retObj.salt;
    expect(buf.Buffer.isBuffer(myCryptedPassword)).to.be.equal.true;
    expect(buf.Buffer.byteLength(myCryptedPassword)).to.be.equal(512);
    expect(mySalt.length).to.be.equal(172);
  });

  it('saltAndHashSync (with retObj and passwordFieldName)', function(){
    var retObj = lib.saltAndHashSync(myPassword,{},'myPass');
    myCryptedPassword = retObj.myPass;
    mySalt = retObj.salt;
    expect(buf.Buffer.isBuffer(myCryptedPassword)).to.be.equal.true;
    expect(buf.Buffer.byteLength(myCryptedPassword)).to.be.equal(512);
    expect(mySalt.length).to.be.equal(172);
  });

  it('saltAndHashSync (throwing)', function(){
    expect(lib.saltAndHashSync.bind(null,true,{})).to.throw(Error, /password is not string/);
    expect(lib.saltAndHashSync.bind(null,myPassword,true)).to.throw(Error, /is not an object/);
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
  it('saltAndHash', function(done){
    var p = lib.saltAndHash(myPassword);
    p.then(
      onSuccess.bind(null,done),
      onError.bind(null,done)
    );
  });

  it('saltAndHash (throwing)', function(){
    expect(lib.saltAndHash.bind(null,true,{})).to.throw(Error, /password is not string/);
    expect(lib.saltAndHash.bind(null,myPassword,true)).to.throw(Error, /is not an object/);
  });

  it('saltAndHash (with retObj)', function(done){
    var p = lib.saltAndHash(myPassword,{});
    p.then(
      onSuccess.bind(null,done),
      onError.bind(null,done)
    );
  });

  it('saltAndHash (with retObj and passwordFieldName)', function(done){
    var pfn = 'myPass';
    var p = lib.saltAndHash(myPassword,{},pfn);
    p.then(
      onSuccessPFN.bind(null,done,pfn),
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

describe('Testing Outer SaltAndHash lib',function(){
  it('saltAndHash', function(done){
    var p = lib.saltAndHashOuter(myPassword);
    p.then(
      onSuccess.bind(null,done),
      onError.bind(null,done)
    );
  });

  it('saltAndHash (throwing)', function(){
    expect(lib.saltAndHashOuter.bind(null,true,{})).to.throw(Error, /password is not string/);
    expect(lib.saltAndHashOuter.bind(null,myPassword,true)).to.throw(Error, /is not an object/);
  });

  it('saltAndHash (with retObj)', function(done){
    var p = lib.saltAndHashOuter(myPassword,{});
    p.then(
      onSuccess.bind(null,done),
      onError.bind(null,done)
    );
  });

  it('saltAndHash (with retObj and passwordFieldName)', function(done){
    var pfn = 'myPass';
    var p = lib.saltAndHashOuter(myPassword,{},pfn);
    p.then(
      onSuccessPFN.bind(null,done,pfn),
      onError.bind(null,done)
    );
  });

  it('saltAndHash (for other password)', function(done){
    var p = lib.saltAndHashOuter('OTHER_PASSWORD_123456789');
    p.then(
      onSuccess2.bind(null,done),
      onError.bind(null,done)
    );
  });

  it('verifyPassword (successfully)', function(done){
    var p = lib.verifyPasswordOuter(myPassword,mySalt,myCryptedPassword);
    p.then(
      onVerifySuccess.bind(null,done),
      onError.bind(null,done)
    );
  });

  it('verifyPassword (unsuccessfully, bad password)', function(done){
    var p = lib.verifyPasswordOuter('BAD_PASSWORD',mySalt,myCryptedPassword);
    p.then(
      onVerifyUnsuccess.bind(null,done),
      onError.bind(null,done)
    );
  });

  it('verifyPassword (unsuccessfully, bad salt)', function(done){
    var p = lib.verifyPasswordOuter(myPassword,'BAD_SALT',myCryptedPassword);
    p.then(
      onVerifyUnsuccess.bind(null,done),
      onError.bind(null,done)
    );
  });
});
