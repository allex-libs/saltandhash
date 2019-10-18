var crypto = require('./crypto');

process.on('message', onMessage);

function onMessage (msg) {
  try {
    process.send({r:crypto.saltAndHashSync(
      msg.password,
      msg.salt,
      msg.iterations,
      msg.keylen,
      msg.digest
    )});
  }
  catch (e) {
    process.send({e:e});
  }
}

