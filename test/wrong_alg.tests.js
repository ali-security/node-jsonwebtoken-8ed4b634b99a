var fs = require('fs');
var path = require('path');
var jwt = require('../index');
var assert = require('chai').assert;


var pub = fs.readFileSync(path.join(__dirname, 'pub.pem'), 'utf8');
// priv is never used
// var priv = fs.readFileSync(path.join(__dirname, 'priv.pem'));

var TOKEN = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE0MjY1NDY5MTl9.ETgkTn8BaxIX4YqvUWVFPmum3moNZ7oARZtSBXb_vP4';

function base64url(str) {
  return new Buffer(str).toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

describe('signing with pub key as symmetric', function () {
  it('should not verify', function (done) {
    jwt.verify(TOKEN, pub, function (err, decoded) {
      assert.isUndefined(decoded);
      assert.instanceOf(err, Error);
      assert.match(err.message, /invalid signature/);
      done();
    });
  });

  ['pub.pem', 'rsa-public.pem', 'rsa-public-key.pem'].forEach(function (file) {
    describe('when the public key is ' + file, function () {
      var key = fs.readFileSync(path.join(__dirname, file));

      ['HS256', 'HS384', 'HS512'].forEach(function (alg) {
        it('should not verify a ' + alg + ' token signed with the public key as secret', function (done) {
          var token = jwt.sign({ foo: 'bar' }, key, { algorithm: alg });

          jwt.verify(token, key, function (err, decoded) {
            assert.isUndefined(decoded);
            assert.instanceOf(err, Error);
            assert.match(err.message, /invalid signature/);
            done();
          });
        });
      });
    });
  });
});

describe('unsigned token (alg none)', function () {
  var token = base64url(JSON.stringify({ typ: 'JWT', alg: 'none' })) + '.' +
              base64url(JSON.stringify({ foo: 'bar' })) + '.';

  it('should not verify with a secret', function (done) {
    jwt.verify(token, 'shhhhh', function (err, decoded) {
      assert.isUndefined(decoded);
      assert.instanceOf(err, Error);
      assert.match(err.message, /invalid signature/);
      done();
    });
  });

  it('should not verify with a public key', function (done) {
    jwt.verify(token, pub, function (err, decoded) {
      assert.isUndefined(decoded);
      assert.instanceOf(err, Error);
      assert.match(err.message, /invalid signature/);
      done();
    });
  });

  it('should not verify without a secret or public key', function (done) {
    jwt.verify(token, undefined, function (err, decoded) {
      assert.isUndefined(decoded);
      assert.instanceOf(err, Error);
      assert.match(err.message, /invalid signature/);
      done();
    });
  });
});

describe('options.algorithms', function () {
  var secret = 'shhhhh';
  var priv = fs.readFileSync(path.join(__dirname, 'priv.pem'));

  it('should not verify when the token alg is not allowed', function (done) {
    var token = jwt.sign({ foo: 'bar' }, secret, { algorithm: 'HS256' });

    jwt.verify(token, secret, { algorithms: ['HS512'] }, function (err, decoded) {
      assert.isUndefined(decoded);
      assert.instanceOf(err, Error);
      assert.match(err.message, /invalid signature/);
      done();
    });
  });

  it('should verify when the token alg is allowed', function (done) {
    var token = jwt.sign({ foo: 'bar' }, secret, { algorithm: 'HS256' });

    jwt.verify(token, secret, { algorithms: ['HS256'] }, function (err, decoded) {
      assert.isNull(err);
      assert.equal('bar', decoded.foo);
      done();
    });
  });

  it('should not carry the default algorithms over between calls', function (done) {
    var options = {};
    var hsToken = jwt.sign({ foo: 'bar' }, secret, { algorithm: 'HS256' });
    var rsToken = jwt.sign({ foo: 'bar' }, priv, { algorithm: 'RS256' });

    jwt.verify(hsToken, secret, options, function (err, decoded) {
      assert.isNull(err);
      assert.equal('bar', decoded.foo);

      jwt.verify(rsToken, pub, options, function (err, decoded) {
        assert.isNull(err);
        assert.equal('bar', decoded.foo);
        done();
      });
    });
  });

  it('should not carry the default algorithms over between calls sharing a callback', function () {
    var results = [];
    var hsToken = jwt.sign({ foo: 'bar' }, secret, { algorithm: 'HS256' });
    var rsToken = jwt.sign({ foo: 'bar' }, priv, { algorithm: 'RS256' });

    function callback(err, decoded) {
      results.push({ err: err, decoded: decoded });
    }

    jwt.verify(hsToken, secret, callback);
    jwt.verify(rsToken, pub, callback);

    assert.lengthOf(results, 2);
    assert.isNull(results[0].err);
    assert.equal('bar', results[0].decoded.foo);
    assert.isNull(results[1].err);
    assert.equal('bar', results[1].decoded.foo);
  });
});
