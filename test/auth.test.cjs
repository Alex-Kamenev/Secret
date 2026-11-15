const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createApp } = require('../app');
const { hashPassword, verifyPassword } = require('../passwords');

test('salted hashes verify correctly and reject legacy or malformed values', async () => {
  const first = await hashPassword('a correct password');
  const second = await hashPassword('a correct password');
  assert.notEqual(first, second);
  assert.equal(await verifyPassword('a correct password', first), true);
  assert.equal(await verifyPassword('wrong password', first), false);
  assert.equal(await verifyPassword('plaintext', 'plaintext'), false);
  assert.equal(await verifyPassword('password', 'scrypt-v1:bad:bad'), false);
});
test('authentication routes terminate failures and never persist plaintext', async t => {
  let account;
  let backendError = false;
  const Model = {
    create: async value => { account = value; },
    findOne: value => ({ select: async () => {
      if (backendError) throw new Error('internal connection details');
      return account && value.email === account.email ? account : null;
    } }),
  };
  const server = createApp(Model).listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const post = (route, body) => fetch(`http://127.0.0.1:${server.address().port}${route}`, {
    method: 'POST', body: new URLSearchParams(body), signal: AbortSignal.timeout(5000),
  });
  assert.equal((await post('/login', { username: 'nobody@example.test', password: 'password123' })).status, 401);
  assert.equal((await post('/register', { username: 'me@example.test', password: 'short' })).status, 400);
  assert.equal((await post('/register', { username: 'ME@example.test', password: 'password123' })).status, 200);
  assert.equal(account.email, 'me@example.test');
  assert.equal(account.password, undefined);
  assert.match(account.passwordHash, /^scrypt-v1:/);
  assert.equal((await post('/login', { username: 'me@example.test', password: 'wrongpassword' })).status, 401);
  assert.equal((await post('/login', { username: 'me@example.test', password: 'password123' })).status, 200);
  assert.equal((await post('/login', { 'username[$ne]': '', password: 'password123' })).status, 401);
  backendError = true;
  const failure = await post('/login', { username: 'me@example.test', password: 'password123' });
  assert.equal(failure.status, 500);
  assert.doesNotMatch(await failure.text(), /connection details/);
});
