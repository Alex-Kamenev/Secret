require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const path = require('node:path');
const { hashPassword, verifyPassword } = require('./passwords');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true, select: false },
});
const User = mongoose.model('User', userSchema);

function credentials(body) {
  if (typeof body.username !== 'string' || typeof body.password !== 'string') return null;
  const email = body.username.trim().toLowerCase();
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || body.password.length < 8 || body.password.length > 1024) return null;
  return { email, password: body.password };
}

function createApp(UserModel = User) {
  const app = express();
  app.disable('x-powered-by');
  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'views'));
  app.use(express.urlencoded({ extended: false, limit: '8kb' }));
  app.use(express.static(path.join(__dirname, 'public')));
  for (const page of ['home', 'login', 'register']) app.get(page === 'home' ? '/' : `/${page}`, (req, res) => res.render(page));

  app.post('/register', async (req, res) => {
    const input = credentials(req.body);
    if (!input) return res.status(400).send('Enter a valid email and a password of 8 to 1024 characters.');
    try {
      const passwordHash = await hashPassword(input.password);
      await UserModel.create({ email: input.email, passwordHash });
      return res.render('secrets');
    } catch (error) {
      return res.status(error.code === 11000 ? 409 : 500).send('Unable to register this account.');
    }
  });

  app.post('/login', async (req, res) => {
    const input = credentials(req.body);
    if (!input) return res.status(401).send('Invalid email or password.');
    try {
      const user = await UserModel.findOne({ email: input.email }).select('+passwordHash');
      if (!user || !(await verifyPassword(input.password, user.passwordHash))) return res.status(401).send('Invalid email or password.');
      return res.render('secrets');
    } catch {
      return res.status(500).send('Unable to sign in.');
    }
  });
  return app;
}

if (require.main === module) {
  mongoose.connect(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/userDB')
    .then(() => createApp().listen(process.env.PORT || 3000, process.env.HOST || '127.0.0.1', () => console.log('Authentication demo started.')))
    .catch(() => { console.error('MongoDB connection failed. Check MONGODB_URI.'); process.exitCode = 1; });
}
module.exports = { createApp, credentials };
