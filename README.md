# Secrets authentication exercise

A historical Express, EJS and MongoDB authentication learning project. New passwords
are salted and hashed with Node.js scrypt; plaintext and reversibly encrypted legacy
passwords are never accepted by the updated login handler. Bad credentials and
backend failures now return a response instead of leaving the request hanging.

Requires Node.js 20.19+ and MongoDB. Run `npm ci`, set `MONGODB_URI` if needed, then
`npm start`. Defaults: local MongoDB `userDB`, localhost port 3000. `PORT` and `HOST`
are configurable. Use `HOST=0.0.0.0` only when intentionally exposing the demo.
Run `npm test` for password and HTTP route regressions with a fake database.

## Existing tutorial accounts

The new `passwordHash` field replaces the old encrypted `password` field. Existing
records are preserved but cannot log in until reset through an independently
verified reset/migration process. No production user migration or database writes
were performed as part of this source maintenance. Do not reuse real passwords in
this tutorial database. The old `SECRET` encryption key is no longer used.

## Scope

This exercise only renders a page after credential verification. It does not
implement sessions, account recovery, email verification, rate limiting, or CSRF
protection and must not be used as a production authentication service.
