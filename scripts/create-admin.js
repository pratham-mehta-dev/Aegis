"use strict";

// Usage: npm run create-admin -- "Name" admin@gmail.com 'StrongPass1!'
const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");

const [name, email, password] = process.argv.slice(2);
if (!name || !email || !password) {
  console.error('Usage: npm run create-admin -- "Name" admin@gmail.com "StrongPass1!"');
  process.exit(1);
}
const cleanEmail = email.trim().toLowerCase();
if (!/^[^\s@]+@gmail\.com$/.test(cleanEmail)) {
  console.error("Admin email must be a @gmail.com address (project rule).");
  process.exit(1);
}
if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/.test(password)) {
  console.error("Password must be >= 8 chars with upper, lower, digit and special.");
  process.exit(1);
}

const db = require("../db");

if (db.prepare("SELECT 1 FROM users WHERE email = ?").get(cleanEmail)) {
  console.error("A user with that email already exists.");
  process.exit(1);
}

const now = Date.now();
db.prepare(
  `INSERT INTO users (id, name, email, password_hash, role, email_verified,
    two_fa_enabled, two_fa_method, created_at, updated_at)
   VALUES (?,?,?,?,'admin',1,1,'email',?,?)`
).run(uuidv4(), name.trim(), cleanEmail, bcrypt.hashSync(password, 12), now, now);

console.log(`Admin created: ${cleanEmail}. 2FA is mandatory — sign in and complete the email OTP step.`);
