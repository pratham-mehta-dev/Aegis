const db = require("./db");
console.log("--- BLOCKED_IPS TABLE SCHEMA ---");
console.table(db.prepare("PRAGMA table_info(blocked_ips)").all());
