const db = require("./db");
console.log("--- RECENT ALERTS FOR 10.77.0.2 ---");
console.table(db.prepare("SELECT id, source_ip, severity, created_at FROM alerts WHERE source_ip = ? ORDER BY created_at DESC LIMIT 5").all("10.77.0.2"));
console.log("--- BLOCKED IPS TABLE ---");
console.table(db.prepare("SELECT * FROM blocked_ips").all());
