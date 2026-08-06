# Access Lon Notes

## Purpose

The web server `access.log` records every HTTP request received by the server. Each log entry contains information about who made the request, what resource was requested, when the request occurred, how the server responded, and which client software (User-Agent) sent the request.

For detection engineering, access logs are valuable because they help identify normal user activity, suspicious requests, web attacks, scanners, bots, and attempted exploitation.

---

## Combined Log Format

A standard Apache/Nginx Combined Log Format contains nini fields.

| Field | Description | Example |
| Client IP Address | IP Address of the client making the request | 192.168.1.100 |
| Remote Logname | Usually "-" and rarely used | - |
| Authenticated User | Username if authenticated, otherwise "-" | - |
| Timestamp | Date and time of the request | [06/Aug/2026:10:29:31 +0530] |
| Request | HTTP method, requested URL, and protocol | GET /index.html HTTP/1.1 |
| Status Code | HTTP response status | 200 |
| Response size | Size of the response in bytes | 1543 | 
| Referer | Previous page that linked to the request | https://example.com |
| User_Agent | Browser, crawler, or client application | Mozilla/5.0 |

---

# Example Log Entry

192.168.1.100 - - [06/Aug/2026:10:20:31 +0530] " GET /index.html HTTP/1.1" 200 1543 "https://example.com" "Mozilla/5.0 (Windows NT 10.0; win64; x64)"

Field Breakdown

- Client IP: 192.168.1.100
- Timestamp: 06/Aug/2026 10:20:31 +0530
- Method: GET
- URL: /index.html
- Protocol: HTTP/1.1
- Status Code: 200
- Response Size: 1543 bytes
- Referer: https://example.com/
- User-Agent: Mozilla/5.0

---

# Normal Traffic Examples

## Example 1

GET / HTTP/1.1

Observation:
User visits the website homepage.

--- 

## Example 2

GET /images/logo.png HTTP/1.1


Observation:
Browser loads an image required by the webpage.

---

## Example 3

POST /login HTTP/1.1

Observation:
User submits login credentials through the website.

---

# SQL Injection Patterns

SQL Injection attempts place SQL syntax inside URL parameters in an attempt to mainpulate the application's detabase queries.

Common indicators include:

- OR '1' ='1
- UNION SELECT
- DROP TABLE
- SELECT
- INSERT
- UPDATE
- DELETE
- --
- /* */

Example URLs

/login.php?id=1' OR '1'='1

/products?id=5 UNION SELECT username,password
/search?id=1; DROP TABLE users

Observation

These requests attempt to modify or bypass database queries. In real enviroments they should be invertigated because they may indicate an attack or security testing.

---

# Cross-Site Scripting (XSS) Patterns

XSS attempts inject HTML or JavaScript into URL parameters so that the application may return executable code to another user's browser.

Common indicators include:

- <script>
- </script>
- alert(
- onerror=
- onload
- javascript:

Example URLs

/search?p=<script>alert(1)<.scrpt>
/comment?text=<img src=x onerror=alert(1)>
/profile?name=<svg onload=alert(1)>

Observation

These payloads attempt to execute JavaScript indide a victim's browser if the web application fails to properly validate or encode user input.

---

# User-Agent Analysis

## Normal User-Agent Examples

Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Mozilla/5.0 (Macintosh; Intel Mac OS X)
Mozilla/5.0 (X11; Linux x86_64)

Observation

These are typical web browsers used by legitimate users.

---

## Suspicious User-Agent Examples
sqlmap

curl/8.5.0

python-requests/2.31.0

Observation 
These clients are commonly used for automation, scripting, or security testing. They are not inherently malicious, but repeated or unusual requests from them may warrant invertigation.

---

# Manual Observations

After reviewing approximately 50 og entries:

- Most requests used the GET methos.
- Status code 200 appeared most frequently.
- Static resources such as CSS, JavaScript, and images were requested regularly.
- Browser User-Agent strings were more common than automated tools.
- The same client often requested multiple resourced in succession, which is expected when loading a webpage.

---

# Detection Engineering Notes

Information that could be extracted automatically from each log entry:

- Client IP Address
- Timestamp
- HTTP Method
- Requested URL
- Query Parameters
- HTTP Status Code
- Response Size
- Referer
- User-Agent

Potential future detection rules:

- Detect SQL Injection keyworlds in URLs.
- Detect XSS payloads in request parameters.
- Detect repeated 404 responses from the same IP.
- Detect excessive requests from a single IP in a short period.
- Detect suspicious User-Agent strings (e.g., sqlmap, curl, puthon-requests).
- Detect requests to sensitive endpoints such as /admin, /login, or /.git.