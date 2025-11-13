# Apache Log Parser (Python)

A lightweight Python tool for reading and analyzing Apache HTTP server logs.

This project can:
- count successful requests (HTTP 200)
- detect broken links (HTTP 404)
- list IP addresses generating errors
- identify requests from specific networks (e.g., Seneca Polytechnic)
- search for patterns inside URLs

### Why I built this
I created this project while learning Python file parsing and regular expressions.  
It helped me understand how servers track user requests and how log data can show performance problems.

---

## 🚀 Features
- Parse Apache logs using regular expressions  
- Count specific HTTP status codes  
- Identify special keywords inside URLs  
- Extract unique IP addresses  
- Simple menu-based CLI for quick use
