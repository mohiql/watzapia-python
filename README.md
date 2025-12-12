# WhatsApp Blast System (WA Blast)

![License](https://img.shields.io/badge/license-MIT-green)  
![Python](https://img.shields.io/badge/python-3.9%2B-blue)  
![Flask](https://img.shields.io/badge/flask-2.3-orange)

A powerful **WhatsApp messaging automation system** built with **Python Flask**, **SQLite**, and **Fonnte API**.  
This system allows users to send bulk messages, images, and spin-text messages to multiple recipients with proxy support, rate limiting, and detailed user activity history.

---

## Features

- **User Authentication**: Register, login, and manage your profile.
- **Admin Panel**:
  - Manage users (add/edit/delete)
  - Manage proxies
  - View user activity & sending progress
  - Configure rate limits
- **Template System**: Create reusable message templates with spin-text support.
- **WA Blast**:
  - Send messages to multiple numbers from file or manual input
  - Attach images
  - Spin-text feature `{a|b|c}` to randomize messages
  - Rate-limiting to avoid being blocked
  - Proxy support with automatic removal of dead proxies
- **History & Reporting**:
  - Track all sent messages
  - Export history to CSV or Excel
- **Secure Passwords**: Passwords are hashed using `Werkzeug`.

---

## Requirements

- Python 3.9+
- Flask
- Requests
- Pandas
- openpyxl (for Excel export)
- Werkzeug

---

## Installation

1. **Clone this repository**
```bash
git clone https://github.com/username/wa-blast.git
cd wa-blast

python -m venv venv
source venv/bin/activate      # Linux / macOS
venv\Scripts\activate         # Windows

pip install -r requirements.txt

python app.py  ===>> http://127.0.0.1:5000
