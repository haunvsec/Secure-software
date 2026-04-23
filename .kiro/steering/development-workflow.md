---
description: Development workflow rules and coding standards for Secure Software Board
inclusion: auto
---

# Quy trình phát triển — Secure Software Board

## Nguyên tắc bắt buộc

Mọi thay đổi code PHẢI tuân thủ quy trình: cập nhật spec trước → code → test → mark done.

### Ngoại lệ (không cần cập nhật spec)
- Fix bug CSS/typo, thay đổi text/label UI, điều chỉnh style nhỏ

## Quy tắc code

- Database: MariaDB ONLY — KHÔNG dùng SQLite
- ORM: SQLAlchemy 2.x — KHÔNG viết raw SQL
- Kiến trúc MVC:
  - `src/config.py` — Configuration (DATABASE_URL)
  - `src/database.py` — SQLAlchemy engine, session, Base
  - `src/app.py` — App factory
  - `src/controllers/` — Flask Blueprints
  - `src/models/` — SQLAlchemy ORM models + queries
  - `src/safe_version.py` — Business logic
  - `src/templates/` — Jinja2 templates
  - `src/static/` — CSS, JS, fonts
- Pagination dùng `get_paginated()` helper
- Input validation dùng `sanitize_*()` functions

## Bảo mật

- SQLAlchemy ORM tự xử lý parameterized queries — KHÔNG viết raw SQL
- KHÔNG dùng `|safe` — dùng `|sanitize_html`
- Jinja2 auto-escaping mặc định
- Input validation qua `sanitize_*()` functions
- Chỉ redirect đến internal paths
- KHÔNG dùng `eval()`, `exec()`, `os.system()` với user input
