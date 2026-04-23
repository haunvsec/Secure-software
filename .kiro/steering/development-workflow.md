---
inclusion: auto
---

# Quy trình phát triển — Secure Software Board

## Nguyên tắc bắt buộc

Mọi thay đổi code trong project này PHẢI tuân thủ quy trình sau:

### 1. Cập nhật tài liệu TRƯỚC KHI code

Trước khi viết bất kỳ dòng code nào, PHẢI thực hiện:

- **Yêu cầu mới hoặc thay đổi chức năng**: Cập nhật `#[[file:.kiro/specs/cve-database-website/requirements.md]]` — thêm yêu cầu mới hoặc sửa yêu cầu hiện tại
- **Thay đổi kiến trúc, model, route, template**: Cập nhật `#[[file:.kiro/specs/cve-database-website/design.md]]` — cập nhật routes, model functions, template layout, data model
- **Task mới**: Cập nhật `#[[file:.kiro/specs/cve-database-website/tasks.md]]` — thêm task mới với reference đến requirements

### 2. Thứ tự thực hiện

1. Phân tích yêu cầu từ người dùng
2. Cập nhật requirements.md (nếu là chức năng mới)
3. Cập nhật design.md (nếu thay đổi kiến trúc/model/route)
4. Thực thi code
5. Test và verify
6. Cập nhật tasks.md (đánh dấu hoàn thành)

### 3. Ngoại lệ

Các thay đổi nhỏ sau KHÔNG cần cập nhật spec trước:
- Fix bug hiển thị (CSS, typo)
- Thay đổi text/label UI
- Sắp xếp lại thứ tự menu
- Điều chỉnh style nhỏ

## Quy tắc code

- Kiến trúc MVC với Flask Blueprints:
  - `src/config.py` — Configuration
  - `src/database.py` — DB connection, cache
  - `src/filters.py` — Jinja2 template filters
  - `src/app.py` — App factory (`create_app()`)
  - `src/controllers/` — Route handlers (Blueprints), mỗi file = 1 nhóm routes
  - `src/models/` — Database queries, mỗi file = 1 nhóm tables
  - `src/safe_version.py` — Business logic
  - `src/templates/` — Jinja2 templates (View)
  - `src/static/` — CSS, JS, fonts
- Thêm route mới → tạo/cập nhật file trong `controllers/`, đăng ký blueprint trong `controllers/__init__.py`
- Thêm model function → tạo/cập nhật file trong `models/`, export trong `models/__init__.py`
- Tất cả queries phải dùng parameterized queries (`%s` cho MariaDB)
- Phân trang dùng `get_paginated_result()` chuẩn
- Input validation dùng `sanitize_*()` functions
- DB connection qua `database.get_db()`, cache qua `database.cache`

## Ngôn ngữ

- Code: English (variable names, function names, comments)
- UI labels: Tiếng Việt hoặc English tùy context
- Tài liệu spec: Tiếng Việt

## Bảo mật (Security Rules)

Mọi code PHẢI tuân thủ các quy tắc bảo mật sau:

### SQL Injection Prevention
- LUÔN dùng parameterized queries (`%s` cho MariaDB, `?` cho SQLite) — KHÔNG BAO GIỜ nối string user input vào SQL
- Biến `{where}` trong f-string SQL chỉ chứa hardcoded conditions + `%s` placeholders, KHÔNG chứa user input trực tiếp
- Tất cả user input từ `request.args` PHẢI đi qua `sanitize_*()` functions trước khi dùng trong query

### XSS Prevention
- KHÔNG dùng `|safe` filter trong templates — dùng `|sanitize_html` thay thế (strip scripts, event handlers)
- Jinja2 auto-escaping mặc định cho tất cả output
- HTML từ nguồn bên ngoài (advisory descriptions) PHẢI qua `sanitize_html` filter

### Input Validation
- `sanitize_page()` — chỉ chấp nhận int >= 1
- `sanitize_severity()` — chỉ chấp nhận CRITICAL/HIGH/MEDIUM/LOW
- `sanitize_year()` — chỉ chấp nhận 1999-2099
- `sanitize_search()` — escape `%`, `_`, convert `*` → `%`, max 200 chars
- CVE ID validation — regex `^CVE-\d{4}-\d+$` trước khi redirect

### Open Redirect Prevention
- Chỉ redirect đến internal paths (`/cves/...`), KHÔNG redirect đến URL từ user input

### Path Traversal Prevention
- `<path:>` route params chỉ dùng làm DB lookup keys, KHÔNG dùng làm file paths

### Dependency Security
- KHÔNG dùng `eval()`, `exec()`, `os.system()` với user input
- Subprocess calls trong sync scripts chỉ dùng hardcoded commands, KHÔNG interpolate user input
