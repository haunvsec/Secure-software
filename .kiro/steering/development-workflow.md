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
