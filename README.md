# Secure Software Board

Ứng dụng web tra cứu lỗ hổng bảo mật (CVE) và security advisories, gợi ý phiên bản an toàn cho phần mềm.

## Tính năng

- Tra cứu ~346,000 CVE từ cvelistV5, duyệt theo vendor/product/severity/CWE/ngày/assigner
- 839 security advisories từ 27 nguồn (Cisco, GitLab, Jenkins, Spring, AWS, ...)
- Gợi ý phiên bản an toàn tích hợp advisory data, cảnh báo End of Support
- Phạm vi phiên bản bị ảnh hưởng với link đến danh sách CVE
- Hỗ trợ CVSS v2/v3/v4
- Tìm kiếm đa tiêu chí với wildcard
- Tự động sync dữ liệu mỗi giờ (phút thứ 15)
- API endpoint `/api/sync/status`

## Yêu cầu

- Python 3.11+
- Git (cho sync jobs)
- Podman hoặc Docker (cho container deployment)

## Cài đặt nhanh (Development)

```bash
# Clone repo
git clone https://github.com/haunvsec/Secure-software.git
cd Secure-software

# Cài dependencies
pip install -r requirements.txt

# Clone dữ liệu CVE
git clone --depth=1 https://github.com/CVEProject/cvelistV5.git

# Clone dữ liệu advisory
git clone --depth=1 https://github.com/haunvsec/security-advisory-db.git

# Import dữ liệu CVE vào SQLite
python scripts/import_cves.py

# Import dữ liệu advisory
python scripts/import_advisories.py

# Chạy ứng dụng
SQLITE_PATH=cve_database.db python src/app.py
```

Truy cập http://localhost:5000

## Deploy với Podman/Docker

### Bước 1: Chuẩn bị dữ liệu

```bash
# Clone và import dữ liệu (nếu chưa có cve_database.db)
git clone --depth=1 https://github.com/CVEProject/cvelistV5.git
python scripts/import_cves.py
python scripts/import_advisories.py
```

### Bước 2: Cấu hình

```bash
cp .env.example .env
# Chỉnh sửa .env nếu cần (port, credentials, ...)
```

### Bước 3: Build và chạy

```bash
# Podman
podman build -t ssb-app .
podman run -d --name ssb-app -p 5005:5000 \
  -e DB_TYPE=sqlite \
  -e SQLITE_PATH=/app/cve_database.db \
  ssb-app:latest

# Hoặc dùng docker-compose / podman-compose
podman-compose up -d app
```

Truy cập http://localhost:5005

### Bước 4 (Tùy chọn): Chạy với MariaDB

```bash
# Start cả app + MariaDB
DB_TYPE=mysql podman-compose --profile mysql up -d

# Migrate dữ liệu từ SQLite sang MariaDB
python scripts/migrate_to_mysql.py
```

## Cấu trúc dự án

```
├── src/                    # Application source (MVC)
│   ├── app.py              # Flask app factory
│   ├── config.py           # Configuration
│   ├── database.py         # DB connection (SQLite/MariaDB)
│   ├── filters.py          # Jinja2 template filters
│   ├── scheduler.py        # APScheduler (sync mỗi giờ)
│   ├── safe_version.py     # Safe version algorithm
│   ├── controllers/        # Route handlers (Blueprints)
│   │   ├── main.py         # Homepage
│   │   ├── cves.py         # CVE list + detail
│   │   ├── browse.py       # By date/type/severity/assigner
│   │   ├── vendors.py      # Vendor list + detail
│   │   ├── products.py     # Product detail/versions/fixed
│   │   ├── search.py       # Search
│   │   ├── advisories.py   # Advisory list + detail
│   │   └── api.py          # API endpoints
│   ├── models/             # Database queries
│   │   ├── helpers.py      # DB helpers, sanitization, pagination
│   │   ├── cves.py         # CVE queries
│   │   ├── browse.py       # Browse queries
│   │   ├── vendors.py      # Vendor/product queries
│   │   ├── products.py     # Version/fixed queries
│   │   ├── search.py       # Search queries
│   │   └── advisories.py   # Advisory queries
│   ├── templates/          # Jinja2 templates
│   └── static/             # CSS, JS, fonts
├── scripts/                # Import & sync scripts
│   ├── import_cves.py      # Full CVE import
│   ├── import_advisories.py # Full advisory import
│   ├── sync_cves.py        # Incremental CVE sync
│   ├── sync_advisories.py  # Incremental advisory sync
│   ├── migrate_to_mysql.py # SQLite → MariaDB migration
│   ├── create_mysql_schema.sql
│   └── init_db.sh
├── tests/                  # 70 tests (unit + property-based)
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── .env.example
```

## Environment Variables

| Variable | Default | Mô tả |
|---|---|---|
| `DB_TYPE` | `sqlite` | `sqlite` hoặc `mysql` |
| `SQLITE_PATH` | `cve_database.db` | Đường dẫn file SQLite |
| `DB_HOST` | `localhost` | MariaDB host |
| `DB_PORT` | `3306` | MariaDB port |
| `DB_USER` | `cvedb` | MariaDB user |
| `DB_PASSWORD` | `cvedb` | MariaDB password |
| `DB_NAME` | `cve_database` | Database name |
| `APP_PORT` | `5005` | Port expose cho container |
| `SYNC_INTERVAL_HOURS` | `1` | Chu kỳ sync (giờ) |
| `DISABLE_SCHEDULER` | `false` | Tắt scheduler |
| `CVE_REPO_PATH` | `cvelistV5` | Đường dẫn repo CVE |
| `ADVISORY_REPO_PATH` | `security-advisory-db` | Đường dẫn repo advisory |

## API

| Endpoint | Method | Mô tả |
|---|---|---|
| `/api/sync/status` | GET | Trạng thái sync CVE và advisory |

## Testing

```bash
python -m pytest tests/ -v
```

## License

MIT
