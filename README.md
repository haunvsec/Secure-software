# Secure Software Board

Ứng dụng web tra cứu lỗ hổng bảo mật (CVE) và security advisories, gợi ý phiên bản an toàn cho phần mềm.

## Tính năng

- Tra cứu ~346,000 CVE từ cvelistV5, duyệt theo vendor/product/severity/CWE/ngày/assigner
- 1,176 security advisories từ 27+ nguồn (Cisco, GitLab, Jenkins, Spring, AWS, ...)
- Gợi ý phiên bản an toàn tích hợp advisory data, cảnh báo End of Support
- Phạm vi phiên bản bị ảnh hưởng với link đến danh sách CVE
- Hỗ trợ CVSS v2/v3/v4
- Tìm kiếm đa tiêu chí với wildcard
- Tự động sync dữ liệu mỗi giờ (APScheduler)
- API endpoint `/api/sync/status`

## Yêu cầu

- Python 3.11+
- MariaDB 11.x
- Git (cho sync jobs)
- Podman hoặc Docker (cho container deployment)

## Deploy với Podman/Docker (Khuyến nghị)

### Bước 1: Chuẩn bị dữ liệu

```bash
# Clone dữ liệu CVE
git clone --depth=1 https://github.com/CVEProject/cvelistV5.git

# Clone dữ liệu advisory
git clone --depth=1 https://github.com/haunvsec/security-advisory-db.git

# Import vào SQLite (nhanh, ~60s)
pip install -r requirements.txt
python scripts/import_cves.py
ADVISORY_DIR=security-advisory-db python scripts/import_advisories_sqlite.py
```

### Bước 2: Cấu hình

```bash
cp .env.example .env
# Chỉnh sửa .env nếu cần (port, credentials, ...)
```

### Bước 3: Build và chạy

```bash
podman-compose up -d
```

### Bước 4: Migrate dữ liệu vào MariaDB

```bash
# Chờ MariaDB healthy (~30s), rồi migrate từ SQLite
SQLITE_PATH=cve_database.db python scripts/migrate_to_mysql.py
```

Truy cập http://localhost:5005

## Cấu trúc dự án

```
├── src/                    # Application source (MVC)
│   ├── app.py              # Flask app factory
│   ├── config.py           # Configuration (DATABASE_URL)
│   ├── database.py         # SQLAlchemy engine, session, cache
│   ├── filters.py          # Jinja2 template filters
│   ├── scheduler.py        # APScheduler (sync mỗi giờ phút 15)
│   ├── safe_version.py     # Safe version algorithm
│   ├── controllers/        # Flask Blueprints
│   │   ├── main.py         # Homepage
│   │   ├── cves.py         # CVE list + detail
│   │   ├── browse.py       # By date/type/severity/assigner
│   │   ├── vendors.py      # Vendor list + detail
│   │   ├── products.py     # Product detail/versions/fixed
│   │   ├── search.py       # Search
│   │   ├── advisories.py   # Advisory list + detail
│   │   └── api.py          # /api/sync/status
│   ├── models/             # SQLAlchemy ORM + query functions
│   │   ├── orm.py          # Re-exports all ORM classes
│   │   ├── cve.py          # Cve, AffectedProduct, CvssScore, CweEntry, Reference
│   │   ├── advisory.py     # SecurityAdvisory, AdvisoryAffectedProduct, AdvisoryCve, AdvisoryReference
│   │   └── queries.py      # Complex query functions (pagination, stats, search)
│   ├── templates/          # Jinja2 templates + Bootstrap 5
│   └── static/             # CSS, JS, fonts (Bootstrap served locally)
├── scripts/                # Import & sync scripts
│   ├── import_cves.py              # Full CVE import → SQLite
│   ├── import_cves_mysql.py        # Full CVE import → MariaDB (direct)
│   ├── import_advisories.py        # Advisory parser + MariaDB import
│   ├── import_advisories_sqlite.py # Advisory import → SQLite
│   ├── sync_cves.py                # Incremental CVE sync (git pull + diff)
│   ├── sync_advisories.py          # Incremental advisory sync (git pull + diff)
│   ├── migrate_to_mysql.py         # SQLite → MariaDB batch migration
│   ├── create_mysql_schema.sql     # MariaDB schema DDL
│   ├── entrypoint.sh               # Container entrypoint (gunicorn)
│   └── init_db.sh                  # DB initialization helper
├── tests/                  # Property-based tests (Hypothesis) + unit tests
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── .env.example
```

## Database Schema

MariaDB only (SQLAlchemy ORM). Bảng chính:

| Bảng | Rows | Mô tả |
|---|---|---|
| `cves` | 346,000 | CVE records |
| `affected_products` | 1,107,755 | Sản phẩm bị ảnh hưởng (vendor/product/version) |
| `cvss_scores` | 189,693 | Điểm CVSS v2/v3/v4 |
| `cwe_entries` | 326,888 | CWE classifications |
| `references_table` | 1,113,847 | URL tham khảo |
| `security_advisories` | 1,176 | Security advisories |
| `advisory_affected_products` | 535 | Sản phẩm bị ảnh hưởng (vendor/product trực tiếp từ JSON) |
| `advisory_cves` | 13,848 | CVE liên kết với advisory |
| `advisory_references` | 2,037 | URL tham khảo advisory |

Ghi chú: `affected_products.product/platform/version_*` dùng TEXT vì dữ liệu CVE thực tế có giá trị lên tới 2048 ký tự.

## Environment Variables

| Variable | Default | Mô tả |
|---|---|---|
| `DATABASE_URL` | — | SQLAlchemy URL (ưu tiên nếu có) |
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
