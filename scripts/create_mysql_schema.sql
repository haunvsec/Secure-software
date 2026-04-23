-- MariaDB schema for Secure Software Board
-- Equivalent to SQLite schema with proper MariaDB types

CREATE DATABASE IF NOT EXISTS cve_database
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE cve_database;

-- CVE records
CREATE TABLE IF NOT EXISTS cves (
    cve_id VARCHAR(30) PRIMARY KEY,
    state VARCHAR(20),
    assigner_org_id VARCHAR(100),
    assigner_short_name VARCHAR(100),
    date_reserved VARCHAR(30),
    date_published VARCHAR(30),
    date_updated VARCHAR(30),
    description TEXT,
    severity VARCHAR(20),
    data_version VARCHAR(20),
    INDEX idx_cves_state (state),
    INDEX idx_cves_date_published (date_published),
    INDEX idx_cves_severity (severity),
    INDEX idx_cves_assigner (assigner_short_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Affected products
CREATE TABLE IF NOT EXISTS affected_products (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(30) NOT NULL,
    vendor VARCHAR(1024),
    product TEXT,
    platform TEXT,
    version_start TEXT,
    version_end TEXT,
    version_exact TEXT,
    default_status VARCHAR(50),
    status VARCHAR(50),
    version_end_type VARCHAR(30),
    INDEX idx_affected_vendor (vendor),
    INDEX idx_affected_product (product(255)),
    INDEX idx_affected_vendor_product (vendor(255), product(255)),
    INDEX idx_affected_cve (cve_id),
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- CVSS scores
CREATE TABLE IF NOT EXISTS cvss_scores (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(30) NOT NULL,
    version VARCHAR(10),
    vector_string VARCHAR(255),
    base_score DECIMAL(4,1),
    base_severity VARCHAR(20),
    attack_vector VARCHAR(30),
    attack_complexity VARCHAR(30),
    privileges_required VARCHAR(30),
    user_interaction VARCHAR(30),
    scope VARCHAR(30),
    confidentiality_impact VARCHAR(30),
    integrity_impact VARCHAR(30),
    availability_impact VARCHAR(30),
    source VARCHAR(50) DEFAULT 'cna',
    INDEX idx_cvss_cve (cve_id),
    INDEX idx_cvss_score (base_score),
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- CWE entries
CREATE TABLE IF NOT EXISTS cwe_entries (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(30) NOT NULL,
    cwe_id VARCHAR(30),
    description TEXT,
    INDEX idx_cwe_cve (cve_id),
    INDEX idx_cwe_id (cwe_id),
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- References
CREATE TABLE IF NOT EXISTS references_table (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(30) NOT NULL,
    url TEXT,
    tags TEXT,
    INDEX idx_refs_cve (cve_id),
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Security advisories
CREATE TABLE IF NOT EXISTS security_advisories (
    id VARCHAR(255) PRIMARY KEY,
    source VARCHAR(50),
    title TEXT,
    description LONGTEXT,
    severity VARCHAR(20),
    cvss_score DECIMAL(4,1),
    cvss_vector VARCHAR(255),
    published_date VARCHAR(50),
    modified_date VARCHAR(50),
    url TEXT,
    vendor VARCHAR(1024),
    solution LONGTEXT,
    json_file VARCHAR(1024),
    INDEX idx_adv_source (source),
    INDEX idx_adv_severity (severity),
    INDEX idx_adv_published (published_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Advisory affected products
CREATE TABLE IF NOT EXISTS advisory_affected_products (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    advisory_id VARCHAR(2048)  NOT NULL,
    vendor VARCHAR(1024),
    product VARCHAR(2048),
    version_range VARCHAR(1024),
    fixed_version VARCHAR(1024),
    INDEX idx_adv_ap_advisory (advisory_id),
    INDEX idx_adv_ap_vendor (vendor),
    INDEX idx_adv_ap_product (product(255)),
    FOREIGN KEY (advisory_id) REFERENCES security_advisories(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Advisory CVEs
CREATE TABLE IF NOT EXISTS advisory_cves (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    advisory_id VARCHAR(2048)  NOT NULL,
    cve_id VARCHAR(30),
    INDEX idx_adv_cves_advisory (advisory_id),
    INDEX idx_adv_cves_cve (cve_id),
    FOREIGN KEY (advisory_id) REFERENCES security_advisories(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Advisory references
CREATE TABLE IF NOT EXISTS advisory_references (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    advisory_id VARCHAR(2048)  NOT NULL,
    url TEXT,
    INDEX idx_adv_refs_advisory (advisory_id),
    FOREIGN KEY (advisory_id) REFERENCES security_advisories(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
