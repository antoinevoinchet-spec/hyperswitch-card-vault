-- Append-only audit trail: one row per vault operation, metadata only.
CREATE TABLE IF NOT EXISTS audit_log (
    audit_id VARCHAR(64) NOT NULL PRIMARY KEY,
    created_at TIMESTAMP NOT NULL,
    request_id VARCHAR(64),
    tenant_id VARCHAR(64) NOT NULL,
    operation VARCHAR(32) NOT NULL,
    merchant_id VARCHAR(255),
    customer_id VARCHAR(255),
    resource_id VARCHAR(255),
    outcome VARCHAR(16) NOT NULL,
    status_code SMALLINT NOT NULL,
    error_type VARCHAR(64)
);

CREATE INDEX IF NOT EXISTS audit_log_created_at_index ON audit_log (created_at);
