-- =============================================================================
-- Enterprise GRC Platform — PostgreSQL Database Schema
-- Multi-tenant with Row-Level Security (RLS) via org_id
-- =============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================================================
-- ENUMS
-- =============================================================================

CREATE TYPE user_role AS ENUM ('super_admin','admin','ciso','risk_manager','auditor','viewer');
CREATE TYPE risk_status AS ENUM ('open','in_treatment','accepted','closed','transferred');
CREATE TYPE risk_likelihood AS ENUM ('rare','unlikely','possible','likely','almost_certain');
CREATE TYPE risk_impact AS ENUM ('negligible','minor','moderate','major','critical');
CREATE TYPE control_type AS ENUM ('preventive','detective','corrective','deterrent','compensating');
CREATE TYPE control_status AS ENUM ('implemented','partially_implemented','planned','not_implemented');
CREATE TYPE policy_status AS ENUM ('draft','under_review','approved','published','retired');
CREATE TYPE incident_status AS ENUM ('detected','triaged','contained','eradicated','recovered','closed');
CREATE TYPE incident_severity AS ENUM ('p1_critical','p2_high','p3_medium','p4_low');
CREATE TYPE finding_severity AS ENUM ('critical','major','minor','observation');
CREATE TYPE finding_status AS ENUM ('open','in_remediation','remediated','accepted','closed');
CREATE TYPE framework_name AS ENUM ('ISO_27001','SOC2','PCI_DSS','NIST_CSF','HIPAA','GDPR','NIST_800_53','CIS_v8');
CREATE TYPE evidence_type AS ENUM ('document','screenshot','log','report','certificate','other');

-- =============================================================================
-- ORGANIZATIONS (Multi-Tenant Root)
-- =============================================================================

CREATE TABLE organizations (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            VARCHAR(255) NOT NULL,
    slug            VARCHAR(100) UNIQUE NOT NULL,
    industry        VARCHAR(100),
    country         VARCHAR(100),
    subscription    VARCHAR(50) DEFAULT 'enterprise',
    settings        JSONB DEFAULT '{}',
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_orgs_slug ON organizations(slug);

-- =============================================================================
-- USERS & AUTH
-- =============================================================================

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email           VARCHAR(255) NOT NULL,
    password_hash   TEXT NOT NULL,
    first_name      VARCHAR(100) NOT NULL,
    last_name       VARCHAR(100) NOT NULL,
    role            user_role NOT NULL DEFAULT 'viewer',
    mfa_enabled     BOOLEAN DEFAULT FALSE,
    mfa_secret      TEXT,                           -- TOTP secret (encrypted)
    is_active       BOOLEAN DEFAULT TRUE,
    last_login_at   TIMESTAMPTZ,
    password_changed_at TIMESTAMPTZ DEFAULT NOW(),
    failed_login_attempts INT DEFAULT 0,
    locked_until    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(org_id, email)
);

CREATE INDEX idx_users_org ON users(org_id);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(org_id, role);

CREATE TABLE refresh_tokens (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL UNIQUE,
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked         BOOLEAN DEFAULT FALSE,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash);

-- =============================================================================
-- AUDIT LOGS (Immutable — append only)
-- =============================================================================

CREATE TABLE audit_logs (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id          UUID NOT NULL,
    user_id         UUID,
    action          VARCHAR(100) NOT NULL,          -- e.g. 'risk.create', 'user.login'
    resource_type   VARCHAR(100),
    resource_id     UUID,
    old_values      JSONB,
    new_values      JSONB,
    ip_address      INET,
    user_agent      TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_audit_org ON audit_logs(org_id, created_at DESC);
CREATE INDEX idx_audit_user ON audit_logs(user_id, created_at DESC);
CREATE INDEX idx_audit_resource ON audit_logs(resource_type, resource_id);

-- =============================================================================
-- ASSETS
-- =============================================================================

CREATE TABLE assets (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    asset_type      VARCHAR(100),                   -- server, application, database, cloud, physical
    owner_id        UUID REFERENCES users(id),
    classification  VARCHAR(50),                    -- public, internal, confidential, restricted
    description     TEXT,
    tags            TEXT[],
    metadata        JSONB DEFAULT '{}',
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_assets_org ON assets(org_id);
CREATE INDEX idx_assets_owner ON assets(owner_id);

-- =============================================================================
-- RISKS
-- =============================================================================

CREATE TABLE risks (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id              UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    risk_id             VARCHAR(50) NOT NULL,        -- e.g. RSK-2024-001
    title               VARCHAR(500) NOT NULL,
    description         TEXT,
    category            VARCHAR(100),                -- cyber, operational, compliance, strategic
    asset_id            UUID REFERENCES assets(id),
    owner_id            UUID REFERENCES users(id),
    reviewer_id         UUID REFERENCES users(id),
    status              risk_status DEFAULT 'open',
    likelihood          risk_likelihood NOT NULL,
    impact              risk_impact NOT NULL,
    inherent_score      NUMERIC(4,2) GENERATED ALWAYS AS (
        CASE likelihood
            WHEN 'rare' THEN 1
            WHEN 'unlikely' THEN 2
            WHEN 'possible' THEN 3
            WHEN 'likely' THEN 4
            WHEN 'almost_certain' THEN 5
        END *
        CASE impact
            WHEN 'negligible' THEN 1
            WHEN 'minor' THEN 2
            WHEN 'moderate' THEN 3
            WHEN 'major' THEN 4
            WHEN 'critical' THEN 5
        END
    ) STORED,
    residual_likelihood risk_likelihood,
    residual_impact     risk_impact,
    residual_score      NUMERIC(4,2),
    treatment_strategy  VARCHAR(50),                 -- mitigate, accept, transfer, avoid
    treatment_notes     TEXT,
    review_date         DATE,
    target_date         DATE,
    tags                TEXT[],
    created_by          UUID REFERENCES users(id),
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(org_id, risk_id)
);

CREATE INDEX idx_risks_org ON risks(org_id);
CREATE INDEX idx_risks_status ON risks(org_id, status);
CREATE INDEX idx_risks_owner ON risks(owner_id);
CREATE INDEX idx_risks_score ON risks(org_id, inherent_score DESC);
CREATE INDEX idx_risks_asset ON risks(asset_id);

-- =============================================================================
-- CONTROLS
-- =============================================================================

CREATE TABLE controls (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id              UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    control_id          VARCHAR(50) NOT NULL,        -- e.g. CTL-001
    title               VARCHAR(500) NOT NULL,
    description         TEXT,
    control_type        control_type NOT NULL,
    status              control_status DEFAULT 'not_implemented',
    effectiveness       NUMERIC(5,2) DEFAULT 0,      -- 0-100 percent
    owner_id            UUID REFERENCES users(id),
    review_frequency    VARCHAR(50),                 -- monthly, quarterly, annually
    last_reviewed_at    TIMESTAMPTZ,
    next_review_date    DATE,
    implementation_notes TEXT,
    testing_procedure   TEXT,
    created_by          UUID REFERENCES users(id),
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(org_id, control_id)
);

CREATE INDEX idx_controls_org ON controls(org_id);
CREATE INDEX idx_controls_status ON controls(org_id, status);
CREATE INDEX idx_controls_owner ON controls(owner_id);

-- Risk-Control Mapping (many-to-many)
CREATE TABLE risk_controls (
    risk_id     UUID NOT NULL REFERENCES risks(id) ON DELETE CASCADE,
    control_id  UUID NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
    notes       TEXT,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (risk_id, control_id)
);

CREATE INDEX idx_risk_controls_control ON risk_controls(control_id);

-- =============================================================================
-- COMPLIANCE FRAMEWORKS
-- =============================================================================

CREATE TABLE frameworks (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            framework_name NOT NULL,
    version         VARCHAR(50),                    -- e.g. '2022', 'Type II'
    description     TEXT,
    total_requirements INT DEFAULT 0,
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE framework_requirements (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    framework_id    UUID NOT NULL REFERENCES frameworks(id) ON DELETE CASCADE,
    requirement_id  VARCHAR(50) NOT NULL,           -- e.g. A.8.1, CC6.1
    title           VARCHAR(500) NOT NULL,
    description     TEXT,
    category        VARCHAR(200),
    parent_id       UUID REFERENCES framework_requirements(id),
    sort_order      INT DEFAULT 0,
    UNIQUE(framework_id, requirement_id)
);

CREATE INDEX idx_req_framework ON framework_requirements(framework_id);

-- Organization's compliance status per framework
CREATE TABLE org_frameworks (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    framework_id    UUID NOT NULL REFERENCES frameworks(id),
    is_active       BOOLEAN DEFAULT TRUE,
    target_date     DATE,
    certification_date DATE,
    certification_expiry DATE,
    notes           TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(org_id, framework_id)
);

-- Control-to-Framework Requirement Mapping (many-to-many)
CREATE TABLE control_framework_mappings (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    control_id      UUID NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
    requirement_id  UUID NOT NULL REFERENCES framework_requirements(id) ON DELETE CASCADE,
    compliance_status VARCHAR(50) DEFAULT 'not_assessed',  -- compliant, partial, non_compliant, not_assessed
    gap_description TEXT,
    notes           TEXT,
    mapped_at       TIMESTAMPTZ DEFAULT NOW(),
    mapped_by       UUID REFERENCES users(id),
    UNIQUE(org_id, control_id, requirement_id)
);

CREATE INDEX idx_cfm_org ON control_framework_mappings(org_id);
CREATE INDEX idx_cfm_control ON control_framework_mappings(control_id);
CREATE INDEX idx_cfm_requirement ON control_framework_mappings(requirement_id);

-- =============================================================================
-- POLICIES
-- =============================================================================

CREATE TABLE policies (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    policy_id       VARCHAR(50) NOT NULL,
    title           VARCHAR(500) NOT NULL,
    description     TEXT,
    category        VARCHAR(100),
    status          policy_status DEFAULT 'draft',
    version         VARCHAR(20) DEFAULT '1.0',
    content         TEXT,                           -- full policy text
    owner_id        UUID REFERENCES users(id),
    approver_id     UUID REFERENCES users(id),
    approved_at     TIMESTAMPTZ,
    effective_date  DATE,
    review_date     DATE,
    expiry_date     DATE,
    created_by      UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(org_id, policy_id)
);

CREATE INDEX idx_policies_org ON policies(org_id);
CREATE INDEX idx_policies_status ON policies(org_id, status);

CREATE TABLE policy_versions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_id       UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    version         VARCHAR(20) NOT NULL,
    content         TEXT,
    changed_by      UUID REFERENCES users(id),
    change_summary  TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_policy_versions ON policy_versions(policy_id, version);

CREATE TABLE policy_acknowledgements (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_id       UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    acknowledged_at TIMESTAMPTZ DEFAULT NOW(),
    ip_address      INET,
    UNIQUE(policy_id, user_id)
);

-- =============================================================================
-- INCIDENTS (CCMP)
-- =============================================================================

CREATE TABLE incidents (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    incident_id     VARCHAR(50) NOT NULL,
    title           VARCHAR(500) NOT NULL,
    description     TEXT,
    severity        incident_severity NOT NULL,
    status          incident_status DEFAULT 'detected',
    category        VARCHAR(100),                   -- data_breach, ransomware, phishing, ddos, insider
    affected_assets JSONB DEFAULT '[]',
    affected_users_count INT,
    data_exfiltrated BOOLEAN DEFAULT FALSE,
    reported_by     UUID REFERENCES users(id),
    assigned_to     UUID REFERENCES users(id),
    incident_commander UUID REFERENCES users(id),
    detected_at     TIMESTAMPTZ NOT NULL,
    contained_at    TIMESTAMPTZ,
    resolved_at     TIMESTAMPTZ,
    closed_at       TIMESTAMPTZ,
    regulatory_notification_required BOOLEAN DEFAULT FALSE,
    regulatory_notified_at TIMESTAMPTZ,
    root_cause      TEXT,
    lessons_learned TEXT,
    estimated_impact NUMERIC(15,2),
    tags            TEXT[],
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(org_id, incident_id)
);

CREATE INDEX idx_incidents_org ON incidents(org_id);
CREATE INDEX idx_incidents_status ON incidents(org_id, status);
CREATE INDEX idx_incidents_severity ON incidents(org_id, severity);
CREATE INDEX idx_incidents_assigned ON incidents(assigned_to);

CREATE TABLE incident_timeline (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id     UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    action          VARCHAR(200) NOT NULL,
    description     TEXT,
    performed_by    UUID REFERENCES users(id),
    performed_at    TIMESTAMPTZ DEFAULT NOW(),
    attachments     JSONB DEFAULT '[]'
);

CREATE INDEX idx_incident_timeline ON incident_timeline(incident_id, performed_at);

-- =============================================================================
-- AUDIT & EVIDENCE
-- =============================================================================

CREATE TABLE audit_engagements (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    audit_id        VARCHAR(50) NOT NULL,
    title           VARCHAR(500) NOT NULL,
    audit_type      VARCHAR(100),                   -- internal, external, regulatory, penetration
    framework_id    UUID REFERENCES frameworks(id),
    lead_auditor_id UUID REFERENCES users(id),
    status          VARCHAR(50) DEFAULT 'planned',  -- planned, in_progress, completed, cancelled
    scope           TEXT,
    start_date      DATE,
    end_date        DATE,
    report_date     DATE,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(org_id, audit_id)
);

CREATE TABLE audit_findings (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    engagement_id   UUID REFERENCES audit_engagements(id) ON DELETE CASCADE,
    finding_id      VARCHAR(50) NOT NULL,
    title           VARCHAR(500) NOT NULL,
    description     TEXT,
    severity        finding_severity NOT NULL,
    status          finding_status DEFAULT 'open',
    control_id      UUID REFERENCES controls(id),
    requirement_id  UUID REFERENCES framework_requirements(id),
    recommendation  TEXT,
    management_response TEXT,
    owner_id        UUID REFERENCES users(id),
    due_date        DATE,
    remediated_at   TIMESTAMPTZ,
    verified_by     UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_findings_org ON audit_findings(org_id);
CREATE INDEX idx_findings_status ON audit_findings(org_id, status);
CREATE INDEX idx_findings_engagement ON audit_findings(engagement_id);

CREATE TABLE evidence (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    evidence_id     VARCHAR(50) NOT NULL,
    title           VARCHAR(500) NOT NULL,
    description     TEXT,
    evidence_type   evidence_type NOT NULL,
    file_name       VARCHAR(500),
    file_path       TEXT,                           -- S3/storage path
    file_size       BIGINT,
    mime_type       VARCHAR(100),
    checksum        TEXT,                           -- SHA-256 for integrity
    control_id      UUID REFERENCES controls(id),
    finding_id      UUID REFERENCES audit_findings(id),
    requirement_id  UUID REFERENCES framework_requirements(id),
    collected_by    UUID REFERENCES users(id),
    collection_date DATE,
    expiry_date     DATE,
    tags            TEXT[],
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_evidence_org ON evidence(org_id);
CREATE INDEX idx_evidence_control ON evidence(control_id);
CREATE INDEX idx_evidence_finding ON evidence(finding_id);

-- =============================================================================
-- KPIs / KRIs
-- =============================================================================

CREATE TABLE kri_metrics (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    metric_id       VARCHAR(50) NOT NULL,
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    category        VARCHAR(100),                   -- risk, compliance, operational
    unit            VARCHAR(50),                    -- percent, count, days, score
    threshold_green NUMERIC(10,2),
    threshold_amber NUMERIC(10,2),
    threshold_red   NUMERIC(10,2),
    current_value   NUMERIC(10,2),
    target_value    NUMERIC(10,2),
    trend           VARCHAR(20),                    -- improving, stable, deteriorating
    owner_id        UUID REFERENCES users(id),
    last_updated_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE kri_measurements (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    metric_id       UUID NOT NULL REFERENCES kri_metrics(id) ON DELETE CASCADE,
    value           NUMERIC(10,2) NOT NULL,
    notes           TEXT,
    recorded_by     UUID REFERENCES users(id),
    recorded_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_kri_org ON kri_metrics(org_id);
CREATE INDEX idx_kri_measurements ON kri_measurements(metric_id, recorded_at DESC);

-- =============================================================================
-- NOTIFICATIONS
-- =============================================================================

CREATE TABLE notifications (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         UUID REFERENCES users(id),
    title           VARCHAR(255) NOT NULL,
    body            TEXT,
    type            VARCHAR(100),                   -- risk_alert, incident_open, compliance_gap
    severity        VARCHAR(50),                    -- info, warning, critical
    resource_type   VARCHAR(100),
    resource_id     UUID,
    is_read         BOOLEAN DEFAULT FALSE,
    read_at         TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_notifications_user ON notifications(user_id, is_read, created_at DESC);

-- =============================================================================
-- VIEWS (Convenience)
-- =============================================================================

CREATE VIEW v_risk_summary AS
SELECT
    r.org_id,
    COUNT(*) AS total_risks,
    COUNT(*) FILTER (WHERE r.inherent_score >= 15) AS critical_risks,
    COUNT(*) FILTER (WHERE r.inherent_score BETWEEN 9 AND 14) AS high_risks,
    COUNT(*) FILTER (WHERE r.inherent_score BETWEEN 4 AND 8) AS medium_risks,
    COUNT(*) FILTER (WHERE r.inherent_score < 4) AS low_risks,
    COUNT(*) FILTER (WHERE r.status = 'open') AS open_risks,
    COUNT(*) FILTER (WHERE r.status = 'accepted') AS accepted_risks,
    ROUND(AVG(r.inherent_score), 2) AS avg_inherent_score,
    ROUND(AVG(r.residual_score), 2) AS avg_residual_score
FROM risks r
GROUP BY r.org_id;

CREATE VIEW v_compliance_score AS
SELECT
    cfm.org_id,
    f.name AS framework_name,
    COUNT(*) AS total_mappings,
    COUNT(*) FILTER (WHERE cfm.compliance_status = 'compliant') AS compliant,
    COUNT(*) FILTER (WHERE cfm.compliance_status = 'partial') AS partial,
    COUNT(*) FILTER (WHERE cfm.compliance_status = 'non_compliant') AS non_compliant,
    ROUND(
        100.0 * COUNT(*) FILTER (WHERE cfm.compliance_status = 'compliant') / NULLIF(COUNT(*), 0),
        1
    ) AS compliance_percentage
FROM control_framework_mappings cfm
JOIN framework_requirements fr ON cfm.requirement_id = fr.id
JOIN frameworks f ON fr.framework_id = f.id
GROUP BY cfm.org_id, f.name;

-- =============================================================================
-- SEED DATA — Frameworks
-- =============================================================================

INSERT INTO frameworks (name, version, description, total_requirements) VALUES
('ISO_27001', '2022', 'Information Security Management System Standard', 93),
('SOC2', 'Type II', 'Service Organization Control 2 - Trust Services Criteria', 64),
('PCI_DSS', 'v4.0', 'Payment Card Industry Data Security Standard', 281),
('NIST_CSF', '2.0', 'NIST Cybersecurity Framework', 108),
('HIPAA', '2024', 'Health Insurance Portability and Accountability Act', 54),
('GDPR', '2018', 'General Data Protection Regulation', 99),
('NIST_800_53', 'Rev5', 'NIST SP 800-53 Security and Privacy Controls', 1000),
('CIS_v8', 'v8.1', 'CIS Critical Security Controls', 153);

-- =============================================================================
-- ER DIAGRAM (Text representation)
-- =============================================================================
--
-- organizations (1) ─────────────────────────── (N) users
--      │                                              │
--      ├──────────────────────────────────────── (N) assets
--      │                                              │
--      ├──────────────────────────────────────── (N) risks ──(M:N)── controls
--      │                                                        │
--      ├──────────────────────────────────────── (N) policies   │
--      │                                                        │
--      ├──────────────────────────────────────── (N) incidents  │
--      │                                                        │
--      ├──────────────────────────────────────── (N) audit_engagements
--      │                                              │
--      │                                         (N) audit_findings
--      │                                              │
--      ├──────────────────────────────────────── (N) evidence
--      │
-- frameworks (1) ──── (N) framework_requirements ─(M:N)─ controls
--                                                           (via control_framework_mappings)
