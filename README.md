## Summary

BigQuery offers a comprehensive suite of data security features specifically designed for handling sensitive data. The platform provides multiple layers of protection through:

1. **Dynamic Data Masking** - Real-time obfuscation at query time
2. **Column-Level Encryption** - Tokenization with Cloud KMS integration
3. **Row-Level Security** - Granular access control per user/group
4. **Column-Level Access Control** - Policy tag-based restrictions
5. **Data Tokenization** - Built-in and Cloud DLP integration

These features address both requirements: (1) managing access to sensitive data in production, and (2) obfuscating data for lower environments.

---

## Problem Statement Analysis

### 1. Production Data Access Control
**Challenge:** Restricted data contains sensitive PII (salaries, performance reviews, personal information) that requires strict access controls.

**Solution Approach:** Multi-layered access control combining IAM, row-level security, and column-level security.

### 2. Lower Environment Data Obfuscation
**Challenge:** Development and test environments need realistic data structures but cannot contain actual sensitive information.

**Solution Approach:** Tokenization and dynamic data masking to create de-identified datasets that maintain referential integrity for testing.

---

## Key BigQuery Features for Sensitive Data Security

### 1. Dynamic Data Masking 

**What it is:** Column-level data obfuscation applied at query time based on user roles.

**Key Capabilities:**
- Masks data in real-time without creating duplicate datasets
- 9 different data policies can be configured per policy tag
- Supports multiple masking rules:
  - **Default Masking:** Returns NULL for sensitive columns
  - **Hash (SHA-256):** One-way hash for joins/aggregations
  - **Custom Masking Routine:** User-defined functions for specialized obfuscation
  - **Date Year Mask:** Truncates dates to year only
  - **Last 4 Characters:** Shows only last 4 chars (e.g., "****6789")
  - **First 4 Characters:** Shows only first 4 chars
  - **Email Mask:** Partially masks email addresses
  - **Nullify:** Returns NULL values

**Use Case:**
```sql
-- Example: HR Manager sees full data, Analysts see masked data
-- Salary column shows actual values to HR team
-- Salary column shows hashed values to Analytics team
-- Salary column shows NULL to everyone else
```

**Implementation Steps:**
1. Create policy tags in Data Catalog taxonomy (e.g., "HR-Sensitive", "PII-High")
2. Create data masking rules for each policy tag
3. Assign policy tags to BigQuery columns (e.g., salary, SSN, performance_rating)
4. Grant "BigQuery Masked Reader" role to groups that should see masked data
5. Grant "Data Catalog Fine-Grained Reader" role for full access

**Benefits:**
- No data duplication required
- Single source of truth
- Reduces data sprawl and inconsistency
- Changes to masking rules apply immediately

**Reference:** [Introduction to data masking - BigQuery](https://cloud.google.com/bigquery/docs/column-data-masking-intro)

---

### 2. Column-Level Encryption & Tokenization

**What it is:** Encrypt sensitive columns using Cloud KMS with deterministic or non-deterministic encryption.

**Two Approaches:**

#### A. Native BigQuery Encryption Functions 
```sql
-- Encrypt data in place
UPDATE hr_dataset.employees
SET ssn_encrypted = KEYS.ENCRYPT(
  'projects/PROJECT/locations/LOCATION/keyRings/KEYRING/cryptoKeys/KEY',
  ssn,
  'AEAD_AES_GCM_256'
)
```

**Benefits:**
- Built into BigQuery engine - high performance
- Works at petabyte scale
- No external dependencies during query execution
- Supports deterministic encryption for joins/aggregations

#### B. Cloud DLP Integration for Tokenization
**Use Cases:**
- Batch tokenization of large datasets during migration
- Automatic PII detection and classification
- Format-preserving tokenization (e.g., "123-45-6789" → "987-65-4321")

**Built-in Tokenization (January 2025 Update):**
- Tokenization technology built directly into BigQuery engine
- Compatible with Sensitive Data Protection (Cloud DLP)
- Can tokenize/detokenize in either system with referential integrity
- Serverless, fully regionalized for compliance

**Use Case:**
```sql
-- Tokenize salary data for lower environments
CREATE OR REPLACE TABLE dev_hr.employees AS
SELECT 
  employee_id,
  first_name,
  last_name,
  DLP.TOKENIZE('projects/PROJECT/locations/LOCATION/deidentifyTemplates/TEMPLATE', 
                salary) as salary_tokenized,
  department
FROM prod_hr.employees;
```

**Reference:** 
- [BigQuery Encrypt and Decrypt with Sensitive Data Protection](https://cloud.google.com/blog/products/identity-security/using-bigquery-encrypt-and-decrypt-with-sensitive-data-protection)
- [Get started with built-in tokenization](https://cloud.google.com/blog/products/identity-security/get-started-with-built-in-tokenization-for-sensitive-data-protection)

---

### 3. Row-Level Security (RLS)

**What it is:** Filter access to specific rows in a table based on user identity or group membership.

**Key Capabilities:**
- Up to 100 access policies per table
- Uses SQL filter predicates (like WHERE clauses)
- Supports SESSION_USER() function for dynamic filtering
- Can reference lookup tables for complex access patterns

**Use Case:**
```sql
-- HR Managers only see their department's employees
CREATE OR REPLACE ROW ACCESS POLICY dept_filter
ON hr_dataset.employees
GRANT TO ('group:hr-managers@org.com')
FILTER USING (
  department = (
    SELECT department 
    FROM hr_dataset.manager_assignments 
    WHERE manager_email = SESSION_USER()
  )
);

-- Executive team sees all departments
CREATE OR REPLACE ROW ACCESS POLICY exec_full_access
ON hr_dataset.employees
GRANT TO ('group:exec-team@org.com')
FILTER USING (TRUE);
```

**Important Considerations:**
- Row access policies don't support partition pruning (you pay for scanning all rows)
- Define policies as Infrastructure-as-Code (Terraform/Cloud Build)
- Policies are inherited by views, authorized views, and API access

**Reference:** [BigQuery provides tighter controls over data access](https://cloud.google.com/blog/products/data-analytics/bigquery-provides-tighter-controls-over-data-access)

---

### 4. Column-Level Access Control (Policy Tags)

**What it is:** Control access to specific columns using Data Catalog policy tags.

**Key Capabilities:**
- Create taxonomies of policy tags (e.g., PII hierarchy)
- Assign tags to columns
- Grant "Fine-Grained Reader" role for column access
- Works with dynamic data masking

**Use Case:**
```
HR Taxonomy:
├── HR-Critical (SSN, Bank Details)
├── HR-Sensitive (Salary, Performance Reviews)
├── HR-General (Department, Job Title)
└── HR-Public (Employee ID, First Name)
```

**Access Pattern:**
- HR Admin → Full access to all columns
- HR Manager → Access to HR-Sensitive and below
- Team Lead → Access to HR-General and below
- Employee → Access to HR-Public only

**Benefits:**
- Centralized policy management in Data Catalog
- Policies apply across BigQuery, Cloud Storage (BigLake), and Cloud Spanner
- Automatic enforcement at query time

---

### 5. IAM Roles and Best Practices

**Principle of Least Privilege Implementation:**

| Role | Use Case | Scope |
|------|----------|-------|
| `bigquery.dataViewer` | Read-only access to data | Dataset level |
| `bigquery.dataEditor` | Read/write data, no schema changes | Dataset level |
| `bigquery.dataOwner` | Full dataset control | Dataset level |
| `bigquery.jobUser` | Run queries (required) | Project level |
| `bigquery.admin` | Full BigQuery control | Project level (sparingly) |

**Best Practices:**
1. **Never grant bigquery.admin or dataEditor at project level to humans**
2. **Grant roles at dataset level** for production HR data
3. **Use service accounts** for ETL pipelines with minimal permissions
4. **Separate environments:** prod_hr, staging_hr, dev_hr datasets with different access controls
5. **Use Google Groups** for role assignments (not individual users)

**Example IAM Structure:**
```
Project: org-data-platform
├── Dataset: prod_hr (production HR data)
│   ├── group:hr-admins@org.com → dataOwner
│   ├── group:hr-managers@org.com → dataViewer + RLS policies
│   └── service-account:etl-pipeline@... → dataEditor
├── Dataset: dev_hr (obfuscated HR data)
│   ├── group:developers@org.com → dataViewer
│   └── group:qa-team@prg.com → dataViewer
└── Project-level:
    └── All users → bigquery.jobUser (to run queries)
```

---

## Recommended Solution Architecture

### Phase 1: Production Data Lake (HR Data Access Control)

```
┌─────────────────────────────────────────────────┐
│          Source Systems (Workday/SAP)           │
└────────────────┬────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────┐
│     Data Ingestion (Dataflow/Cloud Function)    │
│     - Service Account with dataEditor role      │
└────────────────┬────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────┐
│        BigQuery: prod_hr Dataset                │
│                                                  │
│  Tables with Security Layers:                   │
│  ├── employees (base table)                     │
│  │   ├── Policy Tags on columns:                │
│  │   │   • ssn → HR-Critical                    │
│  │   │   • salary → HR-Sensitive                │
│  │   │   • department → HR-General              │
│  │   ├── Row-Level Security:                    │
│  │   │   • Managers see their dept only         │
│  │   │   • HR admins see all                    │
│  │   └── Dynamic Data Masking:                  │
│  │       • Analysts see hashed salaries         │
│  │       • Reporting tools see masked SSN       │
│  └── performance_reviews (base table)           │
│      └── Similar security layers                │
└─────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────┐
│     Authorized Views (curated access)           │
│  • hr_analytics_view (for Looker/Tableau)       │
│  • manager_team_view (for managers)             │
│  • payroll_view (for finance)                   │
└─────────────────────────────────────────────────┘
```

**Security Controls:**
1. **IAM at dataset level** - Not project level
2. **Policy tags** on all sensitive columns
3. **Row-level security** for departmental isolation
4. **Dynamic data masking** for different user personas
5. **Audit logging** enabled on all HR datasets
6. **VPC Service Controls** to restrict data access to corporate network only

---

### Phase 2: Lower Environment Data Obfuscation

```
┌─────────────────────────────────────────────────┐
│        BigQuery: prod_hr Dataset                │
└────────────────┬────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────┐
│   Cloud DLP / Dataflow Pipeline                 │
│   - Tokenization with Cloud KMS                 │
│   - Format-preserving encryption                │
│   - Deterministic for referential integrity     │
└────────────────┬────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────┐
│    BigQuery: dev_hr / staging_hr Datasets       │
│                                                  │
│  De-identified Tables:                           │
│  • employees                                     │
│    ├── employee_id (preserved)                   │
│    ├── first_name → "FirstName_001"              │
│    ├── last_name → "LastName_001"                │
│    ├── ssn → tokenized                           │
│    ├── salary → bucketed ranges                  │
│    └── department (preserved for testing)        │
│                                                  │
│  Access: All developers have dataViewer          │
└─────────────────────────────────────────────────┘
```

**Obfuscation Techniques:**
1. **Tokenization:** SSN, bank details → irreversible tokens
2. **Generalization:** Exact salary → salary bands ($50K-$75K)
3. **Synthetic Data:** Real names → generated names with same distribution
4. **Date Shifting:** Birth dates shifted by random offset per person
5. **Format Preservation:** Phone numbers maintain (XXX) XXX-XXXX format

**Implementation Options:**

**Option A: Dataflow + Cloud DLP (Batch Processing)**
- Best for: Initial data load and periodic refreshes
- Uses: [Google's DLP Dataflow template](https://cloud.google.com/dataflow/docs/guides/templates/provided/dlp-text-to-bigquery)
- Process: GCS → Dataflow (DLP API) → BigQuery dev/staging

**Option B: BigQuery Remote Functions (Real-time)**
- Best for: On-demand de-identification
- Uses: BigQuery → Cloud Run (DLP API) → BigQuery
- Process: SQL function calls DLP for tokenization
- Reference: [BigQuery DLP Remote Function](https://github.com/GoogleCloudPlatform/bigquery-dlp-remote-function)

**Option C: Built-in BigQuery Functions (Highest Performance)**
- Best for: Column-level encryption at scale
- Uses: Native `KEYS.ENCRYPT()` / `DLP.TOKENIZE()` functions
- Process: Direct SQL operations in BigQuery engine
- Lowest latency, highest throughput

---

## Implementation Roadmap

### Week 1-2: Foundation
1. ✅ Create GCP Data Catalog taxonomy for HR data classification
2. ✅ Define policy tags hierarchy (Critical, Sensitive, General, Public)
3. ✅ Set up Google Groups for access control (hr-admins, hr-managers, developers)
4. ✅ Create service accounts for data pipelines

### Week 3-4: Production Security
5. ✅ Apply policy tags to all HR table columns
6. ✅ Configure dynamic data masking rules
7. ✅ Implement row-level security policies
8. ✅ Grant IAM roles at dataset level (not project)
9. ✅ Enable Cloud Audit Logs for HR datasets

### Week 5-6: Lower Environment Setup
10. ✅ Set up Cloud KMS key ring and keys for tokenization
11. ✅ Create Cloud DLP de-identification templates
12. ✅ Develop Dataflow pipeline for data obfuscation
13. ✅ Create dev_hr and staging_hr datasets with tokenized data
14. ✅ Test referential integrity and data utility

### Week 7-8: Testing & Validation
15. ✅ User acceptance testing with HR team
16. ✅ Validate masking rules work as expected
17. ✅ Verify developers can use dev environment effectively
18. ✅ Security audit and compliance review
19. ✅ Documentation and training materials

### Ongoing: Maintenance
- Monitor audit logs for suspicious access patterns
- Quarterly review of access policies
- Refresh dev/staging data monthly
- Update masking rules as new sensitive fields are added

---

## Cost Considerations

### Data Masking Costs
- **Dynamic Data Masking:** No additional query cost (masking is free)
- **Query Scanning:** Pay for bytes scanned (same as normal queries)
- **Important:** Row-level security policies scan all rows regardless of filtering

### Tokenization Costs
- **Cloud DLP API:** $1 per 1,000,000 bytes inspected/tokenized (first 1TB/month free for Data Profiling)
- **BigQuery Native Functions:** No additional cost beyond query processing
- **Dataflow:** VM costs for pipeline execution (~$0.04/vCPU-hour)
- **Cloud KMS:** $0.03/key/month + $0.03 per 10,000 encryption operations

**Cost Optimization Tips:**
1. Use BigQuery native tokenization functions where possible (highest performance, lowest cost)
2. Batch tokenization jobs during off-peak hours
3. Use sampling for Cloud DLP classification (don't scan every row)
4. Partition HR tables by date for efficient querying
5. Consider flat-rate pricing if query volume is high

---

## Compliance and Audit

### Data Privacy Regulations
- **GDPR:** Right to access, right to be forgotten, data minimization
- **UK GDPR:** Post-Brexit UK data protection
- **CCPA:** California Consumer Privacy Act (if applicable)

### BigQuery Features for Compliance
1. **Audit Logs:** Track all data access (who, what, when)
2. **Data Deletion:** Support for "right to be forgotten"
3. **Data Lineage:** Understand data flow from source to consumption
4. **Encryption:** Data encrypted at rest and in transit
5. **Regional Data Residency:** Store HR data in UK/EU regions only

### Recommended Audit Practices
```sql
-- Example: Query audit logs for HR data access
SELECT
  timestamp,
  principal_email,
  resource.labels.dataset_id,
  resource.labels.table_id,
  protopayload_auditlog.methodName,
  protopayload_auditlog.requestMetadata.callerIp
FROM
  `PROJECT.logs.cloudaudit_googleapis_com_data_access`
WHERE
  resource.labels.dataset_id = 'prod_hr'
  AND DATE(timestamp) >= CURRENT_DATE() - 30
ORDER BY timestamp DESC;
```

---

## Advanced Features (Future Considerations)

### 1. BigLake for Multi-Cloud HR Data
- Query HR data stored in AWS S3 or Azure Storage
- Apply same security controls (RLS, masking) across clouds
- Reference: [BigQuery Data Governance](https://cloud.google.com/bigquery/docs/data-governance)

### 2. Dataplex for Centralized Governance
- Automatic data discovery and classification
- Centralized metadata management
- Data quality monitoring
- Reference: [Introduction to data governance in BigQuery](https://cloud.google.com/bigquery/docs/data-governance)

### 3. Sensitive Data Protection (Cloud DLP) Automatic Discovery
- Automatically scan and classify sensitive HR data
- Create data profiles showing risk levels
- Reference: [Data profiles for BigQuery data](https://cloud.google.com/sensitive-data-protection/docs/data-profiles-bigquery)

### 4. VPC Service Controls
- Create secure perimeter around HR data
- Block data exfiltration attempts
- Restrict access to corporate network only
- Reference: [VPC Service Controls for BigQuery](https://cloud.google.com/vpc-service-controls/docs/service-restrictions#bigquery)

---

## Security Best Practices Checklist

### Access Control
- [ ] IAM roles granted at dataset level (not project level)
- [ ] Service accounts used for automated processes
- [ ] Google Groups used for user access (not individual accounts)
- [ ] Principle of least privilege enforced
- [ ] Regular access reviews scheduled (quarterly)

### Data Protection
- [ ] Policy tags applied to all sensitive columns
- [ ] Dynamic data masking configured for different user personas
- [ ] Row-level security policies defined
- [ ] Column-level encryption for highly sensitive fields
- [ ] Data tokenized in lower environments

### Monitoring & Audit
- [ ] Cloud Audit Logs enabled for all HR datasets
- [ ] Alerts configured for suspicious access patterns
- [ ] Regular review of audit logs (weekly)
- [ ] Incident response plan documented
- [ ] Compliance reporting automated

### Data Lifecycle
- [ ] Data retention policies defined
- [ ] Automated data deletion for GDPR compliance
- [ ] Backup and disaster recovery plan
- [ ] Data lineage tracked from source to consumption
- [ ] Regular refresh of dev/staging environments (monthly)

---

## References and Resources

### Google Cloud Documentation
1. [BigQuery Data Masking](https://cloud.google.com/bigquery/docs/column-data-masking-intro)
2. [Row-Level Security](https://cloud.google.com/bigquery/docs/row-level-security-intro)
3. [Column-Level Security](https://cloud.google.com/bigquery/docs/column-level-security-intro)
4. [BigQuery IAM Roles](https://cloud.google.com/bigquery/docs/access-control)
5. [Cloud DLP De-identification](https://cloud.google.com/sensitive-data-protection/docs/deidentify-sensitive-data)
6. [Built-in Tokenization](https://cloud.google.com/blog/products/identity-security/get-started-with-built-in-tokenization-for-sensitive-data-protection)

### GitHub Reference Implementations
1. [DLP Dataflow De-identification Pipeline](https://github.com/GoogleCloudPlatform/dlp-dataflow-deidentification)
2. [Auto Data Tokenize](https://github.com/GoogleCloudPlatform/auto-data-tokenize)
3. [BigQuery DLP Remote Function](https://github.com/GoogleCloudPlatform/bigquery-dlp-remote-function)

### Recent Blog Posts (2024-2025)
1. [Dynamic Data Masking on BigQuery - Plumbers of Data Science](https://medium.com/plumbersofdatascience/dynamic-data-masking-on-bigquery-ae3d004b496c)
2. [Using BigQuery Encrypt and Decrypt with Sensitive Data Protection](https://cloud.google.com/blog/products/identity-security/using-bigquery-encrypt-and-decrypt-with-sensitive-data-protection)
3. [The A to Z BigQuery Security Guide - Vasudev Maduri](https://medium.com/google-cloud/comprehensive-bigquery-security-best-practices-958285edc750)

---

## Appendix: Sample Implementation Code

### A. Policy Tag Taxonomy Creation
```bash
# Create taxonomy
gcloud data-catalog taxonomies create hr-taxonomy \
  --location=europe-west2 \
  --display-name="HR Data Classification" \
  --description="Classification for HR sensitive data"

# Create policy tags
gcloud data-catalog taxonomies policy-tags create hr-critical \
  --taxonomy=hr-taxonomy \
  --location=europe-west2 \
  --display-name="HR Critical"

gcloud data-catalog taxonomies policy-tags create hr-sensitive \
  --taxonomy=hr-taxonomy \
  --location=europe-west2 \
  --display-name="HR Sensitive"
```

### B. Apply Policy Tags to Columns
```sql
-- Apply policy tag to salary column
ALTER TABLE prod_hr.employees
ALTER COLUMN salary
SET OPTIONS (
  policy_tags = 'projects/PROJECT/locations/europe-west2/taxonomies/TAXONOMY_ID/policyTags/TAG_ID'
);
```

### C. Create Data Masking Rules
```sql
-- Create data policy for hashing sensitive data
CREATE OR REPLACE DATA POLICY hr_sensitive_hash
ON (
  SELECT policy_tag 
  FROM `PROJECT.TAXONOMY.hr_sensitive`
)
MASKING RULE hash(salary, "SHA256")
GRANT TO ("group:analysts@org.com");
```

### D. Row-Level Security Implementation
```sql
-- Department-based access
CREATE OR REPLACE ROW ACCESS POLICY dept_managers
ON prod_hr.employees
GRANT TO ('group:dept-managers@org.com')
FILTER USING (
  department IN (
    SELECT department 
    FROM prod_hr.manager_assignments
    WHERE manager_email = SESSION_USER()
  )
);
```

### E. Tokenization Pipeline (Dataflow)
```bash
# Deploy DLP tokenization pipeline
gcloud dataflow jobs run hr-tokenization-job \
  --gcs-location=gs://dataflow-templates/latest/DLP_Text_to_BigQuery \
  --region=europe-west2 \
  --parameters \
inputFilePattern=gs://BUCKET/hr-data/*.csv,\
deidentifyTemplateName=projects/PROJECT/locations/global/deidentifyTemplates/TEMPLATE,\
datasetName=dev_hr,\
dlpProjectId=PROJECT
```

---
# Zero-Trust IAM Strategy for BigQuery HR Data
## Preventing Admin Access to Sensitive Data
---

## Executive Summary

**The Challenge:** Traditional cloud IAM models grant broad permissions to administrators, creating insider threat risks where platform admins can access any data, including highly sensitive HR information.

**The Solution:** A defense-in-depth security architecture combining:
1. **Separation of Duties** - Different teams manage infrastructure vs. data access
2. **Data-Centric Security** - Encryption at column level where only HR owns keys
3. **VPC Service Controls** - Network-level perimeter preventing data exfiltration
4. **Break-Glass Procedures** - Audited emergency access with multi-person authorization
5. **Cryptographic Separation** - Cloud KMS with customer-managed keys controlled by HR team

**Key Principle:** "Zero Standing Privileges" - No one, including admins, has permanent access to raw HR data. Access requires justification, approval, time-boxing, and audit trail.

---

## The Problem: Traditional Admin Access Model

### Current Risk Scenario
```
Traditional Cloud IAM Hierarchy:
├── Organization Admin (roles/resourcemanager.organizationAdmin)
│   └── Can see everything in the organization
├── Folder Admin (roles/resourcemanager.folderAdmin)
│   └── Can see everything in folders
├── Project Owner (roles/owner)
│   └── Can see all data in project
└── BigQuery Admin (roles/bigquery.admin)
    └── Can query all datasets and tables
```

**Problems:**
1. ❌ Platform admins can query any table, including HR data
2. ❌ Service account keys can be extracted and used offline
3. ❌ IAM policies can be changed by admins to grant themselves access
4. ❌ Data can be copied to external projects (data exfiltration)
5. ❌ Compliance violations if admins see PII without business need

### Real-World Attack Vectors

#### Vector 1: Direct Query Access
```sql
-- Platform admin can run this query
SELECT * FROM prod_hr.employees
WHERE salary > 100000;
```

#### Vector 2: Table Export
```bash
# Admin can export sensitive data
bq extract \
  --destination_format=CSV \
  prod_hr.employees \
  gs://admin-personal-bucket/hr_data.csv
```

#### Vector 3: Grant Self Access
```bash
# Admin modifies their own permissions
bq update --dataset \
  --add_iam_binding \
  prod_hr \
  --member=user:admin@org.com \
  --role=roles/bigquery.dataOwner
```

#### Vector 4: Service Account Impersonation
```bash
# Admin impersonates HR service account
gcloud auth application-default login --impersonate-service-account=hr-admin@org.iam.gserviceaccount.com

# Now queries data as HR admin
bq query "SELECT * FROM prod_hr.employees"
```

---

## Solution Architecture: Multi-Layered Defense

### Layer 1: Organizational Structure (Separation of Duties)

```
Org GCP Organization
├── Production Folder (Regulated Data)
│   ├── Project: org-hr-data (HR Data)
│   │   ├── Dataset: prod_hr
│   │   │   ├── Tables with encrypted columns
│   │   │   └── Policy tags enforced
│   │   └── IAM: HR team ONLY
│   └── VPC Service Controls Perimeter: "HR-Sensitive"
│
├── Analytics Folder (Curated Data)
│   ├── Project: org-analytics
│   │   ├── Dataset: hr_analytics (authorized views)
│   │   └── IAM: Analysts with masked access
│   └── VPC Service Controls Perimeter: "Analytics"
│
└── Platform Folder (Infrastructure)
    ├── Project: org-platform-admin
    │   ├── No data stored here
    │   └── IAM: Platform admins manage infra only
    └── No VPC Service Controls (admins need flexibility)
```

**Key Design Principles:**
1. **Data Projects ≠ Admin Projects** - HR data lives in separate project from admin access
2. **Folder-Level IAM** - HR team owns the "Production Folder" IAM policies
3. **VPC-SC Isolation** - HR data perimeter blocks all external access by default

---

### Layer 2: IAM Roles & Permissions Strategy

#### Principle: Least Privilege + Separation of Concerns

| Role | Granted To | Scope | What They CAN Do | What They CANNOT Do |
|------|-----------|-------|------------------|---------------------|
| **Organization Admin** | IT Leadership | Organization | • Manage billing<br>• Create folders/projects<br>• Set org policies | • Query any data<br>• Access HR datasets<br>• Grant themselves data access |
| **Platform Admin** | Cloud Engineering | Platform Project | • Manage VMs, networks<br>• Deploy infrastructure<br>• Create datasets (empty) | • Query HR data<br>• Modify HR IAM policies<br>• Access VPC-SC protected data |
| **HR Data Owner** | HR Leadership | HR Data Project | • Full control over HR dataset<br>• Grant access to HR tables<br>• Manage encryption keys | • Cannot delegate admin rights<br>• Access must be audited |
| **HR Data Steward** | HR Operations | HR Dataset | • Read/write HR data<br>• Create authorized views<br>• Apply policy tags | • Cannot change IAM policies<br>• Cannot export outside perimeter |
| **Analytics Engineer** | Data Team | Analytics Project | • Query authorized views<br>• See masked/aggregated data<br>• Build dashboards | • Cannot access raw HR data<br>• Cannot see sensitive columns<br>• Cannot export outside perimeter |

#### Critical IAM Best Practices

**1. Never Grant These Roles at Organization/Folder/Project Level:**
```bash
# ❌ NEVER DO THIS - Grants access to all data
gcloud projects add-iam-policy-binding org-hr-data \
  --member=user:admin@org.com \
  --role=roles/bigquery.admin

# ✅ CORRECT - Grant only infrastructure permissions
gcloud projects add-iam-policy-binding org-hr-data \
  --member=user:admin@org.com \
  --role=roles/bigquery.jobUser
```

**2. Use Organization Policy Constraints:**
```yaml
# Enforce at organization level
constraints/iam.disableServiceAccountKeyCreation: true
  # Prevents service account key extraction

constraints/iam.allowedPolicyMemberDomains:
  - org.com
  # Only corporate accounts can be granted access

constraints/sql.restrictAuthorizedNetworks: true
  # Requires VPC-SC for database access
```

**3. Custom Role: "HR Platform Admin" (Infrastructure Only)**
```yaml
title: "HR Platform Administrator"
description: "Can manage infrastructure but not access HR data"
stage: "GA"
includedPermissions:
  # Project management
  - resourcemanager.projects.get
  - resourcemanager.projects.list
  
  # BigQuery infrastructure (no data access)
  - bigquery.datasets.create
  - bigquery.datasets.get
  - bigquery.jobs.create
  - bigquery.jobs.list
  
  # Monitoring and logging
  - logging.logEntries.list
  - monitoring.timeSeries.list
  
  # VPC and networking
  - compute.networks.get
  - compute.firewalls.list

excludedPermissions:
  # ✅ Explicitly exclude data access
  - bigquery.tables.getData
  - bigquery.tables.list
  - bigquery.datasets.get
  - bigquery.rowAccessPolicies.*
```

---

### Layer 3: Column-Level Encryption (Cryptographic Separation)

**Concept:** Encrypt sensitive columns with keys that HR team controls. Even if someone gains database access, they cannot decrypt without the key.

#### Implementation: Cloud KMS with Customer-Managed Keys

```
┌─────────────────────────────────────────────────────┐
│         HR Team Controls Encryption Keys            │
│                                                      │
│  Cloud KMS Key Ring: "hr-sensitive-data"            │
│  ├── Key: "employee-ssn-key"                        │
│  │   └── IAM: Only HR team can use                  │
│  ├── Key: "employee-salary-key"                     │
│  │   └── IAM: Only HR team + Finance can use        │
│  └── Key: "performance-review-key"                  │
│      └── IAM: Only HR team can use                  │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│         BigQuery Table: prod_hr.employees           │
│  ┌─────────────────────────────────────────────┐   │
│  │ employee_id  │ first_name │ encrypted_ssn    │   │
│  ├─────────────────────────────────────────────┤   │
│  │ 12345       │ John       │ AwECAXhtB7Qx... │   │
│  │ 12346       │ Sarah      │ BxFDBYiuC8Ry... │   │
│  └─────────────────────────────────────────────┘   │
│                                                      │
│  Platform Admins can see: AwECAXhtB7Qx...          │
│  ✅ But cannot decrypt without KMS key access       │
└─────────────────────────────────────────────────────┘
```

#### Step-by-Step Implementation

**Step 1: Create KMS Key Ring (HR Team Manages)**
```bash
# HR team creates key ring in their project
gcloud kms keyrings create hr-sensitive-data \
  --location=europe-west2 \
  --project=org-hr-kms

# Create encryption key for SSN
gcloud kms keys create employee-ssn-key \
  --location=europe-west2 \
  --keyring=hr-sensitive-data \
  --purpose=encryption \
  --project=org-hr-kms

# Grant ONLY HR team access to use key
gcloud kms keys add-iam-policy-binding employee-ssn-key \
  --location=europe-west2 \
  --keyring=hr-sensitive-data \
  --member=group:hr-team@org.com \
  --role=roles/cloudkms.cryptoKeyEncrypterDecrypter \
  --project=org-hr-kms
```

**Step 2: Encrypt Data in BigQuery**
```sql
-- HR team encrypts SSN column
UPDATE prod_hr.employees
SET ssn_encrypted = KEYS.ENCRYPT(
  'projects/org-hr-kms/locations/europe-west2/keyRings/hr-sensitive-data/cryptoKeys/employee-ssn-key',
  ssn,
  'AEAD_AES_GCM_256'
)
WHERE ssn_encrypted IS NULL;

-- Drop original unencrypted column
ALTER TABLE prod_hr.employees DROP COLUMN ssn;
```

**Step 3: HR Team Queries with Decryption**
```sql
-- Only HR team can decrypt (they have KMS key access)
SELECT 
  employee_id,
  first_name,
  KEYS.DECRYPT_STRING(
    'projects/org-hr-kms/locations/europe-west2/keyRings/hr-sensitive-data/cryptoKeys/employee-ssn-key',
    ssn_encrypted,
    'AEAD_AES_GCM_256'
  ) as ssn
FROM prod_hr.employees
WHERE department = 'Engineering';
```

**Step 4: Platform Admin Sees Encrypted Data Only**
```sql
-- Platform admin runs same query
SELECT 
  employee_id,
  first_name,
  ssn_encrypted
FROM prod_hr.employees;

-- Result: Can see table but data is encrypted
-- employee_id | first_name | ssn_encrypted
-- 12345       | John       | AwECAXhtB7Qx29vF...
-- ❌ Cannot decrypt without KMS key access
```

**Why This Works:**
1. ✅ BigQuery table data is accessible (admins can manage infrastructure)
2. ✅ But sensitive columns are encrypted blobs
3. ✅ Decryption requires Cloud KMS key access
4. ✅ Only HR team has KMS key permissions
5. ✅ All KMS access is logged and auditable

---

### Layer 4: VPC Service Controls (Network Perimeter)

**Concept:** Create a "fortress" around HR data that blocks all network-level access, even with valid IAM permissions. Prevents data exfiltration.

#### What VPC-SC Prevents

```
Blocked Attack Scenarios:

1. Copy to External Bucket:
   bq extract prod_hr.employees gs://attacker-bucket/stolen.csv
   ❌ VPC-SC blocks: "Request is prohibited by organization's policy"

2. Query from Outside Perimeter:
   User queries from personal laptop outside corporate VPN
   ❌ VPC-SC blocks: "Source IP not in allowed access level"

3. Cross-Project Data Copy:
   CREATE TABLE personal_project.test AS SELECT * FROM prod_hr.employees
   ❌ VPC-SC blocks: "Cannot write to resource outside perimeter"

4. Public Dataset Exposure:
   bq update --dataset prod_hr --set_default_table_expiration 0
   ❌ VPC-SC blocks: Even if IAM allows, perimeter denies

5. Service Account Key Extraction:
   Download service account key, use from home
   ❌ VPC-SC blocks: Key works, but home IP not allowed
```

#### Implementation: HR Data Perimeter

**Step 1: Create Access Level (Corporate Network Only)**
```bash
# Define what sources can access HR data
cat > hr-access-level.yaml <<EOF
- ipSubnetworks:
  - 192.168.1.0/24      # Org London office
  - 10.0.0.0/16         # Org VPN range
  - 172.16.0.0/12       # GCP private ranges
EOF

gcloud access-context-manager levels create org-corporate-network \
  --title="Org Corporate Network" \
  --basic-level-spec=hr-access-level.yaml \
  --policy=org-access-policy
```

**Step 2: Create VPC Service Perimeter**
```bash
# Create perimeter around HR data project
gcloud access-context-manager perimeters create hr-data-perimeter \
  --title="HR Sensitive Data Perimeter" \
  --resources=projects/123456789 \  # org-hr-data project number
  --restricted-services=bigquery.googleapis.com,storage.googleapis.com \
  --access-levels=org-corporate-network \
  --policy=org-access-policy

# Start in DRY RUN mode first to test
gcloud access-context-manager perimeters update hr-data-perimeter \
  --set-enforcement-mode=dryrun \
  --policy=org-access-policy
```

**Step 3: Configure Ingress Rules (Controlled Access)**
```yaml
# Allow specific ingress (e.g., ETL pipeline from Workday)
ingressPolicies:
  - ingressFrom:
      identityType: ANY_SERVICE_ACCOUNT
      sources:
        - accessLevel: accessPolicies/org-access-policy/accessLevels/org-corporate-network
    ingressTo:
      operations:
        - serviceName: bigquery.googleapis.com
          methodSelectors:
            - method: 'google.cloud.bigquery.v2.JobService.InsertJob'
            - method: 'google.cloud.bigquery.v2.TableDataService.InsertAll'
      resources:
        - 'projects/123456789'  # HR data project
```

**Step 4: Configure Egress Rules (Prevent Data Leaks)**
```yaml
# Block ALL egress by default
# Allow ONLY egress to analytics project for authorized views
egressPolicies:
  - egressFrom:
      identityType: ANY_IDENTITY
    egressTo:
      operations:
        - serviceName: bigquery.googleapis.com
          methodSelectors:
            - method: 'google.cloud.bigquery.v2.JobService.Query'  # Read-only
      resources:
        - 'projects/987654321'  # Analytics project number
```

**Step 5: Test in Dry Run Mode**
```bash
# Check what would be blocked
gcloud access-context-manager perimeters dry-run enforce hr-data-perimeter \
  --policy=org-access-policy

# Review violations in Cloud Logging
gcloud logging read "protoPayload.metadata.dryRun=true AND resource.type=bigquery_resource" \
  --limit=50 \
  --format=json
```

**Step 6: Enforce Perimeter**
```bash
# After testing, enforce the perimeter
gcloud access-context-manager perimeters update hr-data-perimeter \
  --set-enforcement-mode=enforced \
  --policy=org-access-policy
```

#### VPC-SC Monitoring & Alerts

```sql
-- Query for VPC-SC violations (attempted data exfiltration)
SELECT
  timestamp,
  protoPayload.authenticationInfo.principalEmail,
  protoPayload.metadata.serviceContext.targetResource,
  protoPayload.metadata.violationReason,
  protoPayload.metadata.vpcServiceControlsUniqueId
FROM
  `org-hr-data.logs.cloudaudit_googleapis_com_data_access`
WHERE
  protoPayload.metadata.violationReason IS NOT NULL
  AND DATE(timestamp) >= CURRENT_DATE() - 7
ORDER BY timestamp DESC;
```

---

### Layer 5: Break-Glass Emergency Access

**Challenge:** What if HR system is down and we need emergency access to employee data (e.g., payroll crisis)?

**Solution:** Just-In-Time (JIT) privileged access with multi-person authorization.

#### Break-Glass Architecture

```
Emergency Scenario: Payroll System Down
├── Step 1: Request Emergency Access
│   └── Platform admin files ticket in ITSM system
│
├── Step 2: Multi-Person Authorization
│   ├── HR Director approves (business justification)
│   ├── Security Officer approves (risk assessment)
│   └── Compliance Officer approves (regulatory check)
│
├── Step 3: Time-Boxed Access Grant
│   ├── Cloud IAM grants temporary role (4 hours max)
│   ├── Temporary KMS key access (decrypt only)
│   └── VPC-SC temporary ingress rule
│
├── Step 4: All Actions Logged
│   ├── Every query logged to BigQuery audit table
│   ├── Every KMS decrypt operation logged
│   └── Real-time alert to HR Director + Security
│
└── Step 5: Auto-Revocation
    ├── Access expires after 4 hours
    ├── All temp policies removed
    └── Post-access audit report generated
```

#### Implementation: Break-Glass Service Account

**Step 1: Create Break-Glass Service Account**
```bash
# Create special service account (NEVER used except emergencies)
gcloud iam service-accounts create hr-break-glass \
  --display-name="HR Break-Glass Emergency Access" \
  --description="EMERGENCY USE ONLY - All access logged and audited" \
  --project=org-hr-data

# No default permissions - completely locked down
```

**Step 2: Create JIT Access Workflow (Cloud Functions + PubSub)**
```python
# cloud-function: grant-break-glass-access
def grant_emergency_access(request):
    """
    Grants temporary break-glass access after approvals
    """
    # Validate multi-person approval
    approvals = request.get_json()
    required_approvers = ['hr-director@org.com', 
                          'security-officer@org.com',
                          'compliance@org.com']
    
    if not all(approver in approvals for approver in required_approvers):
        return {'error': 'Insufficient approvals'}, 403
    
    # Grant temporary IAM role (4 hours)
    expiry = datetime.now() + timedelta(hours=4)
    
    add_iam_policy_binding(
        resource='projects/org-hr-data/datasets/prod_hr',
        member='serviceAccount:hr-break-glass@org-hr-data.iam.gserviceaccount.com',
        role='roles/bigquery.dataViewer',
        condition={
            'title': 'Emergency Access',
            'expression': f'request.time < timestamp("{expiry.isoformat()}")'
        }
    )
    
    # Grant temporary KMS key access
    add_kms_iam_policy_binding(
        key='employee-ssn-key',
        member='serviceAccount:hr-break-glass@org-hr-data.iam.gserviceaccount.com',
        role='roles/cloudkms.cryptoKeyDecrypter',  # Decrypt only
        condition={'expression': f'request.time < timestamp("{expiry.isoformat()}")'}
    )
    
    # Add temporary VPC-SC ingress rule
    add_vpc_sc_temporary_ingress(
        perimeter='hr-data-perimeter',
        source='hr-break-glass@org-hr-data.iam.gserviceaccount.com',
        expiry=expiry
    )
    
    # Send alerts
    send_alert_to_slack(
        channel='#hr-security-alerts',
        message=f'⚠️ BREAK-GLASS ACCESS GRANTED\n'
                f'Service Account: hr-break-glass\n'
                f'Approved By: {", ".join(required_approvers)}\n'
                f'Expires: {expiry}\n'
                f'Reason: {request.get("justification")}'
    )
    
    return {'status': 'granted', 'expires_at': expiry.isoformat()}
```

**Step 3: Audit All Break-Glass Activity**
```sql
-- Real-time monitoring of break-glass account
CREATE OR REPLACE TABLE prod_hr.break_glass_audit AS
SELECT
  timestamp,
  protoPayload.authenticationInfo.principalEmail as user,
  protoPayload.resourceName as resource_accessed,
  protoPayload.methodName as action,
  protoPayload.requestMetadata.callerIp as source_ip,
  ARRAY(
    SELECT column_name 
    FROM UNNEST(protoPayload.metadata.tableDataRead.fields) as column_name
  ) as columns_accessed
FROM
  `org-hr-data.logs.cloudaudit_googleapis_com_data_access`
WHERE
  protoPayload.authenticationInfo.principalEmail = 'hr-break-glass@org-hr-data.iam.gserviceaccount.com'
  AND timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY);

-- Alert on any break-glass activity
CREATE OR REPLACE ALERT hr_break_glass_alert
OPTIONS (
  alert_policy = 'immediate',
  notification_channels = ['slack-hr-security-alerts']
)
AS
SELECT *
FROM prod_hr.break_glass_audit
WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 5 MINUTE);
```

---

### Layer 6: Comprehensive Audit Logging

**Principle:** If admins somehow get access, we MUST know what they accessed.

#### What to Log

```
Data Access Logs (bigquery.tables.getData):
├── Who accessed data
├── When they accessed it
├── Which tables/columns
├── Source IP address
├── Query text
└── Rows returned

Admin Activity Logs (bigquery.tables.setIamPolicy):
├── Who changed permissions
├── What permissions changed
├── Previous vs new IAM policy
└── Justification (if provided)

KMS Logs (cloudkms.cryptoKeyVersions.useToDecrypt):
├── Who decrypted data
├── Which encryption key used
├── Timestamp
└── Source identity

VPC-SC Logs (VPC Service Controls violations):
├── Attempted access outside perimeter
├── Source IP and identity
├── Blocked operation
└── Violation reason
```

#### Centralized Security Monitoring Dashboard

```sql
-- Query: Unauthorized access attempts
CREATE OR REPLACE VIEW security.unauthorized_access_attempts AS
SELECT
  timestamp,
  protopayload_auditlog.authenticationInfo.principalEmail as user,
  protopayload_auditlog.resourceName as resource,
  protopayload_auditlog.authorizationInfo[0].denied as was_denied,
  protopayload_auditlog.authorizationInfo[0].permission as permission_required
FROM
  `org-hr-data.logs.cloudaudit_googleapis_com_activity`
WHERE
  protopayload_auditlog.authorizationInfo[0].denied = true
  AND timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY);

-- Query: Privileged admin actions on HR data
CREATE OR REPLACE VIEW security.admin_actions_on_hr_data AS
SELECT
  timestamp,
  protopayload_auditlog.authenticationInfo.principalEmail as admin_user,
  protopayload_auditlog.methodName as action,
  JSON_EXTRACT_SCALAR(protopayload_auditlog.request, '$.policy') as policy_change,
  protopayload_auditlog.resourceName as affected_resource
FROM
  `org-hr-data.logs.cloudaudit_googleapis_com_activity`
WHERE
  protopayload_auditlog.methodName IN (
    'google.iam.admin.v1.SetIamPolicy',
    'v2.TableService.PatchTable',
    'v2.DatasetService.PatchDataset'
  )
  AND timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
ORDER BY timestamp DESC;

-- Query: Anomalous data access patterns
CREATE OR REPLACE VIEW security.anomalous_hr_data_access AS
SELECT
  protopayload_auditlog.authenticationInfo.principalEmail as user,
  DATE(timestamp) as access_date,
  COUNT(*) as query_count,
  SUM(protopayload_auditlog.metadata.tableDataRead.rowCount) as total_rows_accessed,
  ARRAY_AGG(DISTINCT protopayload_auditlog.resourceName) as tables_accessed
FROM
  `org-hr-data.logs.cloudaudit_googleapis_com_data_access`
WHERE
  timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
GROUP BY user, access_date
HAVING 
  query_count > 100  -- Unusual number of queries
  OR total_rows_accessed > 10000  -- Unusual amount of data
ORDER BY query_count DESC;
```

#### Real-Time Alerting (Cloud Monitoring)

```yaml
# Alert Policy: Admin querying HR data
alertPolicy:
  displayName: "Admin accessing HR sensitive data"
  conditions:
    - displayName: "BigQuery Admin role querying prod_hr"
      conditionThreshold:
        filter: |
          resource.type="bigquery_resource"
          AND protoPayload.authenticationInfo.principalEmail=~".*admin.*"
          AND protoPayload.resourceName=~".*prod_hr.*"
        aggregations:
          - alignmentPeriod: 60s
            perSeriesAligner: ALIGN_RATE
        comparison: COMPARISON_GT
        thresholdValue: 0
        duration: 0s
  notificationChannels:
    - "projects/org-hr-data/notificationChannels/slack-security"
    - "projects/org-hr-data/notificationChannels/pagerduty-security-oncall"
  alertStrategy:
    autoClose: 3600s  # Auto-close after 1 hour if no more events

# Alert Policy: VPC-SC perimeter violation
alertPolicy:
  displayName: "VPC Service Controls violation - HR data"
  conditions:
    - displayName: "Attempted data exfiltration"
      conditionThreshold:
        filter: |
          protoPayload.metadata.violationReason:*
          AND resource.labels.project_id="org-hr-data"
        comparison: COMPARISON_GT
        thresholdValue: 0
  notificationChannels:
    - "projects/org-hr-data/notificationChannels/slack-security"
    - "projects/org-hr-data/notificationChannels/soc-email"
  alertStrategy:
    autoClose: 0s  # Never auto-close - requires manual investigation
```

---

## Key Success Metrics

### Security Metrics
- **Zero Unauthorized Access** - No platform admins accessed HR data in last 30 days
- **Break-Glass Usage** - <2 break-glass accesses per quarter (lower is better)
- **Mean Time to Detect** - Unauthorized access detected within 5 minutes
- **Mean Time to Respond** - Access revoked within 15 minutes of detection
- **VPC-SC Violations** - All violations investigated within 24 hours

### Operational Metrics
- **HR Team Productivity** - No impact to HR workflows (they can still do their jobs)
- **Platform Admin Productivity** - Can still manage infrastructure without friction
- **Query Performance** - <10% performance impact from encryption/decryption
- **Break-Glass Approval Time** - Emergency access granted within 1 hour

### Compliance Metrics
- **Audit Completeness** - 100% of data access logged and retained for 7 years
- **Policy Compliance** - Zero IAM policy violations detected
- **Key Rotation** - KMS keys rotated every 90 days
- **Access Review** - 100% of access permissions reviewed quarterly

---

## Ongoing Governance

### Monthly Activities
- [ ] Review all HR data access logs
- [ ] Investigate any anomalous query patterns
- [ ] Validate VPC-SC perimeter policies still effective
- [ ] Check for any new service accounts created
- [ ] Review Cloud KMS access logs

### Quarterly Activities
- [ ] Complete access review (recertify all permissions)
- [ ] Rotate Cloud KMS keys
- [ ] Update organization policy constraints if needed
- [ ] Conduct security awareness training for new hires
- [ ] Red team exercise (attempt data exfiltration)

### Annual Activities
- [ ] External security audit (penetration testing)
- [ ] Compliance certification renewal (SOC 2, ISO 27001)
- [ ] Review and update security policies
- [ ] Disaster recovery drill (including break-glass)
- [ ] Assess new GCP security features

---

## Real-World Reference Architectures

### Example 1: Financial Services (Bank HR Data)
```
HSBC-like Implementation:
├── 3 separate GCP organizations:
│   ├── Production (HR data) - Org 1
│   ├── Analytics (curated data) - Org 2
│   └── Infrastructure (admins) - Org 3
├── Cross-org VPC-SC perimeters with explicit ingress/egress
├── All data encrypted with FIPS 140-2 Level 3 HSM keys
├── Dual-person authorization for ALL data access
└── Zero standing access - all access is JIT with 2-hour max
```

### Example 2: Healthcare (NHS-style)
```
NHS-like Implementation:
├── Data residency: UK region only (VPC-SC enforces)
├── Patient data encrypted with patient consent key
├── Doctors can decrypt only their patients
├── Admins have NO access to patient data
├── Break-glass requires: Doctor + Manager + Compliance Officer
└── All access audited and reported to Care Quality Commission
```

### Example 3: Retail (John Lewis-style)
```
Retail Implementation:
├── Employee data in separate project from customer data
├── HR system integration uses service account with VPC-SC
├── Payroll team has read-only access to encrypted salary data
├── Store managers can see only their store's employees (RLS)
├── Break-glass requires: HR Director + Legal + CISO
└── Weekly access reports to HR leadership
```

---

## FAQ: Common Questions

### Q1: Can platform admins really not see the data at all?
**A:** Correct. With this architecture:
- Platform admins can see encrypted blobs in BigQuery
- They do NOT have Cloud KMS key access to decrypt
- VPC-SC blocks any attempt to copy data outside perimeter
- All their access attempts are logged and alerted

### Q2: What if there's a genuine emergency and HR team is unavailable?
**A:** Use the break-glass procedure:
1. File emergency access ticket
2. Get approval from 3 different executives (HR Director, Security Officer, Compliance)
3. Automated workflow grants temporary access (4 hours max)
4. Every action is logged and audited
5. Access auto-revokes after time expires
6. Post-incident report generated automatically

### Q3: Does this impact HR team's day-to-day work?
**A:** Minimal impact if implemented correctly:
- HR team still has full access to their data
- Decryption happens transparently in queries
- <10% performance overhead for encryption/decryption
- They use familiar BigQuery interface
- Authorized views for reporting tools work normally

### Q4: Can service accounts bypass these controls?
**A:** No, because:
- Service accounts also subject to VPC-SC
- Service accounts cannot impersonate across perimeters
- Service account keys disabled (organization policy)
- Workload Identity used instead (no downloadable keys)
- All service account actions logged

### Q5: How do we grant temporary access to contractors/auditors?
**A:** Use time-boxed IAM conditions:
```bash
# Grant contractor access for 30 days only
gcloud projects add-iam-policy-binding org-hr-data \
  --member=user:contractor@external.com \
  --role=roles/bigquery.dataViewer \
  --condition='expression=request.time < timestamp("2026-03-12T00:00:00Z"),title=Contractor Access,description=Expires March 12'
```

### Q6: What about data scientists who need aggregated HR data?
**A:** Create authorized views in analytics project:
```sql
-- Authorized view in analytics project
CREATE VIEW analytics.hr_metrics AS
SELECT 
  department,
  job_level,
  AVG(CAST(KEYS.DECRYPT_STRING(..., salary_encrypted) AS INT64)) as avg_salary,
  COUNT(*) as headcount
FROM prod_hr.employees
GROUP BY department, job_level
HAVING COUNT(*) >= 10;  -- Prevent individual identification

-- Grant data scientists access to VIEW only (not base table)
```

---

## Summary: Defense-in-Depth Strategy

This architecture implements **6 layers of defense** to ensure even platform admins cannot access sensitive HR data:

```
Layer 1: Organizational Structure
  └── HR data in separate project from admin access

Layer 2: IAM Roles & Permissions
  └── Least privilege + custom roles (infra only, no data)

Layer 3: Column-Level Encryption
  └── Cloud KMS keys controlled by HR team only

Layer 4: VPC Service Controls
  └── Network perimeter blocks all unauthorized access

Layer 5: Break-Glass Emergency Access
  └── Multi-person approval + time-boxed + fully audited

Layer 6: Comprehensive Audit Logging
  └── Every action logged, monitored, alerted
```

**Result:** Zero-trust architecture where:
- ✅ HR team has full access to do their jobs
- ✅ Platform admins can manage infrastructure
- ❌ Platform admins CANNOT see sensitive HR data
- ✅ Emergency access possible with proper controls
- ✅ All access fully audited and compliance-ready

---

## Recommended Approach: Hybrid Strategy
Based on the architecture (GCS → Cloud Function → Airflow → BigQuery), here's what I recommend:

### Solution 1: Encrypt at Ingestion Time (Recommended for Your Flow)
Architecture:
```
CSV File → GCS → Cloud Function → Airflow DAG
                                     ↓
                            Python Script reads CSV
                                     ↓
                            Check PII flag in mapping
                                     ↓
                   PII columns → Encrypt with DLP/KMS
                   Non-PII columns → Pass through
                                     ↓
                            Load to BigQuery
```
**Implementation Steps:**
**1. Enhance Your Mapping Sheet**
Add a column for encryption method:
```
Column K: Security_Class
- "PII" → Encrypt with Cloud DLP tokenization
- "PII-High" → Encrypt with KMS
- "Not PII" → No encryption
```
2. Python Script in Airflow DAG:
```python
import pandas as pd
from google.cloud import bigquery, dlp_v2, storage
import json

# Load your mapping configuration
def load_column_mapping(mapping_file_path):
    """Load mapping sheet from GCS"""
    df = pd.read_csv(mapping_file_path)
    
    # Create dictionary: column_name -> security_class
    pii_config = {}
    for _, row in df.iterrows():
        pii_config[row['Column']] = {
            'security_class': row['Security_Class'],
            'data_type': row['Data_Type']
        }
    return pii_config

# Encrypt PII columns before loading
def encrypt_pii_columns(df, pii_config, dlp_client, project_id):
    """
    Encrypt columns marked as PII using Cloud DLP
    """
    # Get list of PII columns
    pii_columns = [col for col, config in pii_config.items() 
                   if config['security_class'] in ['PII', 'PII-High'] 
                   and col in df.columns]
    
    if not pii_columns:
        return df  # No PII columns to encrypt
    
    # Create DLP deidentify config
    parent = f"projects/{project_id}/locations/global"
    
    # Use deterministic encryption (preserves ability to join)
    crypto_replace_config = {
        "crypto_key": {
            "kms_wrapped": {
                "wrapped_key": "YOUR_WRAPPED_KEY_HERE",
                "crypto_key_name": "projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY"
            }
        }
    }
    
    # Encrypt each PII column
    for col in pii_columns:
        encrypted_values = []
        
        for value in df[col]:
            if pd.isna(value):
                encrypted_values.append(None)
                continue
                
            # Call DLP to encrypt
            item = {"value": str(value)}
            response = dlp_client.deidentify_content(
                request={
                    "parent": parent,
                    "deidentify_config": {
                        "info_type_transformations": {
                            "transformations": [{
                                "primitive_transformation": {
                                    "crypto_deterministic_config": crypto_replace_config
                                }
                            }]
                        }
                    },
                    "item": item
                }
            )
            encrypted_values.append(response.item.value)
        
        # Replace original column with encrypted version
        df[f'{col}_encrypted'] = encrypted_values
        df.drop(columns=[col], inplace=True)  # Drop original
    
    return df

# Main Airflow task
def ingest_and_encrypt_task(**context):
    """
    Airflow task: Read CSV from GCS, encrypt PII, load to BigQuery
    """
    # Initialize clients
    storage_client = storage.Client()
    bq_client = bigquery.Client()
    dlp_client = dlp_v2.DlpServiceClient()
    
    project_id = "org-data-platform"
    bucket_name = "wtrydal-gs-04"
    csv_file = "incoming_data.csv"
    mapping_file = "gs://config-bucket/column_mapping.csv"
    
    # 1. Load mapping configuration
    pii_config = load_column_mapping(mapping_file)
    
    # 2. Download CSV from GCS
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(csv_file)
    csv_content = blob.download_as_text()
    
    # 3. Parse CSV into DataFrame
    df = pd.read_csv(pd.StringIO(csv_content))
    
    # 4. Encrypt PII columns
    df_encrypted = encrypt_pii_columns(df, pii_config, dlp_client, project_id)
    
    # 5. Load to BigQuery
    table_id = f"{project_id}.ctng_dataset.target_table"
    
    job_config = bigquery.LoadJobConfig(
        write_disposition="WRITE_APPEND",
        schema_update_options=[
            bigquery.SchemaUpdateOption.ALLOW_FIELD_ADDITION
        ]
    )
    
    job = bq_client.load_table_from_dataframe(
        df_encrypted, table_id, job_config=job_config
    )
    job.result()  # Wait for completion
    
    print(f"Loaded {len(df_encrypted)} rows to {table_id}")
    print(f"Encrypted PII columns: {[col for col in df.columns if '_encrypted' in col]}")
```

### Solution 2: Native BigQuery Encryption (Alternative)
If you want to load data unencrypted first, then encrypt in BigQuery:
```sql
-- After loading raw data to BigQuery, run this SQL to encrypt PII columns

-- Step 1: Add encrypted columns
ALTER TABLE ctng_dataset.target_table
ADD COLUMN Created_By_Email_Address_encrypted BYTES;

-- Step 2: Encrypt the data
UPDATE ctng_dataset.target_table
SET Created_By_Email_Address_encrypted = KEYS.ENCRYPT(
  'projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY',
  Created_By_Email_Address,
  'AEAD_AES_GCM_256'
)
WHERE Created_By_Email_Address_encrypted IS NULL;

-- Step 3: Drop original unencrypted column
ALTER TABLE ctng_dataset.target_table
DROP COLUMN Created_By_Email_Address;
```
### Recommendations:
Use Solution 1 (encrypt during ingestion) because:
```
✅ Pros:

Never store PII unencrypted - Data encrypted before it touches BigQuery
Simpler schema - No need to manage parallel encrypted/unencrypted columns
Automated - Reads PII flag from your mapping sheet automatically
Auditable - All encryption happens in controlled Airflow DAG
Flexible - Easy to change which columns are PII without schema changes

⚠️ Cons:

Slightly more complex Python code - Need DLP API calls
Performance - Adds ~2-5 seconds per 1000 rows for encryption
Cost - Cloud DLP API charges ($1 per 1M bytes inspected)
```

### Practical Implementation Plan:

### 1: Setup
```bash
# 1. Enable Cloud DLP API
gcloud services enable dlp.googleapis.com

# 2. Create KMS key for PII encryption

gcloud kms keyrings create pii-encryption \
  --location=europe-west2

gcloud kms keys create customer-pii-key \
  --location=europe-west2 \
  --keyring=pii-encryption \
  --purpose=encryption
```
### 3. Grant Airflow service account access
```
gcloud kms keys add-iam-policy-binding customer-pii-key \
  --location=europe-west2 \
  --keyring=pii-encryption \
  --member=serviceAccount:airflow-sa@org.iam.gserviceaccount.com \
  --role=roles/cloudkms.cryptoKeyEncrypterDecrypter
```
### 2: Update Your Mapping Sheet
```
Add Column K: Security_Class with values:

Created_By_Email_Address → PII
Assigned_To_Email_Address → PII
Created_By_Full_Name → PII
Assigned_To_Full_Name → PII
All others → Not PII
```
### 3: Modify Python DAG
```
Read mapping sheet from GCS
Loop through columns, encrypt if Security_Class == "PII"
Rename encrypted columns to {column_name}_encrypted
Load to BigQuery
```
### 4: Test & Validate
```
Run on sample dataset
Verify encrypted columns are base64 blobs
Test queries with decryption
Validate performance impact
```

### Quick Win: Use Cloud DLP Auto-Classification (Optional)
Instead of manually marking PII in your mapping sheet, let Cloud DLP auto-detect:
```python
def auto_classify_pii(df, dlp_client, project_id):
    """
    Use DLP to automatically detect PII columns
    Returns: dict of column_name -> [detected_infotypes]
    """
    parent = f"projects/{project_id}/locations/global"
    
    # Sample first 100 rows for classification
    sample_df = df.head(100)
    
    pii_detected = {}
    
    for col in df.columns:
        # Convert column to string for DLP inspection
        col_text = "\n".join(sample_df[col].astype(str).tolist())
        
        item = {"value": col_text}
        
        response = dlp_client.inspect_content(
            request={
                "parent": parent,
                "item": item,
                "inspect_config": {
                    "info_types": [
                        {"name": "EMAIL_ADDRESS"},
                        {"name": "PERSON_NAME"},
                        {"name": "PHONE_NUMBER"},
                        {"name": "CREDIT_CARD_NUMBER"}
                    ],
                    "min_likelihood": dlp_v2.Likelihood.LIKELY
                }
            }
        )
        
        if response.result.findings:
            pii_detected[col] = [f.info_type.name for f in response.result.findings]
    
    return pii_detected
```
### Usage:
```
pii_columns = auto_classify_pii(df, dlp_client, project_id)
print(f"Auto-detected PII: {pii_columns}")
# Output: {'Created_By_Email_Address': ['EMAIL_ADDRESS'], 
#          'Created_By_Full_Name': ['PERSON_NAME']}
```
### Summary:
For your specific workflow:
```
✅ Keep your mapping sheet with PII flags
✅ In Airflow DAG Python script, read mapping sheet
✅ Encrypt PII columns before loading to BigQuery using Cloud DLP
✅ Load encrypted data to BigQuery with _encrypted suffix
✅ Drop original unencrypted columns from DataFrame
```
This gives you data-at-rest encryption without ever storing unencrypted PII in BigQuery.

---
## Another Approach: External Table → Encrypt → Final Table
```
CSV in GCS → BigQuery External Table → SQL Transform with Encryption → Native BigQuery Table
```
### Why This Is A Great Approach:
```
✅ Advantages:

Pure SQL/BigQuery Native - No Python encryption code needed
Leverage BigQuery's Engine - Encryption happens at massive scale
Simpler Pipeline - Airflow just triggers SQL, doesn't handle data
Schema Management - External table auto-detects CSV schema
Cost-Effective - Only pay for BigQuery query processing (no DLP API costs)
Idempotent - Easy to re-run if something fails
Metadata-Driven - Your mapping sheet controls which columns get encrypted
```

### Implementation:
#### Step 1: Create External Table from GCS
```
-- Create external table pointing to GCS CSV files
CREATE OR REPLACE EXTERNAL TABLE ctng_dataset.ext_raw_data
OPTIONS (
  format = 'CSV',
  uris = ['gs://wtrydal-gs-04/*.csv'],
  skip_leading_rows = 1,
  auto_detect_schema = TRUE
);

-- Verify it works
SELECT * FROM ctng_dataset.ext_raw_data LIMIT 10;
```

#### Step 2: Create KMS Key (One-time Setup)
```bash
# Create key ring
gcloud kms keyrings create pii-encryption \
  --location=europe-west2 \
  --project=org-data-platform

# Create encryption key
gcloud kms keys create customer-pii-key \
  --location=europe-west2 \
  --keyring=pii-encryption \
  --purpose=encryption
```

#### Step 3: SQL Transform with Conditional Encryption
Here's the magic - encrypt only PII columns based on your mapping sheet:
```
-- Option A: Manually specify PII columns
CREATE OR REPLACE TABLE ctng_dataset.final_table AS
SELECT
  -- Non-PII columns - pass through as-is
  Processing_Date_Time,
  Event_Date_Time,
  Ingestion_Method,
  Source_System_Name,
  ID,
  Action_Number,
  Description,
  Type,
  Type_Name,
  Org_Chart_ID,
  Org_Chart_Name,
  Reference_Number,
  Relates_To,
  
  -- PII columns - encrypt with KMS
  KEYS.ENCRYPT(
    'projects/org-data-platform/locations/europe-west2/keyRings/pii-encryption/cryptoKeys/customer-pii-key',
    Created_By_Email_Address,
    'AEAD_AES_GCM_256'
  ) AS Created_By_Email_Address_encrypted,
  
  KEYS.ENCRYPT(
    'projects/org-data-platform/locations/europe-west2/keyRings/pii-encryption/cryptoKeys/customer-pii-key',
    Created_By_Full_Name,
    'AEAD_AES_GCM_256'
  ) AS Created_By_Full_Name_encrypted,
  
  KEYS.ENCRYPT(
    'projects/org-data-platform/locations/europe-west2/keyRings/pii-encryption/cryptoKeys/customer-pii-key',
    Assigned_To_Email_Address,
    'AEAD_AES_GCM_256'
  ) AS Assigned_To_Email_Address_encrypted,
  
  KEYS.ENCRYPT(
    'projects/org-data-platform/locations/europe-west2/keyRings/pii-encryption/cryptoKeys/customer-pii-key',
    Assigned_To_Full_Name,
    'AEAD_AES_GCM_256'
  ) AS Assigned_To_Full_Name_encrypted,
  
  -- Continue with other non-PII columns
  Priority,
  Priority_Name,
  Created_Date,
  Updated_Date
  -- ... rest of columns
FROM ctng_dataset.ext_raw_data;
```

### Comparison: 
|Aspect|External Table Approach | Python Encryption| Post-Load Encryption|
|------|------------------------|------------------|---------------------|
|Complexity|Low (pure SQL)|Medium (Python + DLP)|Medium (SQL + schema mgmt)|
|Performance|Fast (BigQuery native)|Medium (API calls)|Fast (BigQuery native)|
|Cost|Low (query only)|Medium (DLP API)|Low (query only)|
|PII Exposure|Zero (never stored unencrypted)|Zero|Brief (unencrypted → encrypted)|
|Maintainability|High (metadata-driven)|Medium (code changes)|Medium (schema changes)|
|Recommendation|✅ Use This!|Good backup|Last resort|
