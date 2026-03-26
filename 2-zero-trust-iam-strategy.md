# Zero-Trust IAM Implementation Guide
## Preventing Admin Access to Sensitive HR Data in BigQuery

**Document Version:** 2.0  
**Last Updated:** February 10, 2026  
**Audience:** Security Engineers, Platform Admins, DevOps Teams  
**Purpose:** Implementation guide for zero-trust data security architecture

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [The Problem: Traditional Admin Access](#the-problem-traditional-admin-access)
3. [Solution Architecture Overview](#solution-architecture-overview)
4. [Layer 1: Organizational Structure](#layer-1-organizational-structure)
5. [Layer 2: IAM Roles & Permissions](#layer-2-iam-roles--permissions)
6. [Layer 3: Column-Level Encryption](#layer-3-column-level-encryption)
7. [Layer 4: VPC Service Controls](#layer-4-vpc-service-controls)
8. [Layer 5: Break-Glass Emergency Access](#layer-5-break-glass-emergency-access)
9. [Layer 6: Comprehensive Audit Logging](#layer-6-comprehensive-audit-logging)
10. [Implementation Checklist](#implementation-checklist)
11. [Ongoing Governance](#ongoing-governance)
12. [Related Documentation](#related-documentation)

---

## Executive Summary

### The Challenge

Traditional cloud IAM models grant broad permissions to administrators, creating insider threat risks where platform admins can access any data, including highly sensitive HR information like salaries, performance reviews, and personal details.

### The Solution

A **defense-in-depth security architecture** combining six layers of protection:

1. **Separation of Duties** - Different teams manage infrastructure vs. data access
2. **IAM Least Privilege** - Admins get infrastructure permissions, not data access
3. **Cryptographic Separation** - Column-level encryption where only HR owns keys
4. **Network Perimeter** - VPC Service Controls prevent data exfiltration
5. **Break-Glass Procedures** - Audited emergency access with multi-person authorization
6. **Comprehensive Auditing** - Every action logged and monitored

### Key Principle

**"Zero Standing Privileges"** - No one, including platform admins, has permanent access to raw HR data. All access requires:
- Business justification
- Multi-person approval
- Time-boxed duration
- Complete audit trail

---

## The Problem: Traditional Admin Access

### Current Risk Scenario

```
Traditional Cloud IAM Hierarchy:
├── Organization Admin (roles/resourcemanager.organizationAdmin)
│   └── Can see everything in the organization
├── Project Owner (roles/owner)
│   └── Can see all data in project
└── BigQuery Admin (roles/bigquery.admin)
    └── Can query all datasets and tables
```

### Attack Vectors

#### **Vector 1: Direct Query Access**
```sql
-- Platform admin can run this query
SELECT 
  employee_name,
  salary,
  performance_rating
FROM prod_hr.employees
WHERE salary > 100000;
```

#### **Vector 2: Table Export**
```bash
# Admin can export sensitive data
bq extract \
  --destination_format=CSV \
  prod_hr.employees \
  gs://admin-personal-bucket/hr_data.csv
```

#### **Vector 3: Self-Grant Access**
```bash
# Admin modifies their own permissions
bq update --dataset \
  --add_iam_binding \
  prod_hr \
  --member=user:admin@customer.com \
  --role=roles/bigquery.dataOwner
```

#### **Vector 4: Service Account Impersonation**
```bash
# Admin impersonates HR service account
gcloud auth application-default login \
  --impersonate-service-account=hr-admin@customer.iam.gserviceaccount.com

# Now queries data as HR admin
bq query "SELECT * FROM prod_hr.employees"
```

### Impact

- ❌ **Compliance Violations** - Access without business need
- ❌ **Insider Threats** - Malicious admin could steal data
- ❌ **Audit Failures** - Cannot prove admins don't access data
- ❌ **Privacy Breaches** - GDPR right to privacy violated

---

## Solution Architecture Overview

### Multi-Layered Defense

```
┌─────────────────────────────────────────────────────────────┐
│                  Layer 6: Audit Logging                     │
│  Every action logged, monitored, alerted                    │
└─────────────────────────────────────────────────────────────┘
          ↓
┌─────────────────────────────────────────────────────────────┐
│            Layer 5: Break-Glass Emergency Access            │
│  Multi-person approval + time-boxed + fully audited         │
└─────────────────────────────────────────────────────────────┘
          ↓
┌─────────────────────────────────────────────────────────────┐
│           Layer 4: VPC Service Controls (VPC-SC)            │
│  Network perimeter blocks data exfiltration                 │
└─────────────────────────────────────────────────────────────┘
          ↓
┌─────────────────────────────────────────────────────────────┐
│        Layer 3: Column-Level Encryption (Cloud KMS)         │
│  Sensitive columns encrypted, HR team owns keys             │
└─────────────────────────────────────────────────────────────┘
          ↓
┌─────────────────────────────────────────────────────────────┐
│         Layer 2: IAM Roles & Permissions (Least Privilege)  │
│  Admins get infrastructure access, NOT data access          │
└─────────────────────────────────────────────────────────────┘
          ↓
┌─────────────────────────────────────────────────────────────┐
│      Layer 1: Organizational Structure (Separation of Duties)│
│  HR data in separate project from admin infrastructure      │
└─────────────────────────────────────────────────────────────┘
```

### Result

✅ HR team has full access to do their jobs  
✅ Platform admins can manage infrastructure  
❌ Platform admins CANNOT see sensitive HR data  
✅ Emergency access possible with proper controls  
✅ All access fully audited and compliance-ready  

---

## Layer 1: Organizational Structure

### Principle: Separation of Duties

**Data Projects ≠ Admin Projects**

```
customer GCP Organization
├── Production Folder (Regulated Data)
│   ├── Project: customer-hr-data (HR Data)
│   │   ├── Dataset: prod_hr
│   │   │   ├── Tables with encrypted columns
│   │   │   └── Policy tags enforced
│   │   ├── IAM: HR team ONLY (no platform admins)
│   │   └── VPC-SC Perimeter: "HR-Sensitive"
│   │
│   └── Project: customer-hr-kms (Encryption Keys)
│       ├── Cloud KMS key rings
│       ├── Encryption keys for PII
│       └── IAM: HR leadership ONLY
│
├── Analytics Folder (Curated Data)
│   ├── Project: customer-analytics
│   │   ├── Dataset: hr_analytics (authorized views only)
│   │   └── IAM: Analysts with masked access
│   └── VPC-SC Perimeter: "Analytics"
│
└── Platform Folder (Infrastructure)
    ├── Project: customer-platform-admin
    │   ├── No sensitive data stored here
    │   └── IAM: Platform admins manage infra only
    └── No VPC-SC (admins need flexibility)
```

### Key Design Principles

1. **Project Isolation** - HR data lives in separate project
2. **Folder-Level IAM** - HR team owns "Production Folder" IAM policies
3. **VPC-SC Isolation** - HR data perimeter blocks all external access
4. **No Admin Crossover** - Platform admins have ZERO permissions on HR project

### Implementation

```bash
# Create folder structure
gcloud resource-manager folders create \
  --display-name="Production-Regulated" \
  --organization=ORGANIZATION_ID

gcloud resource-manager folders create \
  --display-name="Platform-Infrastructure" \
  --organization=ORGANIZATION_ID

# Create HR data project in Production folder
gcloud projects create customer-hr-data \
  --folder=PRODUCTION_FOLDER_ID \
  --name="customer HR Data"

# Create KMS project in Production folder
gcloud projects create customer-hr-kms \
  --folder=PRODUCTION_FOLDER_ID \
  --name="customer HR KMS Keys"

# Create platform admin project in Infrastructure folder
gcloud projects create customer-platform-admin \
  --folder=PLATFORM_FOLDER_ID \
  --name="customer Platform Admin"
```

### Folder-Level IAM

```bash
# Grant HR team ownership of Production folder
gcloud resource-manager folders add-iam-policy-binding PRODUCTION_FOLDER_ID \
  --member=group:hr-leadership@customer.com \
  --role=roles/resourcemanager.folderAdmin

# Platform admins get NO access to Production folder
# They only get access to Platform folder
gcloud resource-manager folders add-iam-policy-binding PLATFORM_FOLDER_ID \
  --member=group:platform-admins@customer.com \
  --role=roles/resourcemanager.folderAdmin
```

---

## Layer 2: IAM Roles & Permissions

### Principle: Least Privilege + Separation of Concerns

| Role | Granted To | Scope | Permissions | Restrictions |
|------|-----------|-------|-------------|--------------|
| **Organization Admin** | IT Leadership | Organization | Billing, org policies | ❌ No data access |
| **Platform Admin** | Cloud Engineering | Platform Project | Infra management | ❌ No HR data access |
| **HR Data Owner** | HR Leadership | HR Data Project | Full control over HR dataset | ⚠️ Must be audited |
| **HR Data Steward** | HR Operations | HR Dataset | Read/write HR data | ❌ Cannot change IAM |
| **Analytics Engineer** | Data Team | Analytics Project | Query authorized views | ❌ No raw HR data |

### Custom Role: HR Platform Administrator

**Purpose:** Allow infrastructure management WITHOUT data access

```yaml
title: "HR Platform Administrator"
description: "Can manage BigQuery infrastructure but not access data"
stage: "GA"
includedPermissions:
  # Project management
  - resourcemanager.projects.get
  - resourcemanager.projects.list
  
  # BigQuery infrastructure (NO data access)
  - bigquery.datasets.create
  - bigquery.datasets.get
  - bigquery.jobs.create
  - bigquery.jobs.list
  
  # Monitoring
  - logging.logEntries.list
  - monitoring.timeSeries.list

excludedPermissions:
  # Explicitly exclude data access
  - bigquery.tables.getData
  - bigquery.tables.list
  - bigquery.rowAccessPolicies.*
```

### Create Custom Role

```bash
gcloud iam roles create hrPlatformAdmin \
  --project=customer-hr-data \
  --file=hr-platform-admin-role.yaml

# Grant to platform admins
gcloud projects add-iam-policy-binding customer-hr-data \
  --member=group:platform-admins@customer.com \
  --role=projects/customer-hr-data/roles/hrPlatformAdmin
```

### Critical IAM Best Practices

#### **❌ NEVER Grant These at Project/Folder/Org Level:**
```bash
# ❌ DANGEROUS - Grants access to ALL data
roles/bigquery.admin
roles/bigquery.dataOwner
roles/bigquery.dataEditor
roles/owner
```

#### **✅ CORRECT - Grant at Dataset Level Only:**
```bash
# ✅ Scoped to specific dataset
gcloud projects add-iam-policy-binding customer-hr-data \
  --member=group:hr-team@customer.com \
  --role=roles/bigquery.dataOwner \
  --condition=None

# Then use dataset-level permissions
bq update --dataset \
  --add_access_entry=role:roles/bigquery.dataOwner,userByEmail:hr-director@customer.com \
  customer-hr-data:prod_hr
```

### Organization Policy Constraints

```bash
# Prevent service account key extraction
gcloud org-policies set-policy <(cat <<EOF
name: projects/customer-hr-data/policies/iam.disableServiceAccountKeyCreation
spec:
  rules:
    - enforce: true
EOF
)

# Restrict domain for IAM members
gcloud org-policies set-policy <(cat <<EOF
name: projects/customer-hr-data/policies/iam.allowedPolicyMemberDomains
spec:
  rules:
    - values:
        allowedValues:
          - "customer.com"
EOF
)
```

---

## Layer 3: Column-Level Encryption

### Principle: Cryptographic Separation

**Even if someone gains database access, they cannot decrypt without the key.**

### Architecture

```
HR Team Controls Keys → Cloud KMS → Encrypts Data → BigQuery Table
         ↓                                              ↓
    Key Access             Platform Admin Sees:  AwECAXhtB7Qx...
    (HR only)              (encrypted blob, cannot decrypt)
```

### Implementation Steps

#### **Step 1: Create KMS Key Ring (HR Team Manages)**

```bash
# Create in separate KMS project (better security)
gcloud kms keyrings create hr-sensitive-data \
  --location=europe-west2 \
  --project=customer-hr-kms

# Create encryption key for different PII categories
gcloud kms keys create employee-ssn-key \
  --location=europe-west2 \
  --keyring=hr-sensitive-data \
  --purpose=encryption \
  --rotation-period=90d \
  --next-rotation-time=$(date -u -d "+90 days" +%Y-%m-%dT%H:%M:%SZ) \
  --project=customer-hr-kms

gcloud kms keys create employee-salary-key \
  --location=europe-west2 \
  --keyring=hr-sensitive-data \
  --purpose=encryption \
  --rotation-period=90d \
  --project=customer-hr-kms
```

#### **Step 2: Grant ONLY HR Team Key Access**

```bash
# HR team can encrypt/decrypt
gcloud kms keys add-iam-policy-binding employee-ssn-key \
  --location=europe-west2 \
  --keyring=hr-sensitive-data \
  --member=group:hr-team@customer.com \
  --role=roles/cloudkms.cryptoKeyEncrypterDecrypter \
  --project=customer-hr-kms

# Finance team can decrypt salary (not SSN)
gcloud kms keys add-iam-policy-binding employee-salary-key \
  --location=europe-west2 \
  --keyring=hr-sensitive-data \
  --member=group:finance-team@customer.com \
  --role=roles/cloudkms.cryptoKeyDecrypter \
  --project=customer-hr-kms

# Platform admins get NO access to any keys
# (This is the key to zero-trust!)
```

#### **Step 3: Encrypt Data in BigQuery**

```sql
-- Add encrypted columns
ALTER TABLE prod_hr.employees
ADD COLUMN ssn_encrypted BYTES;

ALTER TABLE prod_hr.employees
ADD COLUMN salary_encrypted BYTES;

-- Encrypt existing data
UPDATE prod_hr.employees
SET ssn_encrypted = KEYS.ENCRYPT(
  'projects/customer-hr-kms/locations/europe-west2/keyRings/hr-sensitive-data/cryptoKeys/employee-ssn-key',
  ssn,
  'AEAD_AES_GCM_256'
)
WHERE ssn_encrypted IS NULL;

UPDATE prod_hr.employees
SET salary_encrypted = KEYS.DETERMINISTIC_ENCRYPT(
  'projects/customer-hr-kms/locations/europe-west2/keyRings/hr-sensitive-data/cryptoKeys/employee-salary-key',
  CAST(salary AS STRING),
  'AEAD_AES_SIV_CMAC_256'
)
WHERE salary_encrypted IS NULL;

-- Drop original unencrypted columns
ALTER TABLE prod_hr.employees DROP COLUMN ssn;
ALTER TABLE prod_hr.employees DROP COLUMN salary;
```

#### **Step 4: Query with Decryption (HR Team Only)**

```sql
-- HR team queries (they have KMS key access)
SELECT 
  employee_id,
  first_name,
  KEYS.DECRYPT_STRING(
    'projects/customer-hr-kms/locations/europe-west2/keyRings/hr-sensitive-data/cryptoKeys/employee-ssn-key',
    ssn_encrypted,
    'AEAD_AES_GCM_256'
  ) AS ssn,
  CAST(KEYS.DECRYPT_STRING(
    'projects/customer-hr-kms/locations/europe-west2/keyRings/hr-sensitive-data/cryptoKeys/employee-salary-key',
    salary_encrypted,
    'AEAD_AES_SIV_CMAC_256'
  ) AS INT64) AS salary
FROM prod_hr.employees
WHERE department = 'Engineering';
```

#### **Step 5: Platform Admin Sees Encrypted Blobs**

```sql
-- Platform admin runs query
SELECT 
  employee_id,
  first_name,
  ssn_encrypted,
  salary_encrypted
FROM prod_hr.employees;

-- Result: Can see table structure but data is encrypted
-- employee_id | first_name | ssn_encrypted          | salary_encrypted
-- 12345       | John       | AwECAXhtB7Qx29vF...   | BxFDBYiuC8RyT3mN...

-- ❌ Admin cannot decrypt without KMS key access
SELECT KEYS.DECRYPT_STRING(..., ssn_encrypted, ...) FROM prod_hr.employees;
-- ERROR: Permission 'cloudkms.cryptoKeyVersions.useToDecrypt' denied
```

### Why This Works

1. ✅ Table data is accessible (admins can manage infrastructure)
2. ✅ But sensitive columns are encrypted blobs
3. ✅ Decryption requires Cloud KMS key access
4. ✅ Only HR team has KMS key permissions
5. ✅ All KMS access is logged and auditable
6. ✅ Keys are in separate project (extra isolation)

---

## Layer 4: VPC Service Controls

### Principle: Network-Level Data Exfiltration Prevention

**Create a "fortress" around HR data that blocks all unauthorized network access.**

### What VPC-SC Prevents

```
Attack Scenarios BLOCKED by VPC-SC:

1. Copy to External Bucket:
   bq extract prod_hr.employees gs://attacker-bucket/stolen.csv
   ❌ ERROR: VPC Service Controls violation

2. Query from Unauthorized Network:
   User queries from home laptop
   ❌ ERROR: Source IP not in allowed access level

3. Cross-Project Data Copy:
   CREATE TABLE personal_project.test AS SELECT * FROM prod_hr.employees
   ❌ ERROR: Cannot write to resource outside perimeter

4. Public Dataset Exposure:
   Even if IAM allows public access, VPC-SC denies

5. Service Account Key Extraction:
   Admin downloads key, uses from home
   ❌ ERROR: Source network not authorized
```

### Implementation

#### **Step 1: Create Access Level (Corporate Network Only)**

```bash
# Define allowed networks
cat > hr-access-level.yaml <<EOF
- ipSubnetworks:
  - 192.168.1.0/24      # customer London office
  - 10.0.0.0/16         # customer VPN range
  - 172.16.0.0/12       # GCP private ranges
EOF

gcloud access-context-manager levels create customer-corporate-network \
  --title="customer Corporate Network" \
  --basic-level-spec=hr-access-level.yaml \
  --policy=customer-access-policy
```

#### **Step 2: Create VPC Service Perimeter**

```bash
# Get project number
PROJECT_NUMBER=$(gcloud projects describe customer-hr-data \
  --format="value(projectNumber)")

# Create perimeter (DRY RUN first!)
gcloud access-context-manager perimeters create hr-data-perimeter \
  --title="HR Sensitive Data Perimeter" \
  --resources=projects/$PROJECT_NUMBER \
  --restricted-services=bigquery.googleapis.com,storage.googleapis.com \
  --access-levels=customer-corporate-network \
  --policy=customer-access-policy \
  --perimeter-type=regular \
  --enforcement-mode=dryrun
```

#### **Step 3: Configure Ingress Rules**

```yaml
# Allow ETL pipeline from Workday
ingressPolicies:
  - ingressFrom:
      identityType: ANY_SERVICE_ACCOUNT
      sources:
        - accessLevel: accessPolicies/customer-access-policy/accessLevels/customer-corporate-network
    ingressTo:
      operations:
        - serviceName: bigquery.googleapis.com
          methodSelectors:
            - method: 'google.cloud.bigquery.v2.JobService.InsertJob'
            - method: 'google.cloud.bigquery.v2.TableDataService.InsertAll'
      resources:
        - 'projects/PROJECT_NUMBER'
```

#### **Step 4: Configure Egress Rules**

```yaml
# Block ALL egress by default
# Allow ONLY to analytics project for authorized views
egressPolicies:
  - egressFrom:
      identityType: ANY_IDENTITY
    egressTo:
      operations:
        - serviceName: bigquery.googleapis.com
          methodSelectors:
            - method: 'google.cloud.bigquery.v2.JobService.Query'
      resources:
        - 'projects/ANALYTICS_PROJECT_NUMBER'
```

#### **Step 5: Test in Dry Run Mode**

```bash
# Review violations for 2 weeks
gcloud logging read \
  "protoPayload.metadata.dryRun=true AND resource.type=bigquery_resource" \
  --limit=100 \
  --format=json \
  --project=customer-hr-data
```

#### **Step 6: Enforce Perimeter**

```bash
# After validating no false positives
gcloud access-context-manager perimeters update hr-data-perimeter \
  --set-enforcement-mode=enforced \
  --policy=customer-access-policy
```

### Monitor VPC-SC Violations

```sql
-- Real-time monitoring query
SELECT
  timestamp,
  protoPayload.authenticationInfo.principalEmail as user,
  protoPayload.metadata.violationReason,
  protoPayload.metadata.serviceContext.targetResource as blocked_resource,
  protoPayload.requestMetadata.callerIp as source_ip
FROM
  `customer-hr-data._logs.cloudaudit_googleapis_com_data_access_*`
WHERE
  protoPayload.metadata.violationReason IS NOT NULL
  AND DATE(_PARTITIONTIME) >= CURRENT_DATE() - 7
ORDER BY timestamp DESC;
```

---

## Layer 5: Break-Glass Emergency Access

### Principle: Just-In-Time Privileged Access

**Emergency scenarios require controlled, audited access to sensitive data.**

### Architecture

```
Emergency Request
├── Step 1: File ticket in ITSM system
│   └── Business justification required
│
├── Step 2: Multi-Person Authorization
│   ├── HR Director approves (business need)
│   ├── Security Officer approves (risk assessment)
│   └── Compliance Officer approves (regulatory check)
│
├── Step 3: Automated Grant (Cloud Function)
│   ├── IAM: Temporary dataViewer role (4 hours)
│   ├── KMS: Temporary decrypt permission (4 hours)
│   └── VPC-SC: Temporary ingress rule (4 hours)
│
├── Step 4: Real-Time Monitoring
│   ├── Every query logged
│   ├── Slack alert to HR Director + Security
│   └── Dashboard shows active break-glass sessions
│
└── Step 5: Auto-Revocation
    ├── Access expires after 4 hours
    ├── All temp policies removed
    └── Post-access audit report generated
```

### Implementation

#### **Create Break-Glass Service Account**

```bash
# Create special service account (never used except emergencies)
gcloud iam service-accounts create hr-break-glass \
  --display-name="HR Break-Glass Emergency Access" \
  --description="EMERGENCY USE ONLY - All access logged" \
  --project=customer-hr-data

# No default permissions - completely locked down initially
```

#### **JIT Access Workflow (Cloud Function)**

```python
# deploy to Cloud Functions
from google.cloud import bigquery, kms, secretmanager
from datetime import datetime, timedelta
import json

def grant_break_glass_access(request):
    """
    Grants temporary break-glass access after multi-person approval
    """
    request_json = request.get_json()
    
    # Validate approvals
    required_approvers = [
        'hr-director@customer.com',
        'security-officer@customer.com', 
        'compliance@customer.com'
    ]
    
    approvals = request_json.get('approvals', [])
    if not all(approver in approvals for approver in required_approvers):
        return {'error': 'Insufficient approvals - need HR + Security + Compliance'}, 403
    
    # Grant time-boxed access
    expiry = datetime.utcnow() + timedelta(hours=4)
    
    # 1. Grant temporary BigQuery access
    grant_temporary_bigquery_access(expiry)
    
    # 2. Grant temporary KMS key access
    grant_temporary_kms_access(expiry)
    
    # 3. Add temporary VPC-SC ingress rule
    add_temporary_vpc_ingress(expiry)
    
    # 4. Send alerts
    send_break_glass_alerts(request_json, expiry)
    
    # 5. Schedule auto-revocation
    schedule_auto_revoke(expiry)
    
    return {
        'status': 'granted',
        'expires_at': expiry.isoformat(),
        'service_account': 'hr-break-glass@customer-hr-data.iam.gserviceaccount.com'
    }

def grant_temporary_bigquery_access(expiry):
    """Grant time-boxed BigQuery dataViewer role"""
    # Use IAM conditions for temporary access
    policy_binding = {
        'role': 'roles/bigquery.dataViewer',
        'members': ['serviceAccount:hr-break-glass@customer-hr-data.iam.gserviceaccount.com'],
        'condition': {
            'title': 'Emergency Access',
            'description': 'Break-glass emergency access',
            'expression': f'request.time < timestamp("{expiry.isoformat()}Z")'
        }
    }
    # Apply to dataset...

def send_break_glass_alerts(request_json, expiry):
    """Send real-time alerts"""
    message = f"""
    ⚠️ BREAK-GLASS ACCESS GRANTED ⚠️
    
    Service Account: hr-break-glass@customer-hr-data.iam.gserviceaccount.com
    Approved By: {', '.join(request_json['approvals'])}
    Justification: {request_json.get('justification', 'N/A')}
    Expires: {expiry.isoformat()} UTC
    
    All queries will be logged and monitored.
    """
    
    # Send to Slack
    send_slack_alert('#hr-security-alerts', message)
    
    # Send PagerDuty alert
    send_pagerduty_alert('hr-oncall', message)
    
    # Send email to security team
    send_email('security-team@customer.com', 'Break-Glass Access Granted', message)
```

### Audit Break-Glass Activity

```sql
-- Monitor all break-glass account activity
CREATE OR REPLACE TABLE prod_hr.break_glass_audit AS
SELECT
  timestamp,
  protoPayload.authenticationInfo.principalEmail as service_account,
  protoPayload.resourceName as resource_accessed,
  protoPayload.methodName as action,
  protoPayload.requestMetadata.callerIp as source_ip,
  protoPayload.serviceData.jobCompletedEvent.job.jobConfiguration.query.query as query_text,
  ARRAY(
    SELECT column_name 
    FROM UNNEST(protoPayload.metadata.tableDataRead.fields) as column_name
  ) as columns_accessed
FROM
  `customer-hr-data._logs.cloudaudit_googleapis_com_data_access_*`
WHERE
  protoPayload.authenticationInfo.principalEmail = 'hr-break-glass@customer-hr-data.iam.gserviceaccount.com'
  AND _PARTITIONTIME >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY);

-- Create real-time alert
CREATE OR REPLACE ALERT hr_break_glass_activity_alert
OPTIONS (
  alert_policy = 'immediate',
  notification_channels = ['slack-hr-security-alerts', 'pagerduty-security-oncall']
)
AS
SELECT *
FROM prod_hr.break_glass_audit
WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 5 MINUTE);
```

---

## Layer 6: Comprehensive Audit Logging

### Principle: Complete Visibility into All Data Access

**If unauthorized access somehow occurs, we MUST know immediately.**

### What to Log

```
Data Access Logs (bigquery.tables.getData):
├── Who accessed data (user/service account)
├── When they accessed it (timestamp)
├── Which tables/columns (resource names)
├── Source IP address
├── Query text (full SQL)
└── Rows returned (count)

Admin Activity Logs (IAM changes):
├── Who changed permissions
├── What permissions changed
├── Previous vs new policy
└── Justification (if provided)

KMS Logs (decrypt operations):
├── Who decrypted data
├── Which encryption key used
├── Timestamp
└── Source identity

VPC-SC Logs (violations):
├── Attempted access outside perimeter
├── Source IP and identity
├── Blocked operation
└── Violation reason
```

### Enable Audit Logging

```bash
# Enable data access logs for BigQuery
gcloud projects get-iam-policy customer-hr-data \
  --format=json > policy.json

# Add audit config
cat > audit-config.json <<EOF
{
  "auditConfigs": [
    {
      "service": "bigquery.googleapis.com",
      "auditLogConfigs": [
        {
          "logType": "ADMIN_READ"
        },
        {
          "logType": "DATA_READ"
        },
        {
          "logType": "DATA_WRITE"
        }
      ]
    }
  ]
}
EOF

# Apply
gcloud projects set-iam-policy customer-hr-data policy.json
```

### Security Monitoring Queries

```sql
-- Query 1: Unauthorized access attempts
CREATE OR REPLACE VIEW security.unauthorized_access_attempts AS
SELECT
  timestamp,
  protopayload_auditlog.authenticationInfo.principalEmail as user,
  protopayload_auditlog.resourceName as resource,
  protopayload_auditlog.authorizationInfo[0].permission as permission_required,
  protopayload_auditlog.requestMetadata.callerIp as source_ip
FROM
  `customer-hr-data._logs.cloudaudit_googleapis_com_activity_*`
WHERE
  protopayload_auditlog.authorizationInfo[0].granted = false
  AND _PARTITIONTIME >= CURRENT_DATE() - 7
ORDER BY timestamp DESC;

-- Query 2: Admin actions on HR data
CREATE OR REPLACE VIEW security.admin_actions_on_hr_data AS
SELECT
  timestamp,
  protopayload_auditlog.authenticationInfo.principalEmail as admin_user,
  protopayload_auditlog.methodName as action,
  protopayload_auditlog.resourceName as affected_resource,
  JSON_EXTRACT_SCALAR(protopayload_auditlog.request, '$.policy') as policy_change
FROM
  `customer-hr-data._logs.cloudaudit_googleapis_com_activity_*`
WHERE
  protopayload_auditlog.methodName IN (
    'google.iam.v1.IAMPolicy.SetIamPolicy',
    'v2.TableService.PatchTable',
    'v2.DatasetService.PatchDataset'
  )
  AND _PARTITIONTIME >= CURRENT_DATE() - 30
ORDER BY timestamp DESC;

-- Query 3: Anomalous data access patterns
CREATE OR REPLACE VIEW security.anomalous_hr_data_access AS
SELECT
  protopayload_auditlog.authenticationInfo.principalEmail as user,
  DATE(_PARTITIONTIME) as access_date,
  COUNT(*) as query_count,
  SUM(protopayload_auditlog.metadata.tableDataRead.rowCount) as total_rows_accessed,
  ARRAY_AGG(DISTINCT protopayload_auditlog.resourceName LIMIT 10) as tables_accessed
FROM
  `customer-hr-data._logs.cloudaudit_googleapis_com_data_access_*`
WHERE
  _PARTITIONTIME >= CURRENT_DATE() - 7
GROUP BY user, access_date
HAVING 
  query_count > 100  -- Unusual number of queries
  OR total_rows_accessed > 10000  -- Unusual amount of data
ORDER BY query_count DESC;
```

### Real-Time Alerting

```yaml
# Cloud Monitoring Alert Policy
alertPolicy:
  displayName: "Admin Accessing HR Sensitive Data"
  conditions:
    - displayName: "Platform admin querying prod_hr dataset"
      conditionThreshold:
        filter: |
          resource.type="bigquery_resource"
          AND protoPayload.authenticationInfo.principalEmail=~".*platform-admin.*"
          AND protoPayload.resourceName=~".*prod_hr.*"
        aggregations:
          - alignmentPeriod: 60s
            perSeriesAligner: ALIGN_RATE
        comparison: COMPARISON_GT
        thresholdValue: 0
        duration: 0s
  notificationChannels:
    - "projects/customer-hr-data/notificationChannels/slack-security"
    - "projects/customer-hr-data/notificationChannels/pagerduty-oncall"
  alertStrategy:
    autoClose: 3600s
```

---

## Implementation Checklist

### Phase 1: Foundation (Week 1-2)

- [ ] Create GCP folder structure (Production vs Platform)
- [ ] Create customer-hr-data project in Production folder
- [ ] Create customer-hr-kms project in Production folder
- [ ] Create Google Groups:
  - [ ] hr-leadership@customer.com
  - [ ] hr-team@customer.com
  - [ ] platform-admins@customer.com
  - [ ] finance-team@customer.com
- [ ] Enable required APIs (BigQuery, KMS, Access Context Manager)
- [ ] Document separation of duties matrix

### Phase 2: IAM Configuration (Week 3)

- [ ] Remove all bigquery.admin roles from project-level
- [ ] Create custom "HR Platform Admin" role
- [ ] Grant HR team dataOwner on prod_hr dataset only
- [ ] Grant platform admins jobUser at project level only
- [ ] Set organization policy constraints:
  - [ ] iam.disableServiceAccountKeyCreation
  - [ ] iam.allowedPolicyMemberDomains
  - [ ] sql.restrictAuthorizedNetworks
- [ ] Test: Verify platform admin CANNOT query HR data

### Phase 3: Encryption (Week 4-5)

- [ ] Create Cloud KMS key ring in customer-hr-kms project
- [ ] Create encryption keys:
  - [ ] employee-ssn-key
  - [ ] employee-salary-key
  - [ ] performance-review-key
  - [ ] bank-details-key
- [ ] Grant ONLY HR team KMS permissions
- [ ] Add encrypted columns to tables
- [ ] Encrypt existing data
- [ ] Test HR team can decrypt
- [ ] Test platform admin sees encrypted blobs
- [ ] Drop original unencrypted columns
- [ ] Update queries to use DECRYPT functions

### Phase 4: VPC Service Controls (Week 6-7)

- [ ] Create access level for corporate network
- [ ] Create VPC-SC perimeter (DRY RUN mode)
- [ ] Configure ingress rules (ETL pipelines)
- [ ] Configure egress rules (authorized views only)
- [ ] Test in dry-run for 2 weeks
- [ ] Review violation logs
- [ ] Adjust policies based on violations
- [ ] Enforce perimeter in production
- [ ] Test: Verify cannot copy data outside perimeter

### Phase 5: Break-Glass (Week 8)

- [ ] Create break-glass service account
- [ ] Deploy JIT access Cloud Function
- [ ] Configure multi-person approval workflow
- [ ] Set up automatic access revocation
- [ ] Create real-time alerting for break-glass usage
- [ ] Document emergency procedures
- [ ] Test full break-glass workflow
- [ ] Train Security Operations team

### Phase 6: Monitoring & Audit (Week 9-10)

- [ ] Enable Data Access logs on all HR datasets
- [ ] Enable Admin Activity logs
- [ ] Create security monitoring views
- [ ] Set up Cloud Monitoring alerts:
  - [ ] Admin accessing HR data → PagerDuty
  - [ ] VPC-SC violation → Slack + Email
  - [ ] Break-glass granted → Slack + SMS
  - [ ] Anomalous query patterns → Email
- [ ] Create weekly security dashboard
- [ ] Schedule monthly access reviews
- [ ] Document incident response procedures

### Phase 7: Testing & Validation (Week 11)

- [ ] Penetration testing: Can admin access HR data?
- [ ] Red team exercise: Attempt data exfiltration
- [ ] Test break-glass end-to-end
- [ ] Validate audit logs capture everything
- [ ] Performance testing: Check query latency
- [ ] Compliance review (GDPR, SOC 2)
- [ ] Document test results

### Phase 8: Documentation & Training (Week 12)

- [ ] Complete architecture documentation
- [ ] Create runbooks:
  - [ ] Emergency access procedures
  - [ ] Incident response for data breach
  - [ ] Adding new HR data fields
  - [ ] Key rotation procedures
- [ ] Train HR team on encryption/decryption
- [ ] Train platform admins on limitations
- [ ] Train Security Operations on monitoring
- [ ] Conduct tabletop exercise

---

## Ongoing Governance

### Monthly Activities

- [ ] Review all HR data access logs
- [ ] Investigate anomalous query patterns
- [ ] Validate VPC-SC perimeter effectiveness
- [ ] Check for new service accounts created
- [ ] Review Cloud KMS access logs
- [ ] Update security dashboard metrics

### Quarterly Activities

- [ ] Complete access review (recertify all permissions)
- [ ] Rotate Cloud KMS keys
- [ ] Update organization policies if needed
- [ ] Security awareness training for new hires
- [ ] Red team exercise (simulated breach)
- [ ] Review and update incident response procedures

### Annual Activities

- [ ] External security audit (penetration testing)
- [ ] Compliance certification renewal (SOC 2, ISO 27001)
- [ ] Review and update security policies
- [ ] Disaster recovery drill (including break-glass)
- [ ] Assess new GCP security features
- [ ] Tabletop exercise with leadership

---

## Related Documentation

- [BigQuery Security Features Overview](./1-bigquery-security-overview.md) - Feature catalog
- [customer Implementation Guide](./3-customer-implementation-guide.md) - Data ingestion pipeline

---

**Document Version:** 2.0  
**Last Updated:** February 10, 2026  
**Next Review:** May 10, 2026  
**Maintained By:** customer Data Security Team + EPAM Solutions Architecture
