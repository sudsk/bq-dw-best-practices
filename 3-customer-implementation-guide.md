# customer Data Ingestion & Encryption Guide
## API → GCS → External Table → Encrypted BigQuery

**Document Version:** 1.0  
**Last Updated:** February 10, 2026  
**Audience:** Data Engineers, Developers, Airflow Maintainers  
**Purpose:** Practical implementation for customer data pipeline

---

## Table of Contents

1. [Pipeline Architecture](#pipeline-architecture)
2. [Data Classification & Mapping](#data-classification--mapping)
3. [GCS Bucket Security](#gcs-bucket-security)
4. [External Table Implementation](#external-table-implementation)
5. [Encryption Strategy](#encryption-strategy)
6. [Airflow DAG Implementation](#airflow-dag-implementation)
7. [Dynamic Data Masking Setup](#dynamic-data-masking-setup)
8. [Azure AD Integration](#azure-ad-integration)
9. [Decision Framework](#decision-framework)
10. [Performance Benchmarks](#performance-benchmarks)
11. [FAQ](#faq)
12. [Related Documentation](#related-documentation)

---

## Pipeline Architecture

### Current State (Your Design)

```
┌──────────────┐
│ Source API   │ (Sends CSV data)
└──────┬───────┘
       │
       ▼
┌─────────────────────────────────────────────────┐
│        Cloud Storage Bucket                     │
│        gs://wtrydal-gs-04/                      │
│                                                  │
│  ├── incoming_data.csv                          │
│  └── (CMEK encrypted at rest)                   │
└─────────────────┬───────────────────────────────┘
                  │
                  ▼ (Cloud Function triggered)
┌─────────────────────────────────────────────────┐
│    Cloud Function: CF_General_Trigger_Dag       │
│    └── Triggers Airflow DAG                     │
└─────────────────┬───────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────┐
│         Airflow DAG (Python Code)               │
│                                                  │
│  Step 1: Create External Table                  │
│          └── Points to GCS CSV                  │
│                                                  │
│  Step 2: Generate Encryption SQL                │
│          └── Based on mapping sheet             │
│                                                  │
│  Step 3: Execute CREATE TABLE AS SELECT         │
│          └── Encrypt PII columns with KMS       │
│                                                  │
│  Step 4: Validate & Clean Up                    │
│          └── Drop external table                │
└─────────────────┬───────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────┐
│        BigQuery: ctng_dataset                   │
│                                                  │
│  ├── ext_raw_data (external table - temp)       │
│  │   └── Points to GCS                          │
│  │                                               │
│  └── final_table (native table - permanent)     │
│      ├── Non-PII columns (plain text)           │
│      └── PII columns (KMS encrypted)            │
└─────────────────────────────────────────────────┘
```

### Key Design Decisions

**✅ Why External Table Approach:**
1. **Zero PII Storage Risk** - CSV data never stored unencrypted in BigQuery
2. **Simple SQL-Based** - No complex Python encryption code needed
3. **High Performance** - BigQuery native encryption at scale
4. **Cost-Effective** - No Cloud DLP API costs
5. **Metadata-Driven** - Mapping sheet controls which columns encrypt

**✅ Why Not Pre-Encrypt in Python:**
1. Adds complexity to pipeline
2. Slower (row-by-row API calls)
3. More expensive (DLP API costs)
4. Harder to maintain

**✅ Why Not Post-Load Encryption:**
1. Brief window where PII stored unencrypted
2. Additional schema management (original + encrypted columns)
3. Extra ALTER TABLE operations

---

## Data Classification & Mapping

### Your Mapping Sheet Structure

Based on your spreadsheet, you have these columns in the mapping sheet:

| Column Name | Field Path | Business Glossary | Data Type | Primary Key | Security Class | Classified By | Comment |
|-------------|------------|-------------------|-----------|-------------|----------------|---------------|---------|
| Created_By_Email_Address | ... | ... | STRING | N | PII | BI Dev Team | Employee email |
| Created_By_Full_Name | ... | ... | STRING | N | PII | BI Dev Team | Employee name |
| Assigned_To_Email_Address | ... | ... | STRING | N | PII | BI Dev Team | Employee email |
| Assigned_To_Full_Name | ... | ... | STRING | N | PII | BI Dev Team | Employee name |
| Processing_Date_Time | ... | ... | TIMESTAMP | N | Not PII | BI Dev Team | |
| Event_Date_Time | ... | ... | TIMESTAMP | N | Not PII | BI Dev Team | |

### Recommended Classification

#### **For Employee Audit Columns:**

After discussion about whether employee work emails are truly PII requiring encryption, here's the recommendation:

**Option 1: No Encryption (Recommended for customer) ✅**

**Rationale:**
- These are **work audit trails** (who created/assigned records)
- **Not highly sensitive** (no salaries, performance reviews, medical data)
- **Business need** for visibility (troubleshooting, reporting)
- **Industry standard** - Most companies don't encrypt audit columns
- **UK GDPR** - Encryption not required for low-risk employee data

**Instead, use:**
- IAM access controls (who can query)
- Row-Level Security (if multi-tenant)
- Audit logging (monitor who accesses)
- Dynamic Data Masking (if needed for external users)

**Update your mapping:**
```
Security_Class column values:
- "PII" → Remove this classification for audit columns
- "Not PII" → Use this for employee emails/names in audit context
```

**Option 2: Dynamic Data Masking (If Compliance Requires)**

If your stakeholders or compliance team requires some protection:

```sql
-- Apply DDM instead of encryption
CREATE DATA POLICY hash_employee_emails
ON (SELECT policy_tag FROM `project.taxonomy.Employee-Email`)
MASKING RULE hash(email, "SHA256")
GRANT TO ("group:external-users@customer.com");

-- Internal team sees real emails
GRANT `roles/datacatalog.categoryFineGrainedReader`
ON TAG `project.taxonomy.Employee-Email`
TO "group:customer-employees@customer.com";
```

**Benefits:**
- Fast performance
- Flexible (change masking rules easily)
- No encryption overhead
- Multiple user personas supported

### Mapping Sheet Upload

**Store mapping in BigQuery for easy access:**

```sql
-- Create config dataset
CREATE SCHEMA IF NOT EXISTS customer-data-platform.config_dataset;

-- Upload mapping sheet as table
bq load \
  --source_format=CSV \
  --skip_leading_rows=1 \
  --autodetect \
  customer-data-platform:config_dataset.column_mapping \
  gs://config-bucket/column_mapping.csv

-- Query mapping
SELECT Column, Security_Class
FROM `customer-data-platform.config_dataset.column_mapping`
WHERE Security_Class IN ('PII', 'Not PII');
```

---

## GCS Bucket Security

### Layer 1: Customer-Managed Encryption Keys (CMEK)

**Encrypt bucket with your own KMS key:**

```bash
# 1. Create KMS key for GCS
gcloud kms keys create gcs-bucket-encryption-key \
  --location=europe-west2 \
  --keyring=pii-encryption \
  --purpose=encryption \
  --rotation-period=90d \
  --project=customer-data-platform

# 2. Grant GCS service account access
PROJECT_NUMBER=$(gcloud projects describe customer-data-platform \
  --format="value(projectNumber)")

gcloud kms keys add-iam-policy-binding gcs-bucket-encryption-key \
  --location=europe-west2 \
  --keyring=pii-encryption \
  --member=serviceAccount:service-${PROJECT_NUMBER}@gs-project-accounts.iam.gserviceaccount.com \
  --role=roles/cloudkms.cryptoKeyEncrypterDecrypter \
  --project=customer-data-platform

# 3. Set default encryption on bucket
gsutil kms encryption \
  -k projects/customer-data-platform/locations/europe-west2/keyRings/pii-encryption/cryptoKeys/gcs-bucket-encryption-key \
  gs://wtrydal-gs-04

# All new files automatically encrypted with your key
```

**Result:**
- ✅ Files encrypted at rest with YOUR key
- ✅ Google admins cannot decrypt without key access
- ✅ Automatic encryption on upload
- ✅ Free (no additional cost)

### Layer 2: Lifecycle Policy (Auto-Delete)

**Delete CSV files after successful load:**

```json
{
  "lifecycle": {
    "rule": [
      {
        "action": {
          "type": "Delete"
        },
        "condition": {
          "age": 1,
          "matchesPrefix": ["incoming_data"]
        }
      }
    ]
  }
}
```

```bash
# Apply lifecycle policy
gsutil lifecycle set lifecycle-policy.json gs://wtrydal-gs-04
```

**Benefits:**
- Reduces data exposure window (files exist for <24 hours)
- Automatic cleanup (no manual intervention)
- Compliance-friendly (data minimization)

### Layer 3: IAM Access Control

```bash
# Only Cloud Function can write to bucket
gsutil iam ch \
  serviceAccount:cf-general-mve@customer-data-platform.iam.gserviceaccount.com:objectCreator \
  gs://wtrydal-gs-04

# Only Airflow can read from bucket
gsutil iam ch \
  serviceAccount:airflow-sa@customer-data-platform.iam.gserviceaccount.com:objectViewer \
  gs://wtrydal-gs-04

# No public access
gsutil iam ch -d allUsers:objectViewer gs://wtrydal-gs-04
gsutil iam ch -d allAuthenticatedUsers:objectViewer gs://wtrydal-gs-04
```

### Layer 4: VPC Service Controls (Optional - High Security)

**If you need to prevent data exfiltration from GCS:**

```bash
# Add GCS bucket project to VPC-SC perimeter
gcloud access-context-manager perimeters update data-perimeter \
  --add-resources=projects/PROJECT_NUMBER \
  --restricted-services=storage.googleapis.com \
  --policy=customer-access-policy
```

---

## External Table Implementation

### Step 1: Create External Table

**In Airflow DAG or BigQuery SQL:**

```sql
-- Create external table pointing to GCS CSV
CREATE OR REPLACE EXTERNAL TABLE `customer-data-platform.ctng_dataset.ext_raw_data`
OPTIONS (
  format = 'CSV',
  uris = ['gs://wtrydal-gs-04/incoming_data.csv'],
  skip_leading_rows = 1,
  field_delimiter = ',',
  allow_quoted_newlines = TRUE,
  allow_jagged_rows = FALSE,
  ignore_unknown_values = FALSE,
  max_bad_records = 0
);

-- Verify schema auto-detection worked
SELECT * FROM `customer-data-platform.ctng_dataset.ext_raw_data` LIMIT 10;
```

**Alternative with explicit schema:**

```sql
CREATE OR REPLACE EXTERNAL TABLE `customer-data-platform.ctng_dataset.ext_raw_data`
(
  Processing_Date_Time TIMESTAMP,
  Event_Date_Time TIMESTAMP,
  Ingestion_Method STRING,
  Source_System_Name STRING,
  ID STRING,
  Action_Number INT64,
  Description STRING,
  Type INT64,
  Type_Name STRING,
  Org_Chart_ID STRING,
  Org_Chart_Name STRING,
  Reference_Number INT64,
  Relates_To STRING,
  Created_By_ID STRING,
  Created_By_Full_Name STRING,
  Created_By_Email_Address STRING,
  Assigned_To_ID STRING,
  Assigned_To_Full_Name STRING,
  Assigned_To_Email_Address STRING
  -- ... rest of columns
)
OPTIONS (
  format = 'CSV',
  uris = ['gs://wtrydal-gs-04/incoming_data.csv'],
  skip_leading_rows = 1
);
```

### Step 2: Validate External Table

```sql
-- Check row count
SELECT COUNT(*) as row_count
FROM `customer-data-platform.ctng_dataset.ext_raw_data`;

-- Check for NULL values in key columns
SELECT
  COUNTIF(ID IS NULL) as null_ids,
  COUNTIF(Action_Number IS NULL) as null_action_numbers,
  COUNTIF(Created_By_Email_Address IS NULL) as null_emails
FROM `customer-data-platform.ctng_dataset.ext_raw_data`;

-- Sample data quality check
SELECT *
FROM `customer-data-platform.ctng_dataset.ext_raw_data`
WHERE ID IS NULL
   OR Action_Number IS NULL
LIMIT 100;
```

---

## Encryption Strategy

### Decision: Use KMS Encryption or Not?

Based on our discussion, here's the decision framework:

#### **Scenario 1: Low-Risk Audit Data (Recommended)**

**If your data is:**
- ❌ NOT performance reviews
- ❌ NOT disciplinary records
- ❌ NOT salary information
- ❌ NOT health/medical data
- ✅ JUST workflow audit trails (who created/assigned records)

**Then: DON'T ENCRYPT**

```sql
-- Simple CREATE TABLE AS SELECT (no encryption)
CREATE OR REPLACE TABLE `customer-data-platform.ctng_dataset.final_table` AS
SELECT
  Processing_Date_Time,
  Event_Date_Time,
  Ingestion_Method,
  Source_System_Name,
  ID,
  Action_Number,
  Description,
  
  -- Audit columns (NO encryption)
  Created_By_Email_Address,
  Created_By_Full_Name,
  Assigned_To_Email_Address,
  Assigned_To_Full_Name,
  
  Created_Date,
  Updated_Date
FROM `customer-data-platform.ctng_dataset.ext_raw_data`;
```

**Apply security through:**
- IAM roles (dataset-level access control)
- Audit logging (monitor who accesses)
- Optional: Dynamic Data Masking for external users

#### **Scenario 2: High-Risk Sensitive Data**

**If your data includes:**
- ✅ SSN / National Insurance Numbers
- ✅ Bank account details
- ✅ Salary amounts
- ✅ Performance ratings
- ✅ Medical records

**Then: USE KMS ENCRYPTION**

### KMS Encryption Implementation

**Step 1: Create KMS Key**

```bash
gcloud kms keys create employee-pii-key \
  --location=europe-west2 \
  --keyring=pii-encryption \
  --purpose=encryption \
  --rotation-period=90d \
  --project=customer-data-platform
```

**Step 2: Grant Access**

```bash
# Airflow service account needs encrypt permission
gcloud kms keys add-iam-policy-binding employee-pii-key \
  --location=europe-west2 \
  --keyring=pii-encryption \
  --member=serviceAccount:airflow-sa@customer-data-platform.iam.gserviceaccount.com \
  --role=roles/cloudkms.cryptoKeyEncrypter

# HR team needs decrypt permission
gcloud kms keys add-iam-policy-binding employee-pii-key \
  --location=europe-west2 \
  --keyring=pii-encryption \
  --member=group:hr-team@customer.com \
  --role=roles/cloudkms.cryptoKeyDecrypter
```

**Step 3: Encrypt During CREATE TABLE**

```sql
-- Define KMS key path
DECLARE kms_key STRING;
SET kms_key = 'projects/customer-data-platform/locations/europe-west2/keyRings/pii-encryption/cryptoKeys/employee-pii-key';

-- Create table with encrypted columns
CREATE OR REPLACE TABLE `customer-data-platform.ctng_dataset.final_table` AS
SELECT
  -- Non-PII columns (pass through)
  Processing_Date_Time,
  Event_Date_Time,
  ID,
  Action_Number,
  Description,
  
  -- PII columns (encrypt with KMS)
  KEYS.DETERMINISTIC_ENCRYPT(
    kms_key,
    Created_By_Email_Address,
    'AEAD_AES_SIV_CMAC_256'
  ) AS Created_By_Email_Address_encrypted,
  
  KEYS.DETERMINISTIC_ENCRYPT(
    kms_key,
    Created_By_Full_Name,
    'AEAD_AES_SIV_CMAC_256'
  ) AS Created_By_Full_Name_encrypted,
  
  KEYS.DETERMINISTIC_ENCRYPT(
    kms_key,
    Assigned_To_Email_Address,
    'AEAD_AES_SIV_CMAC_256'
  ) AS Assigned_To_Email_Address_encrypted,
  
  KEYS.DETERMINISTIC_ENCRYPT(
    kms_key,
    Assigned_To_Full_Name,
    'AEAD_AES_SIV_CMAC_256'
  ) AS Assigned_To_Full_Name_encrypted,
  
  Created_Date,
  Updated_Date
FROM `customer-data-platform.ctng_dataset.ext_raw_data`;
```

**Why DETERMINISTIC_ENCRYPT?**
- ✅ Allows JOINs on encrypted columns
- ✅ Allows GROUP BY (e.g., count by creator)
- ✅ Allows analytics without decryption
- ⚠️ Same input → same output (less secure than non-deterministic)

---

## Airflow DAG Implementation

### Complete DAG with Dynamic SQL Generation

```python
# airflow/dags/gcs_to_bigquery_pipeline.py

from airflow import DAG
from airflow.providers.google.cloud.operators.bigquery import (
    BigQueryCreateExternalTableOperator,
    BigQueryInsertJobOperator,
    BigQueryDeleteTableOperator
)
from airflow.operators.python import PythonOperator
from airflow.utils.dates import days_ago
from google.cloud import bigquery
import pandas as pd

default_args = {
    'owner': 'data-engineering',
    'depends_on_past': False,
    'email': ['data-team@customer.com'],
    'email_on_failure': True,
    'email_on_retry': False,
    'retries': 2,
    'retry_delay': timedelta(minutes=5),
}

dag = DAG(
    'gcs_to_bq_with_encryption',
    default_args=default_args,
    description='Load CSV from GCS, encrypt PII (if needed), load to BigQuery',
    schedule_interval='@daily',
    start_date=days_ago(1),
    catchup=False,
    tags=['data-ingestion', 'security'],
)

# Task 1: Create external table
create_external_table = BigQueryCreateExternalTableOperator(
    task_id='create_external_table',
    bucket='wtrydal-gs-04',
    source_objects=['incoming_data.csv'],
    destination_project_dataset_table='customer-data-platform.ctng_dataset.ext_raw_data',
    skip_leading_rows=1,
    autodetect=True,
    dag=dag
)

# Task 2: Generate SQL based on mapping sheet
def generate_create_table_sql(**context):
    """
    Reads mapping sheet and generates SQL to encrypt PII columns
    """
    client = bigquery.Client(project='customer-data-platform')
    
    # Read mapping sheet from BigQuery
    mapping_query = """
    SELECT Column, Security_Class
    FROM `customer-data-platform.config_dataset.column_mapping`
    ORDER BY Column
    """
    mapping_df = client.query(mapping_query).to_dataframe()
    
    # Decide: Use encryption or not?
    # For customer audit columns: NO ENCRYPTION (see decision framework)
    use_encryption = False  # Change to True if you have highly sensitive data
    
    if use_encryption:
        kms_key = 'projects/customer-data-platform/locations/europe-west2/keyRings/pii-encryption/cryptoKeys/employee-pii-key'
        
        # Generate column list with conditional encryption
        select_columns = []
        for _, row in mapping_df.iterrows():
            col = row['Column']
            security = row['Security_Class']
            
            if security == 'PII':
                # Encrypt PII columns
                select_columns.append(f"""
  KEYS.DETERMINISTIC_ENCRYPT(
    '{kms_key}',
    {col},
    'AEAD_AES_SIV_CMAC_256'
  ) AS {col}_encrypted""")
            else:
                # Pass through non-PII columns
                select_columns.append(f"  {col}")
        
        sql = f"""
CREATE OR REPLACE TABLE `customer-data-platform.ctng_dataset.final_table` AS
SELECT
{','.join(select_columns)}
FROM `customer-data-platform.ctng_dataset.ext_raw_data`;
"""
    else:
        # No encryption - simple pass-through
        sql = """
CREATE OR REPLACE TABLE `customer-data-platform.ctng_dataset.final_table` AS
SELECT *
FROM `customer-data-platform.ctng_dataset.ext_raw_data`;
"""
    
    # Push SQL to XCom for next task
    context['task_instance'].xcom_push(key='create_table_sql', value=sql)
    
    print("Generated SQL:")
    print(sql)

generate_sql_task = PythonOperator(
    task_id='generate_create_table_sql',
    python_callable=generate_create_table_sql,
    dag=dag
)

# Task 3: Execute the CREATE TABLE statement
def execute_create_table(**context):
    """
    Executes the SQL generated in previous task
    """
    sql = context['task_instance'].xcom_pull(
        task_ids='generate_create_table_sql',
        key='create_table_sql'
    )
    
    client = bigquery.Client(project='customer-data-platform')
    
    query_job = client.query(sql)
    result = query_job.result()
    
    print(f"✅ Query completed")
    print(f"✅ Bytes processed: {query_job.total_bytes_processed:,}")
    print(f"✅ Rows affected: {query_job.num_dml_affected_rows:,}")
    
    # Push metrics to XCom
    context['task_instance'].xcom_push(key='bytes_processed', value=query_job.total_bytes_processed)
    context['task_instance'].xcom_push(key='rows_loaded', value=query_job.num_dml_affected_rows)

execute_sql_task = PythonOperator(
    task_id='execute_create_table',
    python_callable=execute_create_table,
    dag=dag
)

# Task 4: Validate data load
validate_load = BigQueryInsertJobOperator(
    task_id='validate_load',
    configuration={
        'query': {
            'query': """
                SELECT 
                  COUNT(*) as row_count,
                  COUNTIF(ID IS NULL) as null_ids,
                  MIN(Processing_Date_Time) as earliest_record,
                  MAX(Processing_Date_Time) as latest_record
                FROM `customer-data-platform.ctng_dataset.final_table`
            """,
            'useLegacySql': False
        }
    },
    dag=dag
)

# Task 5: Drop external table (cleanup)
drop_external_table = BigQueryDeleteTableOperator(
    task_id='drop_external_table',
    deletion_dataset_table='customer-data-platform.ctng_dataset.ext_raw_data',
    ignore_if_missing=True,
    dag=dag
)

# Task 6: Send completion notification
def send_completion_notification(**context):
    """
    Send Slack/email notification with pipeline metrics
    """
    rows_loaded = context['task_instance'].xcom_pull(
        task_ids='execute_create_table',
        key='rows_loaded'
    )
    bytes_processed = context['task_instance'].xcom_pull(
        task_ids='execute_create_table',
        key='bytes_processed'
    )
    
    message = f"""
    ✅ BigQuery Load Completed
    
    Table: customer-data-platform.ctng_dataset.final_table
    Rows Loaded: {rows_loaded:,}
    Bytes Processed: {bytes_processed:,}
    Execution Date: {context['execution_date']}
    """
    
    print(message)
    # Add Slack/email notification here

notify_task = PythonOperator(
    task_id='send_notification',
    python_callable=send_completion_notification,
    dag=dag
)

# Define task dependencies
create_external_table >> generate_sql_task >> execute_sql_task >> validate_load >> drop_external_table >> notify_task
```

### Testing the DAG

```bash
# Test locally
airflow dags test gcs_to_bq_with_encryption 2026-02-10

# Trigger manually
airflow dags trigger gcs_to_bq_with_encryption

# Monitor execution
airflow dags list-runs -d gcs_to_bq_with_encryption

# Check logs
airflow tasks logs gcs_to_bq_with_encryption execute_create_table 2026-02-10
```

---

## Dynamic Data Masking Setup

**If you decide to use DDM instead of encryption:**

### Step 1: Create Policy Tag Taxonomy

```bash
# Create taxonomy in Data Catalog
gcloud data-catalog taxonomies create employee-data-taxonomy \
  --location=europe-west2 \
  --display-name="Employee Data Classification" \
  --description="Classification for employee audit data"

# Create policy tag for employee emails
gcloud data-catalog taxonomies policy-tags create employee-email \
  --taxonomy=employee-data-taxonomy \
  --location=europe-west2 \
  --display-name="Employee Email"
```

### Step 2: Apply Policy Tags to Columns

```sql
-- Tag employee email columns
ALTER TABLE `customer-data-platform.ctng_dataset.final_table`
ALTER COLUMN Created_By_Email_Address
SET OPTIONS (
  policy_tags=['projects/customer-data-platform/locations/europe-west2/taxonomies/TAXONOMY_ID/policyTags/TAG_ID']
);

ALTER TABLE `customer-data-platform.ctng_dataset.final_table`
ALTER COLUMN Assigned_To_Email_Address
SET OPTIONS (
  policy_tags=['projects/customer-data-platform/locations/europe-west2/taxonomies/TAXONOMY_ID/policyTags/TAG_ID']
);
```

### Step 3: Create Masking Policies

```sql
-- Policy 1: Hash emails for external users
CREATE OR REPLACE DATA POLICY hash_emails_for_external
ON (SELECT policy_tag FROM `customer-data-platform.employee-data-taxonomy.employee-email`)
MASKING RULE hash(email, "SHA256")
GRANT TO ("group:external-auditors@customer.com");

-- Policy 2: Show domain only for analysts
CREATE OR REPLACE DATA POLICY show_domain_for_analysts
ON (SELECT policy_tag FROM `customer-data-platform.employee-data-taxonomy.employee-email`)
MASKING RULE email_mask(email)
GRANT TO ("group:analysts@customer.com");

-- Policy 3: Full access for customer employees
GRANT `roles/datacatalog.categoryFineGrainedReader`
ON TAG `customer-data-platform.employee-data-taxonomy.employee-email`
TO "group:customer-employees@customer.com";
```

### Step 4: Test Masking

```sql
-- External user queries
SELECT Created_By_Email_Address
FROM `customer-data-platform.ctng_dataset.final_table`
LIMIT 5;
-- Result: 5d41402abc4b2a76b9719d911017c592 (hashed)

-- Analyst queries
SELECT Created_By_Email_Address
FROM `customer-data-platform.ctng_dataset.final_table`
LIMIT 5;
-- Result: ***@customer.com (domain only)

-- customer employee queries
SELECT Created_By_Email_Address
FROM `customer-data-platform.ctng_dataset.final_table`
LIMIT 5;
-- Result: john.smith@customer.com (full email)
```

---

## Azure AD Integration

### Group Sync Setup

**Prerequisite:** Azure AD → Google Cloud federation must be configured

### Step 1: Create Groups in Azure AD

```
Azure Portal → Entra ID → Groups → New Group

Create these groups:
├── customer-employees@customer.com (All employees)
├── hr-team@customer.com (HR staff)
├── analysts@customer.com (Data analysts)
├── platform-admins@customer.com (Infrastructure team)
└── external-auditors@customer.com (External partners)
```

### Step 2: Assign Users to Groups

```
In Azure AD:
- Add employees to respective groups
- Groups automatically sync to Google Cloud Identity
- Wait ~15 minutes for initial sync
```

### Step 3: Verify Groups in GCP

```bash
# List synced groups
gcloud identity groups search \
  --organization=ORGANIZATION_ID \
  --labels="cloudidentity.googleapis.com/groups.discussion_forum"

# Should see:
# - customer-employees@customer.com
# - hr-team@customer.com
# - analysts@customer.com
# - etc.
```

### Step 4: Grant IAM Roles to Azure AD Groups

```bash
# Grant roles using Azure AD groups
gcloud projects add-iam-policy-binding customer-data-platform \
  --member=group:customer-employees@customer.com \
  --role=roles/bigquery.jobUser

gcloud projects add-iam-policy-binding customer-data-platform \
  --member=group:hr-team@customer.com \
  --role=roles/bigquery.dataViewer \
  --condition=None

# Dataset-level access
bq update --dataset \
  --add_access_entry=role:roles/bigquery.dataViewer,userByEmail:hr-team@customer.com \
  customer-data-platform:ctng_dataset
```

### Ongoing Maintenance

✅ **Automatic:**
- User additions/removals in Azure AD sync automatically
- Group membership changes sync within minutes
- No manual intervention in GCP needed

❌ **Manual:**
- Creating new groups (must be done in Azure AD first)
- Changing IAM role assignments (GCP side)

---

## Decision Framework

### When to Use What?

```
┌─────────────────────────────────────────┐
│  Is this highly sensitive data?         │
│  (SSN, bank details, medical, salary)   │
└────────┬────────────────────────────────┘
         │
    ┌────┴────┐
    NO        YES → Use KMS Encryption
    │
    ▼
┌─────────────────────────────────────────┐
│  Do multiple user types need            │
│  different views of same data?          │
└────────┬────────────────────────────────┘
         │
    ┌────┴────┐
    NO        YES → Use Dynamic Data Masking
    │
    ▼
┌─────────────────────────────────────────┐
│  Is data used in frequent reports?      │
└────────┬────────────────────────────────┘
         │
    ┌────┴────┐
    NO        YES → Use DDM or No Masking
    │
    ▼
Use IAM + Access Controls Only
```

### customer Recommendation Matrix

| Data Type | Recommendation | Reasoning |
|-----------|---------------|-----------|
| **Employee work emails (audit)** | No encryption + IAM | Low sensitivity, business need for visibility |
| **Employee names (audit)** | No encryption + IAM | Low sensitivity, needed for troubleshooting |
| **SSN / NI Number** | KMS Encryption | High sensitivity, regulatory requirement |
| **Salary amounts** | KMS Encryption | High sensitivity, limited access needed |
| **Performance ratings** | KMS Encryption or DDM | Medium-high sensitivity |
| **Department names** | No masking | Low sensitivity, public information |
| **Action numbers / IDs** | No masking | Non-sensitive, needed for operations |

---

## Performance Benchmarks

### Test Scenario: 1M Rows, 20 Columns, 4 PII Columns

#### **Scenario 1: No Encryption**
```
External Table Creation: 5 seconds
CREATE TABLE AS SELECT: 12 seconds
Total: 17 seconds
Cost: $0.15 (query processing)
```

#### **Scenario 2: With KMS Encryption (4 columns)**
```
External Table Creation: 5 seconds
CREATE TABLE AS SELECT (with KEYS.ENCRYPT): 18 seconds
  └── KMS API call: +2 seconds (one-time per query)
  └── Encryption: +4 seconds (parallelized)
Total: 23 seconds
Cost: $0.15 (query) + $0.012 (4M encryptions) = $0.162
```

#### **Scenario 3: With Dynamic Data Masking**
```
External Table Creation: 5 seconds
CREATE TABLE AS SELECT: 12 seconds
Apply Policy Tags: 3 seconds
Create Masking Policies: 2 seconds
Total Setup: 22 seconds (one-time)

Query Performance (after setup):
- Masked query: 2.5 seconds
- Unmasked query: 2.5 seconds
Overhead: 0% (masking at query time is negligible)
```

### Cost Comparison (Monthly - 10M Rows)

```
Storage (10M rows × 20 columns):
├── Plain text: $50/month
├── Encrypted (1.5x larger): $75/month
└── DDM (plain text): $50/month

Query Processing (1000 queries/month):
├── Plain text: $50/month
├── Encrypted: $55/month (KMS calls)
└── DDM: $50/month (no overhead)

Encryption/Masking:
├── KMS one-time: $12 (40M operations)
├── KMS monthly: $0.03 (decrypt operations)
└── DDM setup: Free

Total Monthly Cost:
├── No encryption: $100/month
├── KMS encryption: $130/month
└── DDM: $100/month
```

---

## FAQ

### Q1: Are employee work emails really PII requiring encryption?

**A:** Under UK GDPR, yes they are "personal data" but encryption is NOT required for low-risk use cases like audit trails. Industry standard is to use IAM access controls + audit logging instead of encryption. See decision framework above.

### Q2: Can we use format-preserving encryption in BigQuery?

**A:** No, BigQuery native functions (`KEYS.ENCRYPT`) only produce binary blobs. For format-preserving encryption, you need Cloud DLP (slower, more expensive).

### Q3: Is `KEYS.ENCRYPT()` deterministic?

**A:** No. Use `KEYS.DETERMINISTIC_ENCRYPT()` if you need same input → same output (for JOINs, GROUP BY).

### Q4: Do we need Google Cloud Directory Sync (GCDS)?

**A:** No. With Azure AD → Google Cloud federation, groups sync automatically. Just create groups in Azure AD first.

### Q5: What if we need to encrypt later?

**A:** You can always add encryption later:
```sql
-- Add encrypted column
ALTER TABLE final_table ADD COLUMN email_encrypted BYTES;

-- Encrypt existing data
UPDATE final_table
SET email_encrypted = KEYS.ENCRYPT(key, email, ...)
WHERE email_encrypted IS NULL;

-- Drop original
ALTER TABLE final_table DROP COLUMN email;
```

### Q6: Can platform admins see encrypted data?

**A:** They see encrypted blobs only. Without KMS key access, they cannot decrypt.

### Q7: How fast is decryption for reports?

**A:** Very fast. KMS API call is ~100ms, then BigQuery decrypts millions of rows in parallel. ~12% overhead total.

### Q8: Should we use Cloud DLP or KMS?

**A:** For your use case: KMS (simpler, faster, cheaper). Only use DLP if you need format preservation or auto-detection.

---

## Related Documentation

- [BigQuery Security Features Overview](./1-bigquery-security-overview.md) - Complete feature catalog
- [Zero-Trust IAM Strategy](./2-zero-trust-iam-strategy.md) - Preventing admin access

---

**Document Version:** 1.0  
**Last Updated:** February 10, 2026  
**Next Review:** May 10, 2026  
**Maintained By:** customer Data Engineering Team + EPAM Solutions Architecture
