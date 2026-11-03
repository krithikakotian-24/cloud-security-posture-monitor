# Cloud Security Posture Monitor

A Python tool that scans an AWS account for common security misconfigurations and generates an HTML report.

## What it checks

| Check | Risk it detects |
|---|---|
| S3 buckets | Public access through a bucket policy or ACL, or Block Public Access turned off |
| IAM users and roles | Policies that allow all actions on all resources (full admin access) |
| Security groups | Inbound rules open to the internet (0.0.0.0/0) on sensitive ports such as SSH, RDP and database ports |

## How it works

1. Python and Boto3 connect to AWS using a read-only IAM user
2. Each check reads resource settings and compares them with security rules
3. Findings are rated HIGH or MEDIUM
4. A summary is printed in the terminal and saved as `report.html`

## Files in this repository

- `scanner.py`: the scanner (all three checks and the report generator)
- Project documentation (PDF): full explanation, design, testing and results
- Presentation (PPTX): short project overview

## Setup

1. Create an IAM user with read-only permissions for S3, IAM and EC2 (list, get and describe actions only)
2. Install Boto3: `pip install boto3`
3. Set your credentials as environment variables (never write them in the code):

```
$env:AWS_ACCESS_KEY_ID="your-access-key-id"
$env:AWS_SECRET_ACCESS_KEY="your-secret-key"
$env:AWS_DEFAULT_REGION="ap-south-1"
```

4. Run the scanner: `python scanner.py`
5. Open the report: `report.html`

## Results

- Normal account: 5 resources checked, 5 passed
- With a test security group open on SSH (port 22): 6 resources checked, 1 HIGH finding detected
- After deleting the test group: back to 5 passed

## Tech stack

Python, Boto3, AWS (S3, IAM, EC2), HTML

## Note

This tool audits only the AWS account whose keys it uses. Use it only on accounts you own or have permission to test.

## Author

Krithika, MSc Data Science, AIMIT St. Aloysius (Deemed to be University)
