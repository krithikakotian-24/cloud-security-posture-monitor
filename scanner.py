import boto3
from datetime import datetime
from botocore.exceptions import ClientError

s3 = boto3.client("s3")
iam = boto3.client("iam")
ec2 = boto3.client("ec2")

results = []  # every resource checked: (check, resource, [(severity, message)])

# ---------- Check 1: S3 buckets ----------
def check_bucket(name):
    f = []
    try:
        cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        if not all(cfg.values()):
            f.append(("MEDIUM", "Block Public Access is not fully enabled"))
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            f.append(("MEDIUM", "No Block Public Access settings"))
        else:
            raise
    try:
        if s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"]["IsPublic"]:
            f.append(("HIGH", "Bucket policy allows public access"))
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
            raise
    for g in s3.get_bucket_acl(Bucket=name)["Grants"]:
        uri = g["Grantee"].get("URI", "")
        if uri.endswith("AllUsers") or uri.endswith("AuthenticatedUsers"):
            f.append(("HIGH", "ACL grants access to everyone"))
    return f

def run_s3():
    for b in s3.list_buckets()["Buckets"]:
        results.append(("S3 Bucket", b["Name"], check_bucket(b["Name"])))

# ---------- Check 2: IAM ----------
def is_full_admin(arn):
    p = iam.get_policy(PolicyArn=arn)["Policy"]
    doc = iam.get_policy_version(PolicyArn=arn, VersionId=p["DefaultVersionId"])["PolicyVersion"]["Document"]
    sts = doc["Statement"]
    if isinstance(sts, dict):
        sts = [sts]
    for st in sts:
        if st.get("Effect") != "Allow":
            continue
        a, r = st.get("Action", []), st.get("Resource", [])
        a = [a] if isinstance(a, str) else a
        r = [r] if isinstance(r, str) else r
        if "*" in a and "*" in r:
            return True
    return False

def iam_findings(attached):
    return [("HIGH", f"{p['PolicyName']} gives full admin access")
            for p in attached if is_full_admin(p["PolicyArn"])]

def run_iam():
    for page in iam.get_paginator("list_users").paginate():
        for u in page["Users"]:
            att = iam.list_attached_user_policies(UserName=u["UserName"])["AttachedPolicies"]
            results.append(("IAM User", u["UserName"], iam_findings(att)))
    for page in iam.get_paginator("list_roles").paginate():
        for r in page["Roles"]:
            if r["Path"].startswith("/aws-service-role/"):
                continue
            att = iam.list_attached_role_policies(RoleName=r["RoleName"])["AttachedPolicies"]
            results.append(("IAM Role", r["RoleName"], iam_findings(att)))

# ---------- Check 3: Security groups ----------
SENSITIVE = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
             1433: "MS SQL", 27017: "MongoDB", 6379: "Redis"}

def check_sg(sg):
    f = []
    for rule in sg["IpPermissions"]:
        o4 = any(x["CidrIp"] == "0.0.0.0/0" for x in rule.get("IpRanges", []))
        o6 = any(x["CidrIpv6"] == "::/0" for x in rule.get("Ipv6Ranges", []))
        if not (o4 or o6):
            continue
        if rule["IpProtocol"] == "-1":
            f.append(("HIGH", "All traffic open to the internet"))
            continue
        if rule["IpProtocol"] in ("icmp", "icmpv6"):
            f.append(("MEDIUM", "ICMP (ping) open to the internet"))
            continue
        s, e = rule["FromPort"], rule["ToPort"]
        hit = False
        for port, svc in SENSITIVE.items():
            if s <= port <= e:
                f.append(("HIGH", f"{svc} (port {port}) open to the internet"))
                hit = True
        if not hit and not (s == e and s in (80, 443)):
            f.append(("MEDIUM", f"Ports {s}-{e} open to the internet"))
    return f

def run_sg():
    for page in ec2.get_paginator("describe_security_groups").paginate():
        for sg in page["SecurityGroups"]:
            results.append(("Security Group", f"{sg['GroupName']} ({sg['GroupId']})", check_sg(sg)))

# ---------- Run everything ----------
print("Running Cloud Security Posture Scan...\n")
run_s3()
run_iam()
run_sg()

total = len(results)
failed = [r for r in results if r[2]]
passed = total - len(failed)
high = sum(1 for r in results for s, _ in r[2] if s == "HIGH")
medium = sum(1 for r in results for s, _ in r[2] if s == "MEDIUM")

for kind, name, f in results:
    if f:
        print(f"[!] {kind}: {name}")
        for sev, msg in f:
            print(f"    {sev}: {msg}")
    else:
        print(f"[OK] {kind}: {name}")

print(f"\nChecked {total} resources | Passed: {passed} | With issues: {len(failed)} (HIGH: {high}, MEDIUM: {medium})")

# ---------- HTML report ----------
rows = ""
for kind, name, f in results:
    if f:
        for sev, msg in f:
            color = "#c0392b" if sev == "HIGH" else "#e67e22"
            rows += f"<tr><td>{kind}</td><td>{name}</td><td style='color:{color};font-weight:bold'>{sev}</td><td>{msg}</td></tr>"
    else:
        rows += f"<tr><td>{kind}</td><td>{name}</td><td style='color:#27ae60;font-weight:bold'>PASS</td><td>No issues found</td></tr>"

html = f"""<html><head><title>Cloud Security Posture Report</title>
<style>body{{font-family:Arial;margin:30px}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ccc;padding:8px;text-align:left}}th{{background:#2c3e50;color:white}}
.box{{display:inline-block;padding:12px 20px;margin:5px;background:#ecf0f1;border-radius:6px}}</style></head>
<body><h1>Cloud Security Posture Monitor - Report</h1>
<p>Generated: {datetime.now().strftime('%d-%m-%Y %H:%M')} | Region: ap-south-1</p>
<div class='box'>Resources checked: <b>{total}</b></div>
<div class='box'>Passed: <b>{passed}</b></div>
<div class='box'>With issues: <b>{len(failed)}</b></div>
<div class='box'>HIGH: <b>{high}</b></div>
<div class='box'>MEDIUM: <b>{medium}</b></div>
<h2>Findings</h2>
<table><tr><th>Check</th><th>Resource</th><th>Status</th><th>Details</th></tr>{rows}</table>
</body></html>"""

with open("report.html", "w", encoding="utf-8") as fh:
    fh.write(html)
print("Report saved: report.html")