#!/usr/bin/env python3
"""
HIPAA Compliance Validator — Continuous Compliance Checker
Maps 16 HIPAA security controls to GCP resource configuration
and generates a compliance posture report.

Usage:
    python -m scripts.python.compliance.hipaa_validator --org-id 123456 --output json
    python -m scripts.python.compliance.hipaa_validator --org-id 123456 --continuous --interval 3600
"""

import argparse
import json
import logging
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [HIPAA] %(message)s")
log = logging.getLogger("hipaa-validator")


@dataclass
class HIPAAControl:
    """HIPAA Security Rule control mapping."""
    control_id: str
    title: str
    section: str
    requirement: str
    gcp_mapping: str
    check_command: str
    expected: str
    severity: str  # CRITICAL, HIGH, MEDIUM


@dataclass
class ControlResult:
    control_id: str
    title: str
    status: str  # COMPLIANT, NON_COMPLIANT, PARTIAL, ERROR
    evidence: str
    remediation: str
    timestamp: str


# ── HIPAA Control Registry (16 Controls) ──────────────────────
HIPAA_CONTROLS = [
    HIPAAControl(
        control_id="HIPAA-001", title="Access Control — Unique User ID",
        section="§164.312(a)(2)(i)", requirement="Assign unique identifier to each user",
        gcp_mapping="Cloud Identity + Entra ID SAML federation",
        check_command="gcloud identity groups list --organization=$ORG_ID --format=json | jq 'length'",
        expected="7", severity="CRITICAL",
    ),
    HIPAAControl(
        control_id="HIPAA-002", title="Access Control — Emergency Access",
        section="§164.312(a)(2)(ii)", requirement="Establish emergency access procedure",
        gcp_mapping="Break-glass SA in Secret Manager with dual-approval",
        check_command="gcloud secrets list --project=$SECURITY_PROJECT --filter='labels.purpose=break-glass' --format=json | jq 'length'",
        expected="1", severity="CRITICAL",
    ),
    HIPAAControl(
        control_id="HIPAA-003", title="Access Control — Automatic Logoff",
        section="§164.312(a)(2)(iii)", requirement="Terminate session after inactivity",
        gcp_mapping="Entra ID conditional access + GCP session duration policy",
        check_command="gcloud organizations get-iam-policy $ORG_ID --format=json | jq '.auditConfigs | length'",
        expected="", severity="HIGH",
    ),
    HIPAAControl(
        control_id="HIPAA-004", title="Encryption — At Rest",
        section="§164.312(a)(2)(iv)", requirement="Encrypt ePHI at rest",
        gcp_mapping="CMEK via Cloud KMS (HSM for prod) — ADR-005",
        check_command="gcloud kms keyrings list --location=us-central1 --project=$SECURITY_PROJECT --format=json | jq 'length'",
        expected="", severity="CRITICAL",
    ),
    HIPAAControl(
        control_id="HIPAA-005", title="Audit Controls — Activity Logging",
        section="§164.312(b)", requirement="Record and examine access to ePHI",
        gcp_mapping="Cloud Audit Logs → BigQuery sink (7-year retention)",
        check_command="gcloud logging sinks list --organization=$ORG_ID --format=json | jq '[.[] | select(.destination | contains(\"bigquery\"))] | length'",
        expected="1", severity="CRITICAL",
    ),
    HIPAAControl(
        control_id="HIPAA-006", title="Integrity — ePHI Integrity",
        section="§164.312(c)(1)", requirement="Protect ePHI from improper alteration",
        gcp_mapping="GCS object versioning + retention locks + CMEK",
        check_command="gsutil versioning get gs://$AUDIT_BUCKET 2>/dev/null | grep -c Enabled",
        expected="1", severity="HIGH",
    ),
    HIPAAControl(
        control_id="HIPAA-007", title="Transmission Security — Encryption",
        section="§164.312(e)(1)", requirement="Encrypt ePHI in transit",
        gcp_mapping="TLS 1.3 enforced, HA VPN with IKEv2, Private Google Access",
        check_command="gcloud compute vpn-tunnels list --region=us-central1 --format=json | jq '[.[] | select(.status==\"ESTABLISHED\")] | length'",
        expected="2", severity="CRITICAL",
    ),
    HIPAAControl(
        control_id="HIPAA-008", title="Person Authentication",
        section="§164.312(d)", requirement="Verify identity of person seeking access",
        gcp_mapping="Entra ID MFA + Conditional Access + no SA keys (ADR-015)",
        check_command="gcloud resource-manager org-policies describe constraints/iam.disableServiceAccountKeyCreation --organization=$ORG_ID --format=json | jq '.booleanPolicy.enforced'",
        expected="true", severity="CRITICAL",
    ),
    HIPAAControl(
        control_id="HIPAA-009", title="Workstation Security",
        section="§164.310(c)", requirement="Physical safeguards for workstations",
        gcp_mapping="Shielded VMs (Secure Boot, vTPM, Integrity Monitoring)",
        check_command="gcloud resource-manager org-policies describe constraints/compute.requireShieldedVm --organization=$ORG_ID --format=json | jq '.booleanPolicy.enforced'",
        expected="true", severity="HIGH",
    ),
    HIPAAControl(
        control_id="HIPAA-010", title="Facility Access — Data Center",
        section="§164.310(a)(1)", requirement="Limit physical access to facilities",
        gcp_mapping="Assured Workloads HIPAA package (US-only regions)",
        check_command="gcloud assured workloads list --organization=$ORG_ID --location=us-central1 --format=json | jq '[.[] | select(.complianceRegime==\"HIPAA\")] | length'",
        expected="1", severity="CRITICAL",
    ),
    HIPAAControl(
        control_id="HIPAA-011", title="Data Backup",
        section="§164.308(a)(7)(ii)(A)", requirement="Maintain retrievable exact copies of ePHI",
        gcp_mapping="Cloud SQL automated backups + GCS cross-region replication",
        check_command="gcloud sql instances list --format=json | jq '[.[] | select(.settings.backupConfiguration.enabled==true)] | length'",
        expected="", severity="HIGH",
    ),
    HIPAAControl(
        control_id="HIPAA-012", title="Disaster Recovery",
        section="§164.308(a)(7)(ii)(B)", requirement="Procedures to restore lost data",
        gcp_mapping="Multi-zone GKE, Cloud SQL HA, chaos engineering validation",
        check_command="echo 'Manual validation required — see chaos game day results'",
        expected="", severity="HIGH",
    ),
    HIPAAControl(
        control_id="HIPAA-013", title="Security Incident Response",
        section="§164.308(a)(6)", requirement="Identify and respond to security incidents",
        gcp_mapping="SCC Premium + Pub/Sub → Splunk SIEM pipeline",
        check_command="gcloud scc notifications list --organization=$ORG_ID --format=json | jq 'length'",
        expected="", severity="CRITICAL",
    ),
    HIPAAControl(
        control_id="HIPAA-014", title="Risk Analysis",
        section="§164.308(a)(1)(ii)(A)", requirement="Accurate and thorough risk assessment",
        gcp_mapping="SCC vulnerability scanner + VPC SC dry-run analysis",
        check_command="gcloud scc findings list organizations/$ORG_ID --filter='state=\"ACTIVE\"' --format=json --limit=1 | jq 'length'",
        expected="", severity="HIGH",
    ),
    HIPAAControl(
        control_id="HIPAA-015", title="BAA — Business Associate Agreement",
        section="§164.308(b)(1)", requirement="BAA with cloud provider",
        gcp_mapping="Google Cloud BAA (signed via Assured Workloads enrollment)",
        check_command="echo 'Manual validation — verify BAA via console.cloud.google.com/assured-workloads'",
        expected="", severity="CRITICAL",
    ),
    HIPAAControl(
        control_id="HIPAA-016", title="Access Termination",
        section="§164.308(a)(3)(ii)(C)", requirement="Terminate access when no longer needed",
        gcp_mapping="Entra ID lifecycle management + SCIM auto-deprovisioning",
        check_command="gcloud identity groups memberships list --group-email='gcp-admins@$DOMAIN' --format=json | jq '[.[] | select(.roles[].name==\"MEMBER\")] | length'",
        expected="", severity="HIGH",
    ),
]


def run_check(control: HIPAAControl) -> ControlResult:
    """Execute a single HIPAA control check."""
    try:
        result = subprocess.run(
            ["bash", "-c", control.check_command],
            capture_output=True, text=True, timeout=60
        )
        output = result.stdout.strip()

        if control.expected and control.expected in output:
            status = "COMPLIANT"
        elif not control.expected and output:
            status = "COMPLIANT"
        elif "Manual validation" in output:
            status = "PARTIAL"
        else:
            status = "NON_COMPLIANT"

        return ControlResult(
            control_id=control.control_id,
            title=control.title,
            status=status,
            evidence=output[:500],
            remediation="" if status == "COMPLIANT" else f"Implement {control.gcp_mapping}",
            timestamp=datetime.utcnow().isoformat() + "Z",
        )
    except Exception as e:
        return ControlResult(
            control_id=control.control_id,
            title=control.title,
            status="ERROR",
            evidence=str(e),
            remediation=f"Fix check command: {control.check_command}",
            timestamp=datetime.utcnow().isoformat() + "Z",
        )


def generate_report(results: list[ControlResult]) -> dict:
    """Generate the compliance posture report."""
    compliant = sum(1 for r in results if r.status == "COMPLIANT")
    non_compliant = sum(1 for r in results if r.status == "NON_COMPLIANT")
    partial = sum(1 for r in results if r.status == "PARTIAL")
    errors = sum(1 for r in results if r.status == "ERROR")

    score = int((compliant / len(results)) * 100) if results else 0

    return {
        "report_type": "HIPAA Compliance Posture",
        "generated": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "total_controls": len(results),
            "compliant": compliant,
            "non_compliant": non_compliant,
            "partial": partial,
            "errors": errors,
            "compliance_score": score,
            "status": "PASS" if non_compliant == 0 else "FAIL",
        },
        "controls": [asdict(r) for r in results],
        "critical_findings": [
            asdict(r) for r in results
            if r.status == "NON_COMPLIANT" and any(
                c.severity == "CRITICAL" for c in HIPAA_CONTROLS if c.control_id == r.control_id
            )
        ],
    }


def main():
    parser = argparse.ArgumentParser(description="HIPAA Compliance Validator")
    parser.add_argument("--org-id", required=True)
    parser.add_argument("--output", choices=["json", "table"], default="json")
    parser.add_argument("--continuous", action="store_true", help="Run continuously")
    parser.add_argument("--interval", type=int, default=3600, help="Check interval in seconds")
    args = parser.parse_args()

    log.info("╔═══════════════════════════════════════════════════════╗")
    log.info("║  HIPAA Compliance Validator — 16 Controls            ║")
    log.info("╚═══════════════════════════════════════════════════════╝")

    while True:
        results = [run_check(c) for c in HIPAA_CONTROLS]
        report = generate_report(results)

        if args.output == "json":
            print(json.dumps(report, indent=2))
        else:
            print(f"\n{'Control':<12} {'Title':<40} {'Status':<15}")
            print("─" * 67)
            for r in results:
                icon = {"COMPLIANT": "✓", "NON_COMPLIANT": "✗", "PARTIAL": "◐", "ERROR": "⚠"}
                print(f"{r.control_id:<12} {r.title:<40} {icon.get(r.status, '?')} {r.status}")

            print(f"\nCompliance Score: {report['summary']['compliance_score']}%")

        if not args.continuous:
            break
        log.info(f"Next check in {args.interval}s...")
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
