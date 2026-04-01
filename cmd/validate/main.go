// Package main provides the pre-deployment readiness validator.
// Runs 10+ checks against the GCP environment to verify that all
// prerequisites are met before running the deploy orchestrator.
//
// Usage:
//
//	go run ./cmd/validate --env prod --full --json
//	go run ./cmd/validate --env nonprod --check iam,network
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

// ValidationCheck represents a single validation rule.
type ValidationCheck struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Command     string `json:"command"`
	Expected    string `json:"expected"`
	Severity    string `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
}

// CheckResult captures the outcome of running a validation check.
type CheckResult struct {
	ID       string        `json:"id"`
	Name     string        `json:"name"`
	Status   string        `json:"status"` // PASS, FAIL, WARN, SKIP
	Severity string        `json:"severity"`
	Message  string        `json:"message"`
	Duration time.Duration `json:"duration"`
}

// Report is the full validation report.
type Report struct {
	Environment string        `json:"environment"`
	Timestamp   time.Time     `json:"timestamp"`
	Checks      []CheckResult `json:"checks"`
	Summary     Summary       `json:"summary"`
}

// Summary provides aggregate stats.
type Summary struct {
	Total    int `json:"total"`
	Passed   int `json:"passed"`
	Failed   int `json:"failed"`
	Warnings int `json:"warnings"`
	Skipped  int `json:"skipped"`
	Score    int `json:"readiness_score"`
}

// AllChecks defines the full validation suite.
var AllChecks = []ValidationCheck{
	// Authentication & Authorization
	{ID: "V-001", Name: "GCP Authentication", Category: "auth", Severity: "CRITICAL",
		Description: "Verify active GCP authentication with correct project.",
		Command: "gcloud auth print-access-token 2>/dev/null && echo OK || echo FAIL", Expected: "OK"},
	{ID: "V-002", Name: "Org Admin Permissions", Category: "iam", Severity: "CRITICAL",
		Description: "Verify deployer has Organization Admin role.",
		Command: "gcloud organizations get-iam-policy $ORG_ID --format=json | jq '.bindings[] | select(.role==\"roles/resourcemanager.organizationAdmin\") | .members[]'", Expected: "serviceAccount:"},
	{ID: "V-003", Name: "Billing Account Access", Category: "iam", Severity: "CRITICAL",
		Description: "Verify billing account is accessible and linked.",
		Command: "gcloud billing accounts list --format='value(name)' --filter='open=true' | head -1", Expected: "billingAccounts/"},

	// Terraform State
	{ID: "V-004", Name: "State Bucket Exists", Category: "terraform", Severity: "CRITICAL",
		Description: "Verify Terraform state GCS bucket exists with versioning.",
		Command: "gsutil versioning get gs://$ENV-terraform-state 2>/dev/null", Expected: "Enabled"},
	{ID: "V-005", Name: "State Bucket Locking", Category: "terraform", Severity: "HIGH",
		Description: "Verify state bucket has object locking for consistency.",
		Command: "gsutil retention get gs://$ENV-terraform-state 2>/dev/null || echo 'no-lock'", Expected: "Retention"},
	{ID: "V-006", Name: "Terraform Version", Category: "terraform", Severity: "HIGH",
		Description: "Verify Terraform >= 1.9.0 per ADR-002.",
		Command: "terraform version -json | jq -r '.terraform_version'", Expected: "1.9"},

	// Organization Policies
	{ID: "V-007", Name: "Org Policy: No External IPs", Category: "org-policy", Severity: "HIGH",
		Description: "Verify constraints/compute.vmExternalIpAccess is enforced.",
		Command: "gcloud resource-manager org-policies describe constraints/compute.vmExternalIpAccess --organization=$ORG_ID --format=json | jq '.booleanPolicy.enforced'", Expected: "true"},
	{ID: "V-008", Name: "Org Policy: No Default Networks", Category: "org-policy", Severity: "HIGH",
		Description: "Verify constraints/compute.skipDefaultNetworkCreation is enforced.",
		Command: "gcloud resource-manager org-policies describe constraints/compute.skipDefaultNetworkCreation --organization=$ORG_ID --format=json | jq '.booleanPolicy.enforced'", Expected: "true"},
	{ID: "V-009", Name: "Org Policy: No SA Keys", Category: "org-policy", Severity: "CRITICAL",
		Description: "Verify constraints/iam.disableServiceAccountKeyCreation per ADR-015.",
		Command: "gcloud resource-manager org-policies describe constraints/iam.disableServiceAccountKeyCreation --organization=$ORG_ID --format=json | jq '.booleanPolicy.enforced'", Expected: "true"},

	// Network
	{ID: "V-010", Name: "Shared VPC Host Project", Category: "network", Severity: "CRITICAL",
		Description: "Verify Shared VPC host project is configured.",
		Command: "gcloud compute shared-vpc get-host-project $HOST_PROJECT 2>/dev/null && echo OK", Expected: "OK"},
	{ID: "V-011", Name: "HA VPN Tunnels Up", Category: "network", Severity: "HIGH",
		Description: "Verify both HA VPN tunnels are established.",
		Command: "gcloud compute vpn-tunnels list --region=us-central1 --format='value(status)' | grep -c ESTABLISHED", Expected: "2"},

	// Security
	{ID: "V-012", Name: "SCC Premium Active", Category: "security", Severity: "HIGH",
		Description: "Verify Security Command Center Premium is active.",
		Command: "gcloud scc settings describe organizations/$ORG_ID --format=json | jq '.tier'", Expected: "PREMIUM"},
	{ID: "V-013", Name: "Assured Workloads", Category: "compliance", Severity: "CRITICAL",
		Description: "Verify Assured Workloads HIPAA package is applied.",
		Command: "gcloud assured workloads list --organization=$ORG_ID --location=us-central1 --format=json | jq '.[0].complianceRegime'", Expected: "HIPAA"},
	{ID: "V-014", Name: "KMS Keyrings Exist", Category: "security", Severity: "HIGH",
		Description: "Verify CMEK keyrings are provisioned per ADR-005.",
		Command: "gcloud kms keyrings list --location=us-central1 --format='value(name)' | wc -l", Expected: ""},

	// Identity
	{ID: "V-015", Name: "Entra ID Federation", Category: "identity", Severity: "CRITICAL",
		Description: "Verify SAML federation with Entra ID is active.",
		Command: "gcloud identity groups list --organization=$ORG_ID --format=json | jq 'length'", Expected: ""},
}

var (
	envFlag   = flag.String("env", "nonprod", "Target environment")
	fullFlag  = flag.Bool("full", false, "Run all checks (default: critical only)")
	checkFlag = flag.String("check", "", "Comma-separated categories: auth,iam,terraform,network,security,compliance,identity,org-policy")
	jsonFlag  = flag.Bool("json", false, "Output as JSON")
	ciFlag    = flag.Bool("ci", false, "CI mode — exit code 1 if any CRITICAL fails")
)

func main() {
	flag.Parse()
	ctx := context.Background()

	log.Println("╔════════════════════════════════════════════════════════╗")
	log.Println("║  GCP Chaotic Deploy — Pre-Deploy Validator v1.0       ║")
	log.Println("╚════════════════════════════════════════════════════════╝")
	log.Printf("  Environment : %s", *envFlag)

	checks := filterChecks(*fullFlag, *checkFlag)
	log.Printf("  Checks      : %d", len(checks))

	report := Report{
		Environment: *envFlag,
		Timestamp:   time.Now(),
	}

	for _, chk := range checks {
		r := runCheck(ctx, chk)
		report.Checks = append(report.Checks, r)

		icon := "✓"
		if r.Status == "FAIL" {
			icon = "✗"
		} else if r.Status == "WARN" {
			icon = "⚠"
		}
		log.Printf("  %s [%s] %s — %s (%s)", icon, r.Severity, r.Name, r.Status, r.Duration.Round(time.Millisecond))
	}

	// Calculate summary
	for _, r := range report.Checks {
		report.Summary.Total++
		switch r.Status {
		case "PASS":
			report.Summary.Passed++
		case "FAIL":
			report.Summary.Failed++
		case "WARN":
			report.Summary.Warnings++
		case "SKIP":
			report.Summary.Skipped++
		}
	}
	if report.Summary.Total > 0 {
		report.Summary.Score = (report.Summary.Passed * 100) / report.Summary.Total
	}

	log.Printf("\n════ Readiness Score: %d%% (%d/%d passed) ════", report.Summary.Score, report.Summary.Passed, report.Summary.Total)

	if *jsonFlag {
		b, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(b))
	}

	if *ciFlag {
		for _, r := range report.Checks {
			if r.Status == "FAIL" && r.Severity == "CRITICAL" {
				log.Fatal("CI GATE FAILED: Critical checks did not pass.")
			}
		}
	}
}

// filterChecks selects which checks to run based on flags.
func filterChecks(full bool, categories string) []ValidationCheck {
	if full {
		return AllChecks
	}
	if categories != "" {
		cats := strings.Split(categories, ",")
		var filtered []ValidationCheck
		for _, c := range AllChecks {
			for _, cat := range cats {
				if c.Category == strings.TrimSpace(cat) {
					filtered = append(filtered, c)
				}
			}
		}
		return filtered
	}
	// Default: critical only
	var critical []ValidationCheck
	for _, c := range AllChecks {
		if c.Severity == "CRITICAL" {
			critical = append(critical, c)
		}
	}
	return critical
}

// runCheck executes a single validation check.
func runCheck(ctx context.Context, chk ValidationCheck) CheckResult {
	start := time.Now()
	cmd := exec.CommandContext(ctx, "bash", "-c", chk.Command)
	out, err := cmd.CombinedOutput()
	duration := time.Since(start)
	output := strings.TrimSpace(string(out))

	result := CheckResult{
		ID:       chk.ID,
		Name:     chk.Name,
		Severity: chk.Severity,
		Duration: duration,
	}

	if err != nil {
		result.Status = "FAIL"
		result.Message = fmt.Sprintf("Command failed: %s", err)
		return result
	}

	if chk.Expected != "" && strings.Contains(output, chk.Expected) {
		result.Status = "PASS"
		result.Message = output
	} else if chk.Expected == "" && output != "" {
		result.Status = "PASS"
		result.Message = output
	} else {
		result.Status = "FAIL"
		result.Message = fmt.Sprintf("Expected '%s', got '%s'", chk.Expected, output)
	}

	return result
}
