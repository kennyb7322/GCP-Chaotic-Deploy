// Package main provides the stage-by-stage Terraform deployment orchestrator
// for the GCP Enterprise Landing Zone — Chaotic Deploy methodology.
//
// Usage:
//
//	go run ./cmd/deploy --stage 2 --env nonprod --dry-run
//	go run ./cmd/deploy --stage all --env prod --approve
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

// DeployStage represents a single deployment stage with its Terraform modules.
type DeployStage struct {
	Name    string   `json:"name"`
	Stage   int      `json:"stage"`
	Modules []string `json:"modules"`
}

// DeployResult captures the outcome of deploying a single module.
type DeployResult struct {
	Module    string        `json:"module"`
	Status    string        `json:"status"`
	Duration  time.Duration `json:"duration"`
	Resources int           `json:"resources_affected"`
	Error     string        `json:"error,omitempty"`
}

// Pipeline defines the full deployment ordering with dependency resolution.
var Pipeline = []DeployStage{
	{Name: "Foundation", Stage: 1, Modules: []string{
		"landing-zone-root",
		"org-policies",
		"folder-structure",
	}},
	{Name: "Identity & Network", Stage: 2, Modules: []string{
		"cloud-identity",
		"shared-vpc",
		"ha-vpn",
		"hierarchical-firewall",
	}},
	{Name: "Security", Stage: 3, Modules: []string{
		"cloud-kms-cmek",
		"vpc-service-controls",
		"scc",
		"binary-authorization",
	}},
	{Name: "Workloads & Observability", Stage: 4, Modules: []string{
		"audit-logging",
		"budget-alerts",
		"gke-cluster",
		"workload-identity",
	}},
}

var (
	stageFlag   = flag.String("stage", "all", "Stage number (1-4) or 'all'")
	envFlag     = flag.String("env", "nonprod", "Target environment: prod, nonprod, sandbox, shared")
	dryRunFlag  = flag.Bool("dry-run", false, "Run terraform plan only, do not apply")
	approveFlag = flag.Bool("approve", false, "Auto-approve applies (DANGER: use only in CI)")
	rollback    = flag.Bool("rollback", false, "Rollback last deployment for the given stage")
	jsonOut     = flag.Bool("json", false, "Output results as JSON")
	varsFile    = flag.String("vars", "", "Path to additional tfvars file")
)

func main() {
	flag.Parse()
	ctx := context.Background()

	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Println("╔════════════════════════════════════════════════════╗")
	log.Println("║  GCP Chaotic Deploy — Terraform Orchestrator v1.0 ║")
	log.Println("╚════════════════════════════════════════════════════╝")
	log.Printf("  Environment : %s", *envFlag)
	log.Printf("  Dry-Run     : %v", *dryRunFlag)
	log.Printf("  Stage       : %s", *stageFlag)

	if err := preflight(ctx); err != nil {
		log.Fatalf("PREFLIGHT FAILED: %v", err)
	}

	stages := selectStages(*stageFlag)
	if len(stages) == 0 {
		log.Fatal("No valid stages selected.")
	}

	var results []DeployResult
	for _, s := range stages {
		log.Printf("\n▶ Stage %d: %s (%d modules)", s.Stage, s.Name, len(s.Modules))
		for _, mod := range s.Modules {
			r := deployModule(ctx, mod, *envFlag, *dryRunFlag, *approveFlag)
			results = append(results, r)
			if r.Status == "FAILED" && !*dryRunFlag {
				log.Printf("✗ Module %s FAILED — initiating rollback", mod)
				rollbackModule(ctx, mod, *envFlag)
				log.Fatal("Deployment halted. Previous modules remain applied.")
			}
			log.Printf("  ✓ %s — %s (%s)", mod, r.Status, r.Duration.Round(time.Second))
		}
	}

	if *jsonOut {
		b, _ := json.MarshalIndent(results, "", "  ")
		fmt.Println(string(b))
	}

	passed := 0
	for _, r := range results {
		if r.Status == "OK" || r.Status == "PLAN_OK" {
			passed++
		}
	}
	log.Printf("\n════ Summary: %d/%d modules succeeded ════", passed, len(results))
}

// preflight validates that all prerequisites are met before deployment.
func preflight(ctx context.Context) error {
	checks := []struct {
		name string
		cmd  string
		args []string
	}{
		{"gcloud auth", "gcloud", []string{"auth", "print-access-token"}},
		{"terraform version", "terraform", []string{"version"}},
		{"terragrunt version", "terragrunt", []string{"--version"}},
	}

	for _, c := range checks {
		log.Printf("  Preflight: %s ...", c.name)
		cmd := exec.CommandContext(ctx, c.cmd, c.args...)
		cmd.Stdout = nil
		cmd.Stderr = nil
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("preflight check '%s' failed: %w", c.name, err)
		}
	}

	// Verify state bucket exists
	bucket := fmt.Sprintf("gs://%s-terraform-state", *envFlag)
	cmd := exec.CommandContext(ctx, "gsutil", "ls", bucket)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("state bucket %s not accessible: %w", bucket, err)
	}

	log.Println("  ✓ All preflight checks passed")
	return nil
}

// selectStages filters the pipeline based on the --stage flag.
func selectStages(stage string) []DeployStage {
	if stage == "all" {
		return Pipeline
	}
	var n int
	fmt.Sscanf(stage, "%d", &n)
	for _, s := range Pipeline {
		if s.Stage == n {
			return []DeployStage{s}
		}
	}
	return nil
}

// deployModule runs terraform init/plan/apply for a single module.
func deployModule(ctx context.Context, module, env string, dryRun, autoApprove bool) DeployResult {
	start := time.Now()
	modPath := fmt.Sprintf("terraform/environments/%s/%s", env, module)

	// Init
	init := exec.CommandContext(ctx, "terraform", "init", "-reconfigure", "-backend-config=prefix="+module)
	init.Dir = modPath
	if out, err := init.CombinedOutput(); err != nil {
		return DeployResult{Module: module, Status: "FAILED", Duration: time.Since(start), Error: fmt.Sprintf("init: %s", strings.TrimSpace(string(out)))}
	}

	// Plan
	planArgs := []string{"plan", "-detailed-exitcode", "-out=tfplan"}
	if *varsFile != "" {
		planArgs = append(planArgs, fmt.Sprintf("-var-file=%s", *varsFile))
	}
	plan := exec.CommandContext(ctx, "terraform", planArgs...)
	plan.Dir = modPath
	if out, err := plan.CombinedOutput(); err != nil {
		exitCode := plan.ProcessState.ExitCode()
		if exitCode == 2 {
			// Changes detected — expected
		} else {
			return DeployResult{Module: module, Status: "FAILED", Duration: time.Since(start), Error: fmt.Sprintf("plan: %s", strings.TrimSpace(string(out)))}
		}
	}

	if dryRun {
		return DeployResult{Module: module, Status: "PLAN_OK", Duration: time.Since(start)}
	}

	// Apply
	applyArgs := []string{"apply"}
	if autoApprove {
		applyArgs = append(applyArgs, "-auto-approve")
	}
	applyArgs = append(applyArgs, "tfplan")
	apply := exec.CommandContext(ctx, "terraform", applyArgs...)
	apply.Dir = modPath
	apply.Stdout = os.Stdout
	apply.Stderr = os.Stderr
	if err := apply.Run(); err != nil {
		return DeployResult{Module: module, Status: "FAILED", Duration: time.Since(start), Error: err.Error()}
	}

	return DeployResult{Module: module, Status: "OK", Duration: time.Since(start)}
}

// rollbackModule destroys the last-applied changes for a module.
func rollbackModule(ctx context.Context, module, env string) {
	modPath := fmt.Sprintf("terraform/environments/%s/%s", env, module)
	log.Printf("  ↩ Rolling back %s ...", module)
	cmd := exec.CommandContext(ctx, "terraform", "destroy", "-auto-approve")
	cmd.Dir = modPath
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
}
