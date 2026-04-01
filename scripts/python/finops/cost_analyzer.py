#!/usr/bin/env python3
"""
FinOps Cost Analyzer — Budget Tracking & CUD Optimization
Analyzes GCP billing data to track spend, forecast budgets,
and recommend Committed Use Discounts.

Usage:
    python -m scripts.python.finops.cost_analyzer --project billing-export --dataset billing --days 30
"""

import argparse
import json
import logging
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO, format="%(asctime)s [FinOps] %(message)s")
log = logging.getLogger("finops")


@dataclass
class CostBreakdown:
    service: str
    daily_avg: float
    monthly_projected: float
    trend: str  # UP, DOWN, STABLE


def query_billing(project: str, dataset: str, days: int) -> list[dict]:
    """Query BigQuery billing export for cost data."""
    query = f"""
    SELECT
        service.description AS service,
        SUM(cost) AS total_cost,
        AVG(cost) AS avg_daily_cost,
        COUNT(DISTINCT DATE(usage_start_time)) AS active_days
    FROM `{project}.{dataset}.gcp_billing_export_v1_*`
    WHERE DATE(usage_start_time) >= DATE_SUB(CURRENT_DATE(), INTERVAL {days} DAY)
        AND cost > 0
    GROUP BY service.description
    ORDER BY total_cost DESC
    LIMIT 20
    """
    try:
        result = subprocess.run(
            ["bq", "query", "--use_legacy_sql=false", "--format=json", query],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
    except Exception as e:
        log.error(f"Billing query failed: {e}")
    return []


def analyze_cud_opportunities(billing_data: list[dict]) -> list[dict]:
    """Identify services eligible for Committed Use Discounts."""
    cud_eligible = [
        "Compute Engine", "Cloud SQL", "Cloud Spanner",
        "Cloud Memorystore", "GKE", "BigQuery",
    ]
    recommendations = []
    for row in billing_data:
        svc = row.get("service", "")
        cost = float(row.get("total_cost", 0))
        if any(e.lower() in svc.lower() for e in cud_eligible) and cost > 500:
            savings_1yr = cost * 0.37
            savings_3yr = cost * 0.55
            recommendations.append({
                "service": svc,
                "current_monthly": round(cost, 2),
                "cud_1yr_savings": round(savings_1yr, 2),
                "cud_3yr_savings": round(savings_3yr, 2),
                "recommendation": f"1-year CUD saves ~${savings_1yr:,.0f}/mo ({37}%)",
            })
    return recommendations


def generate_budget_alerts(billing_data: list[dict], monthly_budget: float) -> dict:
    """Calculate budget utilization and alert thresholds."""
    total_spend = sum(float(r.get("total_cost", 0)) for r in billing_data)
    utilization = (total_spend / monthly_budget * 100) if monthly_budget > 0 else 0

    status = "GREEN"
    if utilization > 100:
        status = "RED"
    elif utilization > 80:
        status = "AMBER"
    elif utilization > 50:
        status = "YELLOW"

    return {
        "monthly_budget": monthly_budget,
        "current_spend": round(total_spend, 2),
        "utilization_pct": round(utilization, 1),
        "status": status,
        "alert_thresholds": [
            {"threshold": 50, "triggered": utilization > 50},
            {"threshold": 80, "triggered": utilization > 80},
            {"threshold": 100, "triggered": utilization > 100},
        ],
        "forecast_eom": round(total_spend * 1.1, 2),
    }


def main():
    parser = argparse.ArgumentParser(description="FinOps Cost Analyzer")
    parser.add_argument("--project", required=True, help="Billing export project")
    parser.add_argument("--dataset", default="billing", help="BigQuery dataset")
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--budget", type=float, default=50000, help="Monthly budget in USD")
    args = parser.parse_args()

    log.info("╔═══════════════════════════════════════════════════════╗")
    log.info("║  FinOps Cost Analyzer — Budget & CUD Optimizer       ║")
    log.info("╚═══════════════════════════════════════════════════════╝")

    billing_data = query_billing(args.project, args.dataset, args.days)
    cud_recs = analyze_cud_opportunities(billing_data)
    budget = generate_budget_alerts(billing_data, args.budget)

    report = {
        "generated": datetime.utcnow().isoformat() + "Z",
        "period_days": args.days,
        "budget": budget,
        "top_services": billing_data[:10],
        "cud_recommendations": cud_recs,
        "total_potential_savings": sum(r["cud_1yr_savings"] for r in cud_recs),
    }

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
