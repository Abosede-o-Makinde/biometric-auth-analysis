"""Rich terminal reporter for biometric evaluation results."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from biometric_auth.models.results import AttackResult, BiasResult, EvaluationResult, GDPRReport

console = Console()

_STATUS_COLOUR = {"SATISFIED": "green", "PARTIAL": "yellow", "GAP": "red", "N/A": "dim"}
_SEVERITY_COLOUR = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green", "INFO": "dim"}
_VERDICT_COLOUR = {"FAIR": "green", "MARGINAL": "yellow", "BIASED": "bold red"}
_RISK_COLOUR = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bold red"}


def _pct(v: float) -> str:
    return f"{v:.2%}"


def print_evaluation(result: EvaluationResult) -> None:
    console.print(Panel(
        f"[bold]{result.algorithm_name}[/bold] — {result.modality}",
        title="[cyan]Biometric Performance Evaluation[/cyan]",
        border_style="cyan",
    ))
    t = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold cyan")
    t.add_column("Metric", style="bold")
    t.add_column("Value")
    t.add_column("95% CI")
    t.add_row("EER", _pct(result.eer),
              f"[{_pct(result.eer_ci_low)}, {_pct(result.eer_ci_high)}]")
    t.add_row("FAR @ EER threshold", _pct(result.far),
              f"[{_pct(result.far_ci_low)}, {_pct(result.far_ci_high)}]")
    t.add_row("FRR @ EER threshold", _pct(result.frr),
              f"[{_pct(result.frr_ci_low)}, {_pct(result.frr_ci_high)}]")
    t.add_row("AUC-ROC", f"{result.auc_roc:.6f}", "—")
    t.add_row("EER threshold", f"{result.eer_threshold:.6f}", "—")
    t.add_row("Genuine pairs", str(result.n_genuine), "—")
    t.add_row("Impostor pairs", str(result.n_impostor), "—")
    console.print(t)


def print_bias(result: BiasResult) -> None:
    colour = _VERDICT_COLOUR.get(result.fairness_verdict, "white")
    console.print(Panel(
        f"Verdict: [{colour}]{result.fairness_verdict}[/{colour}]",
        title="[cyan]Demographic Bias Analysis[/cyan]",
        border_style="cyan",
    ))

    t = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold cyan")
    t.add_column("Metric")
    t.add_column("Value")
    t.add_column("Threshold")
    t.add_column("Result")

    def _row(name, val, thresh, pass_cond, fmt=_pct):
        ok = "green" if pass_cond else "red"
        t.add_row(name, fmt(val), thresh, f"[{ok}]{'PASS' if pass_cond else 'FAIL'}[/{ok}]")

    _row("Demographic Parity Diff (DPD)", result.demographic_parity_difference,
         "< 5%", result.demographic_parity_difference < 0.05)
    _row("Equal Opportunity Diff (EOD)", result.equal_opportunity_difference,
         "< 5%", result.equal_opportunity_difference < 0.05)
    _row("Equalised Odds (EqOdds)", result.equalised_odds_difference,
         "< 10%", result.equalised_odds_difference < 0.10)
    _row("Disparate Impact Ratio (DIR)", result.disparate_impact_ratio,
         "≥ 0.80", result.disparate_impact_ratio >= 0.80)
    console.print(t)

    grp_t = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold cyan",
                  title="Per-group metrics")
    grp_t.add_column("Group")
    grp_t.add_column("FAR")
    grp_t.add_column("FRR")
    grp_t.add_column("EER")
    grp_t.add_column("AUC-ROC")
    for g in sorted(result.group_results.values(), key=lambda x: x.group_name):
        grp_t.add_row(g.group_name, _pct(g.far), _pct(g.frr), _pct(g.eer),
                      f"{g.auc_roc:.4f}")
    console.print(grp_t)


def print_attack(result: AttackResult) -> None:
    sev_colour = _RISK_COLOUR.get(result.highest_severity, "white")
    console.print(Panel(
        f"Overall vulnerability: [bold]{result.overall_vulnerability_score:.1f}[/bold] / 10  "
        f"| Highest severity: [{sev_colour}]{result.highest_severity}[/{sev_colour}]",
        title="[cyan]Attack Simulation[/cyan]",
        border_style="cyan",
    ))

    t = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold cyan")
    t.add_column("ID", style="bold")
    t.add_column("Attack Type")
    t.add_column("Category")
    t.add_column("Success Rate")
    t.add_column("CVSS-like")
    t.add_column("Severity")

    for v in result.attack_vectors:
        sc = _SEVERITY_COLOUR.get(v.severity, "white")
        t.add_row(
            v.attack_id, v.attack_type, v.attack_category,
            _pct(v.attack_success_rate),
            f"{v.cvss_like_score:.1f}",
            f"[{sc}]{v.severity}[/{sc}]",
        )
    console.print(t)


def print_gdpr(report: GDPRReport) -> None:
    score_pct = f"{report.overall_score:.1%}"
    status_colour = _STATUS_COLOUR.get(report.overall_status, "white")
    risk_colour = _RISK_COLOUR.get(report.risk_rating, "white")

    console.print(Panel(
        f"[bold]{report.system_name}[/bold]\n"
        f"Overall score: [bold]{score_pct}[/bold] "
        f"| Status: [{status_colour}]{report.overall_status}[/{status_colour}] "
        f"| Risk: [{risk_colour}]{report.risk_rating}[/{risk_colour}]\n"
        f"Satisfied threshold: {report.satisfied_threshold:.0%} "
        f"(Art.9 special category — always 90%)\n"
        f"Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
        title="[cyan]GDPR Article 9 Compliance Assessment[/cyan]",
        border_style="cyan",
    ))

    obl_t = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold cyan")
    obl_t.add_column("Obligation")
    obl_t.add_column("Title")
    obl_t.add_column("Score")
    obl_t.add_column("Status")

    for obl in report.obligations:
        sc = _STATUS_COLOUR.get(obl.status, "white")
        obl_t.add_row(
            obl.obligation_ref,
            obl.obligation_title[:55] + ("…" if len(obl.obligation_title) > 55 else ""),
            f"{obl.score:.1%}",
            f"[{sc}]{obl.status}[/{sc}]",
        )
    console.print(obl_t)

    # Print GAPs and PARTIAL checks as findings
    gaps = [
        (obl.obligation_ref, c)
        for obl in report.obligations
        for c in obl.checks
        if c.status in ("GAP", "PARTIAL")
    ]
    if gaps:
        console.print("\n[bold red]Findings requiring attention:[/bold red]")
        for obl_ref, c in sorted(gaps, key=lambda x: (x[1].status != "GAP", x[1].check_id)):
            sc = _STATUS_COLOUR.get(c.status, "white")
            sev = _SEVERITY_COLOUR.get(c.severity, "white")
            console.print(
                f"  [{sc}]{c.status}[/{sc}] [{sev}]{c.severity}[/{sev}] "
                f"[bold]{c.check_id}[/bold] {obl_ref}: {c.description}"
            )
            if c.finding:
                console.print(f"         Finding: {c.finding[:120]}")
            if c.remediation:
                console.print(f"         Remediation: {c.remediation[:120]}")
