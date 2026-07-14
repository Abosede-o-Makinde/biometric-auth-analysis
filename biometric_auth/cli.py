"""biometric-auth CLI — Click entry point for all evaluation subcommands."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click

from biometric_auth.parsers.config_parser import emit_sample_config, load_config
from biometric_auth.parsers.score_file import load_scores
from biometric_auth.reporters.console import (
    print_attack,
    print_bias,
    print_evaluation,
    print_gdpr,
)
from biometric_auth.reporters.json_rep import to_json


@click.group()
@click.version_option(package_name="biometric-auth-analysis")
def cli() -> None:
    """biometric-auth-analysis — biometric security evaluation with GDPR Art.9 assessment."""


# ── evaluate ──────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--scores", required=True, type=click.Path(exists=True),
              help="CSV or JSON score file (columns: score, label [, group, algorithm]).")
@click.option("--algorithm", default=None, help="Algorithm name label.")
@click.option("--modality", default="unknown", help="Biometric modality (face/fingerprint/iris…).")
@click.option("--output", default=None, type=click.Path(),
              help="Write JSON result to this path.")
@click.option("--no-console", is_flag=True, default=False, help="Suppress Rich console output.")
def evaluate(scores: str, algorithm: Optional[str], modality: str,
             output: Optional[str], no_console: bool) -> None:
    """Evaluate a score file: EER, FAR, FRR, AUC-ROC with bootstrap CIs."""
    from biometric_auth.engine.metrics import run_evaluation

    df = load_scores(scores)
    algo_name = algorithm or (df["algorithm"].iloc[0] if "algorithm" in df.columns else "unknown")
    result = run_evaluation(df, algorithm_name=algo_name, modality=modality)

    if not no_console:
        print_evaluation(result)

    json_out = to_json(result, path=output)
    if output:
        click.echo(f"JSON written to {output}")
    elif no_console:
        click.echo(json_out)


# ── compare ───────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--scores", required=True, multiple=True, type=click.Path(exists=True),
              help="Score files to compare (pass --scores twice).")
@click.option("--method", default="delong",
              type=click.Choice(["delong", "permutation"]),
              help="Statistical comparison method.")
@click.option("--output", default=None, type=click.Path())
def compare(scores: tuple[str, ...], method: str, output: Optional[str]) -> None:
    """Compare two score files using DeLong AUC test or permutation test."""
    from biometric_auth.engine.statistics import delong_auc_comparison, permutation_test
    from biometric_auth.engine.metrics import run_evaluation
    from rich.console import Console
    from rich.table import Table

    if len(scores) < 2:
        raise click.UsageError("Provide at least two --scores arguments to compare.")

    console = Console()
    results = []
    for s in scores:
        df = load_scores(s)
        algo = df["algorithm"].iloc[0] if "algorithm" in df.columns else Path(s).stem
        results.append((algo, df, run_evaluation(df, algorithm_name=algo)))

    t = Table(title="Algorithm Comparison", show_header=True, header_style="bold cyan")
    t.add_column("Algorithm")
    t.add_column("EER")
    t.add_column("AUC-ROC")
    for algo, _, r in results:
        t.add_row(algo, f"{r.eer:.4%}", f"{r.auc_roc:.6f}")
    console.print(t)

    console.print(f"\n[bold]Pairwise comparison ({method}):[/bold]")
    import json
    comparisons = []
    for i in range(len(results) - 1):
        for j in range(i + 1, len(results)):
            a_name, _, _ = results[i]
            b_name, _, _ = results[j]
            df_a = results[i][1]
            df_b = results[j][1]
            if method == "delong":
                z, p = delong_auc_comparison(df_a, df_b)
                console.print(f"  {a_name} vs {b_name}: z={z:.3f}, p={p:.4f} "
                               f"({'significant' if p < 0.05 else 'not significant'} at α=0.05)")
                comparisons.append({"a": a_name, "b": b_name, "z": z, "p_value": p, "method": method})
            else:
                p = permutation_test(df_a, df_b, n_permutations=1000)
                console.print(f"  {a_name} vs {b_name}: p={p:.4f} "
                               f"({'significant' if p < 0.05 else 'not significant'} at α=0.05)")
                comparisons.append({"a": a_name, "b": b_name, "p_value": p, "method": method})

    out = {"algorithms": [r.to_dict() for _, _, r in results], "comparisons": comparisons}
    text = json.dumps(out, indent=2)
    if output:
        Path(output).write_text(text)
        click.echo(f"JSON written to {output}")


# ── bias ──────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--scores", required=True, type=click.Path(exists=True))
@click.option("--group-col", default="group", help="Column name for group labels.")
@click.option("--output", default=None, type=click.Path())
@click.option("--no-console", is_flag=True, default=False)
def bias(scores: str, group_col: str, output: Optional[str], no_console: bool) -> None:
    """Analyse demographic bias: DPD, EOD, EqOdds, DIR, calibration."""
    from biometric_auth.engine.bias import run_bias_analysis

    df = load_scores(scores)
    if group_col != "group" and group_col in df.columns:
        df = df.rename(columns={group_col: "group"})
    if "group" not in df.columns:
        raise click.UsageError(f"Group column '{group_col}' not found in score file.")
    algo = df["algorithm"].iloc[0] if "algorithm" in df.columns else "unknown"
    result = run_bias_analysis(df, algorithm_name=algo)

    if not no_console:
        print_bias(result)

    json_out = to_json(result, path=output)
    if output:
        click.echo(f"JSON written to {output}")
    elif no_console:
        click.echo(json_out)


# ── attack ────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--config", required=True, type=click.Path(exists=True),
              help="YAML system configuration file.")
@click.option("--scores", default=None, type=click.Path(exists=True),
              help="Optional score file to use EER as baseline FAR.")
@click.option("--output", default=None, type=click.Path())
@click.option("--no-console", is_flag=True, default=False)
def attack(config: str, scores: Optional[str], output: Optional[str], no_console: bool) -> None:
    """Simulate 7 attack vectors (PAD + digital + infrastructure)."""
    from biometric_auth.engine.attack import run_attack_simulation
    from biometric_auth.engine.metrics import run_evaluation

    sys_config = load_config(config)
    baseline_far = 0.05
    if scores:
        df = load_scores(scores)
        eval_result = run_evaluation(df)
        baseline_far = eval_result.far

    result = run_attack_simulation(sys_config, baseline_far=baseline_far)

    if not no_console:
        print_attack(result)

    json_out = to_json(result, path=output)
    if output:
        click.echo(f"JSON written to {output}")
    elif no_console:
        click.echo(json_out)


# ── gdpr ──────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--config", required=True, type=click.Path(exists=True))
@click.option("--scores", default=None, type=click.Path(exists=True))
@click.option("--output", default=None, type=click.Path())
@click.option("--no-console", is_flag=True, default=False)
def gdpr(config: str, scores: Optional[str], output: Optional[str], no_console: bool) -> None:
    """Run the GDPR Article 9 compliance assessment (22 checks, 7 obligations)."""
    from biometric_auth.engine.attack import run_attack_simulation
    from biometric_auth.engine.bias import run_bias_analysis
    from biometric_auth.engine.gdpr import run_art9_assessment
    from biometric_auth.engine.metrics import run_evaluation

    sys_config = load_config(config)
    eval_result = None
    bias_result = None
    attack_result = None

    if scores:
        df = load_scores(scores)
        eval_result = run_evaluation(
            df,
            algorithm_name=sys_config.algorithm.name,
            modality=sys_config.algorithm.modality,
        )
        if "group" in df.columns and df["group"].nunique() > 1:
            bias_result = run_bias_analysis(df, algorithm_name=sys_config.algorithm.name)
        baseline_far = eval_result.far
        attack_result = run_attack_simulation(sys_config, baseline_far=baseline_far)
    else:
        attack_result = run_attack_simulation(sys_config)

    report = run_art9_assessment(
        sys_config,
        evaluation_result=eval_result,
        bias_result=bias_result,
        attack_result=attack_result,
    )

    if not no_console:
        print_gdpr(report)

    json_out = to_json(report, path=output)
    if output:
        click.echo(f"JSON written to {output}")
    elif no_console:
        click.echo(json_out)


# ── report ────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--config", required=True, type=click.Path(exists=True))
@click.option("--scores", default=None, type=click.Path(exists=True))
@click.option("--output-dir", default=".", type=click.Path())
def report(config: str, scores: Optional[str], output_dir: str) -> None:
    """Generate console + JSON + PDF reports to output-dir."""
    from biometric_auth.engine.attack import run_attack_simulation
    from biometric_auth.engine.bias import run_bias_analysis
    from biometric_auth.engine.gdpr import run_art9_assessment
    from biometric_auth.engine.metrics import run_evaluation
    from biometric_auth.reporters.pdf_rep import generate_pdf

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    sys_config = load_config(config)
    eval_result = None
    bias_result = None

    if scores:
        df = load_scores(scores)
        eval_result = run_evaluation(
            df,
            algorithm_name=sys_config.algorithm.name,
            modality=sys_config.algorithm.modality,
        )
        if "group" in df.columns and df["group"].nunique() > 1:
            bias_result = run_bias_analysis(df, algorithm_name=sys_config.algorithm.name)

    baseline_far = eval_result.far if eval_result else 0.05
    attack_result = run_attack_simulation(sys_config, baseline_far=baseline_far)

    gdpr_report = run_art9_assessment(
        sys_config,
        evaluation_result=eval_result,
        bias_result=bias_result,
        attack_result=attack_result,
    )

    # Console
    print_gdpr(gdpr_report)
    if eval_result:
        print_evaluation(eval_result)
    if bias_result:
        print_bias(bias_result)
    print_attack(attack_result)

    # JSON
    json_path = out / "gdpr_report.json"
    to_json(gdpr_report, path=json_path)
    click.echo(f"JSON: {json_path}")

    # PDF
    pdf_path = out / "gdpr_report.pdf"
    generate_pdf(gdpr_report, evaluation_result=eval_result, output=pdf_path)
    click.echo(f"PDF:  {pdf_path}")


# ── serve ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--port", default=8501, help="Port to run Streamlit on.")
@click.option("--host", default="localhost")
def serve(port: int, host: str) -> None:
    """Launch the Streamlit dashboard."""
    import subprocess

    app_path = Path(__file__).parent / "app.py"
    click.echo(f"Starting dashboard at http://{host}:{port}")
    subprocess.run(
        [sys.executable, "-m", "streamlit", "run", str(app_path),
         "--server.port", str(port), "--server.address", host],
        check=True,
    )


# ── sample ────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--output", default=None, type=click.Path(),
              help="Write sample config to this path instead of stdout.")
def sample(output: Optional[str]) -> None:
    """Emit an annotated sample YAML system configuration."""
    text = emit_sample_config()
    if output:
        Path(output).write_text(text)
        click.echo(f"Sample config written to {output}")
    else:
        click.echo(text)


if __name__ == "__main__":
    cli()
