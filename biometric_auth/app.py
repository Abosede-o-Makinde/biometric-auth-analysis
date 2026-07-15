"""Streamlit dashboard for biometric-auth-analysis.

6 tabs:
  1. Overview        — KPI strip, radar chart, summary table
  2. Performance     — ROC, DET, score histogram, CI ribbon
  3. Algorithm Comp. — EER bar chart, DeLong p-value heatmap
  4. Demographic Bias — per-group ROC, fairness table, FAIR/BIASED badge
  5. Attack Sim.     — CVSS-like bar chart, spider, recommendations
  6. GDPR Art.9      — gauge, obligation bars, finding table, PDF download
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

# ── Helpers ───────────────────────────────────────────────────────────────────

_HERE = Path(__file__).parent
_SYNTHETIC_DIR = _HERE.parent / "data" / "synthetic"


@st.cache_data(show_spinner=False)
def _load_demo_scores(name: str) -> pd.DataFrame:
    from biometric_auth.parsers.score_file import load_scores
    return load_scores(_SYNTHETIC_DIR / name)


@st.cache_data(show_spinner=False)
def _load_demo_config(name: str):
    from biometric_auth.parsers.config_parser import load_config
    config_dir = _HERE.parent / "data" / "sample_configs"
    return load_config(config_dir / name)


def _gauge(value: float, title: str, threshold: float = 0.90) -> go.Figure:
    pct = value * 100
    colour = "#007A33" if value >= threshold else ("#F5A623" if value >= 0.45 else "#C8102E")
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=pct,
        number={"suffix": "%", "font": {"size": 28}},
        title={"text": title, "font": {"size": 14}},
        gauge={
            "axis": {"range": [0, 100], "ticksuffix": "%"},
            "bar": {"color": colour},
            "steps": [
                {"range": [0, 45], "color": "#FFECEC"},
                {"range": [45, 90], "color": "#FFF8E1"},
                {"range": [90, 100], "color": "#E8F5E9"},
            ],
            "threshold": {
                "line": {"color": "#003087", "width": 3},
                "thickness": 0.75,
                "value": threshold * 100,
            },
        },
    ))
    fig.update_layout(height=240, margin=dict(t=40, b=0, l=20, r=20))
    return fig


def _run_full_assessment(scores_df: pd.DataFrame, sys_config):
    from biometric_auth.engine.attack import run_attack_simulation
    from biometric_auth.engine.bias import run_bias_analysis
    from biometric_auth.engine.gdpr import run_art9_assessment
    from biometric_auth.engine.metrics import run_evaluation

    eval_result = run_evaluation(
        scores_df,
        algorithm_name=sys_config.algorithm.name,
        modality=sys_config.algorithm.modality,
    )
    bias_result = None
    if "group" in scores_df.columns and scores_df["group"].nunique() > 1:
        bias_result = run_bias_analysis(scores_df, algorithm_name=sys_config.algorithm.name)
    attack_result = run_attack_simulation(sys_config, baseline_far=eval_result.far)
    gdpr_report = run_art9_assessment(
        sys_config,
        evaluation_result=eval_result,
        bias_result=bias_result,
        attack_result=attack_result,
    )
    return eval_result, bias_result, attack_result, gdpr_report


# ── App layout ────────────────────────────────────────────────────────────────

def main() -> None:
    st.set_page_config(
        page_title="Biometric Auth Analysis",
        page_icon="🔐",
        layout="wide",
    )
    st.title("🔐 Biometric Authentication Security Evaluation")
    st.caption(
        "FAR/FRR · Demographic Bias · Attack Simulation · GDPR Art.9 Compliance  "
        "| [github.com/Abosede-o-Makinde/biometric-auth-analysis](https://github.com/Abosede-o-Makinde/biometric-auth-analysis)"
    )

    # ── Sidebar ────────────────────────────────────────────────────────────
    with st.sidebar:
        st.header("Data Sources")
        demo_scores_name = st.selectbox(
            "Demo score file",
            ["scores_high_accuracy.csv", "scores_medium_accuracy.csv", "scores_low_accuracy.csv"],
        )
        demo_config_name = st.selectbox(
            "Demo system config",
            ["system_face_recognition.yaml", "system_fingerprint.yaml", "system_iris.yaml"],
        )
        uploaded_scores = st.file_uploader("Upload score file (CSV)", type=["csv"])
        uploaded_config = st.file_uploader("Upload config (YAML)", type=["yaml", "yml"])
        use_demo = st.button("Load demo data", type="primary")

    # State
    if "eval_result" not in st.session_state:
        st.session_state.eval_result = None
        st.session_state.bias_result = None
        st.session_state.attack_result = None
        st.session_state.gdpr_report = None
        st.session_state.scores_df = None
        st.session_state.sys_config = None

    # Load data
    if use_demo or (st.session_state.eval_result is None and uploaded_scores is None):
        with st.spinner("Loading demo data…"):
            try:
                scores_df = _load_demo_scores(demo_scores_name)
                sys_config = _load_demo_config(demo_config_name)
                eval_r, bias_r, attack_r, gdpr_r = _run_full_assessment(scores_df, sys_config)
                st.session_state.update({
                    "eval_result": eval_r, "bias_result": bias_r,
                    "attack_result": attack_r, "gdpr_report": gdpr_r,
                    "scores_df": scores_df, "sys_config": sys_config,
                })
            except Exception as e:
                st.error(f"Failed to load demo data: {e}")
                return

    if uploaded_scores is not None:
        from biometric_auth.parsers.score_file import load_scores
        from biometric_auth.parsers.config_parser import load_config
        import io, tempfile, yaml
        try:
            scores_df = load_scores(io.StringIO(uploaded_scores.read().decode()))
        except Exception as e:
            st.sidebar.error(f"Score file error: {e}")
            scores_df = st.session_state.scores_df
        if uploaded_config is not None:
            try:
                with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as tmp:
                    tmp.write(uploaded_config.read())
                    tmp_path = tmp.name
                sys_config = load_config(tmp_path)
            except Exception as e:
                st.sidebar.error(f"Config error: {e}")
                sys_config = st.session_state.sys_config
        else:
            sys_config = st.session_state.sys_config
        if scores_df is not None and sys_config is not None:
            with st.spinner("Running analysis…"):
                eval_r, bias_r, attack_r, gdpr_r = _run_full_assessment(scores_df, sys_config)
                st.session_state.update({
                    "eval_result": eval_r, "bias_result": bias_r,
                    "attack_result": attack_r, "gdpr_report": gdpr_r,
                    "scores_df": scores_df, "sys_config": sys_config,
                })

    eval_result = st.session_state.eval_result
    bias_result = st.session_state.bias_result
    attack_result = st.session_state.attack_result
    gdpr_report = st.session_state.gdpr_report

    if eval_result is None:
        st.info("Click **Load demo data** in the sidebar to get started.")
        return

    tabs = st.tabs([
        "Overview", "Biometric Performance", "Algorithm Comparison",
        "Demographic Bias", "Attack Simulation", "GDPR Art.9",
    ])

    # ── Tab 1: Overview ───────────────────────────────────────────────────
    with tabs[0]:
        st.subheader("System Overview")
        k1, k2, k3, k4 = st.columns(4)
        k1.metric("EER", f"{eval_result.eer:.2%}",
                  help="Equal Error Rate — lower is better")
        k2.metric("AUC-ROC", f"{eval_result.auc_roc:.4f}",
                  help="Area Under ROC Curve — higher is better")
        gdpr_score = gdpr_report.overall_score if gdpr_report else 0.0
        k3.metric("GDPR Art.9 Score", f"{gdpr_score:.1%}",
                  help="Compliance score (90% threshold for Art.9)")
        if bias_result:
            k4.metric("Fairness Verdict", bias_result.fairness_verdict)
        else:
            k4.metric("Fairness", "Not assessed")

        st.divider()
        col_r, col_t = st.columns([1, 2])
        with col_r:
            # Radar chart: 5 axes
            eer_score = max(0.0, 1.0 - eval_result.eer * 5)  # 0% EER → 1.0
            bias_score = (
                max(0.0, 1.0 - bias_result.equalised_odds_difference * 5)
                if bias_result else 0.5
            )
            attack_score = max(0.0, 1.0 - attack_result.overall_vulnerability_score / 10)
            gdpr_obl_scores = [obl.score for obl in gdpr_report.obligations]
            privacy_score = sum(gdpr_obl_scores[:2]) / 2 if gdpr_obl_scores else 0.5

            radar = go.Figure(go.Scatterpolar(
                r=[eer_score, bias_score, attack_score, gdpr_score, privacy_score, eer_score],
                theta=["Accuracy", "Fairness", "Security", "GDPR", "Privacy", "Accuracy"],
                fill="toself",
                line_color="#003087",
                fillcolor="rgba(0,48,135,0.15)",
            ))
            radar.update_layout(
                polar=dict(radialaxis=dict(range=[0, 1])),
                showlegend=False, height=300,
                margin=dict(t=30, b=30, l=30, r=30),
                title="System Radar",
            )
            st.plotly_chart(radar, use_container_width=True)

        with col_t:
            st.markdown("**System Configuration**")
            sys_config = st.session_state.sys_config
            if sys_config:
                st.json({
                    "System": sys_config.system_name,
                    "Algorithm": sys_config.algorithm.name,
                    "Modality": sys_config.algorithm.modality,
                    "Environment": sys_config.deployment.environment,
                    "Use Case": sys_config.deployment.use_case,
                    "Art.9 Basis": sys_config.deployment.art9_basis,
                    "DPIA": sys_config.deployment.dpia_completed,
                    "Template Protection": sys_config.security.template_protection,
                })

    # ── Tab 2: Biometric Performance ──────────────────────────────────────
    with tabs[1]:
        st.subheader("Biometric Performance Evaluation")
        scores_df = st.session_state.scores_df

        c1, c2 = st.columns(2)
        with c1:
            # ROC Curve
            fig_roc = go.Figure()
            fig_roc.add_trace(go.Scatter(
                x=eval_result.roc_fpr, y=eval_result.roc_tpr,
                mode="lines", name=f"ROC (AUC={eval_result.auc_roc:.4f})",
                line=dict(color="#003087", width=2),
            ))
            fig_roc.add_trace(go.Scatter(
                x=[0, 1], y=[0, 1], mode="lines", name="Random",
                line=dict(dash="dash", color="grey"),
            ))
            fig_roc.update_layout(
                title="ROC Curve", xaxis_title="False Positive Rate (FAR)",
                yaxis_title="True Positive Rate (1 - FRR)", height=380,
            )
            st.plotly_chart(fig_roc, use_container_width=True)

        with c2:
            # Score Distribution
            genuine = scores_df[scores_df["label"] == 1]["score"]
            impostor = scores_df[scores_df["label"] == 0]["score"]
            fig_hist = go.Figure()
            fig_hist.add_trace(go.Histogram(
                x=genuine, name="Genuine", opacity=0.6,
                marker_color="#007A33", nbinsx=50,
            ))
            fig_hist.add_trace(go.Histogram(
                x=impostor, name="Impostor", opacity=0.6,
                marker_color="#C8102E", nbinsx=50,
            ))
            fig_hist.add_vline(
                x=eval_result.eer_threshold, line_dash="dash", line_color="#003087",
                annotation_text=f"EER threshold ({eval_result.eer_threshold:.3f})",
            )
            fig_hist.update_layout(
                title="Score Distributions", barmode="overlay",
                xaxis_title="Comparison Score", yaxis_title="Count", height=380,
            )
            st.plotly_chart(fig_hist, use_container_width=True)

        # Metrics table
        st.markdown("**Performance Metrics with 95% Bootstrap CI**")
        st.dataframe(pd.DataFrame({
            "Metric": ["EER", "FAR @ EER threshold", "FRR @ EER threshold", "AUC-ROC"],
            "Value": [f"{eval_result.eer:.4%}", f"{eval_result.far:.4%}",
                      f"{eval_result.frr:.4%}", f"{eval_result.auc_roc:.6f}"],
            "CI Low": [f"{eval_result.eer_ci_low:.4%}", f"{eval_result.far_ci_low:.4%}",
                       f"{eval_result.frr_ci_low:.4%}", "—"],
            "CI High": [f"{eval_result.eer_ci_high:.4%}", f"{eval_result.far_ci_high:.4%}",
                        f"{eval_result.frr_ci_high:.4%}", "—"],
        }), use_container_width=True, hide_index=True)

    # ── Tab 3: Algorithm Comparison ───────────────────────────────────────
    with tabs[2]:
        st.subheader("Algorithm Comparison")
        st.info(
            "Load multiple score files via the CLI (`biometric-auth compare --scores a.csv --scores b.csv`) "
            "or upload a second score file below."
        )
        second_scores = st.file_uploader("Second score file (CSV)", type=["csv"], key="second_scores")
        if second_scores:
            import io
            from biometric_auth.parsers.score_file import load_scores as _ls
            from biometric_auth.engine.metrics import run_evaluation as _re
            from biometric_auth.engine.statistics import delong_auc_comparison
            try:
                df2 = _ls(io.StringIO(second_scores.read().decode()))
                algo2 = df2["algorithm"].iloc[0] if "algorithm" in df2.columns else "System B"
                eval2 = _re(df2, algorithm_name=algo2)
                z, p = delong_auc_comparison(st.session_state.scores_df, df2)
                a1 = st.session_state.eval_result.algorithm_name

                fig_bar = go.Figure([go.Bar(
                    x=[a1, algo2],
                    y=[st.session_state.eval_result.eer * 100, eval2.eer * 100],
                    error_y=dict(type="data", array=[
                        (st.session_state.eval_result.eer_ci_high - st.session_state.eval_result.eer_ci_low) / 2 * 100,
                        (eval2.eer_ci_high - eval2.eer_ci_low) / 2 * 100,
                    ], visible=True),
                    marker_color=["#003087", "#007A73"],
                )])
                fig_bar.update_layout(
                    title="EER Comparison with 95% CI", yaxis_title="EER (%)", height=350
                )
                st.plotly_chart(fig_bar, use_container_width=True)
                sig = "significant" if p < 0.05 else "not significant"
                st.metric("DeLong AUC comparison p-value", f"{p:.4f}",
                          delta=sig, delta_color="off")
            except Exception as e:
                st.error(f"Comparison error: {e}")
        else:
            st.caption("Upload a second score file to enable comparison.")

    # ── Tab 4: Demographic Bias ───────────────────────────────────────────
    with tabs[3]:
        st.subheader("Demographic Bias Analysis")
        if bias_result is None:
            st.warning(
                "No group labels found in the score file. "
                "Use a score file with a `group` column to enable bias analysis."
            )
        else:
            verdict_colour = {"FAIR": "green", "MARGINAL": "orange", "BIASED": "red"}
            vc = verdict_colour.get(bias_result.fairness_verdict, "grey")
            st.markdown(
                f"**Fairness Verdict:** :{vc}[{bias_result.fairness_verdict}]  "
                f"| EqOdds: {bias_result.equalised_odds_difference:.3f}  "
                f"| DIR: {bias_result.disparate_impact_ratio:.3f}"
            )

            c1, c2 = st.columns(2)
            with c1:
                groups = list(bias_result.group_results.values())
                fig_grp = go.Figure()
                fig_grp.add_trace(go.Bar(
                    name="FAR", x=[g.group_name for g in groups],
                    y=[g.far * 100 for g in groups], marker_color="#C8102E",
                ))
                fig_grp.add_trace(go.Bar(
                    name="FRR", x=[g.group_name for g in groups],
                    y=[g.frr * 100 for g in groups], marker_color="#003087",
                ))
                fig_grp.update_layout(
                    barmode="group", title="FAR / FRR by Group",
                    yaxis_title="%", height=350,
                )
                st.plotly_chart(fig_grp, use_container_width=True)

            with c2:
                fairness_metrics = pd.DataFrame({
                    "Metric": ["DPD (FAR spread)", "EOD (FRR spread)", "EqOdds", "DIR"],
                    "Value": [
                        f"{bias_result.demographic_parity_difference:.4f}",
                        f"{bias_result.equal_opportunity_difference:.4f}",
                        f"{bias_result.equalised_odds_difference:.4f}",
                        f"{bias_result.disparate_impact_ratio:.4f}",
                    ],
                    "Threshold": ["< 0.05", "< 0.05", "< 0.10", "≥ 0.80"],
                    "Pass": [
                        "✓" if bias_result.demographic_parity_difference < 0.05 else "✗",
                        "✓" if bias_result.equal_opportunity_difference < 0.05 else "✗",
                        "✓" if bias_result.equalised_odds_difference < 0.10 else "✗",
                        "✓" if bias_result.disparate_impact_ratio >= 0.80 else "✗",
                    ],
                })
                st.dataframe(fairness_metrics, use_container_width=True, hide_index=True)

    # ── Tab 5: Attack Simulation ──────────────────────────────────────────
    with tabs[4]:
        st.subheader("Attack Simulation")
        st.metric("Overall Vulnerability Score",
                  f"{attack_result.overall_vulnerability_score:.1f} / 10",
                  help="Weighted mean of CVSS-like scores (infrastructure attacks weighted 1.5×)")

        attack_data = pd.DataFrame([v.to_dict() for v in attack_result.attack_vectors])
        attack_data["success_pct"] = attack_data["attack_success_rate"] * 100

        c1, c2 = st.columns([3, 2])
        with c1:
            colour_map = {"CRITICAL": "#C8102E", "HIGH": "#F5A623", "MEDIUM": "#FDD835", "LOW": "#007A33"}
            colours = [colour_map.get(s, "grey") for s in attack_data["severity"]]
            fig_atk = go.Figure(go.Bar(
                y=attack_data["attack_type"],
                x=attack_data["success_pct"],
                orientation="h",
                marker_color=colours,
                text=attack_data["severity"],
                textposition="outside",
            ))
            fig_atk.update_layout(
                title="Attack Success Rate by Vector",
                xaxis_title="Success Rate (%)", height=380,
            )
            st.plotly_chart(fig_atk, use_container_width=True)

        with c2:
            st.markdown("**Attack Vectors**")
            st.dataframe(
                attack_data[["attack_id", "attack_type", "cvss_like_score", "severity"]],
                use_container_width=True, hide_index=True,
            )

    # ── Tab 6: GDPR Art.9 ─────────────────────────────────────────────────
    with tabs[5]:
        st.subheader("GDPR Article 9 Compliance Assessment")

        col_g, col_s = st.columns([1, 2])
        with col_g:
            st.plotly_chart(
                _gauge(gdpr_report.overall_score, "GDPR Art.9 Score"),
                use_container_width=True,
            )
            rc = {"LOW": "green", "MEDIUM": "orange", "HIGH": "red", "CRITICAL": "red"}
            r = gdpr_report.risk_rating
            st.markdown(f"**Risk Rating:** :{rc.get(r, 'grey')}[{r}]  "
                        f"| Status: **{gdpr_report.overall_status}**")

        with col_s:
            obl_df = pd.DataFrame([
                {
                    "Obligation": obl.obligation_ref,
                    "Title": obl.obligation_title[:50] + "…"
                    if len(obl.obligation_title) > 50 else obl.obligation_title,
                    "Score": f"{obl.score:.1%}",
                    "Status": obl.status,
                }
                for obl in gdpr_report.obligations
            ])
            st.dataframe(obl_df, use_container_width=True, hide_index=True)

        st.divider()
        st.markdown("**Findings**")
        all_checks = [
            {
                "Check": c.check_id,
                "Obligation": c.obligation_ref,
                "Status": c.status,
                "Severity": c.severity,
                "Description": c.description,
                "Finding": c.finding[:80] + "…" if len(c.finding) > 80 else c.finding,
                "Remediation": c.remediation[:80] + "…" if len(c.remediation) > 80 else c.remediation,
            }
            for obl in gdpr_report.obligations
            for c in obl.checks
            if c.status in ("GAP", "PARTIAL")
        ]
        if all_checks:
            st.dataframe(pd.DataFrame(all_checks), use_container_width=True, hide_index=True)
        else:
            st.success("All checks SATISFIED or N/A.")

        st.divider()
        col_dl1, col_dl2 = st.columns(2)
        with col_dl1:
            import json
            from biometric_auth.reporters.json_rep import to_json
            json_bytes = to_json(gdpr_report).encode()
            st.download_button(
                "⬇ Download JSON Report", data=json_bytes,
                file_name="gdpr_art9_report.json", mime="application/json",
            )
        with col_dl2:
            try:
                from biometric_auth.reporters.pdf_rep import generate_pdf
                pdf_bytes = generate_pdf(gdpr_report, evaluation_result=eval_result)
                st.download_button(
                    "⬇ Download PDF Report", data=pdf_bytes,
                    file_name="gdpr_art9_report.pdf", mime="application/pdf",
                )
            except ImportError:
                st.caption("Install reportlab for PDF download.")


if __name__ == "__main__":
    main()
