"""Streamlit interface for the Control Assurance Engine."""

from datetime import date

import pandas as pd
import streamlit as st

from src.assessment_models import Assessment
from src.assessment_service import create_assessment
from src.assessment_workspace import (
    get_assessment_detail,
    get_assessment_summaries,
)

# Configure the Streamlit application.
st.set_page_config(
    page_title="Control Assurance Engine",
    page_icon="🛡️",
    layout="wide",
)

# Display the application header.
st.title("Control Assurance Engine")
st.subheader("Assessment Workspace")
st.caption("Review saved security control assessments and their findings.")

review_tab, create_tab = st.tabs(["Review Assessments", "Create Assessment"])

with create_tab:
    st.subheader("Create New Assessment")
    st.caption(
        "Enter the assessment details to create a new security control assessment."
    )

    with st.form("create_assessment_form"):
        assessment_id = st.text_input(
            "Assessment ID",
            placeholder="ASM-2026-002",
            key="assessment_id",
        )

        organization = st.text_input("Organization")

        assessor = st.text_input("Assessor")

        assessment_date = st.date_input(
            "Assessment Date",
            value=date.today(),
        )

        framework = st.selectbox(
            "Framework",
            options=[
                "NIST CSF 2.0",
                "ISO/IEC 27001:2022",
                "CIS Controls v8.1",
                "NIST SP 800-53 Rev. 5",
            ],
        )

        scope = st.text_area("Assessment Scope")

        submitted = st.form_submit_button(
            "Create Assessment",
            type="primary",
        )

    if submitted:
        try:
            assessment = Assessment(
                assessment_id=assessment_id.strip(),
                organization=organization.strip(),
                assessor=assessor.strip(),
                assessment_date=assessment_date,
                framework=framework,
                scope=scope.strip(),
            )
            create_assessment(
                assessment,
                [],
                [],
            )

        except FileExistsError:
            st.error("An assessment with this ID already exists.")

        except ValueError as exc:
            st.error(f"Invalid assessment details: {exc}")

        except OSError:
            st.error(
                "The assessment could not be saved. Please check the storage directory."
            )

        else:
            st.success(f"Assessment '{assessment.assessment_id}' created successfully.")

# Retrieve available assessments.
with review_tab:
    assessment_summaries = get_assessment_summaries()

    if not assessment_summaries:
        st.info("No saved assessments are available.")

    else:
        # Allow the user to select a saved assessment.
        selected_assessment = st.selectbox(
            "Select an assessment",
            options=assessment_summaries,
            format_func=lambda assessment: (
                f"{assessment.assessment_id} — {assessment.organization}"
            ),
        )

        # Retrieve the complete assessment record.
        detail = get_assessment_detail(
            selected_assessment.assessment_id,
        )

        if detail is None:
            st.error("The selected assessment could not be found.")

        else:
            # Display assessment metadata.
            st.divider()

            st.header(detail.assessment.organization)

            st.caption(
                f"Assessment {detail.assessment.assessment_id}"
                f"  |  {detail.assessment.assessment_date:%B %d, %Y}"
                f"  |  {detail.assessment.framework}"
            )

            st.markdown(f"**Assessment Scope:** {detail.assessment.scope}")

            # Display assessment summary metrics.
            st.subheader("Assessment Summary")

            summary_columns = st.columns(3, gap="medium")

            with summary_columns[0], st.container(border=True):
                st.metric(
                    label="Controls Evaluated",
                    value=detail.total_controls,
                )

            with summary_columns[1], st.container(border=True):
                st.metric(
                    label="Total Findings",
                    value=detail.total_findings,
                )

            with summary_columns[2], st.container(border=True):
                st.metric(
                    label="High Risk Findings",
                    value=detail.findings_by_severity["HIGH"],
                )

            # Display the risk severity distribution.
            st.subheader("Risk Severity Distribution")

            severity_counts = detail.findings_by_severity

            severity_data = pd.DataFrame(
                {
                    "Severity": [
                        "Low",
                        "Moderate",
                        "High",
                        "Critical",
                    ],
                    "Findings": [
                        severity_counts["LOW"],
                        severity_counts["MODERATE"],
                        severity_counts["HIGH"],
                        severity_counts["CRITICAL"],
                    ],
                }
            )

            st.bar_chart(
                severity_data,
                x="Severity",
                y="Findings",
                horizontal=True,
                sort=False,
            )

            # Display control evaluations.
            st.subheader("Control Evaluations")

            control_rows = [
                {
                    "Control ID": control.control_id,
                    "Assessment Method": control.assessment_method.title(),
                    "Implementation Status": (
                        control.implementation_status.replace("_", " ").title()
                    ),
                    "Evidence Status": (
                        control.evidence_status.replace("_", " ").title()
                    ),
                    "Observations": control.observations,
                }
                for control in detail.control_assessments
            ]

            if control_rows:
                st.dataframe(
                    control_rows,
                    width="stretch",
                    hide_index=True,
                    row_height=70,
                    height=525,
                    column_config={
                        "Control ID": st.column_config.TextColumn(
                            "Control ID",
                            width="small",
                        ),
                        "Assessment Method": st.column_config.TextColumn(
                            "Method",
                            width="small",
                        ),
                        "Implementation Status": st.column_config.TextColumn(
                            "Implementation Status",
                            width="medium",
                        ),
                        "Evidence Status": st.column_config.TextColumn(
                            "Evidence",
                            width="small",
                        ),
                        "Observations": st.column_config.TextColumn(
                            "Observations",
                            width="large",
                            help="Detailed observations recorded during the control evaluation.",
                        ),
                    },
                )
            else:
                st.info("No control evaluations are available.")

            # Display security findings.
            st.subheader("Security Findings")

            finding_rows = [
                {
                    "Finding ID": finding.finding_id,
                    "Control ID": finding.control_id,
                    "Severity": finding.risk_severity.title(),
                    "Risk Score": finding.risk_score,
                    "Likelihood": finding.likelihood,
                    "Impact": finding.impact,
                }
                for finding in detail.findings
            ]

            if finding_rows:
                st.dataframe(
                    finding_rows,
                    width="stretch",
                    hide_index=True,
                )
            else:
                if not detail.control_assessments:
                    st.info(
                        "Assessment not yet evaluated. "
                        "No security findings have been recorded."
                    )
                else:
                    st.success("No security findings were identified.")

            # Display detailed information for each security finding.
            if detail.findings:
                st.markdown("#### Finding Details")

                for finding in detail.findings:
                    finding_label = (
                        f"{finding.finding_id} | "
                        f"{finding.control_id} | "
                        f"{finding.risk_severity.title()} "
                        f"(Score: {finding.risk_score})"
                    )

                    with st.expander(finding_label):
                        st.markdown("**Description**")
                        st.write(finding.description)

                        st.markdown("**Risk Rationale**")
                        st.write(finding.risk_rationale)

                        st.markdown("**Recommended Remediation**")
                        st.write(finding.recommendation)
