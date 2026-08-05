"""Structured knowledge base backing the ``ai_compliance`` pack.

Two frameworks are represented, at different fidelity:

* **NIST AI RMF 1.0** is a U.S. government publication (public domain). The
  Function/Category structure here (``GV``/``MP``/``MS``/``MG`` and their
  numbered categories) matches the official Core faithfully; the
  ``illustrative_practices`` under each category are our own paraphrased,
  non-exhaustive examples of what satisfying that category tends to look like
  in an AI pipeline — not a transcription of NIST's official subcategories.
* **ISO/IEC 42001:2023** is a licensed standard we do not have redistribution
  rights to. What's here is a structural summary — the clause numbers (4-10,
  the common ISO management-system skeleton it shares with 27001/9001) and
  Annex A control-theme titles (A.2-A.10), with our own paraphrased scope
  descriptions. It is not a substitute for the official controlled text, and
  should not be used as the sole basis for a certification audit.

Every control record has a stable ``id`` scoped within its framework, a
``group`` for filtering/reporting, a ``title``, a paraphrased ``description``,
and non-exhaustive ``illustrative_practices``.
"""
from __future__ import annotations

from typing import Any

NIST_AI_RMF: dict[str, Any] = {
    "id": "nist_ai_rmf",
    "name": "NIST AI Risk Management Framework (AI RMF 1.0)",
    "publisher": "National Institute of Standards and Technology (U.S. Dept. of Commerce)",
    "version": "1.0 (January 2023)",
    "url": "https://www.nist.gov/itl/ai-risk-management-framework",
    "summary": (
        "A voluntary framework for managing risks of AI systems across four "
        "functions carried out continuously and iteratively: GOVERN, MAP, "
        "MEASURE, and MANAGE."
    ),
    "note": (
        "Function/category structure is faithful to the public-domain AI RMF "
        "1.0 Core. Illustrative practices are paraphrased examples for "
        "tooling purposes, not official NIST subcategory text."
    ),
    "controls": [
        {
            "id": "GV.1", "group": "GOVERN",
            "title": "Policies, processes, and practices are in place and effective",
            "description": (
                "Organization-wide policies, processes, procedures, and practices "
                "for mapping, measuring, and managing AI risk are documented, "
                "transparent, and actually followed."
            ),
            "illustrative_practices": [
                "A written AI risk management policy exists and is version-controlled.",
                "Legal/regulatory requirements applicable to each AI use case are tracked.",
                "The organization can point to evidence the policy is followed, not just written.",
            ],
        },
        {
            "id": "GV.2", "group": "GOVERN",
            "title": "Accountability structures are in place",
            "description": (
                "Roles and responsibilities for AI risk management are assigned to "
                "specific teams/individuals, who are empowered and trained."
            ),
            "illustrative_practices": [
                "A named owner (person or team) is accountable for each production AI system.",
                "Escalation paths exist for AI incidents or risk findings.",
                "Staff working on AI systems receive risk-management training.",
            ],
        },
        {
            "id": "GV.3", "group": "GOVERN",
            "title": "Workforce diversity and accessibility are prioritized",
            "description": (
                "Processes account for diversity, equity, inclusion, and "
                "accessibility in the teams and practices that manage AI risk."
            ),
            "illustrative_practices": [
                "Review/red-team panels include diverse perspectives on affected populations.",
                "Accessibility is evaluated as part of system design, not bolted on.",
            ],
        },
        {
            "id": "GV.4", "group": "GOVERN",
            "title": "Organizational culture considers and communicates AI risk",
            "description": (
                "Teams are incentivized to surface AI risk, and risk information "
                "flows across the organization rather than staying siloed."
            ),
            "illustrative_practices": [
                "AI risk is a standing agenda item for teams shipping AI features.",
                "There is a safe, non-punitive channel to report AI risk concerns.",
            ],
        },
        {
            "id": "GV.5", "group": "GOVERN",
            "title": "Robust engagement with relevant AI actors",
            "description": (
                "Processes solicit input from stakeholders affected by or "
                "operating the AI system (users, operators, impacted communities)."
            ),
            "illustrative_practices": [
                "External or user feedback on the AI system is collected and reviewed.",
                "Domain experts are consulted for high-stakes use cases.",
            ],
        },
        {
            "id": "GV.6", "group": "GOVERN",
            "title": "Third-party and supply-chain AI risks are addressed",
            "description": (
                "Policies cover risks and benefits from third-party software, "
                "data, pretrained models, and other supply-chain dependencies."
            ),
            "illustrative_practices": [
                "Third-party models/datasets/APIs used in the pipeline are inventoried.",
                "Vendor AI risk (e.g. a foundation-model provider's own RMF posture) is assessed.",
                "Contracts/SLAs address AI-specific risk (e.g. data use, model changes).",
            ],
        },
        {
            "id": "MP.1", "group": "MAP",
            "title": "Context is established and understood",
            "description": (
                "The intended purpose, business context, and legal/regulatory "
                "requirements for the AI system are documented."
            ),
            "illustrative_practices": [
                "A one-page system context doc: purpose, users, deployment environment.",
                "Applicable laws/regulations for the use case and jurisdiction are identified.",
            ],
        },
        {
            "id": "MP.2", "group": "MAP",
            "title": "The AI system is categorized",
            "description": (
                "The type of AI system, its intended function, and its level of "
                "risk (e.g. via a risk-tiering scheme) are determined."
            ),
            "illustrative_practices": [
                "The system is assigned a risk tier (e.g. low/medium/high-stakes).",
                "Whether the system is generative, predictive, or decision-support is documented.",
            ],
        },
        {
            "id": "MP.3", "group": "MAP",
            "title": "Capabilities, benefits, and costs are understood",
            "description": (
                "Expected AI capabilities are compared against benchmarks and "
                "the goals, benefits, and costs of deploying the system."
            ),
            "illustrative_practices": [
                "Benchmark or evaluation results exist for the model/task before launch.",
                "Cost of errors (false positives/negatives) is weighed against expected benefit.",
            ],
        },
        {
            "id": "MP.4", "group": "MAP",
            "title": "Risks and benefits are mapped for all components",
            "description": (
                "Risks are identified per component of the system, including "
                "third-party software, data, and pretrained models."
            ),
            "illustrative_practices": [
                "A component inventory (model, data sources, plugins/tools, infra) exists.",
                "Each component has an associated risk note (e.g. from a vendor security review).",
            ],
        },
        {
            "id": "MP.5", "group": "MAP",
            "title": "Impacts to individuals and society are characterized",
            "description": (
                "Potential positive and negative impacts on individuals, groups, "
                "communities, organizations, and society are assessed."
            ),
            "illustrative_practices": [
                "An impact assessment covers fairness, safety, privacy, and environmental cost.",
                "Impacted groups who were not part of system design are considered.",
            ],
        },
        {
            "id": "MS.1", "group": "MEASURE",
            "title": "Appropriate methods and metrics are identified",
            "description": (
                "Quantitative, qualitative, or mixed methods are selected to "
                "assess AI risks and are documented."
            ),
            "illustrative_practices": [
                "Metrics beyond raw accuracy (e.g. fairness, robustness, calibration) are tracked.",
                "The chosen metrics are documented alongside their known limitations.",
            ],
        },
        {
            "id": "MS.2", "group": "MEASURE",
            "title": "The system is evaluated for trustworthy characteristics",
            "description": (
                "The AI system is tested for validity/reliability, safety, "
                "security/resilience, accountability/transparency, explainability, "
                "privacy, and fairness."
            ),
            "illustrative_practices": [
                "Adversarial/red-team testing (e.g. jailbreak or prompt-injection testing) has run.",
                "Bias/fairness evaluation across relevant subgroups has been performed.",
                "Explainability tooling exists for consequential decisions.",
            ],
        },
        {
            "id": "MS.3", "group": "MEASURE",
            "title": "Risk tracking mechanisms are in place",
            "description": (
                "Mechanisms exist to track identified AI risks over time, "
                "including risks that emerge after deployment."
            ),
            "illustrative_practices": [
                "A risk register lists known issues with owners and status.",
                "Production monitoring flags drift, degraded outputs, or new failure modes.",
            ],
        },
        {
            "id": "MS.4", "group": "MEASURE",
            "title": "Measurement efficacy feedback is gathered",
            "description": (
                "Feedback on whether the chosen measurement approach actually "
                "worked is collected and used to improve it."
            ),
            "illustrative_practices": [
                "Post-incident reviews assess whether existing metrics would have caught the issue.",
                "Measurement approach is revisited on a defined cadence.",
            ],
        },
        {
            "id": "MG.1", "group": "MANAGE",
            "title": "AI risks are prioritized and managed",
            "description": (
                "Risk responses are prioritized and actioned based on the "
                "outputs of the MAP and MEASURE functions."
            ),
            "illustrative_practices": [
                "Risks from evaluations/red-teaming are triaged with severity and an owner.",
                "High-severity risks block release until mitigated or explicitly accepted.",
            ],
        },
        {
            "id": "MG.2", "group": "MANAGE",
            "title": "Benefit/impact strategies are planned and documented",
            "description": (
                "Strategies to maximize benefit and minimize negative impact are "
                "planned, implemented, and documented with input from AI actors."
            ),
            "illustrative_practices": [
                "Mitigations (e.g. guardrails, human review, rate limits) are documented per risk.",
                "A rollback/kill-switch plan exists for the deployed system.",
            ],
        },
        {
            "id": "MG.3", "group": "MANAGE",
            "title": "Third-party AI risks are managed",
            "description": (
                "Risks and benefits arising from third-party components are "
                "actively managed, not just identified."
            ),
            "illustrative_practices": [
                "Third-party model/API changes are monitored (version pins, changelogs).",
                "A contingency plan exists if a third-party AI dependency is deprecated or fails.",
            ],
        },
        {
            "id": "MG.4", "group": "MANAGE",
            "title": "Risk treatments are documented and monitored",
            "description": (
                "Responses to risks, including recovery from previously unknown "
                "risks (incidents), are documented and regularly monitored."
            ),
            "illustrative_practices": [
                "An incident response process exists specifically for AI failures/harms.",
                "Post-incident, the risk register and controls are updated.",
            ],
        },
    ],
}

ISO_42001: dict[str, Any] = {
    "id": "iso_42001",
    "name": "ISO/IEC 42001:2023 - AI Management System (AIMS)",
    "publisher": "International Organization for Standardization / IEC",
    "version": "2023",
    "url": "https://www.iso.org/standard/81230.html",
    "summary": (
        "A certifiable management-system standard (like ISO 27001 for "
        "security) specifying requirements for establishing, implementing, "
        "maintaining, and continually improving an AI management system."
    ),
    "note": (
        "ISO/IEC 42001 is a licensed standard; we do not reproduce its text. "
        "This is a structural summary (clause numbers and Annex A control-theme "
        "titles, with paraphrased scope) for orienting a compliance review, not "
        "a substitute for the official controlled document in an actual audit."
    ),
    "controls": [
        {
            "id": "4", "group": "Clauses 4-10 (management system)",
            "title": "Context of the organization",
            "description": (
                "Determine internal/external issues, interested parties and their "
                "requirements, and the scope of the AI management system."
            ),
            "illustrative_practices": [
                "A documented AIMS scope statement exists (which systems/teams it covers).",
                "Interested parties (regulators, customers, affected individuals) are identified.",
            ],
        },
        {
            "id": "5", "group": "Clauses 4-10 (management system)",
            "title": "Leadership",
            "description": (
                "Top management demonstrates leadership and commitment, "
                "establishes an AI policy, and assigns organizational roles."
            ),
            "illustrative_practices": [
                "An AI policy is signed off by leadership and communicated org-wide.",
                "Roles/authorities for the AIMS are formally assigned.",
            ],
        },
        {
            "id": "6", "group": "Clauses 4-10 (management system)",
            "title": "Planning",
            "description": (
                "Actions address risks and opportunities; AI objectives are set; "
                "changes to the AIMS are planned."
            ),
            "illustrative_practices": [
                "Documented AI risk assessment and treatment process exists.",
                "Measurable AI objectives are set and tracked (not just aspirational statements).",
            ],
        },
        {
            "id": "7", "group": "Clauses 4-10 (management system)",
            "title": "Support",
            "description": (
                "Resources, competence, awareness, communication, and documented "
                "information needed by the AIMS are provided and controlled."
            ),
            "illustrative_practices": [
                "Staff competence for AI roles is defined and tracked.",
                "Document control exists for AIMS records (versioning, ownership, retention).",
            ],
        },
        {
            "id": "8", "group": "Clauses 4-10 (management system)",
            "title": "Operation",
            "description": (
                "Operational planning/control, AI risk assessment, and AI system "
                "impact assessments are carried out in practice."
            ),
            "illustrative_practices": [
                "Impact assessments are performed before deploying a new AI system.",
                "Operational controls (change management, testing gates) are followed, not aspirational.",
            ],
        },
        {
            "id": "9", "group": "Clauses 4-10 (management system)",
            "title": "Performance evaluation",
            "description": (
                "Monitoring, measurement, analysis, evaluation, internal audit, "
                "and management review of the AIMS occur on a defined cadence."
            ),
            "illustrative_practices": [
                "Internal audits of the AIMS are scheduled and records kept.",
                "Management review meetings produce documented outputs/actions.",
            ],
        },
        {
            "id": "10", "group": "Clauses 4-10 (management system)",
            "title": "Improvement",
            "description": (
                "Nonconformities trigger corrective action, and the AIMS is "
                "continually improved."
            ),
            "illustrative_practices": [
                "A corrective-action process exists and has been used at least once.",
                "Lessons from incidents/audits feed back into policy or controls.",
            ],
        },
        {
            "id": "A.2", "group": "Annex A (controls)",
            "title": "Policies related to AI",
            "description": "AI-specific policies exist, are approved, and are kept current.",
            "illustrative_practices": [
                "A responsible-AI or AI-acceptable-use policy is published internally.",
            ],
        },
        {
            "id": "A.3", "group": "Annex A (controls)",
            "title": "Internal organization",
            "description": "Roles, responsibilities, and reporting lines for AI are defined.",
            "illustrative_practices": [
                "An org chart or RACI exists for AI system ownership.",
            ],
        },
        {
            "id": "A.4", "group": "Annex A (controls)",
            "title": "Resources for AI systems",
            "description": (
                "Data, tooling, system, and human resources needed for "
                "responsible AI operation are identified and provisioned."
            ),
            "illustrative_practices": [
                "Compute/tooling/data resourcing is planned, not ad hoc.",
            ],
        },
        {
            "id": "A.5", "group": "Annex A (controls)",
            "title": "Assessing impacts of AI systems",
            "description": (
                "Impacts on individuals, groups, and society are assessed "
                "before and during deployment."
            ),
            "illustrative_practices": [
                "A documented AI impact assessment template is used per system.",
            ],
        },
        {
            "id": "A.6", "group": "Annex A (controls)",
            "title": "AI system life cycle",
            "description": (
                "Controls span design, development, verification/validation, "
                "deployment, operation, monitoring, and retirement."
            ),
            "illustrative_practices": [
                "A defined lifecycle/SDLC exists for AI systems, including a retirement/decommission step.",
            ],
        },
        {
            "id": "A.7", "group": "Annex A (controls)",
            "title": "Data for AI systems",
            "description": "Data quality, provenance, and preparation are controlled.",
            "illustrative_practices": [
                "Training/eval data provenance and licensing are tracked.",
                "Data quality checks run before data is used for training or RAG.",
            ],
        },
        {
            "id": "A.8", "group": "Annex A (controls)",
            "title": "Information for interested parties",
            "description": (
                "Appropriate transparency and documentation is provided to "
                "users and other interested parties about the AI system."
            ),
            "illustrative_practices": [
                "User-facing docs disclose that AI is involved and its limitations.",
                "Model/system cards exist for significant models.",
            ],
        },
        {
            "id": "A.9", "group": "Annex A (controls)",
            "title": "Use of AI systems",
            "description": "Intended use is documented and responsible use is enforced.",
            "illustrative_practices": [
                "Prohibited/out-of-scope use cases are documented and technically discouraged.",
            ],
        },
        {
            "id": "A.10", "group": "Annex A (controls)",
            "title": "Third-party and customer relationships",
            "description": (
                "AI risk arising from suppliers, vendors, and customer-facing "
                "relationships is managed contractually and operationally."
            ),
            "illustrative_practices": [
                "Vendor AI components go through a risk review before adoption.",
                "Contracts define responsibility for AI-related incidents with third parties.",
            ],
        },
    ],
}

FRAMEWORKS: dict[str, dict[str, Any]] = {
    "nist_ai_rmf": NIST_AI_RMF,
    "iso_42001": ISO_42001,
}
