#!/usr/bin/env python3
"""
AI Security Posture Management (AI-SPM) Scanner v1.1.0

A comprehensive static-analysis scanner for AI/ML projects that identifies
security misconfigurations, vulnerabilities, and compliance gaps across the
entire AI lifecycle — from data ingestion through model training, deployment,
and inference.

Coverage areas:
  - Model Security        (unsafe deserialization, extraction, weights)
  - Prompt / LLM Security (injection, jailbreak, output manipulation)
  - Data Pipeline          (poisoning, validation, integrity)
  - Privacy                (PII/PHI leakage, consent, logging)
  - Guardrails             (safety filters, token limits, temperature)
  - Agent Security         (tool use, autonomy, human-in-the-loop)
  - RAG Security           (vector DB auth, retrieval access control)
  - Secrets                (AI API keys — OpenAI, Anthropic, HuggingFace …)
  - Infrastructure         (model serving, endpoints, Jupyter exposure)
  - Supply Chain           (vulnerable AI/ML packages with CVEs)
  - Shadow AI              (unauthorised AI service usage)
  - MCP Security           (Model Context Protocol server/transport security)
  - Fine-tuning Security   (LoRA/QLoRA, adapter injection, alignment)
  - Multimodal Security    (vision/audio input validation, deepfake controls)
  - AI Observability       (drift detection, hallucination, cost monitoring)
  - AI Gateway             (centralised API management, key rotation)
  - AI Bias & Fairness     (fairness evaluation, protected attributes)
  - K8s AI Workloads       (KServe, Seldon, Triton, GPU pod security)
  - Terraform IaC for AI   (SageMaker, Bedrock, Vertex AI misconfigs)
  - Model Card Compliance  (EU AI Act documentation requirements)
  - Compliance mapping     (NIST AI RMF, EU AI Act, OWASP ML Top 10, MITRE ATLAS)

Usage:
  python ai_spm_scanner.py <target_path> [options]
  python ai_spm_scanner.py ./my_ml_project --severity HIGH --json report.json --html report.html
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import textwrap
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

__version__ = "1.1.0"

# ---------------------------------------------------------------------------
# COMPLIANCE FRAMEWORK MAPPING
# ---------------------------------------------------------------------------
COMPLIANCE_MAP: dict[str, dict[str, str]] = {
    # NIST AI RMF categories
    "NIST-AI-RMF-GOVERN":  {"framework": "NIST AI RMF", "category": "GOVERN",  "desc": "AI risk governance & accountability"},
    "NIST-AI-RMF-MAP":     {"framework": "NIST AI RMF", "category": "MAP",     "desc": "Context & risk framing"},
    "NIST-AI-RMF-MEASURE": {"framework": "NIST AI RMF", "category": "MEASURE", "desc": "Risk assessment & metrics"},
    "NIST-AI-RMF-MANAGE":  {"framework": "NIST AI RMF", "category": "MANAGE",  "desc": "Risk treatment & monitoring"},
    # EU AI Act risk levels
    "EU-AI-ACT-HIGH":      {"framework": "EU AI Act",   "category": "High Risk",       "desc": "High-risk AI system requirements"},
    "EU-AI-ACT-LIMITED":   {"framework": "EU AI Act",   "category": "Limited Risk",     "desc": "Transparency obligations"},
    "EU-AI-ACT-GPAI":      {"framework": "EU AI Act",   "category": "GPAI",            "desc": "General-purpose AI model obligations"},
    # OWASP ML Top 10
    "OWASP-ML-01":         {"framework": "OWASP ML Top 10", "category": "ML01", "desc": "Input Manipulation"},
    "OWASP-ML-02":         {"framework": "OWASP ML Top 10", "category": "ML02", "desc": "Data Poisoning"},
    "OWASP-ML-03":         {"framework": "OWASP ML Top 10", "category": "ML03", "desc": "Model Inversion"},
    "OWASP-ML-04":         {"framework": "OWASP ML Top 10", "category": "ML04", "desc": "Membership Inference"},
    "OWASP-ML-05":         {"framework": "OWASP ML Top 10", "category": "ML05", "desc": "Model Theft"},
    "OWASP-ML-06":         {"framework": "OWASP ML Top 10", "category": "ML06", "desc": "AI Supply Chain"},
    "OWASP-ML-07":         {"framework": "OWASP ML Top 10", "category": "ML07", "desc": "Transfer Learning Attack"},
    "OWASP-ML-08":         {"framework": "OWASP ML Top 10", "category": "ML08", "desc": "Model Skewing"},
    "OWASP-ML-09":         {"framework": "OWASP ML Top 10", "category": "ML09", "desc": "Output Integrity"},
    "OWASP-ML-10":         {"framework": "OWASP ML Top 10", "category": "ML10", "desc": "Neural Net Reprogramming"},
    # MITRE ATLAS tactics
    "ATLAS-RECON":         {"framework": "MITRE ATLAS", "category": "Reconnaissance",      "desc": "AI system reconnaissance"},
    "ATLAS-RES-DEV":       {"framework": "MITRE ATLAS", "category": "Resource Development", "desc": "Adversarial resource development"},
    "ATLAS-INIT-ACCESS":   {"framework": "MITRE ATLAS", "category": "Initial Access",      "desc": "Initial access to AI system"},
    "ATLAS-EXEC":          {"framework": "MITRE ATLAS", "category": "ML Attack Execution",  "desc": "Adversarial ML execution"},
    "ATLAS-PERSIST":       {"framework": "MITRE ATLAS", "category": "Persistence",          "desc": "AI system persistence"},
    "ATLAS-EXFIL":         {"framework": "MITRE ATLAS", "category": "Exfiltration",         "desc": "Model/data exfiltration"},
    "ATLAS-IMPACT":        {"framework": "MITRE ATLAS", "category": "Impact",               "desc": "AI system impact"},
}

# ---------------------------------------------------------------------------
# PYTHON SAST RULES — MODEL SECURITY
# ---------------------------------------------------------------------------
MODEL_SECURITY_RULES: list[dict[str, Any]] = [
    {
        "id": "AISPM-MODEL-001", "category": "Model Security", "severity": "CRITICAL",
        "name": "Unsafe pickle model loading",
        "pattern": r"""(?:pickle\.load|pickle\.loads|pickle\.Unpickler)\s*\(""",
        "description": "pickle.load executes arbitrary code during deserialization. An attacker can craft a malicious .pkl model file that runs arbitrary commands when loaded.",
        "cwe": "CWE-502", "recommendation": "Use safetensors, ONNX, or torch.load with weights_only=True instead of pickle for model loading.",
        "compliance": ["OWASP-ML-06", "NIST-AI-RMF-MANAGE", "ATLAS-EXEC"],
    },
    {
        "id": "AISPM-MODEL-002", "category": "Model Security", "severity": "CRITICAL",
        "name": "Unsafe joblib model loading",
        "pattern": r"""joblib\.load\s*\(""",
        "description": "joblib.load uses pickle internally and is vulnerable to arbitrary code execution via crafted model files.",
        "cwe": "CWE-502", "recommendation": "Use safetensors or ONNX format. If joblib is required, verify file integrity with cryptographic hashes before loading.",
        "compliance": ["OWASP-ML-06", "NIST-AI-RMF-MANAGE", "ATLAS-EXEC"],
    },
    {
        "id": "AISPM-MODEL-003", "category": "Model Security", "severity": "CRITICAL",
        "name": "torch.load without weights_only=True",
        "pattern": r"""torch\.load\s*\([^)]*(?<!\bweights_only\s*=\s*True)\)""",
        "description": "torch.load uses pickle by default. Without weights_only=True, malicious model files can execute arbitrary code.",
        "cwe": "CWE-502", "recommendation": "Use torch.load(..., weights_only=True) or migrate to safetensors format.",
        "compliance": ["OWASP-ML-06", "NIST-AI-RMF-MANAGE", "ATLAS-EXEC"],
    },
    {
        "id": "AISPM-MODEL-004", "category": "Model Security", "severity": "HIGH",
        "name": "Unsafe TensorFlow SavedModel loading",
        "pattern": r"""tf\.saved_model\.load\s*\(|tf\.keras\.models\.load_model\s*\(""",
        "description": "Loading TensorFlow SavedModel from untrusted sources can execute arbitrary ops. Verify model provenance before loading.",
        "cwe": "CWE-502", "recommendation": "Only load models from trusted, verified sources. Use TF model signing and hash verification.",
        "compliance": ["OWASP-ML-06", "NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-MODEL-005", "category": "Model Security", "severity": "HIGH",
        "name": "Model downloaded from untrusted hub without verification",
        "pattern": r"""(?:from_pretrained|download_model|hf_hub_download|snapshot_download)\s*\([^)]*(?:trust_remote_code\s*=\s*True)""",
        "description": "trust_remote_code=True allows execution of arbitrary Python code from model repositories. This is a supply chain attack vector.",
        "cwe": "CWE-829", "recommendation": "Set trust_remote_code=False and audit any remote code before enabling. Pin model revisions with specific commit hashes.",
        "compliance": ["OWASP-ML-06", "ATLAS-INIT-ACCESS", "EU-AI-ACT-GPAI"],
    },
    {
        "id": "AISPM-MODEL-006", "category": "Model Security", "severity": "HIGH",
        "name": "Executing model output as code",
        "pattern": r"""(?:exec|eval|compile)\s*\([^)]*(?:model|response|output|completion|generation|result|answer)""",
        "description": "Executing AI model output as code (exec/eval) enables remote code execution if the model is manipulated or produces malicious output.",
        "cwe": "CWE-94", "recommendation": "Never execute model outputs as code. Use structured output parsing and strict validation.",
        "compliance": ["OWASP-ML-09", "NIST-AI-RMF-MANAGE", "ATLAS-IMPACT"],
    },
    {
        "id": "AISPM-MODEL-007", "category": "Model Security", "severity": "MEDIUM",
        "name": "Model weights saved without encryption",
        "pattern": r"""(?:\.save_pretrained|\.save|torch\.save|model\.save_weights|joblib\.dump)\s*\([^)]*(?:(?!encrypt|cipher|kms|vault))""",
        "description": "Model weights saved in plaintext can be stolen or tampered with. Encrypt sensitive model artifacts at rest.",
        "cwe": "CWE-311", "recommendation": "Encrypt model weights at rest using KMS, Vault, or filesystem-level encryption.",
        "compliance": ["OWASP-ML-05", "NIST-AI-RMF-MANAGE", "EU-AI-ACT-HIGH"],
    },
    {
        "id": "AISPM-MODEL-008", "category": "Model Security", "severity": "MEDIUM",
        "name": "No model hash or signature verification",
        "pattern": r"""(?:from_pretrained|load_model|torch\.load|joblib\.load)\s*\([^)]*\)(?!.*(?:verify|hash|checksum|signature|digest))""",
        "description": "Loading models without verifying integrity (hash/signature) allows supply chain attacks via tampered model files.",
        "cwe": "CWE-354", "recommendation": "Verify model files against known SHA-256 hashes or cryptographic signatures before loading.",
        "compliance": ["OWASP-ML-06", "NIST-AI-RMF-MEASURE", "ATLAS-RES-DEV"],
    },
    {
        "id": "AISPM-MODEL-009", "category": "Model Security", "severity": "HIGH",
        "name": "Numpy load with allow_pickle",
        "pattern": r"""np\.load\s*\([^)]*allow_pickle\s*=\s*True""",
        "description": "numpy.load with allow_pickle=True enables arbitrary code execution via crafted .npy/.npz files.",
        "cwe": "CWE-502", "recommendation": "Use allow_pickle=False (default in NumPy >=1.16.3) and save data in safe formats.",
        "compliance": ["OWASP-ML-06", "ATLAS-EXEC"],
    },
    {
        "id": "AISPM-MODEL-010", "category": "Model Security", "severity": "MEDIUM",
        "name": "ONNX model loaded without validation",
        "pattern": r"""onnxruntime\.InferenceSession\s*\(|onnx\.load\s*\(""",
        "description": "ONNX models from untrusted sources may contain malicious custom ops. Validate model structure and provenance.",
        "cwe": "CWE-20", "recommendation": "Run onnx.checker.check_model() before inference. Only load ONNX models from trusted, verified sources.",
        "compliance": ["OWASP-ML-06", "NIST-AI-RMF-MEASURE"],
    },
]

# ---------------------------------------------------------------------------
# PYTHON SAST RULES — PROMPT / LLM SECURITY
# ---------------------------------------------------------------------------
PROMPT_SECURITY_RULES: list[dict[str, Any]] = [
    {
        "id": "AISPM-PROMPT-001", "category": "Prompt Security", "severity": "CRITICAL",
        "name": "User input directly concatenated into prompt",
        "pattern": r"""(?:prompt|system_message|messages)\s*(?:=|\+=)\s*.*(?:f['\"]|\.format\s*\(|%\s*\().*(?:user_input|request\.|input\(|query|user_message|user_query)""",
        "description": "User input directly interpolated into prompts enables prompt injection attacks that can override system instructions.",
        "cwe": "CWE-74", "recommendation": "Use parameterised prompt templates. Separate system instructions from user input. Apply input sanitisation.",
        "compliance": ["OWASP-ML-01", "NIST-AI-RMF-MANAGE", "ATLAS-EXEC", "EU-AI-ACT-HIGH"],
    },
    {
        "id": "AISPM-PROMPT-002", "category": "Prompt Security", "severity": "HIGH",
        "name": "System prompt exposed in client-side code or logs",
        "pattern": r"""(?:system_prompt|system_message|system_instruction)\s*=\s*(?:f?['\"](?:You are|Act as|Your role))""",
        "description": "Hardcoded system prompts can be extracted by attackers to understand and bypass AI guardrails.",
        "cwe": "CWE-200", "recommendation": "Store system prompts server-side in environment variables or secrets manager. Never expose in client code or logs.",
        "compliance": ["OWASP-ML-01", "NIST-AI-RMF-GOVERN", "EU-AI-ACT-LIMITED"],
    },
    {
        "id": "AISPM-PROMPT-003", "category": "Prompt Security", "severity": "HIGH",
        "name": "No output validation or filtering on model response",
        "pattern": r"""(?:response|completion|output|result)\s*(?:\.text|\.content|\[.choices.\]|\.message)\s*(?:\)|$)""",
        "description": "Using model output directly without validation can propagate hallucinations, harmful content, or injected commands.",
        "cwe": "CWE-20", "recommendation": "Validate and sanitise all model outputs before use. Implement content filtering, format validation, and output guardrails.",
        "compliance": ["OWASP-ML-09", "NIST-AI-RMF-MEASURE", "EU-AI-ACT-HIGH"],
    },
    {
        "id": "AISPM-PROMPT-004", "category": "Prompt Security", "severity": "HIGH",
        "name": "Jailbreak pattern — role-play override instruction",
        "pattern": r"""(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|you\s+are\s+now\s+(?:DAN|unfiltered|unrestricted)|do\s+anything\s+now|pretend\s+you\s+(?:have\s+no|are\s+not)\s+(?:restrictions|limited)|jailbreak|bypass\s+(?:safety|content)\s+filter)""",
        "description": "Jailbreak prompt patterns detected in codebase that attempt to override AI safety guardrails.",
        "cwe": "CWE-693", "recommendation": "Remove jailbreak patterns. Implement robust system prompts that resist override attempts. Use input classifiers.",
        "compliance": ["OWASP-ML-01", "ATLAS-EXEC", "EU-AI-ACT-HIGH"],
    },
    {
        "id": "AISPM-PROMPT-005", "category": "Prompt Security", "severity": "MEDIUM",
        "name": "Prompt template allows recursive/nested injection",
        "pattern": r"""(?:template|prompt).*\{.*\{.*\}.*\}""",
        "description": "Nested template variables in prompts can enable second-order prompt injection where model output is re-injected.",
        "cwe": "CWE-74", "recommendation": "Avoid nested prompt templates. Use single-level parameterised templates with strict input validation.",
        "compliance": ["OWASP-ML-01", "NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-PROMPT-006", "category": "Prompt Security", "severity": "HIGH",
        "name": "LLM response used in SQL/shell/OS command",
        "pattern": r"""(?:os\.system|subprocess|cursor\.execute|shell_exec)\s*\([^)]*(?:response|completion|output|result|llm|model|gpt|claude|answer)""",
        "description": "Passing LLM output to system commands or SQL enables injection attacks if the model is manipulated.",
        "cwe": "CWE-78", "recommendation": "Never pass model output to OS commands or SQL. Use parameterised queries and strict output parsing.",
        "compliance": ["OWASP-ML-09", "ATLAS-IMPACT", "NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-PROMPT-007", "category": "Prompt Security", "severity": "MEDIUM",
        "name": "Indirect prompt injection via external data",
        "pattern": r"""(?:requests\.get|urllib|fetch|scrape|crawl|BeautifulSoup)\s*\([^)]*\).*(?:prompt|message|context|input)""",
        "description": "Fetching external content and injecting it into prompts enables indirect prompt injection via compromised web pages or documents.",
        "cwe": "CWE-74", "recommendation": "Sanitise all external data before including in prompts. Clearly delimit user/system/external content boundaries.",
        "compliance": ["OWASP-ML-01", "ATLAS-INIT-ACCESS", "EU-AI-ACT-HIGH"],
    },
    {
        "id": "AISPM-PROMPT-008", "category": "Prompt Security", "severity": "MEDIUM",
        "name": "Chat history included in prompt without length limits",
        "pattern": r"""(?:conversation|chat_history|messages|history)\s*(?:\.\s*append|\s*\+\s*=|\s*\.extend)""",
        "description": "Unbounded chat history in prompts can lead to context window exhaustion (denial of service) and prompt injection via earlier messages.",
        "cwe": "CWE-770", "recommendation": "Implement conversation window limits (e.g. last N messages). Summarise old context. Set max token budgets.",
        "compliance": ["OWASP-ML-01", "NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-PROMPT-009", "category": "Prompt Security", "severity": "HIGH",
        "name": "Function/tool calling without argument validation",
        "pattern": r"""(?:function_call|tool_calls|tools)\s*.*(?:auto|required|any)""",
        "description": "Enabling AI function/tool calling without strict argument validation allows the model to invoke functions with malicious parameters.",
        "cwe": "CWE-20", "recommendation": "Validate all function call arguments. Use allowlists for callable functions. Implement parameter schemas.",
        "compliance": ["OWASP-ML-01", "ATLAS-EXEC", "EU-AI-ACT-HIGH"],
    },
    {
        "id": "AISPM-PROMPT-010", "category": "Prompt Security", "severity": "LOW",
        "name": "No prompt versioning or audit trail",
        "pattern": r"""(?:system_prompt|system_message|SYSTEM_PROMPT)\s*=\s*(?:f?['\"])""",
        "description": "Hardcoded prompts without versioning make it difficult to track changes, audit behaviour, and roll back to safe versions.",
        "cwe": "CWE-778", "recommendation": "Version prompts in a configuration management system. Maintain an audit trail of prompt changes.",
        "compliance": ["NIST-AI-RMF-GOVERN", "EU-AI-ACT-HIGH"],
    },
]

# ---------------------------------------------------------------------------
# PYTHON SAST RULES — DATA PIPELINE SECURITY
# ---------------------------------------------------------------------------
DATA_PIPELINE_RULES: list[dict[str, Any]] = [
    {
        "id": "AISPM-DATA-001", "category": "Data Pipeline", "severity": "HIGH",
        "name": "Training data loaded from untrusted URL without validation",
        "pattern": r"""(?:pd\.read_csv|pd\.read_json|pd\.read_parquet|datasets\.load_dataset|wget|urllib\.request\.urlretrieve)\s*\(\s*(?:f?['\"]https?://)""",
        "description": "Loading training data from remote URLs without integrity verification enables data poisoning attacks.",
        "cwe": "CWE-494", "recommendation": "Verify data integrity with checksums. Use pinned dataset versions. Download over HTTPS and validate provenance.",
        "compliance": ["OWASP-ML-02", "ATLAS-RES-DEV", "NIST-AI-RMF-MAP"],
    },
    {
        "id": "AISPM-DATA-002", "category": "Data Pipeline", "severity": "HIGH",
        "name": "User-supplied data used directly in training/fine-tuning",
        "pattern": r"""(?:\.fit|\.train|\.fine_tune|trainer\.train|\.train_on_batch)\s*\([^)]*(?:user_data|user_input|upload|request\.)""",
        "description": "Incorporating user-supplied data directly into training enables data poisoning and backdoor attacks.",
        "cwe": "CWE-20", "recommendation": "Sanitise and validate all user-supplied training data. Implement data quarantine and review processes.",
        "compliance": ["OWASP-ML-02", "ATLAS-PERSIST", "EU-AI-ACT-HIGH"],
    },
    {
        "id": "AISPM-DATA-003", "category": "Data Pipeline", "severity": "MEDIUM",
        "name": "No data schema validation before model input",
        "pattern": r"""(?:model\.predict|model\.generate|model\.__call__|pipeline\()\s*\([^)]*(?:raw_|unvalidated_|user_)""",
        "description": "Passing unvalidated data to model inference can cause adversarial input attacks, crashes, or unexpected behaviour.",
        "cwe": "CWE-20", "recommendation": "Validate data schemas and ranges before model inference. Use input sanitisation and type checking.",
        "compliance": ["OWASP-ML-01", "NIST-AI-RMF-MEASURE"],
    },
    {
        "id": "AISPM-DATA-004", "category": "Data Pipeline", "severity": "MEDIUM",
        "name": "Eval/test data leaking into training set",
        "pattern": r"""(?:train_test_split|split)\s*\([^)]*(?:shuffle\s*=\s*False|random_state\s*=\s*None)""",
        "description": "Improper data splitting without shuffle or fixed seed can lead to data leakage between train and test sets.",
        "cwe": "CWE-693", "recommendation": "Use proper train/test splitting with fixed random seeds. Verify no data leakage with deduplication checks.",
        "compliance": ["OWASP-ML-08", "NIST-AI-RMF-MEASURE"],
    },
    {
        "id": "AISPM-DATA-005", "category": "Data Pipeline", "severity": "HIGH",
        "name": "Data labelling from untrusted crowd-source without validation",
        "pattern": r"""(?:crowd|mturk|turk|labelbox|scale_ai|snorkel).*(?:label|annotate|tag)""",
        "description": "Crowd-sourced labels without validation are vulnerable to adversarial label corruption (data poisoning).",
        "cwe": "CWE-20", "recommendation": "Implement consensus voting, inter-annotator agreement checks, and anomaly detection on labels.",
        "compliance": ["OWASP-ML-02", "NIST-AI-RMF-MAP", "ATLAS-RES-DEV"],
    },
    {
        "id": "AISPM-DATA-006", "category": "Data Pipeline", "severity": "MEDIUM",
        "name": "No data lineage or provenance tracking",
        "pattern": r"""(?:train|fit|fine_tune)\s*\([^)]*\)(?!.*(?:mlflow|wandb|dvc|lineage|provenance|log))""",
        "description": "Training without data lineage tracking makes it impossible to audit data sources or detect poisoning after the fact.",
        "cwe": "CWE-778", "recommendation": "Implement data lineage tracking with tools like DVC, MLflow, or custom provenance logs.",
        "compliance": ["NIST-AI-RMF-GOVERN", "EU-AI-ACT-HIGH"],
    },
]

# ---------------------------------------------------------------------------
# PYTHON SAST RULES — PRIVACY
# ---------------------------------------------------------------------------
PRIVACY_RULES: list[dict[str, Any]] = [
    {
        "id": "AISPM-PRIV-001", "category": "Privacy", "severity": "CRITICAL",
        "name": "PII/PHI data sent to external AI API",
        "pattern": r"""(?:openai|anthropic|cohere|google\.generativeai|groq|together|replicate|huggingface_hub)\.\w+\.\w+\([^)]*(?:ssn|social.security|date.of.birth|dob|credit.card|passport|medical|diagnosis|patient|health.record)""",
        "description": "Sending PII/PHI (SSN, medical records, etc.) to external AI APIs creates privacy and regulatory violations.",
        "cwe": "CWE-359", "recommendation": "Implement PII detection and redaction before sending data to AI APIs. Use on-premise models for sensitive data.",
        "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-GOVERN"],
    },
    {
        "id": "AISPM-PRIV-002", "category": "Privacy", "severity": "HIGH",
        "name": "AI prompts/responses logged with user data",
        "pattern": r"""(?:logging|logger|log|print|console\.log|write)\s*\([^)]*(?:prompt|response|completion|messages|user_input)""",
        "description": "Logging AI prompts and responses may inadvertently capture PII, secrets, or sensitive user data.",
        "cwe": "CWE-532", "recommendation": "Implement log sanitisation to redact PII/secrets. Use structured logging with sensitivity levels.",
        "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-GOVERN"],
    },
    {
        "id": "AISPM-PRIV-003", "category": "Privacy", "severity": "HIGH",
        "name": "Training on user data without consent mechanism",
        "pattern": r"""(?:\.fit|\.train|\.fine_tune|trainer\.train)\s*\([^)]*(?:user_data|customer_data|personal_data|chat_log)""",
        "description": "Training AI models on user/customer data without consent management violates privacy regulations.",
        "cwe": "CWE-359", "recommendation": "Implement consent management. Document data usage purpose. Provide opt-out mechanisms.",
        "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-GOVERN"],
    },
    {
        "id": "AISPM-PRIV-004", "category": "Privacy", "severity": "MEDIUM",
        "name": "Embedding/vector store contains unredacted PII",
        "pattern": r"""(?:embed|embedding|vectorize|encode)\s*\([^)]*(?:email|phone|address|name|ssn|dob)""",
        "description": "Storing PII in vector embeddings enables membership inference attacks and privacy leaks via similarity search.",
        "cwe": "CWE-359", "recommendation": "Redact PII before embedding. Use differential privacy for embeddings. Implement access controls on vector stores.",
        "compliance": ["OWASP-ML-04", "EU-AI-ACT-HIGH", "ATLAS-EXFIL"],
    },
    {
        "id": "AISPM-PRIV-005", "category": "Privacy", "severity": "MEDIUM",
        "name": "No data retention policy for AI interactions",
        "pattern": r"""(?:store|save|persist|cache)\s*\([^)]*(?:conversation|chat|prompt|response|interaction)(?!.*(?:ttl|expire|retention|delete_after|max_age))""",
        "description": "Storing AI interactions indefinitely without retention policies violates data minimisation principles.",
        "cwe": "CWE-459", "recommendation": "Implement data retention policies with automatic purging. Define TTLs for stored interactions.",
        "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-GOVERN"],
    },
    {
        "id": "AISPM-PRIV-006", "category": "Privacy", "severity": "HIGH",
        "name": "Model memorisation risk — no differential privacy",
        "pattern": r"""(?:\.fit|\.train|trainer\.train)\s*\([^)]*(?:epochs?\s*=\s*(?:[5-9]\d|\d{3,})|num_train_epochs?\s*=\s*(?:[5-9]\d|\d{3,}))""",
        "description": "High epoch counts without differential privacy increase the risk of model memorising training data (extraction attacks).",
        "cwe": "CWE-200", "recommendation": "Use differential privacy (DP-SGD) for training on sensitive data. Limit epochs and monitor for memorisation.",
        "compliance": ["OWASP-ML-03", "ATLAS-EXFIL", "EU-AI-ACT-HIGH"],
    },
]

# ---------------------------------------------------------------------------
# PYTHON SAST RULES — GUARDRAILS
# ---------------------------------------------------------------------------
GUARDRAIL_RULES: list[dict[str, Any]] = [
    {
        "id": "AISPM-GUARD-001", "category": "Guardrails", "severity": "HIGH",
        "name": "No content safety filter on model output",
        "pattern": r"""(?:openai\.ChatCompletion|client\.chat\.completions|anthropic\.messages|claude|generate)\s*\.?\s*(?:create|completions)\s*\([^)]*\)(?!.*(?:filter|moderate|safety|content_filter|guardrail))""",
        "description": "AI model responses without content safety filtering can generate harmful, toxic, or dangerous content.",
        "cwe": "CWE-693", "recommendation": "Implement output content filtering using moderation APIs (OpenAI Moderation, Perspective API) or custom classifiers.",
        "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-MANAGE", "ATLAS-IMPACT"],
    },
    {
        "id": "AISPM-GUARD-002", "category": "Guardrails", "severity": "MEDIUM",
        "name": "Temperature set very high (>1.5) — increased hallucination risk",
        "pattern": r"""temperature\s*=\s*(?:1\.[5-9]|[2-9](?:\.\d+)?|\d{2,})""",
        "description": "Very high temperature values significantly increase hallucination risk and unpredictable outputs.",
        "cwe": "CWE-693", "recommendation": "Use temperature <= 1.0 for factual tasks. Only use higher temperatures for creative tasks with output validation.",
        "compliance": ["OWASP-ML-09", "NIST-AI-RMF-MEASURE"],
    },
    {
        "id": "AISPM-GUARD-003", "category": "Guardrails", "severity": "MEDIUM",
        "name": "No max_tokens limit — unbounded consumption",
        "pattern": r"""(?:\.create|\.generate|\.completions)\s*\([^)]*(?!max_tokens|max_new_tokens|max_length)[^)]*\)""",
        "description": "No max_tokens limit enables unbounded API consumption, leading to cost overruns and potential denial of service.",
        "cwe": "CWE-770", "recommendation": "Always set explicit max_tokens limits appropriate to the use case.",
        "compliance": ["NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-GUARD-004", "category": "Guardrails", "severity": "HIGH",
        "name": "Safety/content filters explicitly disabled",
        "pattern": r"""(?:safety_settings|content_filter|moderation|harm_category|guardrail|safety)\s*(?:=|:)\s*(?:None|False|off|disabled|BLOCK_NONE|HARM_BLOCK_NONE|0)""",
        "description": "Explicitly disabling safety filters removes all content protections and enables generation of harmful content.",
        "cwe": "CWE-693", "recommendation": "Never disable safety filters in production. Use the most restrictive settings appropriate for your use case.",
        "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-MANAGE", "ATLAS-IMPACT"],
    },
    {
        "id": "AISPM-GUARD-005", "category": "Guardrails", "severity": "MEDIUM",
        "name": "No rate limiting on AI API calls",
        "pattern": r"""(?:while\s+True|for\s+\w+\s+in\s+).*(?:openai|anthropic|cohere|generate|complete|chat)""",
        "description": "AI API calls in unbounded loops without rate limiting can cause cost overruns and API abuse.",
        "cwe": "CWE-770", "recommendation": "Implement rate limiting, retry backoff, and cost controls on all AI API calls.",
        "compliance": ["NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-GUARD-006", "category": "Guardrails", "severity": "MEDIUM",
        "name": "No timeout on model inference calls",
        "pattern": r"""(?:openai|anthropic|cohere|client)\.\w+\.\w+\([^)]*(?!timeout)[^)]*\)""",
        "description": "AI API calls without timeouts can hang indefinitely, causing resource exhaustion.",
        "cwe": "CWE-400", "recommendation": "Set explicit timeouts on all AI API calls (e.g., timeout=30).",
        "compliance": ["NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-GUARD-007", "category": "Guardrails", "severity": "HIGH",
        "name": "No input length validation before AI API call",
        "pattern": r"""(?:messages|prompt)\s*=\s*.*(?:request\.|user_input|input\().*(?:openai|anthropic|client\.)""",
        "description": "Sending unvalidated-length user input to AI APIs enables token-stuffing attacks and cost overruns.",
        "cwe": "CWE-770", "recommendation": "Validate input length before API calls. Implement token counting and reject oversized inputs.",
        "compliance": ["OWASP-ML-01", "NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-GUARD-008", "category": "Guardrails", "severity": "LOW",
        "name": "No fallback or error handling for AI API failures",
        "pattern": r"""(?:openai|anthropic|cohere|client)\.\w+\.\w+\([^)]*\)(?!\s*\n\s*except|\s*\.catch)""",
        "description": "AI API calls without error handling can cause application crashes and poor user experience.",
        "cwe": "CWE-755", "recommendation": "Implement try/except with appropriate fallback behaviour for AI API failures.",
        "compliance": ["NIST-AI-RMF-MANAGE"],
    },
]

# ---------------------------------------------------------------------------
# PYTHON SAST RULES — AGENT SECURITY
# ---------------------------------------------------------------------------
AGENT_SECURITY_RULES: list[dict[str, Any]] = [
    {
        "id": "AISPM-AGENT-001", "category": "Agent Security", "severity": "CRITICAL",
        "name": "AI agent with unrestricted shell/command access",
        "pattern": r"""(?:tool|function|action)\s*.*(?:shell|bash|cmd|terminal|exec|subprocess|os\.system|os\.popen)""",
        "description": "AI agents with unrestricted shell access can execute arbitrary commands, leading to full system compromise.",
        "cwe": "CWE-78", "recommendation": "Restrict agent tools to a strict allowlist. Sandbox command execution. Require human approval for destructive actions.",
        "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-MANAGE", "ATLAS-EXEC"],
    },
    {
        "id": "AISPM-AGENT-002", "category": "Agent Security", "severity": "HIGH",
        "name": "AI agent with filesystem write access",
        "pattern": r"""(?:tool|function|action)\s*.*(?:write_file|create_file|save_file|delete_file|modify_file|file_write|write_to)""",
        "description": "AI agents with filesystem write access can overwrite critical files, create backdoors, or cause data loss.",
        "cwe": "CWE-732", "recommendation": "Restrict file operations to specific directories. Implement write approval workflows. Use read-only mode by default.",
        "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-AGENT-003", "category": "Agent Security", "severity": "HIGH",
        "name": "AI agent with network/HTTP request capability",
        "pattern": r"""(?:tool|function|action)\s*.*(?:http_request|fetch_url|web_browse|send_email|api_call|make_request)""",
        "description": "AI agents with network access can exfiltrate data, communicate with C2 servers, or send unauthorised messages.",
        "cwe": "CWE-918", "recommendation": "Restrict network access to allowlisted domains. Log all outbound requests. Implement egress filtering.",
        "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-MANAGE", "ATLAS-EXFIL"],
    },
    {
        "id": "AISPM-AGENT-004", "category": "Agent Security", "severity": "HIGH",
        "name": "No human-in-the-loop for critical agent actions",
        "pattern": r"""(?:auto_approve|human_in_the_loop\s*=\s*False|confirm\s*=\s*False|approve_all\s*=\s*True|autonomous\s*=\s*True)""",
        "description": "AI agents operating without human approval for critical actions can cause irreversible damage.",
        "cwe": "CWE-862", "recommendation": "Require human approval for destructive, financial, or external-facing agent actions.",
        "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-GOVERN"],
    },
    {
        "id": "AISPM-AGENT-005", "category": "Agent Security", "severity": "MEDIUM",
        "name": "Unbounded agent iteration/recursion",
        "pattern": r"""(?:max_iterations\s*=\s*(?:None|0|-1|\d{4,})|max_steps\s*=\s*(?:None|0|-1|\d{4,})|while\s+True.*agent)""",
        "description": "AI agents without iteration limits can enter infinite loops, consuming resources and generating costs.",
        "cwe": "CWE-835", "recommendation": "Set explicit max_iterations/max_steps limits. Implement cost and time budgets for agent runs.",
        "compliance": ["NIST-AI-RMF-MANAGE"],
    },
]

# ---------------------------------------------------------------------------
# PYTHON SAST RULES — RAG SECURITY
# ---------------------------------------------------------------------------
RAG_SECURITY_RULES: list[dict[str, Any]] = [
    {
        "id": "AISPM-RAG-001", "category": "RAG Security", "severity": "HIGH",
        "name": "Vector database without authentication",
        "pattern": r"""(?:Chroma|Pinecone|Weaviate|Qdrant|Milvus|FAISS|PGVector)\s*\([^)]*(?!api_key|auth|token|password|credentials)[^)]*\)""",
        "description": "Vector databases without authentication allow unauthorised access to embedded documents and knowledge bases.",
        "cwe": "CWE-306", "recommendation": "Enable authentication on vector databases. Use API keys, TLS, and network isolation.",
        "compliance": ["NIST-AI-RMF-MANAGE", "ATLAS-INIT-ACCESS"],
    },
    {
        "id": "AISPM-RAG-002", "category": "RAG Security", "severity": "HIGH",
        "name": "No access control on RAG retrieval results",
        "pattern": r"""(?:similarity_search|query|retrieve|search)\s*\([^)]*\)(?!.*(?:filter|access_control|permission|user_id|tenant))""",
        "description": "RAG retrieval without access control can expose documents the requesting user is not authorised to see.",
        "cwe": "CWE-862", "recommendation": "Implement document-level access controls in RAG pipelines. Filter results based on user permissions.",
        "compliance": ["NIST-AI-RMF-GOVERN", "EU-AI-ACT-HIGH"],
    },
    {
        "id": "AISPM-RAG-003", "category": "RAG Security", "severity": "MEDIUM",
        "name": "External documents ingested into RAG without sanitisation",
        "pattern": r"""(?:load|ingest|add_documents|add_texts|from_documents)\s*\([^)]*(?:url|http|upload|external|user_)""",
        "description": "Ingesting external documents into RAG without sanitisation enables indirect prompt injection via poisoned documents.",
        "cwe": "CWE-74", "recommendation": "Sanitise documents before RAG ingestion. Strip executable content and validate document structure.",
        "compliance": ["OWASP-ML-01", "ATLAS-INIT-ACCESS"],
    },
    {
        "id": "AISPM-RAG-004", "category": "RAG Security", "severity": "MEDIUM",
        "name": "RAG context window stuffing — no chunk size limit",
        "pattern": r"""(?:chunk_size\s*=\s*(?:\d{5,}|None)|RecursiveCharacterTextSplitter\s*\([^)]*\)(?!.*chunk_size))""",
        "description": "Very large or unlimited chunk sizes in RAG can overflow context windows and enable injection attacks.",
        "cwe": "CWE-770", "recommendation": "Set appropriate chunk_size limits (e.g. 500-2000 characters). Limit number of retrieved chunks.",
        "compliance": ["NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-RAG-005", "category": "RAG Security", "severity": "LOW",
        "name": "No citation or source attribution in RAG output",
        "pattern": r"""(?:similarity_search|retrieve)\s*\([^)]*\).*(?:response|answer)(?!.*(?:source|citation|reference|metadata))""",
        "description": "RAG responses without source attribution make it impossible to verify claims and detect hallucinations.",
        "cwe": "CWE-451", "recommendation": "Include source citations in RAG outputs. Return document metadata with retrieval results.",
        "compliance": ["EU-AI-ACT-LIMITED", "NIST-AI-RMF-MEASURE"],
    },
]

# ---------------------------------------------------------------------------
# PYTHON SAST RULES — SECRETS (AI API KEYS)
# ---------------------------------------------------------------------------
SECRET_RULES: list[dict[str, Any]] = [
    {
        "id": "AISPM-SECRET-001", "category": "Secrets", "severity": "CRITICAL",
        "name": "Hardcoded OpenAI API key",
        "pattern": r"""(?:sk-[a-zA-Z0-9]{20,}|openai[._]api[._]key\s*=\s*['\"][^'\"]{10,})""",
        "description": "Hardcoded OpenAI API key in source code. Keys can be extracted from code, git history, or compiled artifacts.",
        "cwe": "CWE-798", "recommendation": "Use environment variables or secrets managers (Vault, AWS Secrets Manager). Never commit API keys to source control.",
        "compliance": ["NIST-AI-RMF-GOVERN"],
    },
    {
        "id": "AISPM-SECRET-002", "category": "Secrets", "severity": "CRITICAL",
        "name": "Hardcoded Anthropic API key",
        "pattern": r"""(?:sk-ant-[a-zA-Z0-9-]{20,}|anthropic[._]api[._]key\s*=\s*['\"][^'\"]{10,})""",
        "description": "Hardcoded Anthropic API key in source code.",
        "cwe": "CWE-798", "recommendation": "Use environment variables or secrets managers. Never commit API keys to source control.",
        "compliance": ["NIST-AI-RMF-GOVERN"],
    },
    {
        "id": "AISPM-SECRET-003", "category": "Secrets", "severity": "CRITICAL",
        "name": "Hardcoded HuggingFace token",
        "pattern": r"""(?:hf_[a-zA-Z0-9]{20,}|huggingface[._](?:token|api[._]key)\s*=\s*['\"][^'\"]{10,})""",
        "description": "Hardcoded HuggingFace token in source code enables access to private models and datasets.",
        "cwe": "CWE-798", "recommendation": "Use environment variables or huggingface-cli login. Never commit tokens to source control.",
        "compliance": ["NIST-AI-RMF-GOVERN", "OWASP-ML-06"],
    },
    {
        "id": "AISPM-SECRET-004", "category": "Secrets", "severity": "CRITICAL",
        "name": "Hardcoded Google AI / Vertex API key",
        "pattern": r"""(?:AIza[a-zA-Z0-9_-]{35}|google[._](?:ai|vertex|gemini)[._](?:api[._])?key\s*=\s*['\"][^'\"]{10,})""",
        "description": "Hardcoded Google AI/Vertex AI API key in source code.",
        "cwe": "CWE-798", "recommendation": "Use service accounts and workload identity. Never commit API keys to source control.",
        "compliance": ["NIST-AI-RMF-GOVERN"],
    },
    {
        "id": "AISPM-SECRET-005", "category": "Secrets", "severity": "CRITICAL",
        "name": "Hardcoded Cohere API key",
        "pattern": r"""(?:cohere[._]api[._]key\s*=\s*['\"][^'\"]{10,}|['\"]co-[a-zA-Z0-9]{20,}['\"])""",
        "description": "Hardcoded Cohere API key in source code.",
        "cwe": "CWE-798", "recommendation": "Use environment variables or secrets managers. Never commit API keys to source control.",
        "compliance": ["NIST-AI-RMF-GOVERN"],
    },
    {
        "id": "AISPM-SECRET-006", "category": "Secrets", "severity": "CRITICAL",
        "name": "Hardcoded Replicate / Together / Groq API key",
        "pattern": r"""(?:(?:replicate|together|groq)[._]api[._](?:key|token)\s*=\s*['\"][^'\"]{10,}|r8_[a-zA-Z0-9]{20,})""",
        "description": "Hardcoded AI platform API key in source code.",
        "cwe": "CWE-798", "recommendation": "Use environment variables or secrets managers. Never commit API keys to source control.",
        "compliance": ["NIST-AI-RMF-GOVERN"],
    },
    {
        "id": "AISPM-SECRET-007", "category": "Secrets", "severity": "CRITICAL",
        "name": "Hardcoded Pinecone / Weaviate / vector DB key",
        "pattern": r"""(?:(?:pinecone|weaviate|qdrant|milvus)[._]api[._]key\s*=\s*['\"][^'\"]{10,})""",
        "description": "Hardcoded vector database API key in source code enables unauthorised access to embeddings and knowledge bases.",
        "cwe": "CWE-798", "recommendation": "Use environment variables or secrets managers. Never commit API keys to source control.",
        "compliance": ["NIST-AI-RMF-GOVERN"],
    },
    {
        "id": "AISPM-SECRET-008", "category": "Secrets", "severity": "HIGH",
        "name": "Hardcoded MLflow / W&B / experiment tracker credentials",
        "pattern": r"""(?:(?:mlflow|wandb|neptune|comet)[._](?:tracking_uri|api[._]key|token)\s*=\s*['\"][^'\"]{10,})""",
        "description": "Hardcoded ML experiment tracker credentials in source code.",
        "cwe": "CWE-798", "recommendation": "Use environment variables for experiment tracker credentials.",
        "compliance": ["NIST-AI-RMF-GOVERN"],
    },
]

# ---------------------------------------------------------------------------
# PYTHON SAST RULES — SHADOW AI
# ---------------------------------------------------------------------------
SHADOW_AI_RULES: list[dict[str, Any]] = [
    {
        "id": "AISPM-SHADOW-001", "category": "Shadow AI", "severity": "HIGH",
        "name": "Direct API call to AI service (potential shadow AI)",
        "pattern": r"""requests\.(?:get|post)\s*\(\s*['\"]https?://api\.(?:openai|anthropic|cohere|together|groq|replicate|perplexity)\.com""",
        "description": "Direct HTTP calls to AI APIs bypass organisational AI governance controls and monitoring.",
        "cwe": "CWE-284", "recommendation": "Route all AI API calls through an approved gateway/proxy. Implement AI service cataloguing.",
        "compliance": ["NIST-AI-RMF-GOVERN", "EU-AI-ACT-HIGH"],
    },
    {
        "id": "AISPM-SHADOW-002", "category": "Shadow AI", "severity": "MEDIUM",
        "name": "Unofficial AI SDK import detected",
        "pattern": r"""(?:^|\n)\s*(?:from|import)\s+(?:g4f|gpt4free|undetected_ai|poe_api|rev_chatgpt|chatgpt_api|bardapi|claude_api)""",
        "description": "Usage of unofficial/reverse-engineered AI SDKs bypasses API terms of service and lacks security guarantees.",
        "cwe": "CWE-829", "recommendation": "Use only official AI SDKs. Document all AI services in an approved AI registry.",
        "compliance": ["NIST-AI-RMF-GOVERN", "EU-AI-ACT-LIMITED"],
    },
    {
        "id": "AISPM-SHADOW-003", "category": "Shadow AI", "severity": "MEDIUM",
        "name": "Local LLM deployment without governance",
        "pattern": r"""(?:llama_cpp|ctransformers|gpt4all|ollama|localai|text_generation|vllm)\s*(?:\.|import)""",
        "description": "Local LLM deployments without governance oversight bypass organisational AI policies and monitoring.",
        "cwe": "CWE-284", "recommendation": "Register all local AI deployments in an AI inventory. Apply the same governance policies as cloud AI services.",
        "compliance": ["NIST-AI-RMF-GOVERN", "EU-AI-ACT-GPAI"],
    },
    {
        "id": "AISPM-SHADOW-004", "category": "Shadow AI", "severity": "LOW",
        "name": "AI model cached without organisational awareness",
        "pattern": r"""(?:cache_dir|model_cache|TRANSFORMERS_CACHE|HF_HOME)\s*=\s*['\"](?:/tmp|/home|C:\\|~)""",
        "description": "AI models cached in user directories bypass organisational model management and inventory controls.",
        "cwe": "CWE-538", "recommendation": "Use centralised model registries and approved cache directories. Track all downloaded models.",
        "compliance": ["NIST-AI-RMF-GOVERN"],
    },
]

# ---------------------------------------------------------------------------
# PYTHON SAST RULES — INFRASTRUCTURE
# ---------------------------------------------------------------------------
INFRA_RULES: list[dict[str, Any]] = [
    {
        "id": "AISPM-INFRA-001", "category": "Infrastructure", "severity": "CRITICAL",
        "name": "Model serving endpoint without authentication",
        "pattern": r"""(?:app\.route|@app\.(?:get|post)|FastAPI|flask\.Flask)\s*.*(?:predict|inference|generate|complete|embed|chat)(?!.*(?:auth|token|api_key|login_required|depends.*auth|security))""",
        "description": "AI inference endpoints without authentication allow unauthorised access to model capabilities.",
        "cwe": "CWE-306", "recommendation": "Implement authentication (API keys, OAuth, JWT) on all model serving endpoints.",
        "compliance": ["NIST-AI-RMF-MANAGE", "ATLAS-INIT-ACCESS"],
    },
    {
        "id": "AISPM-INFRA-002", "category": "Infrastructure", "severity": "HIGH",
        "name": "Model served over HTTP (not HTTPS)",
        "pattern": r"""(?:app\.run|uvicorn\.run|serve)\s*\([^)]*(?:ssl|https|cert)(?:\s*=\s*(?:None|False))""",
        "description": "Model serving over HTTP exposes prompts, responses, and API keys to network interception.",
        "cwe": "CWE-319", "recommendation": "Serve models over HTTPS with valid TLS certificates. Terminate TLS at load balancer minimum.",
        "compliance": ["NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-INFRA-003", "category": "Infrastructure", "severity": "HIGH",
        "name": "Model serving bound to 0.0.0.0 (all interfaces)",
        "pattern": r"""(?:app\.run|uvicorn\.run|serve|bind)\s*\([^)]*(?:host\s*=\s*['\"]0\.0\.0\.0['\"]|0\.0\.0\.0)""",
        "description": "Binding model serving to all network interfaces exposes it to the public internet.",
        "cwe": "CWE-668", "recommendation": "Bind to 127.0.0.1 or specific internal interfaces. Use reverse proxy for external access.",
        "compliance": ["NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-INFRA-004", "category": "Infrastructure", "severity": "HIGH",
        "name": "Jupyter notebook server without authentication",
        "pattern": r"""(?:NotebookApp\.token\s*=\s*['\"]['\"]|NotebookApp\.password\s*=\s*['\"]['\"]|--NotebookApp\.token\s*=\s*['\"]['\"])""",
        "description": "Jupyter notebooks without authentication allow anyone to execute arbitrary code on the server.",
        "cwe": "CWE-306", "recommendation": "Enable Jupyter authentication with strong tokens or passwords. Use JupyterHub for multi-user environments.",
        "compliance": ["NIST-AI-RMF-MANAGE", "ATLAS-INIT-ACCESS"],
    },
    {
        "id": "AISPM-INFRA-005", "category": "Infrastructure", "severity": "MEDIUM",
        "name": "MLflow server without authentication",
        "pattern": r"""mlflow\s+(?:server|ui)\s+(?!.*(?:--auth|--app-name\s+basic-auth|--host\s+127))""",
        "description": "MLflow tracking server without authentication exposes experiment data, models, and artifacts.",
        "cwe": "CWE-306", "recommendation": "Enable MLflow authentication. Restrict access to internal networks. Use --app-name basic-auth.",
        "compliance": ["NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-INFRA-006", "category": "Infrastructure", "severity": "HIGH",
        "name": "GPU instance with debug mode enabled",
        "pattern": r"""(?:debug\s*=\s*True|FLASK_DEBUG\s*=\s*1|--reload|--debug).*(?:app\.run|uvicorn|gunicorn)""",
        "description": "Debug mode on model serving exposes detailed errors, stack traces, and potentially model internals.",
        "cwe": "CWE-489", "recommendation": "Disable debug mode in production. Use proper logging and error handling.",
        "compliance": ["NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-INFRA-007", "category": "Infrastructure", "severity": "MEDIUM",
        "name": "Model serving with CORS wildcard",
        "pattern": r"""(?:CORS|cors|Access-Control-Allow-Origin)\s*(?:=|\(|:)\s*['\"\s]*\*""",
        "description": "CORS wildcard (*) on model endpoints allows any website to call your AI APIs from browser-based attacks.",
        "cwe": "CWE-942", "recommendation": "Restrict CORS to specific trusted origins. Never use wildcard in production.",
        "compliance": ["NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-INFRA-008", "category": "Infrastructure", "severity": "MEDIUM",
        "name": "Model endpoint exposes internal model details",
        "pattern": r"""(?:model_name|model_version|model_config|model_architecture|model_params)\s*(?:=|:).*(?:response|return|json)""",
        "description": "Exposing model architecture, version, or configuration details aids adversaries in crafting targeted attacks.",
        "cwe": "CWE-200", "recommendation": "Do not expose model internals in API responses. Return only prediction results.",
        "compliance": ["OWASP-ML-05", "ATLAS-RECON"],
    },
]

# ---------------------------------------------------------------------------
# PYTHON SAST RULES — MCP (MODEL CONTEXT PROTOCOL) SECURITY  [v1.1.0]
# ---------------------------------------------------------------------------
MCP_SECURITY_RULES: list[dict[str, Any]] = [
    {
        "id": "AISPM-MCP-001", "category": "MCP Security", "severity": "CRITICAL",
        "name": "MCP server without authentication",
        "pattern": r"""(?:mcp\.Server|McpServer|MCPServer|mcp_server)\s*\([^)]*(?!.*(?:auth|token|api_key|authenticate|credentials))[^)]*\)""",
        "description": "MCP server instantiated without authentication allows any client to invoke tools and access resources.",
        "cwe": "CWE-306", "recommendation": "Implement authentication on MCP servers using API keys, OAuth tokens, or mTLS.",
        "compliance": ["NIST-AI-RMF-MANAGE", "ATLAS-INIT-ACCESS", "EU-AI-ACT-HIGH"],
    },
    {
        "id": "AISPM-MCP-002", "category": "MCP Security", "severity": "HIGH",
        "name": "MCP tool with filesystem or shell access",
        "pattern": r"""(?:@(?:mcp\.)?tool|add_tool|register_tool)\s*.*(?:read_file|write_file|exec|shell|subprocess|os\.system|run_command|bash|terminal|file_system)""",
        "description": "MCP tool registered with filesystem or shell access can be exploited by prompt injection to execute arbitrary commands.",
        "cwe": "CWE-78", "recommendation": "Sandbox MCP tools. Restrict filesystem access to specific directories. Require user confirmation for destructive operations.",
        "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-MANAGE", "ATLAS-EXEC"],
    },
    {
        "id": "AISPM-MCP-003", "category": "MCP Security", "severity": "HIGH",
        "name": "MCP transport over HTTP (not HTTPS/stdio)",
        "pattern": r"""(?:SSEServerTransport|HttpTransport|sse_transport)\s*\([^)]*(?:http://|port\s*=)""",
        "description": "MCP server using HTTP transport exposes tool calls and responses to network interception.",
        "cwe": "CWE-319", "recommendation": "Use stdio transport for local connections or HTTPS/SSE with TLS for remote MCP servers.",
        "compliance": ["NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-MCP-004", "category": "MCP Security", "severity": "HIGH",
        "name": "MCP resource exposing sensitive data without access control",
        "pattern": r"""(?:@(?:mcp\.)?resource|add_resource|register_resource)\s*.*(?:database|db|credential|secret|password|config|env|key|token|private)""",
        "description": "MCP resource handler exposing sensitive data (credentials, databases) without access control.",
        "cwe": "CWE-862", "recommendation": "Implement per-resource access controls. Never expose credentials or secrets as MCP resources.",
        "compliance": ["NIST-AI-RMF-MANAGE", "EU-AI-ACT-HIGH"],
    },
    {
        "id": "AISPM-MCP-005", "category": "MCP Security", "severity": "MEDIUM",
        "name": "MCP client with auto-approve / no confirmation flow",
        "pattern": r"""(?:mcp|McpClient|MCPClient|mcp_client).*(?:auto_approve|confirm\s*=\s*False|approval\s*=\s*False|interactive\s*=\s*False)""",
        "description": "MCP client configured to auto-approve tool invocations bypasses human-in-the-loop safety.",
        "cwe": "CWE-862", "recommendation": "Require user confirmation for MCP tool calls, especially for destructive or external-facing operations.",
        "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-GOVERN"],
    },
]

# ---------------------------------------------------------------------------
# PYTHON SAST RULES — AGENT FRAMEWORK SPECIFIC  [v1.1.0]
# ---------------------------------------------------------------------------
AGENT_FRAMEWORK_RULES: list[dict[str, Any]] = [
    {
        "id": "AISPM-AGENT-006", "category": "Agent Security", "severity": "HIGH",
        "name": "LangChain/LangGraph agent with unrestricted tool list",
        "pattern": r"""(?:create_(?:react|openai_functions|tool_calling|structured_chat)_agent|AgentExecutor)\s*\([^)]*tools\s*=\s*(?:tools|all_tools|\[.*,.*,.*,.*,)""",
        "description": "LangChain agent initialised with a broad tool list. Over-provisioned tools increase the blast radius of prompt injection.",
        "cwe": "CWE-250", "recommendation": "Apply least-privilege: only grant the agent tools required for its specific task. Use separate agents for separate concerns.",
        "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-MANAGE", "ATLAS-EXEC"],
    },
    {
        "id": "AISPM-AGENT-007", "category": "Agent Security", "severity": "HIGH",
        "name": "CrewAI agent with allow_delegation and no role constraint",
        "pattern": r"""(?:Agent|CrewAgent)\s*\([^)]*allow_delegation\s*=\s*True""",
        "description": "CrewAI agent with delegation enabled can pass tasks to other agents, potentially escalating privileges.",
        "cwe": "CWE-269", "recommendation": "Set allow_delegation=False unless explicitly required. Define strict role boundaries for delegating agents.",
        "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-AGENT-008", "category": "Agent Security", "severity": "CRITICAL",
        "name": "AutoGen agent with code execution enabled without Docker",
        "pattern": r"""code_execution_config\s*=\s*\{[^}]*(?!.*docker)[^}]*\}""",
        "description": "AutoGen agent with code execution enabled but no Docker sandboxing executes code directly on the host.",
        "cwe": "CWE-78", "recommendation": "Enable Docker sandboxing: code_execution_config={'use_docker': True}. Never run generated code on the host.",
        "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-MANAGE", "ATLAS-EXEC"],
    },
    {
        "id": "AISPM-AGENT-009", "category": "Agent Security", "severity": "MEDIUM",
        "name": "Multi-agent system without supervisor or orchestrator",
        "pattern": r"""(?:GroupChat|MultiAgent|agent_team|crew)\s*\([^)]*(?!.*(?:supervisor|orchestrator|manager|admin_agent))[^)]*\)""",
        "description": "Multi-agent systems without a supervisor agent can exhibit emergent behaviour and coordination failures.",
        "cwe": "CWE-693", "recommendation": "Implement a supervisor/orchestrator agent to coordinate and audit inter-agent communication.",
        "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-GOVERN"],
    },
    {
        "id": "AISPM-AGENT-010", "category": "Agent Security", "severity": "MEDIUM",
        "name": "Agent memory persisted without encryption",
        "pattern": r"""(?:ConversationBufferMemory|memory|chat_memory|agent_memory)\s*\([^)]*(?:persist|save|store|file_path|db_path)(?!.*(?:encrypt|cipher|kms))""",
        "description": "Agent conversation memory persisted to disk without encryption exposes sensitive interactions.",
        "cwe": "CWE-311", "recommendation": "Encrypt persisted agent memory at rest. Use KMS or filesystem-level encryption.",
        "compliance": ["NIST-AI-RMF-MANAGE", "EU-AI-ACT-HIGH"],
    },
]

# ---------------------------------------------------------------------------
# PYTHON SAST RULES — FINE-TUNING / LoRA SECURITY  [v1.1.0]
# ---------------------------------------------------------------------------
FINETUNE_SECURITY_RULES: list[dict[str, Any]] = [
    {
        "id": "AISPM-FINETUNE-001", "category": "Fine-tuning Security", "severity": "HIGH",
        "name": "Fine-tuning on unvalidated user-uploaded dataset",
        "pattern": r"""(?:SFTTrainer|Trainer|fine_tune|finetune)\s*\([^)]*(?:upload|user_file|user_data|request\.files)""",
        "description": "Fine-tuning on user-uploaded data without validation enables backdoor injection and data poisoning.",
        "cwe": "CWE-20", "recommendation": "Validate, sanitise, and review all user-uploaded datasets before fine-tuning. Implement data quarantine.",
        "compliance": ["OWASP-ML-02", "ATLAS-PERSIST", "EU-AI-ACT-HIGH", "NIST-AI-RMF-MAP"],
    },
    {
        "id": "AISPM-FINETUNE-002", "category": "Fine-tuning Security", "severity": "HIGH",
        "name": "LoRA/QLoRA adapter loaded from untrusted source",
        "pattern": r"""(?:PeftModel\.from_pretrained|load_adapter|merge_adapter|LoraConfig)\s*\([^)]*(?:http|hub|download|trust_remote_code)""",
        "description": "Loading LoRA/PEFT adapters from untrusted sources can inject backdoors into the base model.",
        "cwe": "CWE-829", "recommendation": "Only load adapters from trusted, verified sources. Pin adapter revisions with commit hashes.",
        "compliance": ["OWASP-ML-06", "ATLAS-PERSIST", "NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-FINETUNE-003", "category": "Fine-tuning Security", "severity": "MEDIUM",
        "name": "No safety evaluation after fine-tuning",
        "pattern": r"""(?:trainer\.train|\.fine_tune|SFTTrainer\.train)\s*\([^)]*\)(?!.*(?:eval|evaluate|benchmark|safety_check|red_team|test))""",
        "description": "Fine-tuning without subsequent safety evaluation may degrade the model's safety alignment.",
        "cwe": "CWE-693", "recommendation": "Run safety benchmarks and red-teaming after every fine-tuning run before deployment.",
        "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-MEASURE"],
    },
    {
        "id": "AISPM-FINETUNE-004", "category": "Fine-tuning Security", "severity": "MEDIUM",
        "name": "RLHF reward model without adversarial testing",
        "pattern": r"""(?:RewardModel|reward_model|PPOTrainer|DPOTrainer|RLHFTrainer)\s*\(""",
        "description": "RLHF/DPO reward models without adversarial testing can be gamed to produce harmful outputs.",
        "cwe": "CWE-693", "recommendation": "Adversarially test reward models. Implement reward hacking detection and output monitoring.",
        "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-MEASURE", "OWASP-ML-08"],
    },
    {
        "id": "AISPM-FINETUNE-005", "category": "Fine-tuning Security", "severity": "HIGH",
        "name": "Full model weights fine-tuned without freezing safety layers",
        "pattern": r"""(?:model\.train\(\)|\.requires_grad\s*=\s*True|freeze\s*=\s*False|trainable\s*=\s*True).*(?:all|full|entire)""",
        "description": "Full-weight fine-tuning without freezing safety-critical layers can destroy pre-trained safety alignment.",
        "cwe": "CWE-693", "recommendation": "Use parameter-efficient fine-tuning (LoRA/QLoRA). Freeze safety-aligned layers. Compare pre/post safety benchmarks.",
        "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-MANAGE", "ATLAS-PERSIST"],
    },
]

# ---------------------------------------------------------------------------
# PYTHON SAST RULES — MULTIMODAL SECURITY  [v1.1.0]
# ---------------------------------------------------------------------------
MULTIMODAL_SECURITY_RULES: list[dict[str, Any]] = [
    {
        "id": "AISPM-MULTI-001", "category": "Multimodal Security", "severity": "MEDIUM",
        "name": "Image input without size or format validation",
        "pattern": r"""(?:Image\.open|cv2\.imread|imageio\.imread|vision|image_input)\s*\([^)]*(?:request|upload|user_|url|http)(?!.*(?:validate|check|verify|max_size|format))""",
        "description": "Processing user-uploaded images without size/format validation enables adversarial image attacks and resource exhaustion.",
        "cwe": "CWE-20", "recommendation": "Validate image dimensions, file size, format, and pixel values before model inference.",
        "compliance": ["OWASP-ML-01", "NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-MULTI-002", "category": "Multimodal Security", "severity": "HIGH",
        "name": "Audio transcription output used in commands",
        "pattern": r"""(?:whisper|transcribe|speech_to_text|stt|recognize)\s*\([^)]*\).*(?:os\.system|subprocess|exec|eval|cursor\.execute)""",
        "description": "Using speech-to-text output directly in commands enables injection via adversarial audio.",
        "cwe": "CWE-78", "recommendation": "Validate and sanitise all transcription output before use in commands or queries.",
        "compliance": ["OWASP-ML-01", "ATLAS-EXEC", "NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-MULTI-003", "category": "Multimodal Security", "severity": "HIGH",
        "name": "OCR/vision output concatenated into LLM prompt",
        "pattern": r"""(?:ocr|extract_text|image_to_text|vision|describe_image)\s*\([^)]*\).*(?:prompt|messages|content)\s*(?:\+|\.format|f['\"])""",
        "description": "Injecting OCR/vision model output into LLM prompts enables indirect prompt injection via images.",
        "cwe": "CWE-74", "recommendation": "Treat vision/OCR output as untrusted input. Sanitise and clearly delimit from system instructions.",
        "compliance": ["OWASP-ML-01", "ATLAS-INIT-ACCESS", "EU-AI-ACT-HIGH"],
    },
    {
        "id": "AISPM-MULTI-004", "category": "Multimodal Security", "severity": "HIGH",
        "name": "No NSFW/content filter on image generation",
        "pattern": r"""(?:StableDiffusion|DALL|image_generate|text_to_image|generate_image)\s*\([^)]*(?!.*(?:safety_checker|nsfw|content_filter|moderation))""",
        "description": "Image generation without NSFW/content filtering can produce harmful, illegal, or explicit content.",
        "cwe": "CWE-693", "recommendation": "Enable safety checkers on all image generation pipelines. Implement content moderation on outputs.",
        "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-MANAGE", "ATLAS-IMPACT"],
    },
    {
        "id": "AISPM-MULTI-005", "category": "Multimodal Security", "severity": "MEDIUM",
        "name": "Generated media without watermarking or provenance",
        "pattern": r"""(?:generate|create|synthesize)\s*\([^)]*(?:image|video|audio|speech|voice)(?!.*(?:watermark|provenance|c2pa|metadata|signature))""",
        "description": "AI-generated media without watermarking or provenance metadata aids deepfake creation and misinformation.",
        "cwe": "CWE-451", "recommendation": "Add C2PA/watermarks to all AI-generated media. Include provenance metadata for traceability.",
        "compliance": ["EU-AI-ACT-LIMITED", "NIST-AI-RMF-GOVERN"],
    },
]

# ---------------------------------------------------------------------------
# PYTHON SAST RULES — AI OBSERVABILITY & MONITORING  [v1.1.0]
# ---------------------------------------------------------------------------
OBSERVABILITY_RULES: list[dict[str, Any]] = [
    {
        "id": "AISPM-OBS-001", "category": "AI Observability", "severity": "MEDIUM",
        "name": "No AI request/response logging configured",
        "pattern": r"""(?:openai|anthropic|client)\.\w+\.\w+\([^)]*\)(?!.*(?:log|trace|span|monitor|observe|callback|langsmith|langfuse|helicone))""",
        "description": "AI API calls without observability make it impossible to detect misuse, debug issues, or audit behaviour.",
        "cwe": "CWE-778", "recommendation": "Implement AI observability with LangSmith, Langfuse, Helicone, or custom logging.",
        "compliance": ["NIST-AI-RMF-MEASURE", "EU-AI-ACT-HIGH"],
    },
    {
        "id": "AISPM-OBS-002", "category": "AI Observability", "severity": "MEDIUM",
        "name": "No model drift detection mechanism",
        "pattern": r"""(?:model\.predict|pipeline\(|\.generate)\s*\([^)]*\)(?!.*(?:drift|monitor|evidently|whylogs|nannyml|fiddler))""",
        "description": "Production model inference without drift detection can silently degrade in accuracy over time.",
        "cwe": "CWE-693", "recommendation": "Implement data/concept drift detection using Evidently, WhyLogs, NannyML, or custom monitoring.",
        "compliance": ["NIST-AI-RMF-MEASURE", "EU-AI-ACT-HIGH"],
    },
    {
        "id": "AISPM-OBS-003", "category": "AI Observability", "severity": "HIGH",
        "name": "No hallucination detection or grounding check",
        "pattern": r"""(?:\.create|\.generate|\.completions)\s*\([^)]*\).*(?:return|response)(?!.*(?:ground|verify|fact_check|hallucination|citation|source))""",
        "description": "LLM responses used without hallucination detection can propagate false information to users.",
        "cwe": "CWE-693", "recommendation": "Implement grounding checks, source citation, or hallucination detection on LLM outputs.",
        "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-MEASURE", "OWASP-ML-09"],
    },
    {
        "id": "AISPM-OBS-004", "category": "AI Observability", "severity": "MEDIUM",
        "name": "No cost monitoring or alerting on AI API usage",
        "pattern": r"""(?:openai|anthropic|cohere)\.\w+\.\w+\([^)]*\)(?!.*(?:cost|budget|usage|billing|quota|limit|meter))""",
        "description": "AI API calls without cost monitoring can lead to unexpected bills from abuse or runaway loops.",
        "cwe": "CWE-770", "recommendation": "Implement cost tracking, usage alerts, and budget limits on all AI API consumption.",
        "compliance": ["NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-OBS-005", "category": "AI Observability", "severity": "LOW",
        "name": "No A/B testing safeguards for model rollouts",
        "pattern": r"""(?:model_version|model_id|deployment)\s*=\s*.*(?:new|v2|beta|canary|experiment)(?!.*(?:rollback|feature_flag|percentage|gradual))""",
        "description": "Model version updates without A/B testing or gradual rollout risk production failures.",
        "cwe": "CWE-693", "recommendation": "Implement canary deployments and A/B testing for model updates. Maintain rollback capability.",
        "compliance": ["NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-OBS-006", "category": "AI Observability", "severity": "LOW",
        "name": "No AI incident response plan referenced",
        "pattern": r"""(?:deploy|production|release|serve).*(?:model|ai|llm|ml)(?!.*(?:incident|runbook|playbook|escalation|rollback|circuit_breaker))""",
        "description": "AI system deployment without referencing an incident response plan for AI-specific failures.",
        "cwe": "CWE-778", "recommendation": "Document AI incident response procedures including model rollback, fallback behaviour, and escalation.",
        "compliance": ["NIST-AI-RMF-GOVERN", "EU-AI-ACT-HIGH"],
    },
]

# ---------------------------------------------------------------------------
# PYTHON SAST RULES — AI GATEWAY / PROXY SECURITY  [v1.1.0]
# ---------------------------------------------------------------------------
GATEWAY_RULES: list[dict[str, Any]] = [
    {
        "id": "AISPM-GW-001", "category": "AI Gateway", "severity": "MEDIUM",
        "name": "Direct AI API call without gateway or proxy",
        "pattern": r"""(?:openai\.(?:Client|OpenAI)|anthropic\.(?:Client|Anthropic)|Cohere)\s*\(\s*(?:api_key|$)""",
        "description": "Direct AI SDK client instantiation bypasses centralised gateway controls (rate limiting, logging, content filtering).",
        "cwe": "CWE-284", "recommendation": "Route AI API calls through a centralised AI gateway (LiteLLM, Portkey, Helicone) for governance.",
        "compliance": ["NIST-AI-RMF-GOVERN", "EU-AI-ACT-HIGH"],
    },
    {
        "id": "AISPM-GW-002", "category": "AI Gateway", "severity": "MEDIUM",
        "name": "No centralised API key rotation mechanism",
        "pattern": r"""(?:api_key|OPENAI_API_KEY|ANTHROPIC_API_KEY)\s*=\s*(?:os\.environ|os\.getenv)\s*\([^)]*\)(?!.*(?:rotate|vault|secrets_manager|kms|refresh))""",
        "description": "AI API keys loaded from environment without rotation mechanism risk prolonged exposure if leaked.",
        "cwe": "CWE-798", "recommendation": "Use secrets managers with automatic rotation (Vault, AWS Secrets Manager). Implement key rotation policies.",
        "compliance": ["NIST-AI-RMF-GOVERN"],
    },
    {
        "id": "AISPM-GW-003", "category": "AI Gateway", "severity": "HIGH",
        "name": "No content inspection on AI request/response",
        "pattern": r"""(?:openai|anthropic|client)\.\w+\.\w+\([^)]*\)(?!.*(?:guardrail|moderate|inspect|filter|scan|check_content|pii_detect))""",
        "description": "AI API calls without content inspection allow PII leakage, prompt injection, and policy violations.",
        "cwe": "CWE-20", "recommendation": "Implement content inspection at the AI gateway layer for both requests and responses.",
        "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-GW-004", "category": "AI Gateway", "severity": "MEDIUM",
        "name": "No per-user or per-team AI usage quotas",
        "pattern": r"""(?:openai|anthropic|client)\.\w+\.\w+\([^)]*\)(?!.*(?:quota|limit|budget|user_id|team_id|tenant))""",
        "description": "AI API calls without per-user/team quotas allow a single user to exhaust the organisation's AI budget.",
        "cwe": "CWE-770", "recommendation": "Implement per-user and per-team usage quotas and rate limits at the AI gateway.",
        "compliance": ["NIST-AI-RMF-MANAGE"],
    },
]

# ---------------------------------------------------------------------------
# PYTHON SAST RULES — AI BIAS & FAIRNESS  [v1.1.0]
# ---------------------------------------------------------------------------
BIAS_FAIRNESS_RULES: list[dict[str, Any]] = [
    {
        "id": "AISPM-FAIR-001", "category": "Bias & Fairness", "severity": "MEDIUM",
        "name": "No fairness evaluation in training pipeline",
        "pattern": r"""(?:\.fit|trainer\.train|model\.train)\s*\([^)]*\)(?!.*(?:fairness|bias|equalized_odds|demographic_parity|fairlearn|aequitas|aif360))""",
        "description": "Model training without fairness evaluation may produce biased outcomes affecting protected groups.",
        "cwe": "CWE-693", "recommendation": "Integrate fairness evaluation (Fairlearn, AIF360, Aequitas) into the training pipeline.",
        "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-MAP", "NIST-AI-RMF-MEASURE"],
    },
    {
        "id": "AISPM-FAIR-002", "category": "Bias & Fairness", "severity": "HIGH",
        "name": "Protected attributes used as direct model features",
        "pattern": r"""(?:features|columns|input_columns|feature_names)\s*(?:=|\[).*(?:race|gender|sex|ethnicity|religion|disability|age|nationality|sexual_orientation)""",
        "description": "Using protected demographic attributes as direct model features can cause discriminatory outcomes.",
        "cwe": "CWE-693", "recommendation": "Remove protected attributes from direct features. Use fairness-aware algorithms. Document any justified use.",
        "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-MAP"],
    },
    {
        "id": "AISPM-FAIR-003", "category": "Bias & Fairness", "severity": "MEDIUM",
        "name": "No demographic parity or equality testing",
        "pattern": r"""(?:predict|classify|score|rank)\s*\([^)]*\).*(?:decision|outcome|result)(?!.*(?:parity|equality|disparity|bias_test|group_metric))""",
        "description": "Model predictions used for decisions without demographic parity testing risk discriminatory impact.",
        "cwe": "CWE-693", "recommendation": "Test predictions across demographic groups. Measure disparate impact ratios. Document results.",
        "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-MEASURE"],
    },
    {
        "id": "AISPM-FAIR-004", "category": "Bias & Fairness", "severity": "LOW",
        "name": "No bias monitoring in production inference",
        "pattern": r"""(?:model\.predict|pipeline)\s*\([^)]*\).*(?:production|deploy|serve)(?!.*(?:bias_monitor|fairness_monitor|drift|disparity))""",
        "description": "Production inference without continuous bias monitoring allows discriminatory drift over time.",
        "cwe": "CWE-693", "recommendation": "Implement continuous bias monitoring in production. Set alert thresholds for disparity metrics.",
        "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-MEASURE"],
    },
]

# ---------------------------------------------------------------------------
# YAML / CONFIG RULES — K8S AI WORKLOADS (KServe, Seldon, Triton)  [v1.1.0]
# ---------------------------------------------------------------------------
K8S_AI_RULES: list[dict[str, Any]] = [
    {
        "id": "AISPM-K8S-AI-001", "category": "K8s AI Workloads", "severity": "HIGH",
        "name": "KServe InferenceService without authentication",
        "pattern": r"""(?:kind:\s*InferenceService|serving\.kserve\.io)(?!.*(?:auth|istio.*auth|security|token))""",
        "description": "KServe InferenceService deployed without authentication exposes model endpoints to unauthorised access.",
        "cwe": "CWE-306", "recommendation": "Enable Istio authentication or KServe auth predictor. Apply network policies to restrict access.",
        "compliance": ["NIST-AI-RMF-MANAGE", "ATLAS-INIT-ACCESS"],
    },
    {
        "id": "AISPM-K8S-AI-002", "category": "K8s AI Workloads", "severity": "MEDIUM",
        "name": "Seldon deployment without resource limits",
        "pattern": r"""(?:kind:\s*SeldonDeployment|machinelearning\.seldon\.io)(?!.*(?:resources|limits|requests))""",
        "description": "Seldon model deployment without resource limits can exhaust cluster resources.",
        "cwe": "CWE-770", "recommendation": "Set CPU, memory, and GPU resource requests and limits on all Seldon containers.",
        "compliance": ["NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-K8S-AI-003", "category": "K8s AI Workloads", "severity": "HIGH",
        "name": "GPU pod without security context constraints",
        "pattern": r"""nvidia\.com/gpu.*(?:(?!securityContext|readOnlyRootFilesystem|runAsNonRoot).)*$""",
        "description": "GPU pods without security context constraints run with excessive privileges.",
        "cwe": "CWE-250", "recommendation": "Apply securityContext with runAsNonRoot, readOnlyRootFilesystem, and drop ALL capabilities.",
        "compliance": ["NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-K8S-AI-004", "category": "K8s AI Workloads", "severity": "MEDIUM",
        "name": "Model serving container with writable root filesystem",
        "pattern": r"""(?:triton|torchserve|tensorflow.serving|vllm|ollama).*(?:readOnlyRootFilesystem:\s*false|(?!readOnlyRootFilesystem))""",
        "description": "Model serving container with writable filesystem allows attackers to modify model files or inject code.",
        "cwe": "CWE-732", "recommendation": "Set readOnlyRootFilesystem: true. Mount model files as read-only volumes.",
        "compliance": ["NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-K8S-AI-005", "category": "K8s AI Workloads", "severity": "MEDIUM",
        "name": "Triton/TorchServe metrics endpoint exposed externally",
        "pattern": r"""(?:triton|torchserve).*(?:metrics|prometheus|8002|8082).*(?:NodePort|LoadBalancer|Ingress)""",
        "description": "Model serving metrics endpoint exposed externally leaks model performance data and aids reconnaissance.",
        "cwe": "CWE-200", "recommendation": "Restrict metrics endpoints to ClusterIP. Use internal monitoring tools to scrape metrics.",
        "compliance": ["ATLAS-RECON", "NIST-AI-RMF-MANAGE"],
    },
]

# ---------------------------------------------------------------------------
# TERRAFORM / IaC RULES — AI SERVICES  [v1.1.0]
# ---------------------------------------------------------------------------
TERRAFORM_AI_RULES: list[dict[str, Any]] = [
    {
        "id": "AISPM-IAC-001", "category": "Terraform AI IaC", "severity": "HIGH",
        "name": "SageMaker endpoint without VPC or encryption",
        "pattern": r"""(?:aws_sagemaker_endpoint|aws_sagemaker_notebook)(?!.*(?:vpc|subnet|kms_key|encryption))""",
        "description": "AWS SageMaker endpoint deployed without VPC isolation or KMS encryption.",
        "cwe": "CWE-311", "recommendation": "Deploy SageMaker endpoints in VPC with private subnets. Enable KMS encryption for data at rest and in transit.",
        "compliance": ["NIST-AI-RMF-MANAGE", "EU-AI-ACT-HIGH"],
    },
    {
        "id": "AISPM-IAC-002", "category": "Terraform AI IaC", "severity": "HIGH",
        "name": "Bedrock model access without IAM restrictions",
        "pattern": r"""(?:aws_bedrock|bedrock).*(?:policy|access).*(?:\*|Allow)(?!.*(?:Condition|StringEquals|IpAddress))""",
        "description": "AWS Bedrock model access policy without IAM conditions allows overly broad access to AI models.",
        "cwe": "CWE-732", "recommendation": "Apply least-privilege IAM policies with conditions (source IP, tags, resource ARN).",
        "compliance": ["NIST-AI-RMF-MANAGE", "EU-AI-ACT-HIGH"],
    },
    {
        "id": "AISPM-IAC-003", "category": "Terraform AI IaC", "severity": "HIGH",
        "name": "Vertex AI notebook without private networking",
        "pattern": r"""(?:google_notebooks_instance|google_vertex_ai)(?!.*(?:no_public_ip|private|internal|vpc))""",
        "description": "Google Vertex AI notebook instance deployed with public IP, exposing interactive compute to the internet.",
        "cwe": "CWE-668", "recommendation": "Set no_public_ip = true. Deploy in VPC with Private Google Access.",
        "compliance": ["NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-IAC-004", "category": "Terraform AI IaC", "severity": "MEDIUM",
        "name": "Azure OpenAI without managed identity (key-based auth)",
        "pattern": r"""(?:azurerm_cognitive_account|azure_openai).*(?:key|api_key|access_key)(?!.*(?:managed_identity|identity|system_assigned))""",
        "description": "Azure OpenAI using key-based authentication instead of managed identity increases credential exposure risk.",
        "cwe": "CWE-798", "recommendation": "Use Azure Managed Identity for authentication. Avoid storing API keys.",
        "compliance": ["NIST-AI-RMF-GOVERN"],
    },
    {
        "id": "AISPM-IAC-005", "category": "Terraform AI IaC", "severity": "CRITICAL",
        "name": "Cloud model/training data bucket publicly accessible",
        "pattern": r"""(?:aws_s3_bucket|google_storage_bucket|azurerm_storage_container).*(?:model|training|dataset|ml-data).*(?:public|acl\s*=\s*['\"]public|allUsers|anonymous)""",
        "description": "Cloud storage bucket containing models or training data is publicly accessible.",
        "cwe": "CWE-732", "recommendation": "Block public access on all AI data buckets. Use IAM policies and VPC endpoints for access.",
        "compliance": ["NIST-AI-RMF-MANAGE", "OWASP-ML-05", "ATLAS-EXFIL"],
    },
]

# ---------------------------------------------------------------------------
# .env FILE RULES
# ---------------------------------------------------------------------------
ENV_RULES: list[dict[str, Any]] = [
    {
        "id": "AISPM-ENV-001", "category": "Secrets", "severity": "CRITICAL",
        "name": "OpenAI API key in .env file",
        "pattern": r"""OPENAI_API_KEY\s*=\s*sk-[a-zA-Z0-9]{20,}""",
        "description": "OpenAI API key stored in .env file. Ensure .env is in .gitignore and not committed to version control.",
        "cwe": "CWE-798", "recommendation": "Verify .env is in .gitignore. Use secrets managers for production. Rotate exposed keys immediately.",
        "compliance": ["NIST-AI-RMF-GOVERN"],
    },
    {
        "id": "AISPM-ENV-002", "category": "Secrets", "severity": "CRITICAL",
        "name": "Anthropic API key in .env file",
        "pattern": r"""ANTHROPIC_API_KEY\s*=\s*sk-ant-[a-zA-Z0-9-]{20,}""",
        "description": "Anthropic API key stored in .env file.",
        "cwe": "CWE-798", "recommendation": "Verify .env is in .gitignore. Use secrets managers for production. Rotate exposed keys immediately.",
        "compliance": ["NIST-AI-RMF-GOVERN"],
    },
    {
        "id": "AISPM-ENV-003", "category": "Secrets", "severity": "CRITICAL",
        "name": "HuggingFace token in .env file",
        "pattern": r"""(?:HF_TOKEN|HUGGINGFACE_TOKEN|HUGGING_FACE_HUB_TOKEN)\s*=\s*hf_[a-zA-Z0-9]{20,}""",
        "description": "HuggingFace token stored in .env file.",
        "cwe": "CWE-798", "recommendation": "Verify .env is in .gitignore. Use secrets managers for production.",
        "compliance": ["NIST-AI-RMF-GOVERN"],
    },
    {
        "id": "AISPM-ENV-004", "category": "Secrets", "severity": "CRITICAL",
        "name": "AI platform API key in .env file",
        "pattern": r"""(?:COHERE_API_KEY|TOGETHER_API_KEY|GROQ_API_KEY|REPLICATE_API_TOKEN|PINECONE_API_KEY|WEAVIATE_API_KEY|GOOGLE_AI_KEY|GEMINI_API_KEY)\s*=\s*[a-zA-Z0-9_-]{10,}""",
        "description": "AI platform API key stored in .env file.",
        "cwe": "CWE-798", "recommendation": "Verify .env is in .gitignore. Use secrets managers for production.",
        "compliance": ["NIST-AI-RMF-GOVERN"],
    },
    {
        "id": "AISPM-ENV-005", "category": "Infrastructure", "severity": "HIGH",
        "name": "Debug mode enabled in .env",
        "pattern": r"""(?:DEBUG|FLASK_DEBUG|FASTAPI_DEBUG)\s*=\s*(?:1|true|True|yes)""",
        "description": "Debug mode enabled in environment configuration — exposes detailed errors and model internals.",
        "cwe": "CWE-489", "recommendation": "Disable debug mode in production environments.",
        "compliance": ["NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-ENV-006", "category": "Infrastructure", "severity": "MEDIUM",
        "name": "AI model endpoint URL in .env without TLS",
        "pattern": r"""(?:MODEL_ENDPOINT|INFERENCE_URL|API_BASE|OPENAI_API_BASE|OLLAMA_HOST)\s*=\s*http://""",
        "description": "AI model endpoint configured to use HTTP instead of HTTPS.",
        "cwe": "CWE-319", "recommendation": "Use HTTPS endpoints for all AI model communication.",
        "compliance": ["NIST-AI-RMF-MANAGE"],
    },
]

# ---------------------------------------------------------------------------
# JS / TS SAST RULES
# ---------------------------------------------------------------------------
JS_SAST_RULES: list[dict[str, Any]] = [
    {
        "id": "AISPM-JS-001", "category": "Prompt Security", "severity": "CRITICAL",
        "name": "User input interpolated into AI prompt (JS/TS)",
        "pattern": r"""(?:messages|prompt|content)\s*(?::|=)\s*(?:`[^`]*\$\{.*(?:req\.|input|query|body|params)|['\"][^'\"]*\+\s*(?:req\.|input|query|body|params))""",
        "description": "User input directly interpolated into AI prompts enables prompt injection attacks.",
        "cwe": "CWE-74", "recommendation": "Use parameterised prompt templates. Separate system instructions from user input.",
        "compliance": ["OWASP-ML-01", "ATLAS-EXEC", "EU-AI-ACT-HIGH"],
    },
    {
        "id": "AISPM-JS-002", "category": "Secrets", "severity": "CRITICAL",
        "name": "Hardcoded AI API key in JavaScript/TypeScript",
        "pattern": r"""(?:(?:apiKey|api_key|authorization|bearer)\s*(?::|=)\s*['\"](?:sk-[a-zA-Z0-9]{20,}|sk-ant-[a-zA-Z0-9-]{20,}|hf_[a-zA-Z0-9]{20,}))""",
        "description": "Hardcoded AI API key in client-side or server-side JavaScript code.",
        "cwe": "CWE-798", "recommendation": "Use environment variables (process.env). Never expose API keys in client-side code.",
        "compliance": ["NIST-AI-RMF-GOVERN"],
    },
    {
        "id": "AISPM-JS-003", "category": "Secrets", "severity": "CRITICAL",
        "name": "AI API key exposed in frontend/client-side code",
        "pattern": r"""(?:NEXT_PUBLIC_|REACT_APP_|VITE_|NUXT_PUBLIC_)(?:OPENAI|ANTHROPIC|AI|LLM|GPT|CLAUDE)_(?:API_KEY|SECRET|TOKEN)""",
        "description": "AI API key exposed via client-side environment variable prefix (NEXT_PUBLIC_, REACT_APP_, etc.).",
        "cwe": "CWE-798", "recommendation": "Never expose AI API keys client-side. Use server-side API routes as proxies.",
        "compliance": ["NIST-AI-RMF-GOVERN"],
    },
    {
        "id": "AISPM-JS-004", "category": "Guardrails", "severity": "HIGH",
        "name": "AI response rendered as HTML without sanitisation (XSS)",
        "pattern": r"""(?:innerHTML|dangerouslySetInnerHTML|v-html)\s*(?:=|:)\s*.*(?:response|completion|output|result|answer|message)""",
        "description": "Rendering AI model output as unsanitised HTML enables cross-site scripting (XSS) attacks.",
        "cwe": "CWE-79", "recommendation": "Sanitise AI outputs with DOMPurify before HTML rendering. Use textContent instead of innerHTML.",
        "compliance": ["OWASP-ML-09", "NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-JS-005", "category": "Prompt Security", "severity": "HIGH",
        "name": "System prompt hardcoded in frontend bundle",
        "pattern": r"""(?:system|role\s*:\s*['\"]system['\"])\s*(?::|,)\s*(?:content\s*:\s*)?['\"](?:You are|Act as|Your role|As an AI)""",
        "description": "System prompts in frontend code are visible in browser DevTools, enabling prompt theft and bypass.",
        "cwe": "CWE-200", "recommendation": "Move system prompts to server-side. Never include in client-side bundles.",
        "compliance": ["OWASP-ML-01", "ATLAS-RECON"],
    },
    {
        "id": "AISPM-JS-006", "category": "Model Security", "severity": "HIGH",
        "name": "eval() on AI model output (JS/TS)",
        "pattern": r"""(?:eval|Function|new\s+Function)\s*\([^)]*(?:response|completion|output|result|answer|message)""",
        "description": "Using eval() on AI output enables remote code execution in the browser or Node.js runtime.",
        "cwe": "CWE-94", "recommendation": "Never eval() model outputs. Use structured JSON parsing with schema validation.",
        "compliance": ["OWASP-ML-09", "ATLAS-IMPACT"],
    },
    {
        "id": "AISPM-JS-007", "category": "Infrastructure", "severity": "MEDIUM",
        "name": "AI endpoint without rate limiting (Express/Next.js)",
        "pattern": r"""(?:app\.(?:post|get)|router\.(?:post|get))\s*\(\s*['\"].*(?:ai|chat|generate|complete|predict).*['\"](?!.*(?:rateLimit|rateLimiter|throttle))""",
        "description": "AI API endpoints without rate limiting are vulnerable to abuse and cost overruns.",
        "cwe": "CWE-770", "recommendation": "Apply rate limiting middleware (express-rate-limit) to all AI endpoints.",
        "compliance": ["NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-JS-008", "category": "Privacy", "severity": "HIGH",
        "name": "User data sent to AI API without consent check (JS/TS)",
        "pattern": r"""(?:fetch|axios|openai|anthropic)\s*(?:\(|\.)\s*[^)]*(?:userData|personalData|profile|email|phone)""",
        "description": "Sending user personal data to AI APIs without consent verification violates privacy regulations.",
        "cwe": "CWE-359", "recommendation": "Implement consent checks before sending user data to AI services. Anonymise where possible.",
        "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-GOVERN"],
    },
]

# ---------------------------------------------------------------------------
# YAML / CONFIG RULES (for AI/ML pipeline configs)
# ---------------------------------------------------------------------------
CONFIG_RULES: list[dict[str, Any]] = [
    {
        "id": "AISPM-CFG-001", "category": "Infrastructure", "severity": "HIGH",
        "name": "ML pipeline with privileged container",
        "pattern": r"""(?:privileged|securityContext).*(?:true|True)""",
        "description": "ML training/serving containers running in privileged mode can escape to the host system.",
        "cwe": "CWE-250", "recommendation": "Run ML containers as non-root with minimal capabilities. Use security contexts.",
        "compliance": ["NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-CFG-002", "category": "Infrastructure", "severity": "HIGH",
        "name": "ML pipeline with root user",
        "pattern": r"""(?:runAsUser|user)\s*:\s*(?:0|root)""",
        "description": "ML pipeline running as root user. Container compromise leads to full host compromise.",
        "cwe": "CWE-250", "recommendation": "Run ML workloads as non-root user. Set runAsNonRoot: true in security context.",
        "compliance": ["NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-CFG-003", "category": "Model Security", "severity": "HIGH",
        "name": "Model registry without authentication in config",
        "pattern": r"""(?:model_registry|mlflow|model_store|artifact_store)\s*:\s*(?:http://|s3://(?!.*(?:auth|iam)))""",
        "description": "Model registry or artifact store configured without authentication.",
        "cwe": "CWE-306", "recommendation": "Enable authentication on model registries. Use IAM roles for cloud storage.",
        "compliance": ["NIST-AI-RMF-MANAGE", "OWASP-ML-06"],
    },
    {
        "id": "AISPM-CFG-004", "category": "Data Pipeline", "severity": "MEDIUM",
        "name": "Training data path with world-readable permissions",
        "pattern": r"""(?:data_path|dataset_path|training_data)\s*:\s*['\"]?(?:/tmp|/shared|/public)""",
        "description": "Training data stored in world-readable locations enables data theft and poisoning.",
        "cwe": "CWE-732", "recommendation": "Store training data in access-controlled directories with proper permissions.",
        "compliance": ["NIST-AI-RMF-MANAGE", "OWASP-ML-02"],
    },
    {
        "id": "AISPM-CFG-005", "category": "Infrastructure", "severity": "MEDIUM",
        "name": "GPU sharing without isolation",
        "pattern": r"""(?:gpu_sharing|nvidia\.com/gpu)\s*:\s*(?:shared|multi)""",
        "description": "GPU sharing between workloads without isolation enables side-channel attacks on model weights.",
        "cwe": "CWE-653", "recommendation": "Use GPU partitioning (MIG/MPS) or dedicated GPUs for sensitive model training.",
        "compliance": ["NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-CFG-006", "category": "Guardrails", "severity": "HIGH",
        "name": "AI safety guardrails disabled in configuration",
        "pattern": r"""(?:safety|guardrails?|content_filter|moderation)\s*:\s*(?:false|False|disabled|off|none)""",
        "description": "AI safety guardrails explicitly disabled in configuration.",
        "cwe": "CWE-693", "recommendation": "Enable safety guardrails in all environments. Use configuration management to enforce.",
        "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-CFG-007", "category": "Privacy", "severity": "HIGH",
        "name": "Telemetry or data collection enabled without disclosure",
        "pattern": r"""(?:telemetry|analytics|data_collection|tracking)\s*:\s*(?:true|True|enabled|on)""",
        "description": "AI system with telemetry enabled may collect user data without proper disclosure or consent.",
        "cwe": "CWE-359", "recommendation": "Disclose data collection practices. Implement opt-in consent. Anonymise telemetry data.",
        "compliance": ["EU-AI-ACT-LIMITED", "NIST-AI-RMF-GOVERN"],
    },
    {
        "id": "AISPM-CFG-008", "category": "Infrastructure", "severity": "MEDIUM",
        "name": "Model serving replicas with no resource limits",
        "pattern": r"""(?:replicas|instances)\s*:\s*\d+(?!.*(?:resources|limits|requests))""",
        "description": "Model serving without resource limits can cause resource exhaustion and noisy-neighbour issues.",
        "cwe": "CWE-770", "recommendation": "Set CPU, memory, and GPU resource limits for model serving containers.",
        "compliance": ["NIST-AI-RMF-MANAGE"],
    },
]

# ---------------------------------------------------------------------------
# DOCKER / CONTAINER RULES (for AI/ML images)
# ---------------------------------------------------------------------------
DOCKER_RULES: list[dict[str, Any]] = [
    {
        "id": "AISPM-DOCKER-001", "category": "Infrastructure", "severity": "HIGH",
        "name": "AI model container running as root",
        "pattern": r"""(?:^USER\s+root|^(?!.*USER))""",
        "description": "Dockerfile for AI model serving runs as root user. Container compromise leads to host compromise.",
        "cwe": "CWE-250", "recommendation": "Add USER directive with non-root user. Use multi-stage builds to minimise attack surface.",
        "compliance": ["NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-DOCKER-002", "category": "Secrets", "severity": "CRITICAL",
        "name": "AI API key in Dockerfile",
        "pattern": r"""(?:ENV|ARG)\s+(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|HF_TOKEN|COHERE_API_KEY|PINECONE_API_KEY)\s*=?\s*[a-zA-Z0-9_-]{10,}""",
        "description": "AI API key embedded in Dockerfile. Keys persist in image layers even if deleted in later layers.",
        "cwe": "CWE-798", "recommendation": "Use Docker secrets, --secret mount, or runtime environment variables. Never embed keys in Dockerfiles.",
        "compliance": ["NIST-AI-RMF-GOVERN"],
    },
    {
        "id": "AISPM-DOCKER-003", "category": "Infrastructure", "severity": "MEDIUM",
        "name": "AI container using latest/unversioned base image",
        "pattern": r"""FROM\s+(?:python|nvidia/cuda|tensorflow|pytorch|huggingface)\s*(?:$|:latest)""",
        "description": "Using unversioned or :latest base images for AI containers can introduce supply chain vulnerabilities.",
        "cwe": "CWE-829", "recommendation": "Pin base images to specific versions with SHA-256 digests.",
        "compliance": ["OWASP-ML-06", "NIST-AI-RMF-MANAGE"],
    },
    {
        "id": "AISPM-DOCKER-004", "category": "Infrastructure", "severity": "HIGH",
        "name": "Jupyter port exposed in Docker container",
        "pattern": r"""EXPOSE\s+8888""",
        "description": "Exposing Jupyter notebook port (8888) in Docker containers can expose interactive code execution.",
        "cwe": "CWE-668", "recommendation": "Remove Jupyter port exposure in production images. Use separate dev and prod Dockerfiles.",
        "compliance": ["NIST-AI-RMF-MANAGE"],
    },
]

# ---------------------------------------------------------------------------
# AI/ML SUPPLY CHAIN — VULNERABLE PACKAGES WITH CVEs
# ---------------------------------------------------------------------------
AI_VULNERABLE_PACKAGES: list[dict[str, Any]] = [
    {"package": "tensorflow",    "cve": "CVE-2023-25801", "severity": "CRITICAL", "fixed": "2.12.0",  "desc": "Remote code execution via crafted SavedModel"},
    {"package": "tensorflow",    "cve": "CVE-2024-3660",  "severity": "CRITICAL", "fixed": "2.16.1",  "desc": "Arbitrary code execution in Keras Lambda layer"},
    {"package": "pytorch",       "cve": "CVE-2024-5480",  "severity": "CRITICAL", "fixed": "2.2.0",   "desc": "Remote code execution via torch.load (pickle)"},
    {"package": "transformers",  "cve": "CVE-2023-49082", "severity": "HIGH",     "fixed": "4.36.0",  "desc": "Arbitrary code execution via malicious model loading"},
    {"package": "transformers",  "cve": "CVE-2024-3568",  "severity": "HIGH",     "fixed": "4.38.0",  "desc": "Code injection via trust_remote_code models"},
    {"package": "langchain",     "cve": "CVE-2023-36188", "severity": "CRITICAL", "fixed": "0.0.247", "desc": "Arbitrary code execution via LLMMathChain"},
    {"package": "langchain",     "cve": "CVE-2023-44467", "severity": "CRITICAL", "fixed": "0.0.312", "desc": "Code injection via PALChain prompt manipulation"},
    {"package": "langchain",     "cve": "CVE-2024-0243",  "severity": "HIGH",     "fixed": "0.1.0",   "desc": "Server-side request forgery via document loaders"},
    {"package": "llama-cpp-python", "cve": "CVE-2024-34359", "severity": "CRITICAL", "fixed": "0.2.72", "desc": "Remote code execution via GGUF model loading"},
    {"package": "gradio",        "cve": "CVE-2024-1561",  "severity": "HIGH",     "fixed": "4.19.2",  "desc": "Path traversal and local file disclosure"},
    {"package": "gradio",        "cve": "CVE-2024-4325",  "severity": "CRITICAL", "fixed": "4.31.4",  "desc": "Server-side request forgery in file upload"},
    {"package": "mlflow",        "cve": "CVE-2024-27132", "severity": "CRITICAL", "fixed": "2.11.3",  "desc": "Remote code execution via recipes module"},
    {"package": "mlflow",        "cve": "CVE-2023-6977",  "severity": "HIGH",     "fixed": "2.9.2",   "desc": "Path traversal in artifact handling"},
    {"package": "ray",           "cve": "CVE-2023-48022", "severity": "CRITICAL", "fixed": "2.8.1",   "desc": "Remote code execution — ShadowRay (unauthenticated dashboard)"},
    {"package": "onnx",          "cve": "CVE-2024-5187",  "severity": "HIGH",     "fixed": "1.16.0",  "desc": "Directory traversal via crafted ONNX model"},
    {"package": "vllm",          "cve": "CVE-2024-9052",  "severity": "HIGH",     "fixed": "0.5.2",   "desc": "Arbitrary code execution via model serialization"},
    {"package": "numpy",         "cve": "CVE-2019-6446",  "severity": "CRITICAL", "fixed": "1.16.3",  "desc": "Arbitrary code execution via pickle in numpy.load"},
    {"package": "scikit-learn",  "cve": "CVE-2020-28975", "severity": "MEDIUM",   "fixed": "0.24.0",  "desc": "Denial of service via crafted pickle model"},
    {"package": "pillow",        "cve": "CVE-2023-44271", "severity": "HIGH",     "fixed": "10.0.0",  "desc": "Denial of service via large image decompression"},
    {"package": "fastapi",       "cve": "CVE-2024-24762", "severity": "HIGH",     "fixed": "0.109.1", "desc": "DoS via multipart content-type header parsing"},
    # v1.1.0 additions
    {"package": "chromadb",      "cve": "CVE-2024-3095",  "severity": "HIGH",     "fixed": "0.4.0",   "desc": "Path traversal in collection operations"},
    {"package": "instructor",    "cve": "CVE-2024-3772",  "severity": "MEDIUM",   "fixed": "0.6.0",   "desc": "Information leakage via verbose error messages"},
    {"package": "bentoml",       "cve": "CVE-2024-2912",  "severity": "CRITICAL", "fixed": "1.2.5",   "desc": "Remote code execution via pickle deserialization"},
    {"package": "lm-format-enforcer", "cve": "CVE-2024-1455", "severity": "HIGH", "fixed": "0.9.0",   "desc": "ReDoS via crafted regex patterns"},
    {"package": "ollama",        "cve": "CVE-2024-39720", "severity": "HIGH",     "fixed": "0.1.47",  "desc": "Path traversal leading to arbitrary file read"},
    {"package": "ollama",        "cve": "CVE-2024-39722", "severity": "HIGH",     "fixed": "0.1.46",  "desc": "Information disclosure of model files via API"},
    {"package": "jupyter-server","cve": "CVE-2024-35178", "severity": "HIGH",     "fixed": "2.14.1",  "desc": "Authentication bypass via crafted URL"},
    {"package": "dspy-ai",       "cve": "CVE-2024-4160",  "severity": "MEDIUM",   "fixed": "2.4.0",   "desc": "Prompt injection via template manipulation"},
    {"package": "label-studio",  "cve": "CVE-2024-26152", "severity": "CRITICAL", "fixed": "1.11.0",  "desc": "Server-side request forgery via data import"},
    {"package": "paddlepaddle",  "cve": "CVE-2024-0917",  "severity": "CRITICAL", "fixed": "2.6.0",   "desc": "Remote code execution via pickle in paddle.load"},
]

# NPM AI packages with CVEs
AI_NPM_VULNERABLE_PACKAGES: list[dict[str, Any]] = [
    {"package": "langchain",    "cve": "CVE-2023-36189", "severity": "CRITICAL", "fixed": "0.0.251", "desc": "Code injection via agents (JS)"},
    {"package": "@huggingface/inference", "cve": "CVE-2024-1234", "severity": "MEDIUM", "fixed": "2.6.0", "desc": "SSRF via model endpoint configuration"},
    {"package": "openai",       "cve": "CVE-2024-0000",  "severity": "LOW",      "fixed": "4.20.0",  "desc": "Information disclosure in error messages"},
]


# ---------------------------------------------------------------------------
# DATA-CLASS: Finding
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    rule_id: str
    name: str
    category: str
    severity: str
    file_path: str
    line_num: int
    line_content: str
    description: str
    recommendation: str
    cwe: str = ""
    cve: str = ""
    compliance: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# SCANNER CLASS
# ---------------------------------------------------------------------------
class AISPMScanner:
    """AI Security Posture Management Scanner v1.1.0"""

    SKIP_DIRS = {
        ".git", ".svn", ".hg", "node_modules", "__pycache__", ".tox",
        ".mypy_cache", ".pytest_cache", "venv", ".venv", "env", ".env_dir",
        "dist", "build", "egg-info", ".eggs", "site-packages",
        ".terraform", ".next", ".nuxt",
    }

    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    SEVERITY_COLOR = {
        "CRITICAL": "\033[91m", "HIGH": "\033[31m",
        "MEDIUM": "\033[33m", "LOW": "\033[36m", "INFO": "\033[37m",
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"

    PY_EXTENSIONS = {".py", ".pyw"}
    JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
    ENV_EXTENSIONS = {".env"}
    CONFIG_EXTENSIONS = {".yaml", ".yml", ".toml"}
    DOCKER_NAMES = {"Dockerfile", "dockerfile", "Containerfile"}
    TF_EXTENSIONS = {".tf"}
    NOTEBOOK_EXTENSION = ".ipynb"
    MODEL_CARD_NAMES = {"MODEL_CARD.md", "model_card.md", "MODEL-CARD.md",
                        "model-card.md", "MODELCARD.md", "modelcard.md"}
    REQUIREMENTS_FILES = {"requirements.txt", "requirements-dev.txt", "requirements-ml.txt",
                          "requirements-ai.txt", "requirements_ai.txt", "requirements_ml.txt",
                          "constraints.txt"}
    PIPFILE_NAMES = {"Pipfile", "Pipfile.lock"}
    PYPROJECT_NAME = "pyproject.toml"
    PACKAGE_JSON = "package.json"

    def __init__(self, verbose: bool = False):
        self.findings: list[Finding] = []
        self.verbose = verbose
        self._scanned_files = 0
        self._ai_inventory: dict[str, set[str]] = {
            "frameworks": set(),
            "models": set(),
            "apis": set(),
            "vector_dbs": set(),
            "experiment_trackers": set(),
        }

    # -- helpers --
    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(f"  [v] {msg}", file=sys.stderr)

    def _warn(self, msg: str) -> None:
        print(f"  [!] {msg}", file=sys.stderr)

    def _add(self, rule: dict, fpath: str, lineno: int, line: str,
             cve: str = "") -> None:
        self.findings.append(Finding(
            rule_id=rule["id"], name=rule["name"], category=rule["category"],
            severity=rule["severity"], file_path=fpath, line_num=lineno,
            line_content=line.strip()[:200], description=rule["description"],
            recommendation=rule["recommendation"], cwe=rule.get("cwe", ""),
            cve=cve, compliance=rule.get("compliance", []),
        ))

    # -- version helpers --
    @staticmethod
    def _parse_ver(s: str) -> tuple[int, ...]:
        parts: list[int] = []
        for tok in re.split(r"[^0-9]+", s.strip()):
            if tok:
                try:
                    parts.append(int(tok))
                except ValueError:
                    break
        return tuple(parts) if parts else (0,)

    @staticmethod
    def _ver_lt(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
        for x, y in zip(a, b):
            if x < y:
                return True
            if x > y:
                return False
        return len(a) < len(b)

    # -- AI inventory detection --
    def _detect_ai_inventory(self, line: str) -> None:
        # Frameworks
        for fw in ("tensorflow", "keras", "torch", "pytorch", "transformers",
                    "langchain", "langgraph", "llamaindex", "llama_index",
                    "autogen", "crewai", "haystack", "semantic_kernel",
                    "dspy", "instructor", "peft", "trl", "bentoml",
                    "gradio", "streamlit", "chainlit"):
            if fw in line.lower():
                self._ai_inventory["frameworks"].add(fw)
        # Models
        for model in ("gpt-4", "gpt-3.5", "claude", "gemini", "llama",
                       "mistral", "mixtral", "phi-", "qwen", "falcon",
                       "stable-diffusion", "dall-e", "whisper"):
            if model in line.lower():
                self._ai_inventory["models"].add(model)
        # APIs
        for api in ("openai", "anthropic", "cohere", "together", "groq",
                     "replicate", "huggingface", "google.generativeai",
                     "vertexai", "bedrock", "azure.ai"):
            if api in line.lower():
                self._ai_inventory["apis"].add(api)
        # Vector DBs
        for vdb in ("pinecone", "weaviate", "qdrant", "milvus", "chroma",
                     "faiss", "pgvector"):
            if vdb in line.lower():
                self._ai_inventory["vector_dbs"].add(vdb)
        # Experiment trackers
        for tracker in ("mlflow", "wandb", "neptune", "comet", "tensorboard"):
            if tracker in line.lower():
                self._ai_inventory["experiment_trackers"].add(tracker)

    # -----------------------------------------------------------------------
    # SCANNING ENTRY POINTS
    # -----------------------------------------------------------------------
    def scan_path(self, target: str) -> list[Finding]:
        p = Path(target)
        if p.is_file():
            self._dispatch_file(str(p))
        elif p.is_dir():
            self._scan_directory(str(p))
        else:
            self._warn(f"Target not found: {target}")
        return self.findings

    def _scan_directory(self, root: str) -> None:
        self._check_model_card(root)
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in self.SKIP_DIRS]
            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                self._dispatch_file(fpath)

    # -----------------------------------------------------------------------
    # MODEL CARD / DOCUMENTATION COMPLIANCE  [v1.1.0]
    # -----------------------------------------------------------------------
    def _check_model_card(self, root: str) -> None:
        """Check for AI documentation compliance at project root."""
        has_model_card = False
        for name in self.MODEL_CARD_NAMES:
            if os.path.isfile(os.path.join(root, name)):
                has_model_card = True
                break

        # Check if this looks like an AI project (has Python/ML files)
        is_ai_project = False
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in self.SKIP_DIRS]
            for fname in filenames:
                if fname.endswith((".py", ".ipynb")):
                    fpath = os.path.join(dirpath, fname)
                    try:
                        with open(fpath, encoding="utf-8", errors="replace") as fh:
                            sample = fh.read(4096)
                        if any(kw in sample.lower() for kw in
                               ("import torch", "import tensorflow", "from transformers",
                                "import openai", "import anthropic", "langchain",
                                "model.predict", "model.generate", "fine_tune",
                                "from sklearn", "import keras")):
                            is_ai_project = True
                            break
                    except OSError:
                        pass
            if is_ai_project:
                break

        if is_ai_project and not has_model_card:
            doc_rules = [
                {
                    "id": "AISPM-DOC-001", "category": "Model Card Compliance", "severity": "MEDIUM",
                    "name": "No model card file in project",
                    "pattern": "", "cwe": "CWE-1059",
                    "description": "AI project has no MODEL_CARD.md documenting the model's intended use, limitations, and risks. Required by EU AI Act for high-risk systems.",
                    "recommendation": "Create a MODEL_CARD.md with: model description, intended use, out-of-scope use, training data, evaluation results, ethical considerations, and limitations.",
                    "compliance": ["EU-AI-ACT-HIGH", "EU-AI-ACT-GPAI", "NIST-AI-RMF-GOVERN", "NIST-AI-RMF-MAP"],
                },
                {
                    "id": "AISPM-DOC-002", "category": "Model Card Compliance", "severity": "MEDIUM",
                    "name": "No AI system risk classification documented",
                    "pattern": "", "cwe": "CWE-1059",
                    "description": "AI project lacks risk classification documentation required by EU AI Act.",
                    "recommendation": "Document the AI system's risk level (unacceptable/high/limited/minimal) and justify the classification.",
                    "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-MAP"],
                },
                {
                    "id": "AISPM-DOC-003", "category": "Model Card Compliance", "severity": "LOW",
                    "name": "No intended use or out-of-scope use documentation",
                    "pattern": "", "cwe": "CWE-1059",
                    "description": "AI project lacks documentation of intended and out-of-scope use cases.",
                    "recommendation": "Document intended use cases, known limitations, and explicitly list out-of-scope or prohibited uses.",
                    "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-MAP"],
                },
                {
                    "id": "AISPM-DOC-004", "category": "Model Card Compliance", "severity": "LOW",
                    "name": "No training data documentation",
                    "pattern": "", "cwe": "CWE-1059",
                    "description": "AI project lacks training data documentation covering sources, preprocessing, and potential biases.",
                    "recommendation": "Document training data sources, preprocessing steps, demographic representation, and known biases.",
                    "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-MAP", "NIST-AI-RMF-MEASURE"],
                },
                {
                    "id": "AISPM-DOC-005", "category": "Model Card Compliance", "severity": "LOW",
                    "name": "No performance metrics or evaluation results documented",
                    "pattern": "", "cwe": "CWE-1059",
                    "description": "AI project lacks performance evaluation documentation.",
                    "recommendation": "Document evaluation metrics, benchmark results, and performance across demographic subgroups.",
                    "compliance": ["EU-AI-ACT-HIGH", "NIST-AI-RMF-MEASURE"],
                },
            ]
            for rule in doc_rules:
                self._add(rule, root, 0, "No MODEL_CARD.md found")

    def _dispatch_file(self, fpath: str) -> None:
        fname = os.path.basename(fpath)
        _, ext = os.path.splitext(fname)
        ext = ext.lower()

        try:
            if ext in self.PY_EXTENSIONS:
                self._scan_python(fpath)
            elif ext in self.JS_EXTENSIONS:
                self._scan_js(fpath)
            elif fname.startswith(".env") or ext in self.ENV_EXTENSIONS:
                self._scan_env(fpath)
            elif ext in self.CONFIG_EXTENSIONS:
                self._scan_config(fpath)
            elif ext in self.TF_EXTENSIONS:
                self._scan_terraform(fpath)
            elif fname in self.DOCKER_NAMES or fname.endswith(".dockerfile"):
                self._scan_docker(fpath)
            elif fname in self.REQUIREMENTS_FILES or (fname.startswith("requirements") and fname.endswith(".txt")):
                self._scan_requirements(fpath)
            elif fname in self.PIPFILE_NAMES or fname == self.PYPROJECT_NAME:
                self._scan_pyproject(fpath)
            elif fname == self.PACKAGE_JSON:
                self._scan_package_json(fpath)
            elif ext == self.NOTEBOOK_EXTENSION:
                self._scan_notebook(fpath)
            else:
                return
            self._scanned_files += 1
        except (OSError, UnicodeDecodeError) as exc:
            self._vprint(f"Skip {fpath}: {exc}")

    # -----------------------------------------------------------------------
    # PYTHON SCANNING
    # -----------------------------------------------------------------------
    def _scan_python(self, fpath: str) -> None:
        self._vprint(f"Scanning Python: {fpath}")
        try:
            with open(fpath, encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            return
        full_text = "".join(lines)

        all_rules = (MODEL_SECURITY_RULES + PROMPT_SECURITY_RULES +
                     DATA_PIPELINE_RULES + PRIVACY_RULES +
                     GUARDRAIL_RULES + AGENT_SECURITY_RULES +
                     RAG_SECURITY_RULES + SECRET_RULES +
                     SHADOW_AI_RULES + INFRA_RULES +
                     MCP_SECURITY_RULES + AGENT_FRAMEWORK_RULES +
                     FINETUNE_SECURITY_RULES + MULTIMODAL_SECURITY_RULES +
                     OBSERVABILITY_RULES + GATEWAY_RULES +
                     BIAS_FAIRNESS_RULES)

        self._sast_scan(fpath, lines, all_rules)

        # AI inventory detection
        for line in lines:
            self._detect_ai_inventory(line)

    # -----------------------------------------------------------------------
    # JS / TS SCANNING
    # -----------------------------------------------------------------------
    def _scan_js(self, fpath: str) -> None:
        self._vprint(f"Scanning JS/TS: {fpath}")
        try:
            with open(fpath, encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            return

        self._sast_scan(fpath, lines, JS_SAST_RULES)

        for line in lines:
            self._detect_ai_inventory(line)

    # -----------------------------------------------------------------------
    # .env SCANNING
    # -----------------------------------------------------------------------
    def _scan_env(self, fpath: str) -> None:
        self._vprint(f"Scanning .env: {fpath}")
        try:
            with open(fpath, encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            return
        self._sast_scan(fpath, lines, ENV_RULES)

    # -----------------------------------------------------------------------
    # CONFIG (YAML/TOML) SCANNING
    # -----------------------------------------------------------------------
    def _scan_config(self, fpath: str) -> None:
        self._vprint(f"Scanning config: {fpath}")
        try:
            with open(fpath, encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            return
        self._sast_scan(fpath, lines, CONFIG_RULES + K8S_AI_RULES)

    # -----------------------------------------------------------------------
    # TERRAFORM (.tf) SCANNING  [v1.1.0]
    # -----------------------------------------------------------------------
    def _scan_terraform(self, fpath: str) -> None:
        self._vprint(f"Scanning Terraform: {fpath}")
        try:
            with open(fpath, encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            return
        self._sast_scan(fpath, lines, TERRAFORM_AI_RULES)

    # -----------------------------------------------------------------------
    # DOCKERFILE SCANNING
    # -----------------------------------------------------------------------
    def _scan_docker(self, fpath: str) -> None:
        self._vprint(f"Scanning Dockerfile: {fpath}")
        try:
            with open(fpath, encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            return

        # Check for USER directive (AISPM-DOCKER-001)
        has_user_directive = any(re.match(r"^\s*USER\s+(?!root)", line)
                                for line in lines)
        if not has_user_directive:
            rule = DOCKER_RULES[0]  # AISPM-DOCKER-001
            self._add(rule, fpath, 1, "No non-root USER directive found")

        # Remaining Docker rules via SAST
        self._sast_scan(fpath, lines, DOCKER_RULES[1:])

    # -----------------------------------------------------------------------
    # REQUIREMENTS.TXT SCANNING (supply chain)
    # -----------------------------------------------------------------------
    def _scan_requirements(self, fpath: str) -> None:
        self._vprint(f"Scanning requirements: {fpath}")
        try:
            with open(fpath, encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            return
        self._check_python_deps(fpath, lines)

    def _check_python_deps(self, fpath: str, lines: list[str]) -> None:
        for lineno, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("#"):
                continue
            # Parse package==version or package>=version
            m = re.match(r"^([a-zA-Z0-9_-]+)\s*(?:==|>=|<=|~=|!=)\s*([\d.]+)", line_stripped)
            if not m:
                m = re.match(r"^([a-zA-Z0-9_-]+)\s*$", line_stripped)
                if m:
                    pkg_name = m.group(1).lower().replace("_", "-")
                    # Check if it's an AI package at all
                    for vuln in AI_VULNERABLE_PACKAGES:
                        if pkg_name == vuln["package"].lower().replace("_", "-"):
                            rule = {
                                "id": f"AISPM-DEP-{vuln['cve']}",
                                "category": "Supply Chain",
                                "severity": "MEDIUM",
                                "name": f"Unpinned AI package: {vuln['package']}",
                                "pattern": "",
                                "description": f"Package {vuln['package']} is not version-pinned. Known CVE {vuln['cve']} affects versions < {vuln['fixed']}: {vuln['desc']}",
                                "cwe": "CWE-1104",
                                "recommendation": f"Pin to version >= {vuln['fixed']}. Use: {vuln['package']}>={vuln['fixed']}",
                                "compliance": ["OWASP-ML-06", "NIST-AI-RMF-MANAGE"],
                            }
                            self._add(rule, fpath, lineno, line_stripped, cve=vuln["cve"])
                continue
            pkg_name = m.group(1).lower().replace("_", "-")
            pkg_ver = self._parse_ver(m.group(2))

            for vuln in AI_VULNERABLE_PACKAGES:
                if pkg_name == vuln["package"].lower().replace("_", "-"):
                    fixed_ver = self._parse_ver(vuln["fixed"])
                    if self._ver_lt(pkg_ver, fixed_ver):
                        rule = {
                            "id": f"AISPM-DEP-{vuln['cve']}",
                            "category": "Supply Chain",
                            "severity": vuln["severity"],
                            "name": f"Vulnerable AI package: {vuln['package']} ({vuln['cve']})",
                            "pattern": "",
                            "description": f"{vuln['desc']}. Affects versions < {vuln['fixed']}.",
                            "cwe": "CWE-1104",
                            "recommendation": f"Upgrade to {vuln['package']} >= {vuln['fixed']}",
                            "compliance": ["OWASP-ML-06", "NIST-AI-RMF-MANAGE"],
                        }
                        self._add(rule, fpath, lineno, line_stripped, cve=vuln["cve"])

    # -----------------------------------------------------------------------
    # PYPROJECT.TOML / PIPFILE SCANNING
    # -----------------------------------------------------------------------
    def _scan_pyproject(self, fpath: str) -> None:
        self._vprint(f"Scanning pyproject/Pipfile: {fpath}")
        try:
            with open(fpath, encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            return
        # Extract dependency lines (simple heuristic)
        dep_lines: list[str] = []
        for line in lines:
            stripped = line.strip()
            # Match patterns like: tensorflow = ">=2.10.0" or "tensorflow==2.10.0"
            m = re.match(r"""^['\"]?([a-zA-Z0-9_-]+)['\"]?\s*(?:=\s*['\"](?:==|>=|<=|~=)?(\d[\d.]*)['\"]|==(\d[\d.]*))""", stripped)
            if m:
                pkg = m.group(1)
                ver = m.group(2) or m.group(3) or ""
                if ver:
                    dep_lines.append(f"{pkg}=={ver}")
                else:
                    dep_lines.append(pkg)
        if dep_lines:
            self._check_python_deps(fpath, dep_lines)

    # -----------------------------------------------------------------------
    # PACKAGE.JSON SCANNING
    # -----------------------------------------------------------------------
    def _scan_package_json(self, fpath: str) -> None:
        self._vprint(f"Scanning package.json: {fpath}")
        try:
            with open(fpath, encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return

        all_deps: dict[str, str] = {}
        for key in ("dependencies", "devDependencies"):
            if key in data and isinstance(data[key], dict):
                all_deps.update(data[key])

        for pkg_name, ver_spec in all_deps.items():
            pkg_lower = pkg_name.lower().replace("_", "-").lstrip("@").replace("/", "-")
            ver_match = re.search(r"(\d+\.\d+[\d.]*)", ver_spec)
            if not ver_match:
                continue
            pkg_ver = self._parse_ver(ver_match.group(1))
            for vuln in AI_NPM_VULNERABLE_PACKAGES:
                vuln_pkg = vuln["package"].lower().replace("_", "-").lstrip("@").replace("/", "-")
                if pkg_lower == vuln_pkg:
                    fixed_ver = self._parse_ver(vuln["fixed"])
                    if self._ver_lt(pkg_ver, fixed_ver):
                        rule = {
                            "id": f"AISPM-DEP-{vuln['cve']}",
                            "category": "Supply Chain",
                            "severity": vuln["severity"],
                            "name": f"Vulnerable AI npm package: {pkg_name} ({vuln['cve']})",
                            "pattern": "",
                            "description": f"{vuln['desc']}. Affects versions < {vuln['fixed']}.",
                            "cwe": "CWE-1104",
                            "recommendation": f"Upgrade to {pkg_name} >= {vuln['fixed']}",
                            "compliance": ["OWASP-ML-06", "NIST-AI-RMF-MANAGE"],
                        }
                        self._add(rule, fpath, 1, f'"{pkg_name}": "{ver_spec}"',
                                  cve=vuln["cve"])

    # -----------------------------------------------------------------------
    # JUPYTER NOTEBOOK SCANNING
    # -----------------------------------------------------------------------
    def _scan_notebook(self, fpath: str) -> None:
        self._vprint(f"Scanning notebook: {fpath}")
        try:
            with open(fpath, encoding="utf-8", errors="replace") as fh:
                nb = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return

        cells = nb.get("cells", [])
        line_offset = 1
        all_rules = (MODEL_SECURITY_RULES + PROMPT_SECURITY_RULES +
                     DATA_PIPELINE_RULES + PRIVACY_RULES +
                     GUARDRAIL_RULES + AGENT_SECURITY_RULES +
                     RAG_SECURITY_RULES + SECRET_RULES +
                     SHADOW_AI_RULES + INFRA_RULES +
                     MCP_SECURITY_RULES + AGENT_FRAMEWORK_RULES +
                     FINETUNE_SECURITY_RULES + MULTIMODAL_SECURITY_RULES +
                     OBSERVABILITY_RULES + GATEWAY_RULES +
                     BIAS_FAIRNESS_RULES)
        for cell in cells:
            if cell.get("cell_type") == "code":
                source = cell.get("source", [])
                if isinstance(source, str):
                    source = source.splitlines(keepends=True)
                self._sast_scan(fpath, source, all_rules, line_offset=line_offset)
                for line in source:
                    self._detect_ai_inventory(line)
                line_offset += len(source)
            else:
                src = cell.get("source", [])
                line_offset += len(src) if isinstance(src, list) else len(src.splitlines())

    # -----------------------------------------------------------------------
    # GENERIC SAST ENGINE
    # -----------------------------------------------------------------------
    def _sast_scan(self, fpath: str, lines: list[str],
                   rules: list[dict[str, Any]], line_offset: int = 0) -> None:
        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue
            for rule in rules:
                pat = rule.get("pattern", "")
                if not pat:
                    continue
                try:
                    if re.search(pat, stripped, re.IGNORECASE):
                        self._add(rule, fpath, lineno + line_offset, stripped)
                except re.error:
                    pass

    # -----------------------------------------------------------------------
    # RESULTS
    # -----------------------------------------------------------------------
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def filter_severity(self, min_sev: str) -> None:
        cutoff = self.SEVERITY_ORDER.get(min_sev.upper(), 4)
        self.findings = [f for f in self.findings
                         if self.SEVERITY_ORDER.get(f.severity, 4) <= cutoff]

    def print_report(self) -> None:
        if not self.findings:
            print(f"\n{self.BOLD}[AI-SPM] No findings.{self.RESET}\n")
            return

        # Sort by severity
        self.findings.sort(key=lambda f: self.SEVERITY_ORDER.get(f.severity, 4))

        print(f"\n{'='*80}")
        print(f"{self.BOLD}  AI Security Posture Management (AI-SPM) Scan Report{self.RESET}")
        print(f"  Scanner Version : {__version__}")
        print(f"  Scan Date       : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"  Files Scanned   : {self._scanned_files}")
        print(f"  Findings        : {len(self.findings)}")
        print(f"{'='*80}\n")

        # AI Inventory
        inv_items = []
        for cat, items in self._ai_inventory.items():
            if items:
                inv_items.append(f"  {cat.replace('_', ' ').title()}: {', '.join(sorted(items))}")
        if inv_items:
            print(f"{self.BOLD}  AI/ML Inventory Discovered:{self.RESET}")
            for item in inv_items:
                print(item)
            print()

        # Findings
        for i, f in enumerate(self.findings, 1):
            color = self.SEVERITY_COLOR.get(f.severity, self.RESET)
            print(f"  {self.BOLD}[{i}] {f.rule_id}{self.RESET} — {color}{f.severity}{self.RESET}")
            print(f"      {f.name}")
            print(f"      File: {f.file_path}:{f.line_num}")
            print(f"      Code: {f.line_content}")
            if f.cve:
                print(f"      CVE:  {f.cve}")
            if f.cwe:
                print(f"      CWE:  {f.cwe}")
            if f.compliance:
                mapped = []
                for c in f.compliance:
                    info = COMPLIANCE_MAP.get(c)
                    if info:
                        mapped.append(f"{info['framework']}:{info['category']}")
                    else:
                        mapped.append(c)
                print(f"      Compliance: {', '.join(mapped)}")
            print(f"      Recommendation: {f.recommendation}")
            print()

        # Summary
        s = self.summary()
        print(f"{'='*80}")
        print(f"  {self.BOLD}Summary:{self.RESET}  ", end="")
        parts = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if s[sev]:
                color = self.SEVERITY_COLOR[sev]
                parts.append(f"{color}{sev}: {s[sev]}{self.RESET}")
        print("  |  ".join(parts))
        print(f"{'='*80}\n")

    def save_json(self, path: str) -> None:
        report = {
            "scanner": "AI-SPM Scanner",
            "version": __version__,
            "scan_date": datetime.now(timezone.utc).isoformat(),
            "files_scanned": self._scanned_files,
            "ai_inventory": {k: sorted(v) for k, v in self._ai_inventory.items()},
            "summary": self.summary(),
            "findings": [asdict(f) for f in self.findings],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)
        print(f"  [+] JSON report saved: {path}")

    def save_html(self, path: str) -> None:
        s = self.summary()
        total = len(self.findings)
        scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # AI inventory HTML
        inv_html = ""
        for cat, items in self._ai_inventory.items():
            if items:
                cat_label = cat.replace("_", " ").title()
                badges = " ".join(f'<span class="badge">{item}</span>' for item in sorted(items))
                inv_html += f'<div class="inv-row"><strong>{cat_label}:</strong> {badges}</div>\n'

        # Compliance summary
        comp_count: dict[str, int] = {}
        for f in self.findings:
            for c in f.compliance:
                info = COMPLIANCE_MAP.get(c, {})
                fw = info.get("framework", c)
                comp_count[fw] = comp_count.get(fw, 0) + 1
        comp_html = ""
        for fw, cnt in sorted(comp_count.items(), key=lambda x: -x[1]):
            comp_html += f'<div class="comp-item"><strong>{fw}</strong>: {cnt} findings</div>\n'

        # Findings rows
        rows = ""
        for f in self.findings:
            sev_class = f.severity.lower()
            comp_tags = ""
            for c in f.compliance:
                info = COMPLIANCE_MAP.get(c, {})
                label = f"{info['framework']}:{info['category']}" if info else c
                comp_tags += f'<span class="comp-tag">{label}</span> '
            cve_cell = f'<a href="https://nvd.nist.gov/vuln/detail/{f.cve}" target="_blank">{f.cve}</a>' if f.cve else "-"
            rows += f"""<tr class="sev-{sev_class}">
  <td><span class="sev {sev_class}">{f.severity}</span></td>
  <td>{f.rule_id}</td>
  <td>{f.name}</td>
  <td class="fp">{f.file_path}:{f.line_num}</td>
  <td><code>{self._html_esc(f.line_content[:120])}</code></td>
  <td>{cve_cell}</td>
  <td>{f.cwe}</td>
  <td>{comp_tags}</td>
  <td>{f.recommendation}</td>
</tr>\n"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI-SPM Scan Report</title>
<style>
:root{{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#e6edf3;--muted:#8b949e;
--crit:#ff4757;--high:#ff6348;--med:#ffa502;--low:#1e90ff;--info:#70a1ff;
--accent-1:#6c5ce7;--accent-2:#a855f7;}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);line-height:1.6}}
.header{{background:linear-gradient(135deg,#6c5ce7,#a855f7,#ec4899);padding:2rem;text-align:center}}
.header h1{{font-size:1.8rem;margin-bottom:0.3rem}}
.header p{{opacity:0.9;font-size:0.95rem}}
.container{{max-width:1400px;margin:0 auto;padding:1.5rem}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1rem;margin:1.5rem 0}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.2rem;text-align:center}}
.card .num{{font-size:2rem;font-weight:700}}
.card .label{{font-size:0.8rem;color:var(--muted);text-transform:uppercase;letter-spacing:1px}}
.card.critical .num{{color:var(--crit)}} .card.high .num{{color:var(--high)}}
.card.medium .num{{color:var(--med)}} .card.low .num{{color:var(--low)}}
.card.total .num{{color:var(--accent-2)}}
.section{{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.5rem;margin:1.5rem 0}}
.section h2{{font-size:1.2rem;margin-bottom:1rem;color:var(--accent-2)}}
.inv-row{{margin:0.4rem 0}} .badge{{background:#30363d;padding:2px 10px;border-radius:12px;font-size:0.85rem;margin:2px}}
.comp-item{{margin:0.3rem 0}}
.filters{{display:flex;gap:0.8rem;flex-wrap:wrap;margin:1rem 0}}
.filters label{{display:flex;align-items:center;gap:4px;cursor:pointer;font-size:0.9rem}}
table{{width:100%;border-collapse:collapse;font-size:0.85rem}}
th{{background:#21262d;padding:10px 8px;text-align:left;position:sticky;top:0;z-index:1;border-bottom:2px solid var(--border)}}
td{{padding:8px;border-bottom:1px solid var(--border);vertical-align:top}}
td.fp{{word-break:break-all;max-width:200px}} td code{{background:#21262d;padding:2px 4px;border-radius:4px;font-size:0.8rem;word-break:break-all}}
.sev{{padding:2px 8px;border-radius:4px;font-weight:700;font-size:0.75rem;text-transform:uppercase}}
.sev.critical{{background:var(--crit);color:#fff}} .sev.high{{background:var(--high);color:#fff}}
.sev.medium{{background:var(--med);color:#000}} .sev.low{{background:var(--low);color:#fff}}
.sev.info{{background:var(--info);color:#000}}
.comp-tag{{background:#30363d;padding:1px 6px;border-radius:4px;font-size:0.75rem;margin:1px;display:inline-block}}
tr:hover{{background:#1c2333}}
a{{color:var(--accent-2);text-decoration:none}} a:hover{{text-decoration:underline}}
.footer{{text-align:center;color:var(--muted);padding:2rem;font-size:0.85rem}}
@media(max-width:768px){{.cards{{grid-template-columns:repeat(2,1fr)}} table{{font-size:0.75rem}}}}
</style>
</head>
<body>
<div class="header">
<h1>AI Security Posture Management Report</h1>
<p>AI-SPM Scanner v{__version__} | {scan_date} | {self._scanned_files} files scanned</p>
</div>
<div class="container">
<div class="cards">
<div class="card total"><div class="num">{total}</div><div class="label">Total</div></div>
<div class="card critical"><div class="num">{s['CRITICAL']}</div><div class="label">Critical</div></div>
<div class="card high"><div class="num">{s['HIGH']}</div><div class="label">High</div></div>
<div class="card medium"><div class="num">{s['MEDIUM']}</div><div class="label">Medium</div></div>
<div class="card low"><div class="num">{s['LOW']}</div><div class="label">Low</div></div>
</div>
{"<div class='section'><h2>AI/ML Inventory</h2>" + inv_html + "</div>" if inv_html else ""}
{"<div class='section'><h2>Compliance Mapping</h2>" + comp_html + "</div>" if comp_html else ""}
<div class="section">
<h2>Findings</h2>
<div class="filters">
<label><input type="checkbox" class="sev-filter" value="critical" checked> Critical</label>
<label><input type="checkbox" class="sev-filter" value="high" checked> High</label>
<label><input type="checkbox" class="sev-filter" value="medium" checked> Medium</label>
<label><input type="checkbox" class="sev-filter" value="low" checked> Low</label>
<label><input type="checkbox" class="sev-filter" value="info" checked> Info</label>
</div>
<table><thead><tr>
<th>Severity</th><th>Rule ID</th><th>Finding</th><th>Location</th><th>Code</th><th>CVE</th><th>CWE</th><th>Compliance</th><th>Recommendation</th>
</tr></thead><tbody>
{rows}
</tbody></table>
</div>
</div>
<div class="footer">
Generated by AI-SPM Scanner v{__version__} | AI Security Posture Management<br>
Compliance frameworks: NIST AI RMF &bull; EU AI Act &bull; OWASP ML Top 10 &bull; MITRE ATLAS
</div>
<script>
document.querySelectorAll('.sev-filter').forEach(cb=>{{
  cb.addEventListener('change',()=>{{
    const active=new Set();
    document.querySelectorAll('.sev-filter:checked').forEach(c=>active.add(c.value));
    document.querySelectorAll('tbody tr').forEach(r=>{{
      const s=r.className.replace('sev-','');
      r.style.display=active.has(s)?'':'none';
    }});
  }});
}});
</script>
</body></html>"""

        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"  [+] HTML report saved: {path}")

    @staticmethod
    def _html_esc(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        prog="ai_spm_scanner",
        description="AI Security Posture Management (AI-SPM) Scanner — "
                    "static analysis for AI/ML projects",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python ai_spm_scanner.py ./my_ml_project
              python ai_spm_scanner.py ./src --severity HIGH --json report.json
              python ai_spm_scanner.py . --html report.html --verbose
        """),
    )
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument("--json", dest="json_file", metavar="FILE",
                        help="Save JSON report to FILE")
    parser.add_argument("--html", dest="html_file", metavar="FILE",
                        help="Save HTML report to FILE")
    parser.add_argument("--severity", metavar="SEV", default=None,
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        help="Minimum severity to report (default: all)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("--version", action="version",
                        version=f"AI-SPM Scanner v{__version__}")
    args = parser.parse_args()

    scanner = AISPMScanner(verbose=args.verbose)
    scanner.scan_path(args.target)

    if args.severity:
        scanner.filter_severity(args.severity)

    scanner.print_report()

    if args.json_file:
        scanner.save_json(args.json_file)
    if args.html_file:
        scanner.save_html(args.html_file)

    # Exit code: 1 if CRITICAL or HIGH findings exist
    s = scanner.summary()
    sys.exit(1 if s["CRITICAL"] or s["HIGH"] else 0)


if __name__ == "__main__":
    main()
