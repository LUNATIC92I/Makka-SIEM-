"""Structured output contract of the AI analysis (validated before storage)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

EvidenceIds = list[str]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ObservedIndicator(_Strict):
    indicator: str = Field(max_length=2048)
    type: str = Field(max_length=16)
    note: str = Field(max_length=1000)


class SourceSummary(_Strict):
    source: str = Field(max_length=100)
    summary: str = Field(max_length=2000)
    evidence_ids: EvidenceIds


class Fact(_Strict):
    statement: str = Field(max_length=2000)
    evidence_ids: EvidenceIds = Field(min_length=1)


class Hypothesis(_Strict):
    statement: str = Field(max_length=2000)
    rationale: str = Field(max_length=2000)
    evidence_ids: EvidenceIds
    how_to_verify: str = Field(max_length=2000)


class Contradiction(_Strict):
    description: str = Field(max_length=2000)
    evidence_ids: EvidenceIds


class AlternativeHypothesis(_Strict):
    statement: str = Field(max_length=2000)
    rationale: str = Field(max_length=2000)


class MitreTechnique(_Strict):
    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    name: str = Field(max_length=200)
    justification: str = Field(max_length=2000)
    evidence_ids: EvidenceIds = Field(min_length=1)


class Assessment(_Strict):
    level: str = Field(max_length=32)
    rationale: str = Field(max_length=2000)


class Action(_Strict):
    action: str = Field(max_length=1000)
    priority: Literal["haute", "moyenne", "basse"]
    requires_human_validation: bool


class Reference(_Strict):
    evidence_id: str = Field(max_length=16)
    source: str = Field(max_length=100)
    url: str | None = Field(default=None, max_length=1024)


class Attribution(_Strict):
    actor: str = Field(max_length=200)
    evidence_ids: EvidenceIds = Field(min_length=1)
    confidence: Literal["faible", "moyenne", "élevée"]
    alternatives: list[str]


class AIAnalysisOutput(_Strict):
    executive_summary: str = Field(max_length=4000)
    initial_event: str = Field(max_length=3000)
    observed_indicators: list[ObservedIndicator]
    osint_results: list[SourceSummary]
    established_facts: list[Fact]
    hypotheses: list[Hypothesis]
    contradictions: list[Contradiction]
    missing_information: list[str]
    alternative_hypotheses: list[AlternativeHypothesis]
    mitre_attack: list[MitreTechnique]
    estimated_risk: Assessment
    confidence: Assessment
    recommended_actions: list[Action]
    references: list[Reference]
    limitations: list[str]
    threat_actor_attribution: list[Attribution]


def strict_json_schema() -> dict:
    """JSON schema with every property required and no additional properties (structured outputs)."""
    schema = AIAnalysisOutput.model_json_schema()
    defs = schema.pop("$defs", {})

    def resolve(node):  # noqa: ANN001, ANN202
        if isinstance(node, dict):
            if "$ref" in node:
                return resolve(defs[node["$ref"].split("/")[-1]])
            out = {k: resolve(v) for k, v in node.items() if k not in ("title", "default", "maxLength", "minLength", "pattern")}
            if out.get("type") == "object" and "properties" in out:
                out["additionalProperties"] = False
                out["required"] = list(out["properties"].keys())
            return out
        if isinstance(node, list):
            return [resolve(v) for v in node]
        return node

    return resolve(schema)
