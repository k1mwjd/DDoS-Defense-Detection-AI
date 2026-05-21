from __future__ import annotations

from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Union

from pydantic import BaseModel, Field


class PredictionRequest(BaseModel):
    source_ip: Optional[str] = Field(default=None, description="Optional source IP used for defense actions.")
    destination_ip: Optional[str] = Field(default=None, description="Optional destination IP for logging.")
    flow_id: Optional[str] = Field(default=None, description="Optional flow identifier.")
    features: Dict[str, Union[float, int]] = Field(..., description="Feature payload matching the trained model schema.")


class PredictionResponse(BaseModel):
    prediction: int
    attack_probability: float
    risk_score: float
    risk_level: str
    action_taken: str
    should_block: bool
    reason: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    flow_id: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    model_path: str
    required_feature_count: int
    windows_firewall_enabled: bool


class BlockedSourceListResponse(BaseModel):
    blocked_sources: List[Dict[str, str]]


class AnalyzePcapRequest(BaseModel):
    pcap_path: str
    apply_defense: bool = False
    packet_limit: Optional[int] = None


class AnalyzeLiveRequest(BaseModel):
    interface: str
    duration_seconds: int = Field(default=10, ge=1, le=300)
    packet_limit: Optional[int] = Field(default=None, ge=1)
    apply_defense: bool = False


class FlowAnalysisSummary(BaseModel):
    total_flows: int
    attack_flows: int
    benign_flows: int
    blocked_sources: List[Dict[str, str]]
    log_csv_path: str
    log_json_path: str


class FlowAnalysisResponse(BaseModel):
    summary: FlowAnalysisSummary
    results: List[Dict[str, Any]]
