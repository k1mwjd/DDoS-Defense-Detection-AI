from __future__ import annotations

from pathlib import Path
from typing import Dict
from typing import List

import pandas as pd
from fastapi import FastAPI, HTTPException

from app.config import DEFAULT_BLOCK_SECONDS, DEFAULT_DEFENSE_THRESHOLD, DEFAULT_MODEL_PATH, ENABLE_WINDOWS_FIREWALL, FEATURE_COLUMNS
from app.schemas import (
    AnalyzeLiveRequest,
    AnalyzePcapRequest,
    BlockedSourceListResponse,
    FlowAnalysisResponse,
    FlowAnalysisSummary,
    HealthResponse,
    PredictionRequest,
    PredictionResponse,
)
from app.services.defense import DefenseManager
from app.services.flow_analysis import analyze_live_interface, analyze_pcap_file, write_analysis_logs
from app.services.inference import ModelInferenceService


app = FastAPI(
    title="AI DDoS Firewall Backend",
    version="1.0.0",
    description="VM1 backend for model inference, packet capture analysis, and defense actions.",
)

inference_service = ModelInferenceService(model_path=DEFAULT_MODEL_PATH)
defense_manager = DefenseManager(
    threshold=DEFAULT_DEFENSE_THRESHOLD,
    block_seconds=DEFAULT_BLOCK_SECONDS,
    enable_windows_firewall=ENABLE_WINDOWS_FIREWALL,
)


@app.on_event("startup")
def startup_event() -> None:
    inference_service.load()


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        model_path=str(Path(DEFAULT_MODEL_PATH).resolve()),
        required_feature_count=len(FEATURE_COLUMNS),
        windows_firewall_enabled=ENABLE_WINDOWS_FIREWALL,
    )


@app.post("/predict", response_model=PredictionResponse)
def predict(request: PredictionRequest) -> PredictionResponse:
    try:
        result = inference_service.predict_from_feature_dict(request.features)
        decision = defense_manager.evaluate(result.prediction, result.attack_probability, request.source_ip)
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail=f"Model file not found: {exc}") from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {exc}") from exc

    return PredictionResponse(
        prediction=result.prediction,
        attack_probability=result.attack_probability,
        risk_score=decision.risk_score,
        risk_level=decision.risk_level,
        action_taken=decision.action_taken,
        should_block=decision.should_block,
        reason=decision.reason,
        source_ip=request.source_ip,
        destination_ip=request.destination_ip,
        flow_id=request.flow_id,
    )


def _run_batch_analysis(df: pd.DataFrame, apply_defense: bool, prefix: str) -> FlowAnalysisResponse:
    if df.empty:
        csv_path, json_path = write_analysis_logs(df, prefix)
        return FlowAnalysisResponse(
            summary=FlowAnalysisSummary(
                total_flows=0,
                attack_flows=0,
                benign_flows=0,
                blocked_sources=defense_manager.list_blocked_sources(),
                log_csv_path=csv_path,
                log_json_path=json_path,
            ),
            results=[],
        )

    predicted_df = inference_service.predict_dataframe(df)
    results: List[Dict[str, object]] = []

    for record in predicted_df.to_dict(orient="records"):
        decision = defense_manager.evaluate(
            int(record["prediction"]),
            float(record["attack_probability"]),
            str(record.get("source_ip")) if apply_defense else None,
        )
        record["risk_score"] = decision.risk_score
        record["risk_level"] = decision.risk_level
        record["action_taken"] = decision.action_taken
        record["should_block"] = decision.should_block
        record["reason"] = decision.reason
        results.append(record)

    output_df = pd.DataFrame(results)
    csv_path, json_path = write_analysis_logs(output_df, prefix)
    attack_flows = int((output_df["prediction"] == 1).sum())
    benign_flows = int((output_df["prediction"] == 0).sum())

    return FlowAnalysisResponse(
        summary=FlowAnalysisSummary(
            total_flows=len(output_df),
            attack_flows=attack_flows,
            benign_flows=benign_flows,
            blocked_sources=defense_manager.list_blocked_sources(),
            log_csv_path=csv_path,
            log_json_path=json_path,
        ),
        results=results,
    )


@app.post("/analyze/pcap", response_model=FlowAnalysisResponse)
def analyze_pcap(request: AnalyzePcapRequest) -> FlowAnalysisResponse:
    pcap_path = Path(request.pcap_path)
    if not pcap_path.exists():
        raise HTTPException(status_code=404, detail=f"PCAP file not found: {pcap_path}")

    try:
        df = analyze_pcap_file(pcap_path, packet_limit=request.packet_limit)
        return _run_batch_analysis(df, request.apply_defense, "pcap_analysis")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"PCAP analysis failed: {exc}") from exc


@app.post("/analyze/live", response_model=FlowAnalysisResponse)
def analyze_live(request: AnalyzeLiveRequest) -> FlowAnalysisResponse:
    try:
        df = analyze_live_interface(
            interface=request.interface,
            duration_seconds=request.duration_seconds,
            packet_limit=request.packet_limit,
        )
        return _run_batch_analysis(df, request.apply_defense, "live_analysis")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Live packet analysis failed: {exc}") from exc


@app.get("/blocked-sources", response_model=BlockedSourceListResponse)
def get_blocked_sources() -> BlockedSourceListResponse:
    return BlockedSourceListResponse(blocked_sources=defense_manager.list_blocked_sources())


@app.delete("/blocked-sources/{source_ip}")
def unblock_source(source_ip: str) -> Dict[str, object]:
    try:
        removed = defense_manager.unblock(source_ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid source_ip: {exc}") from exc
    return {"source_ip": source_ip, "removed": removed}
