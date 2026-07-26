"""Re-export run_telemetry_stage for backward compatibility.
Primary implementation lives in src.usecases.step_4_telemetry.telemetry_stage.
"""
from src.usecases.step_4_telemetry.telemetry_stage import run_telemetry_stage

__all__ = ["run_telemetry_stage"]
