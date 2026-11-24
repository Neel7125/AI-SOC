"""One-shot demo setup: data -> train -> ML evaluation -> pipeline -> RAG/LLM/SOC experiments -> academic report.
Usage: python scripts/setup_demo.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def run_full_setup(progress=print) -> None:
    from detection.pipeline import run_pipeline
    from evaluation.comparison import run_comparison
    from evaluation.llm_evaluation import run_llm_evaluation
    from evaluation.ml_evaluation import run_ml_evaluation
    from ingestion.synthetic import generate_all
    from ml_engine.train import train_all
    from rag.retriever import build_index
    from reporting.academic_report import build_academic_report

    progress("1/7 generating SYNTHETIC data"); progress(generate_all())
    progress("2/7 training models (RF, XGBoost, LR, Isolation Forest)"); progress(train_all())
    progress("3/7 ML evaluation charts/metrics"); run_ml_evaluation()
    progress("4/7 detection pipeline -> database"); progress(run_pipeline())
    progress("5/7 building RAG index"); build_index()
    progress("6/7 LLM evaluation + SOC comparison"); run_llm_evaluation(); run_comparison()
    progress("7/7 academic report"); progress(build_academic_report())
    progress("DONE")


if __name__ == "__main__":
    run_full_setup()
