"""Alert prioritisation by risk score."""
from __future__ import annotations

import pandas as pd


def prioritize(df: pd.DataFrame, by: str = "risk_score") -> pd.DataFrame:
    if df.empty:
        return df
    return df.sort_values([by, "created_at"], ascending=[False, True]).reset_index(drop=True)
