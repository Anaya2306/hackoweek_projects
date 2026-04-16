"""
IoT Sensor Data Cleaning Pipeline
===================================
Dataset: Network packet capture (tshark) from a Kaggle IoT dataset
Columns : frame.number, frame.time, frame.len, eth.src/dst,
          ip.src/dst, ip.proto, ip.len, tcp.len, tcp.srcport, tcp.dstport,
          _ws.col.Info

Approach
--------
1. Load with correct `$` delimiter
2. Parse timestamps
3. Report & handle missing values (per-column strategy)
4. Detect & cap/remove outliers (IQR + Z-score)
5. Type-cast & drop duplicates
6. Save cleaned CSV + cleaning report
"""

import pandas as pd
import numpy as np
from scipy import stats
import warnings
warnings.filterwarnings("ignore")

# ── 0. CONFIG ────────────────────────────────────────────────────────────────
RAW_FILE   = "raw_sensor.csv"
CLEAN_FILE = "cleaned_sensor_data.csv"
REPORT     = "cleaning_report.txt"

NUMERIC_COLS = ["frame.len", "ip.len", "tcp.len", "tcp.srcport", "tcp.dstport"]

# Outlier method: "iqr" or "zscore"
OUTLIER_METHOD = "iqr"
IQR_FACTOR     = 3.0          # cap at median ± 3×IQR (less aggressive than 1.5)
ZSCORE_THRESH  = 3.5

# ── 1. LOAD ──────────────────────────────────────────────────────────────────
print("=" * 60)
print("STEP 1 — Loading raw data")
print("=" * 60)

df = pd.read_csv(RAW_FILE, sep=r"\$", engine="python")
print(f"  Rows : {len(df):,}")
print(f"  Cols : {list(df.columns)}")

report_lines = []
report_lines.append("IoT SENSOR DATA — CLEANING REPORT")
report_lines.append("=" * 60)
report_lines.append(f"Raw shape: {df.shape[0]:,} rows × {df.shape[1]} cols\n")

# ── 2. TIMESTAMP PARSING ─────────────────────────────────────────────────────
print("\nSTEP 2 — Parsing timestamps")

# Example: "Feb 16, 2020 12:37:22.736684743 IST"
# Truncate sub-second precision beyond 6 digits (Python limit)
def parse_tshark_time(ts: str) -> pd.Timestamp:
    # strip timezone label, keep 6 decimal places
    ts = ts.strip()
    ts = ts.rsplit(" ", 1)[0]          # remove "IST" / "UTC" etc.
    parts = ts.split(".")
    if len(parts) == 2:
        ts = parts[0] + "." + parts[1][:6]   # microseconds only
    try:
        return pd.to_datetime(ts, format="%b %d, %Y %H:%M:%S.%f")
    except Exception:
        return pd.NaT

df["timestamp"] = df["frame.time"].apply(parse_tshark_time)
bad_ts = df["timestamp"].isna().sum()
print(f"  Parsed OK : {len(df) - bad_ts:,}")
print(f"  Failed    : {bad_ts:,}")
report_lines.append(f"Timestamp parse failures: {bad_ts}")

# Sort by time
df.sort_values("timestamp", inplace=True)
df.reset_index(drop=True, inplace=True)

# ── 3. MISSING VALUES ────────────────────────────────────────────────────────
print("\nSTEP 3 — Missing values")

missing = df.isnull().sum()
missing_pct = (missing / len(df) * 100).round(2)
mv_summary = pd.concat([missing, missing_pct], axis=1,
                        keys=["count", "pct%"])
print(mv_summary[mv_summary["count"] > 0].to_string())
report_lines.append("\n--- Missing Values (before cleaning) ---")
report_lines.append(mv_summary[mv_summary["count"] > 0].to_string())

# Strategy per column:
#
# ip.src / ip.dst   — missing because packet is non-IP (e.g., ARP).
#   → fill with "NON_IP"
#
# ip.proto          — same root cause as ip.src/ip.dst.
#   → fill with -1 (sentinel for non-IP)
#
# ip.len            — fill with frame.len (frame length is always present
#                     and equals the IP packet length for ethernet)
#
# tcp.len / tcp.srcport / tcp.dstport — missing because packet is not TCP.
#   → fill with 0 (zero payload / no port concept)

df["ip.src"]  = df["ip.src"].fillna("NON_IP")
df["ip.dst"]  = df["ip.dst"].fillna("NON_IP")
df["ip.proto"] = df["ip.proto"].fillna(-1).astype(int)
df["ip.len"]  = df["ip.len"].fillna(df["frame.len"])
df["tcp.len"] = df["tcp.len"].fillna(0)
df["tcp.srcport"] = df["tcp.srcport"].fillna(0)
df["tcp.dstport"] = df["tcp.dstport"].fillna(0)

# Cast ports to int now that NaNs are gone
for col in ["tcp.srcport", "tcp.dstport", "ip.len", "tcp.len"]:
    df[col] = df[col].astype(int)

remaining_missing = df.isnull().sum().sum()
print(f"\n  Remaining missing cells after fill : {remaining_missing}")
report_lines.append(f"\nRemaining missing after filling: {remaining_missing}")

# ── 4. DUPLICATES ────────────────────────────────────────────────────────────
print("\nSTEP 4 — Duplicate rows")

before_dup = len(df)
# frame.number should be unique; duplicates can appear in replayed captures
df.drop_duplicates(subset=["frame.number"], inplace=True)
removed_dup = before_dup - len(df)
print(f"  Removed {removed_dup:,} duplicate rows (same frame.number)")
report_lines.append(f"\nDuplicate rows removed: {removed_dup:,}")

# ── 5. OUTLIER DETECTION & TREATMENT ─────────────────────────────────────────
print(f"\nSTEP 5 — Outlier treatment ({OUTLIER_METHOD.upper()})")
report_lines.append(f"\n--- Outlier Treatment ({OUTLIER_METHOD.upper()}) ---")

outlier_stats = {}

for col in NUMERIC_COLS:
    series = df[col].copy()
    n_before = len(series)

    if OUTLIER_METHOD == "iqr":
        Q1  = series.quantile(0.25)
        Q3  = series.quantile(0.75)
        IQR = Q3 - Q1
        lo  = Q1 - IQR_FACTOR * IQR
        hi  = Q3 + IQR_FACTOR * IQR
        # For sensor/network data we cap (winsorise) rather than drop,
        # so we don't lose valid records just because a packet is large
        n_outliers = int(((series < lo) | (series > hi)).sum())
        # Hard floor: lengths can't be negative
        lo = max(lo, 0)
        df[col] = series.clip(lower=lo, upper=hi)
        method_info = f"IQR×{IQR_FACTOR}: [{lo:.1f}, {hi:.1f}]"

    else:  # zscore
        z = np.abs(stats.zscore(series, nan_policy="omit"))
        n_outliers = int((z > ZSCORE_THRESH).sum())
        # Cap at the boundary values
        mean, std = series.mean(), series.std()
        lo = max(mean - ZSCORE_THRESH * std, 0)
        hi = mean + ZSCORE_THRESH * std
        df[col] = series.clip(lower=lo, upper=hi)
        method_info = f"Z>{ZSCORE_THRESH}: [{lo:.1f}, {hi:.1f}]"

    outlier_stats[col] = {"outliers": n_outliers, "bounds": method_info}
    print(f"  {col:<15}  outliers={n_outliers:>6,}   capped to {method_info}")
    report_lines.append(f"  {col:<15}  outliers={n_outliers:>6,}   {method_info}")

# ── 6. FEATURE ENGINEERING (bonus) ──────────────────────────────────────────
print("\nSTEP 6 — Lightweight feature engineering")

# Derived columns useful for ML / anomaly detection
df["is_tcp"]     = (df["ip.proto"] == 6).astype(int)
df["is_udp"]     = (df["ip.proto"] == 17).astype(int)
df["is_non_ip"]  = (df["ip.proto"] == -1).astype(int)

# Hour-of-day (useful for temporal anomaly models)
df["hour"] = df["timestamp"].dt.hour

# payload ratio — how much of the frame is actual TCP data
df["tcp_payload_ratio"] = np.where(
    df["frame.len"] > 0,
    df["tcp.len"] / df["frame.len"],
    0.0
).round(4)

print("  Added: is_tcp, is_udp, is_non_ip, hour, tcp_payload_ratio")
report_lines.append("\nNew columns added: is_tcp, is_udp, is_non_ip, hour, tcp_payload_ratio")

# ── 7. FINAL SUMMARY ─────────────────────────────────────────────────────────
print("\nSTEP 7 — Final state")

print(f"  Final shape : {df.shape[0]:,} rows × {df.shape[1]} cols")
print(f"  Date range  : {df['timestamp'].min()} → {df['timestamp'].max()}")
print(f"  Missing     : {df.isnull().sum().sum()} cells")

report_lines.append(f"\n--- Final State ---")
report_lines.append(f"Shape       : {df.shape[0]:,} rows × {df.shape[1]} cols")
report_lines.append(f"Date range  : {df['timestamp'].min()} → {df['timestamp'].max()}")
report_lines.append(f"Missing     : {df.isnull().sum().sum()} cells")
report_lines.append("\nFinal dtypes:")
report_lines.append(df.dtypes.to_string())
report_lines.append("\nNumeric summary (cleaned):")
report_lines.append(df[NUMERIC_COLS].describe().round(2).to_string())

# ── 8. SAVE ───────────────────────────────────────────────────────────────────
df.to_csv(CLEAN_FILE, index=False)
print(f"\n  Saved cleaned data → {CLEAN_FILE}")

with open(REPORT, "w") as f:
    f.write("\n".join(report_lines))
print(f"  Saved cleaning report → {REPORT}")

print("\n✓ Pipeline complete.")
