"""Train and evaluate the URL model with domain-grouped splits."""
import json
import os
import warnings

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, fbeta_score,
    confusion_matrix, classification_report, roc_auc_score, precision_recall_curve,
)
from sklearn.model_selection import GroupShuffleSplit

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BASE_DIR, "data", "dataset.csv")
MODEL_FILE = os.path.join(BASE_DIR, "phishing_model.joblib")
METRICS_FILE = os.path.join(BASE_DIR, "evaluation_metrics.json")

FEATURE_COLUMNS = [
    "url_length", "hostname_length", "is_https", "dot_count", "hyphen_count",
    "has_at_symbol", "is_ip", "digit_count", "keyword_count", "path_length",
    "num_slashes",
]


def grouped_split(df, test_size, seed):
    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    train_idx, test_idx = next(splitter.split(df, df["label"], groups=df["domain"]))
    return df.iloc[train_idx].copy(), df.iloc[test_idx].copy()


def choose_threshold(y_true, probabilities):
    precision, recall, thresholds = precision_recall_curve(y_true, probabilities)
    if len(thresholds) == 0:
        return 0.5
    # Prefer recall for phishing detection while retaining a measurable precision tradeoff.
    f2 = (5 * precision[:-1] * recall[:-1]) / (4 * precision[:-1] + recall[:-1] + 1e-12)
    best = int(np.nanargmax(f2))
    return float(thresholds[best])


def evaluate(y_true, probabilities, threshold):
    predictions = (probabilities >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, predictions, labels=[0, 1]).ravel()
    metrics = {
        "threshold": round(float(threshold), 5),
        "accuracy": float(accuracy_score(y_true, predictions)),
        "precision": float(precision_score(y_true, predictions, zero_division=0)),
        "recall": float(recall_score(y_true, predictions, zero_division=0)),
        "f1": float(f1_score(y_true, predictions, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, probabilities)) if len(set(y_true)) == 2 else None,
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }
    return metrics, predictions


def train():
    if not os.path.exists(DATA_FILE):
        raise FileNotFoundError(
            f"Dataset not found: {DATA_FILE}. First obtain source CSVs and run build_dataset.py."
        )
    df = pd.read_csv(DATA_FILE)
    required = set(FEATURE_COLUMNS + ["label", "domain"])
    missing = sorted(required - set(df.columns))
    if missing:
        raise ValueError(
            f"Dataset missing columns: {missing}. Rebuild it with the updated build_dataset.py."
        )
    df = df.dropna(subset=FEATURE_COLUMNS + ["label", "domain"]).copy()
    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    df = df[df["label"].isin([0, 1])]
    df["label"] = df["label"].astype(int)
    df = df.drop_duplicates(subset=["url"]) if "url" in df.columns else df
    if df["label"].nunique() != 2:
        raise ValueError("Training requires both label classes (0 and 1).")
    if df["domain"].nunique() < 20:
        raise ValueError("Too few unique domains for a meaningful grouped evaluation; add more source data.")

    # 70/15/15 approximate split, grouped by registrable-domain approximation so sibling subdomains don't cross splits.
    train_val, test = grouped_split(df, 0.15, 42)
    train_df, val_df = grouped_split(train_val, 0.1765, 43)

    # Evaluate the bundled model on the same grouped holdout before replacing it.
    baseline_metrics = None
    if os.path.exists(MODEL_FILE):
        try:
            old_model = joblib.load(MODEL_FILE)
            old_classes = list(getattr(old_model, "classes_", [0, 1]))
            old_phishing_idx = old_classes.index(1)
            old_prob = old_model.predict_proba(test[FEATURE_COLUMNS])[:, old_phishing_idx]
            baseline_metrics, _ = evaluate(test["label"].to_numpy(), old_prob, 0.5)
            print("\\nEXISTING MODEL HOLDOUT METRICS (threshold=0.5)")
            for key, value in baseline_metrics.items():
                print(f"{key}: {value}")
        except Exception as exc:
            warnings.warn(f"Could not evaluate existing model on the new feature table: {exc}")

    model = RandomForestClassifier(
        n_estimators=300, min_samples_leaf=2, class_weight="balanced_subsample",
        random_state=42, n_jobs=-1,
    )
    model.fit(train_df[FEATURE_COLUMNS], train_df["label"])

    classes = list(model.classes_)
    phishing_idx = classes.index(1)
    val_prob = model.predict_proba(val_df[FEATURE_COLUMNS])[:, phishing_idx]
    threshold = choose_threshold(val_df["label"].to_numpy(), val_prob)

    test_prob = model.predict_proba(test[FEATURE_COLUMNS])[:, phishing_idx]
    metrics, predictions = evaluate(test["label"].to_numpy(), test_prob, threshold)
    print("\nDOMAIN-GROUPED HOLDOUT METRICS (test set not used for threshold selection)")
    for key, value in metrics.items():
        print(f"{key}: {value}")
    print("\nClassification report:")
    print(classification_report(test["label"], predictions, labels=[0, 1],
                                target_names=["popular-domain proxy", "phishing"], zero_division=0))
    print("\nConfusion matrix [[TN, FP], [FN, TP]]:")
    print(confusion_matrix(test["label"], predictions, labels=[0, 1]))
    print("\nFeature importance:")
    for name, importance in sorted(zip(FEATURE_COLUMNS, model.feature_importances_),
                                   key=lambda item: item[1], reverse=True):
        print(f"{name}: {importance:.4f}")

    # Keep compatibility with the existing inference API, which consumes a fitted classifier.
    joblib.dump(model, MODEL_FILE)
    metadata = {
        "model": "RandomForestClassifier",
        "features": FEATURE_COLUMNS,
        "threshold_selected_on_validation": round(threshold, 5),
        "split": "GroupShuffleSplit by approximate registrable domain (common compound suffixes included); approximately 70/15/15 train/validation/test",
        "dataset_rows": int(len(df)),
        "unique_domains": int(df["domain"].nunique()),
        "class_counts": {str(k): int(v) for k, v in df["label"].value_counts().sort_index().items()},
        "test_metrics": metrics,
        "existing_model_test_metrics_at_threshold_0_5": baseline_metrics,
        "warning": "Tranco popular-domain membership is a proxy label, not proof of benign status. Metrics are dataset-specific. Baseline and new model use the same grouped holdout; thresholds differ as documented.",
    }
    with open(METRICS_FILE, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"\nSaved model: {MODEL_FILE}")
    print(f"Saved metrics: {METRICS_FILE}")


if __name__ == "__main__":
    train()
