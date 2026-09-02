import pandas as pd
import joblib
import os

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BASE_DIR, "data", "dataset.csv")
MODEL_FILE = os.path.join(BASE_DIR, "phishing_model.joblib")

FEATURE_COLUMNS = [
    "url_length",
    "hostname_length",
    "is_https",
    "dot_count",
    "hyphen_count",
    "has_at_symbol",
    "is_ip",
    "digit_count",
    "keyword_count",
    "path_length",
    "num_slashes",
]


def train():
    print("Loading dataset...")
    df = pd.read_csv(DATA_FILE)

    X = df[FEATURE_COLUMNS]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Training model...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        class_weight="balanced",   # <-- handles the imbalance
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    print("Evaluating model...")
    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    print(f"\nAccuracy:  {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1-score:  {f1:.4f}")

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))

    # Feature importance — useful for your report/PPT
    print("\nFeature Importances:")
    importances = sorted(
        zip(FEATURE_COLUMNS, model.feature_importances_),
        key=lambda x: x[1],
        reverse=True,
    )
    for name, score in importances:
        print(f"  {name}: {score:.4f}")

    joblib.dump(model, MODEL_FILE)
    print(f"\nModel saved to {MODEL_FILE}")


if __name__ == "__main__":
    train()