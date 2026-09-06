"""
PhishGuard - Model Training Pipeline
Trains and compares three classification algorithms:
  1. Logistic Regression
  2. Decision Tree Classifier
  3. Random Forest Classifier

Selects the best performing model based on F1 Score and saves it to:
  ../model/phishing_model.pkl
Also saves training metadata to ../model/model_metadata.json
"""

import os
import json
import joblib
import pandas as pd
import numpy as np
from datetime import datetime

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# Import the feature extractor module
from feature_extractor import extract_features, FEATURE_NAMES

def load_and_preprocess_dataset(dataset_path: str):
    """
    Loads raw URL dataset, cleans missing entries, and extracts features.
    """
    print(f"[*] Loading dataset from: {dataset_path}")
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset file not found at {dataset_path}. Please run generate_dataset.py first.")

    df = pd.read_csv(dataset_path)
    print(f"[*] Initial dataset shape: {df.shape}")

    # Drop null or missing values
    df.dropna(subset=["url", "label"], inplace=True)
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"] != ""]

    # Remove duplicate URLs
    df.drop_duplicates(subset=["url"], inplace=True)
    df["label"] = df["label"].astype(int)

    print(f"[*] Cleaned dataset shape: {df.shape}")
    print(f"    - Legitimate (0): {(df['label'] == 0).sum()} samples")
    print(f"    - Phishing   (1): {(df['label'] == 1).sum()} samples")

    print("[*] Extracting numerical features from URLs...")
    # Extract features for all URLs in dataset
    X_list = [extract_features(url) for url in df["url"]]
    X = np.array(X_list)
    y = df["label"].values

    return X, y, df

def train_and_evaluate_models(X_train, X_test, y_train, y_test):
    """
    Trains Logistic Regression, Decision Tree, and Random Forest.
    Returns comparison metrics and trained model instances.
    """
    models = {
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
        "Decision Tree": DecisionTreeClassifier(max_depth=12, random_state=42),
        "Random Forest": RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42)
    }

    results = {}
    print("\n" + "=" * 60)
    print("       MODEL TRAINING & PERFORMANCE EVALUATION")
    print("=" * 60)
    print(f"{'Algorithm':<22} | {'Accuracy':<9} | {'Precision':<9} | {'Recall':<9} | {'F1 Score':<9}")
    print("-" * 65)

    for name, model in models.items():
        # Train model
        model.fit(X_train, y_train)

        # Predict on test set
        y_pred = model.predict(X_test)

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)

        results[name] = {
            "model": model,
            "accuracy": round(float(acc) * 100, 2),
            "precision": round(float(prec) * 100, 2),
            "recall": round(float(rec) * 100, 2),
            "f1_score": round(float(f1) * 100, 2)
        }

        print(f"{name:<22} | {acc * 100:>8.2f}% | {prec * 100:>8.2f}% | {rec * 100:>8.2f}% | {f1 * 100:>8.2f}%")

    print("-" * 65)
    return results

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(base_dir)
    dataset_file = os.path.join(project_root, "dataset", "urls.csv")
    model_dir = os.path.join(project_root, "model")
    os.makedirs(model_dir, exist_ok=True)

    # 1. Load data and extract features
    X, y, df = load_and_preprocess_dataset(dataset_file)

    # 2. 80/20 Stratified train-test split
    print("\n[*] Splitting dataset: 80% Training, 20% Testing (Stratified)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"    - Training set: {X_train.shape[0]} samples")
    print(f"    - Testing set:  {X_test.shape[0]} samples")

    # 3. Train and compare models
    results = train_and_evaluate_models(X_train, X_test, y_train, y_test)

    # 4. Automatically select the best model based on F1 Score
    best_model_name = max(results, key=lambda k: (results[k]["f1_score"], results[k]["accuracy"]))
    best_model_data = results[best_model_name]
    best_model = best_model_data["model"]

    print(f"\n[+] Champion Model Selected: {best_model_name}")
    print(f"    - F1 Score: {best_model_data['f1_score']}%")
    print(f"    - Accuracy: {best_model_data['accuracy']}%")

    # 5. Save the best model with Joblib
    model_save_path = os.path.join(model_dir, "phishing_model.pkl")
    joblib.dump(best_model, model_save_path)
    print(f"[+] Model saved successfully to: {model_save_path}")

    # 6. Save metadata for backend & frontend transparency
    comparison_summary = {
        name: {
            "accuracy": data["accuracy"],
            "precision": data["precision"],
            "recall": data["recall"],
            "f1_score": data["f1_score"]
        }
        for name, data in results.items()
    }

    metadata = {
        "best_model": best_model_name,
        "metrics": {
            "accuracy": best_model_data["accuracy"],
            "precision": best_model_data["precision"],
            "recall": best_model_data["recall"],
            "f1_score": best_model_data["f1_score"]
        },
        "all_models": comparison_summary,
        "feature_names": FEATURE_NAMES,
        "dataset_stats": {
            "total_samples": int(len(df)),
            "legitimate_samples": int((df["label"] == 0).sum()),
            "phishing_samples": int((df["label"] == 1).sum()),
            "train_samples": int(len(X_train)),
            "test_samples": int(len(X_test))
        },
        "trained_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    metadata_path = os.path.join(model_dir, "model_metadata.json")
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=4)
    print(f"[+] Metadata saved to: {metadata_path}")

    # Also save test set arrays for evaluate_model.py
    test_data_path = os.path.join(model_dir, "test_data.pkl")
    joblib.dump({"X_test": X_test, "y_test": y_test}, test_data_path)
    print(f"[+] Test data cache saved for evaluation: {test_data_path}")

    print("\n[OK] Model training pipeline completed successfully!")

if __name__ == "__main__":
    main()
