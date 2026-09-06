"""
PhishGuard - Model Evaluation Module
Evaluates the trained phishing detection model on the test dataset.
Generates:
  1. Terminal summary of Accuracy, Precision, Recall, F1 Score, Confusion Matrix
  2. Visual Confusion Matrix plot saved to ../screenshots/confusion_matrix.png
"""

import os
import json
import joblib
import numpy as np
import matplotlib
# Use non-interactive Agg backend for script execution
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

def evaluate():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(base_dir)
    model_path = os.path.join(project_root, "model", "phishing_model.pkl")
    metadata_path = os.path.join(project_root, "model", "model_metadata.json")
    test_data_path = os.path.join(project_root, "model", "test_data.pkl")
    screenshots_dir = os.path.join(project_root, "screenshots")
    os.makedirs(screenshots_dir, exist_ok=True)
    plot_path = os.path.join(screenshots_dir, "confusion_matrix.png")

    print("=" * 65)
    print("      PHISHGUARD - MACHINE LEARNING MODEL EVALUATION")
    print("=" * 65)

    # 1. Load model and metadata
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model file missing at {model_path}. Please run train_model.py first.")
    
    model = joblib.load(model_path)
    print(f"[*] Loaded trained model: {model.__class__.__name__}")

    metadata = {}
    if os.path.exists(metadata_path):
        with open(metadata_path, "r", encoding="utf-8") as f:
            metadata = json.load(f)
        print(f"[*] Champion Algorithm:   {metadata.get('best_model', 'Random Forest')}")
        print(f"[*] Training Timestamp:   {metadata.get('trained_at', 'N/A')}")

    # 2. Load test set
    if not os.path.exists(test_data_path):
        raise FileNotFoundError(f"Test dataset cache missing at {test_data_path}. Please rerun train_model.py.")
    
    test_data = joblib.load(test_data_path)
    X_test = test_data["X_test"]
    y_test = test_data["y_test"]
    print(f"[*] Evaluating on {len(y_test)} unseen test samples...")

    # 3. Model predictions
    y_pred = model.predict(X_test)

    # 4. Compute metrics
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    tn, fp, fn, tp = cm.ravel()

    # 5. Display terminal summary
    print("\n" + "-" * 65)
    print("                 PERFORMANCE METRICS SUMMARY")
    print("-" * 65)
    print(f"  • Accuracy:         {acc * 100:.2f}%  (Overall correct classifications)")
    print(f"  • Precision:        {prec * 100:.2f}%  (Phishing URLs flagged accurately)")
    print(f"  • Recall:           {rec * 100:.2f}%  (True phishing URLs caught)")
    print(f"  • F1 Score:         {f1 * 100:.2f}%  (Harmonic mean of Prec & Rec)")
    print("-" * 65)

    print("\n" + "-" * 65)
    print("                     CONFUSION MATRIX")
    print("-" * 65)
    print(f"{'':<20} | {'Predicted Safe (0)':<20} | {'Predicted Phishing (1)':<20}")
    print(f"{'Actual Safe (0)':<20} | {f'TN = {tn}':<20} | {f'FP = {fp}':<20}")
    print(f"{'Actual Phishing (1)':<20} | {f'FN = {fn}':<20} | {f'TP = {tp}':<20}")
    print("-" * 65)

    print("\n[*] Detailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate (0)", "Phishing (1)"]))

    # 6. Generate confusion matrix visualization
    print(f"[*] Generating Confusion Matrix plot...")
    plt.figure(figsize=(7, 6), facecolor="#0d1117")
    ax = plt.subplot(111)
    ax.set_facecolor("#161b22")

    # Custom styling
    cmap = sns.color_palette("Blues", as_cmap=True)
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap=cmap,
        cbar=True,
        xticklabels=["Legitimate (Safe)", "Phishing (Malicious)"],
        yticklabels=["Legitimate (Safe)", "Phishing (Malicious)"],
        annot_kws={"size": 16, "weight": "bold", "color": "#032b43"},
        linewidths=1.5,
        linecolor="#30363d"
    )

    plt.title(
        f"PhishGuard Confusion Matrix ({metadata.get('best_model', 'Random Forest')})\nAccuracy: {acc*100:.1f}% | F1: {f1*100:.1f}%",
        fontsize=13,
        fontweight="bold",
        color="#e6edf3",
        pad=15
    )
    plt.xlabel("Predicted Class", fontsize=12, fontweight="bold", color="#8b949e", labelpad=10)
    plt.ylabel("Actual Class", fontsize=12, fontweight="bold", color="#8b949e", labelpad=10)
    
    # Tick styling
    ax.tick_params(colors="#c9d1d9", labelsize=10)

    plt.tight_layout()
    plt.savefig(plot_path, dpi=300, facecolor=plt.gcf().get_facecolor(), edgecolor="none")
    plt.close()

    print(f"[+] Confusion matrix visualization saved to:")
    print(f"    {plot_path}")
    print("\n[OK] Model evaluation completed successfully!")

if __name__ == "__main__":
    evaluate()
