# UNSW_NB15 Independent Evaluation Report

**Dataset:** UNSW-NB15
**Model:** Random Forest (100 Trees, `class_weight='balanced_subsample'`, Random State 42)
**Partition:** Stratified 80/20 Holdout (65865 train, 16467 test)

## Summary Metrics

| Metric | Value |
|---|---:|
| **Overall Accuracy** | 0.8751 |
| **Binary Precision** | 0.9907 |
| **Binary Recall** | 0.9596 |
| **Binary F1 Score** | 0.9749 |
| **False Positive Rate (FPR)** | 0.0111 |
| **Binary ROC-AUC** | 0.9972 |
| **Binary PR-AUC** | 0.9978 |
| **Macro F1 Score** | 0.7315 |
| **Balanced Accuracy** | 0.7266 |
| **Inference Throughput** | 148351.4 samples/sec |

## Per-Class Performance

| Class | Precision | Recall | F1-Score | Support |
|---|---:|---:|---:|---:|
| **DoS** | 0.4021 | 0.5978 | 0.4808 | 818 |
| **Normal** | 0.9524 | 0.9889 | 0.9703 | 7400 |
| **Other** | 0.9964 | 0.9635 | 0.9797 | 3783 |
| **Probe** | 0.7747 | 0.7020 | 0.7365 | 2047 |
| **R2L** | 0.7440 | 0.6338 | 0.6845 | 2343 |
| **U2R** | 0.6207 | 0.4737 | 0.5373 | 76 |

## Confusion Matrix

Labels (rows=true, cols=pred): `['DoS', 'Normal', 'Other', 'Probe', 'R2L', 'U2R']`

```text
[[ 489,   23,    5,   84,  212,    5],
 [   1, 7318,    1,   62,   12,    6],
 [  11,   23, 3645,    5,   98,    1],
 [ 214,  213,    1, 1437,  178,    4],
 [ 500,   92,    3,  257, 1485,    6],
 [   1,   15,    3,   10,   11,   36]]
```

## Reproduction Command

```powershell
python scripts/train_dataset_models.py --dataset unsw_nb15
```
