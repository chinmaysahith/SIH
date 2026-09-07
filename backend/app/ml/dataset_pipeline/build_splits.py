"""Splitting and deduplication orchestrator for Stage 4.5 real-world datasets.

Deduplicates across content hashes, performs stratified 70/15/15 train/val/test splitting
with random_state=42, verifies zero leakage, and writes processed artifacts.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Set

from sklearn.model_selection import train_test_split

from app.ml.dataset_pipeline.extractors import (
    extract_enron_csv_sampled,
    extract_nazario_mbox,
    extract_spamassassin_archive,
)
from app.ml.dataset_pipeline.models import EmailSample

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("build_splits")

DATASETS_DIR = Path("ml_datasets")
OUTPUT_PROCESSED_DIR = Path("data/ml/processed")
OUTPUT_METADATA_DIR = Path("data/ml/metadata")
OUTPUT_REPORTS_DIR = Path("data/ml/reports")


def run_pipeline():
    logger.info("Step 1: Extracting Nazario Phishing corpora...")
    naz_2024 = list(extract_nazario_mbox(DATASETS_DIR / "phishing" / "phishing-2024", "nazario-2024", target_label=1))
    naz_2025 = list(extract_nazario_mbox(DATASETS_DIR / "phishing" / "phishing-2025", "nazario-2025", target_label=1))
    logger.info("Extracted %d from 2024, %d from 2025", len(naz_2024), len(naz_2025))

    logger.info("Step 2: Extracting Enron Legitimate corpus (chunked streaming)...")
    enron_samples = extract_enron_csv_sampled(
        DATASETS_DIR / "kaggle" / "emails.csv",
        target_count=1200,
        max_per_mailbox=15,
    )
    logger.info("Extracted %d Enron legitimate samples", len(enron_samples))

    all_raw_candidates: List[EmailSample] = naz_2024 + naz_2025 + enron_samples

    logger.info("Step 3: Deduplicating by content hash...")
    seen_hashes: Dict[str, EmailSample] = {}
    duplicates_removed = 0
    cross_dataset_duplicates = 0

    for s in all_raw_candidates:
        if s.content_hash in seen_hashes:
            duplicates_removed += 1
            if seen_hashes[s.content_hash].source_dataset != s.source_dataset:
                cross_dataset_duplicates += 1
        else:
            seen_hashes[s.content_hash] = s

    deduped_samples: List[EmailSample] = list(seen_hashes.values())
    logger.info(
        "Total raw candidates: %d, Duplicates removed: %d, Cross-dataset: %d, Retained unique: %d",
        len(all_raw_candidates),
        duplicates_removed,
        cross_dataset_duplicates,
        len(deduped_samples),
    )

    phish_count = sum(1 for s in deduped_samples if s.label == 1)
    legit_count = sum(1 for s in deduped_samples if s.label == 0)
    logger.info("Class balance: Phishing=%d (%.1f%%), Legitimate=%d (%.1f%%)",
                phish_count, 100 * phish_count / len(deduped_samples),
                legit_count, 100 * legit_count / len(deduped_samples))

    # Step 4: Stratified 70/15/15 Split with random_state=42
    logger.info("Step 4: Creating stratified 70/15/15 train/val/test splits...")
    labels = [s.label for s in deduped_samples]

    # First split: 70% train, 30% temp (val + test)
    train_samples, temp_samples = train_test_split(
        deduped_samples,
        test_size=0.30,
        random_state=42,
        stratify=labels,
    )

    # Second split: 15% validation, 15% test from temp (equal 50/50 split of the 30%)
    temp_labels = [s.label for s in temp_samples]
    val_samples, test_samples = train_test_split(
        temp_samples,
        test_size=0.50,
        random_state=42,
        stratify=temp_labels,
    )

    logger.info(
        "Splits generated: Train=%d, Validation=%d, Test=%d (Total=%d)",
        len(train_samples),
        len(val_samples),
        len(test_samples),
        len(train_samples) + len(val_samples) + len(test_samples),
    )

    # Step 5: Data Leakage Verification
    logger.info("Step 5: Verifying zero data leakage across splits...")
    train_hashes = {s.content_hash for s in train_samples}
    val_hashes = {s.content_hash for s in val_samples}
    test_hashes = {s.content_hash for s in test_samples}

    leakage_train_val = train_hashes.intersection(val_hashes)
    leakage_train_test = train_hashes.intersection(test_hashes)
    leakage_val_test = val_hashes.intersection(test_hashes)

    assert len(leakage_train_val) == 0, f"Train/Val leakage detected: {len(leakage_train_val)} hashes"
    assert len(leakage_train_test) == 0, f"Train/Test leakage detected: {len(leakage_train_test)} hashes"
    assert len(leakage_val_test) == 0, f"Val/Test leakage detected: {len(leakage_val_test)} hashes"
    logger.info("LEAKAGE CHECK PASSED: Zero hash overlap across train, validation, and test splits.")

    # Step 6: Write Split Files
    logger.info("Step 6: Writing JSONL split files...")
    for split_name, split_data in [
        ("train", train_samples),
        ("validation", val_samples),
        ("test", test_samples),
    ]:
        out_file = OUTPUT_PROCESSED_DIR / split_name / f"{split_name}_samples.jsonl"
        with open(out_file, "w", encoding="utf-8") as f:
            for item in split_data:
                f.write(json.dumps(item.to_dict()) + "\n")
        logger.info("Wrote %s with %d samples", out_file, len(split_data))

    # Step 7: Generate Split Manifest
    manifest_entries = []
    for s in train_samples:
        manifest_entries.append({"source_dataset": s.source_dataset, "source_id": s.source_id, "content_hash": s.content_hash, "label": s.label, "split": "train"})
    for s in val_samples:
        manifest_entries.append({"source_dataset": s.source_dataset, "source_id": s.source_id, "content_hash": s.content_hash, "label": s.label, "split": "validation"})
    for s in test_samples:
        manifest_entries.append({"source_dataset": s.source_dataset, "source_id": s.source_id, "content_hash": s.content_hash, "label": s.label, "split": "test"})

    split_manifest = {
        "manifest_version": "1.0.0",
        "random_state": 42,
        "split_proportions": {"train": 0.70, "validation": 0.15, "test": 0.15},
        "counts": {
            "total": len(manifest_entries),
            "train": len(train_samples),
            "validation": len(val_samples),
            "test": len(test_samples),
        },
        "class_distribution": {
            "train": {"phishing": sum(1 for s in train_samples if s.label == 1), "legitimate": sum(1 for s in train_samples if s.label == 0)},
            "validation": {"phishing": sum(1 for s in val_samples if s.label == 1), "legitimate": sum(1 for s in val_samples if s.label == 0)},
            "test": {"phishing": sum(1 for s in test_samples if s.label == 1), "legitimate": sum(1 for s in test_samples if s.label == 0)},
        },
        "samples": manifest_entries,
    }
    manifest_path = OUTPUT_METADATA_DIR / "split_manifest.json"
    manifest_path.write_text(json.dumps(split_manifest, indent=2), encoding="utf-8")
    logger.info("Wrote split manifest to %s", manifest_path)

    # Step 8: Extract External Validation Corpora (SpamAssassin)
    logger.info("Step 8: Extracting SpamAssassin external validation corpora...")
    easy_ham = list(extract_spamassassin_archive(DATASETS_DIR / "spamassassin" / "20021010_easy_ham.tar.bz2", "spamassassin-easy-ham", target_label=0))
    spam_2 = list(extract_spamassassin_archive(DATASETS_DIR / "spamassassin" / "20050311_spam_2.tar.bz2", "spamassassin-spam-2", target_label=1))
    
    # Write external validation files
    ext_dir = OUTPUT_PROCESSED_DIR / "external_validation"
    ext_dir.mkdir(parents=True, exist_ok=True)
    with open(ext_dir / "easy_ham.jsonl", "w", encoding="utf-8") as f:
        for item in easy_ham:
            f.write(json.dumps(item.to_dict()) + "\n")
    with open(ext_dir / "spam_2.jsonl", "w", encoding="utf-8") as f:
        for item in spam_2:
            f.write(json.dumps(item.to_dict()) + "\n")
    logger.info("Wrote external validation sets: easy_ham=%d, spam_2=%d", len(easy_ham), len(spam_2))


if __name__ == "__main__":
    run_pipeline()
