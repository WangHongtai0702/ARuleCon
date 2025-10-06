"""
RulePilot Settings Configuration
Simple configuration file for SIEM rule and documentation paths.
"""

import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent
DATASET_DIR = BASE_DIR / "dataset"
RULES_DIR = DATASET_DIR / "rules"
DOCS_DIR = DATASET_DIR / "documentations"

# SIEM Rule Paths
SIEM_RULE_PATHS = {
    "Splunk": {
        "detections": RULES_DIR / "Splunk" / "detections",
        "macros": RULES_DIR / "Splunk" / "macros",
    },
    "Microsoft Sentinel": {
        "detections": RULES_DIR / "Microsoft Sentinel" / "Detections",
    },
    "Google Chronicle": {
        "community": RULES_DIR / "Google Chronicle" / "community",
    },
    "IBM QRadar": {
        "rules": RULES_DIR / "IBM QRadar" / "QRCE-Rules-master",
    },
    "RSA NetWitness": {
        "rules": RULES_DIR / "RSA NetWitness" / "nw-esa-master",
    },
}

# Documentation Paths
SIEM_DOC_PATHS = {
    "Splunk": DOCS_DIR / "Splunk",
    "Microsoft Sentinel": DOCS_DIR / "Microsoft Sentinel",
    "Google Chronicle": DOCS_DIR / "Google Chronicle",
    "IBM QRadar": DOCS_DIR / "IBM QRadar",
    "RSA NetWitness": DOCS_DIR / "RSA NetWitness",
}

# Vector Database Paths
VECTOR_DB_PATHS = {
    "Splunk": BASE_DIR / "vector_db" / "Splunk",
    "Google Chronicle": BASE_DIR / "vector_db" / "Google Chronicle",
}

# Result Paths
RESULT_DIR = BASE_DIR / "result"
LOG_DIR = BASE_DIR / "logs"

# Supported SIEM Types
SUPPORTED_SIEM_TYPES = list(SIEM_RULE_PATHS.keys())

# File Extensions by SIEM
SIEM_FILE_EXTENSIONS = {
    "Splunk": [".yml", ".yaml"],
    "Microsoft Sentinel": [".yaml", ".yml"],
    "Google Chronicle": [".yaral"],
    "IBM QRadar": [".txt"],
    "RSA NetWitness": [".ftl"],
}


# Validation function
def validate_paths():
    """Validate that all configured paths exist."""
    missing_paths = []

    # Check rule paths
    for siem, paths in SIEM_RULE_PATHS.items():
        for path_type, path in paths.items():
            if not path.exists():
                missing_paths.append(f"{siem} {path_type}: {path}")

    # Check doc paths
    for siem, path in SIEM_DOC_PATHS.items():
        if not path.exists():
            missing_paths.append(f"{siem} docs: {path}")

    if missing_paths:
        print("Warning: The following paths are missing:")
        for path in missing_paths:
            print(f"  - {path}")
    else:
        print("All configured paths exist.")

    return len(missing_paths) == 0


# Get path helper functions
def get_rule_path(siem_type: str, path_type: str = None) -> Path:
    """Get rule path for a specific SIEM type."""
    if siem_type not in SIEM_RULE_PATHS:
        raise ValueError(f"Unsupported SIEM type: {siem_type}")

    if path_type:
        if path_type not in SIEM_RULE_PATHS[siem_type]:
            raise ValueError(f"Unsupported path type for {siem_type}: {path_type}")
        return SIEM_RULE_PATHS[siem_type][path_type]

    # Return first available path if no specific type requested
    return list(SIEM_RULE_PATHS[siem_type].values())[0]


def get_doc_path(siem_type: str) -> Path:
    """Get documentation path for a specific SIEM type."""
    if siem_type not in SIEM_DOC_PATHS:
        raise ValueError(f"Unsupported SIEM type: {siem_type}")

    return SIEM_DOC_PATHS[siem_type]


def get_vector_db_path(siem_type: str) -> Path:
    """Get vector database path for a specific SIEM type."""
    if siem_type not in VECTOR_DB_PATHS:
        raise ValueError(f"Vector DB not available for SIEM type: {siem_type}")

    return VECTOR_DB_PATHS[siem_type]


def get_file_extensions(siem_type: str) -> list:
    """Get supported file extensions for a specific SIEM type."""
    if siem_type not in SIEM_FILE_EXTENSIONS:
        raise ValueError(f"Unsupported SIEM type: {siem_type}")

    return SIEM_FILE_EXTENSIONS[siem_type]


if __name__ == "__main__":
    # Validate paths when run directly
    validate_paths()
