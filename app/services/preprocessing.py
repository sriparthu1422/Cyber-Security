"""
app/services/preprocessing.py — Data validation and preprocessing pipeline.

Handles:
- Column validation (required vs optional)
- Missing value imputation
- Categorical encoding (protocol, boolean)
- Numerical scaling (StandardScaler)
- Train/test split with no data leakage
- Consistent feature order for training and inference

The scikit-learn Pipeline ensures the same transformations apply to both
training data and new inference data without any leakage.
"""
import logging
from typing import Tuple, Optional, List, Dict, Any

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.model_selection import train_test_split

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
#  Feature column definitions
# ─────────────────────────────────────────────

# Numeric features that will be imputed (median) and scaled
NUMERIC_FEATURES = [
    "failed_logins",
    "bytes_in",
    "bytes_out",
    "connection_duration",
    "port_number",
]

# Categorical features that will be one-hot encoded
CATEGORICAL_FEATURES = ["protocol"]

# Boolean features treated as 0/1 integer
BOOLEAN_FEATURES = ["unusual_hour"]

# All expected feature columns
ALL_FEATURE_COLUMNS = NUMERIC_FEATURES + CATEGORICAL_FEATURES + BOOLEAN_FEATURES

# Optional metadata columns (preserved but not used as features)
METADATA_COLUMNS = ["source_ip", "dest_ip", "timestamp", "label"]

# Label column name (present in supervised datasets)
LABEL_COLUMN = "label"


def validate_dataframe(df: pd.DataFrame) -> Tuple[bool, List[str]]:
    """
    Validate an input DataFrame before preprocessing.

    Checks performed:
    1. At least some feature columns are present
    2. DataFrame is not empty
    3. Numeric columns contain parseable values
    4. Missing value rates are reported (but tolerated up to 80%)

    Returns:
        (is_valid, list_of_warnings)
        is_valid: True if the DataFrame can be processed
        warnings: List of non-fatal issues found
    """
    warnings = []

    # Check not empty
    if df.empty:
        return False, ["DataFrame is empty — no rows to process."]

    # Check if any usable feature columns are present
    available_numeric = [c for c in NUMERIC_FEATURES if c in df.columns]
    available_cat = [c for c in CATEGORICAL_FEATURES if c in df.columns]
    available_bool = [c for c in BOOLEAN_FEATURES if c in df.columns]
    available_features = available_numeric + available_cat + available_bool

    if not available_features:
        return False, [
            f"No usable feature columns found. Expected at least one of: "
            f"{', '.join(ALL_FEATURE_COLUMNS)}. "
            f"Got columns: {', '.join(df.columns.tolist())}"
        ]

    # Warn about missing columns
    missing_cols = [c for c in ALL_FEATURE_COLUMNS if c not in df.columns]
    if missing_cols:
        warnings.append(
            f"Missing optional feature columns (will be imputed with defaults): "
            f"{', '.join(missing_cols)}"
        )

    # Check missing value rates
    for col in available_numeric:
        missing_rate = df[col].isna().mean()
        if missing_rate > 0.8:
            warnings.append(
                f"Column '{col}' has {missing_rate:.0%} missing values — "
                f"imputed values may not be meaningful."
            )

    # Try to parse numeric columns
    for col in available_numeric:
        if col in df.columns:
            try:
                pd.to_numeric(df[col], errors="raise")
            except (ValueError, TypeError):
                # Try coerce — count non-parseable values
                coerced = pd.to_numeric(df[col], errors="coerce")
                bad_count = coerced.isna().sum() - df[col].isna().sum()
                if bad_count > 0:
                    warnings.append(
                        f"Column '{col}' has {bad_count} non-numeric values — "
                        f"they will be treated as missing."
                    )

    return True, warnings


def build_preprocessing_pipeline() -> Pipeline:
    """
    Build a scikit-learn Pipeline for preprocessing feature data.

    The pipeline:
    1. Imputes missing numeric values with the column median
    2. Scales numeric features with StandardScaler (zero mean, unit variance)
    3. One-hot encodes categorical features (protocol)
    4. Passes boolean features through as-is (treated as 0/1 integers)

    The ColumnTransformer applies different transformations to different
    column groups, then concatenates the results.

    Returns:
        sklearn.pipeline.Pipeline ready to be fit on training data.
    """
    # Numeric: impute then scale
    numeric_transformer = Pipeline(steps=[
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler()),
    ])

    # Categorical: impute with most frequent, then one-hot encode
    categorical_transformer = Pipeline(steps=[
        ("imputer", SimpleImputer(strategy="most_frequent")),
        ("encoder", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
    ])

    # Boolean: just impute with 0 (assume not unusual if unknown)
    boolean_transformer = SimpleImputer(strategy="constant", fill_value=0)

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", numeric_transformer, NUMERIC_FEATURES),
            ("cat", categorical_transformer, CATEGORICAL_FEATURES),
            ("bool", boolean_transformer, BOOLEAN_FEATURES),
        ],
        remainder="drop",  # Drop any extra columns not in the transformers
        verbose_feature_names_out=False,
    )

    return Pipeline(steps=[("preprocessor", preprocessor)])


def prepare_features(
    df: pd.DataFrame,
    pipeline: Optional[Pipeline] = None,
    fit: bool = False,
) -> Tuple[np.ndarray, Optional[np.ndarray], Pipeline]:
    """
    Prepare feature matrix from a DataFrame.

    Args:
        df: Input DataFrame with event data
        pipeline: Existing fitted pipeline (for inference). If None, a new one is created.
        fit: If True, fit the pipeline on this data (training mode).
             If False, transform using existing pipeline (inference mode).

    Returns:
        (X, y, pipeline)
        X: Feature matrix as numpy array
        y: Label array (None if no label column)
        pipeline: The (possibly newly fitted) pipeline

    Raises:
        ValueError: If validation fails or pipeline not fitted in inference mode
    """
    df = df.copy()

    # Add missing columns with NaN so the pipeline can handle them
    for col in NUMERIC_FEATURES:
        if col not in df.columns:
            df[col] = np.nan

    for col in CATEGORICAL_FEATURES:
        if col not in df.columns:
            df[col] = "OTHER"

    for col in BOOLEAN_FEATURES:
        if col not in df.columns:
            df[col] = 0

    # Convert boolean-like values
    if "unusual_hour" in df.columns:
        df["unusual_hour"] = df["unusual_hour"].map(
            {True: 1, False: 0, "true": 1, "false": 0, "yes": 1, "no": 0,
             "1": 1, "0": 0, 1: 1, 0: 0}
        ).fillna(0).astype(int)

    # Coerce numeric columns
    for col in NUMERIC_FEATURES:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # Extract labels if present
    y = None
    if LABEL_COLUMN in df.columns:
        y = df[LABEL_COLUMN].values

    # Extract features
    feature_df = df[ALL_FEATURE_COLUMNS]

    # Build or use existing pipeline
    if pipeline is None:
        pipeline = build_preprocessing_pipeline()

    if fit:
        X = pipeline.fit_transform(feature_df)
        logger.info(f"Pipeline fitted on {len(X)} rows, {X.shape[1]} output features")
    else:
        if not hasattr(pipeline.named_steps["preprocessor"], "transformers_"):
            raise ValueError(
                "Pipeline has not been fitted yet. "
                "Call prepare_features with fit=True first, or load a trained pipeline."
            )
        X = pipeline.transform(feature_df)

    return X, y, pipeline


def split_data(
    X: np.ndarray,
    y: Optional[np.ndarray],
    test_size: float = 0.2,
    random_state: int = 42,
) -> Tuple[np.ndarray, np.ndarray, Optional[np.ndarray], Optional[np.ndarray]]:
    """
    Split data into training and testing sets.

    Uses stratified split when labels are present to maintain class balance.
    Uses random split for unsupervised data.

    Args:
        X: Feature matrix
        y: Labels (or None for unsupervised)
        test_size: Fraction of data for testing (0-1)
        random_state: Seed for reproducibility

    Returns:
        (X_train, X_test, y_train, y_test)
    """
    if y is not None:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
    else:
        X_train, X_test = train_test_split(
            X, test_size=test_size, random_state=random_state
        )
        y_train, y_test = None, None

    logger.info(
        f"Data split: {len(X_train)} training rows, {len(X_test)} test rows"
    )
    return X_train, X_test, y_train, y_test


def dataframe_from_events(events: List[Dict[str, Any]]) -> pd.DataFrame:
    """
    Convert a list of event dictionaries (from API requests) to a DataFrame.

    Args:
        events: List of dicts with event features

    Returns:
        pandas DataFrame ready for preprocessing
    """
    return pd.DataFrame(events)
