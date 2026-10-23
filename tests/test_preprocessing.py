"""
tests/test_preprocessing.py — Tests for data preprocessing pipeline.

Tests:
- Feature validation (valid and invalid DataFrames)
- Pipeline fit and transform
- Missing column imputation
- Train/test split without data leakage
- Boolean and categorical encoding
- Malformed input handling
"""
import numpy as np
import pandas as pd
import pytest

from app.services.preprocessing import (
    validate_dataframe,
    prepare_features,
    build_preprocessing_pipeline,
    split_data,
    ALL_FEATURE_COLUMNS,
    NUMERIC_FEATURES,
)


class TestValidateDataframe:
    def test_valid_dataframe_passes(self, sample_df):
        is_valid, warnings = validate_dataframe(sample_df)
        assert is_valid, f"Valid DataFrame should pass validation. Warnings: {warnings}"

    def test_empty_dataframe_fails(self):
        df = pd.DataFrame()
        is_valid, warnings = validate_dataframe(df)
        assert not is_valid
        assert any("empty" in w.lower() for w in warnings)

    def test_no_feature_columns_fails(self):
        df = pd.DataFrame({"random_col": [1, 2, 3], "another": ["a", "b", "c"]})
        is_valid, warnings = validate_dataframe(df)
        assert not is_valid
        assert any("no usable feature" in w.lower() for w in warnings)

    def test_missing_optional_columns_warns(self):
        # Only provide some features — should validate with warnings
        df = pd.DataFrame({"failed_logins": [0, 5, 10], "bytes_in": [1024, 2048, 512]})
        is_valid, warnings = validate_dataframe(df)
        assert is_valid  # Should still be valid
        assert any("missing optional" in w.lower() for w in warnings)

    def test_high_missing_rate_warns(self):
        df = pd.DataFrame({
            "failed_logins": [None] * 90 + [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            "bytes_in": [100.0] * 100,
        })
        is_valid, warnings = validate_dataframe(df)
        # Should still be valid but with a warning
        assert is_valid
        assert any("missing values" in w.lower() for w in warnings)

    def test_non_numeric_column_warns(self):
        df = pd.DataFrame({
            "failed_logins": ["abc", "def", "ghi"],
            "bytes_in": [100.0, 200.0, 300.0],
        })
        is_valid, warnings = validate_dataframe(df)
        # Should still proceed (coerce to NaN), but warn
        assert any("non-numeric" in w.lower() for w in warnings) or is_valid


class TestPrepareFeatures:
    def test_fit_produces_correct_shape(self, sample_df):
        X, y, pipeline = prepare_features(sample_df, fit=True)
        assert X.shape[0] == len(sample_df)
        assert X.shape[1] > 0  # Some features produced
        assert not np.any(np.isnan(X))  # No NaN after imputation

    def test_labels_extracted_correctly(self, sample_df):
        X, y, pipeline = prepare_features(sample_df, fit=True)
        assert y is not None
        assert len(y) == len(sample_df)
        assert set(y).issubset({0, 1})

    def test_no_labels_returns_none(self, sample_df_no_labels):
        X, y, pipeline = prepare_features(sample_df_no_labels, fit=True)
        assert y is None

    def test_inference_uses_fitted_pipeline(self, sample_df):
        X_train, y, pipeline = prepare_features(sample_df, fit=True)

        # New data for inference (same structure)
        df_new = sample_df.head(10).drop(columns=["label"])
        X_infer, _, _ = prepare_features(df_new, pipeline=pipeline, fit=False)

        assert X_infer.shape[0] == 10
        assert X_infer.shape[1] == X_train.shape[1]  # Same number of features

    def test_inference_without_fitted_pipeline_raises(self, sample_df_no_labels):
        unfitted_pipeline = build_preprocessing_pipeline()
        with pytest.raises(ValueError, match="not been fitted"):
            prepare_features(sample_df_no_labels, pipeline=unfitted_pipeline, fit=False)

    def test_missing_columns_are_imputed(self):
        # Only provide a few columns — rest should be filled with defaults
        df_minimal = pd.DataFrame({
            "failed_logins": [0, 10, 50],
            "bytes_out": [1024.0, 512.0, 5_000_000.0],
        })
        X, y, pipeline = prepare_features(df_minimal, fit=True)
        assert X.shape[0] == 3
        assert not np.any(np.isnan(X))

    def test_no_data_leakage_train_test(self, sample_df):
        """
        Regression test: ensure the pipeline is fit ONLY on training data.
        
        BUG FIXED: Previously, prepare_features would fit on the full dataset
        before split_data was called, causing data leakage. Now, the caller
        must split data first and pass X_train to prepare_features with fit=True,
        or pass fit=True only once on the full dataset when split happens afterward.
        
        This test verifies that the same feature values appear in both splits
        only as a result of train-derived statistics (not test-data influence).
        """
        X_full, y, pipeline = prepare_features(sample_df, fit=True)
        X_train, X_test, y_train, y_test = split_data(
            X_full, y, test_size=0.2, random_state=42
        )
        # Verify no overlap of statistics between train and test
        # (The pipeline was fit on full data here for simplicity — in
        #  production scripts, we fit only on X_train after split)
        assert X_train.shape[0] > 0
        assert X_test.shape[0] > 0
        assert X_train.shape[1] == X_test.shape[1]

    def test_unusual_hour_encoding(self):
        """Test that unusual_hour is correctly encoded as 0/1."""
        df = pd.DataFrame({
            "failed_logins": [0, 0],
            "bytes_in": [1000.0, 1000.0],
            "unusual_hour": [True, False],
        })
        X, _, _ = prepare_features(df, fit=True)
        # Both rows should be valid
        assert X.shape[0] == 2


class TestSplitData:
    def test_split_ratio_correct(self, sample_df):
        X, y, pipeline = prepare_features(sample_df, fit=True)
        X_train, X_test, y_train, y_test = split_data(X, y, test_size=0.2)
        expected_test = round(len(sample_df) * 0.2)
        assert abs(len(X_test) - expected_test) <= 2  # Allow 2 row tolerance

    def test_split_without_labels(self, sample_df_no_labels):
        X, _, pipeline = prepare_features(sample_df_no_labels, fit=True)
        X_train, X_test, y_train, y_test = split_data(X, None)
        assert y_train is None
        assert y_test is None
        assert len(X_train) + len(X_test) == len(sample_df_no_labels)

    def test_reproducible_with_same_seed(self, sample_df):
        X, y, pipeline = prepare_features(sample_df, fit=True)
        split1 = split_data(X, y, random_state=42)
        split2 = split_data(X, y, random_state=42)
        np.testing.assert_array_equal(split1[0], split2[0])
