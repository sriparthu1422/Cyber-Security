"""
tests/test_training.py — Tests for ML model training and prediction.

Tests:
- IsolationForest training and prediction
- RandomForest training and evaluation
- Model artifact save/load
- Prediction types (normal vs anomalous should produce different results)
- Metric computation on test set
- Small dataset handling
- Missing artifact handling
"""
import numpy as np
import pytest
from pathlib import Path


class TestIsolationForest:
    def test_training_produces_model(self, sample_df):
        from app.services.preprocessing import prepare_features
        from app.services.training import train_isolation_forest

        X, _, _ = prepare_features(sample_df.drop(columns=["label"]), fit=True)
        model = train_isolation_forest(X, contamination=0.1, n_estimators=50)
        assert model is not None
        assert hasattr(model, "predict")

    def test_predictions_are_binary(self, sample_df):
        from app.services.preprocessing import prepare_features
        from app.services.training import train_isolation_forest

        X, _, _ = prepare_features(sample_df.drop(columns=["label"]), fit=True)
        model = train_isolation_forest(X, contamination=0.1, n_estimators=50)
        preds = model.predict(X)
        assert set(preds).issubset({1, -1})  # IsolationForest returns 1 or -1

    def test_contamination_affects_anomaly_count(self, sample_df):
        from app.services.preprocessing import prepare_features
        from app.services.training import train_isolation_forest

        df = sample_df.drop(columns=["label"])
        X, _, _ = prepare_features(df, fit=True)

        model_low = train_isolation_forest(X, contamination=0.05, n_estimators=50)
        model_high = train_isolation_forest(X, contamination=0.3, n_estimators=50)

        anomalies_low = np.sum(model_low.predict(X) == -1)
        anomalies_high = np.sum(model_high.predict(X) == -1)

        # Higher contamination → more anomalies flagged
        assert anomalies_high > anomalies_low

    def test_scores_are_float(self, sample_df):
        from app.services.preprocessing import prepare_features
        from app.services.training import train_isolation_forest

        X, _, _ = prepare_features(sample_df.drop(columns=["label"]), fit=True)
        model = train_isolation_forest(X)
        scores = model.decision_function(X)
        assert scores.dtype in [np.float32, np.float64]
        assert len(scores) == len(sample_df)


class TestRandomForest:
    def test_training_with_labels(self, sample_df):
        from app.services.preprocessing import prepare_features
        from app.services.training import train_random_forest

        X, y, _ = prepare_features(sample_df, fit=True)
        assert y is not None, "Sample DF should have labels"
        model = train_random_forest(X, y, n_estimators=20)
        assert model is not None
        assert hasattr(model, "predict_proba")

    def test_probabilities_in_range(self, sample_df):
        from app.services.preprocessing import prepare_features
        from app.services.training import train_random_forest

        X, y, _ = prepare_features(sample_df, fit=True)
        model = train_random_forest(X, y, n_estimators=20)
        probs = model.predict_proba(X)[:, 1]
        assert np.all(probs >= 0.0)
        assert np.all(probs <= 1.0)

    def test_evaluation_metrics_populated(self, sample_df):
        from app.services.preprocessing import prepare_features, split_data
        from app.services.training import train_random_forest, evaluate_supervised_model

        X, y, _ = prepare_features(sample_df, fit=True)
        X_train, X_test, y_train, y_test = split_data(X, y, test_size=0.2)
        model = train_random_forest(X_train, y_train, n_estimators=20)
        metrics = evaluate_supervised_model(model, X_test, y_test)

        assert "precision" in metrics
        assert "recall" in metrics
        assert "f1_score" in metrics
        assert "accuracy" in metrics
        assert 0.0 <= metrics["precision"] <= 1.0
        assert 0.0 <= metrics["recall"] <= 1.0
        assert 0.0 <= metrics["f1_score"] <= 1.0


class TestModelArtifacts:
    def test_save_and_load_isolation_forest(self, sample_df, test_artifacts_dir):
        """Regression test: saved model loads and predicts consistently."""
        import app.services.training as training_module
        original_path = training_module.ARTIFACTS_PATH
        training_module.ARTIFACTS_PATH = test_artifacts_dir

        try:
            from app.services.preprocessing import prepare_features
            from app.services.training import (
                train_isolation_forest, save_artifact, load_artifact,
                ISOLATION_FOREST_FILE
            )

            X, _, _ = prepare_features(sample_df.drop(columns=["label"]), fit=True)
            model = train_isolation_forest(X, n_estimators=50)
            preds_before = model.predict(X).tolist()

            save_artifact(model, ISOLATION_FOREST_FILE)
            loaded = load_artifact(ISOLATION_FOREST_FILE)
            preds_after = loaded.predict(X).tolist()

            assert preds_before == preds_after, "Loaded model should produce same predictions"
        finally:
            training_module.ARTIFACTS_PATH = original_path

    def test_load_missing_artifact_returns_none(self, test_artifacts_dir):
        import app.services.training as training_module
        original_path = training_module.ARTIFACTS_PATH
        training_module.ARTIFACTS_PATH = test_artifacts_dir

        try:
            from app.services.training import load_artifact
            result = load_artifact("nonexistent_model.joblib")
            assert result is None
        finally:
            training_module.ARTIFACTS_PATH = original_path


class TestFullTrainingPipeline:
    def test_train_models_returns_metrics(self, sample_df, test_artifacts_dir):
        import app.services.training as training_module
        original_path = training_module.ARTIFACTS_PATH
        training_module.ARTIFACTS_PATH = test_artifacts_dir

        try:
            from app.services.preprocessing import prepare_features
            from app.services.training import train_models

            X, y, pipeline = prepare_features(sample_df, fit=True)
            metrics, run_id = train_models(X, y, pipeline)

            assert "run_id" in metrics
            assert "training_rows" in metrics
            assert "if_anomaly_count" in metrics
            assert "precision" in metrics  # Has labels, so supervised metrics
            assert isinstance(run_id, str)
            assert len(run_id) == 36  # UUID format
        finally:
            training_module.ARTIFACTS_PATH = original_path

    def test_train_without_labels(self, sample_df_no_labels, test_artifacts_dir):
        import app.services.training as training_module
        original_path = training_module.ARTIFACTS_PATH
        training_module.ARTIFACTS_PATH = test_artifacts_dir

        try:
            from app.services.preprocessing import prepare_features
            from app.services.training import train_models

            X, y, pipeline = prepare_features(sample_df_no_labels, fit=True)
            assert y is None
            metrics, run_id = train_models(X, y, pipeline)

            assert "if_anomaly_count" in metrics
            assert metrics.get("precision") is None  # No labels = no supervised metrics
        finally:
            training_module.ARTIFACTS_PATH = original_path
