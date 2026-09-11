"""inference/train_model.py had 0% coverage despite carrying the
.sha256-sidecar fix: without it, the next DeepLearningEngine startup's
integrity check finds a stale/missing hash and crash-loops the fleet.
save_traced_model() was pulled out of the training loop specifically so
this could be tested without running a real 100k-sample training loop.
"""
import hashlib
from unittest.mock import patch

import torch
import torch.nn as nn

from inference.train_model import (
    DGA_CNN,
    FlowAutoencoder,
    generate_benign_flow_dataset,
    generate_hard_dataset,
    save_traced_model,
    train_flow_autoencoder,
    train_to_max,
)


def test_save_traced_model_writes_matching_sha256(tmp_path):
    model = DGA_CNN()
    model.eval()
    traced = torch.jit.trace(model, torch.zeros((1, 35), dtype=torch.long))
    save_path = str(tmp_path / "cnn_dga.pt")

    returned_hash = save_traced_model(traced, save_path)

    with open(save_path, "rb") as f:
        expected_hash = hashlib.sha256(f.read()).hexdigest()
    with open(save_path + ".sha256") as f:
        written_hash = f.read().strip()

    assert returned_hash == expected_hash
    assert written_hash == expected_hash


def test_save_traced_model_overwrites_stale_sha256(tmp_path):
    model = DGA_CNN()
    model.eval()
    traced = torch.jit.trace(model, torch.zeros((1, 35), dtype=torch.long))
    save_path = str(tmp_path / "cnn_dga.pt")

    with open(save_path + ".sha256", "w") as f:
        f.write("stale-hash-from-a-previous-model\n")

    save_traced_model(traced, save_path)

    with open(save_path, "rb") as f:
        expected_hash = hashlib.sha256(f.read()).hexdigest()
    with open(save_path + ".sha256") as f:
        assert f.read().strip() == expected_hash


def test_generate_hard_dataset_shapes_and_labels():
    X, y = generate_hard_dataset(num_samples=20)
    assert X.shape == (20, 35)
    assert y.shape == (20, 1)
    assert X.dtype == torch.long
    # Half malicious (label 1.0), half benign (label 0.0), by construction.
    assert set(y.unique().tolist()) <= {0.0, 1.0}
    assert y.sum().item() == 10.0


def test_dga_cnn_forward_produces_probability_in_unit_range():
    model = DGA_CNN()
    model.eval()
    with torch.no_grad():
        out = model(torch.zeros((2, 35), dtype=torch.long))
    assert out.shape == (2, 1)
    assert torch.all((out >= 0.0) & (out <= 1.0))


def test_homoglyph_collision_safety_net_does_not_crash(monkeypatch):
    # Most real domains contain at least one of o/l/i/e, so
    # base.replace(...) usually changes something -- but with 40,000 real,
    # diverse benign_domains (not the original 10 hardcoded brand names)
    # a handful genuinely won't, so the "dga == base" safety net (a domain
    # that happens to survive the replace unchanged) can't be assumed
    # unreachable via normal random selection anymore either way. Force it
    # directly regardless: fix threat_type into the homoglyph branch and
    # random.choice to a domain with none of those characters.
    monkeypatch.setattr("inference.train_model.random.random", lambda: 0.5)
    monkeypatch.setattr("inference.train_model.random.choice", lambda seq: "abcd.zzz")
    X, y = generate_hard_dataset(num_samples=2)  # must not raise
    assert X.shape == (2, 35)


class TestTrainToMax:
    """train_to_max() runs a real (but here, tiny) training loop -- rather
    than mocking torch/nn, generate_hard_dataset is monkeypatched to a
    handful of samples so the real epoch loop, best-accuracy tracking,
    and save_traced_model() call all genuinely execute in well under a
    second instead of the production 100k-sample/50-epoch run.
    """

    @staticmethod
    def _tiny_dataset(num_samples=100000):
        torch.manual_seed(0)
        X = torch.randint(0, 39, (16, 35), dtype=torch.long)
        y = (torch.arange(16) % 2).float().unsqueeze(1)
        return X, y

    def test_train_to_max_runs_to_completion_and_saves_a_model(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)  # so the hardcoded "models/cnn_dga.pt" never touches the real tracked model
        monkeypatch.setattr("inference.train_model.generate_hard_dataset", self._tiny_dataset)
        train_to_max()  # must not raise, and must terminate within its own 50-epoch cap
        assert (tmp_path / "models" / "cnn_dga.pt").exists()
        assert (tmp_path / "models" / "cnn_dga.pt.sha256").exists()

    def test_train_to_max_stops_on_patience_exhaustion_without_saving_worse_models(self, tmp_path, monkeypatch):
        # Force every epoch to look identical (no improvement ever) by
        # feeding a constant, label-free "dataset" -- exercises the
        # epochs_no_improve/patience branch instead of only the
        # new-best-accuracy branch the first test takes.
        monkeypatch.chdir(tmp_path)

        def _degenerate_dataset(num_samples=100000):
            X = torch.zeros((8, 35), dtype=torch.long)
            y = torch.zeros((8, 1))
            return X, y

        monkeypatch.setattr("inference.train_model.generate_hard_dataset", _degenerate_dataset)
        train_to_max()  # must terminate via the patience or epoch cap, not hang


def test_generate_benign_flow_dataset_shape_and_scaling():
    X = generate_benign_flow_dataset(num_samples=50)
    assert X.shape == (50, 5)
    assert X.dtype == torch.float32
    # log1p'd and divided by FLOW_FEATURE_SCALE -- every training range
    # (orig_bytes up to 2000, resp_bytes up to 500000, etc.) stays well
    # under 1.0 once scaled; a value near or above 1 here would mean the
    # scaling constants and the actual generation ranges have drifted
    # apart from each other.
    assert torch.all(X >= 0.0)
    assert torch.all(X < 1.0)


def test_flow_autoencoder_forward_reconstructs_the_input_shape():
    model = FlowAutoencoder()
    model.eval()
    with torch.no_grad():
        out = model(torch.zeros((4, 5), dtype=torch.float32))
    assert out.shape == (4, 5)


class TestTrainFlowAutoencoder:
    """Mirrors TestTrainToMax's approach: a tiny, fast, monkeypatched
    dataset exercises the real training loop, threshold computation, and
    save_traced_model()/.threshold sidecar writing, instead of the
    production 20,000-sample run.
    """

    @staticmethod
    def _tiny_dataset(num_samples=20000):
        torch.manual_seed(0)
        return torch.rand((40, 5), dtype=torch.float32) * 0.3  # matches the real scaled-down range

    def test_train_flow_autoencoder_saves_model_sha256_and_threshold(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)  # so the hardcoded "models/autoencoder_flow.pt" never touches the real tracked model
        monkeypatch.setattr("inference.train_model.generate_benign_flow_dataset", self._tiny_dataset)
        train_flow_autoencoder()  # must not raise, and must terminate within its own 100-epoch cap

        model_path = tmp_path / "models" / "autoencoder_flow.pt"
        sha_path = tmp_path / "models" / "autoencoder_flow.pt.sha256"
        threshold_path = tmp_path / "models" / "autoencoder_flow.pt.threshold"
        assert model_path.exists()
        assert sha_path.exists()
        assert threshold_path.exists()

        with open(model_path, "rb") as f:
            expected_hash = hashlib.sha256(f.read()).hexdigest()
        assert sha_path.read_text().strip() == expected_hash

        threshold = float(threshold_path.read_text().strip())
        assert threshold > 0.0  # a real, positive reconstruction-error bound, not a placeholder

        # The saved file must actually be loadable TorchScript, not a bare
        # state_dict -- the exact defect this whole feature was fixing:
        # torch.save(model.state_dict(), ...) can't be torch.jit.load()ed.
        loaded = torch.jit.load(str(model_path))
        loaded.eval()
        with torch.no_grad():
            out = loaded(torch.zeros((1, 5), dtype=torch.float32))
        assert out.shape == (1, 5)
