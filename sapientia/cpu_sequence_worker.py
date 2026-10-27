"""Fixed forward GRU classification on real masked 3-D CPU input tensors."""
import math
import time


def calibration_threshold(scores, truth):
    """Max calibration F1/-FP partition, then its deterministic score midpoint.

    The lower/upper boundaries refer to predicted classes, not label extrema:
    overlapping ground-truth classes must retain the same winning predictions.
    Python float comparison avoids rounding an adjacent-float32 midpoint back
    to the lower boundary before evaluating the classification objective.
    """
    if not isinstance(scores, (list, tuple)) or not scores or not isinstance(truth, (list, tuple)) or len(scores) != len(truth):
        raise ValueError("Matching nonempty calibration scores and labels required")
    if any(type(score) not in (int, float) or not math.isfinite(score) or not 0 <= score <= 1 for score in scores):
        raise ValueError("Finite bounded calibration scores required")
    if any(type(label) not in (int, float) or label not in (0, 1) for label in truth):
        raise ValueError("Binary calibration labels required")
    candidates = sorted({0., 1., *[float(score) for score in scores]})
    best = None
    for upper in candidates:
        predictions = [score >= upper for score in scores]
        tp = sum(predicted and label == 1 for predicted, label in zip(predictions, truth))
        fp = sum(predicted and label == 0 for predicted, label in zip(predictions, truth))
        fn = sum(not predicted and label == 1 for predicted, label in zip(predictions, truth))
        f1 = 2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else 0.
        rank = (f1, -fp, upper)
        if best is None or rank > best[0]:
            best = rank, upper
    upper = best[1]
    lower = max((float(score) for score in scores if score < upper), default=0.)
    midpoint = lower + (upper-lower)/2
    # A zero boundary or adjacent float64 scores can have no representable
    # interior midpoint. Retain the exact winning cut in that case.
    if not lower < midpoint <= upper:
        midpoint = upper
    return midpoint


def execute(request, torch):
    began = time.perf_counter()
    width = request["feature_count"]
    if type(width) is not int or not 1 <= width <= 128:
        raise ValueError("Bounded sequence feature width required")

    class Network(torch.nn.Module):
        def __init__(self):
            super().__init__()
            self.gru = torch.nn.GRU(width, 24, batch_first=True)
            self.output = torch.nn.Linear(24, 1)

        def forward(self, values, lengths):
            packed = torch.nn.utils.rnn.pack_padded_sequence(values, lengths.cpu(), batch_first=True, enforce_sorted=False)
            _, hidden = self.gru(packed)
            return self.output(hidden[-1]).squeeze(-1)

    model = Network().to("cpu")
    pooled = torch.nn.Sequential(torch.nn.Linear(width, 16), torch.nn.Tanh(), torch.nn.Linear(16, 1)).to("cpu")

    def tensor(rows):
        if not isinstance(rows, list) or not 1 <= len(rows) <= 4096:
            raise ValueError("1..4096 bounded sequences required")
        if sum(len(row)*width for row in rows) > 2_000_000:
            raise ValueError("Sequence tensor exceeds two million feature values")
        lengths = torch.tensor([len(row) for row in rows], dtype=torch.long, device="cpu")
        if int(lengths.min()) < 2 or int(lengths.max()) > 32:
            raise ValueError("2..32 actual steps required")
        values = torch.zeros((len(rows), int(lengths.max()), width), dtype=torch.float32, device="cpu")
        for i, row in enumerate(rows):
            if any(not isinstance(step, list) or len(step) != width or any(type(v) not in (int, float) or not math.isfinite(v) or not 0 <= v <= 1 for v in step) for step in row):
                raise ValueError("Finite bounded sequence features required")
            values[i, :len(row)] = torch.tensor(row, dtype=torch.float32, device="cpu")
        mask = torch.arange(values.shape[1], device="cpu")[None, :] < lengths[:, None]
        return values, lengths, mask

    def labels(value, n):
        if not isinstance(value, list) or len(value) != n or set(value) != {0, 1} or any(type(x) is not int for x in value):
            raise ValueError("Reviewed external binary labels with both classes required")
        return torch.tensor(value, dtype=torch.float32, device="cpu")

    def load(target, supplied):
        expected = target.state_dict()
        if not isinstance(supplied, dict) or set(supplied) != set(expected):
            raise ValueError("Fixed GRU weight schema mismatch")
        loaded = {}
        for key, weight in expected.items():
            value = torch.tensor(supplied[key], dtype=torch.float32, device="cpu")
            if value.shape != weight.shape or not torch.isfinite(value).all() or value.abs().max() > 100:
                raise ValueError("Invalid finite sequence weights")
            loaded[key] = value
        target.load_state_dict(loaded, strict=True)

    if request["operation"] == "sequence_train":
        training, train_lengths, train_mask = tensor(request["training"])
        calibration, calibration_lengths, calibration_mask = tensor(request["calibration"])
        target = labels(request["training_labels"], len(training))
        calibration_target = labels(request["calibration_labels"], len(calibration))
        epochs = request.get("epochs", 30)
        if type(epochs) is not int or not 1 <= epochs <= 60:
            raise ValueError("Sequence epochs must be 1..60")
        loss_fn = torch.nn.BCEWithLogitsLoss()
        optimizer = torch.optim.Adam(model.parameters(), lr=.006)
        pooled_optimizer = torch.optim.Adam(pooled.parameters(), lr=.006)
        pooled_training = (training*train_mask[:, :, None]).sum(1)/train_lengths[:, None]
        pooled_calibration = (calibration*calibration_mask[:, :, None]).sum(1)/calibration_lengths[:, None]
        with torch.inference_mode():
            initial = float(loss_fn(model(training, train_lengths), target))
        best, best_weights, best_pooled = float("inf"), None, None
        for epoch in range(epochs):
            model.train()
            pooled.train()
            for positions in torch.randperm(len(training), device="cpu").split(64):
                optimizer.zero_grad()
                loss = loss_fn(model(training[positions], train_lengths[positions]), target[positions])
                if not torch.isfinite(loss):
                    raise ValueError("Non-finite sequence training loss")
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), 2.)
                optimizer.step()
                pooled_optimizer.zero_grad()
                pooled_loss = loss_fn(pooled(pooled_training[positions]).squeeze(-1), target[positions])
                pooled_loss.backward()
                pooled_optimizer.step()
            model.eval()
            with torch.inference_mode():
                candidate = float(loss_fn(model(calibration, calibration_lengths), calibration_target))
            if candidate < best:
                best = candidate
                best_weights = {k: v.detach().clone() for k, v in model.state_dict().items()}
        model.load_state_dict(best_weights)
        model.eval()
        pooled.eval()
        with torch.inference_mode():
            train_loss = float(loss_fn(model(training, train_lengths), target))
            scores = torch.sigmoid(model(calibration, calibration_lengths))
            pooled_scores = torch.sigmoid(pooled(pooled_calibration).squeeze(-1))
        score_values, pooled_values = scores.tolist(), pooled_scores.tolist()
        cut = calibration_threshold(score_values, calibration_target.tolist())
        pooled_cut = calibration_threshold(pooled_values, calibration_target.tolist())
        return {"weights": {k: v.tolist() for k, v in model.state_dict().items()},
                "pooled_weights": {k: v.tolist() for k, v in pooled.state_dict().items()},
                "threshold": cut, "pooled_threshold": pooled_cut,
                "calibration_scores": score_values, "pooled_calibration_scores": pooled_values,
                "framework_version": torch.__version__, "metrics": {
                    "training_sequences": len(training), "calibration_sequences": len(calibration), "epochs": epochs,
                    "initial_training_loss": initial, "training_loss": train_loss, "calibration_loss": best,
                    "input_tensor_shape": list(training.shape), "padded_steps": int((~train_mask).sum()),
                    "mask_semantics": "packed actual lengths; padding cannot affect the GRU state",
                    "duration_ms": (time.perf_counter()-began)*1000,
                    "threshold_selection": "maximum calibration F1, minimum false positives; midpoint of the identical-prediction score interval",
                    "calibration_minimum_score_margin": min(abs(score-cut) for score in score_values),
                    "unordered_calibration_minimum_score_margin": min(abs(score-pooled_cut) for score in pooled_values),
                    "holdout_seen_during_training": False, "probability_calibrated": False,
                }}
    if request["operation"] != "sequence_infer":
        raise ValueError("Unknown sequence operation")
    load(model, request["weights"])
    values, lengths, mask = tensor(request["sequences"])
    model.eval()
    with torch.inference_mode():
        scores = torch.sigmoid(model(values, lengths))
        result = {"scores": scores.tolist(), "input_tensor_shape": list(values.shape),
                  "padded_steps": int((~mask).sum()), "device": "cpu", "threads": 1}
        if request.get("pooled_weights") is not None:
            load(pooled, request["pooled_weights"])
            pooled.eval()
            means = (values*mask[:, :, None]).sum(1)/lengths[:, None]
            result["pooled_scores"] = torch.sigmoid(pooled(means).squeeze(-1)).tolist()
            reversed_values = values.clone()
            for i, n in enumerate(lengths.tolist()):
                reversed_values[i, :n] = values[i, :n].flip(0)
            reversed_scores = torch.sigmoid(model(reversed_values, lengths))
            result["order_sensitivity_mean_abs_delta"] = float((reversed_scores-scores).abs().mean())
    result["duration_ms"] = (time.perf_counter()-began)*1000
    return result
