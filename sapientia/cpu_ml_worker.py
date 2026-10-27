"""Isolated CPU PyTorch worker. Only bounded JSON crosses the process boundary.

No model files, pickle, TorchScript, source plugins or GPU devices are loaded.
The parent kills the worker on its wall-clock deadline.
"""

import json
import math
import os
import sys
import time


_TORCH = None
_LIMITS = None


def framework():
    global _TORCH, _LIMITS
    if _TORCH is not None:
        return _TORCH
    os.environ["CUDA_VISIBLE_DEVICES"] = ""
    os.environ["OMP_NUM_THREADS"] = "1"
    os.environ["MKL_NUM_THREADS"] = "1"
    from cpu_ml_limits import child_limits
    _LIMITS = child_limits()
    import torch

    torch.set_num_threads(1)
    torch.set_num_interop_threads(1)
    torch.use_deterministic_algorithms(True)
    _TORCH = torch
    return torch


def main(request=None):
    if request is None:
        request = json.loads(sys.stdin.buffer.read(2 * 1024 * 1024 + 1))
    torch = framework()
    if str(request.get("operation", "")).startswith("research_v2_"):
        from research_v2_worker import execute
        return execute(request, torch)
    if str(request.get("operation", "")).startswith("research_"):
        from research_behavior_worker import execute
        return execute(request, torch)
    torch.manual_seed(81213)
    if str(request.get("operation", "")).startswith("sequence_"):
        from cpu_sequence_worker import execute
        return execute(request, torch)
    began = time.perf_counter()
    if request["operation"] == "status":
        tensor = torch.tensor([[1.0, 2.0]], device="cpu")
        return {"available": True, "framework": "pytorch", "version": torch.__version__,
                "device": "cpu", "threads": 1, "cuda_runtime": torch.version.cuda,
                "smoke_sum": tensor.sum().item(), "duration_ms": (time.perf_counter()-began)*1000}
    model = torch.nn.Sequential(torch.nn.Linear(7, 6), torch.nn.Tanh(),
                                torch.nn.Linear(6, 3), torch.nn.Tanh(),
                                torch.nn.Linear(3, 6), torch.nn.Tanh(),
                                torch.nn.Linear(6, 7), torch.nn.Sigmoid()).to("cpu")

    def features(value):
        if not isinstance(value, list) or not 1 <= len(value) <= 1000:
            raise ValueError("1..1000 feature records required")
        if any(not isinstance(row, list) or len(row) != 7 or
               any(type(x) not in (float, int) or not math.isfinite(x) or not 0 <= x <= 1 for x in row)
               for row in value):
            raise ValueError("Invalid finite bounded feature vector")
        return torch.tensor(value, dtype=torch.float32, device="cpu")

    if request["operation"] == "train":
        training, validation = features(request["training"]), features(request["validation"])
        epochs = request["epochs"]
        if type(epochs) is not int or not 1 <= epochs <= 120:
            raise ValueError("1..120 epochs required")
        optimizer = torch.optim.Adam(model.parameters(), lr=0.025)
        loss_fn = torch.nn.MSELoss()
        initial = float(loss_fn(model(training), training).item())
        for _ in range(epochs):
            optimizer.zero_grad()
            loss = loss_fn(model(training), training)
            if not torch.isfinite(loss):
                raise ValueError("Non-finite training loss")
            loss.backward()
            optimizer.step()
        model.eval()
        with torch.inference_mode():
            train_loss = float(loss_fn(model(training), training).item())
            errors = ((model(validation) - validation)**2).mean(dim=1)
            median = errors.median()
            mad = (errors-median).abs().median()
            threshold = max(0.002, float((torch.quantile(errors, 0.99) + 3*mad + 0.002).item()))
        return {"weights": {k: v.detach().cpu().tolist() for k, v in model.state_dict().items()},
                "threshold": threshold,
                "metrics": {"initial_training_mse": initial, "training_mse": train_loss,
                            "validation_mse": float(errors.mean().item()),
                            "validation_max_mse": float(errors.max().item()),
                            "validation_samples": len(validation), "training_samples": len(training),
                            "epochs": epochs, "duration_ms": (time.perf_counter()-began)*1000,
                            "malicious_precision_recall_measured": False},
                "framework_version": torch.__version__, "device": "cpu", "threads": 1}
    if request["operation"] != "infer":
        raise ValueError("Unknown CPU operation")
    supplied = request["weights"]
    expected = model.state_dict()
    if not isinstance(supplied, dict) or set(supplied) != set(expected):
        raise ValueError("Model weight schema mismatch")
    loaded = {}
    for key, weight in expected.items():
        value = torch.tensor(supplied[key], dtype=torch.float32, device="cpu")
        if value.shape != weight.shape or not torch.isfinite(value).all() or value.abs().max() > 100:
            raise ValueError("Invalid model weight shape or value")
        loaded[key] = value
    model.load_state_dict(loaded, strict=True)
    model.eval()
    values = features(request["features"])
    with torch.inference_mode():
        errors = (model(values)-values)**2
    return {"scores": errors.mean(dim=1).tolist(), "feature_errors": errors.tolist(),
            "duration_ms": (time.perf_counter()-began)*1000, "device": "cpu"}


if __name__ == "__main__":
    if "--persistent" in sys.argv[1:]:
        while True:
            frame = sys.stdin.buffer.readline(32 * 1024 * 1024 + 1)
            if not frame:
                break
            if len(frame) > 32 * 1024 * 1024 or not frame.endswith(b"\n"):
                break
            request_id = None
            try:
                decoded = json.loads(frame)
                request_id = decoded["request_id"]
                answer = main(decoded["payload"])
                if os.name != "nt":
                    answer["runtime_limits"] = _LIMITS
            except Exception as exc:
                answer = {"worker_error": type(exc).__name__, "reason": str(exc)[:500]}
            print(json.dumps({"request_id": request_id, "result": answer}, separators=(",", ":"), allow_nan=False), flush=True)
    else:
        try:
            answer = main()
        except Exception as exc:
            answer = {"worker_error": type(exc).__name__, "reason": str(exc)[:500]}
        print(json.dumps(answer, separators=(",", ":"), allow_nan=False))
