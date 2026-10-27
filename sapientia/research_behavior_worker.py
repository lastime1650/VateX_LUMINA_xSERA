"""JSON-only CPU edge-relation prediction; own research-inspired implementation.

No upstream implementation, pickle, downloaded weight, plugin, or GPU is loaded.
Runs inside the existing bounded single CPU child. Never imports the web server.
"""

import math
import time

WIDTH = 24
CLASSES = 7


def _rows(value, maximum, torch):
    if not isinstance(value, list) or not 1 <= len(value) <= maximum:
        raise ValueError("Bounded nonempty edge vectors required")
    for row in value:
        if (not isinstance(row, list) or len(row) != WIDTH or
                any(type(x) not in (int, float) or not math.isfinite(x) or not 0 <= x <= 1 for x in row)):
            raise ValueError("Invalid research edge feature shape or finite range")
    return torch.tensor(value, dtype=torch.float32, device="cpu")


def _targets(value, count, torch):
    if not isinstance(value, list) or len(value) != count or any(type(v) is not int or not 0 <= v < CLASSES for v in value):
        raise ValueError("Invalid edge relation targets")
    return torch.tensor(value, dtype=torch.long, device="cpu")


def _model(torch):
    return torch.nn.Sequential(torch.nn.Linear(WIDTH, 16), torch.nn.Tanh(), torch.nn.Linear(16, CLASSES)).to("cpu")


def _weights(model, supplied, torch):
    expected = model.state_dict()
    if not isinstance(supplied, dict) or set(supplied) != set(expected):
        raise ValueError("Research model weight keys differ")
    loaded = {}
    for key, original in expected.items():
        value = torch.tensor(supplied[key], dtype=torch.float32, device="cpu")
        if value.shape != original.shape or not torch.isfinite(value).all() or value.abs().max() > 100:
            raise ValueError("Research model weight shape or finite range differs")
        loaded[key] = value
    model.load_state_dict(loaded, strict=True)
    model.eval()
    return model


def _losses(model, x, y, torch):
    with torch.inference_mode():
        return torch.nn.functional.cross_entropy(model(x), y, reduction="none")


def execute(request, torch):
    began = time.perf_counter()
    operation = request.get("operation")
    if operation == "research_status":
        return {"available": True, "device": "cpu", "framework": "pytorch", "version": torch.__version__, "threads": 1}
    if operation == "research_train":
        x, vx = _rows(request.get("training"), 1024, torch), _rows(request.get("validation"), 256, torch)
        y, vy = _targets(request.get("training_targets"), len(x), torch), _targets(request.get("validation_targets"), len(vx), torch)
        epochs, seeds = request.get("epochs"), request.get("seeds")
        if type(epochs) is not int or not 1 <= epochs <= 120:
            raise ValueError("1..120 research epochs required")
        if not isinstance(seeds, list) or not 1 <= len(seeds) <= 3 or len(set(seeds)) != len(seeds) or any(type(v) is not int or not 0 <= v <= 2**31-1 for v in seeds):
            raise ValueError("1..3 distinct bounded integer seeds required")
        if len(set(request["training_targets"])) < 2:
            raise ValueError("At least two normal relation classes required")
        models, metrics, validation = [], [], []
        for seed in seeds:
            torch.manual_seed(seed)
            model = _model(torch)
            optimizer = torch.optim.Adam(model.parameters(), lr=.035)
            initial = float(_losses(model, x, y, torch).mean().item())
            for _ in range(epochs):
                optimizer.zero_grad()
                loss = torch.nn.functional.cross_entropy(model(x), y)
                if not torch.isfinite(loss):
                    raise ValueError("Non-finite research loss")
                loss.backward()
                optimizer.step()
            model.eval()
            train_loss = float(_losses(model,x,y,torch).mean().item())
            errors = _losses(model,vx,vy,torch)
            validation.append(errors)
            with torch.inference_mode():
                accuracy = float((model(vx).argmax(dim=1) == vy).float().mean().item())
                # Real input ablation: replace endpoint semantic vectors while
                # retaining the same relation targets. It may improve or worsen
                # a particular dataset; publish the actual result without a gate.
                ablated = vx.clone()
                ablated[:, :16] = 0
                ablation_loss = float(_losses(model,ablated,vy,torch).mean().item())
            metrics.append({"seed":seed,"initial_training_cross_entropy":initial,
                "training_cross_entropy":train_loss,"validation_cross_entropy":float(errors.mean().item()),
                "validation_relation_accuracy":accuracy,"semantic_feature_ablation_cross_entropy":ablation_loss})
            models.append({"seed":seed,"weights":{k:v.detach().cpu().tolist() for k,v in model.state_dict().items()}})
        errors = torch.stack(validation).mean(dim=0)
        # No attack labels or test split select the threshold.
        threshold = max(.05,float(errors.max().item())+.05)
        distribution = [request["training_targets"].count(i) for i in range(CLASSES)]
        prior = [(v+1)/(len(y)+CLASSES) for v in distribution]
        prior_loss = sum(-math.log(prior[v]) for v in request["validation_targets"])/len(vy)
        return {"ensemble":models,"threshold":threshold,"device":"cpu","framework_version":torch.__version__,
            "metrics":{"training_samples":len(x),"validation_samples":len(vx),"epochs":epochs,
                "seeds":metrics,"seed_validation_range":float(max(m["validation_cross_entropy"] for m in metrics)-min(m["validation_cross_entropy"] for m in metrics)),
                "frequency_baseline_cross_entropy":prior_loss,"validation_cross_entropy":float(errors.mean().item()),
                "attack_precision":None,"attack_recall":None,"false_positive_cases_per_host_day":None,
                "case_latency_p95_ms":None,"real_world_detection_rate_measured":False,
                "duration_ms":(time.perf_counter()-began)*1000,"reproduction_claim":False}}
    if operation != "research_infer":
        raise ValueError("Unknown research worker operation")
    values = _rows(request.get("features"), 32, torch)
    targets = _targets(request.get("targets"), len(values), torch)
    ensemble = request.get("ensemble")
    if not isinstance(ensemble,list) or not 1 <= len(ensemble) <= 3:
        raise ValueError("Bounded research ensemble required")
    losses, logits = [], []
    for member in ensemble:
        model = _weights(_model(torch),member.get("weights"),torch)
        losses.append(_losses(model,values,targets,torch))
        with torch.inference_mode():
            logits.append(torch.softmax(model(values),dim=1))
    scores = torch.stack(losses).mean(dim=0)
    votes = torch.stack(logits).mean(dim=0)
    return {"scores":scores.tolist(),"predicted_relations":votes.argmax(dim=1).tolist(),
            "ensemble_disagreement":torch.stack(losses).var(dim=0,unbiased=False).tolist(),
            "duration_ms":(time.perf_counter()-began)*1000,"device":"cpu","threads":1,
            "malicious_probability":False}
