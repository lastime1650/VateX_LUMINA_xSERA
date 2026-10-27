"""CPU-only class-balanced semantic edge model; no old model code is changed."""

import math
import time

WIDTH=64
CLASSES=7


def _rows(value,maximum,torch):
    if not isinstance(value,list) or not 1<=len(value)<=maximum:raise ValueError("Bounded nonempty v2 feature rows required")
    if any(not isinstance(row,list) or len(row)!=WIDTH or any(type(x) not in (int,float) or not math.isfinite(x) or not 0<=x<=1 for x in row) for row in value):
        raise ValueError("Finite 64-feature v2 vectors required")
    return torch.tensor(value,dtype=torch.float32,device="cpu")


def _targets(value,count,torch):
    if not isinstance(value,list) or len(value)!=count or any(type(x) is not int or not 0<=x<CLASSES for x in value):raise ValueError("Typed v2 relation targets required")
    return torch.tensor(value,dtype=torch.long,device="cpu")


def _model(torch):
    return torch.nn.Sequential(torch.nn.Linear(WIDTH,32),torch.nn.Tanh(),torch.nn.Linear(32,16),torch.nn.Tanh(),torch.nn.Linear(16,CLASSES)).to("cpu")


def _load(value,torch):
    model=_model(torch);state=model.state_dict()
    if not isinstance(value,dict) or set(value)!=set(state):raise ValueError("V2 weight keys differ")
    replacement={}
    for key,original in state.items():
        item=torch.tensor(value[key],dtype=torch.float32,device="cpu")
        if item.shape!=original.shape or not torch.isfinite(item).all() or item.abs().max()>100:raise ValueError("V2 weight shape/range differs")
        replacement[key]=item
    model.load_state_dict(replacement,strict=True);model.eval()
    return model


def execute(request,torch):
    began=time.perf_counter();operation=request.get("operation")
    if operation=="research_v2_train":
        x=_rows(request.get("training"),1024,torch);vx=_rows(request.get("validation"),256,torch)
        y=_targets(request.get("training_targets"),len(x),torch);vy=_targets(request.get("validation_targets"),len(vx),torch)
        epochs=request.get("epochs");seeds=request.get("seeds")
        if type(epochs) is not int or not 1<=epochs<=120:raise ValueError("1..120 v2 epochs required")
        if not isinstance(seeds,list) or not 1<=len(seeds)<=3 or len(set(seeds))!=len(seeds) or any(type(v) is not int or not 0<=v<2**31 for v in seeds):raise ValueError("Bounded distinct v2 seeds required")
        if len(set(request["training_targets"]))<2:raise ValueError("Two normal relation classes required")
        counts=torch.bincount(y,minlength=CLASSES).float();balanced=(counts.sum()/counts.clamp_min(1)).sqrt();balanced=balanced/balanced.mean()
        models=[];metrics=[];losses=[]
        for seed in seeds:
            torch.manual_seed(seed);model=_model(torch);optimizer=torch.optim.AdamW(model.parameters(),lr=.02,weight_decay=.0001)
            initial=float(torch.nn.functional.cross_entropy(model(x),y).item())
            for _ in range(epochs):
                optimizer.zero_grad();loss=torch.nn.functional.cross_entropy(model(x),y,weight=balanced)
                if not torch.isfinite(loss):raise ValueError("Nonfinite v2 loss")
                loss.backward();torch.nn.utils.clip_grad_norm_(model.parameters(),1.0);optimizer.step()
            model.eval()
            with torch.inference_mode():
                error=torch.nn.functional.cross_entropy(model(vx),vy,reduction="none");losses.append(error)
                confusion=torch.zeros((CLASSES,CLASSES),dtype=torch.int64)
                predictions=model(vx).argmax(dim=1)
                for actual,predicted in zip(vy.tolist(),predictions.tolist()):confusion[actual,predicted]+=1
                ablated=vx.clone();ablated[:,24:]=0
                metrics.append({"seed":seed,"initial_training_cross_entropy":initial,"training_cross_entropy":float(torch.nn.functional.cross_entropy(model(x),y).item()),
                    "validation_cross_entropy":float(error.mean().item()),"validation_relation_accuracy":float((predictions==vy).float().mean().item()),
                    "semantic_feature_ablation_cross_entropy":float(torch.nn.functional.cross_entropy(model(ablated),vy).item()),"relation_confusion_matrix":confusion.tolist()})
            models.append({"seed":seed,"weights":{k:v.detach().cpu().tolist() for k,v in model.state_dict().items()}})
        error=torch.stack(losses).mean(dim=0)
        return {"ensemble":models,"threshold":max(.1,float(error.max().item())+.1),"validation_scores":error.tolist(),"framework_version":torch.__version__,"device":"cpu",
            "metrics":{"architecture":"64-32-16-7 class-balanced MLP","training_samples":len(x),"validation_samples":len(vx),"epochs":epochs,"seeds":metrics,
                "seed_validation_range":max(m["validation_cross_entropy"] for m in metrics)-min(m["validation_cross_entropy"] for m in metrics),
                "validation_cross_entropy":float(error.mean().item()),"duration_ms":(time.perf_counter()-began)*1000,"real_world_detection_rate_measured":False}}
    if operation!="research_v2_infer":raise ValueError("Unknown v2 CPU operation")
    x=_rows(request.get("features"),32,torch);y=_targets(request.get("targets"),len(x),torch);members=request.get("ensemble")
    if not isinstance(members,list) or not 1<=len(members)<=3:raise ValueError("Bounded v2 ensemble required")
    losses=[];probabilities=[]
    with torch.inference_mode():
        for member in members:
            model=_load(member.get("weights"),torch);logits=model(x)
            losses.append(torch.nn.functional.cross_entropy(logits,y,reduction="none"));probabilities.append(torch.softmax(logits,dim=1))
    all_losses=torch.stack(losses)
    return {"scores":all_losses.mean(dim=0).tolist(),"predicted_relations":torch.stack(probabilities).mean(dim=0).argmax(dim=1).tolist(),
        "ensemble_disagreement":all_losses.var(dim=0,unbiased=False).tolist(),"duration_ms":(time.perf_counter()-began)*1000,"device":"cpu","threads":1,"malicious_probability":False}
