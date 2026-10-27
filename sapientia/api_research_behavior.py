"""Authenticated research models, original-bound graph runs and dataset audits."""

from fastapi import Request
from starlette.concurrency import run_in_threadpool

from . import research_behavior as research

PREFIX = "/api/research"


def register(app,store,runtime,who,body):
    from . import research_evaluation as evaluation
    from . import research_rebaseline as rebaseline

    @app.post(PREFIX+"/v2/train",status_code=201)
    async def train_v2(request:Request):
        data=await body(request)
        if not isinstance(data,dict) or data.get("gate_version","v2")!="v2":raise ValueError("Explicit v2 training route")
        return await run_in_threadpool(research.train,store,who(request,research.EDITORS),{**data,"gate_version":"v2"})

    @app.get(PREFIX+"/evaluation/datasets")
    async def datasets(request:Request):
        return await run_in_threadpool(evaluation.listing,store,who(request),"datasets")

    @app.post(PREFIX+"/evaluation/datasets",status_code=201)
    async def create_dataset(request:Request):
        return await run_in_threadpool(evaluation.save_dataset,store,who(request,research.EDITORS),await body(request))

    @app.post(PREFIX+"/evaluation/synthetic",status_code=201)
    async def synthetic_dataset(request:Request):
        from . import research_synthetic
        return await run_in_threadpool(research_synthetic.build,store,who(request,("admin",)),await body(request))

    @app.get(PREFIX+"/evaluation/datasets/{identifier}")
    async def dataset(identifier:str,request:Request):
        return await run_in_threadpool(evaluation.dataset,store,who(request),identifier)

    @app.post(PREFIX+"/evaluation/datasets/{identifier}/archive")
    async def archive_dataset(identifier:str,request:Request):
        return await run_in_threadpool(evaluation.archive,store,who(request,research.EDITORS),"datasets",identifier,await body(request))

    @app.get(PREFIX+"/evaluation/runs")
    async def evaluations(request:Request):
        return await run_in_threadpool(evaluation.listing,store,who(request),"runs")

    @app.post(PREFIX+"/evaluation/runs",status_code=201)
    async def evaluate(request:Request):
        return await run_in_threadpool(evaluation.evaluate,store,who(request,research.EDITORS),await body(request))

    @app.get(PREFIX+"/evaluation/runs/{identifier}")
    async def evaluation_run(identifier:str,request:Request):
        return await run_in_threadpool(evaluation.get_run,store,who(request),identifier)

    @app.post(PREFIX+"/evaluation/runs/{identifier}/archive")
    async def archive_evaluation(identifier:str,request:Request):
        return await run_in_threadpool(evaluation.archive,store,who(request,research.EDITORS),"runs",identifier,await body(request))

    @app.get(PREFIX+"/rebaseline/candidates")
    async def candidates(request:Request):
        return await run_in_threadpool(rebaseline.listing,store,who(request))

    @app.post(PREFIX+"/rebaseline/candidates",status_code=201)
    async def create_candidate(request:Request):
        return await run_in_threadpool(rebaseline.create,store,who(request,research.EDITORS),await body(request))

    @app.get(PREFIX+"/rebaseline/candidates/{identifier}")
    async def candidate(identifier:str,request:Request):
        return await run_in_threadpool(rebaseline.get,store,who(request),identifier)

    @app.post(PREFIX+"/rebaseline/candidates/{identifier}/{action}")
    async def candidate_action(identifier:str,action:str,request:Request):
        handlers={"prepare":rebaseline.prepare,"review":rebaseline.review,"promote":rebaseline.promote,"rollback":rebaseline.rollback}
        if action not in handlers:raise ValueError("Unknown rebaseline action")
        return await run_in_threadpool(handlers[action],store,who(request,research.EDITORS),identifier,await body(request))

    @app.get(PREFIX+"/status")
    async def status(request:Request):
        return await run_in_threadpool(research.status,store,who(request))

    @app.get(PREFIX+"/catalog")
    async def catalog(request:Request):
        who(request)
        return {"items":research.CAPABILITIES,"reproduction_claim":False}

    @app.get(PREFIX+"/models")
    async def models(request:Request):
        return await run_in_threadpool(research.list_models,store,who(request))

    @app.post(PREFIX+"/train",status_code=201)
    async def train(request:Request):
        return await run_in_threadpool(research.train,store,who(request,research.EDITORS),await body(request))

    @app.post(PREFIX+"/models/{identifier}/review")
    async def review(identifier:str,request:Request):
        return await run_in_threadpool(research.review,store,who(request,research.EDITORS),identifier,await body(request))

    @app.post(PREFIX+"/models/{identifier}/disable")
    async def disable(identifier:str,request:Request):
        data = await body(request)
        if not isinstance(data,dict) or set(data)!={"reason"}:
            raise ValueError("A disable reason is required")
        return await run_in_threadpool(research.disable,store,who(request,research.EDITORS),identifier,data["reason"])

    @app.post(PREFIX+"/quality")
    async def quality(request:Request):
        return await run_in_threadpool(research.quality,store,who(request),await body(request))

    @app.post(PREFIX+"/models/{identifier}/retire")
    async def retire(identifier:str,request:Request):
        from . import research_behavior_lifecycle
        data=await body(request)
        if not isinstance(data,dict) or set(data)!={"reason"}:
            raise ValueError("A retirement reason is required")
        return await run_in_threadpool(research_behavior_lifecycle.retire,store,who(request,research.EDITORS),identifier,data["reason"])

    @app.post(PREFIX+"/runs/archive")
    async def archive(request:Request):
        from . import research_behavior_lifecycle
        data=await body(request)
        if not isinstance(data,dict) or set(data)!={"run_ids","reason"}:
            raise ValueError("Exact run IDs and archive reason required")
        return await run_in_threadpool(research_behavior_lifecycle.archive_runs,store,who(request,research.EDITORS),data["run_ids"],data["reason"])

    @app.post(PREFIX+"/analyze",status_code=201)
    async def analyze(request:Request):
        return await run_in_threadpool(research.analyze,store,who(request,research.EDITORS),await body(request))

    @app.get(PREFIX+"/runs")
    async def runs(request:Request):
        try:
            limit = int(request.query_params.get("limit","50"))
        except ValueError:
            raise ValueError("limit requires an integer") from None
        return await run_in_threadpool(research.list_runs,store,who(request),limit)

    @app.get(PREFIX+"/runs/{identifier}")
    async def run(identifier:str,request:Request):
        return await run_in_threadpool(research.get_run,store,who(request),identifier)
