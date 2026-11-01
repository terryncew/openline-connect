"""Optional FastAPI app exposing exactly guarded routes, no raw seller submit path."""
from .engine import ProtectionError
from .signing import b64

def create_app(engine):
    from fastapi import FastAPI,HTTPException
    from pydantic import BaseModel,ConfigDict
    app=FastAPI(title='OpenLine Connect — fictional local actions',version='0.1.0rc5.dev3')
    class Request(BaseModel):
        model_config=ConfigDict(extra='forbid')
        action:str
        params:dict
        authorization:str|None=None
        nonce:str
        task_id:str|None=None
        payment:dict|None=None
    @app.get('/healthz')
    def health():return {'status':'ok','scope':'local_sqlite_only'}
    @app.get('/.well-known/openline-connect.json')
    def discovery():
        d=engine.public()
        d['jwks']={'keys':[{'kty':'OKP','crv':'Ed25519','kid':f'seller-epoch-{x["sequence"]}',
                            'x':b64(bytes.fromhex(x['public']))} for x in d['key_epochs']]}
        return d
    @app.post('/v1/connect/execute')
    def execute(req:Request):
        try:
            d=req.model_dump();task_id=d.pop('task_id',None)
            return engine.execute_task(task_id=task_id,**d) if task_id is not None else engine.execute(**d)
        except ProtectionError as e:raise HTTPException(status_code=e.status,detail=e.code)
        except ValueError:raise HTTPException(status_code=400,detail='invalid_signed_evidence_or_shape')
        except Exception:raise HTTPException(status_code=503,detail='indeterminate_reconcile_required')
    return app
