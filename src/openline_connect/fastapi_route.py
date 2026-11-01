"""Opt-in adapter for one pre-existing FastAPI route, reusing ConnectEngine.

Trust and local-effect limits are exactly those of ConnectEngine. This does not
provide external I/O atomicity, a request issuer, or independent key custody.
"""
import json
from .engine import ProtectionError


def mount_guarded_route(app, engine, *, path, action, handler, max_amount_cents=5000):
    """Register receiver-owned *handler(params, authorized_sqlite_db)* as POST path.

    Request JSON requires params + authorization, with nonce for legacy actions;
    optional task_id / recover_only routes into existing engine recovery APIs.
    No generic unguarded handler route is mounted by this adapter.
    """
    from fastapi import Request, HTTPException
    if not isinstance(path, str) or not path.startswith('/') or '//' in path or '{' in path or '}' in path:
        raise ValueError('guarded_route_requires_literal_absolute_path')
    if not isinstance(action, str) or not action:
        raise ValueError('guarded_route_action_required')
    engine.register(action, handler, max_amount_cents=max_amount_cents, atomic=True)

    async def admit(request: Request):
        try:
            raw = await request.body()
            if len(raw) > 65536:
                raise HTTPException(status_code=413, detail='request_too_large')
            def unique(pairs):
                if len({k for k, _ in pairs}) != len(pairs):
                    raise ValueError('duplicate_json_key')
                return dict(pairs)
            payload = json.loads(raw, object_pairs_hook=unique)
            allowed = {'params', 'authorization', 'nonce', 'task_id', 'recover_only'}
            if (type(payload) is not dict or not set(payload).issubset(allowed) or
                'params' not in payload or 'authorization' not in payload or
                type(payload['params']) is not dict or
                type(payload['authorization']) is not str or not payload['authorization'].strip()):
                raise ValueError('bad_guarded_route_shape')
            task_id = payload.get('task_id')
            recover_only = payload.get('recover_only', False)
            nonce = payload.get('nonce')
            if (type(recover_only) is not bool or
                (task_id is not None and (type(task_id) is not str or not task_id.strip())) or
                (nonce is not None and (type(nonce) is not str or not nonce.strip())) or
                (recover_only and task_id is None) or
                (task_id is None and nonce is None)):
                raise ValueError('bad_guarded_route_shape')
            # Exact action is server-selected, never chosen by the untrusted caller.
            if recover_only:
                return engine.inspect_task(task_id=task_id, action=action,
                                           params=payload['params'],
                                           authorization=payload['authorization'])
            if task_id is not None:
                return engine.execute_task(task_id=task_id, action=action,
                                           params=payload['params'],
                                           authorization=payload['authorization'], nonce=nonce)
            return engine.execute(action=action, params=payload['params'],
                                  authorization=payload['authorization'], nonce=nonce)
        except ProtectionError as exc:
            raise HTTPException(status_code=exc.status, detail=exc.code) from exc
        except (ValueError, TypeError, UnicodeDecodeError) as exc:
            raise HTTPException(status_code=400, detail='invalid_request_or_evidence') from exc
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=503, detail='indeterminate_reconcile_required') from exc
    app.add_api_route(path, admit, methods=['POST'], name='openline_guard_'+action)
    return admit
