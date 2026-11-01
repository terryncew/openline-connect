"""Receiver-owned local onboarding. Demo buyer credential is LOCAL FICTIONAL ONLY.

The receiver's policy and seller private key are stored in receiver-owned files.
Never use this sample co-located buyer private key in a deployed multi-party setup.
"""
from __future__ import annotations
import hashlib, json, os, secrets, sqlite3, time
from pathlib import Path
from .engine import ConnectEngine, ProtectionError
from .local_example import register_demo
from .signing import digest, pub, sign
from .verify import inspect as inspect_receipts


def _home(home: str | Path) -> Path:
    return Path(home).expanduser().resolve()


def _write_private(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def _write_policy(path: Path, policy: dict) -> None:
    tmp = path.with_name(path.name + '.tmp-' + secrets.token_hex(5))
    _write_private(tmp, json.dumps(policy, indent=2, sort_keys=True))
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def initialize(home: str | Path) -> dict:
    base = _home(home)
    # Refuse reinitialization even if a partial previous setup exists.
    if base.exists() and any(base.iterdir()):
        raise ProtectionError('already_initialized_or_nonempty_directory', 409)
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(base, 0o700)
    seller = secrets.token_hex(32)
    local_buyer = secrets.token_hex(32)
    _write_private(base / 'keys' / 'receiver.seed', seller + '\n')
    _write_private(base / 'keys' / 'fictional-buyer.seed', local_buyer + '\n')
    policy = {'buyers': {'fictional-buyer': pub(local_buyer)}, 'grants': {},
              'local_profile_only': True, 'version': 1}
    _write_policy(base / 'policy.json', policy)
    engine = ConnectEngine('sqlite:///' + str(base / 'connect.sqlite'), policy,
                           seller_seed=seller, seller_id='fictional-supplier')
    register_demo(engine)
    trust = {'seller_public': pub(seller), 'note': 'Copy to an independent verifier over a trusted channel; this local copy is NOT independent trust.'}
    _write_private(base / 'trust-bootstrap.json', json.dumps(trust, indent=2))
    return {'home': str(base), 'default_deny': True, 'authorized_operations': 0,
            'seller_public': pub(seller), 'fictional_buyer': True, 'network_listener_started': False}


def read_engine(home: str | Path) -> ConnectEngine:
    base = _home(home)
    seller_file = base / 'keys' / 'receiver.seed'
    policy_file = base / 'policy.json'
    if not seller_file.is_file() or not policy_file.is_file():
        raise ProtectionError('not_initialized', 400)
    engine = ConnectEngine('sqlite:///' + str(base / 'connect.sqlite'), str(policy_file),
                           seller_seed=seller_file.read_text(encoding='ascii').strip(),
                           seller_id='fictional-supplier')
    register_demo(engine)
    engine._seed_file=seller_file
    engine._policy_file=policy_file
    return engine


def allow(home: str | Path, *, action: str, target: str | None = None, value: str | None = None,
          amount_cents: int = 0, ttl_seconds: int = 300, grant_name: str | None = None,
          params: dict | None = None) -> dict:
    import re
    if type(action) is not str or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,79}',action):
        raise ProtectionError('invalid_action',400)
    if params is not None:
        if type(params) is not dict or not params or type(params.get('target')) is not str or not params['target']:
            raise ProtectionError('invalid_custom_parameters',400)
        if type(params.get('amount_cents',0)) is not int or not (0<=params.get('amount_cents',0)<=5000):
            raise ProtectionError('invalid_custom_amount',400)
        try:digest(params)
        except (TypeError,ValueError,OverflowError):raise ProtectionError('noncanonical_custom_parameters',400)
        target=params['target'];amount_cents=params.get('amount_cents',0)
    elif not target or len(target)>128 or not value or len(value)>256:
        raise ProtectionError('invalid_operation_arguments',400)
    if type(amount_cents) is not int or not (0 <= amount_cents <= 5000):
        raise ProtectionError('amount_outside_demo_limit', 400)
    if type(ttl_seconds) is not int or not (1 <= ttl_seconds <= 3600):
        raise ProtectionError('expiry_outside_local_policy_limit', 400)
    base = _home(home)
    engine = read_engine(base)
    policy = json.loads((base / 'policy.json').read_text())
    if not isinstance(policy.get('grants'), dict):
        raise ProtectionError('policy_not_default_deny', 409)
    buyer = (base / 'keys' / 'fictional-buyer.seed').read_text(encoding='ascii').strip()
    if params is None:params = {'target': target, 'value': value, 'amount_cents': amount_cents}
    now = engine.clock()
    expires = now + ttl_seconds
    name = grant_name or ('grant-' + secrets.token_hex(8))
    if not name.replace('-', '').replace('_', '').isalnum() or len(name) > 80:
        raise ProtectionError('invalid_grant_name', 400)
    existing = {g['id'] for groups in policy['grants'].values() for g in groups}
    if name in existing:
        raise ProtectionError('grant_name_already_exists', 409)
    grant = {'id': name, 'action': action, 'subject': 'fictional-buyer',
             'target': target, 'grant_mode': 'exact_parameters_v1',
             'parameters_sha256': digest(params), 'max_amount_cents': amount_cents,
             'expires_at': expires, 'active': True}
    grant['receiver_signature'] = sign({**grant, 'kind': 'openline.connect.receiver_grant.v1'}, engine.seed, 'seller')
    policy['grants'].setdefault(action, []).append(grant)
    _write_policy(base / 'policy.json', policy)
    claims = {'kind': 'openline.connect.mandate.v1', 'subject': 'fictional-buyer',
              'seller': engine.seller_id, 'action': action, 'target': target,
              'parameters_sha256': digest(params), 'max_amount_cents': amount_cents,
              'nbf': now - 1, 'exp': expires, 'jti': name}
    authorization = sign(claims, buyer, 'fictional-buyer')
    payload = {'action': action, 'params': params, 'authorization': authorization,
               'nonce': 'nonce-' + secrets.token_hex(12)}
    # Grant is receiver-controlled; buyer mandate is NOT passed into the server via a read tool.
    grant_file = base / 'grants' / (name + '.json')
    _write_private(grant_file, json.dumps(payload, indent=2))
    return {'grant_id': name, 'expires_at': expires, 'action': action,
            'target': target, 'signed_by_receiver': True,
            'fictional_agent_request': str(grant_file),
            'grant_mode': 'exact_parameters_v1',
            'parameters_sha256': digest(params),
            'note': 'Receiver grant is exact-parameter, not a range; restart serve to load a new file policy.'}


def allow_bounded(home: str | Path, *, action: str, permitted_keys: list[str],
                  target_restrictions: dict[str,list], fixed_params: dict,
                  max_amount_per_op: int, max_cumulative_amount: int, max_uses: int,
                  ttl_seconds: int = 300, grant_name: str | None = None,
                  allowed_worker_subjects: list[str] | None = None, amount_key: str = 'amount_cents') -> dict:
    """Receiver-signed local-fictional bounded grant; NEVER a production issuer."""
    from .engine import _scope_shape
    if type(ttl_seconds) is not int or not 1<=ttl_seconds<=3600:
        raise ProtectionError('invalid_bounded_expiry',400)
    base=_home(home);engine=read_engine(base)
    now=engine.clock()
    name=grant_name or 'bounded-'+secrets.token_hex(8)
    if not isinstance(name,str) or not name or len(name)>80 or not all(x.isalnum() or x in '-_' for x in name):
        raise ProtectionError('invalid_grant_name',400)
    policy=json.loads((base/'policy.json').read_text())
    if any(g.get('id')==name for gs in policy['grants'].values() for g in gs):
        raise ProtectionError('grant_name_already_exists',409)
    grant={'id':name,'jti':name,'grant_mode':'bounded_scope_v1','subject':'fictional-buyer',
           'action':action,'allowed_actions':[action],
           'allowed_worker_subjects':list(allowed_worker_subjects if allowed_worker_subjects is not None else ['worker-A','worker-B']),
           'permitted_keys':permitted_keys,
           'target_restrictions':target_restrictions,'fixed_params':fixed_params,
           'amount_key':amount_key,'max_amount_per_op':max_amount_per_op,
           'max_cumulative_amount':max_cumulative_amount,'max_uses':max_uses,
           'expires_at':now+ttl_seconds,'active':True}
    _scope_shape(grant)
    grant['receiver_signature']=sign({**grant,'kind':'openline.connect.receiver_grant.v1'},engine.seed,'seller')
    policy['grants'].setdefault(action,[]).append(grant)
    _write_policy(base/'policy.json',policy)
    return {'grant_id':name,'grant_mode':'bounded_scope_v1','expires_at':grant['expires_at'],
            'signed_by_receiver':True,'local_fictional_only':True}


def issue_fictional_bounded_invocation(home: str | Path, *, action: str,
        params: dict, grant_id: str, delegation_id: str,
        worker_subject: str, worker_seed: str, nonce: str | None = None,
        task_id: str | None = None, delegation_limits: dict | None = None) -> dict:
    """Fixture ONLY; buyer and worker private keys must be separated in deployments.

    Use the same delegation_id for multiple worker invocations under the same
    bounded capacity; each invocation gets a unique worker mandate jti/nonce.
    """
    from .engine import _scope_shape
    engine=read_engine(home);base=_home(home)
    grant=next((g for g in engine.policy['grants'].get(action,[]) if g.get('id')==grant_id),None)
    if grant is None or grant.get('grant_mode')!='bounded_scope_v1':
        raise ProtectionError('bounded_grant_not_found',404)
    now=engine.clock();nonce=nonce or 'attempt-'+secrets.token_hex(12)
    if not isinstance(worker_subject,str) or not worker_subject or worker_subject=='fictional-buyer':
        raise ProtectionError('invalid_worker_subject',400)
    if not isinstance(delegation_id,str) or not delegation_id:
        raise ProtectionError('invalid_delegation_id',400)
    scope={k:grant[k] for k in ('allowed_actions','allowed_worker_subjects','permitted_keys','target_restrictions',
            'fixed_params','amount_key','max_amount_per_op','max_cumulative_amount','max_uses')}
    if delegation_limits:scope.update(delegation_limits)
    _scope_shape(scope)
    buyer=(base/'keys'/'fictional-buyer.seed').read_text(encoding='ascii').strip()
    delegation={'kind':'openline.connect.delegation.v1','grant_mode':'bounded_scope_v1',
                'subject':'fictional-buyer','seller':engine.seller_id,'delegate_subject':worker_subject,
                'delegate_public':pub(worker_seed),'jti':delegation_id,'nbf':now-1,
                'exp':grant['expires_at'], 'max_amount_cents':scope['max_amount_per_op'],**scope}
    # Worker signs the concrete parameters and nonce OR durable task identity.
    mandate={'kind':'openline.connect.mandate.v1','grant_mode':'bounded_scope_v1',
             'subject':'fictional-buyer','delegate_subject':worker_subject,
             'seller':engine.seller_id,'action':action,'target':params.get('target'),
             'parameters_sha256':digest(params),'max_amount_cents':scope['max_amount_per_op'],
             'nbf':now-1,'exp':grant['expires_at'],'jti':'worker-'+secrets.token_hex(16)}
    if task_id is not None:mandate['task_id']=task_id
    else:mandate['nonce']=nonce
    auth=sign(delegation,buyer,'fictional-buyer')+':'+sign(mandate,worker_seed,worker_subject)
    payload={'action':action,'params':params,'nonce':nonce,'authorization':auth}
    if task_id is not None:payload['task_id']=task_id
    return {**payload,'delegation_id':delegation_id,'mandate_id':mandate['jti'],
            'grant_id':grant_id,'local_fictional_only':True}


def verify_local(home: str | Path, *, seller_public: str,
                 expected_head: str | None = None, expected_seq: int | None = None,
                 verify_records: bool = False) -> dict:
    # Only read the database and verify its exported signed records using a key supplied
    # by the caller, never automatically trusting a key bundled in an audit packet.
    base = _home(home)
    db_uri = 'file:' + str(base / 'connect.sqlite') + '?mode=ro'
    try:
        db = sqlite3.connect(db_uri, uri=True)
        rows=db.execute('SELECT d.seq,d.token,a.outcome,a.body FROM decisions d LEFT JOIN audit_entries a ON d.seq=a.seq ORDER BY d.seq').fetchall()
        operation_rows=db.execute('SELECT state,decision,outcome,body FROM operations WHERE body IS NOT NULL').fetchall()
        records=db.execute('SELECT record_id,content FROM records ORDER BY record_id').fetchall()
        epoch_rows=db.execute('SELECT seq,public,previous_key_hash,rotation FROM key_epochs ORDER BY seq').fetchall()
        db.close()
    except sqlite3.Error as e:
        raise ProtectionError('audit_database_unavailable', 404) from e
    from .key_history import inspect as verify_epochs
    from .signing import verify as verify_token
    epoch_list=[dict(zip(('sequence','public','previous_key_hash','rotation'),x)) for x in epoch_rows]
    if not epoch_list or seller_public not in [e['public'] for e in epoch_list]:raise ProtectionError('unpinned_seller_key',403)
    verify_epochs(epoch_list,epoch_list[0]['public'])
    keys=[e['public'] for e in epoch_list]
    entries=[]
    for seq,token,outcome,rawbody in rows:
        if not outcome or rawbody is None:raise ProtectionError('audit_entry_missing',409)
        body=json.loads(rawbody)
        entries.append({'receipt':token,'outcome':outcome,'body':body,'decision_seq':seq})
    for state,receipt,outcome,raw in operation_rows:
        item=json.loads(raw)
        if item.get('receipt')!=receipt or item.get('outcome')!=outcome or item.get('state')!=state:
            raise ProtectionError('operation_audit_tampered',409)
        claim=verify_token(receipt,{'seller':keys},kind='openline.connect.decision.v1')
        recorded=next((e for e in entries if e['decision_seq']==claim['decision_seq']),None)
        if not recorded or recorded['receipt']!=receipt or recorded['outcome']!=outcome or recorded['body']!=item.get('body'):
            raise ProtectionError('operation_body_audit_mismatch',409)
    if not entries:
        return {'verified': False, 'reason': 'no_signed_decisions_yet', 'entries': 0}
    result=inspect_receipts(entries, {'seller': keys},
                            expected_head=expected_head, expected_seq=expected_seq)
    if verify_records:
        from .signing import digest
        import re
        snapshots=[verify_token(e['outcome'],{'seller':keys},kind='openline.connect.outcome.v1')
                   for e in reversed(entries)]
        last=next((x for x in snapshots if x.get('records_snapshot_sha256') is not None
                   and x.get('application_tables_snapshot_sha256') is not None),None)
        if last is None:
            raise ValueError('no_signed_committed_state_snapshot')
        if last.get('records_snapshot_sha256')!=digest(records):
            raise ValueError('records_state_digest_mismatch')
        result['records_state_matches_latest_signed_outcome']=True
        names=last.get('application_tables')
        if type(names) is not list or not names or any(type(n) is not str or
               not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,62}',n) for n in names):
            raise ValueError('invalid_signed_application_table_manifest')
        with sqlite3.connect(db_uri,uri=True) as verify_db:
            actual=ConnectEngine.__new__(ConnectEngine)._application_tables_hash(verify_db,names)
        if actual!=last.get('application_tables_snapshot_sha256'):
            raise ValueError('application_tables_snapshot_mismatch')
        result['application_tables_match_signed_outcome']=True
    result['pinned_first_epoch']=seller_public==epoch_list[0]['public']
    return result

def issue_fictional_delegated_task(home: str | Path, *, action: str, params: dict,
                                    task_id: str, worker_subject: str,
                                    worker_seed: str, ttl_seconds: int = 180) -> dict:
    """LOCAL FIXTURE ONLY: task-bound buyer and worker signing credentials.

    Real buyers and workers MUST keep private keys outside the receiver.
    This test helper never grants receiver policy: allow() plus reload_policy()
    is separately required for a new exact-parameter task admission.
    """
    if (type(action) is not str or not action or type(params) is not dict or
        type(task_id) is not str or not 1 <= len(task_id) <= 96 or
        type(worker_subject) is not str or not worker_subject or
        worker_subject == 'fictional-buyer' or type(worker_seed) is not str or
        type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 3600):
        raise ProtectionError('invalid_fictional_task_delegation', 400)
    try:
        worker_public = pub(worker_seed)
        parameters_sha256 = digest(params)
    except (ValueError, TypeError, OverflowError) as exc:
        raise ProtectionError('invalid_fictional_task_delegation', 400) from exc
    base = _home(home)
    engine = read_engine(base)
    buyer_seed = (base / 'keys' / 'fictional-buyer.seed').read_text(encoding='ascii').strip()
    now = engine.clock()
    expires = now + ttl_seconds
    scope = {'subject': 'fictional-buyer', 'seller': engine.seller_id,
             'action': action, 'target': params.get('target'),
             'parameters_sha256': parameters_sha256, 'task_id': task_id,
             'max_amount_cents': params.get('amount_cents', 0),
             'nbf': now - 1, 'exp': expires}
    delegation_jti = 'delegation-' + secrets.token_hex(12)
    principal = sign({'kind': 'openline.connect.delegation.v1', **scope,
                      'delegate_subject': worker_subject,
                      'delegate_public': worker_public, 'jti': delegation_jti},
                     buyer_seed, 'fictional-buyer')
    worker = sign({'kind': 'openline.connect.mandate.v1', **scope,
                   'delegate_subject': worker_subject,
                   'jti': 'worker-' + secrets.token_hex(12)},
                  worker_seed, worker_subject)
    return {'params': params, 'authorization': principal + ':' + worker,
            'task_id': task_id, 'nonce': 'attempt-' + secrets.token_hex(12),
            'delegation_id': delegation_jti, 'worker_public': worker_public,
            'expires_at': expires, 'fixture_only': True}
