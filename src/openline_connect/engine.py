"""Receiver-owned guarded local transaction ledger, adapted from Accept PR95/96.

SQLite is the ONLY atomic effect boundary. External side effects require a separate,
carefully reviewed outbox/reconciliation integration, and are not claimed atomic here.
"""
from __future__ import annotations
import json,sqlite3,time,hashlib,functools,inspect
from pathlib import Path
from contextlib import closing
from .signing import sign,verify,digest,pub,canon

class ProtectionError(Exception):
    def __init__(self,code,status=403):self.code=code;self.status=status;super().__init__(code)

def _parse_db(d):
    if not isinstance(d,str) or not d.startswith('sqlite:///'):raise ValueError('sqlite:/// absolute or relative path required')
    return d[len('sqlite:///'):]

class _EffectRows:
    """Only data values escape an effect query, never sqlite3.Cursor.connection."""
    __slots__ = ('_rows', 'rowcount', 'lastrowid')
    def __init__(self, cursor):
        self.rowcount=cursor.rowcount
        self.lastrowid=cursor.lastrowid
        self._rows=iter(cursor.fetchall()) if cursor.description is not None else iter(())
    def fetchone(self):
        return next(self._rows, None)
    def fetchall(self):
        return list(self._rows)

class _EffectDB:
    """Capability-limited SQLite access for *trusted* effect callbacks.

    sqlite3.set_authorizer classifies actual resolved table references, never
    substring-matches SQL text. This is no sandbox for arbitrary Python code.
    """
    __slots__ = ('__db','__tables','__functions')
    def __init__(self, db, allowed_tables=('records',), allowed_functions=()):
        self.__db=db
        self.__tables=frozenset(x.casefold() for x in allowed_tables)
        self.__functions=frozenset(x.casefold() for x in allowed_functions)
    def execute(self, sql, parameters=()):
        if not isinstance(sql,str) or not sql.strip():
            raise ProtectionError('effect_sql_invalid',400)
        if not isinstance(parameters,(tuple,list,dict)):
            raise ProtectionError('effect_parameters_required',400)
        import sqlite3
        tables=self.__tables
        funcs=self.__functions
        def auth(action,arg1,arg2,dbname,trigger):
            if trigger is not None:
                return sqlite3.SQLITE_DENY
            if action in (sqlite3.SQLITE_SELECT,):
                return sqlite3.SQLITE_OK
            if action in (sqlite3.SQLITE_READ,sqlite3.SQLITE_INSERT,sqlite3.SQLITE_UPDATE,sqlite3.SQLITE_DELETE):
                return sqlite3.SQLITE_OK if dbname == 'main' and isinstance(arg1,str) and arg1.casefold() in tables else sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_FUNCTION:
                return sqlite3.SQLITE_OK if isinstance(arg2,str) and arg2.casefold() in funcs else sqlite3.SQLITE_DENY
            # PRAGMA, ATTACH, CREATE/DROP, SAVEPOINT, TRANSACTION and extensions denied.
            return sqlite3.SQLITE_DENY
        db=self.__db
        db.set_authorizer(auth)
        try:
            try:
                cursor=db.execute(sql,parameters)
                return _EffectRows(cursor)
            except sqlite3.DatabaseError as exc:
                raise ProtectionError('effect_sql_capability_denied',403) from exc
        finally:
            db.set_authorizer(None)
    def commit(self):raise ProtectionError('effect_commit_forbidden',403)
    def rollback(self):raise ProtectionError('effect_rollback_forbidden',403)

def _scope_shape(scope):
    """Strict bounded authorization shape, no wildcard or implicit permission."""
    if not isinstance(scope,dict):raise ProtectionError('invalid_bounded_scope')
    acts=scope.get('allowed_actions');keys=scope.get('permitted_keys');workers=scope.get('allowed_worker_subjects')
    if (not isinstance(acts,list) or not acts or any(type(a) is not str or not a for a in acts)
        or len(set(acts))!=len(acts) or not isinstance(workers,list) or not workers
        or any(type(w) is not str or not w for w in workers) or len(set(workers))!=len(workers) or not isinstance(keys,list) or not keys
        or any(type(k) is not str or not k for k in keys) or len(set(keys))!=len(keys)):
        raise ProtectionError('invalid_bounded_scope')
    fixed=scope.get('fixed_params',{});targets=scope.get('target_restrictions',{})
    if type(fixed) is not dict or type(targets) is not dict or any(
        k not in keys for k in list(fixed)+list(targets)):
        raise ProtectionError('invalid_bounded_scope')
    if any(type(v) is not list or not v or any(type(t) not in (str,int) for t in v) or
           len({canon(t) for t in v})!=len(v) for v in targets.values()):
        raise ProtectionError('invalid_bounded_scope')
    amount=scope.get('amount_key','amount_cents')
    if type(amount) is not str or amount not in keys:
        raise ProtectionError('invalid_bounded_scope')
    for k in ('max_amount_per_op','max_cumulative_amount','max_uses'):
        if type(scope.get(k)) is not int or scope[k]<=0:
            raise ProtectionError('invalid_bounded_scope')
    if scope['max_amount_per_op']>scope['max_cumulative_amount']:
        raise ProtectionError('invalid_bounded_scope')
    try:canon(fixed)
    except (TypeError,ValueError,OverflowError):raise ProtectionError('invalid_bounded_scope')
    return {'actions':frozenset(acts),'workers':frozenset(workers),'keys':frozenset(keys),'fixed':fixed,
            'targets':targets,'amount_key':amount}

def _bound_subset(delegation,grant):
    """A buyer delegation may narrow, never widen, receiver authority."""
    d=_scope_shape(delegation);g=_scope_shape(grant)
    if (not d['actions']<=g['actions'] or not d['workers']<=g['workers'] or not d['keys']<=g['keys'] or
        d['amount_key']!=g['amount_key'] or any(
            delegation[x]>grant[x] for x in ('max_amount_per_op','max_cumulative_amount','max_uses'))):
        raise ProtectionError('delegation_scope_widening')
    for k,v in g['fixed'].items():
        if d['fixed'].get(k)!=v:raise ProtectionError('delegation_scope_widening')
    for k,values in g['targets'].items():
        if k in d['fixed']:
            if d['fixed'][k] not in values:raise ProtectionError('delegation_scope_widening')
        elif k not in d['targets'] or any(v not in values for v in d['targets'][k]):
            raise ProtectionError('delegation_scope_widening')
    return d,g

def _bound_matches(scope,action,params):
    spec=_scope_shape(scope)
    if action not in spec['actions']:raise ProtectionError('unpermitted_action')
    if not isinstance(params,dict) or any(type(k) is not str for k in params):
        raise ProtectionError('invalid_parameters')
    if not set(params)<=spec['keys']:raise ProtectionError('unpermitted_parameter_key')
    for k,v in spec['fixed'].items():
        if k not in params or type(params[k]) is not type(v) or params[k]!=v:
            raise ProtectionError('fixed_parameter_mismatch')
    for k,values in spec['targets'].items():
        if k not in params or type(params[k]) not in (str,int) or params[k] not in values:
            raise ProtectionError('target_not_permitted')
    amount=params.get(spec['amount_key'])
    if type(amount) is not int or amount<0:raise ProtectionError('invalid_bounded_amount')
    if amount>scope['max_amount_per_op']:raise ProtectionError('bounded_amount_exceeded')
    return amount

class ConnectEngine:
    """Local-only trusted receiver. The operator supplies its own private key.

    registered callbacks may only claim atomic local effects if *all* writes use the
    provided db connection. This cannot guard privileged direct DB/file access.
    """
    def __init__(self, database:str, policy:str|dict, *, seller_seed:str, seller_id='fictional-supplier', now=None):
        self.path=_parse_db(database);self.seed=seller_seed;self.seller_id=seller_id;self.clock=now or (lambda:int(time.time()))
        self._policy_path=Path(policy) if isinstance(policy,str) else None
        self.policy=json.loads(self._policy_path.read_text()) if self._policy_path else policy
        self._handlers={}
        sqlcap=self.policy.get('effect_sql', {'tables':['records'],'functions':[]})
        if not isinstance(sqlcap,dict):raise ValueError('invalid_sql_capability')
        import re
        tables=sqlcap.get('tables',['records'])
        funcs=sqlcap.get('functions',[])
        if not isinstance(tables,list) or not tables or not isinstance(funcs,list):raise ValueError('invalid_sql_capability')
        if any(not isinstance(t,str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,62}',t) for t in tables+funcs):
            raise ValueError('invalid_sql_capability_identifier')
        protected={'decisions','operations','revocations','audit_entries','key_epochs','capacity_usage','sqlite_master','sqlite_schema','sqlite_sequence'}
        if protected.intersection(t.casefold() for t in tables):raise ValueError('protected_table_not_grantable')
        self.effect_tables=tuple(tables)
        self.effect_functions=tuple(funcs)
        if not isinstance(self.policy,dict) or 'buyers' not in self.policy:raise ValueError('missing_receiver_policy')
        if not isinstance(self.policy.get('grants'), dict):
            raise ValueError('receiver_grants_required_default_deny')

        if len(bytes.fromhex(seller_seed))!=32:raise ValueError('bad_seed')
        Path(self.path).parent.mkdir(parents=True,exist_ok=True)
        with closing(self.db()) as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS operations(scope TEXT NOT NULL,nonce TEXT NOT NULL,request_sha TEXT NOT NULL,state TEXT NOT NULL,decision TEXT, outcome TEXT,body TEXT,settlement TEXT,created INTEGER,updated INTEGER,PRIMARY KEY(scope,nonce));
            CREATE TABLE IF NOT EXISTS decisions(seq INTEGER PRIMARY KEY AUTOINCREMENT,token TEXT NOT NULL,prev TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS revocations(token_id TEXT PRIMARY KEY,at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS records(record_id TEXT PRIMARY KEY,content TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS key_epochs(seq INTEGER PRIMARY KEY,public TEXT NOT NULL,previous_key_hash TEXT,rotation TEXT);
            CREATE TABLE IF NOT EXISTS audit_entries(seq INTEGER PRIMARY KEY,outcome TEXT NOT NULL,body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS capacity_usage(kind TEXT NOT NULL,token_id TEXT NOT NULL,used_count INTEGER NOT NULL,cumulative_amount INTEGER NOT NULL,signature TEXT NOT NULL,PRIMARY KEY(kind,token_id));
            ''')
            db.execute('INSERT OR IGNORE INTO key_epochs(seq,public,previous_key_hash,rotation) VALUES(1,?,NULL,NULL)',(pub(seller_seed),))
            key=db.execute('SELECT public FROM key_epochs ORDER BY seq DESC LIMIT 1').fetchone()[0]
            if key!=pub(seller_seed):raise ValueError('active_seller_key_does_not_match_database')
    def db(self):
        c=sqlite3.connect(self.path,timeout=10,isolation_level=None,check_same_thread=False)
        c.execute('PRAGMA journal_mode=WAL');c.execute('PRAGMA synchronous=FULL');c.execute('PRAGMA busy_timeout=10000')
        return c
    def reload_policy(self):
        """Explicit reload for receiver-operated file policy. Durable SQLite revocations survive."""
        if self._policy_path is None:raise ProtectionError('no_policy_file_to_reload',400)
        fresh=json.loads(self._policy_path.read_text())
        if not isinstance(fresh,dict) or not isinstance(fresh.get('buyers'),dict) or not isinstance(fresh.get('grants'),dict):
            raise ProtectionError('invalid_reloaded_policy',400)
        self.policy=fresh
        return {'reloaded':True,'grant_actions':sorted(fresh['grants'])}
    def protect(self,*,action,max_amount_cents=5000):
        """Bind exactly the arguments verified by signed receiver policy.

        Supports explicit signature arguments (including positional-only and keyword-
        only) or a single `params` mapping argument; injects restricted `db` only
        into the receiver-owned effect, never the caller's wrapper.
        """
        def decorator(fn):
            signature=inspect.signature(fn)
            declared=signature.parameters
            if any(p.kind in (inspect.Parameter.VAR_POSITIONAL,inspect.Parameter.VAR_KEYWORD)
                   for p in declared.values()):
                raise ValueError('unsupported_guarded_signature')
            dict_handler='params' in declared
            @functools.wraps(fn)
            def run(*args,**kwargs):
                authorization=kwargs.pop('_authorization',None)
                nonce=kwargs.pop('_nonce',None)
                if 'db' in kwargs:raise ProtectionError('untrusted_handler_db',400)
                try:bound=signature.bind_partial(*args,**kwargs)
                except TypeError as e:raise ProtectionError('invalid_guarded_arguments',400) from e
                if 'db' in bound.arguments:raise ProtectionError('untrusted_handler_db',400)
                bound.apply_defaults()
                missing=[p.name for p in declared.values() if p.name!='db'
                         and p.default is inspect.Parameter.empty and p.name not in bound.arguments]
                if missing:raise ProtectionError('missing_guarded_argument',400)
                if dict_handler:
                    if set(bound.arguments)!={'params'} or type(bound.arguments['params']) is not dict:
                        raise ProtectionError('invalid_params_mapping',400)
                    params=dict(bound.arguments['params'])
                else:params=dict(bound.arguments)
                if 'target' not in params:
                    order=params.get('order_id')
                    if type(order) is not str or not order:
                        raise ProtectionError('explicit_effect_target_required',400)
                    params['target']=order
                params.setdefault('amount_cents',0)
                result=self.execute(action=action,params=params,authorization=authorization,nonce=nonce)
                if result.get('decision')!='ALLOW':raise ProtectionError(result.get('reason','denied'))
                return result['body']
            def guarded(params,db):
                if dict_handler:
                    non_effect=set(declared)-{'db','params'}
                    if non_effect:raise ProtectionError('unsupported_mixed_params_handler',400)
                    if declared['params'].kind is inspect.Parameter.POSITIONAL_ONLY:
                        a=[dict(params)];kw={}
                    else:a=[];kw={'params':dict(params)}
                else:
                    unused=set(params)-set(declared)-{'target','amount_cents'}
                    if unused:raise ProtectionError('unhandled_signed_parameters',400)
                    a=[];kw={}
                    for param in declared.values():
                        if param.name=='db':continue
                        if param.name not in params:continue
                        if param.kind is inspect.Parameter.POSITIONAL_ONLY:
                            a.append(params[param.name])
                        else:kw[param.name]=params[param.name]
                if 'db' in declared:
                    if declared['db'].kind is inspect.Parameter.POSITIONAL_ONLY:
                        a.append(db)
                    else:kw['db']=db
                return fn(*a,**kw)
            self.register(action,guarded,max_amount_cents=max_amount_cents,atomic=True)
            return run
        return decorator
    def register(self,action,handler,*,max_amount_cents=5000,atomic=True,payment_required=False):
        if not isinstance(action,str) or not action or action in self._handlers:raise ValueError('duplicate_or_bad_action')
        self._handlers[action]=(handler,max_amount_cents,atomic,payment_required)
    def public(self):
        with closing(self.db()) as db:
            rows=db.execute('SELECT seq,public,previous_key_hash,rotation FROM key_epochs ORDER BY seq').fetchall()
            head=self._head(db)
        return {'schema':'openline.connect.discovery.v1','seller':self.seller_id,'current_key':pub(self.seed),'key_epochs':[dict(zip(('sequence','public','previous_key_hash','rotation'),r)) for r in rows],**head,'discovered_key_is_not_independent_trust':True}
    def _head(self,db):
        row=db.execute('SELECT seq,token FROM decisions ORDER BY seq DESC LIMIT 1').fetchone()
        return {'decision_seq':row[0] if row else 0,'head_decision_hash':hashlib.sha256(row[1].encode()).hexdigest() if row else '0'*64}
    def _records_hash(self,db):
        """Snapshot of local fictional records, not proof of external consequences."""
        return digest(db.execute('SELECT record_id,content FROM records ORDER BY record_id').fetchall())
    def _application_tables_hash(self,db,table_names=None):
        """Deterministic local SQLite digest for explicitly exposed application tables.

        Signed evidence of a receiver-controlled DB snapshot, not external effect proof.
        Trusted receiver provisioning owns schema; only validated policy identifiers.
        """
        names=tuple(table_names if table_names is not None else self.effect_tables)
        import re
        if any(type(x) is not str or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,62}',x) for x in names):
            raise ProtectionError('invalid_signed_effect_table',403)
        snapshots=[]
        for table in sorted(set(names),key=str.casefold):
            cur=db.execute('SELECT * FROM "'+table+'"')
            columns=[d[0] for d in cur.description]
            rows=[]
            for row in cur.fetchall():
                vals=[]
                for value in row:
                    if type(value) is bytes:
                        import base64
                        vals.append({'blob_base64':base64.b64encode(value).decode('ascii')})
                    elif type(value) in (str,int,bool,type(None)):
                        vals.append(value)
                    elif type(value) is float:
                        import math
                        if not math.isfinite(value):
                            raise ProtectionError('nonfinite_application_sql_real',409)
                        # SQLite's REAL storage class is distinct from INTEGER;
                        # canonical IEEE754 round-trip text avoids -0 and repr drift.
                        vals.append({'sqlite_real':('0' if value==0.0 else format(value,'.17g'))})
                    else:raise ProtectionError('unsupported_application_sql_value',409)
                rows.append(vals)
            rows.sort(key=lambda x:canon(x))
            snapshots.append({'table':table,'columns':columns,'rows':rows})
        return digest(snapshots)
    def _sign_outcome(self,db,claim,body,status):
        claim={**claim,'kind':'openline.connect.decision.v1','seller':self.seller_id}
        prev=self._head(db);claim['decision_seq']=prev['decision_seq']+1;claim['prev_decision_hash']=prev['head_decision_hash']
        token=sign(claim,self.seed,'seller')
        db.execute('INSERT INTO decisions(seq,token,prev) VALUES(?,?,?)',(claim['decision_seq'],token,prev['head_decision_hash']))
        # A failed/pre-effect request never ran an application handler. Avoid
        # a full-table scan and do not falsely attest a fresh state snapshot.
        # Independent audit instead compares the last signed COMMITTED snapshot.
        effect_committed=status=='FULFILLED'
        outcome={'kind':'openline.connect.outcome.v1','seller':self.seller_id,'decision_sha256':hashlib.sha256(token.encode()).hexdigest(),
                 'request_sha256':claim['request_sha256'],'status':status,'body_sha256':digest(body) if body is not None else None,
                 'settlement_status':claim.get('settlement_status'),'settlement_tx':claim.get('settlement_tx'),
                 'records_snapshot_sha256':self._records_hash(db) if effect_committed else None,
                 'application_tables':list(self.effect_tables),
                 'application_tables_snapshot_sha256':self._application_tables_hash(db) if effect_committed else None,
                 'snapshot_observed':effect_committed,
                 'at':claim['at'],
                 'claim_limit':'seller_attests_local_sqlite_effect_not_external_delivery'}
        signed=sign(outcome,self.seed,'seller')
        db.execute('INSERT INTO audit_entries(seq,outcome,body) VALUES(?,?,?)',
                   (claim['decision_seq'],signed,json.dumps(body)))
        return {'decision':claim['decision'],'reason':claim['reason'],'body':body,'receipt':token,'outcome':signed,
                'decision_seq':claim['decision_seq'],'head_decision_hash':hashlib.sha256(token.encode()).hexdigest(),
                'seller_attestation_only':True,'state':status}
    def _identity(self,authorization):
        """Verify cryptographic signer chain; policy/expiry checked at effect entry.

        A delegated worker has its own Ed25519 key; receiver's grant remains
        restricted to the principal subject and exact operation parameters.
        """
        if not isinstance(authorization,str):raise ProtectionError('untrusted_buyer_proof')
        delegated=':' in authorization
        if delegated and authorization.count(':')!=1:raise ProtectionError('invalid_delegation_chain')
        primary,worker=(authorization.split(':',1) if delegated else (authorization,None))
        principal=None
        for subject,key in self.policy['buyers'].items():
            if not isinstance(subject,str) or not subject:continue
            try:
                c=verify(primary,{subject:key},kind=('openline.connect.delegation.v1' if delegated else 'openline.connect.mandate.v1'))
            except ValueError:continue
            if c.get('subject')==subject:principal=c;break
        if principal is None:raise ProtectionError('untrusted_buyer_proof')
        if not delegated:return principal
        delegate=principal.get('delegate_subject')
        pubkey=principal.get('delegate_public')
        if not isinstance(delegate,str) or not delegate or delegate==principal['subject']:
            raise ProtectionError('invalid_delegate_subject')
        if not isinstance(pubkey,str) or len(pubkey)!=64:
            raise ProtectionError('invalid_delegate_public')
        try:
            bytes.fromhex(pubkey)
            mandate=verify(worker,{delegate:pubkey},kind='openline.connect.mandate.v1')
        except (ValueError,TypeError):raise ProtectionError('invalid_delegated_mandate')
        if mandate.get('subject')!=principal['subject'] or mandate.get('delegate_subject')!=delegate:
            raise ProtectionError('delegation_subject_mismatch')
        bounded=principal.get('grant_mode')=='bounded_scope_v1'
        common=('seller',) if bounded else ('seller','action','target','parameters_sha256','task_id')
        for k in common:
            if mandate.get(k)!=principal.get(k):raise ProtectionError('delegation_scope_mismatch')
        if bounded:
            _scope_shape(principal)
            if (mandate.get('grant_mode')!='bounded_scope_v1'
                or not isinstance(mandate.get('nonce'),str) and not isinstance(mandate.get('task_id'),str)):
                raise ProtectionError('delegation_scope_mismatch')
            if mandate.get('action') not in principal['allowed_actions'] or delegate not in principal['allowed_worker_subjects']:
                raise ProtectionError('delegation_scope_mismatch')
        if (type(principal.get('max_amount_cents')) is not int or type(mandate.get('max_amount_cents')) is not int
            or mandate['max_amount_cents']>principal['max_amount_cents']):
            raise ProtectionError('delegation_amount_exceeded')
        if (type(principal.get('nbf')) is not int or type(principal.get('exp')) is not int
            or type(mandate.get('nbf')) is not int or type(mandate.get('exp')) is not int
            or mandate['nbf']<principal['nbf'] or mandate['exp']>principal['exp']):
            raise ProtectionError('delegation_time_widening')
        if not isinstance(principal.get('jti'),str) or not principal['jti']:
            raise ProtectionError('invalid_delegation_id')
        return {**mandate,'_delegation_scope':principal if bounded else None,'_grant_mode':'bounded_scope_v1' if bounded else 'exact_parameters_v1','_delegation_jti':principal['jti'],'_delegate_subject':delegate,
                '_delegate_public':pubkey,'_principal_subject':principal['subject']}
    def _authority(self,db,action,params,authorization,now,*, inspect_existing=False,nonce=None,task_id=None):
        if not authorization:raise ProtectionError('authorization_required')
        claims=self._identity(authorization)
        if claims.get('_delegation_jti'):
            djti=claims['_delegation_jti']
            if db.execute('SELECT 1 FROM revocations WHERE token_id=?', (djti,)).fetchone() or (
                not inspect_existing and claims.get('_grant_mode')!='bounded_scope_v1' and db.execute('SELECT 1 FROM revocations WHERE token_id=?', ('used_delegation:'+djti,)).fetchone()):
                raise ProtectionError('revoked_or_consumed_delegation')
        if claims.get('seller')!=self.seller_id or claims.get('action')!=action or claims.get('target')!=params.get('target') or claims.get('parameters_sha256')!=digest(params):raise ProtectionError('mandate_binding_mismatch')
        if claims.get('_grant_mode')=='bounded_scope_v1':
            if task_id is not None:
                if claims.get('task_id')!=task_id:raise ProtectionError('bounded_task_binding_mismatch')
            elif nonce is not None and claims.get('nonce')!=nonce:
                raise ProtectionError('bounded_nonce_binding_mismatch')
        if type(claims.get('nbf')) is not int or type(claims.get('exp')) is not int or now<claims['nbf'] or now>=claims['exp']:raise ProtectionError('authorization_expired')
        if db.execute('SELECT 1 FROM revocations WHERE token_id=?',(claims.get('jti'),)).fetchone():raise ProtectionError('revoked_mandate')
        # Every bounded admission requires BOTH an independently receiver-signed
        # policy grant and a narrow buyer-signed delegation plus worker mandate.
        permitted=False
        selected_grant_id=None
        bounded_cap=None
        for grant in self.policy['grants'].get(action, []):
            try:
                signed=verify(grant['receiver_signature'],{'seller':pub(self.seed)},
                              kind='openline.connect.receiver_grant.v1')
            except (KeyError,ValueError,TypeError):continue
            if {k:v for k,v in signed.items() if k!='kind'}!={k:v for k,v in grant.items() if k!='receiver_signature'}:
                continue
            gid=grant.get('id',grant.get('jti'))
            if not (grant.get('active') is True and grant.get('subject')==claims.get('subject')
                    and type(gid) is str and bool(gid)
                    and type(grant.get('expires_at')) is int and grant['expires_at']>now
                    and not db.execute('SELECT 1 FROM revocations WHERE token_id=?',('grant:'+gid,)).fetchone()):
                continue
            mode=grant.get('grant_mode','exact_parameters_v1')
            if mode=='exact_parameters_v1':
                if (grant.get('action')==action and grant.get('target')==params.get('target')
                    and type(grant.get('parameters_sha256')) is str and grant['parameters_sha256']==digest(params)
                    and type(grant.get('max_amount_cents')) is int and type(params.get('amount_cents')) is int
                    and 0<=params['amount_cents']<=grant['max_amount_cents']
                    and (inspect_existing or not db.execute('SELECT 1 FROM revocations WHERE token_id=?',
                                    ('used_grant:'+gid,)).fetchone())):
                    permitted=True;selected_grant_id=gid;break
            elif mode=='bounded_scope_v1' and claims.get('_grant_mode')=='bounded_scope_v1':
                delegation=claims.get('_delegation_scope')
                if not isinstance(delegation,dict) or (delegation.get('subject')!=claims['subject'] or
                    delegation.get('seller')!=self.seller_id or
                    type(delegation.get('exp')) is not int or delegation['exp']>grant['expires_at']):
                    raise ProtectionError('delegation_scope_widening')
                _bound_subset(delegation,grant)
                if claims.get('_delegate_subject') not in grant['allowed_worker_subjects']:
                    raise ProtectionError('worker_not_permitted')
                amount=_bound_matches(grant,action,params)
                _bound_matches(delegation,action,params)
                if type(claims.get('max_amount_cents')) is not int or claims['max_amount_cents']<amount:
                    raise ProtectionError('mandate_amount_exceeded')
                if not inspect_existing:
                    for kind,ident,sc in (('receiver',gid,grant),('delegation',delegation['jti'],delegation)):
                        count,total=self._capacity_read(db,kind,ident,sc)
                        if count>=sc['max_uses'] or total+amount>sc['max_cumulative_amount']:
                            raise ProtectionError('bounded_capacity_exhausted')
                permitted=True;selected_grant_id=gid;bounded_cap={
                    'receiver':(gid,grant),'delegation':(delegation['jti'],delegation),
                    'amount':amount};break
        if not permitted:raise ProtectionError('receiver_allowlist_denied')
        if not isinstance(claims.get('jti'),str) or not claims['jti']:raise ProtectionError('invalid_mandate_id')
        if not inspect_existing and db.execute('SELECT 1 FROM revocations WHERE token_id=?',('used_jti:'+claims['jti'],)).fetchone():raise ProtectionError('replayed_mandate_jti')
        limit=self._handlers[action][1]
        amount=bounded_cap['amount'] if bounded_cap is not None else params.get('amount_cents',0)
        if type(amount) is not int or type(claims.get('max_amount_cents')) is not int or amount<0 or amount>limit or amount>claims['max_amount_cents']:raise ProtectionError('amount_exceeds_authority')
        return {**claims,'_receiver_grant_id':selected_grant_id,'_bounded_cap':bounded_cap}
    @staticmethod
    def _capacity_scope_hash(kind, scope):
        fields=('allowed_actions','allowed_worker_subjects','permitted_keys','fixed_params','target_restrictions',
                'amount_key','max_amount_per_op','max_cumulative_amount','max_uses')
        extras=('subject','seller','delegate_subject','delegate_public','exp') if kind=='delegation' else ('subject','action','expires_at')
        return digest({key:scope.get(key) for key in fields+extras})

    def _capacity_read(self,db,kind,ident,scope):
        row=db.execute('SELECT used_count,cumulative_amount,signature FROM capacity_usage WHERE kind=? AND token_id=?',
                       (kind,ident)).fetchone()
        if row is None:
            # A removed capacity row must not restore a consumed grant. Receiver
            # decisions are signed; only inspect earlier entries when no counter exists.
            # The local SQLite administrator remains trusted; an administrator able to
            # replace the entire ledger is outside this self-contained threat model.
            for (token,) in db.execute('SELECT token FROM decisions ORDER BY seq DESC'):
                try:
                    keys=[r[0] for r in db.execute('SELECT public FROM key_epochs ORDER BY seq')]
                    prior=verify(token,{'seller':keys},kind='openline.connect.decision.v1')
                except (ValueError,TypeError):
                    raise ProtectionError('capacity_state_tampered',409)
                ref=prior.get('receiver_grant_id') if kind=='receiver' else prior.get('delegation_id')
                if prior.get('decision')=='ALLOW' and ref==ident and prior.get('bounded_scope_v1') is True:
                    raise ProtectionError('capacity_state_tampered',409)
            return (0,0)
        count,total,signature=row
        keys=[r[0] for r in db.execute('SELECT public FROM key_epochs ORDER BY seq')]
        try:statement=verify(signature,{'seller':keys},kind='openline.connect.capacity.v1')
        except (ValueError,TypeError):raise ProtectionError('capacity_state_tampered',409)
        if (statement!={'kind':'openline.connect.capacity.v1','seller':self.seller_id,
                        'capacity_kind':kind,'token_id':ident,'used_count':count,'cumulative_amount':total,
                        'scope_sha256':self._capacity_scope_hash(kind,scope)}
            or type(count) is not int or type(total) is not int or count<0 or total<0):
            raise ProtectionError('capacity_state_tampered',409)
        return (count,total)

    def _charge_bounded(self,db,claims):
        cap=claims.get('_bounded_cap')
        if cap is None:return
        amount=cap['amount']
        for kind in ('receiver','delegation'):
            ident,limit=cap[kind]
            count,total=self._capacity_read(db,kind,ident,limit)
            if count>=limit['max_uses'] or total+amount>limit['max_cumulative_amount']:
                raise ProtectionError('bounded_capacity_exhausted')
            updated=sign({'kind':'openline.connect.capacity.v1','seller':self.seller_id,
                          'capacity_kind':kind,'token_id':ident,'used_count':count+1,
                          'cumulative_amount':total+amount,
                          'scope_sha256':self._capacity_scope_hash(kind,limit)},self.seed,'seller')
            db.execute('INSERT INTO capacity_usage(kind,token_id,used_count,cumulative_amount,signature) VALUES(?,?,?,?,?) '
                       'ON CONFLICT(kind,token_id) DO UPDATE SET used_count=excluded.used_count,cumulative_amount=excluded.cumulative_amount,signature=excluded.signature',
                       (kind,ident,count+1,total+amount,updated))

    def dry_run(self,action,params,authorization):
        if action not in self._handlers:return {'allowed':False,'reason':'unknown_operation'}
        with closing(self.db()) as db:
            try:
                c=self._authority(db,action,params,authorization,self.clock())
                return {'allowed':True,'subject':c['subject'],'target':c['target']}
            except ProtectionError as e:return {'allowed':False,'reason':e.code}
    def _payment(self,action,params,payment,now):
        if payment is None:return {'state':'NOT_APPLICABLE','tx':None}
        if not isinstance(payment,dict):raise ProtectionError('invalid_payment_context')
        if payment.get('unknown') is True:return {'state':'UNKNOWN','tx':None}
        fac=self.policy.get('facilitator_public')
        if not fac:raise ProtectionError('no_pinned_facilitator')
        try: c=verify(payment.get('assertion'),{'facilitator':fac},kind='openline.connect.mock_settlement.v1')
        except (ValueError,KeyError,TypeError):raise ProtectionError('untrusted_settlement_assertion')
        amt=c.get('amount')
        if not isinstance(amt,str) or not amt.isdecimal() or len(amt)>78 or int(amt)<max(1,params.get('amount_cents',0)):raise ProtectionError('invalid_atomic_amount')
        if (c.get('seller')!=self.seller_id or c.get('action')!=action or c.get('target')!=params.get('target') or
            c.get('request_sha256')!=digest(params) or c.get('status')!='SETTLED' or not c.get('tx')):raise ProtectionError('settlement_scope_mismatch')
        if type(c.get('nbf')) is not int or type(c.get('exp')) is not int or not c['nbf']<=now<c['exp']:raise ProtectionError('stale_settlement_assertion')
        return {'state':'ATTESTED_SETTLED','tx':c['tx'],'assertion':payment['assertion']}
    def execute_task(self,*,task_id,action,params,authorization,nonce=None,payment=None,fault=None):
        """Start/resume/inspect one signed task across credential changes.

        Stable identity is the receiver + principal + task_id + exact requested intent.
        The current worker must authenticate on EVERY request, including cache reads.
        A durable settlement in limbo is returned as reconciliation-required, never
        silently retried for an irreversible effect.
        """
        if not isinstance(task_id,str) or not 1<=len(task_id)<=96:
            raise ProtectionError('invalid_task_id',400)
        return self.execute(action=action,params=params,authorization=authorization,
                            nonce=nonce or 'attempt',payment=payment,fault=fault,task_id=task_id)

    def inspect_task(self,*,task_id,action,params,authorization):
        """Read-only task status, requiring *current* task-bound authority."""
        if not isinstance(task_id,str) or not 1<=len(task_id)<=96:
            raise ProtectionError('invalid_task_id',400)
        if action not in self._handlers:raise ProtectionError('unsupported_operation',404)
        identity=self._identity(authorization)
        if identity.get('task_id')!=task_id:raise ProtectionError('task_binding_mismatch')
        scope=self.seller_id+':'+action
        canonical=digest({'kind':'openline.connect.task_intent.v1','principal':identity['subject'],
                          'receiver':self.seller_id,'task_id':task_id,'action':action,
                          'params':params,'amount_cents':params.get('amount_cents',0)})
        with closing(self.db()) as db:
            db.execute('BEGIN IMMEDIATE')
            self._authority(db,action,params,authorization,self.clock(),inspect_existing=True)
            row=db.execute('SELECT request_sha,state,body FROM operations WHERE scope=? AND nonce=?',
                           (scope,'task:'+task_id)).fetchone()
            if row is None:raise ProtectionError('unknown_task',404)
            if row[0]!=canonical:raise ProtectionError('task_intent_mismatch',409)
            if row[1] in ('FULFILLED','COMPENSATED','REFUSED_PRE_EFFECT'):
                stored=json.loads(row[2]);receipt=stored.get('receipt');outcome=stored.get('outcome')
                keys=[x[0] for x in db.execute('SELECT public FROM key_epochs ORDER BY seq')]
                rc=verify(receipt,{'seller':keys},kind='openline.connect.decision.v1')
                oc=verify(outcome,{'seller':keys},kind='openline.connect.outcome.v1')
                if oc.get('body_sha256')!=(digest(stored.get('body')) if stored.get('body') is not None else None) or \
                   oc.get('decision_sha256')!=hashlib.sha256(receipt.encode()).hexdigest():
                    raise ProtectionError('stored_replay_evidence_tampered',409)
                audit=db.execute('SELECT outcome,body FROM audit_entries WHERE seq=?',(rc['decision_seq'],)).fetchone()
                if not audit or audit[0]!=outcome or json.loads(audit[1])!=stored.get('body'):
                    raise ProtectionError('stored_replay_audit_mismatch',409)
                return {**stored,'replayed':True,'task_id':task_id}
            return {'task_id':task_id,'state':row[1],
                    'reconciliation_required':row[1] in ('SETTLED_PENDING','SETTLEMENT_UNKNOWN','RESERVED','SETTLED_UNFULFILLED_REFUND_DUE')}

    def execute(self,*,action,params,authorization,nonce,payment=None,fault=None,task_id=None):
        now=self.clock()
        if action not in self._handlers:raise ProtectionError('unsupported_operation',404)
        # Payment required for NEW tasks; a known settled task can be inspected without a fresh assertion.
        if not isinstance(nonce,str) or not 1<=len(nonce)<=128:raise ProtectionError('invalid_nonce',400)
        if not isinstance(params,dict) or 'target' not in params:raise ProtectionError('target_required',400)
        # Reject unauthenticated nonce squatting before allocating any ledger slot.
        identity=self._identity(authorization)
        # Sign verified principal/delegate attribution into the receiver decision.
        attribution=({'task_id':task_id} if task_id is not None else {})
        attribution.update(({'delegate_subject':identity['_delegate_subject'],
                      'delegation_id':identity['_delegation_jti'],
                      'delegate_public_sha256':digest(identity['_delegate_public'])}
                     if identity.get('_delegation_jti') else {}))
        invocation_nonce=nonce
        if task_id is not None:
            if not isinstance(task_id,str) or not 1<=len(task_id)<=96 or identity.get('task_id')!=task_id:
                raise ProtectionError('task_binding_mismatch')
            req_sha=digest({'kind':'openline.connect.task_intent.v1','principal':identity['subject'],
                            'receiver':self.seller_id,'task_id':task_id,'action':action,
                            'params':params,'amount_cents':params.get('amount_cents',0)})
            nonce='task:'+task_id
        else:
            if nonce.startswith('task:'):raise ProtectionError('reserved_task_nonce_prefix',400)
            req_sha=digest({'action':action,'params':params,'authorization':authorization,'payment':payment})
        scope=self.seller_id+':'+action
        with closing(self.db()) as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                row=db.execute('SELECT request_sha,state,body,decision,outcome FROM operations WHERE scope=? AND nonce=?',(scope,nonce)).fetchone()
                if row:
                    # Auth before any cached-body/status disclosure; spent one-use rights
                    # permit inspection but revoked, expired, or changed scope never do.
                    try:
                        self._authority(db,action,params,authorization,now,inspect_existing=True,nonce=invocation_nonce,task_id=task_id)
                    except ProtectionError as exc:
                        if row[1]=='SETTLED_PENDING' and exc.code=='authorization_expired' and row[0]==req_sha:
                            # Previously committed fictional settlement; no new effect.
                            # Exact original signed request required and no handler call.
                            pass
                        elif row[1]=='REFUSED_PRE_EFFECT' and exc.code=='receiver_allowlist_denied' and row[0]==req_sha:
                            # A still-valid authenticated subject may learn only a
                            # generic refusal, never the original cached body or receipt.
                            db.commit()
                            return {'state':'REFUSED_PRE_EFFECT','decision':'DENY',
                                    'reason':'receiver_allowlist_denied','replayed':True}
                        else:
                            raise
                    if row[0]!=req_sha:raise ProtectionError('idempotency_payload_mismatch',409)

                    if row[1] in ('FULFILLED','REFUSED_PRE_EFFECT','COMPENSATED'):
                        stored=json.loads(row[2]);receipt=stored['receipt'];outcome=stored['outcome']
                        keys=[r[0] for r in db.execute('SELECT public FROM key_epochs ORDER BY seq')]
                        from .verify import inspect as verify_receipts
                        # Verify the signed outcome body before serving mutable cached data.
                        rc=verify(receipt,{'seller':keys},kind='openline.connect.decision.v1')
                        oc=verify(outcome,{'seller':keys},kind='openline.connect.outcome.v1')
                        if (oc['decision_sha256']!=hashlib.sha256(receipt.encode()).hexdigest() or
                            oc['body_sha256']!=(digest(stored['body']) if stored['body'] is not None else None)):
                            raise ProtectionError('stored_replay_evidence_tampered',409)
                        audit=db.execute('SELECT outcome,body FROM audit_entries WHERE seq=?',(rc['decision_seq'],)).fetchone()
                        if not audit or audit[0]!=outcome or json.loads(audit[1])!=stored['body']:
                            raise ProtectionError('stored_replay_audit_mismatch',409)
                        db.commit();return {**stored,'replayed':True}
                    if row[1] in ('SETTLEMENT_UNKNOWN','SETTLED_UNFULFILLED_REFUND_DUE'):
                        db.commit();return {'state':row[1],'replayed':True,'reconciliation_required':True,'signed_record':row[3]}
                    if row[1]=='RESERVED':
                        # No trusted callback can commit this state; an old corrupt row is unresolved.
                        raise ProtectionError('unexpected_reserved_state_requires_reconciliation',409)
                    if row[1]!='SETTLED_PENDING':raise ProtectionError('unexpected_durable_state',409)
                    # The simulated settlement was already recorded before a crash.
                    # Never execute an effect automatically on retry: require manual reconciliation.
                    settled=verify(db.execute('SELECT settlement FROM operations WHERE scope=? AND nonce=?',(scope,nonce)).fetchone()[0],
                                   {'facilitator':self.policy['facilitator_public']},kind='openline.connect.mock_settlement.v1')
                    claim={**attribution,'decision':'INDETERMINATE','reason':'settlement_pending_reconciliation',
                           'subject':identity['subject'],'authenticated_subject':True,
                           'action':action,'target':params['target'],'request_sha256':req_sha,
                           'parameters_sha256':digest(params),'settlement_status':'ATTESTED_SETTLED',
                           'settlement_tx':settled['tx'],'at':self.clock()}
                    r=self._sign_outcome(db,claim,None,'SETTLED_UNFULFILLED_REFUND_DUE')
                    db.execute('UPDATE operations SET state=?,decision=?,outcome=?,body=?,updated=? WHERE scope=? AND nonce=?',
                               ('SETTLED_UNFULFILLED_REFUND_DUE',r['receipt'],r['outcome'],json.dumps(r),self.clock(),scope,nonce))
                    db.commit();return {**r,'reconciliation_required':True}
                else:
                    if self._handlers[action][3] and payment is None:
                        raise ProtectionError('paid_operation_requires_verified_settlement_evidence',402)
                    previous_settled=False
                    db.execute('INSERT INTO operations(scope,nonce,request_sha,state,created,updated) VALUES(?,?,?,?,?,?)',(scope,nonce,req_sha,'RESERVED',now,now))
                try:c=self._authority(db,action,params,authorization,now,nonce=invocation_nonce,task_id=task_id)
                except ProtectionError as e:
                    # Must not rewrite recorded settlement if effect-time authority expired.
                    subject=identity['subject'] if isinstance(identity.get('subject'),str) and identity['subject'] else None
                    owed=previous_settled
                    state='SETTLED_UNFULFILLED_REFUND_DUE' if owed else 'REFUSED_PRE_EFFECT'
                    claim={**attribution,'decision':'INDETERMINATE' if owed else 'DENY','reason':e.code,'subject':subject,'authenticated_subject':subject is not None,
                           'action':action,'target':params['target'],'request_sha256':req_sha,'parameters_sha256':digest(params),
                           'settlement_status':'ATTESTED_SETTLED' if owed else 'NOT_APPLICABLE',
                           'settlement_tx':db.execute('SELECT settlement FROM operations WHERE scope=? AND nonce=?',(scope,nonce)).fetchone()[0] if False else None,'at':now}
                    r=self._sign_outcome(db,claim,None,state)
                    db.execute('UPDATE operations SET state=?,decision=?,outcome=?,body=?,updated=? WHERE scope=? AND nonce=?',(state,r['receipt'],r['outcome'],json.dumps(r),now,scope,nonce))
                    db.commit();return r
                payment_state=self._payment(action,params,payment,now)
                if payment_state['state']=='ATTESTED_SETTLED':
                    if db.execute('SELECT 1 FROM revocations WHERE token_id=?',('used_tx:'+payment_state['tx'],)).fetchone():
                        raise ProtectionError('replayed_settlement_tx',409)
                if payment_state['state']=='UNKNOWN':
                    claim={**attribution,'decision':'INDETERMINATE','reason':'external_settlement_unobserved','subject':c['subject'],'authenticated_subject':True,'action':action,'target':params['target'],'request_sha256':req_sha,'parameters_sha256':digest(params),'settlement_status':'UNKNOWN','at':now}
                    r=self._sign_outcome(db,claim,None,'SETTLEMENT_UNKNOWN')
                    db.execute('UPDATE operations SET state=?,decision=?,outcome=?,body=?,updated=? WHERE scope=? AND nonce=?',('SETTLEMENT_UNKNOWN',r['receipt'],r['outcome'],json.dumps(r),now,scope,nonce))
                    db.commit();return r
                if payment is not None and not previous_settled:
                    db.execute('UPDATE operations SET state=?,settlement=?,updated=? WHERE scope=? AND nonce=?',('SETTLED_PENDING',payment_state.get('assertion'),now,scope,nonce))
                    db.execute('INSERT INTO revocations VALUES(?,?)',('used_tx:'+payment_state['tx'],now))
                    db.commit()
                    if fault=='after_settlement':raise RuntimeError('SIMULATED_CRASH_AFTER_SETTLEMENT')
                    db.execute('BEGIN IMMEDIATE')
                    row=db.execute('SELECT state,request_sha FROM operations WHERE scope=? AND nonce=?',(scope,nonce)).fetchone()
                    if row!=('SETTLED_PENDING',req_sha):raise ProtectionError('operation_changed_during_settlement',409)
                if fault=='before_effect':raise RuntimeError('SIMULATED_CRASH_BEFORE_EFFECT')
                # Re-check right before the DB effect and signed record commit.
                effective=self.clock()
                try:self._authority(db,action,params,authorization,effective,nonce=invocation_nonce,task_id=task_id)
                except ProtectionError as exc:
                    state='SETTLED_UNFULFILLED_REFUND_DUE' if payment is not None else 'REFUSED_PRE_EFFECT'
                    claim={**attribution,'decision':'INDETERMINATE' if payment is not None else 'DENY','reason':exc.code,
                           'subject':c['subject'],'authenticated_subject':True,'action':action,'target':params['target'],
                           'request_sha256':req_sha,'parameters_sha256':digest(params),
                           'settlement_status':payment_state['state'],'settlement_tx':payment_state.get('tx'),'at':effective}
                    r=self._sign_outcome(db,claim,None,state)
                    db.execute('UPDATE operations SET state=?,decision=?,outcome=?,body=?,updated=? WHERE scope=? AND nonce=?',(state,r['receipt'],r['outcome'],json.dumps(r),effective,scope,nonce))
                    db.commit();return r
                handler,limit,atomic,requires_payment=self._handlers[action]
                if not atomic:raise ProtectionError('unproven_external_effect_atomicity',503)
                db.execute('SAVEPOINT effect')
                try:
                    body=handler(params,_EffectDB(db,self.effect_tables,self.effect_functions))
                    if fault=='effect_raises':raise RuntimeError('FICTIONAL_EFFECT_FAILURE')
                    self._charge_bounded(db,c)
                    db.execute('RELEASE effect')
                except Exception:
                    db.execute('ROLLBACK TO effect');db.execute('RELEASE effect')
                    claim={**attribution,'decision':'INDETERMINATE','reason':'local_effect_failed','subject':c['subject'],'authenticated_subject':True,'action':action,'target':params['target'],
                           'request_sha256':req_sha,'parameters_sha256':digest(params),'settlement_status':payment_state['state'],'settlement_tx':payment_state.get('tx'),'at':effective}
                    state='SETTLED_UNFULFILLED_REFUND_DUE' if payment is not None else 'REFUSED_PRE_EFFECT'
                    r=self._sign_outcome(db,claim,None,state)
                    db.execute('UPDATE operations SET state=?,decision=?,outcome=?,body=?,updated=? WHERE scope=? AND nonce=?',(state,r['receipt'],r['outcome'],json.dumps(r),effective,scope,nonce))
                    db.commit();return r
                bound_ref=({'bounded_scope_v1':True,'receiver_grant_id':c['_receiver_grant_id']}
                           if c.get('_bounded_cap') is not None else {})
                claim={**attribution,**bound_ref,'decision':'ALLOW','reason':'local_effect_committed','subject':c['subject'],'authenticated_subject':True,'action':action,'target':params['target'],
                       'request_sha256':req_sha,'parameters_sha256':digest(params),'settlement_status':payment_state['state'],'settlement_tx':payment_state.get('tx'),'at':effective}
                r=self._sign_outcome(db,claim,body,'FULFILLED')
                if payment is not None:
                    from .x402_wire import attach_offer_receipt
                    r['payment_response']=attach_offer_receipt({'x402Version':2,'transaction':payment_state.get('tx'),
                         'success':True,'scope':'mock_settlement_not_verified_by_x402_sdk'},r['outcome'])
                db.execute('INSERT INTO revocations VALUES(?,?)',('used_jti:'+c['jti'],effective))
                if c.get('_delegation_jti') and c.get('_bounded_cap') is None:
                    db.execute('INSERT INTO revocations VALUES(?,?)',('used_delegation:'+c['_delegation_jti'],effective))
                if c.get('_bounded_cap') is None:
                    db.execute('INSERT INTO revocations VALUES(?,?)',('used_grant:'+c['_receiver_grant_id'],effective))
                db.execute('UPDATE operations SET state=?,decision=?,outcome=?,body=?,updated=? WHERE scope=? AND nonce=?',('FULFILLED',r['receipt'],r['outcome'],json.dumps(r),effective,scope,nonce))
                db.commit();return r
            except BaseException:
                if db.in_transaction:db.rollback()
                raise
    def recover(self,scope,nonce):
        with closing(self.db()) as db:
            row=db.execute('SELECT state,request_sha,body FROM operations WHERE scope=? AND nonce=?',(scope,nonce)).fetchone()
            if not row:raise ProtectionError('unknown_operation',404)
            return {'state':row[0],'reconciliation_required':row[0] in ('RESERVED','SETTLEMENT_UNKNOWN','SETTLED_UNFULFILLED_REFUND_DUE','SETTLED_PENDING'),
                    'instruction':'do_not_retry_external_settlement_automatically','operation_scope':scope,'nonce':nonce}
    def record_mock_compensation(self,scope,nonce,compensation_assertion):
        """Operator-only local record of separately signed SIMULATED refund confirmation.

        This never initiates compensation; it also cannot prove real money refunded.
        """
        fac=self.policy.get('facilitator_public')
        if not fac:raise ProtectionError('no_pinned_facilitator')
        try:c=verify(compensation_assertion,{'facilitator':fac},kind='openline.connect.mock_compensation.v1')
        except ValueError:raise ProtectionError('invalid_compensation_attestation')
        with closing(self.db()) as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                row=db.execute('SELECT state,request_sha,settlement FROM operations WHERE scope=? AND nonce=?',(scope,nonce)).fetchone()
                if not row or row[0] not in ('SETTLED_UNFULFILLED_REFUND_DUE','SETTLED_PENDING'):raise ProtectionError('not_compensable',409)
                original=verify(row[2],{'facilitator':fac},kind='openline.connect.mock_settlement.v1')
                if (c.get('scope')!=scope or c.get('nonce')!=nonce or c.get('original_tx')!=original['tx'] or
                    not isinstance(c.get('refund_tx'),str) or not c['refund_tx'] or c.get('status')!='MOCK_REFUNDED'):
                    raise ProtectionError('compensation_scope_or_evidence_mismatch')
                claim={'decision':'COMPENSATED','reason':'facilitator_mock_refund_attested','subject':None,'authenticated_subject':False,
                    'action':scope.split(':',1)[-1],'target':None,'request_sha256':row[1],
                    'parameters_sha256':None,'settlement_status':'MOCK_COMPENSATED_NOT_REAL','settlement_tx':original['tx'],'at':self.clock()}
                result=self._sign_outcome(db,claim,{'refund_tx':c['refund_tx']},'COMPENSATED')
                db.execute('UPDATE operations SET state=?,decision=?,outcome=?,body=?,updated=? WHERE scope=? AND nonce=?',
                          ('COMPENSATED',result['receipt'],result['outcome'],json.dumps(result),self.clock(),scope,nonce))
                db.commit();return result
            except BaseException:
                if db.in_transaction:db.rollback()
                raise
    def revoke(self,jti):
        """Revoke one buyer mandate jti; receiver grants are separate."""
        if not isinstance(jti,str) or not jti:
            raise ProtectionError('invalid_mandate_id',400)
        with closing(self.db()) as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('INSERT OR IGNORE INTO revocations VALUES(?,?)',(jti,self.clock()))
            db.commit()
    def revoke_grant(self,grant_id):
        """Revoke receiver authority for all future SQLite effect entries."""
        if not isinstance(grant_id,str) or not grant_id:
            raise ProtectionError('invalid_grant_id',400)
        with closing(self.db()) as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('INSERT OR IGNORE INTO revocations VALUES(?,?)',
                       ('grant:' + grant_id,self.clock()))
            db.commit()
    def list_unresolved(self):
        with closing(self.db()) as db:
            return [dict(zip(('scope','nonce','state'),row)) for row in db.execute("SELECT scope,nonce,state FROM operations WHERE state IN ('RESERVED','SETTLED_PENDING','SETTLEMENT_UNKNOWN','SETTLED_UNFULFILLED_REFUND_DUE') ORDER BY created")]
    def inspect(self):return {'actions':sorted(self._handlers),'seller':self.seller_id,'policy_max':{a:v[1] for a,v in self._handlers.items()},'paid_actions':[a for a,v in self._handlers.items() if v[3]],**self.public()}
    def export(self):
        with closing(self.db()) as db:return [{'seq':a,'token':b} for a,b in db.execute('SELECT seq,token FROM decisions ORDER BY seq')]
    def rotate(self,new_seed):
        """Local receiver key succession. File + SQLite are NOT power-loss atomic.

        If interrupted between DB and file replacement, recovery requires the
        operator's separately retained new seed. Do not treat as remote/HSM custody.
        """
        if not isinstance(new_seed,str) or len(bytes.fromhex(new_seed))!=32:
            raise ProtectionError('bad_new_seed',400)
        old_seed=self.seed
        current=pub(old_seed)
        # Only a correctly signed existing grant may be renewed by the receiver.
        updated=json.loads(json.dumps(self.policy))
        for grants in updated['grants'].values():
            for grant in grants:
                original={k:v for k,v in grant.items() if k!='receiver_signature'}
                verified=verify(grant['receiver_signature'],{'seller':current},kind='openline.connect.receiver_grant.v1')
                if {k:v for k,v in verified.items() if k!='kind'}!=original:
                    raise ProtectionError('untrusted_grant_during_rotation',409)
                grant['receiver_signature']=sign({**original,'kind':'openline.connect.receiver_grant.v1'},new_seed,'seller')
        with closing(self.db()) as db:
            db.execute('BEGIN IMMEDIATE')
            last=db.execute('SELECT seq,public FROM key_epochs ORDER BY seq DESC LIMIT 1').fetchone()
            if last[1]!=current:raise ProtectionError('stale_seller_key')
            sequence=last[0]+1
            previous_hash=hashlib.sha256(bytes.fromhex(last[1])).hexdigest()
            record={'kind':'openline.connect.key_succession.v1','sequence':sequence,'previous_key_hash':previous_hash,'new_public':pub(new_seed),'seller':self.seller_id}
            token=sign(record,old_seed,'seller')
            db.execute('INSERT INTO key_epochs VALUES(?,?,?,?)',(sequence,pub(new_seed),previous_hash,token))
            db.commit()
        self.seed=new_seed
        self.policy=updated
        # The receiver local example maintains two root-owned files; do not
        # silently pretend this multi-file sequence is one atomic commit.
        for target,content in ((getattr(self,'_seed_file',None),new_seed+'\n'),
                               (getattr(self,'_policy_file',None),json.dumps(updated,indent=2,sort_keys=True))):
            if target is not None:
                import os,secrets
                path=Path(target)
                staged=path.with_name(path.name+'.rotate-'+secrets.token_hex(5))
                fd=os.open(staged,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                with os.fdopen(fd,'w') as file:
                    file.write(content);file.flush();os.fsync(file.fileno())
                os.replace(staged,path)
        return token