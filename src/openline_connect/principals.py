"""Public separated-authority helpers for local receiver-owned Connect grants.

Each caller owns its own Ed25519 seed; receiver APIs require public keys only.
No server, remote key registry, hosted identity or claims built by integrators.
"""
from __future__ import annotations
import copy
import os
from pathlib import Path
import secrets
import time
from .engine import ConnectEngine, ProtectionError, _scope_shape, _bound_subset, _bound_matches
from .signing import digest, pub, sign, verify


class _LocalIdentityKey:
    """Optional self-managed local key file; no receiver-mediated private keys."""
    def store(self,path):
        path=Path(path)
        path.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'w') as f:
            f.write(self._seed)
            f.flush();os.fsync(f.fileno())
        return path

    @classmethod
    def load(cls,*,subject,path):
        path=Path(path)
        if os.name=='posix' and path.stat().st_mode & 0o077:
            raise ProtectionError('private_key_file_permissions',400)
        return cls(subject=subject,private_seed=path.read_text().strip())


class ReceiverAuthority:
    """Receiver provisioning and bounded grant issuance; receiver seed stays here."""
    @staticmethod
    def initial_policy(*, effect_tables):
        if not isinstance(effect_tables, list) or not effect_tables:
            raise ValueError('effect_tables_required')
        return {'buyers':{}, 'grants':{},
                'effect_sql':{'tables':list(effect_tables),'functions':[]}}

    @staticmethod
    def register_buyer(policy, *, buyer_subject, buyer_public):
        if not isinstance(policy,dict) or not isinstance(policy.get('buyers'),dict):
            raise ValueError('invalid_receiver_policy')
        if not isinstance(buyer_subject,str) or not buyer_subject or not isinstance(buyer_public,str):
            raise ValueError('invalid_buyer_registration')
        try:
            if len(bytes.fromhex(buyer_public))!=32:raise ValueError('invalid_public_key')
        except (ValueError,TypeError):raise ValueError('invalid_public_key')
        if buyer_subject in policy['buyers'] or buyer_public in policy['buyers'].values():
            raise ValueError('buyer_identity_already_registered')
        policy=copy.deepcopy(policy)
        policy['buyers'][buyer_subject]=buyer_public
        return policy

    def __init__(self, engine:ConnectEngine):
        self.engine=engine

    def issue_bounded_grant(self, *, buyer_subject, action, grant_id,
                          allowed_worker_subjects, permitted_keys, fixed_params,
                          target_restrictions, max_amount_per_op,
                          max_cumulative_amount, max_uses, expires_at,
                          amount_key='amount_cents'):
        engine=self.engine
        if buyer_subject not in engine.policy['buyers']:
            raise ProtectionError('buyer_not_registered',400)
        if not isinstance(grant_id,str) or not grant_id:
            raise ProtectionError('invalid_grant_id',400)
        if type(expires_at) is not int or expires_at<=engine.clock():
            raise ProtectionError('invalid_grant_expiry',400)
        scope={'id':grant_id,'jti':grant_id,'grant_mode':'bounded_scope_v1',
               'subject':buyer_subject,'action':action,'allowed_actions':[action],
               'allowed_worker_subjects':list(allowed_worker_subjects),
               'permitted_keys':list(permitted_keys),'fixed_params':dict(fixed_params),
               'target_restrictions':copy.deepcopy(target_restrictions),
               'amount_key':amount_key, 'max_amount_per_op':max_amount_per_op,
               'max_cumulative_amount':max_cumulative_amount,'max_uses':max_uses,
               'expires_at':expires_at,'active':True}
        _scope_shape(scope)
        if action not in engine._handlers:
            raise ProtectionError('operation_not_registered',400)
        if any(g.get('subject')==buyer_subject and g.get('id')==grant_id
               for grants in engine.policy['grants'].values() for g in grants):
            raise ProtectionError('duplicate_grant_id',409)
        scope['receiver_signature']=sign({**scope,'kind':'openline.connect.receiver_grant.v1'},engine.seed,'seller')
        engine.policy['grants'].setdefault(action,[]).append(scope)
        return copy.deepcopy(scope)

    def revoke_buyer_mandate(self, *, buyer_subject, mandate_id):
        self.engine.revoke(mandate_id,buyer_subject=buyer_subject)

    def revoke_delegation(self, *, buyer_subject, delegation_id):
        self.engine.revoke(delegation_id,buyer_subject=buyer_subject)

    def revoke_grant(self, *, buyer_subject, grant_id):
        self.engine.revoke_grant(grant_id,buyer_subject=buyer_subject)

    def inspect(self):
        return self.engine.inspect()


class BuyerAuthority(_LocalIdentityKey):
    """Run by the buyer, never by the receiver; buyer secret stays with buyer."""
    def __init__(self, *, subject, private_seed):
        if not isinstance(subject,str) or not subject:
            raise ValueError('buyer_subject_required')
        self.subject=subject
        self._seed=private_seed
        self.public_key=pub(private_seed)

    @classmethod
    def generate(cls, *, subject):
        return cls(subject=subject,private_seed=secrets.token_hex(32))

    def delegate(self, *, receiver_grant, receiver_public, receiver_id,
                 worker_subject, worker_public, delegation_id,
                 expires_at=None, scope_limits=None, now=None):
        try:
            signed=verify(receiver_grant['receiver_signature'],{'seller':receiver_public},
                          kind='openline.connect.receiver_grant.v1')
        except (ValueError,KeyError,TypeError) as e:
            raise ProtectionError('invalid_receiver_grant') from e
        if {k:v for k,v in signed.items() if k!='kind'}!={k:v for k,v in receiver_grant.items() if k!='receiver_signature'}:
            raise ProtectionError('receiver_grant_tampered')
        if receiver_grant.get('subject')!=self.subject:
            raise ProtectionError('wrong_buyer_grant')
        if type(worker_public) is not str or len(worker_public)!=64 or type(worker_subject) is not str or not worker_subject:
            raise ProtectionError('invalid_worker_identity')
        if type(delegation_id) is not str or not delegation_id:
            raise ProtectionError('invalid_delegation_id')
        timestamp=int(time.time()) if now is None else now
        expiry=receiver_grant['expires_at'] if expires_at is None else expires_at
        if type(expiry) is not int or timestamp>=expiry or expiry>receiver_grant['expires_at']:
            raise ProtectionError('delegation_expiry_widening')
        fields=('allowed_actions','allowed_worker_subjects','permitted_keys',
                'fixed_params','target_restrictions','amount_key',
                'max_amount_per_op','max_cumulative_amount','max_uses')
        scope={k:copy.deepcopy(receiver_grant[k]) for k in fields}
        if scope_limits:scope.update(copy.deepcopy(scope_limits))
        delegation={'kind':'openline.connect.delegation.v1','grant_mode':'bounded_scope_v1',
                    'subject':self.subject,'seller':receiver_id,
                    'delegate_subject':worker_subject,'delegate_public':worker_public,
                    'jti':delegation_id,'nbf':timestamp-1,'exp':expiry,
                    'max_amount_cents':scope['max_amount_per_op'],**scope}
        _bound_subset(delegation,receiver_grant)
        if worker_subject not in scope['allowed_worker_subjects']:
            raise ProtectionError('worker_not_permitted')
        return sign(delegation,self._seed,self.subject)


class WorkerIdentity(_LocalIdentityKey):
    """Signs each concrete operation. Does not need either buyer or receiver private key."""
    def __init__(self, *, subject, private_seed):
        if not isinstance(subject,str) or not subject:raise ValueError('worker_subject_required')
        self.subject=subject
        self._seed=private_seed
        self.public_key=pub(private_seed)

    @classmethod
    def generate(cls, *, subject):
        return cls(subject=subject,private_seed=secrets.token_hex(32))

    def request(self, *, delegation, buyer_subject, buyer_public, action, params,
                task_id=None, nonce=None, mandate_id=None, now=None):
        try:claims=verify(delegation,{buyer_subject:buyer_public},kind='openline.connect.delegation.v1')
        except (ValueError,TypeError) as e:raise ProtectionError('invalid_buyer_delegation') from e
        if (claims.get('subject')!=buyer_subject or claims.get('delegate_subject')!=self.subject
            or claims.get('delegate_public')!=self.public_key or claims.get('grant_mode')!='bounded_scope_v1'):
            raise ProtectionError('wrong_worker_delegation')
        amount=_bound_matches(claims,action,params)
        timestamp=int(time.time()) if now is None else now
        if timestamp>=claims['exp']:raise ProtectionError('expired_delegation')
        nonce=nonce or 'attempt-'+secrets.token_hex(12)
        mandate={'kind':'openline.connect.mandate.v1','grant_mode':'bounded_scope_v1',
                 'subject':buyer_subject,'delegate_subject':self.subject,
                 'seller':claims['seller'],'action':action,'target':params['target'],
                 'parameters_sha256':digest(params),'max_amount_cents':claims['max_amount_cents'],
                 'nbf':timestamp-1,'exp':claims['exp'],'jti':mandate_id or 'mandate-'+secrets.token_hex(16)}
        if task_id is None:mandate['nonce']=nonce
        else:mandate['task_id']=task_id
        auth=delegation+':'+sign(mandate,self._seed,self.subject)
        request={'action':action,'params':dict(params),'nonce':nonce,'authorization':auth}
        if task_id is not None:request['task_id']=task_id
        return request

    def recovery_request(self, *, task_id, **kwargs):
        """Create a successor-signed, task-bound read/recovery request."""
        if not isinstance(task_id,str) or not task_id:
            raise ProtectionError('task_id_required_for_recovery',400)
        return {**self.request(task_id=task_id,**kwargs),'recover_only':True}

    @staticmethod
    def http_payload(request):
        """Guarded HTTP routes choose the action; remove that caller-side hint."""
        if not isinstance(request,dict) or 'action' not in request:
            raise ProtectionError('invalid_worker_request',400)
        return {key:value for key,value in request.items() if key!='action'}
