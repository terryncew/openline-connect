"""LOCAL FICTIONAL invoice workflow. Co-located keys are DEMO ONLY.

One receiver-signed bounded grant permits several buyer-delegated worker actions;
each concrete request has an individually worker-signed mandate.
No third-party payments, external settlements, or autonomous production effects.
"""
import json, sqlite3, tempfile
from pathlib import Path
from openline_connect.onboarding import (
    initialize, read_engine, allow_bounded, issue_fictional_bounded_invocation)


def run():
    with tempfile.TemporaryDirectory() as root:
        home = Path(root)
        initialize(home)
        p = home / 'policy.json'
        policy = json.loads(p.read_text())
        policy['effect_sql'] = {'tables': ['invoices'], 'functions': []}
        p.write_text(json.dumps(policy))
        with sqlite3.connect(home / 'connect.sqlite') as db:
            db.execute('CREATE TABLE invoices(id TEXT PRIMARY KEY, vendor TEXT, amount INTEGER)')
        grant = allow_bounded(home, action='invoice.approve',
            permitted_keys=['target', 'department', 'vendor_id', 'amount_cents'],
            fixed_params={'department': 'engineering'},
            target_restrictions={'vendor_id': ['acme', 'beta']},
            allowed_worker_subjects=['worker-A', 'worker-B'],
            max_amount_per_op=300, max_cumulative_amount=600, max_uses=3)
        engine = read_engine(home)
        def effect(params, db):
            db.execute('INSERT INTO invoices VALUES(?,?,?)',
                (params['target'], params['vendor_id'], params['amount_cents']))
            return {'invoice_id': params['target']}
        engine.register('invoice.approve', effect, max_amount_cents=300)
        def request(index, *, vendor='acme', amount=200, worker='worker-A',
                    delegation='delegation-A', seed='23'*32, task=None):
            params = {'target': f'INV-{index}', 'department': 'engineering',
                      'vendor_id': vendor, 'amount_cents': amount}
            payload = issue_fictional_bounded_invocation(home,action='invoice.approve',
                params=params,grant_id=grant['grant_id'],delegation_id=delegation,
                worker_subject=worker,worker_seed=seed,task_id=task)
            request_args={k:payload[k] for k in ('action','params','authorization','nonce')}
            if task: request_args['task_id']=task
            return request_args
        one=engine.execute(**request(1))
        two=engine.execute(**request(2))
        out_of_scope=engine.execute(**request(22,vendor='unauthorized'))
        original=engine.execute_task(**request(3,task='lost-invoice-reply'))
        # Simulate the client dropping the reply; Worker A is revoked.
        engine.revoke('delegation-A')
        args=request(3,worker='worker-B',delegation='delegation-B',seed='34'*32,
                     task='lost-invoice-reply')
        recovered=engine.inspect_task(task_id='lost-invoice-reply',
            action=args['action'],params=args['params'],authorization=args['authorization'])
        over_cap=engine.execute(**request(4,worker='worker-B',
            delegation='delegation-B',seed='34'*32,amount=1))
        with engine.db() as db:
            effect_rows=db.execute('SELECT COUNT(*) FROM invoices').fetchone()[0]
            capacity=db.execute('SELECT kind,used_count,cumulative_amount FROM capacity_usage ORDER BY kind').fetchall()
        result={'two_prior_allowed':one['decision']=='ALLOW' and two['decision']=='ALLOW',
                'out_of_scope_refused':out_of_scope['decision']=='DENY',
                'worker_b_original_signed_receipt':original['receipt']==recovered['receipt'],
                'fourth_action_refused':over_cap['decision']=='DENY',
                'committed_invoice_rows':effect_rows,
                'receiver_budget':next((x[1:] for x in capacity if x[0]=='receiver'),None),
                'scope':'fictional single-host SQLite, not external payment completion'}
        assert result['two_prior_allowed'] and result['out_of_scope_refused']
        assert result['worker_b_original_signed_receipt'] and result['fourth_action_refused']
        assert effect_rows==3 and result['receiver_budget']==(3,600)
        print(json.dumps(result,sort_keys=True))

if __name__=='__main__':
    run()
