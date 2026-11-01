"""Source-exact local multi-principal collision and migration regressions."""
import concurrent.futures,sqlite3,tempfile,time,unittest
from pathlib import Path
from openline_connect.engine import ConnectEngine,ProtectionError
from openline_connect.principals import ReceiverAuthority,BuyerAuthority,WorkerIdentity
from openline_connect.signing import pub,verify

class MultiBuyer(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=str(Path(self.tmp.name)/'receiver.sqlite')
        self.sell_seed='11'*32
        self.buyers={s:BuyerAuthority(subject=s,private_seed=k*32) for s,k in (('alpha','21'),('beta','22'))}
        self.workers={s:{w:WorkerIdentity(subject=w,private_seed=k*32) for w,k in keys}
            for s,keys in {'alpha':[('worker-a','31'),('worker-b','32')], 'beta':[('worker-a','41'),('worker-b','42')]}.items()}
        self.policy=ReceiverAuthority.initial_policy(effect_tables=['invoices'])
        for s,b in self.buyers.items():
            self.policy=ReceiverAuthority.register_buyer(self.policy,buyer_subject=s,buyer_public=b.public_key)
        self.engine=self.make_engine(self.sell_seed,self.policy)
        with self.engine.db() as db:db.execute('CREATE TABLE invoices(buyer TEXT,invoice TEXT,amount INTEGER, UNIQUE(buyer,invoice))')
        self.grants={}
        ra=ReceiverAuthority(self.engine)
        for buyer in ('alpha','beta'):
            self.grants[buyer]=ra.issue_bounded_grant(buyer_subject=buyer,action='invoice.approve',grant_id='SAME-GRANT',
                allowed_worker_subjects=['worker-a','worker-b'],permitted_keys=['buyer','target','amount_cents'],
                fixed_params={'buyer':buyer},target_restrictions={},max_amount_per_op=100,
                max_cumulative_amount=200,max_uses=3,expires_at=int(time.time())+600)
        self.policy=self.engine.policy

    def make_engine(self,seed,policy):
        e=ConnectEngine('sqlite:///'+self.path,policy,seller_seed=seed,seller_id='receiver')
        def handler(params,db):
            db.execute('INSERT INTO invoices VALUES(?,?,?)',(params['buyer'],params['target'],params['amount_cents']))
            return {'invoice':params['target']}
        e.register('invoice.approve',handler,max_amount_cents=500)
        return e

    def request(self,buyer,worker='worker-a',invoice=None,task='same-task',mandate='SAME-MANDATE',delegation_id='SAME-DELEGATION'):
        wi=self.workers[buyer][worker]
        delegation=self.buyers[buyer].delegate(receiver_grant=self.grants[buyer],receiver_public=pub(self.engine.seed),
            receiver_id='receiver',worker_subject=worker,worker_public=wi.public_key,delegation_id=delegation_id)
        params={'buyer':buyer,'target':invoice or buyer+'-inv','amount_cents':50}
        return wi.request(delegation=delegation,buyer_subject=buyer,buyer_public=self.buyers[buyer].public_key,
                          action='invoice.approve',params=params,task_id=task,mandate_id=mandate)

    def test_identical_all_ids_and_independent_recovery(self):
        a=self.request('alpha');b=self.request('beta')
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            ra,rb=ex.map(lambda q:self.engine.execute_task(**q),(a,b))
        self.assertEqual((ra['decision'],rb['decision']),('ALLOW','ALLOW'))
        self.assertNotEqual(ra['receipt'],rb['receipt'])
        with self.engine.db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM invoices').fetchone()[0],2)
            self.assertEqual(db.execute('SELECT count(*) FROM operations').fetchone()[0],2)
            self.assertEqual(db.execute('SELECT count(*) FROM capacity_usage').fetchone()[0],4)
            self.assertEqual(set(x[1] for x in db.execute('SELECT kind,token_id FROM capacity_usage')),set(x[0] for x in db.execute('SELECT token_id FROM capacity_usage')))
        self.engine.revoke('SAME-DELEGATION',buyer_subject='alpha')
        alpha_b=self.request('alpha',worker='worker-b',delegation_id='new-alpha',mandate='next-jti')
        recovered=self.engine.inspect_task(task_id='same-task',action='invoice.approve',params=alpha_b['params'],authorization=alpha_b['authorization'])
        self.assertEqual(recovered['receipt'],ra['receipt'])
        self.assertEqual(self.engine.execute_task(**alpha_b)['receipt'],ra['receipt'])
        self.assertEqual(self.engine.inspect_task(task_id='same-task',action='invoice.approve',params=b['params'],authorization=b['authorization'])['receipt'],rb['receipt'])
        cross={**b,'params':a['params']}
        with self.assertRaises(ProtectionError):self.engine.inspect_task(task_id='same-task',action='invoice.approve',params=cross['params'],authorization=cross['authorization'])
        with self.engine.db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM invoices').fetchone()[0],2)
            self.assertEqual(db.execute('SELECT sum(used_count) FROM capacity_usage WHERE kind="receiver"').fetchone()[0],2)

    def test_colliding_jti_revocations_and_grant_dont_cross(self):
        self.engine.revoke('SAME-MANDATE',buyer_subject='alpha')
        self.engine.revoke_grant('SAME-GRANT',buyer_subject='alpha')
        self.assertEqual(self.engine.execute_task(**self.request('beta'))['decision'],'ALLOW')
        self.assertEqual(self.engine.execute_task(**self.request('alpha'))['decision'],'DENY')
        with self.assertRaises(ProtectionError) as cm:self.engine.revoke('SAME-DELEGATION')
        self.assertEqual(cm.exception.code,'buyer_subject_required_for_scoped_revocation')

    def test_restart_and_receiver_rotation_maintain_tenant_recovery(self):
        original=self.engine.execute_task(**self.request('alpha'))
        self.engine.revoke('SAME-DELEGATION',buyer_subject='alpha')
        self.engine.rotate('63'*32)
        self.engine=self.make_engine('63'*32,self.engine.policy)
        self.grants={buyer:next(g for g in self.engine.policy['grants']['invoice.approve'] if g['subject']==buyer) for buyer in ('alpha','beta')}
        recover=self.request('alpha',worker='worker-b',delegation_id='successor',mandate='successor-jti')
        got=self.engine.inspect_task(task_id='same-task',action='invoice.approve',params=recover['params'],authorization=recover['authorization'])
        self.assertEqual(got['receipt'],original['receipt'])
        self.assertEqual(self.engine.execute_task(**recover)['receipt'],original['receipt'])
        self.assertEqual(self.engine.execute_task(**self.request('beta'))['decision'],'ALLOW')

    def test_multi_buyer_ledger_cannot_downgrade_to_legacy_one_buyer(self):
        self.assertEqual(self.engine.execute_task(**self.request('alpha'))['decision'],'ALLOW')
        reduced=dict(self.engine.policy)
        reduced['buyers']={'alpha':self.buyers['alpha'].public_key}
        with self.assertRaises(ProtectionError) as cm:
            self.make_engine(self.sell_seed,reduced)
        self.assertEqual(cm.exception.code,'multi_buyer_registry_downgrade_requires_migration')
        with self.engine.db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM capacity_usage').fetchone()[0],2)

    def test_pinned_buyer_public_change_does_not_reset_budget(self):
        self.assertEqual(self.engine.execute_task(**self.request('alpha'))['decision'],'ALLOW')
        amended=dict(self.engine.policy)
        amended['buyers']={**amended['buyers'],'alpha':self.workers['alpha']['worker-a'].public_key}
        with self.assertRaises(ProtectionError) as cm:
            self.make_engine(self.sell_seed,amended)
        self.assertEqual(cm.exception.code,'buyer_key_rotation_requires_explicit_migration')
        with self.engine.db() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM capacity_usage').fetchone()[0],2)

    def test_legacy_unscoped_state_fails_closed_without_reset(self):
        with tempfile.TemporaryDirectory() as tmp:
            dbpath=Path(tmp)/'legacy.sqlite'
            old={'buyers':{'alpha':self.buyers['alpha'].public_key},'grants':{},'effect_sql':{'tables':['records'],'functions':[]}}
            single=ConnectEngine('sqlite:///'+str(dbpath),old,seller_seed='a1'*32,seller_id='receiver')
            with single.db() as db:
                db.execute("INSERT INTO revocations VALUES('used_jti:OLD-ID',123)")
            new=dict(old);new['buyers']={**old['buyers'],'beta':self.buyers['beta'].public_key}
            with self.assertRaises(ProtectionError) as cm:
                ConnectEngine('sqlite:///'+str(dbpath),new,seller_seed='a1'*32,seller_id='receiver')
            self.assertEqual(cm.exception.code,'legacy_unscoped_state_requires_explicit_migration')
            with single.db() as db:self.assertEqual(db.execute('SELECT count(*) FROM revocations').fetchone()[0],1)

if __name__=='__main__':unittest.main()
