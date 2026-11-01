"""Standalone verifier: public seller key and supplied tokens only, no seller DB.
Seller signing a claim never independently proves external ERP/order fulfillment.
"""
import sys,json,argparse
from pathlib import Path

from .transport import verify

def run(tokens,public,arm,outcomes=None):
    if outcomes is not None and len(outcomes)!=len(tokens):raise ValueError('decision_outcome_count')
    results=[]
    for i,tok in enumerate(tokens):
        value=verify(tok,{'seller':public},'seller_decision',arm)
        if value.get('scope')!='synthetic_sqlite_order_only_not_ERP_fulfillment':
            raise ValueError('unknown_scope')
        if value.get('decision')=='ACCEPTED' and value.get('local_effect')!='COMMITTED':
            raise ValueError('inconsistent_decision_effect_claim')
        if outcomes is not None:
            from .transport import sha
            o=verify(outcomes[i],{'seller':public},'seller_outcome',arm)
            if o.get('decision_sha256')!=sha(tok) or o.get('request_sha256')!=value.get('order_hash') or o.get('buyer')!=value.get('buyer') or o.get('po')!=value.get('po'):
                raise ValueError('outcome_decision_binding')
            expected='LOCAL_COMMIT' if value['decision']=='ACCEPTED' else 'PRIOR_COMMIT_NO_NEW_EFFECT' if value['decision']=='REPLAY_SAME' else 'NO_EFFECT'
            if o.get('status')!=expected or o.get('local_effect')!=value.get('local_effect') or o.get('scope')!=value.get('scope'):
                raise ValueError('outcome_claim_inconsistent')
        results.append({'po':value['po'],'decision':value['decision'],'signed':True,
                        'outcome_verified':outcomes is not None,'external_fulfillment_proof':False})
    return results

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('packet');args=ap.parse_args()
    x=json.load(open(args.packet));print(json.dumps(run(x['receipts'],x['seller_public'],x['arm']),indent=2))
