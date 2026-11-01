"""Independent company configurations; repeatable deterministic scenarios, synthetic identities."""
from .transport import newkey,public,sign,sha
from .adapters import build_cxml,build_agent
from .engine import Seller

PROFILES=['sap_cxml','coupa_cxml','agent_json']
TERMS='NET30_SYNTHETIC_v1'

def fixture(arm,count=3,seeds=None,root=None):
    if seeds is None:seeds=[newkey() for _ in range(3+count*2)]
    seller_seed=seeds[0];contract_seed=seeds[1];inventory_seed=seeds[2]
    buyers={}
    for i in range(count):
        name=f'buyer-{i+1:02d}'
        profile=PROFILES[i%3]
        buyers[name]={'profile':profile,'public':public(seeds[3+2*i]),'provider_public':public(seeds[4+2*i]),'shared_secret':'synthetic-secret-'+name}
    policy={'v':1,'kind':'policy','seller':'supplier','seq':1,'nbf':100,'exp':9999999,
            'sku':'industrial-filter-17','unit_cents':250000,'max_units':20,'terms':TERMS,
            'buyers':buyers,'sources':{'contract':public(contract_seed),'inventory':public(inventory_seed)},'revoked':[]}
    trust={'seller_public':public(seller_seed)}
    seller=Seller(str(root),arm,seller_seed,trust)
    seller.install(sign(policy,seller_seed,'seller',arm))
    return {'arm':arm,'seller':seller,'policy':policy,'seller_seed':seller_seed,'contract_seed':contract_seed,'inventory_seed':inventory_seed,'buyers':buyers,'buyer_seeds':seeds[3:]}

def payload(ctx,buyer='buyer-01',po='PO-1',now=10000,units=2,override=None):
    override=override or {}
    arm=ctx['arm'];cfg=ctx['buyers'][buyer];number=int(buyer.split('-')[1]);buyer_seed=ctx['buyer_seeds'][2*(number-1)];provider_seed=ctx['buyer_seeds'][2*(number-1)+1]
    profile=cfg['profile'];seller=ctx['seller']
    facts=[]
    for source,seed in [('contract',ctx['contract_seed']),('inventory',ctx['inventory_seed'])]:
        fact={'v':1,'kind':'business_evidence','issuer':source,'buyer':buyer,'po':po,'approved':True,'business_version':'1','nbf':100,'exp':20000}
        fact.update(override.get(source,{}))
        facts.append(sign(fact,seed,source,arm))
    mandate={'v':1,'kind':'buyer_mandate','seller':'supplier','buyer':buyer,'po':po,'sku':ctx['policy']['sku'],
             'profile':profile,'max_cents':units*ctx['policy']['unit_cents'],'jti':'jti-'+po,
             'nbf':100,'exp':20000,'evidence_hashes':sorted(facts)}
    mandate.update(override.get('mandate',{}))
    token=sign(mandate,buyer_seed,buyer,arm)
    if profile=='agent_json':
        purchase=build_agent(buyer,'supplier',po,ctx['policy']['sku'],units,ctx['policy']['unit_cents'],ctx['policy']['terms'])
        raw=sign({'v':1,'kind':'agent_purchase','buyer':buyer,'purchase':purchase,'mandate_sha':sha(token)},provider_seed,buyer,arm)
    else:
        raw=build_cxml(profile,buyer,'supplier',cfg['shared_secret'],po,ctx['policy']['sku'],units,ctx['policy']['unit_cents'],ctx['policy']['terms'])
    d={'buyer':buyer,'profile':profile,'order':raw,'mandate':token,'evidence':facts}
    d.update(override.get('payload',{}))
    return d

def update_policy(ctx,**changes):
    import copy
    p=copy.deepcopy(ctx['policy']);p['seq']+=1;p.update(changes)
    ctx['seller'].install(sign(p,ctx['seller_seed'],'seller',ctx['arm']));ctx['policy']=p

# Synthetic conventional and OpenLine adapters share semantics deliberately.
