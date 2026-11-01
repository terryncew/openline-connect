"""Private OpenLine Accept 0.1 local seller evaluation commands, zero paid services."""
import argparse,json,os,secrets,stat,sys,time,urllib.request,urllib.error
from pathlib import Path
from .transport import newkey,public,sign,sha
from .adapters import build_cxml,build_agent
from .engine import Seller
from .audit import run as audit
from .gateway import serve,VERSION

PROFILES=['procurement_cxml','agent_json']

def write(path,obj,private=False):
    p=Path(path);p.parent.mkdir(parents=True,exist_ok=True)
    raw=json.dumps(obj,sort_keys=True,indent=2)+'\n'
    fd=os.open(str(p),os.O_CREAT|os.O_TRUNC|os.O_WRONLY,0o600 if private else 0o644)
    try:
        if private:os.fchmod(fd,0o600)
        os.write(fd,raw.encode())
    finally:os.close(fd)

def load(path):return json.loads(Path(path).read_text())

def seller_from_dir(d):
    d=Path(d);config=load(d/'seller.json')
    mode=os.stat(d/'seller.json').st_mode
    if mode & (stat.S_IRWXG|stat.S_IRWXO):raise ValueError('seller_key_file_must_be_0600')
    return Seller(d/'ledger.sqlite',config['arm'],config['seller_seed'],{'seller_public':config['seller_public']})

def init(d,arm):
    d=Path(d)
    if d.exists() and any(d.iterdir()):raise ValueError('destination_not_empty')
    d.mkdir(parents=True,exist_ok=True);os.chmod(d,0o700)
    now=int(time.time())
    seller_seed=newkey();contract_seed=newkey();inventory_seed=newkey()
    buyers={}
    for i,buyer in enumerate(('buyer-enterprise','buyer-agent')):
        buyer_seed,provider_seed=newkey(),newkey()
        profile='procurement_cxml' if i==0 else 'agent_json'
        buyers[buyer]={'profile':profile,'public':public(buyer_seed),'provider_public':public(provider_seed),'shared_secret':'local-'+secrets.token_hex(16)}
        write(d/f'{buyer}.json',{'buyer':buyer,'profile':profile,'buyer_seed':buyer_seed,'provider_seed':provider_seed,'shared_secret':buyers[buyer]['shared_secret']},True)
    policy={'v':1,'kind':'policy','seller':'supplier','seq':1,'nbf':now-60,'exp':now+86400,
            'sku':'industrial-filter-17','unit_cents':250000,'max_units':20,'terms':'NET30_SYNTHETIC_v1',
            'buyers':buyers,'sources':{'contract':public(contract_seed),'inventory':public(inventory_seed)},'revoked':[]}
    write(d/'seller.json',{'seller_seed':seller_seed,'seller_public':public(seller_seed),'arm':arm,'admin_token':secrets.token_urlsafe(32)},True)
    write(d/'source-contract.json',{'seed':contract_seed,'issuer':'contract'},True)
    write(d/'source-inventory.json',{'seed':inventory_seed,'issuer':'inventory'},True)
    write(d/'policy-public.json',policy)
    write(d/'public-config.json',{'arm':arm,'seller_public':public(seller_seed),'version':VERSION})
    s=seller_from_dir(d);s.install(sign(policy,seller_seed,'seller',arm))
    return {'arm':arm,'profiles':PROFILES,'seller_public':public(seller_seed),'health_path':'/v1/healthz'}

def create_request(d,buyer,po,units=2):
    d=Path(d);bc=load(d/f'{buyer}.json');policy=load(d/'policy-public.json');seller=load(d/'public-config.json')
    if type(units)!=int or not 0<units<=policy['max_units']:raise ValueError('invalid_units')
    now=int(time.time());facts=[]
    for name in ('contract','inventory'):
        c=load(d/f'source-{name}.json')
        body={'v':1,'kind':'business_evidence','issuer':name,'buyer':buyer,'po':po,'approved':True,'business_version':'1','nbf':now-30,'exp':now+3600}
        facts.append(sign(body,c['seed'],name,seller['arm']))
    mandate={'v':1,'kind':'buyer_mandate','seller':'supplier','buyer':buyer,'po':po,
             'sku':policy['sku'],'profile':bc['profile'],'max_cents':units*policy['unit_cents'],
             'jti':buyer+':'+po,'nbf':now-30,'exp':now+3600,'evidence_hashes':sorted(facts)}
    mandate_token=sign(mandate,bc['buyer_seed'],buyer,seller['arm'])
    if bc['profile']=='procurement_cxml':
        # Reference cXML-shaped offline procurement adapter; never certified as SAP/Coupa.
        raw=build_cxml('sap_cxml',buyer,'supplier',bc['shared_secret'],po,policy['sku'],units,policy['unit_cents'],policy['terms'])
    else:
        purchase=build_agent(buyer,'supplier',po,policy['sku'],units,policy['unit_cents'],policy['terms'])
        raw=sign({'v':1,'kind':'agent_purchase','buyer':buyer,'purchase':purchase,'mandate_sha':sha(mandate_token)},bc['provider_seed'],buyer,seller['arm'])
    return {'version':VERSION,'buyer':buyer,'profile':bc['profile'],'order':raw,'mandate':mandate_token,'evidence':facts}

def request(url,body=None,token=None,path='/v1/orders'):
    headers={'Accept':'application/json'}
    if token:headers['Authorization']='Bearer '+token
    data=None
    if body is not None:
        data=json.dumps(body,separators=(',',':')).encode()
        headers['Content-Type']='application/json'
    req=urllib.request.Request(url.rstrip('/')+path,data=data,headers=headers)
    try:
        with urllib.request.urlopen(req,timeout=10) as r:return r.status,json.loads(r.read())
    except urllib.error.HTTPError as e:return e.code,json.loads(e.read())

def rotate(d,buyer):
    d=Path(d);config=load(d/'seller.json');policy=load(d/'policy-public.json');bc=load(d/f'{buyer}.json')
    if bc['profile']!='agent_json':raise ValueError('only_agent_provider_rotation_supported')
    bc['provider_seed']=newkey();policy['buyers'][buyer]['provider_public']=public(bc['provider_seed']);policy['seq']+=1
    s=seller_from_dir(d);s.install(sign(policy,config['seller_seed'],'seller',config['arm']))
    write(d/f'{buyer}.json',bc,True);write(d/'policy-public.json',policy)
    return {'buyer':buyer,'policy_seq':policy['seq'],'new_provider_public':policy['buyers'][buyer]['provider_public']}

def update_operator_policy(d,*,revoked_jti=None,max_units=None,terms=None):
    d=Path(d);cfg=load(d/'seller.json');policy=load(d/'policy-public.json')
    if revoked_jti is not None:
        if len(revoked_jti)>200:raise ValueError('revocation_id_too_long')
        policy['revoked']=sorted(set(policy['revoked'])|{revoked_jti})
    if max_units is not None:
        if type(max_units) is not int or not 0<max_units<=100000:raise ValueError('max_units_out_of_scope')
        policy['max_units']=max_units
    if terms is not None:
        if terms not in ('NET30_SYNTHETIC_v1','NET15_SYNTHETIC_v2'):raise ValueError('unrecognized_synthetic_terms')
        policy['terms']=terms
    policy['seq']+=1
    seller_from_dir(d).install(sign(policy,cfg['seller_seed'],'seller',cfg['arm']))
    write(d/'policy-public.json',policy)
    return {'policy_seq':policy['seq'],'revoked':len(policy['revoked']),'max_units':policy['max_units'],'terms':policy['terms']}

def main(argv=None):
    ap=argparse.ArgumentParser(description='OpenLine Accept local evaluation (not for production)')
    sub=ap.add_subparsers(dest='cmd',required=True)
    p=sub.add_parser('init');p.add_argument('--dir',required=True);p.add_argument('--arm',choices=['connect','conventional'],default='connect')
    p=sub.add_parser('serve');p.add_argument('--dir',required=True);p.add_argument('--port',type=int,default=8765)
    p=sub.add_parser('make-request');p.add_argument('--dir',required=True);p.add_argument('--buyer',choices=['buyer-enterprise','buyer-agent'],default='buyer-agent');p.add_argument('--po',required=True);p.add_argument('--out',required=True)
    p=sub.add_parser('submit');p.add_argument('--url',default='http://127.0.0.1:8765');p.add_argument('--request',required=True);p.add_argument('--out')
    p=sub.add_parser('export');p.add_argument('--dir',required=True);p.add_argument('--out',required=True)
    p=sub.add_parser('verify');p.add_argument('--packet',required=True)
    p=sub.add_parser('revoke');p.add_argument('--dir',required=True);p.add_argument('--jti',required=True)
    p=sub.add_parser('set-policy');p.add_argument('--dir',required=True);p.add_argument('--max-units',type=int);p.add_argument('--terms')
    p=sub.add_parser('rotate-provider');p.add_argument('--dir',required=True);p.add_argument('--buyer',default='buyer-agent')
    sub.add_parser('quickstart')
    p=sub.add_parser('demo');p.add_argument('--dir',required=True);p.add_argument('--arm',choices=['connect','conventional'],default='connect')
    args=ap.parse_args(argv)
    if args.cmd=='quickstart':
        from importlib.resources import files
        print((files('openline_accept')/'QUICKSTART.md').read_text());return 0
    if args.cmd=='init':result=init(args.dir,args.arm)
    elif args.cmd=='serve':
        c=load(Path(args.dir)/'seller.json')
        print('local evaluation listening 127.0.0.1:'+str(args.port),flush=True)
        return serve(seller_from_dir(args.dir),c['admin_token'],port=args.port)
    elif args.cmd=='make-request':
        result=create_request(args.dir,args.buyer,args.po);write(args.out,result);result={'saved':args.out,'buyer':args.buyer,'po':args.po}
    elif args.cmd=='submit':
        status,result=request(args.url,load(args.request));result={'http_status':status,**result}
        if args.out:write(args.out,result)
    elif args.cmd=='export':
        s=seller_from_dir(args.dir);result={'version':VERSION,'arm':s.arm,'seller_public':s.trust['seller_public'],'receipts':s.export_receipts(),'outcomes':s.export_outcomes()};write(args.out,result);result={'saved':args.out,'receipts':len(result['receipts']),'outcomes':len(result['outcomes'])}
    elif args.cmd=='verify':
        pkt=load(args.packet)
        if pkt['version']!=VERSION:raise ValueError('unsupported_packet_version')
        result={'verified':audit(pkt['receipts'],pkt['seller_public'],pkt['arm'],pkt.get('outcomes')),'seller_log_access':False,'proves_external_fulfillment':False}
    elif args.cmd=='rotate-provider':result=rotate(args.dir,args.buyer)
    elif args.cmd=='revoke':result=update_operator_policy(args.dir,revoked_jti=args.jti)
    elif args.cmd=='set-policy':result=update_operator_policy(args.dir,max_units=args.max_units,terms=args.terms)
    elif args.cmd=='demo':
        result=init(args.dir,args.arm);s=seller_from_dir(args.dir)
        a=create_request(args.dir,'buyer-enterprise','PO-DEMO-001')
        b=create_request(args.dir,'buyer-agent','PO-DEMO-002')
        r1=s.submit({k:v for k,v in a.items() if k!='version'});r2=s.submit({k:v for k,v in b.items() if k!='version'})
        retry=s.submit({k:v for k,v in b.items() if k!='version'})
        old_key=s.trust['seller_public'];rotation=rotate(args.dir,'buyer-agent')
        c=create_request(args.dir,'buyer-agent','PO-DEMO-003')
        r3=s.submit({k:v for k,v in c.items() if k!='version'})
        pkt={'version':VERSION,'arm':s.arm,'seller_public':old_key,'receipts':s.export_receipts(),'outcomes':s.export_outcomes()}
        write(Path(args.dir)/'receipt-packet.json',pkt)
        audit_result=audit(pkt['receipts'],pkt['seller_public'],pkt['arm'],pkt['outcomes'])
        result={'arm':args.arm,'decisions':[r1['decision'],r2['decision'],retry['decision'],r3['decision']],
                'counts':s.counts(),'audit_count':len(audit_result),'provider_rotation':rotation,'outcome_claim':'local_sqlite_only'}
    print(json.dumps(result,sort_keys=True,indent=2))
    return 0
if __name__=='__main__':raise SystemExit(main())
