"""Start the REAL PR#90 openline_accept.Seller and gateway in a separate process.

Only loopback HTTP; policy/keys supplied by independent receiver-side files.
This module deliberately imports the installed openline_accept package, not a mock.
"""
import argparse,json
from pathlib import Path
from openline_accept.engine import Seller
from openline_accept.gateway import serve
from openline_connect.signing import sign,pub

def main(argv=None):
 p=argparse.ArgumentParser()
 p.add_argument('--config',required=True)
 args=p.parse_args(argv)
 config=json.loads(Path(args.config).read_text())
 seed=Path(config['receiver_key_path']).read_text().strip()
 policy=config['receiver_policy']
 seller=Seller(config['sqlite_path'],'connect',seed,{'seller_public':pub(seed)})
 seller.install(sign(policy,seed,'seller'))
 serve(seller,config['admin_token'],host='127.0.0.1',port=config['port'])
if __name__=='__main__': main()
