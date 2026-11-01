"""Independently written JWS verifier with real signed Accept receipts and negatives."""
import importlib.util,json,secrets,tempfile,unittest
from pathlib import Path
from openline_accept.scenarios import fixture,payload
from openline_accept.transport import sha

FILE=Path(__file__).resolve().parents[1]/'examples'/'independent_accept_verifier.py'
spec=importlib.util.spec_from_file_location('independent_accept_verifier',FILE)
verifier=importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)

class IndependentAcceptVerification(unittest.TestCase):
    def test_real_seller_receipts_and_falsifiers(self):
        with tempfile.TemporaryDirectory() as temp:
            f=fixture('connect',root=str(Path(temp)/'accept.sqlite'))
            obj=payload(f,buyer='buyer-03',po='PO-IND-1',now=10000)
            out=f['seller'].submit(obj,now=10000)
            self.assertEqual(out['decision'],'ACCEPTED')
            request_sha=sha({'raw':obj['order'],'profile':obj['profile'],'buyer':obj['buyer'],
                            'mandate':obj['mandate'],'evidence':obj['evidence']})
            kw=dict(receipt=out['receipt'],outcome=out['outcome'],seller_pub=f['seller'].trust['seller_public'],
                    buyer='buyer-03',po='PO-IND-1',request_sha256=request_sha)
            self.assertTrue(verifier.verify_pair(**kw)['verified'])
            for wrong in ({'buyer':'other'}, {'po':'PO-FORGED'}, {'request_sha256':'0'*64},
                          {'seller_pub':'ab'*32}, {'receipt':out['receipt'][:-2]+'aa'},
                          {'outcome':out['outcome'][:-2]+'aa'}):
                with self.subTest(wrong=wrong):
                    with self.assertRaises(ValueError):verifier.verify_pair(**{**kw,**wrong})
            self.assertEqual(f['seller'].counts()['orders'],1)

if __name__=='__main__':unittest.main()
