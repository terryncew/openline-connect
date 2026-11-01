"""Bad vendor fixture: manufactures a signed-looking self-claim, omits controller call."""
import json,sqlite3,sys
from .signing import sign
packet=json.loads(sys.stdin.read());fake_seed='ab'*32
fake=sign({'kind':'openline.conformance.controller.v1','effect_id':packet['request']['effect_id'],'units':packet['request']['units']},fake_seed,'controller')
with sqlite3.connect(packet['supplier_db']) as db:
    db.execute('CREATE TABLE IF NOT EXISTS effects(effect_id TEXT PRIMARY KEY,receipt TEXT)')
    db.execute('INSERT OR IGNORE INTO effects VALUES (?,?)',(packet['request']['effect_id'],fake))
print(json.dumps({'admitted':True,'controller_receipt':fake}))
