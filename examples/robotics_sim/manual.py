"""Persistent explicit 10-step CLI version of the hero simulation."""
from scenario import init,request,dispatch,amend_worker,apply_change,reapprove
from pathlib import Path
from wire import read,write

def step(state,number):
 state=Path(state)
 if number==1:return dispatch(state,'A','admit',{'request':request(state,'A','A','xfer-001',5)})
 if number==2:
  result=dispatch(state,'A','admit',{'request':request(state,'A','A','xfer-002',5),'crash':True});write(state/'unknown.json',{'xfer-002':'UNKNOWN'});return result
 if number==3:return amend_worker(state)
 if number==4:return dispatch(state,'A','recover',{'request':request(state,'A','B','xfer-002',op='recover')})
 if number==5:return dispatch(state,'A','admit',{'request':request(state,'A','A','xfer-003',5)})
 if number==6:return apply_change(state)
 if number==7:return dispatch(state,'A','admit',{'request':request(state,'A','B','xfer-003',10)})
 if number==8:return dispatch(state,'B','admit',{'request':request(state,'B','B','south-001',2)})
 if number==9:return reapprove(state)
 if number==10:return {'final':dispatch(state,'A','admit',{'request':request(state,'A','B','xfer-003',10)}),'north':dispatch(state,'A','inspect'),'south':dispatch(state,'B','inspect')}
 raise ValueError('STEP_1_TO_10')
