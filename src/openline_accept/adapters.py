"""Bounded, standards-shaped fixture adapters; NOT certified SAP/Coupa integration.
References: SAP cXML Solutions 2605; Coupa supplier cXML OrderRequest/OrderResponse.
No external HTTP, DTD, remote key discovery, or actual corporate identities.
"""
import decimal, hmac, json, re, xml.etree.ElementTree as ET

class FormatError(ValueError):pass

def _money(value):
    try:
        n=decimal.Decimal(str(value))
        if not n.is_finite() or n.as_tuple().exponent < -2 or n<=0:raise FormatError('invalid_money')
        cents=n*100
        if cents!=cents.to_integral_value():raise FormatError('subcent')
        return int(cents)
    except decimal.InvalidOperation:raise FormatError('invalid_money')

def _required(parent,path):
    node=parent.find(path)
    if node is None:raise FormatError('missing_'+path.replace('/','_'))
    return node

def read_cxml(raw,*, expected_profile, buyer_id, seller_id, shared_secret):
    if type(raw) is not str or len(raw)>50000 or re.search(r'<!\s*(DOCTYPE|ENTITY)',raw,re.I):
        raise FormatError('unsafe_xml')
    try:r=ET.fromstring(raw)
    except ET.ParseError:raise FormatError('broken_xml')
    if r.tag!='cXML' or r.get('payloadID') is None:raise FormatError('not_cxml')
    header=_required(r,'Header')
    actual_from=_required(header,'From/Credential/Identity').text
    actual_to=_required(header,'To/Credential/Identity').text
    actual_sender=_required(header,'Sender/Credential/Identity').text
    supplied=_required(header,'Sender/Credential/SharedSecret').text
    if (actual_from!=buyer_id or actual_to!=seller_id or actual_sender!=buyer_id or
        not hmac.compare_digest((supplied or '').encode(),shared_secret.encode())):
        raise FormatError('wrong_trading_parties_or_secret')
    if r.get('profile')!=expected_profile:raise FormatError('profile_binding')
    request=_required(r,'Request/OrderRequest')
    oh=_required(request,'OrderRequestHeader');oid=oh.get('orderID')
    if not oid or oh.get('type') not in ('new','update'):raise FormatError('order_header')
    if oh.get('type')!='new':raise FormatError('updates_need_separate_approval')
    items=request.findall('ItemOut')
    if len(items)!=1:raise FormatError('one_line_only_fixture')
    item=items[0];units=int(item.get('quantity','0'))
    if units<1 or units>100000:raise FormatError('invalid_units')
    sku=_required(item,'ItemID/SupplierPartID').text
    unit=_required(item,'ItemDetail/UnitPrice/Money')
    total=_required(oh,'Total/Money')
    if unit.get('currency')!='USD' or total.get('currency')!='USD':raise FormatError('currency')
    unit_cents=_money(unit.text);total_cents=_money(total.text)
    if units*unit_cents!=total_cents:raise FormatError('totals_do_not_reconcile')
    if not sku or len(sku)>80 or len(oid)>120:raise FormatError('identifier')
    return {'profile':expected_profile,'buyer':buyer_id,'seller':seller_id,'po':oid,'sku':sku,'units':units,'unit_cents':unit_cents,'total_cents':total_cents,'currency':'USD','terms':oh.get('terms')}

def build_cxml(profile,buyer,seller,secret,po,sku,units,unit_cents,terms):
    if profile not in ('sap_cxml','coupa_cxml'):raise ValueError('profile')
    price=f'{unit_cents/100:.2f}';total=f'{units*unit_cents/100:.2f}'
    r=ET.Element('cXML',{'payloadID':'synthetic-'+po,'timestamp':'2026-10-30T12:00:00Z','profile':profile})
    h=ET.SubElement(r,'Header')
    for label,name in [('From',buyer),('To',seller),('Sender',buyer)]:
        top=ET.SubElement(h,label);cred=ET.SubElement(top,'Credential',{'domain':'NetworkID' if profile=='sap_cxml' else 'DUNS'})
        ET.SubElement(cred,'Identity').text=name
        if label=='Sender':ET.SubElement(cred,'SharedSecret').text=secret
    req=ET.SubElement(ET.SubElement(r,'Request',{'deploymentMode':'test'}),'OrderRequest')
    oh=ET.SubElement(req,'OrderRequestHeader',{'orderID':po,'orderDate':'2026-10-30T12:00:00Z','type':'new','terms':terms})
    ET.SubElement(ET.SubElement(oh,'Total'),'Money',{'currency':'USD'}).text=total
    item=ET.SubElement(req,'ItemOut',{'quantity':str(units),'lineNumber':'1'})
    ET.SubElement(ET.SubElement(item,'ItemID'),'SupplierPartID').text=sku
    detail=ET.SubElement(item,'ItemDetail');ET.SubElement(ET.SubElement(detail,'UnitPrice'),'Money',{'currency':'USD'}).text=price
    ET.SubElement(detail,'Description',{'{http://www.w3.org/XML/1998/namespace}lang':'en'}).text='Synthetic inventory commitment, no physical goods'
    return ET.tostring(r,encoding='unicode')

def read_agent(blob,*, buyer_id,seller_id):
    if type(blob) is not dict or set(blob)!={'v','buyer','seller','po','sku','units','unit_cents','total_cents','currency','terms','profile'}:
        raise FormatError('agent_schema')
    if blob['v']!=1 or blob['profile']!='agent_json' or blob['buyer']!=buyer_id or blob['seller']!=seller_id:
        raise FormatError('agent_entity')
    if blob['currency']!='USD' or type(blob['units']) is not int or type(blob['unit_cents']) is not int or blob['units']<1 or blob['units']>100000 or blob['unit_cents']<=0 or blob['units']*blob['unit_cents']!=blob['total_cents']:
        raise FormatError('agent_totals')
    return {k:blob[k] for k in ('profile','buyer','seller','po','sku','units','unit_cents','total_cents','currency','terms')}

def build_agent(buyer,seller,po,sku,units,unit_cents,terms):
    return dict(v=1,profile='agent_json',buyer=buyer,seller=seller,po=po,sku=sku,units=units,unit_cents=unit_cents,total_cents=units*unit_cents,currency='USD',terms=terms)
