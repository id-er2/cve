#!/usr/bin/env python3
"""Read one CVE record from NVD. No scanning, exploit code or target interaction."""

import argparse
from datetime import datetime, timezone
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

ENDPOINT = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
MAX_BYTES = 4 * 1024 * 1024


class CVEError(ValueError):
    pass


def normalize_id(value):
    if not isinstance(value,str) or not re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,19}',value.upper()):
        raise CVEError('Use a CVE ID such as CVE-2021-44228')
    return value.upper()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(cve_id,timeout=15):
    cve_id=normalize_id(cve_id)
    if not 1<=timeout<=30: raise CVEError('Timeout must be between 1 and 30 seconds')
    request=urllib.request.Request(ENDPOINT+'?'+urllib.parse.urlencode({'cveIds':cve_id}),
                                  headers={'Accept':'application/json','User-Agent':'cve-lookup/1.0'})
    try:
        with urllib.request.build_opener(NoRedirect()).open(request,timeout=timeout) as response:
            data=response.read(MAX_BYTES+1)
    except urllib.error.HTTPError as exc:
        if exc.code in (403,429): raise CVEError('NVD denied or rate-limited the request; wait before a manual retry') from exc
        raise CVEError(f'NVD returned HTTP {exc.code}') from exc
    except (urllib.error.URLError,OSError,TimeoutError) as exc:
        raise CVEError('Could not reach NVD (network or timeout)') from exc
    if len(data)>MAX_BYTES: raise CVEError('NVD response exceeded 4 MiB')
    try: return json.loads(data)
    except (ValueError,UnicodeError) as exc: raise CVEError('NVD returned invalid JSON') from exc


def summarize(payload,cve_id):
    cve_id=normalize_id(cve_id)
    if not isinstance(payload,dict) or not isinstance(payload.get('vulnerabilities'),list):
        raise CVEError('Malformed NVD response')
    items=payload['vulnerabilities']
    if not items: return {'id':cve_id,'found':False,'note':'Not returned by NVD. It may be reserved, not yet received or unavailable; this does not prove it does not exist.'}
    if len(items)!=1 or not isinstance(items[0],dict) or not isinstance(items[0].get('cve'),dict):
        raise CVEError('Unexpected number or shape of CVE records')
    cve=items[0]['cve']
    if cve.get('id')!=cve_id: raise CVEError('NVD returned a different CVE ID')
    descriptions=cve.get('descriptions',[])
    if not isinstance(descriptions,list): raise CVEError('Malformed descriptions')
    description=next((x.get('value') for x in descriptions if isinstance(x,dict) and x.get('lang')=='en' and isinstance(x.get('value'),str)),None)
    scores=[]
    metrics=cve.get('metrics',{})
    if not isinstance(metrics,dict): raise CVEError('Malformed metrics')
    for group in ['cvssMetricV40','cvssMetricV31','cvssMetricV30','cvssMetricV2']:
        entries=metrics.get(group,[])
        if not isinstance(entries,list): raise CVEError('Malformed metric list')
        for entry in entries:
            if not isinstance(entry,dict) or not isinstance(entry.get('cvssData'),dict): raise CVEError('Malformed score')
            data=entry['cvssData'];score=data.get('baseScore')
            if type(score) not in (int,float) or not 0<=score<=10: raise CVEError('Invalid score')
            scores.append({'version':data.get('version'),'source':entry.get('source'),
                           'type':entry.get('type'),'score':score,
                           'severity':data.get('baseSeverity',entry.get('baseSeverity')),
                           'vector':data.get('vectorString')})
    refs=cve.get('references',[])
    if not isinstance(refs,list): raise CVEError('Malformed references')
    references=[]
    for item in refs:
        if not isinstance(item,dict) or not isinstance(item.get('url'),str): continue
        url=item['url']
        try:p=urllib.parse.urlsplit(url)
        except ValueError:continue
        if p.scheme not in ('http','https') or not p.hostname or p.username is not None:continue
        references.append({'url':url,'source':item.get('source'),'tags':item.get('tags',[])})
    return {'id':cve_id,'found':True,'status':cve.get('vulnStatus'),
            'source_identifier':cve.get('sourceIdentifier'),'published':cve.get('published'),
            'last_modified':cve.get('lastModified'),'description':description,'scores':scores,
            'references':references,
            'note':'NVD data, not a scan or a verdict that your software is affected. Check vendor advisories and installed versions. References are untrusted links and were not opened.'}


def lookup(cve_id,timeout=15):
    cve_id=normalize_id(cve_id)
    result=summarize(fetch(cve_id,timeout),cve_id)
    result['api_source']=ENDPOINT+'?'+urllib.parse.urlencode({'cveIds':cve_id})
    result['retrieved_at']=datetime.now(timezone.utc).isoformat()
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('id');parser.add_argument('--timeout',type=float,default=15)
    parser.add_argument('--json',action='store_true',help='JSON is also the default output')
    args=parser.parse_args(argv)
    try:result=lookup(args.id,args.timeout)
    except CVEError as exc:
        print(json.dumps({'error':str(exc)}));return 2
    print(json.dumps(result,ensure_ascii=True,indent=2))
    return 0 if result['found'] else 1


if __name__=='__main__':sys.exit(main())
