import json
import os
import subprocess
import sys
import unittest
import urllib.error
from unittest.mock import patch

import cve

ID='CVE-2021-44228'

def payload():
    return {'vulnerabilities':[{'cve':{'id':ID,'vulnStatus':'Analyzed','descriptions':[{'lang':'en','value':'Example description'}],
        'metrics':{'cvssMetricV31':[{'source':'nvd@nist.gov','type':'Primary','cvssData':{'version':'3.1','baseScore':10.0,'baseSeverity':'CRITICAL','vectorString':'CVSS:3.1/example'}}]},
        'references':[{'url':'https://example.com/advisory','source':'vendor','tags':['Vendor Advisory']}]}}]}


class Parsing(unittest.TestCase):
    def test_id(self):
        self.assertEqual(cve.normalize_id(ID.lower()),ID)
        for value in ['CVE-21-1234','CVE-2021-1','CVE-2021-44228&x=1',' '+ID,ID+'\n',None]:
            with self.subTest(value=value),self.assertRaises(cve.CVEError):cve.normalize_id(value)

    def test_summary(self):
        r=cve.summarize(payload(),ID)
        self.assertTrue(r['found']);self.assertEqual(r['scores'][0]['score'],10)
        self.assertEqual(r['description'],'Example description');self.assertEqual(len(r['references']),1)

    def test_not_found(self):
        r=cve.summarize({'vulnerabilities':[]},ID);self.assertFalse(r['found']);self.assertIn('does not prove',r['note'])

    def test_missing_optional(self):
        p={'vulnerabilities':[{'cve':{'id':ID}}]}
        r=cve.summarize(p,ID);self.assertEqual(r['scores'],[]);self.assertIsNone(r['description'])

    def test_multiple_sources(self):
        p=payload();entry=p['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0].copy();entry['source']='vendor'
        p['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'].append(entry)
        self.assertEqual(len(cve.summarize(p,ID)['scores']),2)

    def test_rejected_status_preserved(self):
        p=payload();p['vulnerabilities'][0]['cve']['vulnStatus']='Rejected'
        self.assertEqual(cve.summarize(p,ID)['status'],'Rejected')

    def test_bad_payloads(self):
        for p in [None,[],{}, {'vulnerabilities':{}},{'vulnerabilities':[None]},
                  {'vulnerabilities':[{'cve':{'id':'CVE-2020-1234'}}]}, {'vulnerabilities':[{},{}]}]:
            with self.subTest(p=p),self.assertRaises(cve.CVEError):cve.summarize(p,ID)

    def test_invalid_scores(self):
        for score in [True,-1,11,'10',None,float('nan')]:
            p=payload();p['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']=score
            with self.subTest(score=score),self.assertRaises(cve.CVEError):cve.summarize(p,ID)

    def test_reference_filter(self):
        p=payload();p['vulnerabilities'][0]['cve']['references']=[{'url':u} for u in ['javascript:alert(1)','file:///tmp/x','https://user:pass@example.com','http://[bad','https://example.com']]
        r=cve.summarize(p,ID);self.assertEqual(len(r['references']),1)

    def test_no_english(self):
        p=payload();p['vulnerabilities'][0]['cve']['descriptions']=[{'lang':'es','value':'x'}]
        self.assertIsNone(cve.summarize(p,ID)['description'])


class Network(unittest.TestCase):
    @patch('cve.urllib.request.build_opener')
    def test_request(self,opener):
        h=opener.return_value.open.return_value.__enter__.return_value
        h.read.return_value=json.dumps(payload()).encode()
        self.assertEqual(cve.fetch(ID),payload())
        args,kw=opener.return_value.open.call_args
        self.assertIn('cveIds='+ID,args[0].full_url);self.assertEqual(kw['timeout'],15)
        h.read.assert_called_once_with(cve.MAX_BYTES+1)

    @patch('cve.urllib.request.build_opener')
    def test_errors(self,opener):
        for error in [OSError(),TimeoutError(),urllib.error.URLError('down'),
                      urllib.error.HTTPError('x',429,'rate',{},None),urllib.error.HTTPError('x',500,'error',{},None)]:
            opener.return_value.open.side_effect=error
            with self.subTest(error=error),self.assertRaises(cve.CVEError):cve.fetch(ID)

    @patch('cve.urllib.request.build_opener')
    def test_bodies(self,opener):
        h=opener.return_value.open.return_value.__enter__.return_value
        for body in [b'invalid',b'\xff',b'x'*(cve.MAX_BYTES+1)]:
            h.read.return_value=body
            with self.subTest(size=len(body)),self.assertRaises(cve.CVEError):cve.fetch(ID)

    @patch('cve.urllib.request.build_opener')
    def test_options(self,opener):
        for timeout in [0,31,float('nan'),float('inf')]:
            with self.subTest(timeout=timeout),self.assertRaises(cve.CVEError):cve.fetch(ID,timeout)
        opener.assert_not_called()

    def test_redirect(self):
        self.assertIsNone(cve.NoRedirect().redirect_request(None,None,302,'',{},'http://127.0.0.1'))

    @patch('cve.fetch',return_value=payload())
    def test_lookup_metadata(self,fetch):
        r=cve.lookup(ID);self.assertIn('retrieved_at',r);self.assertIn('cveIds=',r['api_source'])


class CLI(unittest.TestCase):
    def test_invalid(self):
        p=subprocess.run([sys.executable,os.path.join(os.path.dirname(__file__),'cve.py'),'bad','--json'],stdout=subprocess.PIPE)
        self.assertEqual(p.returncode,2);self.assertIn('error',json.loads(p.stdout))


if __name__=='__main__':unittest.main()
