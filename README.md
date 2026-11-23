# cve

Read one CVE record from the NIST National Vulnerability Database (NVD).
Python 3.9+, standard library only. No scanning, target connections,
exploit execution or automatic opening of reference links.

## Usage

```
git clone https://github.com/id-er2/cve.git
cd cve
python3 cve.py CVE-2021-44228
python3 cve.py CVE-2021-44228 --json --timeout 10
```

JSON is the default output; `--json` is accepted for consistency with
other tools. Input is a single CVE ID, case-insensitive. No keyword
searches, bulk enumeration or API key setup are needed.

One GET request goes to NVD's fixed HTTPS API endpoint using `cveIds`.
The timeout is per socket operation, 1 to 30 seconds (default 15).
Responses are capped at 4 MiB. Redirects and automatic retries are
refused. A rate-limit or denied response is reported as an error rather
than retried in a loop. Wait before a manual retry and respect NVD's
current usage limits.

## Output

- `id`, `found` and NVD's vulnerability `status`
- Source identifier, publication date and last-modified date
- English description when one is present
- All supplied CVSS 4.0, 3.1, 3.0 and 2.0 score entries, retaining each
  score's source, type, version, severity and vector
- HTTP/HTTPS references as supplied by NVD, with source and tags
- Exact API source URL and UTC retrieval timestamp

Multiple CVSS sources are not silently collapsed to one score. A missing
score is not zero severity. NVD status, including Rejected or Awaiting
Analysis, is preserved. A record absent from the API can be reserved,
not yet received by NVD or otherwise unavailable. Absence does not prove
that a CVE does not exist.

## Interpretation and privacy

This is a record lookup, not a check of your computer or software. A CVE
entry alone cannot tell you whether an installed product/version/config
is affected. Check vendor advisories and your own inventory. Scores and
descriptions can change as the record is updated.

Reference links are untrusted data. The tool lists them but does not
visit them, run downloaded material or treat their contents as commands.
JSON escaping prevents record text from sending control characters to
your terminal.

NVD sees the requested CVE ID and client IP. No local software inventory,
files or target addresses are submitted. There is no cache or saved
history, though your terminal and shell may retain commands and output.

## Exit codes

- `0`: the requested record was returned, regardless of its NVD status
- `1`: NVD returned no record
- `2`: invalid ID, malformed response or network/API failure

Runtime errors are JSON objects with an `error` field. CLI syntax errors
use argparse's normal usage output.

## Tests

```
python3 -m unittest -v test_cve
```

Synthetic tests cover ID validation, record identity, missing records,
optional fields, multiple score sources, rejected status, score bounds,
reference filtering, request limits, errors and metadata. Tests make no
network requests. A separate live lookup was checked during development.

NVD API documentation:
https://nvd.nist.gov/developers/vulnerabilities

This product uses data from the NVD API but is not endorsed or certified
by the NVD.

## License

MIT. See [LICENSE](LICENSE).
