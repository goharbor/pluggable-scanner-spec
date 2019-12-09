# pluggable-scanner-spec

<img src="http://validator.swagger.io/validator?url=https://raw.githubusercontent.com/goharbor/pluggable-scanner-spec/master/api/spec/scanner-adapter-openapi-v1.0.yaml">

Open API spec definition for the scanners that can be plugged into Harbor to do artifact scanning.


## Background

Add support to Harbor for using other image scanners than just _Clair_ by replacing the current Clair-specific
scanning job implementation with an adapter layer implemented as an HTTP API between Harbor and the scanners' native
interfaces. This will provide runtime configurable scanner invocation to provide vulnerability scanning initially with
the option for other types of scanning in the future.

Introduce:
1. Scanner Adapter HTTP API (defined and maintained by Harbor)
   - Core operations:
     - Execute a scan (non-blocking)
     - Retrieve a scan report (polling by Harbor)
     - Describe the scanner’s capabilities, i.e. supported artifacts and reports
2. Scanner Adapter HTTP client in Harbor
3. Scanner Adapter configuration management and persistence in the Harbor DB

The adapter interface is a well-defined REST API specified and maintained by Harbor. Harbor will have a client for the
API, and manage configuration of the client. The configuration is primarily an endpoint registration, and multiple
configurations will be supported concurrently in the system. This will allow user-selectable and configurable scanning
of images at runtime with no restarts for Harbor required. Scanner adapters must implement the specified API, but the
deployment and configuration of the adapter services is out-of-scope and should be covered by the provider themselves. Harbor itself is
not responsible for management or deployment of the adapter services.

For more details, you can refer to the original [design proposal](https://github.com/goharbor/community/blob/master/proposals/pluggable-image-vulnerability-scanning_proposal.md).

## Scanner Adapter API

Scanner vendors are supposed to implement Scanner Adapters exposing the Scanner Adapter API as specified in
[Scanner Adapter v1.0 - OpenAPI Specification](./api/spec/scanner-adapter-openapi-v1.0.yaml).

> Note: OpenAPI spec yaml file can be opened in the online [Swagger Editor](https://editor.swagger.io/?url=https://raw.githubusercontent.com/goharbor/pluggable-scanner-spec/master/api/spec/scanner-adapter-openapi-v1.0.yaml).

- The deployment method is up to the vendor as long as the mounted API endpoint URL is accessible to Harbor services.
- For each ScanRequest a Scanner Adapter generates a unique identifier which is used to poll for the corresponding
  ScanReport.
- The lifetime of ScanRequest identifier returned by a Scanner Adapter is defined by the adapter. The TTL of the
  ScanReport and its identifier is long enough to support polling with reasonable timeouts.
- Scanner Adapters are not expected to persist scan reports forever, Harbor is supposed to cache at least the latest
  Scan Report.
- Scanner Adapters are not expected to make responses for the given artifact immutable, i.e. Scan Reports might change
  over time when new vulnerabilities are discovered.
- A Scan Job may get a 404 response status for a ScanRequest identifier and should treat it as failed and return a
  failure in the job. Harbor is expected to send a new Scan Request in that case.
- Scanner Adapter API leverages content negotiation by using MIME types in the `Accept` header to define schema of
  a result returned by GET `/scan/{scan_request_id}/report` requests.

### Sample Interaction between Harbor and Scanner Adapter

1. Make sure that the Scanner Adapter has expected capabilities:
   ```
   curl -H 'Accept: application/vnd.scanner.adapter.metadata+json; version=1.0" \
     http://scanner-adapter:8080/api/v1/metadata

   Content-Type: application/vnd.scanner.adapter.scanner.metadata+json; version=1.0
   Status: 200 OK

   {
     "scanner": {
       "name": "Microscanner",
       "vendor": "Aqua Security",
       "version": "3.0.5",
     },
     "capabilities": [
       {
         "consumes_mime_types": [
           "application/vnd.oci.image.manifest.v1+json",
           "application/vnd.docker.distribution.manifest.v2+json"
         ],
         "produces_mime_types": [
           "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0",
           "application/vnd.scanner.adapter.vuln.report.raw"
         ]
       }
     ],
     "properties": {
       "harbor.scanner-adapter/scanner-type": "os-package-vulnerability",
       "harbor.scanner-adapter/vulnerability-database-updated-at": "2019-08-13T08:16:33.345Z"
     }
   }
   ```
2. Submit the scan request
   1. Submit an invalid scan request:
       ```
       curl http://scanner-adapter:8080/api/v1/scan \
       -H 'Content-Type: application/vnd.scanner.adapter.scan.request+json; version=1.0' \
       -d @- << EOF
       {
         "registry": {
           "url": "INVALID_REGISTRY_URL",
           "authorization": "Bearer JWTTOKENGOESHERE"
         },
         "artifact": {
           "repository": "library/mongo",
           "digest": "sha256:917f5b7f4bef1b35ee90f03033f33a81002511c1e0767fd44276d4bd9cd2fa8e"
         }
       }
       EOF

       Status: 422 Unprocessable Entity
       Content-Type: application/vnd.scanner.adapter.error+json; version=1.0'

       {
         "error": {
           "message": "invalid registry_url"
         }
       }
       ```
   2. Submit a valid scan request:
       ```
       curl http://scanner-adapter:8080/api/v1/scan \
       -H 'Content-Type: application/vnd.scanner.adapter.scan.request+json; version=1.0' \
       -d @- << EOF
       {
         "registry": {
           "url": "harbor-harbor-registry:5000",
           "authorization": "Bearer: JWTTOKENGOESHERE"
         },
         "artifact": {
           "repository": "library/mongo",
           "digest": "sha256:917f5b7f4bef1b35ee90f03033f33a81002511c1e0767fd44276d4bd9cd2fa8e"
         }
       }
       EOF

       Status: 202 Accepted
       Content-Type: application/vnd.scanner.adapter.scan.response+json; version=1.0'

       {
         "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
       }
       ```
3. Try getting scan report (in unified Harbor format understandable by Harbor Web console):
   ```
   curl -H 'Accept: application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0' \
     http://scanner-adapter:8080/api/v1/scan/3fa85f64-5717-4562-b3fc-2c963f66afa6/report

   Retry-After: 15
   Status: 302 Found
   ```
4. Wait 15 seconds or use your own retry interval ...
5. ... and try getting scan report again:
   ```
   curl -H 'Accept: application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0' \
     http://scanner-adapter:8080/api/v1/scan/3fa85f64-5717-4562-b3fc-2c963f66afa6/report

   Content-Type: application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0
   Status: 200 OK

   {
     "generated_at": "2019-08-07T12:17:21.854Z",
     "artifact": {
       "repository": "library/mongo",
       "digest": "sha256:917f5b7f4bef1b35ee90f03033f33a81002511c1e0767fd44276d4bd9cd2fa8e"
     },
     "scanner": {
       "name": "Microscanner",
       "vendor": "Aqua Security",
       "version": "3.0.5",
     },
     "severity": "High",
     "vulnerabilities": [
       {
         "id": "CVE-2017-8283",
         "package": "dpkg",
         "version": "1.17.27",
         "fix_version": "1.18.0",
         "severity": "High",
         "description": "...",
         "links": [
           "https://security-tracker.debian.org/tracker/CVE-2017-8283"
         ]
       },
       ...
     ]
   }
   ```
6. Alternatively we could request a proprietary vulnerability report (with an example report generated
   by MicroScanner in JSON format):
   ```
   curl -H 'Accept: application/vnd.scanner.adapter.vuln.report.raw' \
      http://scanner-adapter:8080/api/v1/scan/3fa85f64-5717-4562-b3fc-2c963f66afa6/report

   Content-Type: application/vnd.scanner.adapter.vuln.report.raw
   Status: 200 OK

   {
     "scan_started": {
       "seconds": 1561386673,
       "nanos": 390482870
     },
     "scan_duration": 2,
     "digest": "b3c8bc6c39af8e8f18f5caf53eec3c6c4af60a1332d1736a0cd03e710388e9c8",
     "os": "debian",
     "version": "8",
     "resources": [
       {
         "resource": {
           "format": "deb",
           "name": "apt",
           "version": "1.0.9.8.5",
           "arch": "amd64",
           "cpe": "pkg:/debian:8:apt:1.0.9.8.5",
           "name_hash": "583f72a833c7dfd63c03edba3776247a"
         },
         "scanned": true,
         "vulnerabilities": [
           {
             "name": "CVE-2011-3374",
             "vendor_score_version": "Aqua",
             "vendor_severity": "negligible",
             "vendor_statement": "Not exploitable in Debian, since no keyring URI is defined",
             "vendor_url": "https://security-tracker.debian.org/tracker/CVE-2011-3374",
             "classification": "..."
           }
         ]
       }
     ]
   }
   ```

- The `Accept` request header is required to indicate to Scanner Adapter an intended scan report format
- If the client does not specify the `Accept` header it's assumed to be Harbor vulnerability report with the
  MIME type `application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0`.
- In phase 1 each Scanner Adapter should support at least the following artifact MIME types:
  - `application/vnd.oci.image.manifest.v1+json`
  - `application/vnd.docker.distribution.manifest.v2+json`
- In phase 1 each Scanner Adapter should support at least the following scan report MIME types:
  - `application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0` - corresponds to `HarborVulnerabilityReport`
     - fixed schema described in Scanner Adapter API spec
     - can be parsed in type-safe manner and displayed in Harbor Web console.
  - `application/vnd.scanner.adapter.vuln.report.raw`
    - corresponds to a raw scan report
    - no fixed schema, documented by a scanner's vendor
- New scan report MIME types might be introduced without breaking the backward compatibility of the API and introducing
  new URL paths to the Scanner Adapter API spec.
- For example, there can be a vendor specific policy report returned by Anchore with the corresponding MIME type
  `application/vnd.anchore.policy.report+json; version=0.3`:
  ```json
  [
    {
      "sha256:57334c50959f26ce1ee025d08f136c2292c128f84e7b229d1b0da5dac89e9866": {
        "docker.io/alpine:latest": [
          {
            "detail": {},
            "last_evaluation": "2019-08-07T06:33:48Z",
            "policyId": "2c53a13c-1765-11e8-82ef-23527761d060",
            "status": "pass"
          }
        ]
      }
    }
  ]
  ```

## Scanner Adapter Implementations

* [Clair](https://github.com/goharbor/harbor-scanner-clair)
* [Aqua Trivy](https://github.com/aquasecurity/harbor-scanner-trivy)
* [Anchore](https://github.com/anchore/harbor-scanner-adapter)
* [Aqua CSP](https://github.com/aquasecurity/harbor-scanner-aqua)
* [DoSec Scanner](https://github.com/dosec-cn/harbor-scanner/blob/master/README_en.md)

For more details, please refer to the [Harbor compatibility list](https://github.com/goharbor/harbor/blob/master/docs/harbor_compatibility_list.md) document.
