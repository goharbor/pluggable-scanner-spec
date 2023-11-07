# Data Spec for SBOM

## MIME Type

`application/vnd.security.sbom.report+json; version=1.0`

## Report Data Model

### Artifact

| Field | Type | Description |
| ------ | ----- | ----- |
| `repository` | string | The name of the Docker Registry repository containing the artifact. |
| `digest` | string | The artifact's digest, consisting of an algorithm and hex portion. |
| `tag` | string | The artifact's tag. |
| `mime_type` | string | The MIME type of the artifact. |

### Scanner

| Field | Type | Description |
| ------ | ----- | ----- |
| `name` | string | The name of the scanner. |
| `vendor` | string | The name of the scanner's provider. |
| `version` | string | The version of the scanner. |

### Report

| Field | Type | Description |
| ------ | ----- | ----- |
| `generated_at` | string | The time of the report generated. |
| `artifact` | [artifact](#artifact) | The information of the scanned artifact. |
| `scanner`  | [scanner](#scanner) | The information of the scanner. |
| `vendor_attributes` | map[string]interface{} | The additional attributes of the vendor. |
| `media_type` | string | The media type of the sbom data, currently only `application/spdx+json` and `application/vnd.cyclonedx+json` are supported.|
| `sbom` | map[string]interface{} | The raw data of the sbom format by media_type. |

### Example

```json
{
  "generated_at": "2021-03-09T11:40:28.154072066Z",
  "artifact": {
     "repository": "library/docker",
      "digest": "sha256:7215e8e09ea282e517aa350fc5380c1773c117b1867316fb59076d901e252d15",
      "mime_type": "application/vnd.docker.distribution.manifest.v2+json"
  },
  "scanner": {
      "name": "Trivy",
      "vendor": "Aqua Security",
      "version": "v0.16.0"
  },
  "vendor_attributes": {
    "spec-version": "1.5",
    "create-by": "trivy",
    "create-time": "1695368355"
  },
  "media_type": "application/spdx+json",
  "sbom": {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "alpine:latest",
    "documentNamespace": "<http://aquasecurity.github.io/trivy/container_image/alpine:latest-24fab3cb-05fa-479b-b3b7-f76151354cc3>",
    "creationInfo":{
      "licenseListVersion": "",
      "creators": [
        "Organization: aquasecurity",
        "Tool: trivy-0.44.1"
      ],
      "created": "2023-09-22T07:41:04Z"
    },
    "packages": [
        {
          "name": "alpine",
          "SPDXID": "SPDXRef-OperatingSystem-68bf9b9d283c287a",
          "versionInfo": "3.18.3",
          "downloadLocation": "NONE",
          "copyrightText": "",
          "primaryPackagePurpose": "OPERATING-SYSTEM"
        },
        ...
    ]
    ...
    }
  }
}

```

### OpenAPI Definition

```yaml
components:
  schemas:
    ...
    HarborSbomReport:
      type: object
      properties:
        generated_at:
          type: string
          format: 'date-time'
        artifact:
          $ref: '#/components/schemas/Artifact'
        scanner:
          $ref: '#/components/schemas/Scanner'
        vendor_attributes:
          type: object
          additionalProperties: true
        media_type:
          type: string
          enum:
            - application/spdx+json
            - application/vnd.cyclonedx+json
        sbom:
          type: object
          additionalProperties: true
```

## Statement

### Generate SBOM

The capability to generate the SBOM from the container image, the process is similar with the scan vulnerabilities, the scanner should pull the image from harbor and then generate SBOM, harbor will polling the scanner to get the SBOM until timeout or error occurred. The capabilities return from `/metadata` should includes the sbom capability.

```json
  "capabilities": [
    {
      "type": "vulnerability",
      "consumes_mime_types": [
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json"
      ],
      "produces_mime_types": [
        "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"
      ]
    },
    {
      "type": "sbom",
      "consumes_mime_types": [
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json"
      ],
      "produces_mime_types": [
        "application/vnd.security.sbom.report+json; version=1.0"
      ]
    }
  ],
```

### Scan SBOM

The capability to scan the image vulnerabilities from the SBOM of image, which have the better performance as the scanner only needs to pull the SBOM artifact instead of whole image. The basic process is exactly same with the image vulnerabilities scan because the SBOM has been bundled as an [OCI artifact](#harbor-sbom-artifact-layout). If the `artifactType` is `application/vnd.goharbor.harbor.sbom.v1` of the manifest, then scanner should treat is as SBOM artifact and pull the raw SBOM content from layers and scan vulnerabilities from it, the `artifact` field in the report should be the **subject** artifact.

### Harbor SBOM Artifact Layout

The support of [OCI Distribution spec v1.1's](https://github.com/goharbor/community/blob/main/proposals/new/distribution-1.1-adoption.md) referrer API in harbor enables the packaging of SBOM into OCI artifacts and their association with the respective subject artifact based on its attributes. Subsequently, by following the OCI distribution v2 image push process and API, you can push the SBOM artifact to Harbor, where it will be automatically processed as an accessory to the subject artifact. The layout is designed by following the [artifact guidelines](https://github.com/opencontainers/image-spec/blob/v1.1.0-rc5/manifest.md#guidelines-for-artifact-usage).

Here are some constraints:

1. The `artifactType` MUST set to **application/vnd.goharbor.harbor.sbom.v1** because harbor leverages this to identify it as the SBOM, and set `config` to the [empty descriptor value](https://github.com/opencontainers/image-spec/blob/v1.1.0-rc5/manifest.md#guidance-for-an-empty-descriptor).
2. The SBOM file should be packed as the artifact layer, should not be compressed, the `mediaType` should set the format of the SBOM file, currently only **application/spdx+json** and **application/vnd.cyclonedx+json** are supported. (These mediaType are registered on the [IANA](https://www.iana.org/assignments/media-types/media-types.xhtml))
3. The vendor can add the customize attributes to the `annotations`.
4. The `subject` should set the info of the subject artifact.
5. The `layers` should only contains one layer which storing the SBOM file, you should separate to multiple SBOM artifact if you have multiple SBOM files with different formats.

Example

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.goharbor.harbor.sbom.v1",
  "config": {
    "mediaType": "application/vnd.oci.empty.v1+json",
    "size": 2,
    "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    "data": "e30="
  },
  "layers": [
    {
      "mediaType": "application/spdx+json",
      "size": 180911,
      "digest": "sha256:5969ee831c94c0d918ceb6efc2463c032100afd03d721e920dafefd34913f2f4"
    }
  ],
  "annotations": {
    "created-by": "trivy",
    "org.opencontainers.artifact.created": "2023-09-01T15:17:14+08:00",
    "org.opencontainers.artifact.description": "SPDX JSON SBOM"
  },
  "subject": {
    "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
    "size": 3040,
    "digest": "sha256:0f27d0c6b893b0298fca3c6c7253db047b7c21a9f6815da53ab4208000b839d8"
  }
}
```

## Open Questions
