# ohhai-go

## Features

-   **Detailed Request Info**: Responds with the incoming request's method, path, headers, and remote address.
-   **Execution Context**: Includes server's system hostname, UID, GID, and user namespace mappings (`/proc/self/uid_map`), which is invaluable for debugging in containers.
-   **External URL Fetching**: Can be configured to fetch an external URL and include the response details in its own response.
-   **TLS Cert Details**: When fetching an `https` URL, it provides a listing of the TLS certificate chain, including:
    -   Subject and Issuer Common Names.
    -   SANs (DNS Names and IP Addresses).
    -   Validity Period (Not Before/After).
    -   Signature Algorithm.
    -   **Crucially, it captures and reports TLS verification errors (e.g., expired cert, hostname mismatch) without failing the request**, allowing you to debug misconfigured services.
-   **Structured JSON Output**: All responses and logs are in easy-to-parse JSON format.
-   **Container Ready**: Includes a minimal, multi-stage `Dockerfile` for a small and secure image.
-   **Health Check Endpoint**: Provides a `/readyz` endpoint for readiness probes.

## Usage

### Endpoints

| Path      | Description                                                                                                                                                                                           |
| :-------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/`       | The main endpoint. Returns a JSON object with request, environment, and optional external fetch details. Accepts a `fetch_url` query parameter to trigger an external fetch for that specific request. |
| `/readyz` | A readiness probe endpoint for orchestrators like Kubernetes. Returns `200 OK` with a plain text body of "OK".                                                                                         |

### Configuration

Configuration is managed via environment variables.

| Variable    | Description                                                                                        | Default |
| :---------- | :------------------------------------------------------------------------------------------------- | :------ |
| `PORT`      | The port on which the server listens.                                                              | `8080`  |
| `FETCH_URL` | A default URL to fetch on every incoming request. If set, this is used unless a `fetch_url` query parameter is provided. | `""`    |

### Examples

**1. Basic Request**

Get information about your request and the server environment.

```sh
curl '<your-hostname>/'
```

**2. On-the-fly External Fetch**

Use the `fetch_url` query parameter to inspect an external resource.

```sh
# Fetch an API endpoint
curl '<your-hostname>/?fetch_url=https://checkip.amazonaws.com'

# The URL must be URL-encoded if it contains special characters
```

**3. Running with a Default Fetch URL**

You can configure the server to always hit a specific endpoint by setting the environment variable `FETCH_URL`

**4. Debugging TLS/SSL Certificates**

You can point it at any HTTPS endpoint to inspect its certificate chain.

```sh
# Inspect a valid certificate
curl '<your-hostname>/?fetch_url=https://google.com'

# Inspect an expired certificate from badssl.com
# Note the "verification_error" field in the response.
curl '<your-hostname>/?fetch_url=https://expired.badssl.com/'
```


## Example Response

Here is an example response from a request to `<your-hostname>/?fetch_url=https://expired.badssl.com/`. Note the populated `external_fetch_result` with the `tls_info` and its `verification_error`.

```json
{
  "method": "GET",
  "path": "/",
  "http_version": "HTTP/1.1",
  "host": "localhost:8080",
  "remote_addr": "172.17.0.1:59096",
  "timestamp": "2025-07-18T01:10:41Z",
  "headers": {
    "Accept-Encoding": "gzip, deflate, br",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Microsoft Windows 10.0.19045; en-AU) PowerShell/7.5.2"
  },
  "running_context": {
    "system_hostname": "4b4baa170e76",
    "uid": 10001,
    "gid": 10001,
    "uid_map_content": "0          0 4294967295",
    "gid_map_content": "0          0 4294967295"
  },
  "external_fetch_result": {
    "url": "https://expired.badssl.com/",
    "status_code": 200,
    "content_type": "text/html",
    "body": "\u003c!DOCTYPE html\u003e\n\u003chtml\u003e\n\u003chead\u003e\n  \u003cmeta charset=\"utf-8\"\u003e\n  \u003cmeta name=\"viewport\" content=\"width=device-width, initial-scale=1\"\u003e\n  \u003clink rel=\"shortcut icon\" href=\"/icons/favicon-red.ico\"/\u003e\n  \u003clink rel=\"apple-touch-icon\" href=\"/icons/icon-red.png\"/\u003e\n  \u003ctitle\u003eexpired.badssl.com\u003c/title\u003e\n  \u003clink rel=\"stylesheet\" href=\"/style.css\"\u003e\n  \u003cstyle\u003ebody { background: red; }\u003c/style\u003e\n\u003c/head\u003e\n\u003cbody\u003e\n\u003cdiv id=\"content\"\u003e\n  \u003ch1 style=\"font-size: 12vw;\"\u003e\n    expired.\u003cbr\u003ebadssl.com\n  \u003c/h1\u003e\n\u003c/div\u003e\n\n\u003c/body\u003e\n\u003c/html\u003e\n",
    "resolved_ip": "104.154.89.105",
    "source_port": 46336,
    "tls_info": {
      "verification_error": "x509: certificate has expired or is not yet valid: current time 2025-07-18T01:10:42Z is after 2015-04-12T23:59:59Z",
      "certificate_chain": [
        {
          "subject_common_name": "*.badssl.com",
          "issuer_common_name": "COMODO RSA Domain Validation Secure Server CA",
          "dns_names": [
            "*.badssl.com",
            "badssl.com"
          ],
          "ip_addresses": null,
          "not_before": "2015-04-09T00:00:00Z",
          "not_after": "2015-04-12T23:59:59Z",
          "signature_algorithm": "SHA256-RSA"
        },
        {
          "subject_common_name": "COMODO RSA Domain Validation Secure Server CA",
          "issuer_common_name": "COMODO RSA Certification Authority",
          "dns_names": null,
          "ip_addresses": null,
          "not_before": "2014-02-12T00:00:00Z",
          "not_after": "2029-02-11T23:59:59Z",
          "signature_algorithm": "SHA384-RSA"
        },
        {
          "subject_common_name": "COMODO RSA Certification Authority",
          "issuer_common_name": "AddTrust External CA Root",
          "dns_names": null,
          "ip_addresses": null,
          "not_before": "2000-05-30T10:48:38Z",
          "not_after": "2020-05-30T10:48:38Z",
          "signature_algorithm": "SHA384-RSA"
        }
      ]
    }
  }
}
```
