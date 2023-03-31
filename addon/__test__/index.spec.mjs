import test from 'ava'

import { verifySignature } from '../index.js'

test('verify signature', (t) => {
  const pem = `-----BEGIN CERTIFICATE-----
MIICiDCCAjKgAwIBAgIJAL+acWZrTrlfMA0GCSqGSIb3DQEBBQUAMGMxCzAJBgNV
BAYTAjg2MREwDwYDVQQIEwhaaGVqaWFuZzERMA8GA1UEBxMISGFuZ3pob3UxDzAN
BgNVBAoTBkFsaXl1bjEMMAoGA1UECxMDTW5zMQ8wDQYDVQQDEwZub3RpZnkwHhcN
MTUwNzAyMDIwNjE2WhcNMTYwNzAxMDIwNjE2WjBjMQswCQYDVQQGEwI4NjERMA8G
A1UECBMIWmhlamlhbmcxETAPBgNVBAcTCEhhbmd6aG91MQ8wDQYDVQQKEwZBbGl5
dW4xDDAKBgNVBAsTA01uczEPMA0GA1UEAxMGbm90aWZ5MFwwDQYJKoZIhvcNAQEB
BQADSwAwSAJBALX0sFVowct1NAQjDyYSUf0rp1rOHLkz4kp0zNWcDyXMXa5PzsPU
UwJXaLwhvNCDLLWuiLK6Oh5elmOmL8Gy/5MCAwEAAaOByDCBxTAdBgNVHQ4EFgQU
kEah2o9HpCUCxhN/fY3kUtPkP4owgZUGA1UdIwSBjTCBioAUkEah2o9HpCUCxhN/
fY3kUtPkP4qhZ6RlMGMxCzAJBgNVBAYTAjg2MREwDwYDVQQIEwhaaGVqaWFuZzER
MA8GA1UEBxMISGFuZ3pob3UxDzANBgNVBAoTBkFsaXl1bjEMMAoGA1UECxMDTW5z
MQ8wDQYDVQQDEwZub3RpZnmCCQC/mnFma065XzAMBgNVHRMEBTADAQH/MA0GCSqG
SIb3DQEBBQUAA0EAluPg+k0Fc7WRcpP78+eLptYD8an7YOapUdNUmT2/SQC5BZ+t
cyWFit5pAEipngFL105d7AuW2AtwqG0FgV0ipw==
-----END CERTIFICATE-----`
  const data = `POST
4CCBAD7AF2D23C2D00DDECCA59323A8C
text/plain;charset=utf-8
Wed, 29 Mar 2023 08:41:27 GMT
x-mns-message-id:250EB49D5F8D737A391C93C6ED165396
x-mns-publish-time:1680079287576
x-mns-request-id:6423F9B7BF94313030AF5EA0
x-mns-signing-cert-url:aHR0cHM6Ly9tbnN0ZXN0Lm9zcy1jbi1oYW5nemhvdS5hbGl5dW5jcy5jb20veDUwOV9wdWJsaWNfY2VydGlmaWNhdGUucGVt
x-mns-subscriber:1321669497458181
x-mns-subscription-name:mns-en-subs-oss-fecdn-internal-pre-1-22849529855680
x-mns-topic-name:mns-en-topics-oss-fecdn-internal-pre-22849529792243
x-mns-topic-owner:1321669497458181
x-mns-version:2015-06-06
/notifications`
  const signature = 'LP3cxoTCbhsiLJi0KQdEiRaufaxMfWUdLH064yoVoKl8xNcY+299itGmGsirVMY8vDpuZ1VwS0Uw7R5dNduSXg=='
  console.time('sign')
  t.is(verifySignature(pem, data, signature), true)
  console.timeEnd('sign')
})
