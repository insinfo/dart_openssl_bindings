/// OpenSSL Wrapper Library for Dart
library openssl;

/// Core API
export 'src/api/openssl.dart';
export 'src/api/openssl_context.dart';
export 'src/api/mixins/signature_mixin.dart';
export 'src/api/mixins/provider_mixin.dart';
export 'src/api/mixins/verification_mixin.dart';
export 'src/openssl_loader.dart';

/// Cryptography
export 'src/crypto/evp_pkey.dart';

/// X.509 & PKI
export 'src/x509/x509_certificate.dart';
export 'src/x509/icp_brasil_info.dart';
export 'src/x509/icp_brasil_parser.dart';
export 'src/x509/x509_extensions.dart';
export 'src/x509/x509_crl.dart';
export 'src/x509/x509_crl_builder.dart';
export 'src/x509/x509_builder.dart';
export 'src/x509/x509_request.dart';
export 'src/x509/x509_request_builder.dart';
export 'src/x509/x509_name.dart';
export 'src/pki/pki_utils.dart';
export 'src/pki/pki_builder.dart';

/// CMS / PKCS#7
export 'src/cms/cms_content.dart';
export 'src/cms/cms_pkcs7_signer.dart';

/// OCSP
export 'src/ocsp/ocsp_response_builder.dart';
export 'src/ocsp/ocsp_client.dart';

/// KDF (Argon2: nativo via EVP_KDF, com fallback em Dart puro)
export 'src/kdf/argon2.dart';

/// PKCS bundles
export 'src/pkcs/pkcs12_bundle.dart';

/// PKCS#12 em Dart puro (sem FFI, dispensa o provider `legacy`).
/// As primitivas (der.dart, digests.dart, block_ciphers.dart) ficam fora do
/// barril para não despejar nomes genéricos como `hmac` e `pbkdf2` no
/// namespace de quem importa o pacote; importe-as pelo caminho direto.
export 'src/pkcs/pure/pkcs12_pure.dart';

/// TLS (TCP)
export 'src/ssl/secure_socket_openssl_async.dart';
export 'src/ssl/secure_socket_openssl_sync.dart';

/// HTTP/HTTPS client
export 'src/http/openssl_http_client.dart';

/// HTTP/HTTPS server
export 'src/http/openssl_http_server.dart';

/// DTLS (UDP)
export 'src/dtls/dtls_client.dart';
export 'src/dtls/dtls_server.dart';
export 'src/dtls/dtls_connection.dart';

/// Infrastructure / Exceptions
export 'src/infra/ssl_exception.dart';
export 'src/dtls/psk_credentials.dart';

/// Infrastructure
export 'src/infra/openssl_lib.dart';
export 'src/infra/ssl_object.dart';
export 'src/infra/bio_helper.dart';
export 'src/generated/ffi.dart';
