const int kBioCtrlPending = 10; // BIO_CTRL_PENDING
const int kDefaultCiphertextChunk = 16 * 1024;
const int kSslErrorWantRead = 2;
const int kSslErrorWantWrite = 3;
const int kSslErrorZeroReturn = 6;

/// Recommended TLS 1.2 cipher suites (ECDHE + AEAD).
const List<String> kTls12RecommendedCipherSuites = [
	'ECDHE-ECDSA-AES128-GCM-SHA256',
	'ECDHE-RSA-AES128-GCM-SHA256',
	'ECDHE-ECDSA-AES256-GCM-SHA384',
	'ECDHE-RSA-AES256-GCM-SHA384',
	'ECDHE-ECDSA-CHACHA20-POLY1305',
	'ECDHE-RSA-CHACHA20-POLY1305',
];

/// TLS 1.2 cipher list string for SSL_CTX_set_cipher_list.
const String kTls12RecommendedCipherList =
		'ECDHE-ECDSA-AES128-GCM-SHA256:'
		'ECDHE-RSA-AES128-GCM-SHA256:'
		'ECDHE-ECDSA-AES256-GCM-SHA384:'
		'ECDHE-RSA-AES256-GCM-SHA384:'
		'ECDHE-ECDSA-CHACHA20-POLY1305:'
		'ECDHE-RSA-CHACHA20-POLY1305';

/// TLS 1.3 cipher suites.
const List<String> kTls13CipherSuites = [
	'TLS_AES_128_GCM_SHA256',
	'TLS_AES_256_GCM_SHA384',
	'TLS_CHACHA20_POLY1305_SHA256',
	'TLS_AES_128_CCM_SHA256',
	'TLS_AES_128_CCM_8_SHA256',
];

/// TLS 1.3 cipher suites list string for SSL_CTX_set_ciphersuites.
const String kTls13CipherSuitesList =
		'TLS_AES_128_GCM_SHA256:'
		'TLS_AES_256_GCM_SHA384:'
		'TLS_CHACHA20_POLY1305_SHA256:'
		'TLS_AES_128_CCM_SHA256:'
		'TLS_AES_128_CCM_8_SHA256';

/// TLS 1.3 cipher suite IDs (hex) for reference.
const Map<String, String> kTls13CipherSuiteIds = {
	'TLS_AES_128_GCM_SHA256': '0x1301',
	'TLS_AES_256_GCM_SHA384': '0x1302',
	'TLS_CHACHA20_POLY1305_SHA256': '0x1303',
	'TLS_AES_128_CCM_SHA256': '0x1304',
	'TLS_AES_128_CCM_8_SHA256': '0x1305',
};
