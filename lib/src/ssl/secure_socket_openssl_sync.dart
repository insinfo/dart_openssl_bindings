// ignore_for_file: lines_longer_than_80_chars

import 'dart:async';
import 'dart:ffi' as ffi;
import 'dart:io' as io;
import 'dart:typed_data';
import 'package:ffi/ffi.dart';

import '../native/native_buffer_utils.dart';
import '../generated/ffi.dart';
import '../openssl_loader.dart';
import '../infra/ssl_exception.dart';

import 'ciphertext_callback.dart';
import 'ssl_constants.dart';

/// A synchronous TLS socket that reuses the OpenSSL BIO engine.
class SecureSocketOpenSSLSync {
  SecureSocketOpenSSLSync._({
    io.RawSynchronousSocket? socket,
    CiphertextWriterSync? writer,
    CiphertextReaderSync? reader,
    required bool isServer,
    String? certFile,
    String? keyFile,
    bool eagerHandshake = false,
    String? cryptoPath,
    String? sslPath,
  })  : _socket = socket,
        _ciphertextWriter = writer,
        _ciphertextReader = reader,
        _useCallbacks = writer != null && reader != null,
        _isServer = isServer {
    _initOpenSsl(cryptoPath: cryptoPath, sslPath: sslPath);
    _initializeSSL(certFile: certFile, keyFile: keyFile);
    _attachSslObject();
    if (eagerHandshake || isServer) {
      _handshakeFuture = ensureHandshakeCompleted();
    }
  }

  static SecureSocketOpenSSLSync connect(
    String host,
    int port, {
    bool eagerHandshake = true,
    String? cryptoPath,
    String? sslPath,
  }) {
    final socket = io.RawSynchronousSocket.connectSync(host, port);
    return SecureSocketOpenSSLSync._(
      socket: socket,
      isServer: false,
      eagerHandshake: eagerHandshake,
      cryptoPath: cryptoPath,
      sslPath: sslPath,
    );
  }

  factory SecureSocketOpenSSLSync.clientFromSocket(
    io.RawSynchronousSocket socket, {
    bool eagerHandshake = true,
    String? cryptoPath,
    String? sslPath,
  }) =>
      SecureSocketOpenSSLSync._(
          socket: socket,
          isServer: false,
          eagerHandshake: eagerHandshake,
          cryptoPath: cryptoPath,
          sslPath: sslPath);

  factory SecureSocketOpenSSLSync.clientWithCallbacks({
    required CiphertextWriterSync writer,
    required CiphertextReaderSync reader,
    bool eagerHandshake = true,
    String? cryptoPath,
    String? sslPath,
  }) =>
      SecureSocketOpenSSLSync._(
        socket: null,
        writer: writer,
        reader: reader,
        isServer: false,
        eagerHandshake: eagerHandshake,
        cryptoPath: cryptoPath,
        sslPath: sslPath,
      );

  factory SecureSocketOpenSSLSync.serverFromSocket(
    io.RawSynchronousSocket socket, {
    required String certFile,
    required String keyFile,
    bool eagerHandshake = true,
    String? cryptoPath,
    String? sslPath,
  }) =>
      SecureSocketOpenSSLSync._(
        socket: socket,
        isServer: true,
        certFile: certFile,
        keyFile: keyFile,
        eagerHandshake: eagerHandshake,
        cryptoPath: cryptoPath,
        sslPath: sslPath,
      );

  final io.RawSynchronousSocket? _socket;
  final CiphertextWriterSync? _ciphertextWriter;
  final CiphertextReaderSync? _ciphertextReader;
  final bool _useCallbacks;
  final bool _isServer;
  late final OpenSsl _openSsl;
  late final OpenSsl _openSslCrypto;
  ffi.Pointer<ssl_ctx_st>? _ctx;
  ffi.Pointer<ssl_st>? _ssl;
  ffi.Pointer<BIO>? _networkReadBio;
  ffi.Pointer<BIO>? _networkWriteBio;
  bool _sslInitialized = false;
  Future<void>? _handshakeFuture;
  bool _socketClosed = false;

  io.RawSynchronousSocket? get socket => _socket;

  bool get isHandshakeComplete => _sslInitialized;

  Future<void> ensureHandshakeCompleted() {
    _handshakeFuture ??= _performHandshake();
    return _handshakeFuture!;
  }

  Future<void> _performHandshake() async {
    while (true) {
      final result = _openSsl.SSL_do_handshake(_sslPtr);
      await _drainWriteBio();
      if (result == 1) {
        _sslInitialized = true;
        return;
      }
      final error = _openSsl.SSL_get_error(_sslPtr, result);
      if (error == kSslErrorWantRead) {
        final filled = await _fillReadBio();
        if (!filled) {
          throw OpenSslHandshakeException(
            'TLS handshake aborted: socket closed before completion.',
          );
        }
        continue;
      }
      if (error == kSslErrorWantWrite) {
        continue;
      }
      throw OpenSslHandshakeException(
        'TLS handshake failed (OpenSSL code $error, mode ${_isServer ? 'server' : 'client'}).',
      );
    }
  }

  Future<int> send(Uint8List data) async {
    if (data.isEmpty) {
      return 0;
    }
    await ensureHandshakeCompleted();
    final buffer = NativeUint8Buffer.fromBytes(data);
    var written = 0;
    try {
      while (written < data.length) {
        final remaining = data.length - written;
        final ptr = buffer.slice(written).cast<ffi.Void>();
        final result = _openSsl.SSL_write(_sslPtr, ptr, remaining);
        await _drainWriteBio();
        if (result > 0) {
          written += result;
          continue;
        }
        final error = _openSsl.SSL_get_error(_sslPtr, result);
        if (error == kSslErrorWantRead) {
          final filled = await _fillReadBio();
          if (!filled) {
            throw OpenSslTlsException(
              'Socket closed while SSL_write was waiting for data.',
            );
          }
          continue;
        }
        if (error == kSslErrorWantWrite) {
          continue;
        }
        throw OpenSslTlsException('SSL write failed (OpenSSL code $error).');
      }
    } finally {
      buffer.release();
    }
    return data.length;
  }

  Future<Uint8List> recv(int bufferSize) async {
    if (bufferSize <= 0) {
      throw ArgumentError.value(bufferSize, 'bufferSize', 'must be positive');
    }
    await ensureHandshakeCompleted();
    final buffer = NativeUint8Buffer.allocate(bufferSize);
    try {
      while (true) {
        final received =
            _openSsl.SSL_read(_sslPtr, buffer.pointer.cast(), bufferSize);
        if (received > 0) {
          return buffer.copyToDart(received);
        }
        final error = _openSsl.SSL_get_error(_sslPtr, received);
        if (error == kSslErrorWantRead) {
          final filled = await _fillReadBio(
            preferredSize: bufferSize,
          );
          if (!filled) {
            return Uint8List(0);
          }
          continue;
        }
        if (error == kSslErrorWantWrite) {
          await _drainWriteBio();
          continue;
        }
        if (error == kSslErrorZeroReturn) {
          return Uint8List(0);
        }
        throw OpenSslTlsException('SSL read failed (OpenSSL code $error).');
      }
    } finally {
      buffer.release();
    }
  }

  Future<void> shutdown() async {
    if (_ssl == null || _ssl == ffi.nullptr || !_sslInitialized) {
      return;
    }
    final result = _openSsl.SSL_shutdown(_sslPtr);
    if (result == 0) {
      await _drainWriteBio();
      await _fillReadBio();
      _openSsl.SSL_shutdown(_sslPtr);
    }
    await _drainWriteBio();
    _sslInitialized = false;
  }

  Future<void> close() async {
    await shutdown();
    if (!_socketClosed) {
      final socket = _socket;
      if (socket != null) {
        socket.closeSync();
      }
      _socketClosed = true;
    }
    final ssl = _ssl;
    if (ssl != null && ssl != ffi.nullptr) {
      _openSsl.SSL_free(ssl);
      _ssl = null;
      _networkReadBio = null;
      _networkWriteBio = null;
    }
    final ctx = _ctx;
    if (ctx != null && ctx != ffi.nullptr) {
      _openSsl.SSL_CTX_free(ctx);
      _ctx = null;
    }
  }

  Future<bool> _fillReadBio({int? preferredSize}) async {
    final bio = _networkReadBio;
    if (bio == null || bio == ffi.nullptr) {
      throw OpenSslTlsException('TLS read BIO is unavailable.');
    }
    Uint8List? bytes;
    if (_useCallbacks) {
      final size = (preferredSize == null || preferredSize <= 0)
          ? kDefaultCiphertextChunk
          : preferredSize;
      bytes = await _ciphertextReader!(size);
    } else {
      final socket = _requireSocket();
      final chunkSize = (preferredSize == null || preferredSize <= 0)
          ? kDefaultCiphertextChunk
          : preferredSize;
      List<int>? ciphertext;
      try {
        ciphertext = socket.readSync(chunkSize);
      } on io.SocketException catch (_) {
        _socketClosed = true;
        rethrow;
      }
      if (ciphertext != null && ciphertext.isNotEmpty) {
        bytes = ciphertext is Uint8List
            ? ciphertext
            : Uint8List.fromList(ciphertext);
      }
    }
    if (bytes == null || bytes.isEmpty) {
      _socketClosed = true;
      return false;
    }
    final buffer = NativeUint8Buffer.fromBytes(bytes);
    try {
      final written = _openSslCrypto.BIO_write(
        bio,
        buffer.pointer.cast(),
        bytes.length,
      );
      if (written <= 0) {
        throw OpenSslTlsException('Failed to feed the TLS read BIO.');
      }
    } finally {
      buffer.release();
    }
    return true;
  }

  Future<void> _drainWriteBio() async {
    final bio = _networkWriteBio;
    if (bio == null || bio == ffi.nullptr) {
      return;
    }
    while (true) {
      final pending = _openSslCrypto.BIO_ctrl(
        bio,
        kBioCtrlPending,
        0,
        ffi.nullptr.cast<ffi.Void>(),
      );
      if (pending <= 0) {
        break;
      }
      final chunkSize =
          pending < kDefaultCiphertextChunk ? pending : kDefaultCiphertextChunk;
      final buffer = NativeUint8Buffer.allocate(chunkSize);
      try {
        final read =
            _openSslCrypto.BIO_read(bio, buffer.pointer.cast(), chunkSize);
        if (read <= 0) {
          break;
        }
        final ciphertext = buffer.copyToDart(read);
        if (_useCallbacks) {
          _ciphertextWriter!(ciphertext);
        } else {
          final socket = _requireSocket();
          socket.writeFromSync(ciphertext);
        }
      } finally {
        buffer.release();
      }
    }
  }

  io.RawSynchronousSocket _requireSocket() {
    final socket = _socket;
    if (socket == null) {
      throw OpenSslTlsException(
          'No underlying socket available in callback mode');
    }
    return socket;
  }

  void _initOpenSsl({String? cryptoPath, String? sslPath}) {
    final bindings =
        OpenSslBindings.load(cryptoPath: cryptoPath, sslPath: sslPath);
    _openSsl = bindings.ssl;
    _openSslCrypto = bindings.crypto;
  }

  void _initializeSSL({String? certFile, String? keyFile}) {
    ffi.Pointer<SSL_METHOD> method =
        _isServer ? _openSsl.TLS_server_method() : _openSsl.TLS_client_method();
    _ctx = _openSsl.SSL_CTX_new(method);
    if (_ctx == ffi.nullptr || _ctx == null) {
      throw OpenSslTlsException('Failed to create the SSL context.');
    }
    if (_isServer) {
      if (certFile == null || keyFile == null) {
        throw OpenSslTlsException(
          'Certificate and private key are required in server mode.',
        );
      }
      final certFilePtr = certFile.toNativeUtf8(allocator: calloc);
      final keyFilePtr = keyFile.toNativeUtf8(allocator: calloc);
      final ctxPtr = _ctxPtr;
      final certResult = _openSsl.SSL_CTX_use_certificate_file(
        ctxPtr,
        certFilePtr.cast(),
        1,
      );
      final keyResult = _openSsl.SSL_CTX_use_PrivateKey_file(
        ctxPtr,
        keyFilePtr.cast(),
        1,
      );
      calloc.free(certFilePtr);
      calloc.free(keyFilePtr);
      if (certResult != 1) {
        throw OpenSslTlsException('Failed to load the certificate file.');
      }
      if (keyResult != 1) {
        throw OpenSslTlsException('Failed to load the private key file.');
      }
    }
  }

  void _attachSslObject() {
    final ctxPtr = _ctxPtr;
    _ssl = _openSsl.SSL_new(ctxPtr);
    if (_ssl == ffi.nullptr || _ssl == null) {
      throw OpenSslTlsException('Failed to create the SSL instance.');
    }
    _networkReadBio = _openSslCrypto.BIO_new(_openSslCrypto.BIO_s_mem());
    _networkWriteBio = _openSslCrypto.BIO_new(_openSslCrypto.BIO_s_mem());
    if (_networkReadBio == ffi.nullptr || _networkWriteBio == ffi.nullptr) {
      throw OpenSslTlsException('Failed to create the TLS transport BIOs.');
    }
    _openSsl.SSL_set_bio(_sslPtr, _networkReadBioPtr, _networkWriteBioPtr);
    if (_isServer) {
      _openSsl.SSL_set_accept_state(_sslPtr);
    } else {
      _openSsl.SSL_set_connect_state(_sslPtr);
    }
  }

  ffi.Pointer<ssl_ctx_st> get _ctxPtr {
    final ctx = _ctx;
    if (ctx == null || ctx == ffi.nullptr) {
      throw OpenSslTlsException('SSL context is unavailable.');
    }
    return ctx;
  }

  ffi.Pointer<ssl_st> get _sslPtr {
    final ssl = _ssl;
    if (ssl == null || ssl == ffi.nullptr) {
      throw OpenSslTlsException('SSL object is unavailable.');
    }
    return ssl;
  }

  ffi.Pointer<BIO> get _networkReadBioPtr {
    final bio = _networkReadBio;
    if (bio == null || bio == ffi.nullptr) {
      throw OpenSslTlsException('TLS read BIO is unavailable.');
    }
    return bio;
  }

  ffi.Pointer<BIO> get _networkWriteBioPtr {
    final bio = _networkWriteBio;
    if (bio == null || bio == ffi.nullptr) {
      throw OpenSslTlsException('TLS write BIO is unavailable.');
    }
    return bio;
  }
}
