/// Demonstração do Bug: Heap Corruption com struct tm no Linux
///
/// Este script demonstra o bug de corrupção de heap que ocorria no Linux
/// devido à diferença de tamanho da struct tm entre plataformas.
///
/// COMO FUNCIONA O BUG:
/// - No Windows, struct tm tem 9 campos int = 36 bytes
/// - No Linux x64, struct tm tem 9 campos + tm_gmtoff (long 8 bytes) + tm_zone (pointer 8 bytes) = ~56 bytes
/// - O Dart FFI declara apenas os 9 campos (36 bytes)
/// - Quando OpenSSL escreve nos campos extras, corrompe memória adjacente
///
/// COMO RODAR:
///   dart run script/demonstrate_tm_bug.dart
///
/// NO LINUX: Este script pode causar crash ou corrupção de heap!
/// NO WINDOWS: Funciona normalmente (struct tm é menor)

import 'dart:ffi';
import 'dart:io';
import 'package:ffi/ffi.dart';
import 'package:openssl_bindings/openssl.dart';


void main() {
  print('=== Demonstração do Bug: struct tm no Linux ===\n');

  // 1. Mostrar tamanhos
  print('1. TAMANHOS DAS ESTRUTURAS:');
  print('   sizeOf<tm>() no Dart FFI: ${sizeOf<tm>()} bytes');
  print('   Campos declarados: tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year, tm_wday, tm_yday, tm_isdst');
  print('   = 9 campos × 4 bytes = 36 bytes');
  print('');

  if (Platform.isLinux) {
    print('   [!] ATENCAO: No Linux x64, a struct tm real do sistema tem:');
    print('      - 9 campos int (36 bytes)');
    print('      - tm_gmtoff: long (8 bytes)');
    print('      - tm_zone: const char* (8 bytes)');
    print('      - Padding possivel');
    print('      = ~56 bytes TOTAL');
    print('');
    print('   O Dart aloca apenas 36 bytes, mas OpenSSL escreve 56 bytes!');
  } else {
    print('   [OK] No Windows, struct tm tem apenas os 9 campos padrao.');
  }
  print('');

  // 2. Demonstrar o bug
  print('2. DEMONSTRAÇÃO DO BUG:');
  print('');

  final openssl = OpenSSL();

  // Criar um certificado para ter uma data ASN1_TIME
  print('   Criando certificado de teste...');
  final key = openssl.generateRsa(2048);
  final builder = X509CertificateBuilder(openssl);
  builder.setSubject(commonName: 'Test Bug Demo');
  builder.setIssuerAsSubject();
  builder.setValidity(notBeforeOffset: 0, notAfterOffset: 86400 * 365); // 1 ano
  builder.setPublicKey(key);
  final cert = builder.sign(key);
  print('   Certificado criado.');
  print('');

  // 3. Demonstrar alocação com bug vs corrigida
  print('3. COMPARAÇÃO DE ALOCAÇÕES:');
  print('');

  print('   VERSÃO COM BUG (como era antes):');
  print('   ```dart');
  print('   final tmPtr = calloc<tm>();  // Aloca apenas ${sizeOf<tm>()} bytes!');
  print('   bindings.ASN1_TIME_to_tm(timePtr, tmPtr);  // OpenSSL escreve ~56 bytes');
  print('   calloc.free(tmPtr);  // CRASH: metadata do heap foi corrompida');
  print('   ```');
  print('');

  print('   VERSÃO CORRIGIDA:');
  print('   ```dart');
  print('   final tmRawPtr = calloc<Uint8>(64);  // Aloca 64 bytes (suficiente para Linux)');
  print('   final tmPtr = tmRawPtr.cast<tm>();');
  print('   bindings.ASN1_TIME_to_tm(timePtr, tmPtr);  // OpenSSL escreve ~56 bytes - OK!');
  print('   calloc.free(tmRawPtr);  // Funciona corretamente');
  print('   ```');
  print('');

  // 4. Testar acesso às datas (usa código corrigido agora)
  print('4. TESTANDO ACESSO ÀS DATAS (código corrigido):');
  print('   cert.notBefore: ${cert.notBefore}');
  print('   cert.notAfter: ${cert.notAfter}');
  print('');

  // 5. Se quiser realmente demonstrar o crash no Linux, descomente abaixo
  if (Platform.isLinux) {
    print('5. QUER VER O CRASH? (descomente o código abaixo no script)');
    print('');
    print('   Para reproduzir o bug original, você pode:');
    print('   a) Reverter a correção em x509_certificate.dart');
    print('   b) Ou descomentar o código abaixo que simula o problema');
    print('');
    
    // DESCOMENTE PARA VER O CRASH NO LINUX:
    _demonstrateCrash(openssl, cert);
  }

  print('=== Fim da Demonstração ===');
}

/// Demonstra o crash alocando memória insuficiente para struct tm.
/// ATENCAO: Este código CAUSA CRASH no Linux!
// ignore: unused_element
void _demonstrateCrash(OpenSSL openssl, X509Certificate cert) {
  print('   [!] EXECUTANDO CODIGO COM BUG - PODE CAUSAR CRASH!');
  print('');

  // Obter ponteiro para ASN1_TIME do certificado
  final timePtr = openssl.bindings.X509_getm_notBefore(cert.handle);
  if (timePtr == nullptr) {
    print('   Erro: nao foi possivel obter notBefore');
    return;
  }

  // Alocar INCORRETAMENTE - apenas 36 bytes
  print('   Alocando calloc<tm>() = ${sizeOf<tm>()} bytes...');
  final tmPtrBuggy = calloc<tm>();

  print('   Chamando ASN1_TIME_to_tm (OpenSSL vai escrever ~56 bytes)...');
  final result = openssl.bindings.ASN1_TIME_to_tm(timePtr, tmPtrBuggy);
  print('   Resultado: $result');

  // Ler os valores (pode já ter corrompido memória)
  print('   tm_year: ${tmPtrBuggy.ref.tm_year}');
  print('   tm_mon: ${tmPtrBuggy.ref.tm_mon}');
  print('   tm_mday: ${tmPtrBuggy.ref.tm_mday}');

  // O crash geralmente acontece aqui, ao liberar memória corrompida
  print('   Liberando memoria com calloc.free()...');
  print('   (Se crashar aqui, o bug foi reproduzido!)');
  calloc.free(tmPtrBuggy);

  print('   [OK] Nao crashou (sorte ou plataforma diferente)');
}
