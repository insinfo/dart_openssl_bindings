/// Resultado da validação CMS.
class CmsValidationResult {
  final bool isValid;
  final int errorCode;
  final String? errorMessage;
  final String? errorDetail;

  CmsValidationResult({
    required this.isValid,
    this.errorCode = 0,
    this.errorMessage,
    this.errorDetail,
  });

  @override
  String toString() {
    return 'CmsValidationResult(isValid: $isValid, errorCode: $errorCode, message: $errorMessage)';
  }
}
