param(
  [Parameter(Mandatory = $true)]
  [string]$DllPath,
  [Parameter(Mandatory = $true)]
  [string]$Symbol
)

if (-not (Test-Path -LiteralPath $DllPath)) {
  Write-Error "DLL not found: $DllPath"
  exit 2
}

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

namespace Native {
  public static class Kernel32 {
    [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32", SetLastError = true)]
    public static extern bool FreeLibrary(IntPtr hModule);

    [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
  }
}
"@

$module = [Native.Kernel32]::LoadLibrary($DllPath)
if ($module -eq [IntPtr]::Zero) {
  $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
  Write-Error "LoadLibrary failed with error $err"
  exit 3
}

try {
  $proc = [Native.Kernel32]::GetProcAddress($module, $Symbol)
  if ($proc -eq [IntPtr]::Zero) {
    Write-Output "NOT_FOUND: $Symbol"
    exit 1
  }

  Write-Output "FOUND: $Symbol"
  exit 0
} finally {
  [Native.Kernel32]::FreeLibrary($module) | Out-Null
}
