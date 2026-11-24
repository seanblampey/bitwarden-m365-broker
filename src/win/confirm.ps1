# Windows PowerShell 5.1 compatible. Reads a JSON ApprovalRequest from stdin.
# Exit 0 = Yes, 1 = No (default button).
$ErrorActionPreference = 'Stop'
try {
  [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
  [Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
  Add-Type -AssemblyName System.Windows.Forms

  $req = [Console]::In.ReadToEnd() | ConvertFrom-Json
  $action = [string]$req.action
  if ($action.Length -gt 1500) { $action = $action.Substring(0, 1500) + '...' }

  $text = "Tenant: $($req.tenant)`r`nAccount: $($req.account)`r`n`r`nAction:`r`n$action`r`n`r`nAllow this change?"

  $result = [System.Windows.Forms.MessageBox]::Show(
    $text,
    'Claude wants to make a change',
    [System.Windows.Forms.MessageBoxButtons]::YesNo,
    [System.Windows.Forms.MessageBoxIcon]::Warning,
    [System.Windows.Forms.MessageBoxDefaultButton]::Button2,
    [System.Windows.Forms.MessageBoxOptions]::ServiceNotification
  )
  if ($result -eq [System.Windows.Forms.DialogResult]::Yes) { exit 0 }
  exit 1
} catch {
  exit 2
}
