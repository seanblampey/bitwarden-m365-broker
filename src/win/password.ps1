# Windows PowerShell 5.1 compatible. Prints the entered password to stdout (no trailing newline).
# Exit 0 = OK, 1 = Cancel.
$ErrorActionPreference = 'Stop'
try {
  [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
  Add-Type -AssemblyName System.Windows.Forms
  Add-Type -AssemblyName System.Drawing
  [System.Windows.Forms.Application]::EnableVisualStyles()

  $form = New-Object System.Windows.Forms.Form
  $form.Text = 'Unlock Bitwarden for Claude'
  $form.TopMost = $true
  $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
  $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
  $form.MaximizeBox = $false
  $form.MinimizeBox = $false
  $form.ClientSize = New-Object System.Drawing.Size(360, 120)

  $label = New-Object System.Windows.Forms.Label
  $label.Text = 'Bitwarden master password:'
  $label.Location = New-Object System.Drawing.Point(12, 14)
  $label.AutoSize = $true
  $form.Controls.Add($label)

  $box = New-Object System.Windows.Forms.TextBox
  $box.UseSystemPasswordChar = $true
  $box.Location = New-Object System.Drawing.Point(12, 38)
  $box.Size = New-Object System.Drawing.Size(336, 24)
  $form.Controls.Add($box)

  $ok = New-Object System.Windows.Forms.Button
  $ok.Text = 'OK'
  $ok.Location = New-Object System.Drawing.Point(192, 80)
  $ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
  $form.Controls.Add($ok)

  $cancel = New-Object System.Windows.Forms.Button
  $cancel.Text = 'Cancel'
  $cancel.Location = New-Object System.Drawing.Point(273, 80)
  $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
  $form.Controls.Add($cancel)

  $form.AcceptButton = $ok     # Enter = OK
  $form.CancelButton = $cancel # Esc = Cancel
  # Claude Code is usually in the foreground: re-assert TopMost and pull focus to the box once shown.
  $form.Add_Shown({ $form.TopMost = $true; $form.Activate(); $form.BringToFront(); $box.Focus() | Out-Null })

  $result = $form.ShowDialog()
  if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    [Console]::Out.Write($box.Text)
    [Console]::Out.Flush()
    exit 0
  }
  exit 1
} catch {
  exit 2
}
