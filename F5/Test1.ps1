
Add-PSSnapIn iControlSnapIn
$username = "pguo"
$secpasswd = ConvertTo-SecureString "start123*" -AsPlainText -Force
$mycreds = New-Object System.Management.Automation.PSCredential ($username, $secpasswd)s
Initialize-F5.iControl -HostName 10.107.9.3 -PSCredentials $mycreds
