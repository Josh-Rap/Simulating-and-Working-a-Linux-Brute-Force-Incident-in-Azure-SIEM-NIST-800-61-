Import-Module Posh-SSH

$vmIp = "20.119.81.56"  # Azure VM's public IP
$wrongPassword = "__BAD_PASSWORD__"  # Fake password for failures
$correctPassword = "PASSWORD"  # Real SSH password
$realusername = "USERNAME"  # Real username
$users = @("admin", "test", "root", "fakeuser") # Fake usernames for failures
$attempts = 30  # Number of failed attempts before success

Write-Host "Starting brute-force simulation against $vmIp..."

# Simulate failed login attempts
for ($i = 1; $i -le $attempts; $i++) {
    Write-Host "Attempt ${i}: Trying incorrect login..."
    try {
        Start-Sleep -Seconds 2  
        $username = $users[(Get-Random -Maximum $users.Length)]
        $secpasswd = ConvertTo-SecureString $wrongPassword -AsPlainText -Force
        $Credentials = New-Object System.Management.Automation.PSCredential($username, $secpasswd)
        New-SSHSession -ComputerName $vmIp -Credential $Credentials -ErrorAction Stop
    } catch {
        Write-Host "Login failed (expected)."
    }
}

Write-Host "Attempting successful login..."

# Successfully login
try {
    $secpasswd = ConvertTo-SecureString $correctPassword -AsPlainText -Force
    $Credentials = New-Object System.Management.Automation.PSCredential($realusername, $secpasswd)
    $session = New-SSHSession -ComputerName $vmIp -Credential $Credentials
    Invoke-SSHCommand -Index $session.Sessionid -Command "echo 'Successful login'"
    Remove-SSHSession -SessionId $session.SessionId
} catch {
    Write-Host "Unexpected failure on successful login."
}

Write-Host "Brute-force simulation complete."