param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('386', 'amd64')]
    [string]$Arch,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$SliverVersion,

    [string]$ManifestPath = '.github/sliver-bof-e2e.generated.yml'
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security

$objectName = if ($Arch -eq '386') { 'ChromiumKeyDump.x86.o' } else { 'ChromiumKeyDump.x64.o' }
$object = "build/$objectName"
if (-not (Test-Path -LiteralPath $object -PathType Leaf)) {
    throw "Missing tested BOF object: $object"
}

# Local State normally stores a DPAPI-prefixed, base64-encoded protected key.
# A fixed plaintext makes the expected BOF output deterministic while the
# protected bytes are generated for the ephemeral runner's current user.
$plaintext = [byte[]](0..31)
$scope = [System.Security.Cryptography.DataProtectionScope]::CurrentUser
$protected = [System.Security.Cryptography.ProtectedData]::Protect($plaintext, $null, $scope)
$roundTrip = [System.Security.Cryptography.ProtectedData]::Unprotect($protected, $null, $scope)
$expected = [Convert]::ToBase64String($plaintext)
if ([Convert]::ToBase64String($roundTrip) -ne $expected) {
    throw 'DPAPI fixture round trip failed'
}

$browserId = $null
$localState = $null
$localAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
if ([string]::IsNullOrWhiteSpace($localAppData)) {
    throw 'Could not resolve the current user LocalAppData folder'
}
foreach ($candidate in @(
    @{ Id = 0; Path = (Join-Path $localAppData 'Google\Chrome\User Data\Local State') },
    @{ Id = 1; Path = (Join-Path $localAppData 'Microsoft\Edge\User Data\Local State') }
)) {
    if (-not (Test-Path -LiteralPath $candidate.Path)) {
        $browserId = $candidate.Id
        $localState = $candidate.Path
        break
    }
}
if ($null -eq $localState) {
    throw 'Both browser Local State paths already exist; refusing to overwrite them'
}
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $localState) | Out-Null
$blob = [byte[]]([System.Text.Encoding]::ASCII.GetBytes('DPAPI') + $protected)
$encryptedKey = [Convert]::ToBase64String($blob)
$json = '{"os_crypt":{"encrypted_key":"' + $encryptedKey + '"}}'
$utf8 = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText($localState, $json, $utf8)

$manifest = @{
    schema = 'sliver-bof-e2e/v1'
    sliver = @{ version = $SliverVersion }
    defaults = @{
        bof_executor = 'reflektor'
        entrypoint = 'go'
        modes = @('session', 'beacon')
        command_timeout = '3m'
    }
    suites = @(
        @{
            name = "windows-$Arch"
            target = @{ os = 'windows'; arch = $Arch }
            tests = @(
                @{
                    name = 'chromium-dpapi-masterkey'
                    object = $object
                    args = @(@{ type = 'int'; value = $browserId })
                    expect = @{
                        output = @{
                            contains = @("[ChromiumKeyDump] Masterkey: $expected")
                        }
                    }
                }
            )
        }
    )
}

$manifestFile = [System.IO.Path]::GetFullPath((Join-Path (Get-Location).Path $ManifestPath))
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $manifestFile) | Out-Null
[System.IO.File]::WriteAllText($manifestFile, ($manifest | ConvertTo-Json -Depth 12), $utf8)
Write-Host "Created synthetic browser $browserId Local State fixture and windows/$Arch BOF test manifest"
