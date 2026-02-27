<#
.SYNOPSIS
    Enterprise-Zapp one-time setup script.
    Creates a temporary, read-only app registration in your Entra ID tenant
    that Enterprise-Zapp uses to scan for hygiene issues.

.DESCRIPTION
    This script:
    1. Connects to Microsoft Graph (requires Global Admin or Privileged Role Admin)
    2. Creates an app registration named "Enterprise-Zapp-Scan-<date>"
    3. Grants read-only admin consent for the required API permissions
    4. Saves the client_id and tenant_id to enterprise_zapp_config.json

    The app registration can be deleted after the scan with: .\setup.ps1 -Cleanup

.PARAMETER Cleanup
    Delete the app registration created by a previous run of this script.

.EXAMPLE
    # First-time setup:
    .\setup.ps1

    # Cleanup after scan:
    .\setup.ps1 -Cleanup

.NOTES
    Required PowerShell module: Microsoft.Graph (installed automatically if missing)
    Required role: Global Administrator or Privileged Role Administrator
#>

param(
    [switch]$Cleanup
)

$ErrorActionPreference = "Stop"
$ConfigFile = Join-Path $PSScriptRoot "enterprise_zapp_config.json"
$AppName = "Enterprise-Zapp-Scan-$(Get-Date -Format 'yyyy-MM-dd')"

# ── Required read-only delegated permissions (Graph API) ─────────────────────
$RequiredPermissions = @(
    @{ Api = "00000003-0000-0000-c000-000000000000"; Permission = "Application.Read.All";  Id = "c79f8feb-a9db-4090-85f9-90d820caa0eb" },
    @{ Api = "00000003-0000-0000-c000-000000000000"; Permission = "Directory.Read.All";    Id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61" },
    @{ Api = "00000003-0000-0000-c000-000000000000"; Permission = "AuditLog.Read.All";     Id = "b0afded3-3588-46d8-8b3d-9842eff778da" },
    @{ Api = "00000003-0000-0000-c000-000000000000"; Permission = "Reports.Read.All";      Id = "230c1aed-a721-4c5d-9cb4-a90514e508ef" },
    @{ Api = "00000003-0000-0000-c000-000000000000"; Permission = "Policy.Read.All";       Id = "572fea84-0151-49b2-9301-11cb16974376" }
)

function Write-Banner {
    Write-Host ""
    Write-Host "  ███████╗ ███╗  ██╗ ████████╗ ███████╗ ██████╗  ██████╗ ██╗ ███████╗ ███████╗" -ForegroundColor Cyan
    Write-Host "  ██╔════╝ ████╗ ██║ ╚══██╔══╝ ██╔════╝ ██╔══██╗ ██╔══██╗██║ ██╔════╝ ██╔════╝" -ForegroundColor Cyan
    Write-Host "  █████╗   ██╔██╗██║    ██║    █████╗   ██████╔╝ ██████╔╝██║ ███████╗ █████╗  " -ForegroundColor Cyan
    Write-Host "  ██╔══╝   ██║╚████║    ██║    ██╔══╝   ██╔══██╗ ██╔═══╝ ██║ ╚════██║ ██╔══╝  " -ForegroundColor Cyan
    Write-Host "  ███████╗ ██║ ╚███║    ██║    ███████╗ ██║  ██║ ██║     ██║ ███████║ ███████╗" -ForegroundColor Cyan
    Write-Host "  ╚══════╝ ╚═╝  ╚══╝    ╚═╝    ╚══════╝ ╚═╝  ╚═╝ ╚═╝     ╚═╝ ╚══════╝ ╚══════╝" -ForegroundColor Cyan
    Write-Host "                              Z A P P" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Entra ID Enterprise App Hygiene Scanner — Setup" -ForegroundColor White
    Write-Host "  Read-only. No changes made to your tenant." -ForegroundColor Green
    Write-Host ""
}

function Install-GraphModule {
    if (-not (Get-Module -ListAvailable -Name "Microsoft.Graph.Applications")) {
        Write-Host "[*] Installing Microsoft.Graph module (this may take a minute)..." -ForegroundColor Yellow
        Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module Microsoft.Graph.Applications -ErrorAction SilentlyContinue
    Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
    Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction SilentlyContinue
}

function Remove-ExistingApp {
    if (-not (Test-Path $ConfigFile)) {
        Write-Host "[!] No config file found at $ConfigFile. Nothing to clean up." -ForegroundColor Yellow
        return
    }

    $Config = Get-Content $ConfigFile | ConvertFrom-Json
    $ClientId = $Config.client_id

    Write-Host "[*] Connecting to Microsoft Graph for cleanup..." -ForegroundColor Cyan
    Connect-MgGraph -Scopes "Application.ReadWrite.All" -NoWelcome

    $App = Get-MgApplication -Filter "appId eq '$ClientId'" -ErrorAction SilentlyContinue
    if ($App) {
        Remove-MgApplication -ApplicationId $App.Id
        Write-Host "[+] App registration '$($App.DisplayName)' deleted successfully." -ForegroundColor Green
    } else {
        Write-Host "[!] App with client ID $ClientId not found. It may have already been deleted." -ForegroundColor Yellow
    }

    Remove-Item $ConfigFile -Force
    Write-Host "[+] Config file removed." -ForegroundColor Green
}

function New-AppRegistration {
    Write-Host "[*] Connecting to Microsoft Graph..." -ForegroundColor Cyan
    Write-Host "    You will be prompted to sign in as a Global Admin or Privileged Role Admin." -ForegroundColor Gray
    Write-Host ""

    Connect-MgGraph -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "DelegatedPermissionGrant.ReadWrite.All" -NoWelcome

    # Get tenant info
    $TenantDetails = Get-MgOrganization
    $TenantId = $TenantDetails.Id
    $TenantName = $TenantDetails.DisplayName
    Write-Host "[+] Connected to tenant: $TenantName ($TenantId)" -ForegroundColor Green

    # Check if an app with today's name already exists
    $Existing = Get-MgApplication -Filter "displayName eq '$AppName'" -ErrorAction SilentlyContinue
    if ($Existing) {
        Write-Host "[!] App '$AppName' already exists. Using existing registration." -ForegroundColor Yellow
        $App = $Existing
    } else {
        Write-Host "[*] Creating app registration: $AppName" -ForegroundColor Cyan

        # Build required resource access (delegated permissions for Microsoft Graph)
        $GraphResourceAccess = $RequiredPermissions | ForEach-Object {
            @{
                id   = $_.Id
                type = "Role"  # Role = Application permission; Scope = Delegated
            }
        }

        $AppParams = @{
            DisplayName            = $AppName
            SignInAudience         = "AzureADMyOrg"
            RequiredResourceAccess = @(
                @{
                    ResourceAppId  = "00000003-0000-0000-c000-000000000000"
                    ResourceAccess = $GraphResourceAccess
                }
            )
        }

        $App = New-MgApplication @AppParams
        Write-Host "[+] App registration created. App ID: $($App.AppId)" -ForegroundColor Green
    }

    # Grant admin consent via service principal
    Write-Host "[*] Creating service principal and granting admin consent..." -ForegroundColor Cyan

    # Ensure the service principal exists
    $SP = Get-MgServicePrincipal -Filter "appId eq '$($App.AppId)'" -ErrorAction SilentlyContinue
    if (-not $SP) {
        $SP = New-MgServicePrincipal -AppId $App.AppId
    }

    # Get the Microsoft Graph service principal
    $GraphSP = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

    # Grant each app role (admin consent for application permissions)
    foreach ($Perm in $RequiredPermissions) {
        $Existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SP.Id -ErrorAction SilentlyContinue |
            Where-Object { $_.AppRoleId -eq $Perm.Id }

        if (-not $Existing) {
            $Params = @{
                PrincipalId = $SP.Id
                ResourceId  = $GraphSP.Id
                AppRoleId   = $Perm.Id
            }
            New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SP.Id -BodyParameter $Params | Out-Null
            Write-Host "    [+] Granted: $($Perm.Permission)" -ForegroundColor Green
        } else {
            Write-Host "    [=] Already granted: $($Perm.Permission)" -ForegroundColor Gray
        }
    }

    # Save config
    $Config = @{
        client_id   = $App.AppId
        tenant_id   = $TenantId
        tenant_name = $TenantName
        app_name    = $AppName
        created_at  = (Get-Date -Format "o")
    }
    $Config | ConvertTo-Json | Set-Content $ConfigFile -Encoding UTF8

    Write-Host ""
    Write-Host "  ════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Setup complete!" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Tenant:    $TenantName" -ForegroundColor White
    Write-Host "  Tenant ID: $TenantId" -ForegroundColor White
    Write-Host "  Client ID: $($App.AppId)" -ForegroundColor White
    Write-Host "  Config:    $ConfigFile" -ForegroundColor White
    Write-Host ""
    Write-Host "  Next step — run the scan:" -ForegroundColor Yellow
    Write-Host "    python -m src.cli" -ForegroundColor White
    Write-Host "  Or after pip install:" -ForegroundColor Yellow
    Write-Host "    enterprise-zapp" -ForegroundColor White
    Write-Host ""
    Write-Host "  To clean up the app registration after your scan:" -ForegroundColor Gray
    Write-Host "    .\setup.ps1 -Cleanup" -ForegroundColor Gray
    Write-Host "  ════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
}

# ── Entry point ───────────────────────────────────────────────────────────────
Write-Banner
Install-GraphModule

if ($Cleanup) {
    Write-Host "[*] Cleanup mode: removing Enterprise-Zapp app registration..." -ForegroundColor Yellow
    Remove-ExistingApp
} else {
    New-AppRegistration
}
