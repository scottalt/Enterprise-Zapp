<#
.SYNOPSIS
    Enterprise-Zapp one-time setup script.
    Creates a temporary, read-only app registration in your Entra ID tenant
    that Enterprise-Zapp uses to scan for hygiene issues.

.DESCRIPTION
    This script:
    1. Connects to Microsoft Graph (requires Privileged Role Administrator or Global Administrator)
    2. Creates an app registration named "Enterprise-Zapp"
    3. Grants read-only admin consent for the required API permissions
    4. Saves the client_id and tenant_id to enterprise_zapp_config.json

    NOTE: Application Administrator and Cloud Application Administrator are NOT sufficient
    for this script — those roles cannot grant admin consent for Microsoft Graph application
    permissions. You must sign in as a Privileged Role Administrator or Global Administrator.

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
    Required role: Privileged Role Administrator (minimum) or Global Administrator
#>

param(
    [switch]$Cleanup
)

$ErrorActionPreference = "Stop"
$ConfigFile = Join-Path $PSScriptRoot "enterprise_zapp_config.json"
$AppName = "Enterprise-Zapp"

# ── Required application permissions / app roles (Graph API) ─────────────────
# IDs must be the appRole (application permission) GUIDs from the Microsoft
# Graph service principal, NOT the oauth2PermissionScope (delegated) GUIDs.
$RequiredPermissions = @(
    @{ Api = "00000003-0000-0000-c000-000000000000"; Permission = "Application.Read.All";  Id = "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30" },
    @{ Api = "00000003-0000-0000-c000-000000000000"; Permission = "Directory.Read.All";    Id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61" },
    @{ Api = "00000003-0000-0000-c000-000000000000"; Permission = "AuditLog.Read.All";     Id = "b0afded3-3588-46d8-8b3d-9842eff778da" },
    @{ Api = "00000003-0000-0000-c000-000000000000"; Permission = "User.Read.All";         Id = "df021288-bdef-4463-88db-98f22de89214" },
    @{ Api = "00000003-0000-0000-c000-000000000000"; Permission = "Policy.Read.All";       Id = "246dd0d5-5bd0-4def-940b-0421030a5b68" },
    @{ Api = "00000003-0000-0000-c000-000000000000"; Permission = "Reports.Read.All";     Id = "230c1aed-a721-4c5d-9cb4-a90514e508ef" }
)

function Write-Banner {
    param([string]$Mode = "Setup")
    Write-Host ""
    Write-Host "  ███████╗ ███╗  ██╗ ████████╗ ███████╗ ██████╗  ██████╗ ██╗ ███████╗ ███████╗" -ForegroundColor Cyan
    Write-Host "  ██╔════╝ ████╗ ██║ ╚══██╔══╝ ██╔════╝ ██╔══██╗ ██╔══██╗██║ ██╔════╝ ██╔════╝" -ForegroundColor Cyan
    Write-Host "  █████╗   ██╔██╗██║    ██║    █████╗   ██████╔╝ ██████╔╝██║ ███████╗ █████╗  " -ForegroundColor Cyan
    Write-Host "  ██╔══╝   ██║╚████║    ██║    ██╔══╝   ██╔══██╗ ██╔═══╝ ██║ ╚════██║ ██╔══╝  " -ForegroundColor Cyan
    Write-Host "  ███████╗ ██║ ╚███║    ██║    ███████╗ ██║  ██║ ██║     ██║ ███████║ ███████╗" -ForegroundColor Cyan
    Write-Host "  ╚══════╝ ╚═╝  ╚══╝    ╚═╝    ╚══════╝ ╚═╝  ╚═╝ ╚═╝     ╚═╝ ╚══════╝ ╚══════╝" -ForegroundColor Cyan
    Write-Host "                     ███████╗  █████╗  ██████╗  ██████╗ " -ForegroundColor Green
    Write-Host "                     ╚════██║ ██╔══██╗ ██╔══██╗ ██╔══██╗" -ForegroundColor Green
    Write-Host "                         ██╔╝ ███████║ ██████╔╝ ██████╔╝" -ForegroundColor Green
    Write-Host "                        ██╔╝  ██╔══██║ ██╔═══╝  ██╔═══╝ " -ForegroundColor Green
    Write-Host "                     ███████╗ ██║  ██║ ██║      ██║     " -ForegroundColor Green
    Write-Host "                     ╚══════╝ ╚═╝  ╚═╝ ╚═╝      ╚═╝     " -ForegroundColor Green
    Write-Host ""
    if ($Mode -eq "Cleanup") {
        Write-Host "  Entra ID Enterprise App Hygiene Scanner — Cleanup" -ForegroundColor White
        Write-Host "  Removing the Enterprise-Zapp app registration from your tenant." -ForegroundColor Yellow
    } else {
        Write-Host "  Entra ID Enterprise App Hygiene Scanner — Setup" -ForegroundColor White
        Write-Host "  Read-only. No changes made to your tenant." -ForegroundColor Green
    }
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

function Assert-EntraIDAccount {
    $ctx = Get-MgContext
    if (-not $ctx) {
        Write-Host "[!] Not connected to Microsoft Graph." -ForegroundColor Red
        exit 1
    }

    # The well-known MSA consumer tenant ID
    $ConsumerTenantId = "9188040d-6c67-4c5b-b112-36a304b66dad"

    if ($ctx.TenantId -eq $ConsumerTenantId) {
        Write-Host "" -ForegroundColor Red
        Write-Host "  [!] ERROR: Personal Microsoft Account (MSA) detected." -ForegroundColor Red
        Write-Host ""
        Write-Host "  Enterprise-Zapp requires an Entra ID work or school account." -ForegroundColor Yellow
        Write-Host "  You are signed in as: $($ctx.Account)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Please re-run the script and sign in with your organization's" -ForegroundColor White
        Write-Host "  Entra ID credentials (e.g., user@yourcompany.com)." -ForegroundColor White
        Write-Host ""
        Write-Host "  TIP: If your personal account keeps being selected automatically," -ForegroundColor Gray
        Write-Host "  try signing out of that account from the browser first, or run:" -ForegroundColor Gray
        Write-Host "    Connect-MgGraph -UseDeviceAuthentication" -ForegroundColor Gray
        Write-Host ""
        Disconnect-MgGraph | Out-Null
        exit 1
    }
}

function Remove-ExistingApp {
    if (-not (Test-Path $ConfigFile)) {
        Write-Host "[!] No config file found at $ConfigFile. Nothing to clean up." -ForegroundColor Yellow
        return
    }

    $Config = Get-Content $ConfigFile | ConvertFrom-Json
    $ClientId = $Config.client_id

    Write-Host "[*] Connecting to Microsoft Graph for cleanup..." -ForegroundColor Cyan

    # Disconnect any cached session so a fresh sign-in prompt always appears
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

    Connect-MgGraph -Scopes "Application.ReadWrite.All" -NoWelcome
    Assert-EntraIDAccount

    $App = Get-MgApplication -Filter "appId eq '$ClientId'" -ErrorAction SilentlyContinue
    if ($App) {
        try {
            Remove-MgApplication -ApplicationId $App.Id -ErrorAction Stop
            Write-Host "[+] App registration '$($App.DisplayName)' deleted successfully." -ForegroundColor Green
        } catch {
            Write-Host "[!] Failed to delete app registration '$($App.DisplayName)': $_" -ForegroundColor Red
            Write-Host "[!] You may need the Application Administrator or Global Administrator role to delete app registrations." -ForegroundColor Yellow
        }
    } else {
        Write-Host "[!] App with client ID $ClientId not found. It may have already been deleted." -ForegroundColor Yellow
    }

    Remove-Item $ConfigFile -Force
    Write-Host "[+] Config file removed." -ForegroundColor Green
}

function New-AppRegistration {
    Write-Host "[*] Connecting to Microsoft Graph..." -ForegroundColor Cyan
    Write-Host "    You will be prompted to sign in as a Privileged Role Administrator or Global Administrator." -ForegroundColor Gray
    Write-Host ""

    # Disconnect any cached session so a fresh sign-in prompt always appears
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

    Connect-MgGraph -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "DelegatedPermissionGrant.ReadWrite.All", "Organization.Read.All" -NoWelcome
    Assert-EntraIDAccount

    # Get tenant info
    try {
        $TenantDetails = Get-MgOrganization
        $TenantId = $TenantDetails.Id
        $TenantName = $TenantDetails.DisplayName
    } catch {
        Write-Host "[!] Could not retrieve tenant details. Falling back to context info." -ForegroundColor Yellow
        $ctx = Get-MgContext
        $TenantId = $ctx.TenantId
        $TenantName = "(unknown)"
    }
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
            DisplayName              = $AppName
            SignInAudience           = "AzureADMyOrg"
            IsFallbackPublicClient   = $true   # required for MSAL device code flow
            RequiredResourceAccess   = @(
                @{
                    ResourceAppId  = "00000003-0000-0000-c000-000000000000"
                    ResourceAccess = $GraphResourceAccess
                }
            )
        }

        $App = New-MgApplication @AppParams
        Write-Host "[+] App registration created. App ID: $($App.AppId)" -ForegroundColor Green
    }

    # Ensure public client flows are enabled (covers apps created before this fix)
    if (-not $App.IsFallbackPublicClient) {
        Update-MgApplication -ApplicationId $App.Id -IsFallbackPublicClient:$true
        Write-Host "[+] Enabled public client flows on app registration." -ForegroundColor Green
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
    # Write UTF-8 without BOM so Python can read it with standard utf-8 encoding
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($ConfigFile, ($Config | ConvertTo-Json), $utf8NoBom)

    Write-Host ""
    Write-Host "  ════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Setup complete!" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Tenant:    $TenantName" -ForegroundColor White
    Write-Host "  Tenant ID: $TenantId" -ForegroundColor White
    Write-Host "  Client ID: $($App.AppId)" -ForegroundColor White
    Write-Host "  Config:    $ConfigFile" -ForegroundColor White
    Write-Host ""
    Write-Host "  Next step — install and run the scan:" -ForegroundColor Yellow
    Write-Host "    pip install -e ." -ForegroundColor White
    Write-Host "    enterprise-zapp" -ForegroundColor White
    Write-Host ""
    Write-Host "  Already installed? Just run:" -ForegroundColor Gray
    Write-Host "    enterprise-zapp" -ForegroundColor White
    Write-Host ""
    Write-Host "  Prefer to run directly from source (no install):" -ForegroundColor Gray
    Write-Host "    python -m src.cli" -ForegroundColor White
    Write-Host ""
    Write-Host "  To clean up the app registration after your scan:" -ForegroundColor Gray
    Write-Host "    .\setup.ps1 -Cleanup" -ForegroundColor Gray
    Write-Host "  ════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
}

# ── Entry point ───────────────────────────────────────────────────────────────
if ($Cleanup) {
    Write-Banner -Mode "Cleanup"
} else {
    Write-Banner -Mode "Setup"
}
Install-GraphModule

if ($Cleanup) {
    Remove-ExistingApp
} else {
    New-AppRegistration
}
