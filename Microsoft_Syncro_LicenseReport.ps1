Param
(

[cmdletbinding()]
    [Parameter(Mandatory= $true, HelpMessage="Enter your ApplicationId from the Secure Application Model https://github.com/KelvinTegelaar/SecureAppModel/blob/master/Create-SecureAppModel.ps1")]
    [string]$ApplicationId,
    [Parameter(Mandatory= $true, HelpMessage="Enter your ApplicationSecret from the Secure Application Model")]
    [string]$ApplicationSecret,
    [Parameter(Mandatory= $true, HelpMessage="Enter your Partner Tenantid")]
    [string]$tenantID,
    [Parameter(Mandatory= $true, HelpMessage="Enter your refreshToken from the Secure Application Model")]
    [string]$refreshToken,
    [Parameter(Mandatory= $true)]
    [string]$SyncroAPIKey,
    [Parameter(Mandatory= $true)]
    [string]$SyncroSubdomain

)

# Check if the MSOnline PowerShell module has already been loaded.
if ( ! ( Get-Module MSOnline) ) {
    # Check if the MSOnline PowerShell module is installed.
    if ( Get-Module -ListAvailable -Name MSOnline ) {
        Write-Host -ForegroundColor Green "Loading the Azure AD PowerShell module..."
        Import-Module MsOnline
    } else {
        Install-Module MsOnline
    }
}

###MICROSOFT SECRETS#####

$ApplicationId = $ApplicationId
$ApplicationSecret = $ApplicationSecret
$tenantID = $tenantID
$refreshToken = $refreshToken
$secPas = $ApplicationSecret| ConvertTo-SecureString -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($ApplicationId, $secPas)


###Syncro Secrets####
 
$SyncroSubdomain = $SyncroSubdomain
$SyncroAPIKey = $SyncroAPIKey


###API Permissions Needed In Syncro#####
# Customers - List/Search
# Customers - View Detail
# Customers - Edit
# Documentation - Allow Usage
# Documentation - Create
# Documentation - Edit



###FUNCTION TO Get All Customers IN SYNCRO####
function GetAll-Customers () {

<#
.SYNOPSIS
This function is used to get all customer records in Syncro. 
.DESCRIPTION
The function connects to your Syncro environment and finds all customers
.EXAMPLE
GetAll-Customers -SyncroSubDomain $SyncroSubDomain -SyncroAPIKey $SyncroAPIkey
Retrieves all customers
.NOTES
NAME: GetAll-Customers
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    [string]$SyncroSubdomain,
    [string]$SyncroAPIKey,
    [string]$page
)


$url =  "https://$($SyncroSubdomain).syncromsp.com/api/v1/customers?api_key=$($SyncroAPIKey)&page=$($page)"
$response = Invoke-RestMethod -Uri $url -Method Get -ContentType 'application/json'
$response

}



###Update Documents in Syncro #######

function Update-WikiPage () {

<#
.SYNOPSIS
This function is used to update a document in Syncro. 
.DESCRIPTION
The function connects to your Syncro environment and updates a document 
.EXAMPLE
Update-WikiPage -SyncroSubDomain $SyncroSubDomain -SyncroAPIKey $SyncroAPIkey -WikiID $WikiID -body $body
Updates document with new body. 
.NOTES
NAME: Update-WikiPage
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    [string]$SyncroSubdomain,
    [string]$SyncroAPIKey,
    [string]$WikiID,
    [string]$body
)



$UpdateWikiPage =@{
    body = $body
    api_key=$SyncroAPIKey
}

$body = (ConvertTo-Json $UpdateWikiPage)
$url =  "https://$($SyncroSubdomain).syncromsp.com/api/v1/wiki_pages/$($WikiID)"
$response = Invoke-RestMethod -Uri $url -Method Put -Body $body -ContentType 'application/json'
$response

}

###Create new document in Syncro #######

function Create-WikiPage () {

<#
.SYNOPSIS
This function is used to create a document for a customer in Syncro. 
.DESCRIPTION
The function connects to your Syncro environment and creates a document for a customer
.EXAMPLE
Create-WikiPage -SyncroSubDomain $SyncroSubDomain -SyncroAPIKey $SyncroAPIkey -customerID $customerID -name $name -body $body
Creates a new document for a customer in Syncro
.NOTES
NAME: Create-WikiPage
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    [string]$SyncroSubdomain,
    [string]$SyncroAPIKey,
    [string]$customerID,
    [string]$name,
    $body
)



$CreatePage =@{
    customer_id = $customerID
    name = $name
    body= $body
    api_key=$SyncroAPIKey
}

$body = (ConvertTo-Json $CreatePage)
$url =  "https://$($SyncroSubdomain).syncromsp.com/api/v1/wiki_pages"
$response = Invoke-RestMethod -Uri $url -Method Post -Body $body -ContentType 'application/json'
$response

}

###GET All Documentsin Syncro #######

function Get-WikiPage () {

<#
.SYNOPSIS
This function is used to get all documents within Syncro
.DESCRIPTION
The function connects to your Syncro environment and gets all documents 
.EXAMPLE
Get-WikiPage -SyncroSubDomain $SyncroSubDomain -SyncroAPIKey $SyncroAPIkey
Gets all documents that exist
.NOTES
NAME: Get-WikiPage
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    [string]$SyncroSubdomain,
    [string]$SyncroAPIKey,
    [string]$page
)


$url =  "https://$($SyncroSubdomain).syncromsp.com/api/v1/wiki_pages?api_key=$($SyncroAPIKey)&page=$($page)"
$response = Invoke-RestMethod -Uri $url -Method GET -ContentType 'application/json'
$response

}



###Fnd All Syncro Customers##########
Write-Host "Getting All Customers In Syncro"

$page = 1
$totalPageCount = (GetAll-Customers -SyncroSubdomain $SyncroSubdomain -SyncroAPIKey $SyncroAPIKey -page 1).meta.total_pages
$SyncroCustomers  = Do{
   (GetAll-Customers -SyncroSubdomain $SyncroSubdomain -SyncroAPIKey $SyncroAPIKey -page $page).customers
   $page = $page + 1
   }Until ($page -gt $totalPageCount)
Write-Host "Found $($SyncroCustomers.Count) Customers in Syncro" -ForegroundColor Green
$CustomerObj = forEach ($customer in $SyncroCustomers) {
    Write-Host "Getting domain for $($customer.business_name)"
    $customerDomain = ($customer.email -split "@")[1]
    if(!$customerDomain){
    Write-Host "$($customer.business_name) does not have an email on file" -ForegroundColor Red
      } else {
      Write-Host "Customer domain is $($customerDomain)"
      }
    [PSCustomObject]@{
            Domain   = $customerDomain
            customer_id = $customer.id
            }

}



#Account SKUs to transform to normal name.
$AccountSkuIdDecodeData = @{
    "SPB"                                = "Micorsoft 365 Business Premium"
    "SMB_BUSINESS"                       = "MICROSOFT 365 APPS FOR BUSINESS"
    "SMB_BUSINESS_ESSENTIALS"            = "MICROSOFT 365 BUSINESS BASIC"
    "M365_F1"                            = "Microsoft 365 F1"
    "O365_BUSINESS_ESSENTIALS"           = "MICROSOFT 365 BUSINESS BASIC"
    "O365_BUSINESS_PREMIUM"              = "MICROSOFT 365 BUSINESS STANDARD"
    "DESKLESSPACK"                       = "OFFICE 365 F3"
    "TEAMS_FREE"                         = "MICROSOFT TEAM (FREE)"
    "TEAMS_EXPLORATORY"                  = "MICROSOFT TEAMS EXPLORATORY" 
    "M365EDU_A3_STUDENT"                 = "MICROSOFT 365 A3 FOR STUDENTS"
    "M365EDU_A5_STUDENT"                 = "MICROSOFT 365 A5 FOR STUDENTS"
    "M365EDU_A3_FACULTY"                 = "MICROSOFT 365 A3 FOR FACULTY"
    "M365EDU_A5_FACULTY"                 = "MICROSOFT 365 A5 FOR FACULTY"
    "MCOEV_FACULTY"                      = "MICROSOFT 365 PHONE SYSTEM FOR FACULTY"
    "MCOEV_STUDENT"                      = "MICROSOFT 365 PHONE SYSTEM FOR STUDENTS"
    "ENTERPRISEPREMIUM_STUDENT"          = "Office 365 A5 for students"
    "ENTERPRISEPREMIUM_FACULTY"          = "Office 365 A5 for faculty"
    "M365EDU_A1"                         = "Microsoft 365 A1"
    "SHAREPOINTSTANDARD"                 = "SHAREPOINT ONLINE (PLAN 1)"
    "SHAREPOINTENTERPRISE"               = "SHAREPOINT ONLINE (PLAN 2)" 
    "EXCHANGEDESKLESS"                   = "EXCHANGE ONLINE KIOSK"
    "LITEPACK"                           = "OFFICE 365 SMALL BUSINESS"
    "EXCHANGESTANDARD"                   = "EXCHANGE ONLINE (PLAN 1)"
    "STANDARDPACK"                       = "OFFICE 365 E1"
    "STANDARDWOFFPACK"                   = "Office 365 (Plan E2)"
    "ENTERPRISEPACK"                     = "OFFICE 365 E3"
    "VISIOCLIENT"                        = "Visio Pro Online"
    "POWER_BI_ADDON"                     = "Office 365 Power BI Addon"
    "POWER_BI_INDIVIDUAL_USE"            = "Power BI Individual User"
    "POWER_BI_STANDALONE"                = "Power BI Stand Alone"
    "POWER_BI_STANDARD"                  = "Power-BI Standard"
    "PROJECTESSENTIALS"                  = "Project Lite"
    "PROJECTCLIENT"                      = "Project Professional"
    "PROJECTONLINE_PLAN_1"               = "Project Online"
    "PROJECTONLINE_PLAN_2"               = "Project Online and PRO"
    "ProjectPremium"                     = "Project Online Premium"
    "EMS"                                = "ENTERPRISE MOBILITY + SECURITY E3"
    "EMSPREMIUM"                         = "ENTERPRISE MOBILITY + SECURITY E5"
    "RIGHTSMANAGEMENT"                   = "AZURE INFORMATION PROTECTION PLAN 1"
    "MCOMEETADV"                         = "Microsoft 365 Audio Conferencing"
    "BI_AZURE_P1"                        = "POWER BI FOR OFFICE 365 ADD-ON"
    "INTUNE_A"                           = "INTUNE"
    "WIN_DEF_ATP"                        = "Microsoft Defender Advanced Threat Protection"
    "IDENTITY_THREAT_PROTECTION"         =  "Microsoft 365 E5 Security"
    "IDENTITY_THREAT_PROTECTION_FOR_EMS_E5" = "Microsoft 365 E5 Security for EMS E5"
    "ATP_ENTERPRISE"                     = "Office 365 Advanced Threat Protection (Plan 1)"
    "EQUIVIO_ANALYTICS"                  = "Office 365 Advanced eDiscovery"
    "AAD_BASIC"                          = "Azure Active Directory Basic"
    "RMS_S_ENTERPRISE"                   = "Azure Active Directory Rights Management"
    "AAD_PREMIUM"                        = "Azure Active Directory Premium"
    "STANDARDPACK_GOV"                   = "Microsoft Office 365 (Plan G1) for Government"
    "M365_G3_GOV"                        = "MICROSOFT 365 GCC G3"
    "ENTERPRISEPACK_USGOV_DOD"           = "Office 365 E3_USGOV_DOD"
    "ENTERPRISEPACK_USGOV_GCCHIGH"       = "Office 365 E3_USGOV_GCCHIGH"
    "ENTERPRISEPACK_GOV"                 = "OFFICE 365 GCC G3"
    "SHAREPOINTLITE"                     = "SharePoint Online (Plan 1)"
    "MCOIMP"                             = "SKYPE FOR BUSINESS ONLINE (PLAN 1)"
    "OFFICESUBSCRIPTION"                 = "MICROSOFT 365 APPS FOR ENTERPRISE"
    "YAMMER_MIDSIZE"                     = "Yammer"
    "DYN365_ENTERPRISE_PLAN1"            = "Dynamics 365 Customer Engagement Plan Enterprise Edition"
    "ENTERPRISEPREMIUM_NOPSTNCONF"       = "Enterprise E5 (without Audio Conferencing)"
    "ENTERPRISEPREMIUM"                  = "Enterprise E5 (with Audio Conferencing)"
    "MCOSTANDARD"                        = "Skype for Business Online Standalone Plan 2"
    "PROJECT_MADEIRA_PREVIEW_IW_SKU"     = "Dynamics 365 for Financials for IWs"
    "EOP_ENTERPRISE_FACULTY"             = "Exchange Online Protection for Faculty"
    "DYN365_FINANCIALS_BUSINESS_SKU"     = "Dynamics 365 for Financials Business Edition"
    "DYN365_FINANCIALS_TEAM_MEMBERS_SKU" = "Dynamics 365 for Team Members Business Edition"
    "FLOW_FREE"                          = "Microsoft Flow Free"
    "POWER_BI_PRO"                       = "Power BI Pro"
    "O365_BUSINESS"                      = "MICROSOFT 365 APPS FOR BUSINESS"
    "DYN365_ENTERPRISE_SALES"            = "Dynamics Office 365 Enterprise Sales"
    "PROJECTPROFESSIONAL"                = "Project Professional"
    "VISIOONLINE_PLAN1"                  = "Visio Online Plan 1"
    "EXCHANGEENTERPRISE"                 = "Exchange Online Plan 2"
    "DYN365_ENTERPRISE_P1_IW"            = "Dynamics 365 P1 Trial for Information Workers"
    "DYN365_ENTERPRISE_TEAM_MEMBERS"     = "Dynamics 365 For Team Members Enterprise Edition"
    "CRMSTANDARD"                        = "Microsoft Dynamics CRM Online Professional"
    "EXCHANGEARCHIVE_ADDON"              = "Exchange Online Archiving For Exchange Online"
    "SPZA_IW"                            = "App Connect"
    "WINDOWS_STORE"                      = "Windows Store for Business"
    "MCOEV"                              = "Microsoft Phone System"
    "MCOEV_GOV"                          = "MICROSOFT 365 PHONE SYSTEM FOR GCC"
    "SPE_E5"                             = "Microsoft 365 E5"
    "SPE_E3"                             = "Microsoft 365 E3"
    "MCOPSTN1"                           = "PSTN DOMESTIC CALLING"
    "MCOPSTN2"                           = "Domestic and International Calling Plan"
    "MCOPSTN_"                           = "MICROSOFT 365 DOMESTIC CALLING PLAN (120 Minutes)"
    "DYN365_TEAM_MEMBERS"                = "Dynamics 365 Team Members"
    "WIN10_PRO_ENT_SUB"                  = "WINDOWS 10 ENTERPRISE E3"
    "WIN10_VDA_E3"                       = "WINDOWS 10 ENTERPRISE E3"
    "WIN10_VDA_E5"                       = "Windows 10 Enterprise E5"
    "MDATP_XPLAT"                        = "Microsoft Defender for Endpoint"
    "CCIBOTS_PRIVPREV_VIRAL"             = "Power Virtual Agents Viral Trial"
    "ADALLOM_STANDALONE"                 = "Microsoft Cloud App Security"
    "BUSINESS_VOICE_MED2_TELCO"          = "Microsoft 365 Business Voice (US)"
 
}




###Connect to your Own Partner Center to get a list of customers/tenantIDs #########
$aadGraphToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.windows.net/.default' -ServicePrincipal -Tenant $tenantID
$graphToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.microsoft.com/.default' -ServicePrincipal -Tenant $tenantID

Connect-MsolService -AdGraphAccessToken $aadGraphToken.AccessToken -MsGraphAccessToken $graphToken.AccessToken

$customers = Get-MsolPartnerContract -All
 
Write-Host "Found $($customers.Count) customers in Partner Center." -ForegroundColor DarkGreen


foreach ($customer in $customers) {
    Write-Host "Found $($customer.Name) in Partner Center" -ForegroundColor Green
    $CustomerToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.microsoft.com/.default' -Tenant $customer.TenantID
    $headers = @{ "Authorization" = "Bearer $($CustomerToken.AccessToken)" }
    write-host "Collecting data for $($Customer.Name)" -ForegroundColor Green
    $domain = $customer.DefaultDomainName
    $Licenselist = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/subscribedSkus" -Headers $Headers -Method Get -ContentType "application/json").value
    $Licenselist | ForEach-Object { $_.skupartnumber = "$($AccountSkuIdDecodeData.$($_.skupartnumber))" }
    $Users = (Invoke-RestMethod -Uri 'https://graph.microsoft.com/beta/users?$top=999' -Headers $Headers -Method Get -ContentType "application/json").value | Select-Object DisplayName, proxyaddresses, AssignedLicenses, userprincipalname
    $UserObj = foreach ($user in $users) {
        [PSCustomObject]@{
            'DisplayName'      = $user.displayname
            'UPN'         = $user.userprincipalname
            "LicensesAssigned" = ($Licenselist | Where-Object { $_.skuid -in $User.assignedLicenses.skuid }).skupartnumber -join "`n"
        }
     
    }
    $licenseObj = foreach ($License in $Licenselist) {
        [PSCustomObject]@{
            'License Name'      = $license.skupartnumber
            'Active Licenses'   = $license.prepaidUnits.enabled - $license.prepaidUnits.suspended
            'Consumed Licenses' = $license.consumedunits
            'unused licenses'   = $license.prepaidUnits.enabled - $license.prepaidUnits.suspended - $license.consumedunits
        }  
    }
   $customer_id = ($CustomerObj | Where-Object { $_.Domain -eq $domain}).customer_id
   $page = 1
   $totaldocCount = (Get-WikiPage -SyncroSubdomain $SyncroSubdomain -SyncroAPIKey $SyncroAPIKey -page 1).meta.total_pages
   $CurrentDocuments = Do{
   (Get-WikiPage -SyncroSubdomain $SyncroSubdomain -SyncroAPIKey $SyncroAPIKey -page $page).wiki_pages
   $page = $page + 1
   }Until ($page -gt $totaldocCount) 
   
   $name = "Microsoft License Report: $($customer.Name)"
   if($customer_id){
   $bodyVariables = @{
        "customer_Name" = $customer.Name
        "Tenant_ID"     = $customer.TenantID
        "licenses"      = ($licenseObj | select-object 'License Name', 'Active licenses', 'Consumed Licenses', 'Unused Licenses' | convertto-html -Fragment  | out-string)
        "licensed_users"   = (($UserObj | Where-Object { $_.'LicensesAssigned' -ne "" }) | convertto-html -Fragment  | out-string)
        "unlicensed_users" = (($UserObj | Where-Object { $_.'LicensesAssigned' -eq "" }) | convertto-html -Fragment  | out-string)

   }
   $body = "<p>Customer Name: $($bodyVariables.customer_Name)</p>

   <p>TenantID: $($bodyVariables.Tenant_ID)</p>

   <p>License Summary: $($bodyVariables.licenses)</p>

   <p>Licensed Users: $($bodyVariables.licensed_users)</p>
   
   <p>Unlicensed Users: $($bodyVariables.unlicensed_users)</p>"

   $docExist = ($CurrentDocuments | where-object {$_.name -eq $name})

   if(!$docExist){
      Write-Host "Creating a new document" -ForegroundColor Green
      Create-WikiPage -SyncroSubdomain $SyncroSubdomain -SyncroAPIKey $SyncroAPIKey -customerID $customer_id -name $name -body $body
   } else {
     Write-Host "Document already exist. Updating Existing Document" -ForegroundColor Yellow
     Update-WikiPage -SyncroSubdomain $SyncroSubdomain -SyncroAPIKey $SyncroAPIKey -WikiID $docExist.id -body $body
   }
   
}
}
