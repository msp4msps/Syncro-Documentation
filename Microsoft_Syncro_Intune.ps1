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
    [Parameter(Mandatory= $true, HelpMessage="Enter your ExchangeRefreshToken from the Secure Application Model")]
    [string]$ExchangeRefreshToken,
    [Parameter(Mandatory= $true, HelpMessage="Enter your UserPrincipalName from the Secure Application Model")]
    [string]$upn,
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
$ExchangeRefreshToken = $ExchangeRefreshToken
$upn = $upn
$secPas = $ApplicationSecret| ConvertTo-SecureString -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($ApplicationId, $secPas)


###Additional API Permissions Need for App in Azure AD####
#DeviceManagementApps.Read.All
#Device.Read.All
#DeviceManagementConfiguration.Read.All
#DeviceManagementManagedDevices.Read.All



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

###Connect to your Own Partner Center to get a list of customers/tenantIDs #########
$aadGraphToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.windows.net/.default' -ServicePrincipal -Tenant $tenantID
$graphToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.microsoft.com/.default' -ServicePrincipal -Tenant $tenantID


Connect-MsolService -AdGraphAccessToken $aadGraphToken.AccessToken -MsGraphAccessToken $graphToken.AccessToken

$customers = Get-MsolPartnerContract -All
 
Write-Host "Found $($customers.Count) customers in Partner Center." -ForegroundColor DarkGreen
foreach ($customer in $customers) {
    Write-Host "Found $($customer.Name) in Partner Center" -ForegroundColor Green

    ###Get Access Token########
    $CustomerToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.microsoft.com/.default' -Tenant $customer.TenantID
    $headers = @{ "Authorization" = "Bearer $($CustomerToken.AccessToken)" }
    $domain = $customer.DefaultDomainName
    $AllDomains = Get-MsolDomain -TenantId $customer.TenantID

    #####Get Intune information if it is available####
    try{
    $Devices = (Invoke-RestMethod -Uri 'https://graph.microsoft.com/beta/deviceManagement/managedDevices' -Headers $headers -Method Get -ContentType "application/json").value | Select-Object deviceName, ownerType, operatingSystem, osVersion, complianceState,userPrincipalName, autopilotEnrolled,isEncrypted
    $complianceSummary = (Invoke-RestMethod -Uri 'https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicyDeviceStateSummary' -Headers $headers -Method Get -ContentType "application/json") | Select-Object inGracePeriodCount, compliantDeviceCount, nonCompliantDeviceCount
    $apps = (Invoke-RestMethod -Uri 'https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?$filter=(microsoft.graph.managedApp/appAvailability eq null or isAssigned eq true)&$orderby=displayName' -Headers $headers -Method Get -ContentType "application/json").value  | Select-Object displayName
    }catch{("Either this tenant does not have Intune licensing or you have not given proper permissions to the app listed at the begining of this script")
    continue}
   
   #####Create or Update Documentation in Snycro####
   if($Devices){
   $customer_id = ($CustomerObj | Where-Object { $_.Domain -in $AllDomains.name}).customer_id
   $page = 1
   $totaldocCount = (Get-WikiPage -SyncroSubdomain $SyncroSubdomain -SyncroAPIKey $SyncroAPIKey -page 1).meta.total_pages
   $CurrentDocuments = Do{
   (Get-WikiPage -SyncroSubdomain $SyncroSubdomain -SyncroAPIKey $SyncroAPIKey -page $page).wiki_pages
   $page = $page + 1
   }Until ($page -gt $totaldocCount)
   $name = "Microsoft Intune Report: $($customer.Name)"
   if($customer_id){
   $bodyVariables = @{
        "customer_Name"    = $customer.Name
        "Tenant_ID"        = $customer.TenantID
        "Devices"       = ($Devices | convertto-html -Fragment  | out-string)
        "complianceSummary"   = ($complianceSummary | convertto-html -Fragment  | out-string)
        "apps" = ($apps | convertto-html -Fragment  | out-string)

   }
   $body = "<p>Customer Name: $($bodyVariables.customer_Name)</p>

   <p>TenantID: $($bodyVariables.Tenant_ID)</p>

   <p>Compliance Summary: $($bodyVariables.complianceSummary)</p>

   <p>Devices: $($bodyVariables.Devices)</p>

   <p>Apps: $($bodyVariables.apps)</p>"

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
}
