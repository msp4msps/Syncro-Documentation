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
    [string]$SyncroAPIKey
)


$url =  "https://$($SyncroSubdomain).syncromsp.com/api/v1/customers?api_key=$($SyncroAPIKey)"
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
    [string]$SyncroAPIKey
)


$url =  "https://$($SyncroSubdomain).syncromsp.com/api/v1/wiki_pages?api_key=$($SyncroAPIKey)"
$response = Invoke-RestMethod -Uri $url -Method GET -ContentType 'application/json'
$response

}



###Fnd All Syncro Customers##########
Write-Host "Getting All Customers In Syncro"

$SyncroCustomers = (GetAll-Customers -SyncroSubdomain $SyncroSubdomain -SyncroAPIKey $SyncroAPIKey).customers
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

     #Get ALL Licensed Users and Find Shared  Mailboxes#
    Write-Host "Checking Mailboxes for $($Customer.Name)" -ForegroundColor Green
    try{
    $token = New-PartnerAccessToken -ApplicationId 'a0c73c16-a7e3-4564-9a95-2bdf47383716'-RefreshToken $ExchangeRefreshToken -Scopes 'https://outlook.office365.com/.default' -Tenant $customer.TenantId -ErrorAction SilentlyContinue
    $tokenValue = ConvertTo-SecureString "Bearer $($token.AccessToken)" -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential($upn, $tokenValue)
    $domain = $customer.DefaultDomainName
    $InitialDomain = Get-MsolDomain -TenantId $customer.TenantId | Where-Object {$_.IsInitial -eq $true}
    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "https://ps.outlook.com/powershell-liveid?DelegatedOrg=$($InitialDomain)&BasicAuthToOAuthConversion=true" -Credential $credential -Authentication Basic -AllowRedirection -ErrorAction SilentlyContinue
    Import-PSSession $session
    }catch{("This tenant does not have exchange")}
    try{ 
    $mailboxes = Get-Mailbox | Get-MailboxStatistics | Select-Object DisplayName, @{name=”TotalItemSize (GB)”;expression={[math]::Round((($_.TotalItemSize.Value.ToString()).Split(“(“)[1].Split(” “)[0].Replace(“,”,””)/1GB),2)}},ItemCount,LastLogonTime | Sort “TotalItemSize (GB)” -Descending
    Write-Host "Geting ALl Mailbox information, this will take a few minutes"
    $mailflowRules = Get-TransportRule | Select-Object Name
    $DkimConfig = Get-DkimSigningConfig | Select-Object Domain, Enabled
    $ATPSettings = Get-AtpPolicyForO365 | Select-Object Name, EnableSafeLinksForO365Clients, EnableATPForSPOTeamsODB
    $SafeLinksPolicy = Get-SafeLinksPolicy | Select-Object Name, isEnabled, isDefault
    $SafeAttachmentPolicy = Get-SafeAttachmentPolicy | Select-Object Name, Action, Enable
    }catch{("This tenant does not have ATP licensing")}
    try{
    Remove-PSSession $session}catch{("There is no session to Remove")}
   $customer_id = ($CustomerObj | Where-Object { $_.Domain -eq $domain}).customer_id
   $CurrentDocuments = (Get-WikiPage -SyncroSubdomain $SyncroSubdomain -SyncroAPIKey $SyncroAPIKey).wiki_pages
   $name = "Microsoft Exchange Report: $($customer.Name)"
   if($customer_id){
   $bodyVariables = @{
        "customer_Name" = $customer.Name
        "Tenant_ID"     = $customer.TenantID
        "Mailboxes" = ($mailboxes| convertto-html -Fragment  | out-string)
        "mailflow_rules"      = ($mailflowRules | convertto-html -Fragment  | out-string)
        "DkimConfig"   = ($DkimConfig | convertto-html -Fragment  | out-string)
        "ATPSettings" = ($ATPSettings | convertto-html -Fragment  | out-string)
        "SafeLinksPolicy" = ($SafeLinksPolicy | convertto-html -Fragment  | out-string)
        "SafeAttachmentPolicy" = ($SafeAttachmentPolicy | convertto-html -Fragment  | out-string)

   }
   $body = "<p>Customer Name: $($bodyVariables.customer_Name)</p>

   <p>TenantID: $($bodyVariables.Tenant_ID)</p>

   <p>Mailboxes: $($bodyVariables.Mailboxes)</p>

   <p>Mailflow Rules: $($bodyVariables.mailflow_rules)</p>
   
   <p>DKIM Configuration: $($bodyVariables.DkimConfig)</p>
   
   <p>ATP Settings: $($bodyVariables.ATPSettings)</p>
   
   <p>Safe Links Policies: $($bodyVariables.SafeLinksPolicy)</p>
   
   <p>Safe Attachment Policies: $($bodyVariables.SafeAttachmentPolicy)</p>"

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