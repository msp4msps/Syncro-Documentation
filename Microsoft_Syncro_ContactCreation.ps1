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
# Contacts - Import
# Customers - List/Search
# Customers - View Detail
# Customers - Edit


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



###FUNCTION TO CREATE CONTACTS IN SYNCRO####

function Create-Contact () {

<#
.SYNOPSIS
This function is used to create a new contact in Syncro. 
.DESCRIPTION
The function connects to your Syncro environment and adds a new contact
.EXAMPLE
Create-Contact -SyncroSubDomain $SyncroSubDomain -SyncroAPIKey $SyncroAPIkey -customerID $customerID -name $name -email $email
Adds a new contact with name and email for a customer
.NOTES
NAME: Create-Contact
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    [string]$SyncroSubdomain,
    [string]$SyncroAPIKey,
    [string]$customerID,
    [string]$name,
    [string]$email,
    [string]$notes
)



$NewContact =@{
    customer_id = $customerID
    name = $name
    email = $email
    notes = $notes
    api_key=$SyncroAPIKey
}

$body = (ConvertTo-Json $NewContact)
$url =  "https://$($SyncroSubdomain).syncromsp.com/api/v1/contacts"
$response = Invoke-RestMethod -Uri $url -Method Post -Body $body -ContentType 'application/json'
$response

}

function Update-Contact () {

<#
.SYNOPSIS
This function is used to update a contact record in Syncro. 
.DESCRIPTION
The function connects to your Syncro environment and updates a contact 
.EXAMPLE
Update-Contact -SyncroSubDomain $SyncroSubDomain -SyncroAPIKey $SyncroAPIkey -contactId $customerID -notes $notes
Adds a new contact with name and email for a customer
.NOTES
NAME: Update-Contact
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    [string]$SyncroSubdomain,
    [string]$SyncroAPIKey,
    [string]$contactID,
    [string]$notes
)



$UpdateContact =@{
    notes = $notes
    api_key=$SyncroAPIKey
}

$body = (ConvertTo-Json $UpdateContact)
$url =  "https://$($SyncroSubdomain).syncromsp.com/api/v1/contacts/$($contactID)"
$response = Invoke-RestMethod -Uri $url -Method Put -Body $body -ContentType 'application/json'
$response

}

###GET All contacts in Syncro #######

function Get-Contacts () {

<#
.SYNOPSIS
This function is used to get all contacts that exist in Syncro
.DESCRIPTION
The function connects to your Syncro environment and list all contacts 
.EXAMPLE
Get-Contacts -SyncroSubDomain $SyncroSubDomain -SyncroAPIKey $SyncroAPIkey
Gets All Available Contacts in Syncro
.NOTES
NAME: Get-Contacts
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    [string]$SyncroSubdomain,
    [string]$SyncroAPIKey,
    [string]$customerId,
    [string]$page
)


$url =  "https://$($SyncroSubdomain).syncromsp.com/api/v1/customers/$($customerId)?api_key=$($SyncroAPIKey)&page=$($page)"
$response = Invoke-RestMethod -Uri $url -Method Get -ContentType 'application/json'
$response

}


###Fnd All Syncro Customers##########
Write-Host "Getting All Customers In Syncro"

$page = 1
$totalPageCount = (GetAll-Customers -SyncroSubdomain $SyncroSubdomain -SyncroAPIKey $SyncroAPIKey -page 1).meta.total_pages
$SyncroCustomers  = Do{
   (GetAll-Customers -SyncroSubdomain $SyncroSubdomain -SyncroAPIKey $SyncroAPIKey).customers
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



###Connect to Partner Center to get a list of customers/tenantIDs #########
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
    $Users = (Invoke-RestMethod -Uri 'https://graph.microsoft.com/beta/users' -Headers $Headers -Method Get -ContentType "application/json").value | Select-Object DisplayName, proxyaddresses, AssignedLicenses, userprincipalname
   $customer_id = ($CustomerObj | Where-Object { $_.Domain -eq $domain}).customer_id
   $page = 1
   $totalPageCount = (Get-Contacts -SyncroSubdomain $SyncroSubdomain -SyncroAPIKey $SyncroAPIKey -page 1).meta.total_pages
   $contacts = Do{
   (Get-Contacts -SyncroSubdomain $SyncroSubdomain -SyncroAPIKey $SyncroAPIKey -customerId $customer_id -page $page).customer.contacts
   $page = $page + 1
   }Until ($page -gt $totalPageCount)
   if($customer_id){
   foreach ($user in $Users) {
   $userExist = ($contacts| where-object {$_.email -eq $user.userprincipalName})
         if(!$userExist){
           Write-Host "$($user.DisplayName) doesnt exist in Syncro. Creating New Contact...." -ForegroundColor Green
           Create-Contact -SyncroSubdomain $SyncroSubdomain -SyncroAPIKey $SyncroAPIKey -customerID $customer_id -name $user.DisplayName -email $user.Userprincipalname
        } else {
            Write-Host "$($user.DisplayName) exist in Syncro. Updating Contact...." -ForegroundColor Yellow
            Update-Contact -SyncroSubdomain $SyncroSubdomain -SyncroAPIKey $SyncroAPIKey -contactId $userExist.id
        }
    }
    forEach ($contact in $contacts) {
        if($Users.userprincipalname -notcontains $contact.email){
            Write-Host "$($contact.name) is not in Microsoft. Adding Note of Inactive in Syncro...." -ForegroundColor Red
            Update-Contact -SyncroSubdomain $SyncroSubdomain -SyncroAPIKey $SyncroAPIKey -contactId $contact.id -notes "User doesn't exist in Microsoft"
        }
    }
}
}
