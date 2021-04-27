# Syncro-Documentation

Documenting customer Microsoft 365 environments can be extremely tedious and time consuming. Keeping that information up to date is also a heavy task to manage. I wanted to create some scripts that would automate and update documents in Syncro that are tied to your customer environments. For this reason I created a some scripts that perform the following:
<ul>
 	<li><strong>Microsoft License Information</strong> =&gt; Displays all current licensed and unlicensed users as well as showing what licenses are available vs. consumed</li>
 	<li><strong>Microsoft MFA Status</strong> =&gt; Displays MFA status, Conditional Access Policies, and DUO MFA custom controls</li>
 	<li><strong>Microsoft Exchange Information</strong> =&gt; Displays mailbox usage in GB, last login time, mailflow rules, DKIM Config, and ATP policies</li>
 	<li><strong>Microsoft Intune Information</strong> =&gt; Displays enrolled devices, compliance status, OS version, Autopilot info, encryption, and Assigned Apps</li>
 	<li><strong>Microsoft Contact Creation</strong></span> =&gt; Creates a contact on the customer record in Syncro for Active 365 Users</li>
</ul>
<div>All documentation is listed for the customer and contacts are automatically added or updated to the customer record.</div>
<br>
<a target="_blank" href="/Syncro/pic8.png">
<img src="/Syncro/pic8.png" alt="Download SPPKG file screenshot" style="max-width:100%;">
</a>

<h2>Prerequisites</h2>
You will need to garner tokens and GUIDs from both the Secure Application Model and Syncro. The secure application model allows for a headless connection into all of your customer environments. The script to run that can be found from Kelvin over at CyberDrain. <a href="https://github.com/KelvinTegelaar/SecureAppModel/blob/master/Create-SecureAppModel.ps1">Click here to go to that page in Github.</a>
<br></br>
In Syncro you will need to create a new API Key that has permissions to customers and documentation to perform the necessary read and write actions. <a href="https://help.syncromsp.com/hc/en-us/articles/360048794414-API-Tokens">Click Here for Syncro's Documentation on generating a new API key</a>. The only other variable you will be prompted for is your Syncro subdomain. This is simply just the prefix of the URL you go to when signing in. Ex:
<br></br>
<a target="_blank" href="/Syncro/pic15.png">
<img src="/Syncro/pic15.png" alt="Download SPPKG file screenshot" style="max-width:100%;">
</a>

<h2>Author(s)</h2>
Nick Ross

<h2>Microsoft License Report</h2>

The license report displays all active and consumed licensing as well as all licensed and unlicensed users
<br></br>
<a target="_blank" href="/Syncro/pic6.png">
<img src="/Syncro/pic6.png" alt="Download SPPKG file screenshot" style="max-width:100%;">
</a>
<a target="_blank" href="/Syncro/pic7.png">
<img src="/Syncro/pic7.png" alt="Download SPPKG file screenshot" style="max-width:100%;">
</a>

<h2>Microsoft MFA Status</h2>

This report shows you all users MFA status. Since Microsoft has evolved their MFA registration over time there are now 3 different ways in which a user could have MFA enforced.
<ul>
 	<li>Legacy MFA Portal (where you see Enabled, Enforced, Disabled)</li>
 	<li>Conditional Access Policies</li>
 	<li>Security Defaults</li>
</ul>
For this reason I include two columns that shows if a user has registered with one of these methods (I am able to see Security Defaults and Conditional Access Registration in a combined output). Here I also show the names of all Conditional Access Policies and also an additional filed that shows if you have DUO listed as a custom control in any conditional access policy
<br></br>
<a target="_blank" href="/Syncro/pic9.png">
<img src="/Syncro/pic9.png" alt="Download SPPKG file screenshot" style="max-width:100%;">
</a>
<a target="_blank" href="/Syncro/pic10.png">
<img src="/Syncro/pic10.png" alt="Download SPPKG file screenshot" style="max-width:100%;">
</a>

<h2>Microsoft Exchange Report</h2>
For the exchange report I display mailboxes, active consumption in GB (in a descending order), last login time, mailflow rules, DKIM Configuration, and ATP Settings/Policies
<br></br>
<a target="_blank" href="/Syncro/pic11.png">
<img src="/Syncro/pic11.png" alt="Download SPPKG file screenshot" style="max-width:100%;">
</a>
<a target="_blank" href="/Syncro/pic12.png">
<img src="/Syncro/pic12.png" alt="Download SPPKG file screenshot" style="max-width:100%;">
</a>

<h2>Microsoft Intune Report</h2>
The Intune report displays a summary of device compliance, devices, and all apps that are in an assigned state
<br></br>
<a target="_blank" href="/Syncro/pic13.png">
<img src="/Syncro/pic13.png" alt="Download SPPKG file screenshot" style="max-width:100%;">
</a>

<h2>Microsoft Contact Creation</h2>
Microsoft 365 Users are created as contacts for a customer if they do not already exist. If the user is not longer in 365, then a note is added to an existing contact to say that they are no longer active. (Wish there was a flag or something for this in Syncro as it wasn't the best way to show removal of users)
<br></br>
<a target="_blank" href="/Syncro/pic14.png">
<img src="/Syncro/pic14.png" alt="Download SPPKG file screenshot" style="max-width:100%;">
</a>

