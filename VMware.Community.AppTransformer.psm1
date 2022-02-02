Function Connect-AppTransformer {
<#
    .NOTES
    ===========================================================================
    Created by:    William Lam
    Date:          01/14/2022
    Organization:  VMware
    Blog:          http://www.williamlam.com
    Twitter:       @lamw
    ===========================================================================

    .SYNOPSIS
        Connect to Application Transformer for VMware Tanzu API
    .DESCRIPTION
        This cmdlet creates $global:appTransformerConnection object containing the Application Transformer for VMware Tanzu URL along with App Transformer Token
    .EXAMPLE
        $AppTransformerUsername = "FILL_ME_IN"
        $AppTransformerPassword = "FILL_ME_IN"

        [Security.SecureString]$SecurePassword = ConvertTo-SecureString $AppTransformerPassword -AsPlainText
        Connect-AppTransformer -Server at.vmware.corp -Username $AppTransformerUsername -Password $SecurePassword
#>
    Param (
        [Parameter(Mandatory=$true)][String]$Server,
        [Parameter(Mandatory=$true)][String]$Username,
        [Parameter(Mandatory=$true)][Security.SecureString]$Password,
        [Switch]$Troubleshoot
    )

    $requests = Invoke-WebRequest -Uri "https://${Server}/discovery/session" -Method POST -Headers @{"Accept"="application/json";"Content-Type"="application/json"} -Body "{`"username`":`"${Username}`",`"password`":`"$($password | ConvertFrom-SecureString -AsPlainText)`"}" -SkipCertificateCheck
    if($requests.StatusCode -ne 200) {
        Write-Host -ForegroundColor Red "Failed to login to Application Transformer, please verify that your login credentials are correct"
        break
    }
    $token = ($requests | ConvertFrom-Json).token

    $headers = @{
        "Authorization"="Bearer ${token}"
        "Content-Type"="application/json"
        "Accept"="application/json"
    }

    $global:appTransformerConnection = new-object PSObject -Property @{
        'Server' = "https://${Server}/discovery"
        'headers' = $headers
    }
    $global:appTransformerConnection
}

Function New-AppTransformerVCenter {
<#
    .NOTES
    ===========================================================================
    Created by:    William Lam
    Date:          01/14/2022
    Organization:  VMware
    Blog:          http://www.williamlam.com
    Twitter:       @lamw
    ===========================================================================
    .SYNOPSIS
        Register a vCenter Server with Application Transformer
    .DESCRIPTION
        This cmdlet register a vCenter Server with Application Transformer
    .EXAMPLE
        $vcenterAddress = "10.8.224.4"
        $vcenterName = "VMC-vCenter-Server"
        $vcenterCredentialName = "cloudadmin@vmc.local"

        New-AppTransformerVCenter -Address $vcenterAddress -Name $vcenterName -CredentialName $vcenterCredentialName
#>
    Param (
        [Parameter(Mandatory=$true)][String]$Name,
        [Parameter(Mandatory=$true)][String]$Address,
        [Parameter(Mandatory=$true)][String]$CredentialName,
        [Switch]$Troubleshoot
    )

    $vcenterUrl = $global:appTransformerConnection.Server + "/vcenters"
    $method = "POST"

    $credential = Get-AppTransformerCredential -Name $CredentialName

    $json = @{
        fqdn = $Address
        vcName = $Name
        vcServiceAccountUUID = $credential.uuid
        defaultWindowsVMServiceAccountUUID = $null
        defaultLinuxVMServiceAccountUUID = $null
        fullVCShallowScan = $null
    }

    $body = $json | ConvertTo-Json

    if($Troubleshoot) {
        Write-Host -ForegroundColor cyan "`n[DEBUG] - $method`n$vcenterUrl`n"
        Write-Host -ForegroundColor cyan "[DEBUG]`n$body`n"
    }

    try {
        $requests = Invoke-Webrequest -Uri $vcenterUrl -Method $method -UseBasicParsing -Body $body -Headers $global:appTransformerConnection.headers -SkipCertificateCheck
    } catch {
        if($_.Exception.Response.StatusCode -eq "Unauthorized") {
            Write-Host -ForegroundColor Red "`nApplication Transformer session is no longer valid, please re-run the Connect-AppTransformer cmdlet to retrieve a new token`n"
            break
        } else {
            Write-Error "Error in adding vCenter Server"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }
    }

    if($requests.StatusCode -eq 202) {
        Write-Host "`nSuccessfully added vCenter Server $Name ..."
    }
}

Function Get-AppTransformerVCenter {
<#
    .NOTES
    ===========================================================================
    Created by:    William Lam
    Date:          01/14/2022
    Organization:  VMware
    Blog:          http://www.williamlam.com
    Twitter:       @lamw
    ===========================================================================
    .SYNOPSIS
        List all vCenter Servers registered in Application Transformer
    .DESCRIPTION
        This cmdlet lists all vCenter Servers registered in Application Transformer
    .EXAMPLE
        Get-AppTransformerVCenter
    .EXAMPLE
        Get-AppTransformerVCenter -Name <vcenter-name>
#>
    Param (
        [Parameter(Mandatory=$false)][String]$Name,
        [Switch]$Troubleshoot
    )

    if ($PSBoundParameters.ContainsKey("Name")){
        $vcenterUrl = $global:appTransformerConnection.Server + "/vcenters?vcName=${Name}"
    } else {
        $vcenterUrl = $global:appTransformerConnection.Server + "/vcenters"
    }

    $method = "GET"

    if($Troubleshoot) {
        Write-Host -ForegroundColor cyan "`n[DEBUG] - $method`n$directoryUrl`n"
    }

    try {
        $requests = Invoke-Webrequest -Uri $vcenterUrl -Method $method -UseBasicParsing -Headers $global:appTransformerConnection.headers -SkipCertificateCheck
    } catch {
        if($_.Exception.Response.StatusCode -eq "Unauthorized") {
            Write-Host -ForegroundColor Red "`nApplication Transformer session is no longer valid, please re-run the Connect-AppTransformer cmdlet to retrieve a new token`n"
            break
        } else {
            Write-Error "Error in retrieving vCenter Servers"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }
    }

    if($requests.StatusCode -eq 200) {
        $vcenters = (($requests.Content | ConvertFrom-Json)._embedded).vcenters

        $vcenters
    }
}

Function Get-AppTransformerNetworkInsight {
<#
    .NOTES
    ===========================================================================
    Created by:    William Lam
    Date:          01/14/2022
    Organization:  VMware
    Blog:          http://www.williamlam.com
    Twitter:       @lamw
    ===========================================================================
    .SYNOPSIS
        List all vRealize Network Insight instances registered in Application Transformer
    .DESCRIPTION
        This cmdlet lists vRealize Network Insight instances registered in Application Transformer
    .EXAMPLE
        Get-AppTransformerNetworInsight
    .EXAMPLE
        Get-AppTransformerNetworInsight -Name <vcenter-name>
#>
    Param (
        [Parameter(Mandatory=$false)][String]$Name,
        [Switch]$Troubleshoot
    )

    $vrniUrl = $global:appTransformerConnection.Server + "/vrni"
    $method = "GET"

    if($Troubleshoot) {
        Write-Host -ForegroundColor cyan "`n[DEBUG] - $method`n$vrniUrl`n"
    }

    try {
        $requests = Invoke-Webrequest -Uri $vrniUrl -Method $method -UseBasicParsing -Headers $global:appTransformerConnection.headers -SkipCertificateCheck
    } catch {
        if($_.Exception.Response.StatusCode -eq "Unauthorized") {
            Write-Host -ForegroundColor Red "`nApplication Transformer session is no longer valid, please re-run the Connect-AppTransformer cmdlet to retrieve a new token`n"
            break
        } else {
            Write-Error "Error in retrieving vRealize Network Insight instances"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }
    }

    if($requests.StatusCode -eq 200) {
        $vrnis = $requests.Content | ConvertFrom-Json

        $vrnis
    }
}

Function New-AppTransformerNetworkInsightCloud {
<#
    .NOTES
    ===========================================================================
    Created by:    William Lam
    Date:          01/14/2022
    Organization:  VMware
    Blog:          http://www.williamlam.com
    Twitter:       @lamw
    ===========================================================================
    .SYNOPSIS
        Register a vRealize Network Insight Cloud with Application Transformer
    .DESCRIPTION
        This cmdlet register a vRealize Network Insight Cloud with Application Transformer
    .EXAMPLE
        $CSP_TOKEN = "FILL_ME_IN"
        $VCENTER_NAME = "VMC-vCenter-Server"
        New-AppTransformerNetworkInsightCloud -APIToken $CSP_TOKEN -VCenterName $VCENTER_NAME
#>
    Param (
        [Parameter(Mandatory=$true)][String]$APIToken,
        [Parameter(Mandatory=$true)][String]$VCenterName,
        [Switch]$Troubleshoot
    )

    $vrniUrl = $global:appTransformerConnection.Server + "/vrni"
    $method = "POST"

    $vcenter = Get-AppTransformerVCenter -Name $VCenterName

    $json = @{
        ip = "api.mgmt.cloud.vmware.com"
        cspUrl = "console.cloud.vmware.com"
        apiToken = $APIToken
        isSaaS = $true
        vcUuids = @($vcenter.irisVcenterUUID)
    }

    $body = $json | ConvertTo-Json

    if($Troubleshoot) {
        Write-Host -ForegroundColor cyan "`n[DEBUG] - $method`n$vrniUrl`n"
        Write-Host -ForegroundColor cyan "[DEBUG]`n$body`n"
    }

    try {
        $requests = Invoke-Webrequest -Uri $vrniUrl -Method $method -UseBasicParsing -Body $body -Headers $global:appTransformerConnection.headers -SkipCertificateCheck
    } catch {
        if($_.Exception.Response.StatusCode -eq "Unauthorized") {
            Write-Host -ForegroundColor Red "`nApplication Transformer session is no longer valid, please re-run the Connect-AppTransformer cmdlet to retrieve a new token`n"
            break
        } else {
            Write-Error "Error in adding vRealize Network Insight Cloud instance"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }
    }

    if($requests.StatusCode -eq 200) {
        Write-Host "`nSuccessfully added vRealize Network Insight Cloud instance ..."
    }
}

Function Get-AppTransformerCredential {
<#
    .NOTES
    ===========================================================================
    Created by:    William Lam
    Date:          01/14/2022
    Organization:  VMware
    Blog:          http://www.williamlam.com
    Twitter:       @lamw
    ===========================================================================
    .SYNOPSIS
        List all credentials in Application Transformer
    .DESCRIPTION
        This cmdlet lists all credentials in Application Transformer
    .EXAMPLE
        Get-AppTransformerCredential
    .EXAMPLE
        Get-AppTransformerCredential -Name <credential-alias-name>
#>
    Param (
        [Parameter(Mandatory=$false)][String]$Name,
        [Switch]$Troubleshoot
    )

    if ($PSBoundParameters.ContainsKey("Name")){
        $credentialUrl = $global:appTransformerConnection.Server + "/serviceaccounts?alias=${Name}"
    } else {
        $credentialUrl = $global:appTransformerConnection.Server + "/serviceaccounts?size=10"
    }

    $method = "GET"

    if($Troubleshoot) {
        Write-Host -ForegroundColor cyan "`n[DEBUG] - $method`n$credentialUrl`n"
    }

    try {
        $requests = Invoke-Webrequest -Uri $credentialUrl -Method $method -UseBasicParsing -Headers $global:appTransformerConnection.headers -SkipCertificateCheck
    } catch {
        if($_.Exception.Response.StatusCode -eq "Unauthorized") {
            Write-Host -ForegroundColor Red "`nApplication Transformer session is no longer valid, please re-run the Connect-AppTransformer cmdlet to retrieve a new token`n"
            break
        } else {
            Write-Error "Error in retrieving Credentials"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }
    }

    if($requests.StatusCode -eq 200) {
        $baseCredentialUrl = $credentialUrl
        $totalCredntialCount = ($requests.Content | ConvertFrom-Json).page.totalElements

        if($Troubleshoot) {
            Write-Host -ForegroundColor cyan "`n[DEBUG] totalCredntialCount = $totalCredntialCount"
        }
        $totalCredentials= (($requests.Content | ConvertFrom-Json)._embedded).serviceaccounts
        $seenCredentials = $totalCredentials.count

        if($Troubleshoot) {
            Write-Host -ForegroundColor cyan "`n[DEBUG] $credentialUrl (currentCount = $seenCredentials)"
        }

        $pageCount = 0
        while ( $seenCredentials -lt $totalCredntialCount) {
            $pageCount++
            $credentialUrl = $baseCredentialUrl + "&page=$($pageCount)"

            try {
                $requests = Invoke-Webrequest -Uri $credentialUrl -Method $method -UseBasicParsing -Headers $global:appTransformerConnection.headers -SkipCertificateCheck
            } catch {
                if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                    Write-Host -ForegroundColor Red "`nApplication Transformer session is no longer valid, please re-run the Connect-AppTransformer cmdlet to retrieve a new token`n"
                    break
                } else {
                    Write-Error "Error in retrieving Credentials"
                    Write-Error "`n($_.Exception.Message)`n"
                    break
                }
            }
            $credentials = (($requests.Content | ConvertFrom-Json)._embedded).serviceaccounts
            $totalCredentials += $credentials
            $seenCredentials += $totalCredentials.count

            if($Troubleshoot) {
                Write-Host -ForegroundColor cyan "`n[DEBUG] $credentialUrl (currentCount = $seenCredentials)"
            }
        }

        if ($PSBoundParameters.ContainsKey("Name")){
            $totalCredentials = $totalCredentials | where {$_.alias -eq $Name}
        }

        $totalCredentials
    }
}

Function New-AppTransformerCredential {
<#
    .NOTES
    ===========================================================================
    Created by:    William Lam
    Date:          01/14/2022
    Organization:  VMware
    Blog:          http://www.williamlam.com
    Twitter:       @lamw
    ===========================================================================
    .SYNOPSIS
        Creates a new credential in Application Transformer
    .DESCRIPTION
        This cmdlet creates a new credential in Application Transformer
    .EXAMPLE
        $alias = "FILL_ME_IN"
        $username = "FILL_ME_IN"
        $password = "FILL_ME_IN"

        [Security.SecureString]$SecurePassword = ConvertTo-SecureString $Password -AsPlainText
        New-AppTransformerCredential -Alias $alias -Username $username -Password $SecurePassword
#>
    Param (
        [Parameter(Mandatory=$true)][String]$Alias,
        [Parameter(Mandatory=$true)][String]$Username,
        [Parameter(Mandatory=$true)][Security.SecureString]$Password,
        [Switch]$Troubleshoot
    )

    $credentialUrl = $global:appTransformerConnection.Server + "/serviceaccounts"
    $method = "POST"

    $json = @{
        alias = $Alias
        username = $Username
        password = $($password | ConvertFrom-SecureString -AsPlainText)
    }

    $body = $json | ConvertTo-Json

    if($Troubleshoot) {
        Write-Host -ForegroundColor cyan "`n[DEBUG] - $method`n$credentialUrl`n"
        Write-Host -ForegroundColor cyan "[DEBUG]`n$body`n"
    }

    try {
        $requests = Invoke-Webrequest -Uri $credentialUrl -Method $method -UseBasicParsing -Headers $global:appTransformerConnection.headers -Body $body -SkipCertificateCheck
    } catch {
        if($_.Exception.Response.StatusCode -eq "Unauthorized") {
            Write-Host -ForegroundColor Red "`nApplication Transformer session is no longer valid, please re-run the Connect-AppTransformer cmdlet to retrieve a new token`n"
            break
        } else {
            Write-Error "Error in creating new credential"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }
    }

    if($requests.StatusCode -eq 200) {
        Write-Host "`nSuccessfully created credential $Alias ..."
    }
}

Function Remove-AppTransformerCredential {
<#
    .NOTES
    ===========================================================================
    Created by:    William Lam
    Date:          01/14/2022
    Organization:  VMware
    Blog:          http://www.williamlam.com
    Twitter:       @lamw
    ===========================================================================
    .SYNOPSIS
        Deletes a specific credential from Application Transformer
    .DESCRIPTION
        This cmdlet deletes a specific credential from Application Transformer
    .EXAMPLE
        Remove-AppTransformerCredential -Name <credential-alias>
#>
    Param (
        [Parameter(Mandatory=$true)][String]$Name,
        [Switch]$Troubleshoot
    )

    $credential = Get-AppTransformerCredential -Name $Name

    if($credential) {
        $credentialUrl = $global:appTransformerConnection.Server + "/serviceaccounts/$($credential.uuid)"
        $method = "DELETE"

        if($Troubleshoot) {
            Write-Host -ForegroundColor cyan "`n[DEBUG] - $method`n$credentialUrl`n"
        }

        try {
            $requests = Invoke-Webrequest -Uri $credentialUrl -Method $method -UseBasicParsing -Headers $global:appTransformerConnection.headers -SkipCertificateCheck
        } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nApplication Transformer session is no longer valid, please re-run the Connect-AppTransformer cmdlet to retrieve a new token`n"
                break
            } else {
                Write-Error "Error in deleting credential"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
        }

        if($requests.StatusCode -eq 200) {
            Write-Host "`nSuccessfully deleted credential $Name ..."
        }
    } else {
        Write-Host "`nUnable to find credential $Name"
    }
}

Function Get-AppTransformerVM {
<#
    .NOTES
    ===========================================================================
    Created by:    William Lam
    Date:          01/14/2022
    Organization:  VMware
    Blog:          http://www.williamlam.com
    Twitter:       @lamw
    ===========================================================================
    .SYNOPSIS
        List all Virtual Machines discovered by Application Transformer
    .DESCRIPTION
        This cmdlet lists all Virtual Machines discovered by Application Transformer
    .EXAMPLE
        Get-AppTransformerVM
    .EXAMPLE
        Get-AppTransformerVM -Name <vm-name>
#>
    Param (
        [Parameter(Mandatory=$false)][String]$Name,
        [Switch]$Troubleshoot
    )

    if ($PSBoundParameters.ContainsKey("Name")){
        $vmUrl = $global:appTransformerConnection.Server + "/virtualmachines?name=${Name}"
    } else {
        $vmUrl = $global:appTransformerConnection.Server + "/virtualmachines?size=10"
    }

    $method = "GET"

    if($Troubleshoot) {
        Write-Host -ForegroundColor cyan "`n[DEBUG] - $method`n$vmUrl`n"
    }

    try {
        $requests = Invoke-Webrequest -Uri $vmUrl -Method $method -UseBasicParsing -Headers $global:appTransformerConnection.headers -SkipCertificateCheck
    } catch {
        if($_.Exception.Response.StatusCode -eq "Unauthorized") {
            Write-Host -ForegroundColor Red "`nApplication Transformer session is no longer valid, please re-run the Connect-AppTransformer cmdlet to retrieve a new token`n"
            break
        } else {
            Write-Error "Error in retrieving Virtual Machines"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }
    }

    if($requests.StatusCode -eq 200) {
        $baseVmUrl = $vmUrl
        $totalVmCount = ($requests.Content | ConvertFrom-Json).page.totalElements

        if($Troubleshoot) {
            Write-Host -ForegroundColor cyan "`n[DEBUG] totalVmCount = $totalVmCount"
        }
        $totalVms= (($requests.Content | ConvertFrom-Json)._embedded).virtualmachines
        $seenVms = $totalVms.count

        if($Troubleshoot) {
            Write-Host -ForegroundColor cyan "`n[DEBUG] $vmUrl (currentCount = $seenVms)"
        }

        $pageCount = 0
        while ( $seenVms -lt $totalVmCount) {
            $pageCount++
            $vmUrl = $baseVmUrl + "&page=$($pageCount)"

            try {
                $requests = Invoke-Webrequest -Uri $vmUrl -Method $method -UseBasicParsing -Headers $global:appTransformerConnection.headers -SkipCertificateCheck
            } catch {
                if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                    Write-Host -ForegroundColor Red "`nApplication Transformer session is no longer valid, please re-run the Connect-AppTransformer cmdlet to retrieve a new token`n"
                    break
                } else {
                    Write-Error "Error in retrieving Virtual Machines"
                    Write-Error "`n($_.Exception.Message)`n"
                    break
                }
            }
            $vms = (($requests.Content | ConvertFrom-Json)._embedded).virtualmachines
            $totalVms += $vms
            $seenVms += $totalVms.count

            if($Troubleshoot) {
                Write-Host -ForegroundColor cyan "`n[DEBUG] $vmUrl (currentCount = $seenVms)"
            }
        }

        if ($PSBoundParameters.ContainsKey("Name")){
            $totalVms = $totalVms | where {$_.name -eq $Name}
        }

        $totalVms
    }
}

Function New-AppTransformerCredentialAssociation {
<#
    .NOTES
    ===========================================================================
    Created by:    William Lam
    Date:          01/14/2022
    Organization:  VMware
    Blog:          http://www.williamlam.com
    Twitter:       @lamw
    ===========================================================================
    .SYNOPSIS
        Associate a credential with a set of VM(s) in Application Transformer
    .DESCRIPTION
        This cmdlet associate a credential with a set of VM(s) in Application Transformer
    .EXAMPLE
        $SimpleVMCredentialName = "root-simple"
        $SimpleVMs = ("tomcat-vm","tomcat_centos7")

        New-AppTransformerCredentialAssociation -CredentialName $SimpleVMCredentialName -VMNames $SimpleVMs
#>
    Param (
        [Parameter(Mandatory=$true)][String]$CredentialName,
        [Parameter(Mandatory=$true)][String[]]$VMNames,
        [Switch]$Troubleshoot
    )

    $credential = Get-AppTransformerCredential -Name $CredentialName

    $credentialUrl = $global:appTransformerConnection.Server + "/serviceaccounts/$($credential.uuid)/virtualmachines"
    $method = "PUT"

    $vms = @()
    foreach ($VMName in $VMNames) {
        $vm = Get-AppTransformerVM -Name $VMName
        $tmp = @{
            uuid = $vm.id
            name = $vm.name
        }
        $vms += $tmp
    }

    $json = @{
        "virtualmachines" = $vms
    }

    $body = $json | ConvertTo-Json -Depth 2

    if($Troubleshoot) {
        Write-Host -ForegroundColor cyan "`n[DEBUG] - $method`n$credentialUrl`n"
        Write-Host -ForegroundColor cyan "[DEBUG]`n$body`n"
    }

    try {
        $requests = Invoke-Webrequest -Uri $credentialUrl -Method $method -UseBasicParsing -Headers $global:appTransformerConnection.headers -Body $body -SkipCertificateCheck
    } catch {
        if($_.Exception.Response.StatusCode -eq "Unauthorized") {
            Write-Host -ForegroundColor Red "`nApplication Transformer session is no longer valid, please re-run the Connect-AppTransformer cmdlet to retrieve a new token`n"
            break
        } else {
            Write-Error "Error in associating credentials to VMs"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }
    }

    if($requests.StatusCode -eq 200) {
        Write-Host "`nSuccessfully associated credential $CredentialName with VMs $(${VMNames} -join ",") ..."
    }
}

Function Start-AppTransformerIntrospection {
<#
    .NOTES
    ===========================================================================
    Created by:    William Lam
    Date:          01/14/2022
    Organization:  VMware
    Blog:          http://www.williamlam.com
    Twitter:       @lamw
    ===========================================================================
    .SYNOPSIS
        Performs an Introspection operation on a set of VM(s) Application Transformer
    .DESCRIPTION
        This cmdlet performs an Introspection operation on a set of VM(s) Application Transformer
    .EXAMPLE
        New-AppTransformerCredentialAssocation -Credential "root-simple" -VMNames @("tomcat-vm","tomcat_centos7")
#>
    Param (
        [Parameter(Mandatory=$true)][String]$VMName,
        [Switch]$Troubleshoot
    )

    $vm = Get-AppTransformerVM -Name $VMName

    $vmUrl = $global:appTransformerConnection.Server + "/virtualmachines/$($vm.id)/components"
    $method = "POST"

    if($Troubleshoot) {
        Write-Host -ForegroundColor cyan "`n[DEBUG] - $method`n$vmUrl`n"
    }

    try {
        $requests = Invoke-Webrequest -Uri $vmUrl -Method $method -UseBasicParsing -Headers $global:appTransformerConnection.headers -SkipCertificateCheck
    } catch {
        if($_.Exception.Response.StatusCode -eq "Unauthorized") {
            Write-Host -ForegroundColor Red "`nApplication Transformer session is no longer valid, please re-run the Connect-AppTransformer cmdlet to retrieve a new token`n"
            break
        } else {
            Write-Error "Error in introspecting VM $VMName, likely maximum introspection tasks in flight, please try again"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }
    }

    if($requests.StatusCode -eq 202) {
        Write-Host "`nSuccessfully started intropsection operation on VM $VMName ..."
    }
}

Function Get-AppTransformerApplication {
<#
    .NOTES
    ===========================================================================
    Created by:    William Lam
    Date:          01/14/2022
    Organization:  VMware
    Blog:          http://www.williamlam.com
    Twitter:       @lamw
    ===========================================================================
    .SYNOPSIS
        List all Applications created and/or discovered in Application Transformer
    .DESCRIPTION
        This cmdlet list all Applications created and/or discovered in Application Transformer
    .EXAMPLE
        Get-AppTransformerApplication
    .EXAMPLE
        Get-AppTransformerApplication -Name <app-name>
#>
    Param (
        [Parameter(Mandatory=$false)][String]$Name,
        [Switch]$Troubleshoot
    )

    $applicationUrl = $global:appTransformerConnection.Server + "/applications?size=10"
    $method = "GET"

    if($Troubleshoot) {
        Write-Host -ForegroundColor cyan "`n[DEBUG] - $method`n$applicationUrl`n"
    }

    try {
        $requests = Invoke-Webrequest -Uri $applicationUrl -Method $method -UseBasicParsing -Headers $global:appTransformerConnection.headers -SkipCertificateCheck
    } catch {
        if($_.Exception.Response.StatusCode -eq "Unauthorized") {
            Write-Host -ForegroundColor Red "`nApplication Transformer session is no longer valid, please re-run the Connect-AppTransformer cmdlet to retrieve a new token`n"
            break
        } else {
            Write-Error "Error in retrieving Application"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }
    }

    if($requests.StatusCode -eq 200) {
        $baseApplicationUrl = $applicationUrl
        $totalApplicationCount = ($requests.Content | ConvertFrom-Json).page.totalElements

        if($Troubleshoot) {
            Write-Host -ForegroundColor cyan "`n[DEBUG] totalApplicationCount = $totalApplicationCount"
        }
        $totalApplications = (($requests.Content | ConvertFrom-Json)._embedded).applications
        $seenApplications = $totalApplications.count

        if($Troubleshoot) {
            Write-Host -ForegroundColor cyan "`n[DEBUG] $applicationUrl (currentCount = $seenApplications)"
        }

        $pageCount = 0
        while ( $seenApplications -lt $totalApplicationCount) {
            $pageCount++
            $applicationUrl = $baseApplicationUrl + "&page=$($pageCount)"

            try {
                $requests = Invoke-Webrequest -Uri $applicationUrl -Method $method -UseBasicParsing -Headers $global:appTransformerConnection.headers -SkipCertificateCheck
            } catch {
                if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                    Write-Host -ForegroundColor Red "`nApplication Transformer session is no longer valid, please re-run the Connect-AppTransformer cmdlet to retrieve a new token`n"
                    break
                } else {
                    Write-Error "Error in retrieving Applications"
                    Write-Error "`n($_.Exception.Message)`n"
                    break
                }
            }
            $applications = (($requests.Content | ConvertFrom-Json)._embedded).applications
            $totalApplications += $applications
            $seenApplications += $applications.count

            if($Troubleshoot) {
                Write-Host -ForegroundColor cyan "`n[DEBUG] $applicationUrl (currentCount = $seenApplications)"
            }
        }

        if ($PSBoundParameters.ContainsKey("Name")){
            $totalApplications = $totalApplications | where {$_.name -eq $Name}
        }

        $totalApplications
    }
}

Function Get-AppTransformerComponent {
<#
    .NOTES
    ===========================================================================
    Created by:    William Lam
    Date:          01/14/2022
    Organization:  VMware
    Blog:          http://www.williamlam.com
    Twitter:       @lamw
    ===========================================================================
    .SYNOPSIS
        List all Components discovered by Application Transformer
    .DESCRIPTION
        This cmdlet lists all Components discovered by Application Transformer
    .EXAMPLE
        Get-AppTransformerComponent
    .EXAMPLE
        Get-AppTransformerComponent -Name <component-name>
#>
    Param (
        [Parameter(Mandatory=$false)][String]$Name,
        [Switch]$Troubleshoot
    )

    $componentUrl = $global:appTransformerConnection.Server + "/components?size=10"
    $method = "GET"

    if($Troubleshoot) {
        Write-Host -ForegroundColor cyan "`n[DEBUG] - $method`n$componentUrl`n"
    }

    try {
        $requests = Invoke-Webrequest -Uri $componentUrl -Method $method -UseBasicParsing -Headers $global:appTransformerConnection.headers -SkipCertificateCheck
    } catch {
        if($_.Exception.Response.StatusCode -eq "Unauthorized") {
            Write-Host -ForegroundColor Red "`nApplication Transformer session is no longer valid, please re-run the Connect-AppTransformer cmdlet to retrieve a new token`n"
            break
        } else {
            Write-Error "Error in retrieving Components"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }
    }

    if($requests.StatusCode -eq 200) {
        $baseComponentUrl = $componentUrl
        $totalComponentCount = ($requests.Content | ConvertFrom-Json).page.totalElements

        if($Troubleshoot) {
            Write-Host -ForegroundColor cyan "`n[DEBUG] totalComponentCount = $totalComponentCount"
        }
        $totalComponents = (($requests.Content | ConvertFrom-Json)._embedded).components
        $seenComponents = $totalComponents.count

        if($Troubleshoot) {
            Write-Host -ForegroundColor cyan "`n[DEBUG] $componentUrl (currentCount = $seenComponents)"
        }

        $pageCount = 0
        while ( $seenComponents -lt $totalComponentCount) {
            $pageCount++
            $componentUrl = $baseComponentUrl + "&page=$($pageCount)"

            try {
                $requests = Invoke-Webrequest -Uri $componentUrl -Method $method -UseBasicParsing -Headers $global:appTransformerConnection.headers -SkipCertificateCheck
            } catch {
                if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                    Write-Host -ForegroundColor Red "`nApplication Transformer session is no longer valid, please re-run the Connect-AppTransformer cmdlet to retrieve a new token`n"
                    break
                } else {
                    Write-Error "Error in retrieving Components"
                    Write-Error "`n($_.Exception.Message)`n"
                    break
                }
            }
            $components = (($requests.Content | ConvertFrom-Json)._embedded).components
            $totalComponents += $components
            $seenComponents += $components.count

            if($Troubleshoot) {
                Write-Host -ForegroundColor cyan "`n[DEBUG] $componentUrl (currentCount = $seenComponents)"
            }
        }

        if ($PSBoundParameters.ContainsKey("Name")){
            $totalComponents = $totalComponents | where {$_.compName -eq $Name}
        }

        $totalComponents
    }
}

Function Get-AppTransformerComponentSignature {
<#
    .NOTES
    ===========================================================================
    Created by:    William Lam
    Date:          01/14/2022
    Organization:  VMware
    Blog:          http://www.williamlam.com
    Twitter:       @lamw
    ===========================================================================
    .SYNOPSIS
        List all Component signatures defined in Application Transformer
    .DESCRIPTION
        This cmdlet lists all Component signatures defined in Application Transformer
    .EXAMPLE
        Get-AppTransformerComponentSignature
    .EXAMPLE
        Get-AppTransformerComponentSignature -Name <component-signature-name>
#>
    Param (
        [Parameter(Mandatory=$false)][String]$Name,
        [Switch]$Troubleshoot
    )

    $componentSignatureUrl = $global:appTransformerConnection.Server + "/component-list"
    $method = "GET"

    if($Troubleshoot) {
        Write-Host -ForegroundColor cyan "`n[DEBUG] - $method`n$vmUrl`n"
    }

    try {
        $requests = Invoke-Webrequest -Uri $componentSignatureUrl -Method $method -UseBasicParsing -Headers $global:appTransformerConnection.headers -SkipCertificateCheck
    } catch {
        if($_.Exception.Response.StatusCode -eq "Unauthorized") {
            Write-Host -ForegroundColor Red "`nApplication Transformer session is no longer valid, please re-run the Connect-AppTransformer cmdlet to retrieve a new token`n"
            break
        } else {
            Write-Error "Error in retrieving Component Signatures"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }
    }

    if($requests.StatusCode -eq 200) {
        $componentSignatureList = ($requests.Content | ConvertFrom-Json)

        $componentSignatures = @()
        foreach ($signature in ($componentSignatureList|Get-Member -MemberType NoteProperty).Name) {
            $componentSignatures+=$componentSignatureList.${signature}
        }

        if ($PSBoundParameters.ContainsKey("Name")){
            $componentSignatures = $componentSignatures | where {$_.userFriendlyName -eq $Name}
        }

        $componentSignatures
    }
}