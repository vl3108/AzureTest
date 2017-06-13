#Author: Marcin Pazdzior
[CmdletBinding()]
$ErrorActionPreference = "Continue"

#Variables
$LogPath = 'C:\Salt-AgentInstall.log'
$StartDate = Get-Date
$hostsfile = "$env:windir\System32\drivers\etc\hosts"
$SaltUser = "svc_salt"
$SaltMaster = @("saltmaster1", "saltmaster2")
$SaltExec = "salt-bootstrap.ps1"
$Key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$ConsentPromptBehaviorAdmin_Name = "ConsentPromptBehaviorAdmin"
$PromptOnSecureDesktop_Name = "PromptOnSecureDesktop"
$ConsentPromptBehaviorAdmin_Value = 0 
$PromptOnSecureDesktop_Value = 0
$OShardeningDownloadFile = "https://ocmgmtscripts.blob.core.windows.net/vmconfigurationscripts/TietoOShardeningForAzureWindowsVMs.inf?sv=2016-05-31&ss=b&srt=sco&sp=rl&se=2117-06-09T23:17:40Z&st=2017-06-08T15:17:40Z&spr=https,http&sig=11EgFcOqCQAoNAfrnf717YYSZId4Vz6tIDldZulcV0k%3D"
$ipv4=$NULL

#region Function
#Function to generate password
Function Generate-NewPassword() {
    Param (
        [int]$length=16,
        [string[]]$sourcedata
    )

    For ($loop=1; $loop –le $length; $loop++) {
        $TempPassword+=($sourcedata | Get-Random)
    }
    return $TempPassword
}

#Function to add local user to local group
Function Add-LocalUserToLocalGroup {
     Param(
        [string[]]$LocalGroup,
        [string[]]$LocalUser
     )
    $group = [ADSI]"WinNT://$env:computername/$LocalGroup,group"
    $group.Add("WinNT://$env:computername/$LocalUser,user")
}

#Function create local user account
Function Create-NewLocalUserAccount ($NewLocalUser,$NewLocalUserPassword,$NewLocalUserDecription) {
    $objOu = [ADSI]”WinNT://$env:computername“
    $objUser = $objOU.Create(“User“, $NewLocalUser)
    $objUser.setpassword($NewLocalUserPassword)
    $objUser.UserFlags = 65536
    $objUser.SetInfo()
    $objUser.description = $NewLocalUserDecription
    $objUser.SetInfo()
}

#Function configure security policy for Salt service account
Function Add-AccountToLogonAsAService {
    Param (
        [string[]]$accountToAdd
    )

    #Check if parameter was specified
    if( [string]::IsNullOrEmpty($accountToAdd) ) {
	    return
    }

    #Read account SID
    $sidstr = $null
    try {
	    $ntprincipal = new-object System.Security.Principal.NTAccount "$accountToAdd"
	    $sid = $ntprincipal.Translate([System.Security.Principal.SecurityIdentifier])
	    $sidstr = $sid.Value.ToString()
    } catch {
	    $sidstr = $null
    }

    #Exit if there is no SID
    if( [string]::IsNullOrEmpty($sidstr) ) {
	    Return
    }

    $tmp = [System.IO.Path]::GetTempFileName()

    #Export current Local Security Policy
    secedit.exe /export /cfg $tmp 

    $c = Get-Content -Path $tmp 

    $currentSetting = ""

    foreach($s in $c) {
	    if( $s -like "SeServiceLogonRight*") {
		    $x = $s.split("=",[System.StringSplitOptions]::RemoveEmptyEntries)
		    $currentSetting = $x[1].Trim()
	    }
    }

	    if( [string]::IsNullOrEmpty($currentSetting) ) {
		    $currentSetting = "*$($sidstr)"
	    } else {
		    $currentSetting = "*$($sidstr),$($currentSetting)"
	    }
	
	$outfile = @"
[Unicode] `r`n
Unicode=yes `r`n
[Version] `r`n
signature="`$CHICAGO`$" `r`n
Revision=1 `r`n
[Privilege Rights] `r`n
SeServiceLogonRight = $($currentSetting) `r`n
"@

	$tmp2 = [System.IO.Path]::GetTempFileName()
	#Import new settings to Local Security Policy
	$outfile | Set-Content -Path $tmp2 -Encoding Unicode -Force
	Push-Location (Split-Path $tmp2)
	
	try {
        secedit.exe /configure /db secedit.sdb /cfg $tmp2 /areas USER_RIGHTS 
	} finally {	
		Pop-Location
	}
}

#Function to modify registry used for UAC turn off
Function Set-RegistryValue($key, $name, $value, $type="Dword") {  
  If ((Test-Path -Path $key) -Eq $false) { New-Item -ItemType Directory -Path $key | Out-Null }  
       Set-ItemProperty -Path $key -Name $name -Value $value -Type $type  
}  

#Function download file
Function Get-InstallFile ($Source, $TargetFileName) {
    
    [string]$TmpPath = [System.IO.Path]::GetTempPath()
    if($TmpPath.Length -eq 0) {
        Write-Warning "Unnable to resolve temporary path. Default one is used."
    }else {
        $Temp = $TmpPath
    }

    if(-not (Test-Path $Temp)) {
        Write-Error $([System.String]::Format("Temp path {0} does not exist", $Temp))
        exit 1
    }

    $InstallFile=if ($Temp[-1] -eq '\') { "$Temp$TargetFileName" } else { "$Temp`\$TargetFileName" }
    Write-Host "Downloading to $InstallFile"

    try {
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($Source, $InstallFile)
    } catch [System.Net.WebException],[System.IO.IOException] {  
        write-error $([System.String]::Format("Unable to download from $MediaUrl"))
        exit 3
    } catch {
        write-error $([System.String]::Format("{0}", $_))
        exit 3
    }

    $InstallFile
}
#endregion


#Configure server
    #Initiate logging
    Add-Content $LogPath "***************************************"
    Add-Content $LogPath "Installation started on $StartDate"
    
    #Get server internal IP address
    Add-Content $LogPath "Getting local server IP address"
    $IPAddresses = (gwmi Win32_NetworkAdapterConfiguration | ? { $_.IPAddress -ne $null }).ipaddress
    $ipv4 = $IPAddresses[0]
    if ($ipv4 -eq $NULL) {
        Add-Content $LogPath "This server does not have IP address"
    }
    else {
        #Add SALT IP and names to hosts file
        Add-Content $LogPath "Adding Salt maters IP and names to hosts file"
        "10.240.88.21 " + $SaltMaster[0] | Add-Content $hostsfile
        "10.240.88.22 " + $SaltMaster[1] | Add-Content $hostsfile

        #Check which Salt master is responding
        Add-Content $LogPath "Selecting Salt master to connect"
        $SaltMediaDownloadUrl1 = [System.String]::Format("http://{0}/saltstack/{1}", $SaltMaster[0], $SaltExec)
        $SaltMediaDownloadUrl2 = [System.String]::Format("http://{0}/saltstack/{1}", $SaltMaster[1], $SaltExec)
        if (($SaltMediaDownloadUrlTest = Invoke-WebRequest -Uri $SaltMediaDownloadUrl1 -DisableKeepAlive -UseBasicParsing -Method Head -ErrorAction SilentlyContinue).StatusCode -ne 200) {
            $SaltMediaDownloadUrlTest = Invoke-WebRequest -Uri $SaltMediaDownloadUrl2 -DisableKeepAlive -UseBasicParsing -Method Head -ErrorAction SilentlyContinue
        }

        $OShardeningDownloadFileUrl = Invoke-WebRequest -Uri $OShardeningDownloadFile -DisableKeepAlive -UseBasicParsing -Method Head -ErrorAction SilentlyContinue
        $SaltMediaDownloadUrl = $SaltMediaDownloadUrl1 
    }

try {
    #Prepare set of signs for password generation
    $ascii=$NULL
    For ($a=48;$a –le 122;$a++) {$ascii+=,[char][byte]$a }
    
    If (($ipv4 -ne $NULL) -and ($SaltMediaDownloadUrlTest.StatusCode -eq 200) -and ($OShardeningDownloadFileUrl.StatusCode -eq 200)) {
        Add-Content $LogPath "Connection to installation media is OK. Setup can continue"
        If (!(get-ciminstance win32_useraccount | Select Name -ExpandProperty Name | where name -like $SaltUser -ErrorAction SilentlyContinue)) {
            Add-Content $LogPath "Salt agent is not installed. Setup can continue"
            #Apply Tieto OS hardening to server OS
            Add-Content $LogPath "Applying Tieto OS hardening to server OS"
            $OShardeningConfigFile = Get-InstallFile -Source $OShardeningDownloadFile -TargetFileName TietoOShardeningForAzureWindowsVMs.inf
            #secedit.exe /configure /db secedit.sdb /cfg $OShardeningConfigFile

            #Generate password for Salt service account
            $NewPassword = Generate-NewPassword –length 16 –sourcedata $ascii

            #Create and configure Salt service account
            Add-Content $LogPath "Creating Salt service account"
            Create-NewLocalUserAccount -NewLocalUser $SaltUser -NewLocalUserPassword $NewPassword -NewLocalUserDecription "Tieto automation account"
            Add-LocalUserToLocalGroup -LocalGroup Administrators -LocalUser $SaltUser
            Add-AccountToLogonAsAService -accountToAdd $SaltUser

            #Turn off UAC
            Add-Content $LogPath "Turning off UAC"
            Set-RegistryValue -Key $Key -Name $ConsentPromptBehaviorAdmin_Name -Value $ConsentPromptBehaviorAdmin_Value 
            Set-RegistryValue -Key $Key -Name $PromptOnSecureDesktop_Name -Value $PromptOnSecureDesktop_Value 

            #Download and install Salt client
            Add-Content $LogPath "Installing Salt agent"
            $SaltInstallFile = Get-InstallFile -Source $SaltMediaDownloadUrl -TargetFileName $SaltExec
            &$SaltInstallFile -Master $SaltMaster -MinionID $ipv4 -UserName $SaltUser
        }
        else {
            Add-Content $LogPath "Salt agent is or was already installed. Setup is ending"
        }
    }
    else {
        Add-Content $LogPath "No connection to installation media. Failed to install Salt agent"
    }

$EndDate = Get-Date
Add-Content $LogPath "Setup has ended on $EndDate"
Add-Content $LogPath "***************************************"
}

catch {
    Add-Content $LogPath "Something went wrong. Failed to install Salt agent"
    $EndDate = Get-Date
    Add-Content $LogPath "Setup has ended on $EndDate"
    Add-Content $LogPath "***************************************"
}
