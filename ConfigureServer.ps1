﻿#Author: Marcin Pazdzior
$StartDate = Get-Date
$Key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$ConsentPromptBehaviorAdmin_Name = "ConsentPromptBehaviorAdmin"
$PromptOnSecureDesktop_Name = "PromptOnSecureDesktop"
$ConsentPromptBehaviorAdmin_Value = 0 
$PromptOnSecureDesktop_Value = 0
#Function to generate password
    $objUser = $objOU.Create(“User“, $NewLocalUser)
    $objUser.setpassword($NewLocalUserPassword)
    $objUser.UserFlags = 65536
    $objUser.SetInfo()
    $objUser.description = $NewLocalUserDecription
    $objUser.SetInfo()
}
  If ((Test-Path -Path $key) -Eq $false) { New-Item -ItemType Directory -Path $key | Out-Null }  
       Set-ItemProperty -Path $key -Name $name -Value $value -Type $type  
}  
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
    Add-Content $LogPath "***************************************"
    Add-Content $LogPath "Installation started on $StartDate"
    Add-Content $LogPath "Getting local server IP address"
    $IPAddresses = (gwmi Win32_NetworkAdapterConfiguration | ? { $_.IPAddress -ne $null }).ipaddress
        "10.240.88.22 " + $SaltMaster[1] | Add-Content $hostsfile
    
            Set-RegistryValue -Key $Key -Name $PromptOnSecureDesktop_Name -Value $PromptOnSecureDesktop_Value 