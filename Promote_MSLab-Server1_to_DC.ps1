##Load LabConfig....
        . "$PSScriptRoot\LabConfig.ps1"

##Load 3_Deploy.ps1....
        #. "$PSScriptRoot\3_Deploy.ps1"

# Get-VM | Where-Object { $_.Name -match 'DC\d+' } | Select-Object -ExpandProperty Name
# Get-VM | Where-Object { $_.Name -match "$($LabConfig.Prefix)-?DC\d+" } | ForEach-Object {
#    Start-VM $_
# }

#region Set variables

    If (!$LabConfig.DomainNetbiosName){
        $LabConfig.DomainNetbiosName="Corp"
    }

    If (!$LabConfig.DomainName){
        $LabConfig.DomainName="Corp.contoso.com"
    }

    If (!$LabConfig.DefaultOUName){
        $LabConfig.DefaultOUName="Workshop"
    }

    if (!$Labconfig.AllowedVLANs){
        $Labconfig.AllowedVLANs="1-10"
    }

    $DN=$null
    $LabConfig.DomainName.Split(".") | ForEach-Object {
        $DN+="DC=$_,"
    }
    $LabConfig.DN=$DN.TrimEnd(",")

    $global:IP=1

    if (!$LabConfig.Prefix){
        $labconfig.prefix="$($PSScriptRoot | Split-Path -Leaf)-"
    }

    if (!$LabConfig.SwitchName){
        $LabConfig.SwitchName = 'LabSwitch'
    }

    $SwitchName=($labconfig.prefix+$LabConfig.SwitchName)

    $LABfolder="$PSScriptRoot\LAB"

    $LABfolderDrivePath=$LABfolder.Substring(0,3)

    $ExternalSwitchName="$($Labconfig.Prefix)$($LabConfig.Switchname)-External"

    #Grab TimeZone
    $TimeZone=(Get-TimeZone).id

#endregion

#$adminUsername = $LabConfig.DomainAdminName
#$adminUsername = 'corp.contoso.com\LabAdmin'
#$adminPassword = $LabConfig.AdminPassword
#$adminPassword = 'LS1setup!'

$VMNames =  Get-VM | Where-Object { $_.Name -match 'DC\d+' } | Select-Object -ExpandProperty Name
$VMGuid = (Get-VM -Name $VMNames).Id

#$securePassword = ConvertTo-SecureString $LabConfig.AdminPassword -AsPlainText -Force
#$credentials = New-Object System.Management.Automation.PSCredential ($LabConfig.DomainAdminName, $securePassword)


#Credentials for Session
        #$username = "$($Labconfig.DomainNetbiosName)\Administrator"
        $username = "$($Labconfig.DomainNetbiosName)\$($LabConfig.DomainAdminName)"
        #$password = $LabConfig.AdminPassword
        $password = "LS1setup!"
        $secstr = New-Object -TypeName System.Security.SecureString
        $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
        $credPSDC = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr

$passwordPlain = $LabConfig.AdminPassword
$securePassword = ConvertTo-SecureString $passwordPlain -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ($username, $securePassword)

$session = New-PSSession -VMGuid $VMGuid -Credential $credPSDC
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $LabConfig.DomainAdminName, $secstr
$dsrmPassword = ConvertTo-SecureString -String "MySuperSecurePassword!!!" -AsPlainText -Force


# Run the commands within the VM via PowerShell Direct
Invoke-Command -Session $session -ScriptBlock {
#Invoke-Command -VMGuid $VMGuid -Credential (New-Object System.Management.Automation.PSCredential ($adminUsername, $adminPassword)) -ScriptBlock {
    # Rename the Computer (Optional)
    # Rename-Computer -NewName 'DC2'

    # Install Necessary Roles and Features
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

    # Promote to Domain Controller
    Install-ADDSDomainController `
        -SkipPreChecks:$false `
        -NoGlobalCatalog:$false `
        -CreateDnsDelegation:$false `
        -Credential $using:credential `
        -SafeModeAdministratorPassword $using:dsrmPassword `
        -CriticalReplicationOnly:$false `
        -DomainName $using:LabConfig.DomainName `
        -InstallDns:$true `
        -NoRebootOnCompletion:$false `
        -LogPath "C:\Windows\NTDS" `
        -SysvolPath "C:\Windows\SYSVOL" `
        -DatabasePath "C:\Windows\NTDS" `
        -Force:$true
    
    #Reboot VM
    #Restart-Computer -Force
    
}

# Clean up and close the session
Remove-PSSession -Session $session
