# Verify Running as Admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
If (-not $isAdmin) {
    Write-Host "-- Restarting as Administrator" -ForegroundColor Cyan ; Start-Sleep -Seconds 1

    if($PSVersionTable.PSEdition -eq "Core") {
        Start-Process pwsh.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs 
    } else {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs 
    }
    
    exit
}

# Skipping 10 lines because if running when all prereqs met, statusbar covers powershell output
1..10 | ForEach-Object { Write-Host "" }

#region Functions
#region Output logging
function WriteInfo($message) {
    Write-Host $message
}

function WriteInfoHighlighted($message) {
    Write-Host $message -ForegroundColor Cyan
}

function WriteSuccess($message) {
    Write-Host $message -ForegroundColor Green
}

function WriteError($message) {
    Write-Host $message -ForegroundColor Red
}

function WriteErrorAndExit($message) {
    Write-Host $message -ForegroundColor Red
    Write-Host "Press enter to continue ..."
    Stop-Transcript
    Read-Host | Out-Null
    Exit
}
#endregion

#region Telemetry
Function Merge-Hashtables {
    $Output = @{}
    ForEach ($Hashtable in ($Input + $Args)) {
        If ($Hashtable -is [Hashtable]) {
            ForEach ($Key in $Hashtable.Keys) {$Output.$Key = $Hashtable.$Key}
        }
    }
    $Output
}
function Get-StringHash {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline, Mandatory = $true)]
        [string]$String,
        $Hash = "SHA1"
    )
    
    process {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($String)
        $algorithm = [System.Security.Cryptography.HashAlgorithm]::Create($Hash)
        $StringBuilder = New-Object System.Text.StringBuilder 
      
        $algorithm.ComputeHash($bytes) | 
        ForEach-Object { 
            $null = $StringBuilder.Append($_.ToString("x2")) 
        } 
      
        $StringBuilder.ToString() 
    }
}

function Get-VolumePhysicalDisk {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Volume
    )

    process {
        if(-not $Volume.EndsWith(":")) {
            $Volume += ":"
        }

        $physicalDisks = Get-cimInstance "win32_diskdrive"
        foreach($disk in $physicalDisks) {
            $partitions = Get-cimInstance -Query "ASSOCIATORS OF {Win32_DiskDrive.DeviceID=`"$($disk.DeviceID.replace('\','\\'))`"} WHERE AssocClass = Win32_DiskDriveToDiskPartition"
            foreach($partition in $partitions) {
                $partitionVolumes = Get-cimInstance -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID=`"$($partition.DeviceID)`"} WHERE AssocClass = Win32_LogicalDiskToPartition"
                foreach($partitionVolume in $partitionVolumes) {
                    if($partitionVolume.Name -eq $Volume) {
                        $physicalDisk = Get-PhysicalDisk | Where-Object DeviceID -eq $disk.Index
                        return $physicalDisk
                    }
                }
            }
        }
    }
}

function Get-TelemetryLevel {
    param(
        [switch]$OptOut
    )
    process {
        $acceptedTelemetryLevels = "None", "Basic", "Full"

        # LabConfig value has a priority
        if($LabConfig.TelemetryLevel -and $LabConfig.TelemetryLevel -in $acceptedTelemetryLevels) {
            return $LabConfig.TelemetryLevel
        }

        # Environment variable as a fallback
        if($env:MSLAB_TELEMETRY_LEVEL -and $env:MSLAB_TELEMETRY_LEVEL -in $acceptedTelemetryLevels) {
            return $env:MSLAB_TELEMETRY_LEVEL
        }

        # If nothing is explicitely configured and OptOut flag enabled, explicitely disable telemetry
        if($OptOut) {
            return "None"
        }

        # as a last option return nothing to allow asking the user
    }
}

function Get-TelemetryLevelSource {
    param(
        [switch]$OptOut
    )
    process {
        $acceptedTelemetryLevels = "None", "Basic", "Full"

        # Is it set interactively?
        if($LabConfig.ContainsKey("TelemetryLevelSource")) {
            return $LabConfig.TelemetryLevelSource
        }

        # LabConfig value has a priority
        if($LabConfig.TelemetryLevel -and $LabConfig.TelemetryLevel -in $acceptedTelemetryLevels) {
            return "LabConfig"
        }

        # Environment variable as a fallback
        if($env:MSLAB_TELEMETRY_LEVEL -and $env:MSLAB_TELEMETRY_LEVEL -in $acceptedTelemetryLevels) {
            return "Environment"
        }
    }
}

function Get-PcSystemType {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Id
    )
    process {
        $type = switch($Id) {
            1 { "Desktop" }
            2 { "Laptop" }
            3 { "Workstation" }
            4 { "Server" }
            7 { "Server" }
            5 { "Server" }
            default { $Id }
        }

        $type
    }
}

$aiPropertyCache = @{}

function New-TelemetryEvent {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Event,
        $Properties,
        $Metrics,
        $NickName
    )

    process {
        if(-not $TelemetryInstrumentationKey) {
            WriteInfo "Instrumentation key is required to send telemetry data."
            return
        }
        
        $level = Get-TelemetryLevel
        $levelSource = Get-TelemetryLevelSource

        $r = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        $build = "$($r.CurrentMajorVersionNumber).$($r.CurrentMinorVersionNumber).$($r.CurrentBuildNumber).$($r.UBR)"
        $osVersion = "$($r.ProductName) ($build)"
        $hw = Get-CimInstance -ClassName Win32_ComputerSystem
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $machineHash = (((Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Cryptography).MachineGuid) | Get-StringHash)

        if(-not $NickName) {
            $NickName = "?"
        }

        $osType = switch ($os.ProductType) {
            1 { "Workstation" }
            default { "Server" }
        }

        $extraMetrics = @{}
        $extraProperties = @{
            'telemetry.level' = $level
            'telemetry.levelSource' = $levelSource
            'telemetry.nick' = $NickName
            'powershell.edition' = $PSVersionTable.PSEdition
            'powershell.version' = $PSVersionTable.PSVersion.ToString()
            'host.isAzure' = (Get-CimInstance win32_systemenclosure).SMBIOSAssetTag -eq "7783-7084-3265-9085-8269-3286-77"
            'host.os.type' = $osType
            'host.os.build' = $r.CurrentBuildNumber
            'hw.type' = Get-PcSystemType -Id $hw.PCSystemType
        }
        if($level -eq "Full") {
            # OS
            $extraProperties.'device.locale' = (Get-WinsystemLocale).Name

            # RAM
            $extraMetrics.'memory.total' = [Math]::Round(($hw.TotalPhysicalMemory)/1024KB, 0)
            
            # CPU
            $extraMetrics.'cpu.logical.count' = $hw.NumberOfLogicalProcessors
            $extraMetrics.'cpu.sockets.count' = $hw.NumberOfProcessors

            if(-not $aiPropertyCache.ContainsKey("cpu.model")) {
                $aiPropertyCache["cpu.model"] = (Get-CimInstance "Win32_Processor" | Select-Object -First 1).Name
            }
            $extraProperties.'cpu.model' = $aiPropertyCache["cpu.model"]

            # Disk
            $driveLetter = $ScriptRoot -Split ":" | Select-Object -First 1
            $volume = Get-Volume -DriveLetter $driveLetter
            $disk = Get-VolumePhysicalDisk -Volume $driveLetter
            $extraMetrics.'volume.size' = [Math]::Round($volume.Size / 1024MB)
            $extraProperties.'volume.fs' = $volume.FileSystemType
            $extraProperties.'disk.type' = $disk.MediaType
            $extraProperties.'disk.busType' = $disk.BusType
        }

        $payload = @{
            name = "Microsoft.ApplicationInsights.Event"
            time = $([System.dateTime]::UtcNow.ToString("o")) 
            iKey = $TelemetryInstrumentationKey
            tags = @{ 
                "ai.internal.sdkVersion" = 'mslab-telemetry:1.0.2'
                "ai.application.ver" = $mslabVersion
                "ai.cloud.role" = Split-Path -Path $PSCommandPath -Leaf
                "ai.session.id" = $TelemetrySessionId
                "ai.user.id" = $machineHash
                "ai.device.id" = $machineHash
                "ai.device.type" = $extraProperties["hw.type"]
                "ai.device.locale" = "" # not propagated anymore
                "ai.device.os" = ""
                "ai.device.osVersion" = ""
                "ai.device.oemName" = ""
                "ai.device.model" = ""
            }
            data = @{
                baseType = "EventData"
                baseData = @{
                    ver = 2 
                    name = $Event
                    properties = ($Properties, $extraProperties | Merge-Hashtables)
                    measurements = ($Metrics, $extraMetrics | Merge-Hashtables)
                }
            }
        }

        if($level -eq "Full") {
            $payload.tags.'ai.device.os' = $osVersion
            $payload.tags.'ai.device.osVersion' = $build
        }
    
        $payload
    }
}

function Send-TelemetryObject {
    param(
        [Parameter(Mandatory = $true)]
        [array]$Data
    )

    process {
        $json = "{0}" -f (($Data) | ConvertTo-Json -Depth 10 -Compress)

        if($LabConfig.ContainsKey('TelemetryDebugLog')) {
            Add-Content -Path "$ScriptRoot\Telemetry.log" -Value ((Get-Date -Format "s") + "`n" + $json)
        }

        try {
            $response = Invoke-RestMethod -Uri 'https://dc.services.visualstudio.com/v2/track' -Method Post -UseBasicParsing -Body $json -TimeoutSec 20
        } catch { 
            WriteInfo "`tSending telemetry failed with an error: $($_.Exception.Message)"
            $response = $_.Exception.Message
        }

        if($LabConfig.ContainsKey('TelemetryDebugLog')) {
            Add-Content -Path "$ScriptRoot\Telemetry.log" -Value $response
            Add-Content -Path "$ScriptRoot\Telemetry.log" -Value "`n------------------------------`n"
        }
    }
}

function Send-TelemetryEvent {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Event,

        $Properties,
        $Metrics,
        $NickName
    )

    process {
        $telemetryEvent = New-TelemetryEvent -Event $Event -Properties $Properties -Metrics $Metrics -NickName $NickName
        Send-TelemetryObject -Data $telemetryEvent
    }
}

function Send-TelemetryEvents {
    param(
        [Parameter(Mandatory = $true)]
        [array]$Events
    )

    process {
        Send-TelemetryObject -Data $Events
    }
}

function Read-TelemetryLevel {
    process {
        # Ask user for consent
        WriteInfoHighlighted "`nLab telemetry"
        WriteInfo "By providing a telemetry information you will help us to improve MSLab scripts. There are two levels of a telemetry information and we are not collecting any personally identifiable information (PII)."
        WriteInfo "Details about telemetry levels and the content of telemetry messages can be found in documentation https://aka.ms/mslab/telemetry"
        WriteInfo "Available telemetry levels are:"
        WriteInfo " * None  -- No information will be sent"
        WriteInfo " * Basic -- Information about lab will be sent (e.g. script execution time, number of VMs, guest OSes)"
        WriteInfo " * Full  -- Information about lab and the host machine (e.g. type of disk)"
        WriteInfo "Would you be OK with providing an information about your MSLab usage?"
        WriteInfo "`nTip: You can also configure telemetry settings explicitly in LabConfig.ps1 file or by setting an environmental variable and suppress this prompt."

        $options = [System.Management.Automation.Host.ChoiceDescription[]] @(
          <# 0 #> New-Object System.Management.Automation.Host.ChoiceDescription "&None", "No information will be sent"
          <# 1 #> New-Object System.Management.Automation.Host.ChoiceDescription "&Basic", "Lab info will be sent (e.g. script execution time, number of VMs)"
          <# 2 #> New-Object System.Management.Automation.Host.ChoiceDescription "&Full", "More details about the host machine and deployed VMs (e.g. guest OS)"
        )
        $response = $host.UI.PromptForChoice("MSLab telemetry level", "Please choose a telemetry level for this MSLab instance. For more details please see MSLab documentation.", $options, 1 <#default option#>)

        $telemetryLevel = $null
        switch($response) {
            0 {
                $telemetryLevel = 'None'
                WriteInfo "`nNo telemetry information will be sent."
            }
            1 {
                $telemetryLevel = 'Basic'
                WriteInfo "`nTelemetry has been set to Basic level, thank you for your valuable feedback."
            }
            2 {
                $telemetryLevel = 'Full'
                WriteInfo "`nTelemetry has been set to Full level, thank you for your valuable feedback."
            }
        }

        $telemetryLevel
    }
}

# Instance values
$ScriptRoot = $PSScriptRoot
$mslabVersion = "v23.06.1"
$TelemetryEnabledLevels = "Basic", "Full"
$TelemetryInstrumentationKey = "9ebf64de-01f8-4f60-9942-079262e3f6e0"
$TelemetrySessionId = $ScriptRoot + $env:COMPUTERNAME + ((Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Cryptography).MachineGuid) | Get-StringHash
#endregion

function  Get-WindowsBuildNumber { 
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    return [int]($os.BuildNumber) 
} 
#endregion

#region Initialization

# grab Time and start Transcript
    Start-Transcript -Path "$PSScriptRoot\Prereq.log"
    $StartDateTime = Get-Date
    WriteInfo "Script started at $StartDateTime"
    WriteInfo "`nMSLab Version $mslabVersion"

#Load LabConfig....
    . "$PSScriptRoot\LabConfig.ps1"

# Telemetry Event
    if((Get-TelemetryLevel) -in $TelemetryEnabledLevels) {
        WriteInfo "Telemetry is set to $(Get-TelemetryLevel) level from $(Get-TelemetryLevelSource)"
        Send-TelemetryEvent -Event "Prereq.Start" -NickName $LabConfig.TelemetryNickName | Out-Null
    }

#define some variables if it does not exist in labconfig
    If (!$LabConfig.DomainNetbiosName) {
        $LabConfig.DomainNetbiosName="Corp"
    }

    If (!$LabConfig.DomainName) {
        $LabConfig.DomainName="Corp.contoso.com"
    }

#set TLS 1.2 for github downloads
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#endregion

#region OS checks and folder build

# Check if not running in root folder
    if (($psscriptroot).Length -eq 3) {
        WriteErrorAndExit "`t MSLab canot run in root folder. Please put MSLab scripts into a folder. Exiting"
    }

# Checking for Compatible OS
    WriteInfoHighlighted "Checking if OS is Windows 10 1511 (10586)/Server 2016 or newer"

    $BuildNumber=Get-WindowsBuildNumber
    if ($BuildNumber -ge 10586){
        WriteSuccess "`t OS is Windows 10 1511 (10586)/Server 2016 or newer"
    }else{
        WriteErrorAndExit "`t Windows version  $BuildNumber detected. Version 10586 and newer is needed. Exiting"
    }

# Checking Folder Structure
    "ParentDisks","Temp","Temp\DSC","Temp\ToolsVHD\DiskSpd","Temp\ToolsVHD\SCVMM\ADK","Temp\ToolsVHD\SCVMM\ADKWinPE","Temp\ToolsVHD\SCVMM\SQL","Temp\ToolsVHD\SCVMM\SCVMM","Temp\ToolsVHD\SCVMM\UpdateRollup" | ForEach-Object {
        if (!( Test-Path "$PSScriptRoot\$_" )) { New-Item -Type Directory -Path "$PSScriptRoot\$_" } }

    "Temp\ToolsVHD\SCVMM\ADK\Copy_ADK_with_adksetup.exe_here.txt","Temp\ToolsVHD\SCVMM\ADKWinPE\Copy_ADKWinPE_with_adkwinpesetup.exe_here.txt","Temp\ToolsVHD\SCVMM\SQL\Copy_SQL2017_or_SQL2019_with_setup.exe_here.txt","Temp\ToolsVHD\SCVMM\SCVMM\Copy_SCVMM_with_setup.exe_here.txt","Temp\ToolsVHD\SCVMM\UpdateRollup\Copy_SCVMM_Update_Rollup_MSPs_here.txt" | ForEach-Object {
        if (!( Test-Path "$PSScriptRoot\$_" )) { New-Item -Type File -Path "$PSScriptRoot\$_" } }
#endregion

#region Download Scripts

#add scripts for VMM
    $filenames = "1_SQL_Install", "2_ADK_Install", "3_SCVMM_Install"
    foreach ($filename in $filenames) {
        $Path = "$PSScriptRoot\Temp\ToolsVHD\SCVMM\$filename.ps1"
        if (Test-Path -Path $Path) {
            WriteSuccess "`t $Filename is present, skipping download"
        } else {
            $FileContent = $null

            try {
                # try to download tagged version first
                $FileContent = (Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/microsoft/MSLab/$mslabVersion/Tools/$filename.ps1").Content
            } catch {
                WriteInfo "Download $filename failed with $($_.Exception.Message), trying master branch now"
                # if that fails, try master branch
                $FileContent = (Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/microsoft/MSLab/master/Tools/$filename.ps1").Content
            }

            if ($FileContent) {
                $script = New-Item $Path -type File -Force
                $FileContent=$FileContent -replace "PasswordGoesHere",$LabConfig.AdminPassword #only applies to 1_SQL_Install and 3_SCVMM_Install.ps1
                $FileContent=$FileContent -replace "DomainNameGoesHere",$LabConfig.DomainNetbiosName #only applies to 1_SQL_Install and 3_SCVMM_Install.ps1
                Set-Content -Path $script -value $FileContent
            } else {
                WriteErrorAndExit "Unable to download $Filename."
            }
        }
    }

# add createparentdisks, DownloadLatestCU and PatchParentDisks scripts to Parent Disks folder
    $fileNames = "CreateParentDisk", "DownloadLatestCUs", "PatchParentDisks", "CreateVMFleetDisk"
    if($LabConfig.Linux) {
        $fileNames += "CreateLinuxParentDisk"
    }
    foreach ($filename in $fileNames) {
        $path = "$PSScriptRoot\ParentDisks\$FileName.ps1"
        If (Test-Path -Path $path) {
            WriteSuccess "`t $filename is present, skipping download"
        } else {
            $FileContent = $null

            try {
                # try to download release version first
                Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/microsoft/MSLab/releases/download/$mslabVersion/$Filename.ps1" -OutFile $path
            } catch {
                WriteInfo "Download $filename failed with $($_.Exception.Message), trying master branch now"
                
                # if that fails, try master branch
                $FileContent = (Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/microsoft/MSLab/master/Tools/$FileName.ps1").Content
                if ($FileContent) {
                    $script = New-Item $path -type File -Force
                    Set-Content -Path $script -value $FileContent
                } else {
                    WriteErrorAndExit "Unable to download $Filename."
                }
            }
        }
    }

# Download convert-windowsimage into Temp
    WriteInfoHighlighted "Testing Convert-windowsimage presence"
    $convertWindowsImagePath = "$PSScriptRoot\Temp\Convert-WindowsImage.ps1"
    If (Test-Path -Path $convertWindowsImagePath) {
        WriteSuccess "`t Convert-windowsimage.ps1 is present, skipping download"
    } else {
        WriteInfo "`t Downloading Convert-WindowsImage"
        try {
            Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/microsoft/MSLab/releases/download/$mslabVersion/Convert-WindowsImage.ps1" -OutFile $convertWindowsImagePath
        } catch {
            try {
                WriteInfo "Download Convert-windowsimage.ps1 failed with $($_.Exception.Message), trying master branch now"
                Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/microsoft/MSLab/master/Tools/Convert-WindowsImage.ps1" -OutFile $convertWindowsImagePath
            } catch {
                WriteError "`t Failed to download Convert-WindowsImage.ps1!"
            }
        }
    }
#endregion

#region some tools to download
# Downloading diskspd if its not in ToolsVHD folder
    WriteInfoHighlighted "Testing diskspd presence"
    If ( Test-Path -Path "$PSScriptRoot\Temp\ToolsVHD\DiskSpd\diskspd.exe" ) {
        WriteSuccess "`t Diskspd is present, skipping download"
    }else{ 
        WriteInfo "`t Diskspd not there - Downloading diskspd"
        try {
            <# aka.ms/diskspd changed. Commented
            $webcontent  = Invoke-WebRequest -Uri "https://aka.ms/diskspd" -UseBasicParsing
            if($PSVersionTable.PSEdition -eq "Core") {
                $link = $webcontent.Links | Where-Object data-url -Match "/Diskspd.*zip$"
                $downloadUrl = "{0}://{1}{2}" -f $webcontent.BaseResponse.RequestMessage.RequestUri.Scheme, $webcontent.BaseResponse.RequestMessage.RequestUri.Host, $link.'data-url'
            } else {
                $downloadurl = $webcontent.BaseResponse.ResponseUri.AbsoluteUri.Substring(0,$webcontent.BaseResponse.ResponseUri.AbsoluteUri.LastIndexOf('/'))+($webcontent.Links | where-object { $_.'data-url' -match '/Diskspd.*zip$' }|Select-Object -ExpandProperty "data-url")
            }
            #>
            $downloadurl="https://github.com/microsoft/diskspd/releases/download/v2.0.21a/DiskSpd.zip"
            Invoke-WebRequest -Uri $downloadurl -OutFile "$PSScriptRoot\Temp\ToolsVHD\DiskSpd\diskspd.zip"
        }catch{
            WriteError "`t Failed to download Diskspd!"
        }
        # Unnzipping and extracting just diskspd.exe x64
            Microsoft.PowerShell.Archive\Expand-Archive "$PSScriptRoot\Temp\ToolsVHD\DiskSpd\diskspd.zip" -DestinationPath "$PSScriptRoot\Temp\ToolsVHD\DiskSpd\Unzip"
            Copy-Item -Path (Get-ChildItem -Path "$PSScriptRoot\Temp\ToolsVHD\diskspd\" -Recurse | Where-Object {$_.Directory -like '*amd64*' -and $_.name -eq 'diskspd.exe' }).fullname -Destination "$PSScriptRoot\Temp\ToolsVHD\DiskSpd\"
            Remove-Item -Path "$PSScriptRoot\Temp\ToolsVHD\DiskSpd\diskspd.zip"
            Remove-Item -Path "$PSScriptRoot\Temp\ToolsVHD\DiskSpd\Unzip" -Recurse -Force
    }

#endregion

#region Downloading required Posh Modules
# Downloading modules into Temp folder if needed.

    $modules=("xActiveDirectory","3.0.0.0"),("xDHCpServer","2.0.0.0"),("xDNSServer","1.15.0.0"),("NetworkingDSC","7.4.0.0"),("xPSDesiredStateConfiguration","8.10.0.0")
    foreach ($module in $modules){
        WriteInfoHighlighted "Testing if modules are present" 
        $modulename=$module[0]
        $moduleversion=$module[1]
        if (!(Test-Path "$PSScriptRoot\Temp\DSC\$modulename\$Moduleversion")){
            WriteInfo "`t Module $module not found... Downloading"
            #Install NuGET package provider   
            if ((Get-PackageProvider -Name NuGet) -eq $null){   
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Confirm:$false -Force
            }
            Find-DscResource -moduleName $modulename -RequiredVersion $moduleversion | Save-Module -Path "$PSScriptRoot\Temp\DSC"
        }else{
            WriteSuccess "`t Module $modulename version found... skipping download"
        }
    }

# Installing DSC modules if needed
    foreach ($module in $modules) {
        WriteInfoHighlighted "Testing DSC Module $module Presence"
        # Check if Module is installed
        if ((Get-DscResource -Module $Module[0] | where-object {$_.version -eq $module[1]}) -eq $Null) {
            # module is not installed - install it
            WriteInfo "`t Module $module will be installed"
            $modulename=$module[0]
            $moduleversion=$module[1]
            Copy-item -Path "$PSScriptRoot\Temp\DSC\$modulename" -Destination "C:\Program Files\WindowsPowerShell\Modules" -Recurse -Force
            WriteSuccess "`t Module was installed."
            Get-DscResource -Module $modulename
        } else {
            # module is already installed
            WriteSuccess "`t Module $Module is already installed"
        }
    }

#endregion

#region Linux prereqs
if($LabConfig.Linux -eq $true) {
    WriteInfoHighlighted "Testing Linux prerequisites"
    WriteInfo "`t Test Packer availability"

    # Packer
    if (Get-Command "packer.exe" -ErrorAction SilentlyContinue) 
    { 
        WriteSuccess "`t Packer is in PATH."
    } else {
        WriteInfo "`t`t Downloading latest Packer binary"

        WriteInfo "`t`t Creating packer directory"
        $linuxToolsDirPath = "$PSScriptRoot\LAB\bin" 
        New-Item $linuxToolsDirPath -ItemType Directory -Force | Out-Null
        
        if(-not (Test-Path (Join-Path $linuxToolsDirPath "packer.exe"))) {
            $packerReleaseInfo = Invoke-RestMethod -Uri "https://checkpoint-api.hashicorp.com/v1/check/packer"
            $downloadUrl = "https://releases.hashicorp.com/packer/$($packerReleaseInfo.current_version)/packer_$($packerReleaseInfo.current_version)_windows_amd64.zip" 
            Start-BitsTransfer -Source $downloadUrl -Destination (Join-Path $linuxToolsDirPath "packer.zip") 
            Expand-Archive -Path (Join-Path $linuxToolsDirPath "packer.zip")  -DestinationPath $linuxToolsDirPath -Force
            Remove-Item -Path (Join-Path $linuxToolsDirPath "packer.zip") 
        }
    
        WriteInfo "`t`t Creating Packer firewall rule"
        $id = $PSScriptRoot -replace '[^a-zA-Z0-9]'
        $fwRule = Get-NetFirewallRule -Name "mslab-packer-$id" -ErrorAction SilentlyContinue
        if(-not $fwRule) {
            New-NetFirewallRule -Name "mslab-packer-$id" -DisplayName "Allow MSLab Packer ($($PSScriptRoot))" -Action Allow -Program (Join-Path $linuxToolsDirPath "packer.exe") -Profile Any -ErrorAction SilentlyContinue
        }
    }

    # Packer templates
    WriteInfo "`t`t Downloading Packer templates"
    $packerTemplatesDirectory = "$PSScriptRoot\ParentDisks\PackerTemplates\"
    if (-not (Test-Path $packerTemplatesDirectory)) {
        New-Item -Type Directory -Path $packerTemplatesDirectory 
    }

    $templatesBase = "https://github.com/microsoft/mslab-templates/releases/latest/download/"
    $templatesFile = "$($packerTemplatesDirectory)\templates.json"

    Invoke-WebRequest -Uri "$($templatesBase)/templates.json" -OutFile $templatesFile
    if(-not (Test-Path -Path $templatesFile)) {
        WriteErrorAndExit "Download of packer templates failed"
    }

    $templatesInfo = Get-Content -Path $templatesFile | ConvertFrom-Json
    foreach($template in $templatesInfo.templates) {
        $templateZipFile = Join-Path $packerTemplatesDirectory $template.package
        Invoke-WebRequest -Uri "$($templatesBase)/$($template.package)" -OutFile $templateZipFile
        Expand-Archive -Path $templateZipFile -DestinationPath (Join-Path $packerTemplatesDirectory $template.directory)
        Remove-Item -Path $templateZipFile
    }

    # OpenSSH
    $capability = Get-WindowsCapability -Online -Name "OpenSSH.Client~~~~0.0.1.0"
    if($capability.State -ne "Installed") {
        WriteInfoHighlighted "`t Enabling OpensSH Client"
        Add-WindowsCapability -Online -Name "OpenSSH.Client~~~~0.0.1.0"
        Set-Service ssh-agent -StartupType Automatic
        Start-Service ssh-agent
    }

    # SSH Key
    WriteInfoHighlighted "`t SSH key"
    if($LabConfig.SshKeyPath) {
        if(-not (Test-Path $LabConfig.SshKeyPath)) {
            WriteError "`t Cannot find specified SSH key $($LabConfig.SshKeyPath)."
        }

        $private = ssh-keygen.exe -y -e -f $LabConfig.SshKeyPath
        $public = ssh-keygen.exe -y -e -f "$($LabConfig.SshKeyPath).pub"
        $comparison = Compare-Object -ReferenceObject $private -DifferenceObject $public
        if($comparison) {
            WriteError "`t SSH Keypair $($LabConfig.SshKeyPath) does not match."
        }
    } 
    else 
    {
        WriteInfo "`t`t Generating new SSH key pair"
        $sshKeyDir = "$PSScriptRoot\LAB\.ssh" 
        $key = "$sshKeyDir\lab_rsa"
        New-Item -ItemType Directory $sshKeyDir -ErrorAction SilentlyContinue | Out-Null
        ssh-keygen.exe -t rsa -b 4096 -C "$($LabConfig.DomainAdminName)" -f $key -q -N '""'
    }
}
#endregion

# Telemetry Event
if((Get-TelemetryLevel) -in $TelemetryEnabledLevels) {
    $metrics = @{
        'script.duration' = ((Get-Date) - $StartDateTime).TotalSeconds
    }
 
    Send-TelemetryEvent -Event "Prereq.End" -Metrics $metrics -NickName $LabConfig.TelemetryNickName | Out-Null
}

# finishing 
WriteInfo "Script finished at $(Get-date) and took $(((get-date) - $StartDateTime).TotalMinutes) Minutes"

Stop-Transcript

If (!$LabConfig.AutoClosePSWindows) {
    WriteSuccess "Press enter to continue..."
    Read-Host | Out-Null
}

# SIG # Begin signature block
# MIInkwYJKoZIhvcNAQcCoIInhDCCJ4ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCDqTPjjZFINDEP
# A0oFqUZjTXuE+Ykz9kNb20LG8l1eQKCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
# esGEb+srAAAAAANOMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMwMzE2MTg0MzI5WhcNMjQwMzE0MTg0MzI5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDdCKiNI6IBFWuvJUmf6WdOJqZmIwYs5G7AJD5UbcL6tsC+EBPDbr36pFGo1bsU
# p53nRyFYnncoMg8FK0d8jLlw0lgexDDr7gicf2zOBFWqfv/nSLwzJFNP5W03DF/1
# 1oZ12rSFqGlm+O46cRjTDFBpMRCZZGddZlRBjivby0eI1VgTD1TvAdfBYQe82fhm
# WQkYR/lWmAK+vW/1+bO7jHaxXTNCxLIBW07F8PBjUcwFxxyfbe2mHB4h1L4U0Ofa
# +HX/aREQ7SqYZz59sXM2ySOfvYyIjnqSO80NGBaz5DvzIG88J0+BNhOu2jl6Dfcq
# jYQs1H/PMSQIK6E7lXDXSpXzAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUnMc7Zn/ukKBsBiWkwdNfsN5pdwAw
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMDUxNjAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAD21v9pHoLdBSNlFAjmk
# mx4XxOZAPsVxxXbDyQv1+kGDe9XpgBnT1lXnx7JDpFMKBwAyIwdInmvhK9pGBa31
# TyeL3p7R2s0L8SABPPRJHAEk4NHpBXxHjm4TKjezAbSqqbgsy10Y7KApy+9UrKa2
# kGmsuASsk95PVm5vem7OmTs42vm0BJUU+JPQLg8Y/sdj3TtSfLYYZAaJwTAIgi7d
# hzn5hatLo7Dhz+4T+MrFd+6LUa2U3zr97QwzDthx+RP9/RZnur4inzSQsG5DCVIM
# pA1l2NWEA3KAca0tI2l6hQNYsaKL1kefdfHCrPxEry8onJjyGGv9YKoLv6AOO7Oh
# JEmbQlz/xksYG2N/JSOJ+QqYpGTEuYFYVWain7He6jgb41JbpOGKDdE/b+V2q/gX
# UgFe2gdwTpCDsvh8SMRoq1/BNXcr7iTAU38Vgr83iVtPYmFhZOVM0ULp/kKTVoir
# IpP2KCxT4OekOctt8grYnhJ16QMjmMv5o53hjNFXOxigkQWYzUO+6w50g0FAeFa8
# 5ugCCB6lXEk21FFB1FdIHpjSQf+LP/W2OV/HfhC3uTPgKbRtXo83TZYEudooyZ/A
# Vu08sibZ3MkGOJORLERNwKm2G7oqdOv4Qj8Z0JrGgMzj46NFKAxkLSpE5oHQYP1H
# tPx1lPfD7iNSbJsP6LiUHXH1MIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGXMwghlvAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJgioxuAB4/Tq/kVDeR4e/Y5
# 3eoogoxv7nCqVDdIYVkaMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAp50aOuK/69YXZSeIeQgXfZi5ZkqZvYsJz1zqbnCpODpUK6u8L1nPWZZ2
# eRNgYz8YOAWG+yRpnwuyhNVlsAXb31v/yz47GA49cbI/v9Bnj0wdVBhyRG7u75lG
# LRM1h0aZQ3Zq+AZ4KfKPCQsK1R25pbTokoI9lVmeuUmz+dAbNT8Jn8q52n168h4W
# lGqIFQjFzQZFViHoNk9maYODwVZW5rYUWDwo7TGBPItOXcDKFhhtcjSGD5jzrDAa
# yc4rA4PYljd2ztF03MBuifLzzRv/tUeXCLvAqoz/MCC3S0M0SKR2Yv5Sl+uvlGI3
# mYhdpNmbsrWDb9kL9S+SX/EVTYEkd6GCFv0wghb5BgorBgEEAYI3AwMBMYIW6TCC
# FuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsq
# hkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCDEQvY3Hn6z4lHk9OHYEuYSauXhxxcTEL+28UWw8DoNCwIGZItYFIFn
# GBMyMDIzMDYxNjE5NTMwMi4zMjdaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpBRTJDLUUz
# MkItMUFGQzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCC
# EVQwggcMMIIE9KADAgECAhMzAAABv99uuQQVUihYAAEAAAG/MA0GCSqGSIb3DQEB
# CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMTEwNDE5MDEy
# NFoXDTI0MDIwMjE5MDEyNFowgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkFFMkMtRTMyQi0xQUZDMSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAuExh0n1UxKMzBvkPHer47nryD4UK2GVy1X6bOVC+hLVh
# DlsIWQ1uX/9a8IRI3zXo/y1oTDuj+rJHyX4OZQn42E0iu7x6swPvM34zIOSPn8lg
# nWzGEAsRtz9zBrLW9+4w/YhWlXI8hvc7ovqupuL3TXte8BbmNOUDSL+Ou2bBfObG
# zsH3yY/BELvqwO13KZ9Z1OxKacnqq1u9E9Rhai90STog22lR2MVRSx55FHi/emnZ
# A/IKvsAtEH2K6JmgOyQ7/mDQrWNEA5roUjhQqLQw1/3wz/CIvc9+FPxX2dxR0nvv
# Ye5VLqv8Q99cOkO6z6V4stGDyFDuO8CwtiSvCC3QrOOugAl33aPD9YZswywWRk+Y
# GyLI+Fw+kCCUY6h1qOjTj5glz0esmds3ue45WaI2hI9usForM8gy//5tDZXj0KKU
# 1BxA04xpfEy91RZUbc6pdAvEkpYrN2jlpXhMvTD7pgdYyxkVSaWZv7kWp5y9NjWP
# /CTDGXTC6DWiGcXwPQO66QdVNWxuiGdpfPaEUnWXcKnDVua1khBAxO4m9wg/1qM6
# f7HwXf/pHifMej+qB7SUZOiJScX+1HmffmZRAFiJXS0qUDk0ZAZW3oX2xLyl0044
# eHI7Y95GPaw8OlSTeNiNAKl+MyH5OaifsUuyVHOf4rsrE+ZyAuS9e9ERqu5H/10C
# AwEAAaOCATYwggEyMB0GA1UdDgQWBBRVAolUT3eV3wK/+Luf/wawCPMYpzAfBgNV
# HSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwG
# CCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRz
# L01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNV
# HRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IC
# AQAjCREvjT6yXwJYdvkFUqTGGh6RizAY+ciuB6UOBUm0yqq5QC+5pCEa9WSMvbUG
# zxDCEFBgD93gWGnkiyYcHCazlgZK+E7WxtI3bP++Fb4RJZiWLo/IC9hX12hCZZwY
# XIGVzC9BVAcNx/zsFqI/9u8u/bhGjDHPad47C4OQNCHrkNqzGYxb4GQq6Psw6o7c
# Ety3MU3Jd4uzBazaFhPRvmBfSn+Ufd6pTNZLgIX9BjrLmZblc/d2LIAurEr5W29W
# fW5RMRIEZzO9TaMr/zzdmW/cV6VdaDTygy5g4O3UXadt1DraUpn5jcD10TVWNnyz
# /paeleHojrGCCksqexpelMkUsiYP0HX9pFUgNglWU10r1wEzFwZM9aX2Rqq3fFRr
# N3gu8tCX+H1nKK2AobW1vmsKLTH6PyX1LkyvRwTj45a1paeHIR8TGzm3+iY7wpC1
# MHuzqAqAdDeaIVdVlch807VJJ4hDive6AiOQCV9MwiUyhf5v4P8jTGof8CqjDb3P
# nLlNSnFm2BFhMZ35oNTEosc37GZHScM83hTN1E481sLYJrrhhcdtcyNB60juMjqG
# UD6uQ/7DbMvtv93tFj5WjxVhMCkkY66EEYgpfFLOCb2ngJJWFuJCIGsCiDfDxGwE
# 4RVYAnoFzoa2OfSqijYg2drdZfpptRRvKxMsAzu3oxkS/TCCB3EwggVZoAMCAQIC
# EzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBS
# b290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoX
# DTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC
# 0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VG
# Iwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP
# 2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/P
# XfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361
# VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwB
# Sru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9
# X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269e
# wvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDw
# wvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr
# 9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+e
# FnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAj
# BgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+n
# FV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEw
# PwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9j
# cy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3
# FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAf
# BgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBH
# hkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNS
# b29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUF
# BzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0Nl
# ckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4Swf
# ZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTC
# j/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu
# 2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/
# GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3D
# YXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbO
# xnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqO
# Cb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I
# 6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0
# zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaM
# mdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNT
# TY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLLMIICNAIBATCB+KGB0KSBzTCByjEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWlj
# cm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046QUUyQy1FMzJCLTFBRkMxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVADgEd+JNrp4dpvFKMZi91txbfic3oIGD
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEF
# BQACBQDoNygLMCIYDzIwMjMwNjE3MDIyNzIzWhgPMjAyMzA2MTgwMjI3MjNaMHQw
# OgYKKwYBBAGEWQoEATEsMCowCgIFAOg3KAsCAQAwBwIBAAICDY4wBwIBAAICEpkw
# CgIFAOg4eYsCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgC
# AQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQBRbOuMF9oEYhzU
# tYumsg5b8TnG44RVo1tez59zm7wdW6QUhLwLWSGCxmtmmKxpx7Q+Y+2unXKuK0k3
# 7ib9Fbm6tfLJktHWOH2P8JVJraNPhszg10u3g6SHGc7l7w1SRlz6M6HuEMtEcdvo
# RV5sRTeYw6BPQR4+UT5h04MYGJGDyDGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABv99uuQQVUihYAAEAAAG/MA0GCWCGSAFl
# AwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcN
# AQkEMSIEIOwBiSfYPAH+IYyzH+A0NrAU4DJMGIiEfCgLslwjJqGOMIH6BgsqhkiG
# 9w0BCRACLzGB6jCB5zCB5DCBvQQg/Q4tRz63EiRj4K+19yNUwogBIOsp44CIuBfn
# ZHCvBa4wgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# Ab/fbrkEFVIoWAABAAABvzAiBCB+ji9FKkck5oFUZPQETyWOQyqI4aZYywv7aTRd
# g92tsTANBgkqhkiG9w0BAQsFAASCAgAGOF+NnvMecHJICV5Zn+Nw8UUsF7UPKIx6
# 6ZZlhhWOdrOYZSuOOAdsvicd7QFCiD/ICLVnW1D5h4N91jgbLBioQbpUL/oSQZtm
# +2jYbceK8qi8UdwPgtqS2H7l4F+gJt0rR7FhNOqchSyqB+5P4LNBf1WzS8zYifU+
# M7x5nZArGcBh3C8qEx8JSFCrpGD9+YvNipB+av0urWcqhgjb6650GrjHhK2cv0+2
# g+Y2Qk96wrWzCFuzBHZWza+VOOY63+2+ott/4zr02siDMuhc3iDoCu2Ldpg61O8n
# TSv0vwOjMxfrqwXA+wdmv5e1wjjDzZ3N1C47+LRAfeuIece3GOacSHS8Yasx/sum
# momtbtTILWbgRTvBjSiWgVR2rZTdZzwcmWDfkjQ724fHYKAzC+itxlrWOVYjh7OB
# NlSctKQack/AdpGJhL3X2MpBTKrgm9xJ3n+2L5lD3jCE56KfBsmUaItlRl9SLDdS
# fqbIIIBDUiM3bsk+jpfdp5EQGctCVJa4VvQYK6vT128CFfrjPHKTglRvFphNRaeS
# tc/QDDdVIt8PkYkoasAIg/amE+HD0gaSXELmRKwwMaPIUHd6iT8Tj4ggCxUJ36Gh
# Bza5K1Q+Q9ezKXedI5k1dsLIozwBPoaXXxTIswGXr8viYStGYhE9fT30YMIPRt4R
# lvfL4yrPbg==
# SIG # End signature block
