#basic config for Windows Server 2022, that creates VMs for S2D Hyperconverged scenario https://github.com/Microsoft/MSLab/tree/master/Scenarios/S2D%20Hyperconverged

$LabConfig=@{ DomainAdminName='LabAdmin'; AdminPassword='LS1setup!'; Prefix = 'MSLab-' ; DCEdition='4'; DCVMProcessorCount=4; Internet=$true ; AutoStartAfterDeploy=$true; TelemetryLevel="None"; EnableGuestServiceInterface=$true; ServerISOFolder="C:\MSLab\ServerISO"; ServerMSUsFolder="C:\MSLab\ServerMSUs"; AdditionalNetworksConfig=@(); VMs=@()}
# Windows Server 2022
#1..2 | ForEach-Object {$VMNames="Server"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Simple' ; ParentVHD = 'Win2022_G2.vhdx' ; MGMTNICs=1; VMProcessorCount=4; MemoryMinimumBytes= 1GB; MemoryStartupBytes= 1536MB ; AddToolsVHD=$True ; DisableWCF=$True; vTPM=$True }}
$LABConfig.VMs += @{ VMName = "DC2" ; Configuration = 'Simple' ; ParentVHD = 'Win2022_G2.vhdx' ; MGMTNICs=1; VMProcessorCount=4; MemoryMinimumBytes= 1GB; MemoryStartupBytes= 2GB ; AddToolsVHD=$True ; DisableWCF=$True; vTPM=$True }
# Windows 11 | Client
#1..9 | ForEach-Object {$VMNames="Client"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; ParentVHD = 'Win1122H2_G2.vhdx' ; MGMTNICs=1; VMProcessorCount=4; MemoryMinimumBytes= 1GB; MemoryStartupBytes= 2GB ; AddToolsVHD=$True ; DisableWCF=$True; vTPM=$True }}
# Windows Server 2012 R2
#$LabConfig.VMs += @{ VMName = 'Win2012R2' ; ParentVHD = 'Win2012R2_G2.vhdx' ; MGMTNICs=1; VMProcessorCount=4; MemoryMinimumBytes= 1GB; MemoryStartupBytes= 2GB ; AddToolsVHD=$True ; DisableWCF=$True; vTPM=$True }

#1..4 | ForEach-Object {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2022Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 512MB }}
# Or Azure Stack HCI 21H2
#1..4 | ForEach-Object {$VMNames="AzSHCI"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'AzSHCI21H2_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 1GB }}
# Or Windows Server 2019
#1..4 | ForEach-Object {$VMNames="S2D"; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'S2D' ; ParentVHD = 'Win2019Core_G2.vhdx'; SSDNumber = 0; SSDSize=800GB ; HDDNumber = 12; HDDSize= 4TB ; MemoryStartupBytes= 512MB }}

### HELP ###

#If you need more help or different configuration options, ping us at jaromir.kaspar@dell.com or vlmach@microsoft.com

#region Same as above, but with more explanation
    <#
    $LabConfig=@{
        DomainAdminName="LabAdmin";                  # Used during 2_CreateParentDisks (no affect if changed after this step)
        AdminPassword="LS1setup!";                   # Used during 2_CreateParentDisks. If changed after, it will break the functionality of 3_Deploy.ps1
        Prefix = "MSLab-";                           # (Optional) All VMs and vSwitch are created with this prefix, so you can identify the lab. If not specified, Lab folder name is used
        SwitchName = "LabSwitch";                    # (Optional) Name of vSwitch
        SwitchNICs = "";                             # (Optional) Adds these NICs to vSwitch (without connecting hostOS). (example "NIC1","NIC2")
        SecureBoot=$true;                            # (Optional) Useful when testing unsigned builds (Useful for MS developers for daily builds)
        DCEdition="4";                               # 4 for DataCenter or 3 for DataCenterCore
        InstallSCVMM="No";                           # (Optional) Yes/Prereqs/SQL/ADK/No
        AdditionalNetworksInDC=$false;               # (Optional) If Additional networks should be added also to DC
        DomainNetbiosName="Corp";                    # (Optional) If set, custom domain NetBios name will be used. if not specified, Default "corp" will be used
        DomainName="Corp.contoso.com";               # (Optional) If set, custom DomainName will be used. If not specified, Default "Corp.contoso.com" will be used
        DefaultOUName="Workshop";                    # (Optional) If set, custom OU for all machines and account will be used. If not specified, default "Workshop" is created
        AllowedVLANs="1-10";                         # (Optional) Sets the list of VLANs that can be used on Management vNICs. If not specified, default "1-10" is set.
        Internet=$false;                             # (Optional) If $true, it will add external vSwitch and configure NAT in DC to provide internet (Logic explained below)
        UseHostDnsAsForwarder=$false;                # (Optional) If $true, local DNS servers will be used as DNS forwarders in DC
        CustomDnsForwarders=@("8.8.8.8","1.1.1.1");  # (Optional) If configured, script will use those servers as DNS fordwarders in DC (Defaults to 8.8.8.8 and 1.1.1.1)
        PullServerDC=$true;                          # (Optional) If $false, then DSC Pull Server will not be configured on DC
        ServerISOFolder="";                          # (Optional) If configured, script will use ISO located in this folder for Windows Server hydration (if more ISOs are present, then out-grid view is called)
        ServerMSUsFolder="";                         # (Optional) If configured, script will inject all MSU files found into server OS
        EnableGuestServiceInterface=$false;          # (Optional) If True, then Guest Services integration component will be enabled on all VMs.
        DCVMProcessorCount=2;                        # (Optional) 2 is default. If specified more/less, processorcount will be modified.
        DHCPscope="10.0.0.0";                        # (Optional) 10.0.0.0 is configured if nothing is specified. Scope has to end with .0 (like 10.10.10.0). It's always /24       
        DCVMVersion="9.0";                           # (Optional) Latest is used if nothing is specified. Make sure you use values like "8.0","8.3","9.0"
        TelemetryLevel="";                           # (Optional) If configured, script will stop prompting you for telemetry. Values are "None","Basic","Full"
        TelemetryNickname="";                        # (Optional) If configured, telemetry will be sent with NickName to correlate data to specified NickName. So when leaderboards will be published, MSLab users will be able to see their own stats
        AutoStartAfterDeploy=$false;                 # (Optional) If $false, no VM will be started; if $true or 'All' all lab VMs will be started after Deploy script; if 'DeployedOnly' only newly created VMs will be started.
        InternetVLAN="";                             # (Optional) If set, it will apply VLAN on Interent adapter connected to DC
        ManagementSubnetIDs="";                      # (Optional) If set, it will add another dhcp-enable management networks.
        Linux=$false;                                # (Optional) If set to $true, required prerequisities for building Linux images with Packer will be configured.
        LinuxAdminName="linuxadmin";                 # (Optional) If set, local user account with that name will be created in Linux image. If not, DomainAdminName will be used as a local account.
        SshKeyPath="$($env:USERPROFILE)\.ssh\id_rsa" # (Optional) If set, specified SSH key will be used to build and access Linux images.
        AutoClosePSWindows=$false;                   # (Optional) If set, the PowerShell console windows will automatically close once the script has completed successfully. Best suited for use in automated deployments.
        AutoCleanUp=$false;                          # (Optional) If set, after creating initial parent disks, files that are no longer necessary will be cleaned up. Best suited for use in automated deployments.
        AdditionalNetworksConfig=@();                # Just empty array for config below
        VMs=@();                                     # Just empty array for config below
    }

    # Specifying LabVMs
    1..4 | ForEach-Object { 
        $VMNames="S2D";                                # Here you can bulk edit name of 4 VMs created. In this case will be s2d1,s2d2,s2d3,s2d4 created
        $LABConfig.VMs += @{
            VMName = "$VMNames$_" ;
            Configuration = 'S2D' ;                    # Simple/S2D/Shared/Replica
            ParentVHD = 'Win2022Core_G2.vhdx';         # VHD Name from .\ParentDisks folder
            SSDNumber = 0;                             # Number of "SSDs" (its just simulation of SSD-like sized HDD, just bunch of smaller disks)
            SSDSize=800GB ;                            # Size of "SSDs"
            HDDNumber = 12;                            # Number of "HDDs"
            HDDSize= 4TB ;                             # Size of "HDDs"
            MemoryStartupBytes= 512MB;                 # Startup memory size
        }
    }

    #optional: (only if AdditionalNetworks are configured in $LabConfig.VMs) this is just an example. In this configuration its not needed.
    $LABConfig.AdditionalNetworksConfig += @{ 
        NetName = 'Storage1';                        # Network Name
        NetAddress='172.16.1.';                      # Network Addresses prefix. (starts with 1), therefore first VM with Additional network config will have IP 172.16.1.1
        NetVLAN='1';                                 # VLAN tagging
        Subnet='255.255.255.0'                       # Subnet Mask
    }
    $LABConfig.AdditionalNetworksConfig += @{ NetName = 'Storage2'; NetAddress='172.16.2.'; NetVLAN='2'; Subnet='255.255.255.0'}
    $LABConfig.AdditionalNetworksConfig += @{ NetName = 'Storage3'; NetAddress='172.16.3.'; NetVLAN='3'; Subnet='255.255.255.0'}

    #>
#endregion

#region $Labconfig
    <#
    DomainAdminName (Mandatory)
        Additional Domain Admin.

    Password (Mandatory)
        Specifies password for your lab. This password is used for domain admin, vmm account, sqlservice account and additional DomainAdmin... Define before running 2_CreateParentImages

    Prefix (Optional)
        Prefix for your lab. Each VM and switch will have this prefix.
        If not specified, labfolder name will be used

    SwitchName (Optional)
        If not specified, LabSwitch will be used as switch name

    Secureboot (Optional)
        $True/$False
        This enables or disables secure boot. In Microsoft we can test unsigned test builds with Secureboot off.

    DCEdition (Mandatory)
        'ServerDataCenter'/'ServerDataCenterCore'
        If you dont like GUI and you have management VM, you can select Core edition.

    InstallSCVMM * (Optional)
        'Yes'         - installs ADK, SQL and VMM
        'ADK'         - installs just ADK
        'SQL'         - installs just SQL
        'Prereqs'     - installs ADK and SQL
        'No'          - No, or anything else, nothing is installed.
            
            *requires install files in toolsVHD\SCVMM\, or it will fail. You can download all tools here:
                SQL: http://www.microsoft.com/en-us/evalcenter/evaluate-sql-server-2016
                SCVMM: http://www.microsoft.com/en-us/evalcenter/evaluate-system-center-technical-preview
                ADK: https://msdn.microsoft.com/en-us/windows/hardware/dn913721.aspx (you need to run setup and download the content. 2Meg file is not enough)

    AdditionalNetworksInDC (optional)
        If $True, networks specified in $LABConfig.AdditionalNetworksConfig will be added.

    MGMTNICsInDC (Optional)
        If nothing specified, then just 1 NIC is added in DC.
        Can be 1-8

    DomainNetbiosName (Optional)
        Domain NetBios Name. If nothing is specified, default "Corp" will be used

    DomainName (Optional)
        Domain Name. If nothing is specified, default "Corp.contoso.com" will be used

    DefaultOUName (Optional)
        Default Organization Unit Name for all computers and accounts. If nothing is specified, default "Workshop" will be used

    AllowedVLANs (Optional)
        Allowed VLANs configured on all management adapters. Accepts "1-10" or "1,2,3,4,5,6,7,8,9,10"

    Internet (Optional)
        If $True, it will configure vSwitch based on following Logic (designed to not ask you anything most of the times):
            If no vSwitch exists:
                If only one connected adapter exists, then it will create vSwitch from it.
                If more connected adapters exists, it will ask for only one
            If vSwitch named "$($labconfig.Prefix)$($labconfig.Switchname)-External" exists, it will be used (in case lab already exists)
            If only one vSwitch exists, then it will be used
            If more vSwitches exists, you will be prompted for what to use.
        It will add vNIC to DC and configure NAT with some Open DNS servers in DNS forwarder

    UseHostDnsAsForwarder (Optional)
        If $true, local DNS servers will be used as DNS forwarders in DC when Internet is enabled. 
        By default local host's DNS servers will be used as forwarders.

    CustomDnsForwarders (Optional)
        If configured, DNS servers listed will be appended to DNS forwaders list on DC's DNS server.
        If not defined at all, commonly known DNS servers will be used as a fallback:
             - Google DNS: 8.8.8.8
             - Cloudfare: 1.1.1.1
    
    DHCPscope (Optional)
        If configured, a custom DHCP scope will be used. Will always use a '/24'.
        Specify input like '10.1.0.0' or '192.168.0.0'
        If not defined at all, DHCP scope 10.0.0.0 will be used.

    PullServerDC (optional)
        If $False, Pull Server will not be setup.

    ServerISOFolder
        Example: ServerISOFolder="d:\ISO\Server2016"
        Script will try to find ISO in this folder and subfolders. If more ISOs are present, then out-grid view is called and you will be promted to select only one

    ServerMSUsFolder
        Example: ServerMSUsFolder="d:\Updates\Server2016"
        If ServerISOFolder is specified, then updates are being grabbed from ServerMSUsFolder.
        If ServerMSUsFolder is not specified, or empty, you are not asked for providing MSU files and no MSUs are applied.

    DCVMProcessorCount (optional)
        Example: DCVMProcessorCount=4
        Number of CPUs in DC.
        If not specified, 2 vCPUs will be set. If specified more/less, processorcount will be modified. If more vCPUs specified than available in host, the maximum possible number will be configured.

    EnableGuestServiceInterface (optional)
        Example: EnableGuestServiceInterface=$true
        If True, then Guest Services integration component will be enabled on all VMs. This allows simple file copy from host to guests.

    DCVMVersion
        Example: DCVMVersion="8.0" (optional)
        If set, version for DC will be used. It is useful if you want to keep DC older to be able to use it on previous versions of OS.

    TelemetryLevel (optional)
        Example: TelemetryLevel="Full"
        If set, scripts will not prompt for telemetry. Can be "None","Basic","Full"
        For more info see https://aka.ms/mslab/telemetry

    TelemetryNickname (optional)
        Example: TelemetryNickname="Jaromirk"
        If configured, telemetry will be sent with NickName to correlate data to specified NickName. So when leaderboards will be published, MSLab users will be able to see their own stats

    ManagementSubnetIDs
        Example: ManagementSubnetIDs=0..3
        If configured, it will add another management subnet. For example if configured 0..3, it will add 3 more subnets 10.0.1.0/24 to 10.0.3.0/24 on VLANs that 11,12, and 13. (Because allowed VLANs are 1-10)
    
    Linux (optional)
        Example: Linux=$true
        If set to $true, additional prerequisities (SSH Client, SSH Key, Packer, Packer templates) required for building Linux images will be downloaded and configured.
    
    LinuxAdminName (optional)
        Example: LinuxAdminName="linuxadmin"
        If set, local user account with that name will be created in Linux image. If not, DomainAdminName will be used as a local account.

    SshKeyPath (optional)
        Example: SshKeyPath="$($env:USERPROFILE)\.ssh\id_rsa"
        If configured, existing SSH key will be used for building and connecting to Linux images. If not, 0_Prereq.ps1 will generate a new SSH key pair and store it locally in LAB folder.

    AutoStartAfterDeploy (optional)
        Example: AutoClosePSWindows=$true
        If set to true, the PowerShell console windows will automatically close once the script has completed successfully. Best suited for use in automated deployments.

    AutoCleanup (optional)
        Example: AutoCleanUp=$true
        If set to true, after creating initial parent disks, files that are no longer necessary will be cleaned up. Best suited for use in automated deployments.

    #>
#endregion

#region $LabConfig.VMs
    <#
    Example
        Single:
        $LABConfig.VMs += @{ VMName = 'Management' ; Configuration = 'Simple'   ; ParentVHD = 'Win10_G2.vhdx'    ; MemoryStartupBytes= 1GB ; AddToolsVHD=$True }
        Multiple:
        1..2 | ForEach-Object { $VMNames="Replica" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Replica'  ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; ReplicaHDDSize = 20GB ; ReplicaLogSize = 10GB ; MemoryStartupBytes= 2GB ; VMSet= 'ReplicaSet1' ; AdditionalNetworks = $True} }
    
    VMName (Mandatory)
        Can be whatever. This name will be used as name to djoin VM.

    Configuration (Mandatory)
        'Simple' - No local storage. Just VM
        'S2D' - locally attached SSDS and HDDs. For Storage Spaces Direct. You can specify 0 for SSDnumber or HDD number if you want only one tier.
        'Shared' - Shared VHDS attached to all nodes. Simulates traditional approach with shared space/shared storage. Requires Shared VHD->Requires Clustering Components
        'Replica' - 2 Shared disks, first for Data, second for Log. Simulates traditional storage. Requires Shared VHD->Requires Clustering Components

    VMSet (Mandatory for Shared and Replica configuration)
        This is unique name for your set of VMs. You need to specify it for Spaces and Replica scenario, so script will connect shared disks to the same VMSet.

    ParentVHD (Mandatory)
        'Win2016Core_G2.vhdx'     - Windows Server 2016 Core
        'Win2016NanoHV_G2.vhdx'    - Windows Server 2016 Nano with these packages: DSC, Failover Cluster, Guest, Storage, SCVMM
        'Win2016NanoHV_G2.vhdx'   - Windows Server 2016 Nano with these packages: DSC, Failover Cluster, Guest, Storage, SCVMM, Compute, SCVMM Compute
        'Win10_G2.vhdx'        - Windows 10 if you selected to hydrate it with create client parent.

    AdditionalNetworks (Optional)
        $True - Additional networks (configured in AdditonalNetworkConfig) are added 

    AdditionalNetworkAdapters (Optional) - Hashtable or array if multiple network adapters should be connected to this virtual machine
        @{
            VirtualSwitchName  (Mandatory) - Name of the Hyper-V Switch to witch the adapter will be connected
            Mac                (Optional)  - Static MAC address of the interface otherwise default will be generated
            VlanId             (Optional)  - VLAN ID for this adapter
            IpConfiguration    (Optional)  - DHCP or hastable with specific IP configuration
            @{
                IpAddress      (Mandatory) - Static IP Address that would be injected to the OS
                Subnet         (Mandatory) 
            }
        }

    DSCMode (Optional)
        If 'Pull', VMs will be configured to Pull config from DC.

    Config
        You can specify random Config names to identify configuration that should be pulled from pull server

    NestedVirt (Optional)
        If $True, nested virt is enabled
        Enables -ExposeVirtualizationExtensions $true

    MemoryStartupBytes (Mandatory)
        Example: 512MB
        Startup memory bytes

    MemoryMinimumBytes (Optional)
        Example: 1GB
        Minimum memory bytes, must be less or equal to MemoryStartupBytes
        If not set, default is used.    

    StaticMemory (Optional)
        if $True, then static memory is configured

    AddToolsVHD (Optional)
        If $True, then ToolsVHD will be added

    Unattend
        Example: Unattend="DjoinCred"
        Possible values: "DjoinBlob", "DjoinCred", "NoDjoin", "None"
        Default "DjoinBlob"
        "DjoinBlob" uses blob, can be consumed only by Windows Server 2016+
        "DjoinCred" uses credentials. Can be used in 2008+
        "NoDjoin" inserts just local admin. For win10 use also AdditionalLocalAdmin
        "None" does not inject any unattend.

    LinuxDomainJoin
        Example: LinuxDomainJoin="No"
        Possible values: "No", "SSSD"
        Default: SSSD
          "No" VM will be just renamed, but not joined to Active Directory
          "SSSD" VM will be joined to domain online using SSSD tool

    SkipDjoin (Optional,Deprecated)
        If $True, VM will not be djoined. Default unattend used.
        Note: you might want to use AdditionalLocalAdmin variable with Windows 10 as local administrator account is by default disabled there.

    Win2012Djoin (Optional,Deprecated)
        If $True, older way to domain join will be used (Username and Password in Answer File instead of blob) as Djoin Blob works only in Win 2016

    vTPM (Optional)
        if $true, vTPM will be enabled for virtual machine. Gen2 only.

    MGMTNICs (Optional)
        Number of management NIC.
        Default is 2, maximum 8.

    DisableWCF (Optional)
        If $True, then Disable Windows Consumer Features registry is added= no consumer apps in start menu.

    AdditionalLocalAdmin (Optional, only applies if Unattend="NoDjoin")
        Example AdditionalLocalAdmin='Ned'
        Works only with SkipDjoin as you usually don't need additional local account
        When you skipDjoin on Windows10 and local administrator is disabled. Then AdditionalLocalAdmin is useful

    VMProcessorCount (Optional)
        Example VMProcessorCount=8
        Number of Processors in VM. If specified more than available in host, maximum possible number will be used.
        If "Max" is specified, maximum number of VCPUs will be used (determined from host where mslab is running)

    Generation (Optional)
        Example Generation=1
        If not specified, then it's 2. If 1, then its 1. Easy.

    EnableWinRM (Optional)
        Example EnableWinRM=$True
        If $true, then synchronous command winrm quickconfig -force -q will be run
        Only useful for 2008 and Win10

    CustomPowerShellCommands (Optional)
        Example (single command) CustomPowerShellCommands="New-Item -Name Temp -Path c:\ -ItemType Directory"
        Example (multiple commands) CustomPowerShellCommands="New-Item -Name Temp -Path c:\ -ItemType Directory","New-Item -Name Temp1 -Path c:\ -ItemType Directory"

    ManagementSubnetID (Optional)
        This will set Management NICs to defined subnet id by configuring native VLAN ID. Default is 0. If configured to 1, it will increase highest allowed VLAN by one and configure.
        For example ManagementSubnetID=1, AllowedVlans=10, then ManagementSubnetID VLAN will be configured 11. 

    #DisableTimeIC (Optional)
        Example DisableTimeIC=$true
        if $true, time Hyper-V Time Synchronization Integration Service (VMICTimeProvider) will be disabled
    #>
#endregion

#region $LabConfig.AdditionalNetworksConfig
    <#
    Example: $LABConfig.AdditionalNetworksConfig += @{ NetName = 'Storage1'; NetAddress='172.16.1.'; NetVLAN='1'; Subnet='255.255.255.0'}

    NetName
        Name of network adapter (visible from host)

    NetAddress
        Network prefix of IP address thats injected into the VM. IP Starts with 1.

    NetVLAN
        Will tag VLAN. If 0, vlan tagging will be skipped.

    Subnet
        Subnet of network.
    #>
#endregion

#region $LabConfig.VMs Examples
    <#
    Just some VMs
        $LabConfig.VMs = @(
            @{ VMName = 'Simple1'  ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; MemoryStartupBytes= 512MB }, 
            @{ VMName = 'Simple2'  ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; MemoryStartupBytes= 512MB }, 
            @{ VMName = 'Simple3'  ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; MemoryStartupBytes= 512MB }, 
            @{ VMName = 'Simple4'  ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; MemoryStartupBytes= 512MB }
        )

    or you can use this to deploy 100 simple VMs with name NanoServer1, NanoServer2...
        1..100 | ForEach-Object {"NanoServer$_"}  | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'    ; MemoryStartupBytes= 512MB } }

    or you can use this to deploy 100 server VMs with 1 Client OS with name Windows10
        1..100 | ForEach-Object {"NanoServer$_"}  | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'    ; MemoryStartupBytes= 512MB } }
        $LabConfig.VMs += @{ VMName = 'Windows10' ; Configuration = 'Simple'  ; ParentVHD = 'Win10_G2.vhdx'    ; MemoryStartupBytes= 512MB ; AddToolsVHD=$True ; DisableWCF=$True}

    or you can use this to deploy 100 nanoservers and 100 Windows 10 machines named Windows10_..
        1..100 | ForEach-Object {"NanoServer$_"}  | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'    ; MemoryStartupBytes= 512MB } }
        1..100 | ForEach-Object {"Windows10_$_"}  | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win10_G2.vhdx'          ; MemoryStartupBytes= 512MB ;   AddToolsVHD=$True ; DisableWCF=$True } }

    or Several different VMs 
        * you need to provide your GPT VHD for win 2012 (like created with convertwindowsimage script)
        $LabConfig.VMs += @{ VMName = 'Win10'            ; Configuration = 'Simple'   ; ParentVHD = 'Win10_G2.vhdx'            ; MemoryStartupBytes= 512MB ; DisableWCF=$True ; vTPM=$True ; EnableWinRM=$True }
        $LabConfig.VMs += @{ VMName = 'Win10_OOBE'       ; Configuration = 'Simple'   ; ParentVHD = 'Win10_G2.vhdx'            ; MemoryStartupBytes= 512MB ; DisableWCF=$True ; vTPM=$True ; Unattend="None" }
        $LabConfig.VMs += @{ VMName = 'Win10_NotInDomain'; Configuration = 'Simple'   ; ParentVHD = 'Win10_G2.vhdx'            ; MemoryStartupBytes= 512MB ; DisableWCF=$True ; vTPM=$True ; Unattend="NoDjoin" ; AdditionalLocalAdmin="Ned" }
        $LabConfig.VMs += @{ VMName = 'Win2016'          ; Configuration = 'Simple'   ; ParentVHD = 'Win2016_G2.vhdx'          ; MemoryStartupBytes= 512MB ; Unattend="NoDjoin" }
        $LabConfig.VMs += @{ VMName = 'Win2016_Core'     ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Core_G2.vhdx'      ; MemoryStartupBytes= 512MB }
        $LabConfig.VMs += @{ VMName = 'Win2016_Nano'     ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'    ; MemoryStartupBytes= 256MB }
        $LabConfig.VMs += @{ VMName = 'Win2012R2'        ; Configuration = 'Simple'   ; ParentVHD = 'Win2012r2_G2.vhdx'        ; MemoryStartupBytes= 512MB ; Unattend="DjoinCred" }
        $LabConfig.VMs += @{ VMName = 'Win2012R2_Core'   ; Configuration = 'Simple'   ; ParentVHD = 'Win2012r2Core_G2.vhdx'    ; MemoryStartupBytes= 512MB ; Unattend="DjoinCred" }
        $LabConfig.VMs += @{ VMName = 'Win2008R2_Core'   ; Configuration = 'Simple'   ; ParentVHD = 'Win2008R2.vhdx'           ; MemoryStartupBytes= 512MB ; Unattend="DjoinCred" ; Generation = 1}

    Example with sets of different DSC Configs
        1..2 | ForEach-Object {"Nano$_"} | ForEach-Object { $LABConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'    ; ParentVHD = 'Win2016NanoHV_G2.vhdx'    ; MemoryStartupBytes= 256MB ; DSCMode='Pull'; DSCConfig=@('LAPS_Nano_Install','LAPSConfig1')} }
        3..4 | ForEach-Object {"Nano$_"} | ForEach-Object { $LABConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'    ; ParentVHD = 'Win2016NanoHV_G2.vhdx'    ; MemoryStartupBytes= 256MB ; DSCMode='Pull'; DSCConfig=@('LAPS_Nano_Install','LAPSConfig2')} }
        1..6 | ForEach-Object {"DSC$_"}  | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'    ; ParentVHD = 'Win2016NanoHV_G2.vhdx' ; MemoryStartupBytes= 512MB ; DSCMode='Pull'; DSCConfig=@('Config1','Config2')} }
        7..12| ForEach-Object {"DSC$_"}  | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'    ; ParentVHD = 'Win2016NanoHV_G2.vhdx' ; MemoryStartupBytes= 512MB ; DSCMode='Pull'; DSCConfig='Config3'} }

    Hyperconverged S2D with nano and nested virtualization (see https://msdn.microsoft.com/en-us/virtualization/hyperv_on_windows/user_guide/nesting for more info)
        1..4 | ForEach-Object {"S2D$_"}  | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'S2D'       ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; SSDNumber = 4; SSDSize=800GB ; HDDNumber = 12 ; HDDSize= 4TB ; MemoryStartupBytes= 4GB ; NestedVirt=$True} }

    HyperConverged Storage Spaces Direct with Nano Server
        1..4 | ForEach-Object {"S2D$_"}  | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'S2D'       ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; SSDNumber = 4; SSDSize=800GB ; HDDNumber = 12 ; HDDSize= 4TB ; MemoryStartupBytes= 512MB } }

    Disaggregated Storage Spaces Direct with Nano Server
        1..4 | ForEach-Object {"Compute$_"}  | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; MemoryStartupBytes= 512MB } }
        1..4 | ForEach-Object {"SOFS$_"}     | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'S2D'      ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; SSDNumber = 12; SSDSize=800GB ; HDDNumber = 0 ; HDDSize= 4TB ; MemoryStartupBytes= 512MB } }

    "traditional" stretch cluster (like with traditional SAN)
        1..2 | ForEach-Object {"Replica$_"} | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Replica'  ; ParentVHD = 'Win2016NanoHV_G2.vhdx' ; ReplicaHDDSize = 20GB ; ReplicaLogSize = 10GB ; MemoryStartupBytes= 2GB ; VMSet= 'ReplicaSet1' ; AdditionalNetworks = $True} }
        3..4 | ForEach-Object {"Replica$_"} | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Replica'  ; ParentVHD = 'Win2016NanoHV_G2.vhdx' ; ReplicaHDDSize = 20GB ; ReplicaLogSize = 10GB ; MemoryStartupBytes= 2GB ; VMSet= 'ReplicaSet2' ; AdditionalNetworks = $True} }

    HyperConverged Storage Spaces with Shared Storage
        1..4 | ForEach-Object {"Compute$_"}  | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; MemoryStartupBytes= 512MB } }
        1..4 | ForEach-Object {"SOFS$_"}     | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Shared'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'     ; SSDNumber = 4; SSDSize=800GB ; HDDNumber = 8  ; HDDSize= 4TB ; MemoryStartupBytes= 512MB ; VMSet= 'SharedLab1'} }

    ShieldedVMs lab
        $LABConfig.VMs += @{ VMName = 'HGS' ; Configuration = 'Simple'   ; ParentVHD = 'Win2016Core_G2.vhdx'    ; MemoryStartupBytes= 512MB ; Unattend="NoDjoin" }
        1..2 | ForEach-Object { $VMNames="Compute" ; $LABConfig.VMs += @{ VMName = "$VMNames$_" ; Configuration = 'Simple'   ; ParentVHD = 'Win2016NanoHV_G2.vhdx'   ; MemoryStartupBytes= 2GB ; NestedVirt=$True ; vTPM=$True  } }

    Windows Server 2012R2 Hyper-V (8x4TB CSV + 1 1G Witness)
        1..8 | ForEach-Object {"Node$_"} | ForEach-Object { $LABConfig.VMs += @{ VMName = $_ ; Configuration = 'Shared'   ; ParentVHD = 'win2012r2Core_G2.vhdx'   ; SSDNumber = 1; SSDSize=1GB ; HDDNumber = 8  ; HDDSize= 4TB ; MemoryStartupBytes= 512MB ; VMSet= 'HyperV2012R2Lab' ;Unattend="DjoinCred" } }

    Windows Server 2012R2 Storage Spaces
        1..2 | ForEach-Object {"2012r2Spaces$_"} | ForEach-Object { $LabConfig.VMs += @{ VMName = $_ ; Configuration = 'Shared'   ; ParentVHD = 'win2012r2Core_G2.vhdx'     ; SSDNumber = 4; SSDSize=800GB ; HDDNumber = 8  ; HDDSize= 4TB ; MemoryStartupBytes= 512MB ; VMSet= '2012R2SpacesLab';Unattend="DjoinCred" } }

    #>
#endregion

# SIG # Begin signature block
# MIInogYJKoZIhvcNAQcCoIInkzCCJ48CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDTMdnQREsovuXI
# JT6zSvlmZnfcWUbEky5YPrJt7wsmNaCCDYUwggYDMIID66ADAgECAhMzAAADTU6R
# phoosHiPAAAAAANNMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMwMzE2MTg0MzI4WhcNMjQwMzE0MTg0MzI4WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDUKPcKGVa6cboGQU03ONbUKyl4WpH6Q2Xo9cP3RhXTOa6C6THltd2RfnjlUQG+
# Mwoy93iGmGKEMF/jyO2XdiwMP427j90C/PMY/d5vY31sx+udtbif7GCJ7jJ1vLzd
# j28zV4r0FGG6yEv+tUNelTIsFmmSb0FUiJtU4r5sfCThvg8dI/F9Hh6xMZoVti+k
# bVla+hlG8bf4s00VTw4uAZhjGTFCYFRytKJ3/mteg2qnwvHDOgV7QSdV5dWdd0+x
# zcuG0qgd3oCCAjH8ZmjmowkHUe4dUmbcZfXsgWlOfc6DG7JS+DeJak1DvabamYqH
# g1AUeZ0+skpkwrKwXTFwBRltAgMBAAGjggGCMIIBfjAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUId2Img2Sp05U6XI04jli2KohL+8w
# VAYDVR0RBE0wS6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEWMBQGA1UEBRMNMjMwMDEyKzUwMDUxNzAfBgNVHSMEGDAW
# gBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIw
# MTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDEx
# XzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIB
# ACMET8WuzLrDwexuTUZe9v2xrW8WGUPRQVmyJ1b/BzKYBZ5aU4Qvh5LzZe9jOExD
# YUlKb/Y73lqIIfUcEO/6W3b+7t1P9m9M1xPrZv5cfnSCguooPDq4rQe/iCdNDwHT
# 6XYW6yetxTJMOo4tUDbSS0YiZr7Mab2wkjgNFa0jRFheS9daTS1oJ/z5bNlGinxq
# 2v8azSP/GcH/t8eTrHQfcax3WbPELoGHIbryrSUaOCphsnCNUqUN5FbEMlat5MuY
# 94rGMJnq1IEd6S8ngK6C8E9SWpGEO3NDa0NlAViorpGfI0NYIbdynyOB846aWAjN
# fgThIcdzdWFvAl/6ktWXLETn8u/lYQyWGmul3yz+w06puIPD9p4KPiWBkCesKDHv
# XLrT3BbLZ8dKqSOV8DtzLFAfc9qAsNiG8EoathluJBsbyFbpebadKlErFidAX8KE
# usk8htHqiSkNxydamL/tKfx3V/vDAoQE59ysv4r3pE+zdyfMairvkFNNw7cPn1kH
# Gcww9dFSY2QwAxhMzmoM0G+M+YvBnBu5wjfxNrMRilRbxM6Cj9hKFh0YTwba6M7z
# ntHHpX3d+nabjFm/TnMRROOgIXJzYbzKKaO2g1kWeyG2QtvIR147zlrbQD4X10Ab
# rRg9CpwW7xYxywezj+iNAc+QmFzR94dzJkEPUSCJPsTFMIIHejCCBWKgAwIBAgIK
# YQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEw
# OTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYD
# VQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+la
# UKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc
# 6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4D
# dato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+
# lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nk
# kDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6
# A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmd
# X4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL
# 5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zd
# sGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3
# T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS
# 4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRI
# bmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAL
# BgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBD
# uRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEF
# BQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1h
# cnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkA
# YwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn
# 8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7
# v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0b
# pdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/
# KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvy
# CInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBp
# mLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJi
# hsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYb
# BL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbS
# oqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sL
# gOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtX
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGXMwghlvAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAANNTpGmGiiweI8AAAAA
# A00wDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIFZO
# aCeNddmwuftaLubPasHBLwQS16Om4VEb6qSQb60KMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAlHqrrI+WxQ8TvmmqQxpavSrYJ5wChfmZfueq
# 6ggjiTUukPdBByUI/6Qdhte83RMQZYrE6ZbNLzkJhrHacs4biWgawU9QKGGN6GlT
# B8/U3H1uRDerytHq0aTKbtsiaY4X0k7GTYBTRCdfFfEpY/yd+9OCBX5dyzsblunT
# RKaHLNVu2UExwFZziuaNOIj+gGz2MYFZRqiRMQYujVIRxaXiKv8FFBQp2NWneVQ6
# ZIaiTPo5m8czvxb2xovpqlnfkZp4cRarFni/W6V2HRkKpU1FkXiRRAOgR3X2sArc
# Ne3FlxGd7Bspg8vEAAbhdWWnYr44A0CiiV4JRNnv4AYxQEjXSqGCFv0wghb5Bgor
# BgEEAYI3AwMBMYIW6TCCFuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCBrUFhOhLFlw97rfhlMWhA1d+jNCrQL0rw5
# EeP2/MyS0AIGZIthwxI6GBMyMDIzMDYxNjE5NTMwNi41MjNaMASAAgH0oIHQpIHN
# MIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQL
# ExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjo0OUJDLUUzN0EtMjMzQzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZaCCEVQwggcMMIIE9KADAgECAhMzAAABwFWkjcNkFcVLAAEA
# AAHAMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MB4XDTIyMTEwNDE5MDEyNVoXDTI0MDIwMjE5MDEyNVowgcoxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVy
# aWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjQ5QkMtRTM3
# QS0yMzNDMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvO1g+2NhhmBQvlGlCTOMaFw3
# jbIhUdDTqkaQhRpdHVb+huU/0HNhLmoRYvrp7z5vIoL1MPAkVBFWJIkrcG7sSred
# nyZwreY207C9n8XivL9ZBOQeiUeL/TMlJ6VinrcafbhdnkNO5JDlPozC9dGySiub
# ryds5GKtu69D1wNat9DIQl6alFO6pncZK4RIzfv+KzkM7RkY3vHphV0C8EFUpF+l
# ysaGJXFf9QsUUHwj9XKWHfc9BfhLoCReXUzvgrspdFmVnA9ATYXmidSjrshf8A+E
# 0/FpTdhXPI9XXqsZDHBqr7DlYoSCU3lvrVDRu1p5pHHf7s3kM16HpK6arDtY3ai1
# soASmEpv3C2N/y5MDBApDd4SpSkLMa7+6es/daeS7zdH1qdCa2RoJPM6Eh/6YmBf
# ofhfLQofKPJl34ALlZWK5AzVtFRNOXacoj6MAG2dT8Rc5fpKCH1E3n7Zje0dK24Q
# VfSv/YOxw52ECaMLlW5PhHT3ZINNaCmRgcHCTClOKzC2FOr03YBc2zPOW6bIVdXl
# oPmBMVaE+thXqPmANBw0YsncaOkVggjDb5O5VqOp98MklHpJoJI6pk5zAlx8/OtC
# 7FutrdtYNUC6ykXzMAPFuYkWGgx/W7A0itKW8WzYzwO3bAhprwznouGZmRiw2k8p
# en80BzqzdyPvbzTxQsMCAwEAAaOCATYwggEyMB0GA1UdDgQWBBQARMZ480jwpK3P
# 6quVWUEJ0c30hTAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNV
# HR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2Ny
# bC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYI
# KwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAy
# MDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0G
# CSqGSIb3DQEBCwUAA4ICAQCtTh0EQn16kKQyCeVk9Vc10m6L0EwLRo3ATRouP7Yd
# 2hWeEB2Y4ZF4CJKe9qfXWGJKzV7tMUm6DAsBKYH/nT+8ybI8uJiHGnfnVi6Sh7gF
# jnTpfh1j1T90H/uLeoFjpOn/+eoCoJmorW5Gb2ezlTlo5I0kNAubxtCxqbLizuPN
# Pob8kRAKQgv+4/CC1JmiUFG0uKINlKj9SsHcrWeBBQHX62nNgziIwT44JqHrA02I
# 6cmQAi9BZcsf57OOLpRYlzoPH3x/+ldSySXAmyLq2uSbWtQuD84I/0ZgS/B5L3ew
# qTdiE1KbKX89MW5JqCK/yI/mAIQammAlHPqU9eZZTMPOHQs0XrpCijlk+qyo2JaH
# iySww6nuPqXzU3sEj3VW00YiVSayKEu1IrRzzX3La8qe6OqLTvK/6gu5XdKq7TT8
# 52nB6IP0QM+Budtr4Fbx4/svpKHGpK9/zBuaHHDXX5AoSksh/kSDYKfefQIhIfQJ
# JzoE3X+MimMJrgrwZXltb6j1IL0HY3qCpa03Ghgi0ITzqfkw3Man3G8kB1Ql+SeN
# ciPUj73Kn2veJenGLtT8JkUM9RUi0woO0iuY4tJnYuS+SeqavXUOWqUYVY19FIr1
# PLqpmWkbrO5xKjkyOHoAmLxjNbKjOnkAwft+1G00kulKqzqPbm+Sn+47JsGQFhNG
# bTCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQEL
# BQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNV
# BAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4X
# DTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM
# 57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm
# 95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzB
# RMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBb
# fowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCO
# Mcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYw
# XE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW
# /aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/w
# EPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPK
# Z6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2
# BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfH
# CBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYB
# BAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8v
# BO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYM
# KwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEF
# BQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBW
# BgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUH
# AQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# L2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsF
# AAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518Jx
# Nj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+
# iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2
# pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefw
# C2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7
# T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFO
# Ry3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhL
# mm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3L
# wUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5
# m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE
# 0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLLMIICNAIB
# ATCB+KGB0KSBzTCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UE
# CxMdVGhhbGVzIFRTUyBFU046NDlCQy1FMzdBLTIzM0MxJTAjBgNVBAMTHE1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVABAQ7ExF19Kk
# wVL1E3Ad8k0Peb6doIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTAwDQYJKoZIhvcNAQEFBQACBQDoNzGwMCIYDzIwMjMwNjE3MDMwODMyWhgPMjAy
# MzA2MTgwMzA4MzJaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAOg3MbACAQAwBwIB
# AAICBnQwBwIBAAICEYMwCgIFAOg4gzACAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYK
# KwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUF
# AAOBgQCQtxE2CT4kopYxHu9Tckog69Kk7u9Y1FvTXyvDaxN3BYS+hPd2iyEj0JjG
# uEYuhB7uGQDhuLyfxPRr4dngVl9iPXYGUGnl5FiukTrH1HcjR4oyyD3AO3mp3hUa
# umN//HuMT4yaAYPOVcYfJUma64BUp5wags44sP/crOgMcdW7fTGCBA0wggQJAgEB
# MIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABwFWkjcNkFcVL
# AAEAAAHAMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcN
# AQkQAQQwLwYJKoZIhvcNAQkEMSIEIMlJN02T4QrFnyYCK3HmioclW/wTlkTl0IGB
# d7/O25A1MIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgWvFYolIIXME0zK/W
# 6XsCkkYX7lYNb9yA8JxwY04Pk08wgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMAITMwAAAcBVpI3DZBXFSwABAAABwDAiBCB9FNiUB0Z0G/FSHBgE
# GyPMhPduFMpgcbbwf1XvQCO3uzANBgkqhkiG9w0BAQsFAASCAgAVnpLCs0NUNPjk
# odzfB6vay+u7Ed57EC8s/v5Ij2jl0vHQCNDgY+/ZwbHenHppkE4b6eNm1bq/l4qG
# UBdxz9/N4ZsdaeZG0L5Qow3q0RvTOYfgcK1m4FTgHsaRa3pMkWzL5vIEaer4tmfb
# eLYDjOBKTpjYSvUITxfdBDfMnQ4CIpf827VFT/bVcG00eEYUUuL3mS7pyC4UkINY
# ndJO6V9PykEUzq3j38JJW974vpWkTld3Q+DEcUyUmPiK7MYZJi8xVZotMfeTP+R7
# XIRQZO3rXOefgm57BRZpJs3sF0Dxst4YQLUwwaEg+4lcugSvAbiw4VYCijhTucPV
# KFAWYMnYyMgBvzrgx/y0/VA5Js57EcWQlJfLUWFVGvaNNM1RdW3zSNxUtR6nedt7
# heNuqbhnDm1eXTWZfxSoH+tzNK0sG/632+WaQ8AydVi/Nm9SKGHJ26R9DuQxRof4
# uBGFoX9IJPDX/h4iZVD+PZGZIqfhPpjkGGmIybfL9qKq0hJQgck9hS6lfZX56lV6
# Wbj+VpQklhD/8wX3gMcAeKG7e368NeE3sq0D5XhJD1udkAnkYq6ky8i3eFgSAehx
# mAXj0RK1v/5PboD7zjKkGORBtZ+39fucNuHIft/XZdqHi9RGwgLagv29RDsJ0bZZ
# SaiFLaXDqFWRyl5/HTZxSwtI5rTprg==
# SIG # End signature block
