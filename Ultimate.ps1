Do {
IF ($Computer -eq $null) {
    [string]$Computer = $args[0]
 }

Write-Host Welcome to the Ultimate Menu
#Ultimate Menu - Dev by Daniel A

Start-Process -Filepath ".\PsExec.exe" -ArgumentList "\\$Computer -s winrm.cmd quickconfig -q"

#Data Gather
$diskold = Get-WmiObject Win32_LogicalDisk -ComputerName $Computer -Filter "DeviceID='C:'" | Select-Object Size, FreeSpace
$Disk = ("{0}GB free" -f [math]::truncate($diskold.FreeSpace / 1GB))
if ([math]::truncate($diskold.FreeSpace / 1GB) -lt 7) {$DiskColor = 'Red'} else {$DiskColor = 'Green'}
$ComputerInfo = Get-WmiObject Win32_ComputerSystem -Computer $Computer
$OSInfo = (Get-WmiObject Win32_OperatingSystem -computer $computer)
$BiosAge = Invoke-Command -computername $Computer -scriptblock {((Get-CIMInstance Win32_BIOS).ReleaseDate).tostring("MM/yyy")}
$BiosAgeComp = Invoke-Command -computername $Computer -scriptblock {((Get-CIMInstance Win32_BIOS).ReleaseDate)}
$BiosAgeCompare = ((get-date).AddDays(-300))
if ($BiosAgeComp -lt $BiosAgeCompare) {$BiosColor = 'Red'} else {$BiosColor = 'Green'}
$Boot0 = (gwmi win32_operatingsystem -ComputerName $computer).lastbootuptime
$boottime = [Management.ManagementDateTimeConverter]::ToDateTime($Boot0)
if ((get-date).AddDays(-0.5) -gt $boottime) {$bootcolor = 'Red'} else {$bootcolor = 'Green'}
$Serial = (gwmi -ComputerName $Computer win32_bios).SerialNumber
$User = ($ComputerInfo.UserName).Trim("DOMAIN\")
$Name = (Get-ADuser -Identity "$User" -Properties *)
$Memory0 = Get-WmiObject -class "win32_physicalmemory" -namespace "root\CIMV2" -ComputerName $Computer
$Memory = "$((($Memory0).Capacity | Measure-Object -Sum).Sum/1GB)GB"
$GDrives = Import-Csv "C:\Share\Scripts\GDrives.csv"
$Match = ($GDrives | where-object {$_.samaccountname -eq "$User"}).homedirectory
C:\Share\'Master Hacker Tools'\owexec.exe -c $Computer -k "cmd.exe /c net use > \\SHARE\FOLDER\MapDriveOutput.txt" -u DOMAIN\$User -nowait
$MDrives = (Get-Content -Path \\SERVER\FOLDER\MapDriveOutput.txt)
$CompBday = ((Get-ADComputer -Identity $Computer -Properties *).created).ToString(‘M/d/y’)

$OSBuild = switch (($OSInfo).Version){
"10.0 (10240)" {1507}
"10.0.10240" {1507}

"10.0 (10586)" {1511}
"10.0.10586" {1511}

"10.0 (14393)" {1607}
"10.0.14393" {1607}

"10.0 (15063)" {1703}
"10.0.15063" {1703}

"10.0 (16299)" {1709}
"10.0.16299" {1709}

"10.0 (17134)" {1803}
"10.0.17134" {1803}

"10.0 (17763)" {1809}
"10.0.17763" {1809}

"10.0 (18362)" {1903}
"10.0.18362" {1903}

"10.0 (18363)" {1909}
"10.0.18363" {1909}

"10.0 (19041)" {2004}
"10.0.19041" {2004}

"10.0 (19042)" {"20H2"}
"10.0.19042" {"20H2"}

"10.0 (19043)" {"21H1"}
"10.0.19043" {"21H1"}

}
if ($OSBuild -like "20H2" -or "21H1") {$OSBuildColor = 'Green'} else {$OSBuildColor = 'Red'}


Invoke-Command -ComputerName $Computer -ScriptBlock {Set-ExecutionPolicy unrestricted}

Invoke-Command -ComputerName $Computer -ScriptBlock {
$User= "NT AUTHORITY\SYSTEM"
$Task = "SFC"
$Action= New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "sfc /scannow"
Register-ScheduledTask -TaskName "$Task" -User $User -Action $Action -RunLevel Highest –Force
(Get-ScheduledTask -TaskName $Task).State
Start-ScheduledTask -TaskName $Task
Start-Sleep -Seconds 5
(Get-ScheduledTask -TaskName $Task).State
}

#Set functions for menus
function Show-Menu
{
     param (
           [string]$Title = 'Ultimate Menu'
     )
     cls
     Write-Host "================ $Title ================"
     Write-Host Name: $Name.DisplayName - $Name.Title -foregroundcolor Gray
     Write-Host Location: $Name.physicalDeliveryOfficeName -foregroundcolor DarkGray
     Write-Host "Username: $User"  -foregroundcolor Yellow
     Write-Host Computer Name: $Computer birthed $CompBday
     Write-Host Model: $ComputerInfo.Model -foregroundcolor Magenta
     Write-Host OS: ($osinfo.caption).TrimStart("Microsoft ") "$OSBuild" "Arc:"$osinfo.osarchitecture -ForegroundColor $OSBuildColor
     Write-Host Bios Updated: $BiosAge -ForegroundColor $Bioscolor
     Write-Host Memory: $Memory -ForegroundColor Gray
     Write-Host "Serial: $Serial" -foregroundcolor Magenta
     Write-Host Last Boot: $Boottime -ForegroundColor $Bootcolor
     Write-Host           
     Write-Host "1: Press '1' for Remote Control" -ForegroundColor Green
     Write-Host "2: Press '2' to Get Map Drive List" -ForegroundColor Magenta
     Write-Host "3: Press '3' to Run Disk Cleanup " -ForegroundColor Cyan -nonewline; Write-Host $Disk -ForegroundColor $diskcolor
     Write-Host "4: Press '4' to Run SFC" -ForegroundColor Blue -BackgroundColor Cyan
     Write-Host
     Write-Host "5: Press '5' for Software Menu" -ForegroundColor Gray
     Write-Host "6: Press '6' for Quick Fix Menu" -ForegroundColor Blue -BackgroundColor White
     Write-Host "7: Press '7' for Printer Control Menu" -ForegroundColor Yellow
     Write-Host "8: Press '8' for Granular Details" -ForegroundColor DarkGray -BackgroundColor Black
     Write-Host "9: Press '9' for RDP MSTSC" -ForegroundColor Green
     Write-Host "10: Press '10' for Continuous Ping" -ForegroundColor Cyan
     Write-Host "11: Press '11' to SHUTDOWN remote computer" -ForegroundColor Red
     Write-Host "12: Press '12' to RESTART remote computer" -ForegroundColor Red
     Write-Host "13: Press '13' For Windows Explorer to C Drive" -ForegroundColor Cyan
     Write-Host "14: Press '14' For Windows Explorer User's folder" -ForegroundColor Cyan
     Write-Host "15: Press '15' For Windows Updates" -ForegroundColor White
     Write-Host "16: Press '16' For Lizard" -ForegroundColor Cyan
     Write-Host "17: Press '17' For Event Logs" -ForegroundColor White
     Write-Host "18: Press '18' For Services" -ForegroundColor White
     Write-Host "Q: Press 'Q' to quit." -ForegroundColor Red
}

function SoftwareMenu
{
     param (
           [string]$Title2 = 'Remote Computer Software Menu'
     )
     cls
     Write-Host "============ $Title2 ============"
     Write-Host "1: Press '1' for Adobe Acrobat Pro CC Suite" -ForegroundColor Green
     Write-Host "2: Press '2' for Adobe Reader DC" -ForegroundColor Green
     Write-Host "3: Press '3' for Drive File Stream" -ForegroundColor Green
     Write-Host "4: Press '4' for Jabber" -ForegroundColor Green
     Write-Host "5: Press '5' for SANITIZED" -ForegroundColor Green
     Write-Host "6: Press '6' for VPN" -ForegroundColor Green
     Write-Host "7: Press '7' for PS Engine Install" -ForegroundColor Green
     Write-Host "8: Press '8' to Remove Adobe Reader DC" -ForegroundColor Red
     Write-Host "9: Press '9' to Remove Adobe Reader XI" -ForegroundColor Red
     Write-Host "10: Press '10' to Remove Old Google Drive" -ForegroundColor Red
     Write-Host "11: Press '11' to Remove old Firefox" -ForegroundColor Red -NoNewline; Write-Host " and Install Latest Version" -ForegroundColor Green
     Write-Host "12: Press '12' For Chocolate" -ForegroundColor Cyan
     Write-Host "13: Press '13' to Remove Teams" -ForegroundColor Red -NoNewline; Write-Host " and Install Latest Version" -ForegroundColor Green
     Write-Host "14: Press '14' to Install O365" -ForegroundColor Green
     Write-Host 
     Write-Host "B: Press 'B' to Go Back." -ForegroundColor Cyan
     Write-Host "Q: Press 'Q' to Exit" -ForegroundColor Red
}

function Chocolate
{
     param (
           [string]$Title5 = 'Chocolatey Install Menu'
     )
     Write-Host "Enter your options:
                adobereader, arduino, vlc..." -ForegroundColor Green
}

function QuickFix-Menu
{
     param (
           [string]$Title3 = 'Quick Fix Menu'
     )
     cls
     Write-Host "============ $Title3 ============"
     Write-Host "1: Press '1' for Adobe License Fix on single computer" -ForegroundColor Magenta
     Write-Host "2: Press '2' for Mapping a Network Drive" -ForegroundColor Cyan
     Write-Host "3: Press '3' for New Outlook Profile (2010, 2013, 2016)" -ForegroundColor Green
     Write-Host "4: Press '4' for Disabling SNMP on all Printers" -ForegroundColor DarkCyan
     Write-Host "5: Press '5' for Updating to 20H2" -ForegroundColor Gray
     Write-Host "6: Press '6' for BIOS update" -ForegroundColor Red
     Write-Host 
     Write-Host "B: Press 'B' to Go Back." -ForegroundColor Cyan
     Write-Host "Q: Press 'Q' to Exit" -ForegroundColor Red
}

function PrinterControl-Menu
{
     param (
           [string]$Title4 = 'Printer Control Menu'
     )
     cls
     Write-Host "============ $Title4 ============"
     Write-Host "1: Press '1' to List Printers" -ForegroundColor Cyan
     Write-Host "2: Press '2' to Remove Printers from a list" -ForegroundColor Red
     Write-Host "3: Press '3' Delete Print Jobs" -ForegroundColor Red -NoNewline; Write-Host " and Restart Print Spooler" -ForegroundColor Green
     Write-Host 
     Write-Host "B: Press 'B' to Go Back." -ForegroundColor Cyan
     Write-Host "Q: Press 'Q' to Exit" -ForegroundColor Red
}

function Update-Install
    {
    Copy-Item "C:\Share\Scripts\Remote Operations\WU.ps1" -Destination "\\$Computer\c$\Windows\Temp"
    Invoke-Command -ComputerName $Computer -ScriptBlock {
        Install-PackageProvider -Name NuGet -Force
        Import-PackageProvider NuGet -Force
        Install-Module PSWindowsUpdate
        Get-Command –module PSWindowsUpdate
        Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false
        $User= "NT AUTHORITY\SYSTEM"
        $Action= New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "C:\windows\temp\wu.ps1"
        Register-ScheduledTask -TaskName "Dupdate" -User $User -Action $Action -RunLevel Highest –Force
        }
    }

function Update-Windows
    {
    (Get-ScheduledTask -CimSession $computer | where {$_.TaskName -eq "dupdate"}).state
    Invoke-Command -ComputerName $Computer -ScriptBlock {Start-ScheduledTask -TaskName dupdate}
    Start-Sleep -Seconds 10
    if ((Get-ScheduledTask -CimSession $computer | where {$_.TaskName -eq "dupdate"}).state -eq "Running"){Write-Host Updating windows... this may take some time -ForegroundColor Green 
    start powershell "C:\Share\Scripts\'Environment Variables'\UpdateRunning.ps1 $Computer" -WindowStyle Minimized
    } else {Write-Host "Not running... check script" -ForegroundColor Red}
    Start-Sleep -Seconds 5
    }

#Start the Menu!!!

do
{
     Show-Menu
     $input = Read-Host "Please make a selection"
     switch ($input)
     {
           '1' {
                'Remote Control launching...'
                & start-process "C:\Share\CfgMgr Remote Control\CmRcViewer.exe" $Computer
           } '2' {
#This part is just a little funky grabbing mapped drives but not displaying them on the screen until you go back to the main menu...
                'Got it!'
                $MDrives
           } '3' {
                'Running Disk Cleanup... This will take a few minutes...'
                #Copy Cleanup! to remote computer
                Copy-Item "\\SERVER\SOFTWARE\Cleanup.exe" -Destination "\\$Computer\c$\Windows\Temp"
                Invoke-Command -ComputerName $Computer -ScriptBlock {Start-Process C:\Windows\Temp\cleanup.exe /autorun -Wait}
                $disknew = Get-WmiObject Win32_LogicalDisk -ComputerName $Computer -Filter "DeviceID='C:'" | Select-Object Size, FreeSpace
                Write-Host Freespace after:
                Write-Host ("{0}GB free" -f [math]::truncate($disknew.FreeSpace / 1GB))
                $Disk = ("{0}GB free" -f [math]::truncate($disknew.FreeSpace / 1GB))
           } '4' {
                    #Available. SFC moved to Scheduled Task
           } '5' {
#Start Software Menu                    
                    do
                        {
                            SoftwareMenu
                            $inputSoftware = Read-Host "Please make a selection"
                            switch ($inputSoftware)
                            {
                             '1' {
                                   # 'Installing Adobe Acrobat Pro 2017'
                                    'Finding Adobe Reader installation...'
                                    if (Test-Path \\$Computer\c$\'Program Files (x86)\Adobe\Acrobat Reader DC'\Reader\AcroRd32.exe) 
                                        {
                                        Write-Host "Found Adobe Reader DC x86"
                                        $Adobe0 = (Get-WmiObject -Class win32_product -Filter "name='adobe acrobat reader dc'" -ComputerName $Computer)
                                        $Adobe1 = ($Adobe0.identifyingnumber)
                                        'Found! Removing Adobe Reader DC...'
                                        (C:\Share\SysinternalsSuite\PsExec.exe \\$Computer -s msiexec.exe /x $adobe1 /q)
                                        Sleep -Seconds 5
                                        if (Test-Path \\$Computer\c$\'Program Files (x86)\Adobe\Acrobat Reader DC'\Reader\AcroRd32.exe) 
                                            {
                                            Write-Host "Uninstall didn't work..."
                                            } else { Write-Host "Uninstalled!" }
                                        } else {Write-Host "Adobe Reader DC not found"}
                                    Write-Host Copying files...
                                    Copy-Item "\\SERVER\SOFTWARE\Adobe Acrobat Pro DC_en_US_WIN_64\Adobe Acrobat Pro DC" -Recurse -Destination "\\$Computer\c$\Windows\Temp"
                                    Write-Host Done! Installing...
                                    (C:\Share\SysinternalsSuite\PsExec.exe \\$Computer -s msiexec.exe /i "c:\Windows\Temp\Adobe Acrobat Pro DC\Build\Adobe Acrobat Pro DC.msi" ALLUSERS=1 /q /log AdobeCCLog.log)
                                    Invoke-Command -ComputerName $Computer -ScriptBlock {start-process C:\Windows\Temp\'Adobe Acrobat Pro DC'\Build\Setup\APRO21.0\'Adobe Acrobat'\Setup.exe "--silent" -Wait}
                                    Start-Sleep -s 5
                                    Write-Host Install completed! Checking for success...
                                    if (Test-Path \\$Computer\c$\'Program Files (x86)\Adobe\Acrobat DC\Acrobat'\Acrobat.exe) {Write-Host "Install successful!" -ForegroundColor Green} else { Write-Host "Install failed... see logs..." -ForegroundColor Red}
                                    Start-sleep -s 5
                            }'2' {
                                    'Installing Adobe Reader DC'
                                    (C:\Share\SysinternalsSuite\PsExec.exe \\$Computer -s msiexec.exe /i "\\SERVER\SOFTWARE\Adobe\Acrobat Reader DC\AcroRead.msi" /q)
                                    Start-sleep -s 5
                            } '3' {
                                    'Installing Drive File Stream'
                                    Copy-Item "\\SERVER\SOFTWARE\Google\Google Drive FileStream\GoogleDriveFSSetup.exe" -Destination "\\$Computer\c$\Windows\Temp"
                                    (C:\Share\SysinternalsSuite\PsExec.exe \\$Computer -s cmd /c "c:\Windows\Temp\GoogleDriveFSSetup.exe --silent")
                            } '4' {
                                    'Installing Cisco Jabber'
                                    Invoke-Expression -Command "C:\Share\Scripts\'Application Installs'\'Jabber Install Remote Computer'.ps1"
                            } '5' {
                                    #SANITIZED
                            } '6' {
                                    Invoke-Expression -Command "C:\Share\Scripts\'Application Installs'\'VPN Client Install'.ps1"
                                    Start-sleep -s 5
                            } '7' {
                                    #Install engine
                                    Copy-Item "\\SERVER\SOFTWARE\PowerSchool Engine Installer\PSScheduling-Engine-Install-win.exe" -Destination "\\$Computer\c$\Windows\Temp"
                                    Invoke-Command -ComputerName $Computer -ScriptBlock {start-process c:\Windows\Temp\PSScheduling-Engine-Install-win.exe "/S"}
                                    Start-Sleep -s 10
                                    if (Test-Path -path "\\$Computer\c$\Program Files (x86)\Pearson\PSSE\SchedulingLauncher.jar") {Write-Host PS Engine Installed. Setting permissions... -ForegroundColor Green} Else {
                                    Write-Host Something did not work right... Maybe have the user try restarting? -ForegroundColor Red
                                    Return}
                                    #Set Full Control Permissions
                                    $path = "\\$Computer\c$\Program Files (x86)\Pearson"
                                    $acl = Get-Acl -Path $path
                                    $permission = "$user", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow"
                                    $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $permission
                                    $acl.SetAccessRule($rule)
                                    $acl | Set-Acl -Path $path
                                    Write-Host Permissions set! Check to make sure: -ForegroundColor Green
                                    (Get-ACL -Path $path).Access | Format-Table IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -AutoSize
                                    Pause
                            } '8' {
                                    'Finding Adobe Reader installation...'
                                    if (Test-Path \\$Computer\c$\'Program Files (x86)\Adobe\Acrobat Reader DC'\Reader\AcroRd32.exe) 
                                        {
                                        Write-Host "Found Adobe Reader DC x86"
                                        $Adobe0 = (Get-WmiObject -Class win32_product -Filter "name='adobe acrobat reader dc'" -ComputerName $Computer)
                                        $Adobe1 = ($Adobe0.identifyingnumber)
                                        'Found! Removing Adobe Reader DC...'
                                        (C:\Share\SysinternalsSuite\PsExec.exe \\$Computer -s msiexec.exe /x $adobe1 /q)
                                        Sleep -Seconds 5
                                        if (Test-Path \\$Computer\c$\'Program Files (x86)\Adobe\Acrobat Reader DC'\Reader\AcroRd32.exe) 
                                            {
                                            Write-Host "Uninstall didn't work..."
                                            } else { Write-Host "Uninstalled!" }
                                        } else {Write-Host "Adobe Reader DC not found"}
                                        Start-sleep -s 5
                            } '9' {
                                    'Finding Adobe Reader XI installation...'
                                    if (Test-Path \\$Computer\c$\'Program Files (x86)\Adobe\Reader 11.0'\Reader\AcroRd32.exe) 
                                        {
                                        Write-Host "Found Adobe Reader XI x86"
                                        $Adobe0 = (Get-WmiObject -Class win32_product -Filter "name='adobe reader xi'" -ComputerName $Computer)
                                        $Adobe1 = ($Adobe0.identifyingnumber)
                                        'Found! Removing Adobe Reader XI...'
                                        (C:\Share\SysinternalsSuite\PsExec.exe \\$Computer -s msiexec.exe /x $adobe1 /q)
                                        Sleep -Seconds 5
                                        if (Test-Path \\$Computer\c$\'Program Files (x86)\Adobe\Reader 11.0'\Reader\AcroRd32.exe) 
                                            {
                                            Write-Host "Uninstall didn't work..."
                                            } else { Write-Host "Uninstalled!" }
                                        } else {Write-Host "Adobe Reader XI not found"}
                                        start-sleep -s 5
                            } '10' {
                                    'Removing Google Drive'
                                    $Google0 = (Get-WmiObject -Class win32_product -Filter "name='google drive'" -ComputerName $Computer)
                                    $Google1 = ($Google0.identifyingnumber)
                                    (C:\Share\SysinternalsSuite\PsExec.exe \\$Computer -s msiexec.exe /x $Google1 /q)
                            } '11' {
                                    'Removing Old Firefox and Installing Latest Version. This WILL kill their bookmarks, Continue?'
                                    Pause
                                    Invoke-Expression -Command "C:\Share\Scripts\'Application Installs\Firefox Find Remove Install and set chrome default'.ps1"
                            } '12' {
                                    Chocolate
                                    Invoke-Command -ComputerName $Computer -ScriptBlock {Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))}
                                    $inputchoco = Read-Host "Please enter application names"
                                    Invoke-Command -ComputerName $Computer -ScriptBlock {choco install $inputchoco -y --force}
                            } '13' {
                                    'Removing Teams...'
                                    $TeamsPath1 = "\\$computer\c$\users\$user\appdata\Local\Microsoft\Teams"
                                    $TeamsPath2 = "\\$computer\c$\users\$user\appdata\Roaming\Microsoft\Teams"
                                    $TeamsPath3 = "\\$computer\c$\users\$user\appdata\Roaming\Microsoft Teams"
                                    $TeamsPath4 = "\\$computer\c$\users\$user\appdata\Roaming\Teams"
                                    $TeamsUpdateExePath = "\\$computer\c$\users\$user\appdata\Local\Microsoft\Teams\Update.exe"
                                    (C:\Share\SysinternalsSuite\PsExec.exe \\$Computer -s cmd /c "$TeamsUpdateExePath -uninstall -s")
                                    $Teamfolders = $TeamsPath1,$TeamsPath2,$TeamsPath3,$TeamsPath4
                                    foreach ($folder in $Teamfolders) {
                                    Get-ChildItem -path $folder -Include *.* -file -Recurse | Remove-Item -Force
                                    Remove-Item $folder -Confirm -Force -Recurse
                                    }
                                    'Copying Teams to desktop'
                                    Copy-Item -Path C:\Share\Applications\Teams_windows_x64.exe -Destination \\$computer\c$\users\$user\desktop        
                            } '14' {
                                    Write-Host Installing Office 365
                                    Invoke-Expression -Command "C:\Share\Scripts\'Application Installs'\'O365 App Install - Remote Computer.ps1'"
                            } 'Q'  {
                                    Exit
                                  }                        
                            }
                            
                        }
                    until ($inputSoftware -eq 'B')
#End Software Menu

#Start Chocolate                    
                    do
                        {
                            
                        }
                    until ($inputSoftware -eq 'B')
#End Chocolate

            } '6' {
#Start Quick Fix Menu                    
                    do
                        {
                            QuickFix-Menu
                            $inputFix = Read-Host "Please make a selection"
                            switch ($inputFix)
                            {
                              '1' {
                                    'Fixing Adobe Licensing on computer...BETA'
                                    #SANITIZED
                            } '2' {
                                    'Mapping Network Drive... need more info please'
                                    
                                    Write-Host Current list of mapped drives: 
                                    Do {
                                        Write-Host 'To map G drive press 1'
                                        Write-Host 'To map I drive press 2'
                                        Write-Host 'To Fix the G drive for someone who needs it back now, press 3'
                                        Write-Host 'B to go back'
                                        Write-Host
                                        Write-Host 'Current:' 
                                        $MDrives
                                        $mapdriveletter = Read-Host "Please make a selection"
                                        switch ($mapdriveletter)
                                               {
                                                 '1' {
                                                      'Mapping G drive...'
                                                      $GDrive = $Answer.HomeDirectory
                                                      C:\Share\'Master Hacker Tools'\owexec.exe -c $Computer -k "cmd.exe /c net use G: $Gdrive" -u DOMAIN\$User -nowait
                                                      C:\Share\'Master Hacker Tools'\owexec.exe -c $Computer -k "cmd.exe /c net use > \\SERVER\FOLDER\MapDriveOutput.txt" -u DOMAIN\$User -nowait
                                                      $MDrives = (Get-Content -Path \\SERVER\FOLDER\MapDriveOutput.txt)
                                        
                                                     }
                                                 '2' {
                                                      Invoke-Expression -Command "C:\Share\Scripts\Ultimate\'Map Network Drive'.ps1"
                                                      C:\Share\'Master Hacker Tools'\owexec.exe -c $Computer -k "cmd.exe /c net use > \\SERVER\FOLDER\MapDriveOutput.txt" -u DOMAIN\$User -nowait
                                                      $MDrives = (Get-Content -Path \\SERVER\FOLDER\MapDriveOutput.txt)
                                                     }
                                                '3' {
                                                      Set-ADUser -Identity $user -HomeDirectory $Match -HomeDrive G
                                                      Write-Host 'Reboot now'
                                                      pause
                                                     }
		                                        }
                                        } Until ($mapdriveletter -eq 'b')

                            } '3' {
                                    #Kill Outlook on remote computer
                                    if($process=(get-process -computername $Computer 'outlook' -ErrorAction SilentlyContinue))
                                        {
                                        Write-Host "Outlook is running so close it.." -ForegroundColor Green
                                        kill($process)
                                        Write-Host "Outlook is stopped " -ForegroundColor Green
                                        }

                                    #Set variables
                                    $RanNum = (Get-Random -Maximum 1000)
                                    Set-Location \\$Computer\C$

                                    #Checking for Office 2016
                                    if (Test-Path 'Program Files (x86)\Microsoft Office\Office16\OUTLOOK.EXE')
                                        {
                                        C:\Share\'Master Hacker Tools'\owexec.exe -c $Computer -k "cmd.exe /c reg add HKCU\Software\Microsoft\Office\16.0\Outlook\Profiles\Outlook$RanNum" -u DOMAIN\$User -nowait
                                        C:\Share\'Master Hacker Tools'\owexec.exe -c $Computer -k "cmd.exe /c reg add HKCU\Software\Microsoft\Office\16.0\Outlook /v DefaultProfile /t REG_SZ /d Outlook$RanNum /F" -u DOMAIN\$User -nowait
                                        }
                                    if (Test-Path 'Program Files\Microsoft Office\Office16\OUTLOOK.EXE')
                                        {
                                        C:\Share\'Master Hacker Tools'\owexec.exe -c $Computer -k "cmd.exe /c reg add HKCU\Software\Microsoft\Office\16.0\Outlook\Profiles\Outlook$RanNum" -u DOMAIN\$User -nowait
                                        C:\Share\'Master Hacker Tools'\owexec.exe -c $Computer -k "cmd.exe /c reg add HKCU\Software\Microsoft\Office\16.0\Outlook /v DefaultProfile /t REG_SZ /d Outlook$RanNum /F" -u DOMAIN\$User -nowait
                                        }
                                    
                                    #Checking for Office 2013
                                    if (Test-Path 'Program Files (x86)\Microsoft Office\Office15\OUTLOOK.EXE')
                                        {
                                        C:\Share\'Master Hacker Tools'\owexec.exe -c $Computer -k "cmd.exe /c reg add HKCU\Software\Microsoft\Office\15.0\Outlook\Profiles\Outlook$RanNum" -u DOMAIN\$User -nowait
                                        C:\Share\'Master Hacker Tools'\owexec.exe -c $Computer -k "cmd.exe /c reg add HKCU\Software\Microsoft\Office\15.0\Outlook /v DefaultProfile /t REG_SZ /d Outlook$RanNum /F" -u DOMAIN\$User -nowait
                                        }
                                    if (Test-Path 'Program Files\Microsoft Office\Office15\OUTLOOK.EXE')
                                        {
                                        C:\Share\'Master Hacker Tools'\owexec.exe -c $Computer -k "cmd.exe /c reg add HKCU\Software\Microsoft\Office\15.0\Outlook\Profiles\Outlook$RanNum" -u DOMAIN\$User -nowait
                                        C:\Share\'Master Hacker Tools'\owexec.exe -c $Computer -k "cmd.exe /c reg add HKCU\Software\Microsoft\Office\15.0\Outlook /v DefaultProfile /t REG_SZ /d Outlook$RanNum /F" -u DOMAIN\$User -nowait
                                        }
                                    
                                    #Check for Office 2010
                                    if (Test-Path 'Program Files (x86)\Microsoft Office\Office14\OUTLOOK.EXE')
                                        {
                                        C:\Share\'Master Hacker Tools'\owexec.exe -c $Computer -k "cmd.exe /c reg add HKCU\Software\Microsoft\Office\15.0\Outlook\Profiles\Outlook$RanNum" -u DOMAIN\$User -nowait
                                        C:\Share\'Master Hacker Tools'\owexec.exe -c $Computer -k "cmd.exe /c reg add HKCU\Software\Microsoft\Office\15.0\Outlook /v DefaultProfile /t REG_SZ /d Outlook$RanNum /F" -u DOMAIN\$User -nowait
                                        }
                                    if (Test-Path 'Program Files\Microsoft Office\Office14\OUTLOOK.EXE')
                                        {
                                        C:\Share\'Master Hacker Tools'\owexec.exe -c $Computer -k "cmd.exe /c reg add HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\$RanNum" -u DOMAIN\$User -nowait
                                        C:\Share\'Master Hacker Tools'\owexec.exe -c $Computer -k "cmd.exe /c reg add HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles /v DefaultProfile /t REG_SZ /d Outlook$RanNum /F" -u DOMAIN\$User -nowait
                                        C:\Share\'Master Hacker Tools'\owexec.exe -c $Computer -k "cmd.exe /c reg add HKCU\Software\Microsoft\Exchange\Client\Options /v PickLogonProfile /t REG_DWORD /d 0 /f" -u DOMAIN\$User -nowait
                                        }
                                    #Done
                                    Write-Host "New profile created. Have the user re-open Outlook and verify they had to set it up for the first time." -ForegroundColor Green
                                    Pause
                            } '4' {
                                   Write-Host "Disabling SNMP for all printers on remote machine $Computer..."
                                   #Gather printer IP and if SNMP is enabled
                                   Invoke-Command -ComputerName $computer -ScriptBlock {
                                        get-wmiobject Win32_TCPIPPrinterPort | select SNMPEnabled,Name | ft
                                    }
                                   #Uncheck SNMP enabled box on all printers
                                    invoke-command -computername $computer -scriptblock {
                                        Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors\Standard TCP/IP Port\Ports' | ForEach-Object -Process {
                                            Set-ItemProperty -Path $_.PSPath -Name 'SNMP Enabled' -Value 0
                                            Set-ItemProperty -Path $_.PSPath -Name 'SNMP Index' -Value 0
                                        }
                                    Get-Service -Name 'Spooler' | Restart-Service -Force
                                    }
                                    #Checking to make sure they are now disabled
                                    Invoke-Command -ComputerName $computer -ScriptBlock {
                                        get-wmiobject Win32_TCPIPPrinterPort | select SNMPEnabled,Name | ft
                                    }
                            } '5' {
                                    Copy-Item "C:\Share\Applications\Windows10Upgrade9252.exe" -Destination "\\$Computer\c$\Windows\Temp"
                                    Invoke-Command -ComputerName $Computer -ScriptBlock {
                                        $User= "NT AUTHORITY\SYSTEM"
                                        $Task = "20H2"
                                        $Action= New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "Start-Process -FilePath C:\Windows\Temp\Windows10Upgrade9252.exe '/quietinstall /skipeula  /UninstallUponUpgrade /NoRestartUI /auto upgrade' -Wait"
                                        Register-ScheduledTask -TaskName "$Task" -User $User -Action $Action -RunLevel Highest –Force
                                        (Get-ScheduledTask -TaskName $Task).State
                                        Start-ScheduledTask -TaskName $Task
                                        Start-Sleep -Seconds 10
                                        (Get-ScheduledTask -TaskName $Task).State
                                        }
                                   IF (Invoke-Command -ComputerName $Computer -ScriptBlock {Get-Process | where {$_.ProcessName -like "Windows10UpgraderApp"}}) {Write-Host Upgrade to 20H2 Running... -ForegroundColor Green} else {Write-Host Upgrade failed to run... checking to see where it failed...
                                   if (Test-Path \\$Computer\c$\Windows\Temp\Windows10Upgrade9252.exe) {Write-Host "File copied successfully..." -ForegroundColor Green
                                   Write-Host "Checking process again..."
                                   if (Invoke-Command -ComputerName $Computer -ScriptBlock {Get-Process | where {$_.ProcessName -like "Windows10UpgraderApp"}}) {Write-Host "Now it's running... silly process..." -ForegroundColor Green} else {Write-Host Nope... not sure what happened. Try restarting? -ForegroundColor Red}
                                   Start-Sleep -s 7
                                   } else { Write-Host "File did not copy!" -ForegroundColor Red}
                                   }
                                    Start-Sleep -s 7
                                    $Restart = (get-date).AddMinutes(125).ToShortTimeString()
                                    shutdown -r -t 7500 -m \\$computer -c "Your computer will restart at $Restart to finalize updates. Please save your work"
                                    start powershell "C:\Share\Scripts\'Environment Variables'\Checking20H2Upgrade.ps1 $Computer" -WindowStyle Minimized
                            } '6' {
                                    Copy-Item "C:\Share\Scripts\Installers\hp-cmsl-1.6.3.exe" -Destination "\\$Computer\c$\Windows\Temp"
                                    (C:\Share\SysinternalsSuite\PsExec.exe \\$Computer -s C:\Windows\Temp\hp-cmsl-1.6.3.exe /SP /VERYSILENT /SUPPRESSMSGBOXES /NORESTART)
                                    invoke-command -computer $computer -scriptblock { Get-HPBIOSUpdates -Flash}
                                    start-sleep -s 5
                            } 'Q' {
                                    Exit
                                  }                        
                            }
                            
                        }
                    until ($inputFix -eq 'B')
#End Quick Fix Menu
            } '7' {
#Start Printer Control Menu                    
                    do
                        {
                            PrinterControl-Menu
                            $inputPrinter = Read-Host "Please make a selection"
                            switch ($inputPrinter)
                            {
                              '1' {
                                    $List2 = Get-WMIObject -Class Win32_Printer -Computer $computer
                                    Write-Host Printers on $Computer :
                                    $List2  | select Name,PortName,DriverName | Format-Table | Out-String|% {Write-Host $_}
                                    Pause
                            } '2' {
                                    $List = Get-WMIObject -Class Win32_Printer -Computer $computer
                                    $Printer = $List  | select Name,PortName,DriverName | Out-GridView -Title 'Which printer do you want to remove?' -PassThru | ForEach-Object { $_.Name }
                                    cls
                                    Write-Host Starting Removal of $Printer
                                    Write-Host 
                                    Write-Host Restarting Print Spooler to clear any stuck jobs...
                                    (Get-Service -ComputerName $Computer -Name spooler).Stop()
                                    Sleep -Seconds 5
                                    (Get-Service -ComputerName $Computer -Name spooler).Start()
                                    Sleep -Seconds 8
                                    get-service -ComputerName $Computer -Name spooler | Select DisplayName,Status | ft -HideTableHeaders

                                    Write-Host Deleting $Printer Printer...

                                    Remove-Printer -Name "$Printer" -ComputerName $Computer

                                    Write-Host Check to see if it is now deleted:
                                    $List2 = Get-WMIObject -Class Win32_Printer -Computer $computer
                                    $List2  | select Name,PortName,DriverName | Format-Table | Out-String|% {Write-Host $_}
                            } '3' {
                                    Write-Host Stopping Print spooler...
                                    Invoke-Command -ComputerName $Computer {Stop-Service -Name Spooler -Force}
                                    Write-Host Removing print jobs...
                                    Invoke-Command -ComputerName $Computer {Remove-Item -Path "$env:SystemRoot\System32\spool\PRINTERS\*" -force -Recurse}
                                    Write-Host Starting Print spooler...
                                    Invoke-Command -ComputerName $Computer {Start-Service -Name Spooler}
                                    Start-Sleep -s 3
                            } 'Q' {
                                    Exit
                                  }                        
                            }
                            
                        }
                    until ($inputPrinter -eq 'B')
#End Printer Control Menu
            } '8' {
                            $GPO = Get-GPO -All| where DisplayName -Like *gpo-$SiteC-General*
 
        foreach ($Policy in $GPO){
 
                $GPOID = $Policy.Id
                $GPODom = $Policy.DomainName
                $GPODisp = $Policy.DisplayName
 
                 if (Test-Path "\\$($GPODom)\SYSVOL\$($GPODom)\Policies\{$($GPOID)}\User\Preferences\Drives\Drives.xml")
                 {
                     [xml]$DriveXML = Get-Content "\\$($GPODom)\SYSVOL\$($GPODom)\Policies\{$($GPOID)}\User\Preferences\Drives\Drives.xml"
 
                            foreach ( $drivemap in $DriveXML.Drives.Drive )
 
                                {New-Object PSObject -Property @{
                                    GPOName = $GPODisp
                                    DriveLetter = $drivemap.Properties.Letter + ":"
                                    DrivePath = $drivemap.Properties.Path
                                    DriveAction = $drivemap.Properties.action.Replace("U","Update").Replace("C","Create").Replace("D","Delete").Replace("R","Replace")
                                    DriveLabel = $drivemap.Properties.label
                                    DrivePersistent = $drivemap.Properties.persistent.Replace("0","False").Replace("1","True")
                                    DriveFilterGroup = $drivemap.Filters.FilterGroup.Name
                                }
                            }
                }
        }
$IDrive = $drivemap.Properties.path
                    cls
                    'Listing Granular Sugar Details...'
                    Write-host 'G Drive is ' $Name.HomeDirectory
                    Write-host I drive is supposed to be $IDrive
                    Write-host 'Department: ' $Name.Department
                    Write-host 'Acct Creation: ' $Name.Created
                    Write-Host 'Employee ID: ' $Name.EmployeeID
                    Write-host 'AD Location: ' $Name.CanonicalName
                    Write-host 'Notes in AD: ' $Name.info
                    Write-host 'Last Bad PW: ' $Name.LastBadPasswordAttempt
                    Write-host 'Group Memberships:'
                    (Get-ADPrincipalGroupMembership $name.SamAccountName).name
            } '9' {Write-Host RDPing in to $Computer
                   cmdkey /generic:$Computer /user:DOMAIN\USER
                   mstsc.exe /v:$Computer /f
            } '10' {Write-Host Launching Ping
                   start-process cmd -ArgumentList "/c ping $Computer -4 /t"
            } '11' {Write-Host WARNING: This will SHUTDOWN $Computer! -ForegroundColor Red
                    Pause
                   start-process cmd -ArgumentList "/c shutdown /m \\$Computer -t 0 -s"
            } '12' {Write-Host WARNING: This will RESTART $Computer! -ForegroundColor Red
                    Pause
                   start-process cmd -ArgumentList "/c shutdown /m \\$Computer -t 0 -r"
            } '13' {Write-Host Opening C Drive of remote computer... -ForegroundColor Yellow
                   ii \\$Computer\c$\
            } '14' {Write-Host "Opening User's folder of remote computer..." -ForegroundColor Yellow
                   ii \\$Computer\c$\Users\$User
            } '15' {Write-Host "Launching Windows Updates..."
                    (C:\Share\SysinternalsSuite\PsExec.exe \\$Computer -s winrm.cmd quickconfig -q)
                    Update-Install
                    Update-Windows
            } '16' {
                    start-process "C:\Program Files (x86)\LizardSystems\Remote Process Explorer\rpexplorer.exe" -ArgumentList $computer
            } '17' {
                    start-process "eventvwr" -ArgumentList $computer
            } '18' {
                    start-process "services.msc" -ArgumentList "/computer= $computer"
            } 'q' {
             Exit
            }
     }
     pause
}
until ($input -eq 'r')
} while ($true)
