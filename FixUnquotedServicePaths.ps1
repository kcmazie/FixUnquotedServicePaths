Param(
    [switch]$FullDomain = $True,
    [switch]$Console = $False,
    [switch]$TestRun = $False, 
    [switch]$BriefLog = $true,
    [switch]$Debug = $false
)
<#======================================================================================
         File Name : FixUnquotedServicePaths.ps1
   Original Author : Kenneth C. Mazie (kcmjr AT kcmjr.com)
                   :
       Description : Will scan a specific list of Windows systems and check all services
                   : to assure the path is quoted if it contains spaces. If not it
                   : corrects the path by adding quotes. Fixes Nessus Plugin ID 63155.
                   : See: https://www.tenable.com/plugins/nessus/63155
                   :
         Operation : Requires PowerShell AD module.
                   : Looks for any text file in the same folder as the script. If found it loads the
                   : list of IP addresses or system names and cycles through them. It then renames
                   : test file to avoid redetection. Can alternately enumerate a domain. Original script
                   : used REG.EXE for all operations, this proved unreliable so the writes were switched to
                   : using .NET functions. HTML logs are written to the script folder. Only
                   : the previous 10 logs are retained.
                   :
         Arguments : Normal operation is with no command line options.
                   : -console $true : Displays status output to console - defaults to $false
                   : Note... If enabled this writes ALL output to the console
                   : -fulldomain $false : Forces scan of contents of any file ending in .TXT, otherwise scans full domain.
                   : withing the script folder. - defaults to $false
                   : -testrun $false : Writes changes. - defaults to $false as a safety measure CHANGE TO TRUE FOR LIVE RUNS
                   : -brieflog $true : Only writes identified bad paths to the log file, otherwise
                   : all output is written to the log file.
                   :
          Warnings : Could possibly break services: You've been warned. Only the first text
                   : file is read, make sure only one is in the folder.
                   :
             Legal : Public Domain. Modify and redistribute freely. No rights reserved.
                   : SCRIPT PROVIDED "AS IS" WITHOUT WARRANTIES OR GUARANTEES OF
                   : ANY KIND. USE AT YOUR OWN RISK. NO TECHNICAL SUPPORT PROVIDED.
                   :
           Credits : Code snippets and/or ideas came from many sources including but
                   : not limited to the following:
                   : http://www.ryanandjeffshow.com/blog/2013/04/11/powershell-fixing-unquoted-service-paths-complete/
                   :
    Last Update by : Kenneth C. Mazie
   Version History : v1.00 - Original
    Change History : v2.00 - 04-28-16 - Added header and numerous changes
                   : v2.10 - 07-08-16 - Switched full domain from false to true for automated runs.
                   : v3.00 - 11-16-17 - Rewrite for PSv5. Added external config. Added email.
                   : v3.10 - 03-02-18 - Minor notation update for PS Gallery upload
                   :
=======================================================================================#>
<#PSScriptInfo
.VERSION 3.10
.AUTHOR Kenneth C. Mazie (kcmjr AT kcmjr.com)
.DESCRIPTION
 Will scan a specific list of Windows systems and check all services to assure the path is quoted if it contains spaces. If not it corrects the path by adding quotes. Fixes Nessus Plugin ID 63155.
#> 
#requires -version 5.0

Clear-Host
$ErrorActionPreference = "silentlycontinue"

If ($FullDomain){$Script:FullDomain = $true}
If ($Console){$Script:Console = $true }
If ($TestRun){$script:TestRun = $true }
If ($BriefLog){$Script:BriefLog = $true }
If ($Debug){$Script:Debug = $true }

#--[ Functions ]-------------------------------------------------------------------------
Function LoadModules {
    Import-Module PSRemoteRegistry
}

Function LoadConfig { #--[ Read and load configuration file ]-----------------------------------------
    If (!(Test-Path $Script:ConfigFile)){       #--[ Error out if configuration file doesn't exist ]--
        Write-Host "---------------------------------------------" -ForegroundColor Red
        Write-Host "--[ MISSING CONFIG FILE. Script aborted. ]--" -ForegroundColor Red
        Write-Host "---------------------------------------------" -ForegroundColor Red
          SendEmail
          break
    }Else{
        [xml]$Script:Configuration = Get-Content $Script:ConfigFile       
        #$Script:Targets = ($Script:Configuration.Settings.General.Targets).split(",")
        $Script:ReportName = $Script:Configuration.Settings.General.ReportName
        $Script:DebugTarget = $Script:Configuration.Settings.General.DebugTarget   
        $Script:LogCount = $Script:Configuration.Settings.General.LogCount  
        $Script:Subject = $Script:Configuration.Settings.Email.Subject
        $Script:EmailTo = $Script:Configuration.Settings.Email.To
        $Script:EmailFrom = $Script:Configuration.Settings.Email.From
        $Script:EmailHTML = $Script:Configuration.Settings.Email.HTML
        $Script:SmtpServer = $Script:Configuration.Settings.Email.SmtpServer
        $Script:DebugEmail = $Script:Configuration.Settings.Email.DebugEmail 
        $Script:UserName = $Script:Configuration.Settings.Credentials.Username
        $Script:EncryptedPW = $Script:Configuration.Settings.Credentials.Password
        $Script:Base64String = $Script:Configuration.Settings.Credentials.Key   
        $ByteArray = [System.Convert]::FromBase64String($Base64String)
        $Script:Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserName, ($EncryptedPW | ConvertTo-SecureString -Key $ByteArray)
        $Script:Password = $Credential.GetNetworkCredential().Password        
    }
}    

Function GetIt ($Script:Target){                                                #--[ ForEach for singular or arrayed input on the shell try to get SVC Paths from $Script:Target ]--
    If ($Script:Console){ Write-Host "Connecting and bulk-loading service registry keys..." -ForegroundColor Yellow }
    If ($Script:Console){ Write-Host " ... Stand By ..." -ForegroundColor Yellow }
    $Script:Log += '<p style="font-family:Lucida Console;size:7pt;color:#800000;margin-top:0px;margin-bottom:0px;">Connecting and bulk-loading service registry keys...'
    $ErrorActionPreference = "continue"
    
    $GetItResult = ''
    $GetItResult = get-wmiobject win32_service -Credential $Script:Credential -ComputerName $Target    

    If ($Script:Console){ Write-Host " ... Done ..." -ForegroundColor Yellow }
    $ErrorActionPreference="silentlycontinue"
    
    $count = 1
    If ($Script:Console){Write-Host "`nParsing keys and key values..." -ForegroundColor Yellow  }
    $Script:Log += '<p style="font-family:Lucida Console;size:7pt;color:#800000;margin-top:0px;margin-bottom:0px;">Parsing keys and key values...'
    While ($count -lt ($GetItResult.length)){
        If ($Script:Console){ Write-Host "." -NoNewline }
        $Obj = New-Object -Typename PSObject
        $Obj | Add-Member -Membertype NoteProperty -Name Count -Value $count
        $Obj | Add-Member -Membertype NoteProperty -Name ComputerName -Value $Script:Target
        $Obj | Add-Member -MemberType NoteProperty -Name Status -Value "Retrieved"
        $Obj | Add-Member -MemberType NoteProperty -Name Key -Value (($GetItResult[$count]).name)
        $Obj | Add-Member -MemberType NoteProperty -Name PathName -Value (($GetItResult[$count]).pathname)
        [array]$collection += $Obj
        $count++ # = $count + 2
    } 
    If ($Script:Console){ Write-Host "`n"}
    $Script:Flag = $False
    Foreach ($foundkey in $collection){
        FindIt $foundkey
    }
    If (!($Script:Flag)){
        $Script:Log += '<p style="font-family:Lucida Console;size:7pt;color:#009933;margin-top:0px;margin-bottom:0px;">&nbsp;---&nbsp;No&nbsp;bad&nbsp;paths&nbsp;detected&nbsp;---</p>'
    }
       
    $collection = $null                                                                     #--[ reset collection ]--
    $GetItResult = ""
} 
 
Function FindIt ($Obj ) {                                                                   #--[ Process each path sent on Pipeline
    If ($Script:Console){Write-Host "Processing Service: " -NoNewline }
    If ($Script:Console){Write-Host "$($Obj.computername)\$($Obj.key)" -ForegroundColor Gray -NoNewline }
    If ($Script:LogDetail){$Script:Log += ('<p style="font-family:Lucida Console;size:7pt;color:#666666;margin-top:0px;margin-bottom:0px;">Processing&nbsp;key:&nbsp;'+"$($Obj.computername)\$($Obj.key)"+'</p>')}
    If ($Obj.key -eq "Unavailable"){                                                        #--[ The keys were unavailable, I just append object and continue ]--
        $Obj | Add-Member �MemberType NoteProperty �Name BadKey -Value "Unknown"
        $Obj | Add-Member �MemberType NoteProperty �Name FixedKey -Value "Can't Fix"
        $Obj = $nul                                                                         #--[ clear $Obj ]--
    }else{                                                                                  #--[ If we get here, I have a key to examine and fix. We're looking for keys with spaces in the path and unquoted ]--
        If ($Script:Console){Write-Host " Inspecting Value: " -NoNewline }
        If ($Script:Console){Write-Host $Obj.PathName -ForegroundColor Gray -NoNewline }
        If ($Script:LogDetail){$Script:Log += ('<p style="font-family:Lucida Console;size:7pt;color:#666666;margin-top:0px;margin-bottom:0px;">&nbsp;&nbsp;&nbsp;Inspecting&nbsp;Value:&nbsp;'+$Obj.ImagePath+'<nobr>')}
        $examine = $Obj.PathName                                                            #--[ the Path is always the first thing on the line, even with embedded arguments ]--
        If (!($examine.StartsWith('"'))) {                                                  #--[ Doesn't start with a quote ]--
            If (!($examine.StartsWith("\??"))) {                                            #--[ Some MS Services start with this but don't appear vulnerable ]--
                If ($examine.contains(" ")) {                                               #--[ If contains space when I get here, I can either have a good path with arguments, or a bad path ]--
                    If ($examine.contains("-") -or $examine.contains("/")) {                #--[ found arguments, might still be bad ]--
                        $split = $examine -split " -", 0, "simplematch"                     #--[ split out arguments ]--
                        $split = $split[0] -split " /", 0, "simplematch"
                        $newpath = $split[0].Trim(" ")                                      #--[ Path minus flagged args ]--
                        If ($newpath.contains(" ")){                                        #--[ check for unflagged argument ]--
                            $eval = $newpath -Replace '".*"', ''                            #--[ drop all quoted arguments ]--
                            $detunflagged = $eval -split "\", 0, "simplematch"              #--[ split on folder delim ]--
                            If ($detunflagged[-1].contains(" ")){                           #--[ last elem is executable and any unquoted args ]--
                                $fixarg = $detunflagged[-1] -split " ", 0, "simplematch"    #--[ split out args ]--
                                $quoteexe = $fixarg[0] + '"'                                #--[ quote that EXE and insert it back ]--
                                $examine = $examine.Replace($fixarg[0], $quoteexe)
                                $examine = $examine.Replace($examine, '"' + $examine)
                                $Script:BadPath = $true
                            }  
                            $examine = $examine.Replace($newpath, '"' + $newpath + '"')
                            $Script:BadPath = $true
                        }else{                                                              #--[ If newpath doesn't have spaces, it was just the argument tripping the check ]--
                            $Script:BadPath = $false
                        }  
                    }else{                                                                  #--[ check for unflagged argument ]--
                        $eval = $examine -Replace '".*"', ''                                #--[ drop all quoted arguments ]--
                        $detunflagged = $eval -split "\", 0, "simplematch"
                        If ($detunflagged[-1].contains(" ")){
                            $fixarg = $detunflagged[-1] -split " ", 0, "simplematch"
                            $quoteexe = $fixarg[0] + '"'
                            $examine = $examine.Replace($fixarg[0], $quoteexe)
                            $examine = $examine.Replace($examine, '"' + $examine)
                            $Script:BadPath = $true
                        }else{                                                              #--[ just a bad path. surround path in quotes ]--
                            $examine = $examine.replace($examine, '"' + $examine + '"')
                            $Script:BadPath = $true
                        }
                    }
                }else{
                   $Script:BadPath = $false 
                }
            }else{ 
                $Script:BadPath = $false 
            }
        }else{ 
            $Script:BadPath = $false 
        }

        If ($Script:BadPath){
            $Script:Flag = $True
            $Obj | Add-Member -MemberType NoteProperty -Name BadKey -Value "Yes"
            If ($examine.endswith('""')){ $examine = $examine.replace('""','"') }              #--[ sometimes we catch doublequotes ]--
            $Obj | Add-Member -MemberType NoteProperty -Name FixedKey -Value $examine
            If ($Script:BadPath -eq $true){
                If ($examine.contains("sql")){
                    If ($Script:Console -and $Script:BadPath){Write-Host " --- SQL BYPASS ---" -ForegroundColor Magenta }
                    If ($Script:LogDetail){$Script:Log += '<font color="darkmagenta"> --- SQL BYPASS ---</font></p>'}
                }else{
                    If ($Script:Console -and $Script:BadPath){Write-Host " --- BAD ---" -ForegroundColor Red } 
                    Write-Host "-------------------------------------------------------------"
                    If ($Script:LogDetail){$Script:Log += '<font color="red"> --- BAD ---</font></p>'}
                    $Script:Log += '<p style="font-family:Lucida Console;size:7pt;color:#000000;margin-top:0px;margin-bottom:0px;">-------------------------------------------------------------</p>'
                    $xKey = $Obj.key.trimstart("HKEY_LOCAL_MACHINE\")
                    FixIt $Script:Target "LocalMachine" $xKey "ImagePath" $Obj.Fixedkey
                    Write-Host "-------------------------------------------------------------"
                    $Script:Log += '<p style="font-family:Lucida Console;size:7pt;color:#000000;margin-top:0px;margin-bottom:0px;">-------------------------------------------------------------<br>'
                }
                $Obj = $nul                                                         #--[ clear $Obj ]--
            }
        }Else{                                                                    #--[ Update Objects ]--
            $Obj | Add-Member -MemberType NoteProperty -Name BadKey -Value "No"
            $Obj | Add-Member -MemberType NoteProperty -Name FixedKey -Value "N/A"
            If ($Script:BadPath -eq $true){Write-Output $Obj}
            $Obj = $nul                                                            #--[ clear $Obj ]--
            If ($Script:Console){Write-Host " --- GOOD ---" -ForegroundColor Green }
            If ($Script:LogDetail){$Script:Log += '<font color="#009933"> --- GOOD ---</font></p>'}
        }     
    } 
}

Function FixIt ($Script:Target,$xHive,$xKey,$xValue,$xData){                    #--[ Function to repair bad paths ]--
    $xType = "ExpandString"
    $xRegistryPath = "\SYSTEM\CurrentControlSet\Services\$xKey"
    $xRegistryFullPath = "HKLM:"+$xRegistryPath  

    #---------------------------------------------------
    If (!($script:TestRun)){                                                    #--[ Setting the testrun option will bypass the SET command ]--
        try{
            #--[ Get original value ]--
            $RegInitial = Invoke-Command -ComputerName $Target -ScriptBlock { get-itemproperty -path $Using:xRegistryFullPath } -Credential $Credential
            
            #--[ Seconadry test to verify path is accessible ]--
            $TestPath = Invoke-Command -ComputerName $Target -ScriptBlock { test-path -path $Using:xRegistryFullPath'\'$xData } -Credential $Credential
            
            #--[ Update the value ]--
            $UpdateValue = Invoke-Command -ComputerName $Target -ScriptBlock { 
                set-itemproperty -path $Using:xRegistryFullPath -name "ImagePath" -Value $Using:xData -force
            } -Credential $Credential

            <#--[ Optional to rename the value ]--
            $RenameValue = Invoke-Command -ComputerName $Target -ScriptBlock {
                rename-itemproperty -path $Using:xRegistryFullPath -name "ImagePath" -newname "OldImagePath" -force
            } -Credential $Credential
            #>
    
            <#--[ Optional to create a new value ]--
            $NewValue = Invoke-Command -ComputerName $Target -ScriptBlock {
                New-itemproperty -path $Using:xRegistryFullPath -name "ImagePath" -Value $Using:xData -force
            } -Credential $Credential
            #>
        }Catch{
            $ErrorMessage = $_.Exception.Message
            $FailedItem = $_.Exception.ItemName
            If ($Console){
                Write-Host "-- Error Message ="$ErrorMessage -for red
                Write-host "-- Failed Item :"$FailedItem -for red
            }
        }
    
        #--[ Verify by re-reading the key ]--
        $RegVerify = Invoke-Command -ComputerName $Target -ScriptBlock { get-itemproperty -path $Using:xRegistryFullPath } -Credential $Credential
        #------------------------------------------------------------
    
        If ($Console){
            write-host "-- Target = "$Script:Target -ForegroundColor Yellow
            write-host "-- RegHive = "$xHive -ForegroundColor Yellow
            write-host "-- FullPath = "$xRegistryFullPath -ForegroundColor Yellow
            write-host "-- ShortPath = "$xRegistryPath -ForegroundColor Yellow
            write-host "-- KeyName = "$xKey -ForegroundColor Yellow
            write-host "-- ValueName = "$xValue -ForegroundColor Yellow
            write-host "-- ValueType = "$xType -ForegroundColor Yellow
            Write-Host "-- Value Read = "$RegInitial.$xValue -ForegroundColor Red 
            write-host "-- Value Write = "$xData -ForegroundColor Cyan
        }

        $Script:Log += ('<p style="font-family:Lucida Console;size:7pt;color:#800000;margin-top:0px;margin-bottom:0px;">Target&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;=&nbsp;'+$Script:Target+'</p>')
        $Script:Log += ('<p style="font-family:Lucida Console;size:7pt;color:#800000;margin-top:0px;margin-bottom:0px;">RegHive&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;=&nbsp;'+$xHive+'</p>')
        $Script:Log += ('<p style="font-family:Lucida Console;size:7pt;color:#800000;margin-top:0px;margin-bottom:0px;">Full&nbsp;RegPath&nbsp;&nbsp;&nbsp;=&nbsp;'+$xRegistryFullPath+'</p>')
        $Script:Log += ('<p style="font-family:Lucida Console;size:7pt;color:#800000;margin-top:0px;margin-bottom:0px;">Short&nbsp;RegPath&nbsp;&nbsp;=&nbsp;'+$xRegistryPath+'</p>')
        $Script:Log += ('<p style="font-family:Lucida Console;size:7pt;color:#800000;margin-top:0px;margin-bottom:0px;">KeyName&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;=&nbsp;'+$xKey+'</p>')
        $Script:Log += ('<p style="font-family:Lucida Console;size:7pt;color:#800000;margin-top:0px;margin-bottom:0px;">ValueName&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;=&nbsp;'+$xValue+'</p>')
        $Script:Log += ('<p style="font-family:Lucida Console;size:7pt;color:#800000;margin-top:0px;margin-bottom:0px;">ValueType&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;=&nbsp;'+$xType+'</p>')
        $Script:Log += ('<p style="font-family:Lucida Console;size:7pt;color:#0000ff;margin-top:0px;margin-bottom:0px;">Initial&nbsp;Value&nbsp;&nbsp;=&nbsp;'+$RegInitial.$xValue+'</p>')
        $Script:Log += ('<p style="font-family:Lucida Console;size:7pt;color:#9900cc;margin-top:0px;margin-bottom:0px;">Adjusted&nbsp;Value&nbsp;=&nbsp;'+$xData+'</p>')
    
        If ($RegVerify.$xValue -eq $xData){    
            if ($Script:Console){write-host "-- Value Re-Read = "($RegVerify.$xValue)"`n --- Validated ---" -ForegroundColor Green }
            $Script:Log += '<p style="font-family:Lucida Console;size:7pt;color:#009933;margin-top:0px;margin-bottom:0px;">Value&nbsp;Re-Read&nbsp;&nbsp;=&nbsp;'+$RegVerify.$xValue+'<br>&nbsp;&nbsp;&nbsp;---&nbsp;Validated&nbsp;Good&nbsp;---</p>'
        }Else{
            If ($Script:TestRun){
                if ($Script:Console){write-host "-- Value Re-Read = "($RegVerify.$xValue)"`n --- Test Mode - No Changes ---" -ForegroundColor Red }
                $Script:Log += '<p style="font-family:Lucida Console;size:7pt;color:#ff0000;margin-top:0px;margin-bottom:0px;">Value&nbsp;Re-Read&nbsp;&nbsp;=&nbsp;'+$RegVerify.$xValue+'<br><strong>&nbsp;&nbsp;&nbsp;---&nbsp;Test&nbsp;Mode&nbsp;-&nbsp;No&nbsp;Changes&nbsp;Written&nbsp;---</strong></p>'
            }Else{
                if ($Script:Console){write-host "-- Value Re-Read = "($RegVerify.$xValue)"`n --- Validation FAILED ---" -ForegroundColor Red }
                $Script:Log += '<p style="font-family:Lucida Console;size:7pt;color:#ff0000;margin-top:0px;margin-bottom:0px;">Value&nbsp;Re-Read&nbsp;&nbsp;=&nbsp;'+$RegVerify.$xValue+'<br><strong>&nbsp;&nbsp;&nbsp;---&nbsp;Validation&nbsp;FAILED&nbsp;---</strong></p>'
            }    
        }
    } 
}

Function PingHost {
    $Script:TargetError = ""
    $job = Test-Connection -ComputerName $Script:Target -count 1 -BufferSize 16 -asjob
    while ($job.JobStateInfo.State -eq "Running") {}
    $Script:PingResult = Receive-Job $job #.statuscode

    $Code = $Script:PingResult.statuscode
    switch ($Code) {
        0 { $Script:TargetError = 'Successful' }
        11001 { $Script:TargetError = 'Buffer too small' }
        11002 { $Script:TargetError = 'Destination net unreachable' }
        11003 { $Script:TargetError = "Destination Host Unreachable "}
        11004 { $Script:TargetError = "Destination Protocol Unreachable"}
        11005 { $Script:TargetError = "Destination Port Unreachable "}
        11006 { $Script:TargetError = "No Resources "}
        11007 { $Script:TargetError = "Bad Option "}
        11008 { $Script:TargetError = "Hardware Error "}
        11009 { $Script:TargetError = "Packet Too Big "}
        11010 { $Script:TargetError = "Request Timed Out" }
        11011 { $Script:TargetError = "Bad Request "}
        11012 { $Script:TargetError = "Bad Route "}
        11013 { $Script:TargetError = "TimeToLive Expired Transit "}
        11014 { $Script:TargetError = "TimeToLive Expired Reassembly" }
        11015 { $Script:TargetError = "Parameter Problem "}
        11016 { $Script:TargetError = "Source Quench "}
        11017 { $Script:TargetError = "Option Too Big "}
        11018 { $Script:TargetError = "Bad Destination "}
        11032 { $Script:TargetError = "Negotiating IPSEC" }
        11050 { $Script:TargetError = "General Failure "}
        default { $Script:TargetError = 'Failed' }
    }
}

#==[ Main Body ]================================================================
$DayOfWeek = (get-date).DayOfWeek
$StartTime = [datetime]::Now
$domain = (Get-ADDomain).DNSroot
$Computer = $Env:ComputerName
$Script:Message = ""
$ScriptName = ($MyInvocation.MyCommand.Name).split(".")[0] 
$Script:ConfigFile = "$PSScriptRoot\$ScriptName.xml"  
$Script:LogFile = "$PSScriptRoot\$ScriptName-{0:MM-dd-yyyy_HHmmss}.html" -f (Get-Date)  
LoadConfig 
LoadModules

#--[ Delete all but the last X log files as specified in the config file ]-------------
Get-ChildItem -Path "$PSScriptRoot\" | Where-Object { -not $_.PsIsContainer } | Where-Object -Property extension -like "*.html" | Sort-Object -Descending -Property CreationTime | Select-Object -Skip $Script:LogCount | Remove-Item -Force 

If ($script:TestRun){
    If ($Script:Console){ Write-Host "`nNOTE: Script is running in TEST mode. No changes will be made...`n" -ForegroundColor Yellow }
    $Script:Message += "<head></head><html><strong><br>NOTE: Script is running in TEST mode. No changes will be made...</strong><br>"
}Else{    
    $Script:Message += "<head></head><html>"
}
$Script:InputFile = $Null

If($Script:Debug){
    $Script:Targets = get-adcomputer -Filter {(operatingSystem -like "*server*") -and (Enabled -eq "True") -and (name -eq "test-kmazie")} -properties name #| Where-object {Test-Connection -computername $($_.name) -count 1 -quiet}
    [int]$Script:TargetCount = 1
}ElseIf ($Script:FullDomain){   #<--[ The default mode ]--
    $Script:Targets = get-adcomputer -Filter {(operatingSystem -like "*windows*") -and (Enabled -eq "True")} -properties name | sort name #| Where-object {Test-Connection -computername $($_.name) -count 1 -quiet}
    [int]$Script:TargetCount = $Script:Targets.Count
}Else{    
    #--[ The next line retreves and inputs the target file if one exists, then renames it ]--
    $Script:InputFile = Get-ChildItem -Path "$PSScriptRoot\" | Where-Object { -not $_.PsIsContainer } | Where-Object -Property extension -like "*txt" | Sort-Object -Descending -Property LastTimeWrite 
    If ($Script:InputFile -ne ""){
        $Script:Targets = Get-Content $Script:InputFile.PSPath
        sleep -Seconds 3
        Rename-Item $Script:InputFile.FullName -NewName ($Script:InputFile.FullName+".old") -Force 
    }
    [int]$Script:TargetCount = $Script:Targets.Count

    #--[ The next lines are variations on domain scan input. Comment out as needed. ]--
    #$Script:Targets = get-adcomputer -Filter {(Enabled -eq "True") -and (name -notlike "*esx*")} -properties name | Where-object {Test-Connection -computername $($_.name) -count 1 -quiet}
    #$Script:Targets = Get-ADComputer -filter * | select name
    #$Script:Targets = "kmazie-test"
    #[string]$DateTime = Get-Date -Format MM-dd-yyyy_HHmmss
    #[string]$Script:FileName = "$PSScriptRoot\LocalAdminAdjustment_$DateTime.log"
}

$Script:Log = ('<p style="font-family:Lucida Console;size:8pt;color:#000000;margin-top:0px;margin-bottom:0px;"><br><strong>--[ Start Time: '+$StartTime+' ]-----------------------------------------------</strong></p>')
#--[ Main Loop ]------------------------------------------------------------------------------------------
ForEach ($Script:Target in $Script:Targets){                                         #--[ Cycle through list of selected targets ]--
    If ($Script:Target.name -ne $null){$Script:Target = $Script:Target.name}         #--[ Detect file input verses scan input ]--
       If ($Script:Console){Write-Host `n'--[ Processing:'$Script:Target' ('$Script:TargetCount' of'($Script:Targets).Count'Total) ]-----------------------------------------------' -ForegroundColor Cyan}
    $Script:Log += ('<p style="font-family:Lucida Console;size:8pt;color:#000000;margin-top:0px;margin-bottom:0px;"><br><strong>--[ Processing: '+$Script:Target+' ]-----------------------------------------------</strong></p>')
    PingHost
    If ($Script:TargetError -eq 'Successful'){
        if ($Script:Console){write-host "Ping Test GOOD: Result = $Script:TargetError" -ForegroundColor Green }
        $Script:Log += '<p style="font-family:Lucida Console;size:7pt;color:#009933;margin-top:0px;margin-bottom:0px;">Ping&nbsp;Test&nbsp;GOOD:&nbsp;Result&nbsp;=&nbsp;'+$Script:TargetError+'</p>'
        GetIt $Script:Target
    }Else{
        if ($Script:Console){write-host "--- Ping Test FAILED: Error = $Script:TargetError ---" -ForegroundColor Red }
        $Script:Log += '<p style="font-family:Lucida Console;size:7pt;color:#ff0000;margin-top:0px;margin-bottom:0px;"><strong>---&nbsp;Ping&nbsp;Test&nbsp;FAILED:&nbsp;Error&nbsp;=&nbsp;'+$Script:TargetError+'&nbsp;---</strong></p>'
    }
    $Script:Message += $Script:Log                        #--[ Add current system results to log file variable ]--
    $Script:Log = ""
    [int]$Script:TargetCount--
}
#-----------------------------------------------------------------------------------------------------------
$StopTime = [datetime]::Now
$Script:Log += '<p style="font-family:Lucida Console;size:7pt;color:#ff0000;margin-top:0px;margin-bottom:0px;"><br>---&nbsp;Completed:&nbsp&nbspStop&nbspTime: '+$StopTime+'---</p></html>'
if ($Script:Console){Write-Host "`n--- Completed at $StopTime ---" -ForegroundColor Red }
$Script:Message += $Script:Log
Add-Content -path $Script:LogFile -Value $Script:Message 

$SMTP = new-object System.Net.Mail.SmtpClient($Script:SMTPServer)
$Email = New-Object System.Net.Mail.MailMessage
$Email.Body = $Script:Message
$Email.IsBodyHtml = $Script:EmailHTML
$Email.To.Add($Script:EmailTo)
$Email.From = $Script:EmailFrom 
$Email.Subject = $Script:Subject
$Email.Attachments.Add($Script:LogFile)
$SMTP.Send($Email)
$Email.Dispose()
$SMTP.Dispose()


<#--[ Sample XML config file ]-------------------------------------------------------------
<!-- Settings & Configuration File -->
<Settings>
    <General>
        <Targets></Targets>
        <ReportName>Weekly Unquoted Service Path Fix</ReportName>
        <DebugTarget>test-pc</DebugTarget>
        <Log>$true</Log>
        <LogCount>20</LogCount>
    </General>
    <Email>
        <Subject>Unquoted Service Path Fix</Subject>
        <From>WeeklyReports@domain.com</From>
        <To>me@domain.com</To>
        <HTML>$true</HTML>
        <SmtpServer>10.10.15.1</SmtpServer>
        <DebugEmail>me@domain.com</DebugEmail>
    </Email>
    <Credentials>
        <UserName>domain\serviceuser</UserName>
        <Password>76492d1116743f0423AZQAxAGIATgBaADcAYwBtAHAAWAw050a5345MgB8AHIAegB2AHYQADQAYwB413b16050a5345MgB8AHQ4ADQ413b1613b16050a5345MgB8AHIAeNgA0AGEAMAIAegB2AHYANA2AGQAZAA2AA4AGQAZgA3ADIAYQAwADYAZAA3AGUAZgBkAGYAZAA=</Password>
        <Key>kdh413bADQ413b16a534gB2AHYie8mE=</Key>
    </Credentials>
</Settings>
 
#>
