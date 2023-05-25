# FixUnquotedServicePaths
Will scan a specific list of Windows systems and check all services to assure the path is quoted if it contains spaces. 

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
