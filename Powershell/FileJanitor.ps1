#
# FileJanitor.ps1 - Cleans up unneeded log files and other application specific files that are no longer needed.
#----------------------------

Clear-Host

function CleanFilesByDays {
	param ($FilePath, $Days, [switch] $Recurse)
    if ($Recurse) {
        $files = Get-ChildItem -Path $FilePath -recurse
       }
    else {
        $files = Get-ChildItem -Path $FilePath
    }

    Foreach ($File in $files) {
        if (!$File.PSIsContainer) {
            if ($File.LastWriteTime -lt ($(Get-Date).Adddays($days * -1))) {
					Remove-Item -Path $File.FullName -Force
            }
        }    
	} 
}

function CompressFiles {
    param ($FilePath, [switch] $Recurse)

    if ($Recurse) {
        $files = Get-ChildItem -Path $FilePath -recurse
       }
    else {
        $files = Get-ChildItem -Path $FilePath
    }

    Foreach ($File in $files) {
        if (!$File.PSIsContainer -and ($file.extension -ne ".zip")) {
            if ($File.LastWriteTime -lt ($(Get-Date).Adddays(-1))) {
                $compfile = join-path $file.DirectoryName ($file.baseName + ".zip")
        		Add-Content -Path $LogFile  -Value "Compressing $($file.fullname)"
                $file | Add-Zip -zipfilename $compfile
                remove-item $file.fullname
            }
        }    
	} 


}

function Add-Zip  # usage: Get-ChildItem $folder | Add-Zip $zipFullName 
{
    param([string]$zipfilename)

    if(!(test-path($zipfilename))) {
        set-content $zipfilename ("PK" + [char]5 + [char]6 + ("$([char]0)" * 18))
        (dir $zipfilename).IsReadOnly = $false    
    }

    $shellApplication = new-object -com shell.application
    $zipPackage = $shellApplication.NameSpace($zipfilename)

    foreach($file in $input) { 
        $zipPackage.CopyHere($file.FullName)
        do {
            Start-sleep 2
        } until ( $zipPackage.Items() | select {$_.Name -eq $file.Name} )
    }
}


$ScriptPath = Split-Path ((Get-Variable MyInvocation).Value).MyCommand.Path
Set-Location -Path $ScriptPath

$Logfile = Join-Path -Path $ScriptPath -ChildPath "FileJanitor.log"
if (Test-Path $LogFile) {
    Remove-Item $LogFile
}

# These paths may (or may not) be available on any given F1 server.  If the path exists, clean it up
$Cleanup = @(
				@{"Path"="E:\MongoDBData\Logs";																		"Days"=7;	"Recurse"=$false; "Compress"=$false},
				@{"Path"="E:\logfiles";         																	"Days"=90;	"Recurse"=$true;  "Compress"=$true},
				@{"Path"="C:\inetpub\logs\LogFiles"; 																"Days"=7;	"Recurse"=$true;  "Compress"=$false},
				@{"Path"="E:\F1Email"; 																				"Days"=7;	"Recurse"=$false; "Compress"=$false},
				@{"Path"="C:\ProgramData\Microsoft\Windows\WER"; 													"Days"=14;	"Recurse"=$true;  "Compress"=$false},
				@{"Path"="E:\RSTempFiles";					 														"Days"=1;	"Recurse"=$true;  "Compress"=$false},
				@{"Path"="C:\Program Files\Microsoft SQL Server\MSRS11.MSSQLSERVER\Reporting Services\LogFiles";	"Days"=7;	"Recurse"=$false; "Compress"=$false}
			)

Foreach ($item in $Cleanup) {
	if (Test-Path -Path $item.Path) {
		Add-Content -Path $LogFile  -Value "Cleaning $($item.Path)"
        # Cleanup old files
		if ($item.Recurse) {
            CleanFilesByDays -Recurse -FilePath $item.Path -Days $item.Days
		}
		else {
         	CleanFilesByDays -FilePath $item.Path -Days $item.Days
		}
        if ($item.Compress) {
        	Add-Content -Path $LogFile -Value "Compressing $($item.Path)"
			if ($item.Recurse) {
				CompressFiles -FilePath $item.Path -Recurse 
			}
			else {
				CompressFiles -FilePath $item.Path
			}
        }           
	}
}

# Temporary ASP.NET files - Iterate through each folder and keep the most current subfolder
$aspnet = @(
				"C:\Windows\Microsoft.NET\Framework\v2.0.50727\Temporary ASP.NET Files",
				"C:\Windows\Microsoft.NET\Framework64\v2.0.50727\Temporary ASP.NET Files",
				"C:\Windows\Microsoft.NET\Framework\v4.0.30319\Temporary ASP.NET Files",
				"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files"
			)				

foreach ($tanf in $aspnet) {
	if (Test-Path -Path $tanf) {
		Add-Content -Path $LogFile -Value "Cleaning $tanf"
		$folders = Get-ChildItem -Directory -Path $tanf
		foreach ($folder in $folders) {
			Add-Content -Path $LogFile -Value "    Cleaning $folder"
			$subfolders = Get-ChildItem -Directory -Path $folder.FullName | Sort-Object -Property LastWriteTime -Descending
			Add-Content -Path $LogFile -Value "    Subfolders: $subfolders"			
			$end = $subfolders.count - 1
			Add-Content -Path $LogFile -Value "    End: $end"
			if ($end) {
				remove-item -force $($subfolders[1..$end]).FullName -Recurse
			}
		}
	}
}	

# Cleanup the report and statment folders, but since it's on a fileshare, only have one server responsible for the cleanup effort.
# Delegate to the rpt10a node for reports and app10a for statements in each environment.  Both can be cleaned up at the same 7 day 
# interval
$pathmap = 	@{
				"WSF1INTRPT10A" =	"\\fileshare\NonProd_Com_Fai_f1int01\reportfiles";
				"WSF1QARPT10A" =	"\\fileshare\NonProd_Com_Fai_f1qa02\reportfiles";
				"WSF1UATRPT10A" =	"\\fileshare\Prod_Com_Fai_f1uat01\reportfiles";
				"WSF1PRODRPT10A" =	"\\fileshare\Prod_Com_Fai_f1prod01\reportfiles";
				"WSF1INTAPP10A" =	"\\fileshare\NonProd_Com_Fai_f1int01\statements";
				"WSF1QAAPP10A" = 	"\\fileshare\NonProd_Com_Fai_f1qa02\statements";
				"WSF1UATAPP10A" =	"\\fileshare\Prod_Com_Fai_f1uat01\statements";
				"WSF1PRODAPP10A" =	"\\fileshare\Prod_Com_Fai_f1prod01\statements"
			}
									
$path = $pathmap.($env:COMPUTERNAME)
if ($path -ne $null) {
	if (Test-Path -Path $path) {	
		Add-Content -Path $LogFile -Value "Cleaning $path"
		CleanFilesByDays -FilePath $path -Days 7 -Recurse
	}
}

