<#
    .DISCLAIMER:
    By using this content you agree to the following: This script may be used for legal purposes only. 
    Users take full responsibility for any actions performed using this script. The author accepts no liability 
    for any damage caused by this script.  

    .SYNOPSIS
    This script can be used to do a quick search for files that should receive additional review against a list of provided extensions. 

    .DESCRIPTION
    Certain file types in secure environments should receive additional review to help ensure security. 
    This script will scan a specified path, including folders/subfolders, and compare the file extension of 
    each file found against a list of extensions. If the item is found, the full path to the file will be displayed. 
    The complete list will also be written to a txt file in the directory where the script is run, titled 
    SusExtensionSearcher-Result-yyyy-MM-dd.HH.mm.txt. The script will also create a runlog file that contains a 
    summary of who ran the script, when, how many files were found, and how long the scan took, among other details. 
    Note that this is a basic check for extensions and isn't advanced enough to determine if a file is using more advanced techniques to hide. 
    This script can be helpful,  but should NOT be used as your only check. 

    .PARAMETER Path
    Used to specify what path you want to scan. please be aware of the size of directory and subdirectories you are trying to scan

    .PARAMETER Extensions
    This designates a path to the extensions list you are wanting to check. The file should be a list of extensions with each type on a new line. 

    .EXAMPLE
    Suspicious_Extension_Finder.ps1 -path C:\Users\Hydrophobia\Downloads -extensions C:\Users\Hydrophobia\Downloads\extensions.txt

    .NOTES
    Created by: KaijuLogic
    Created Date: 4.2024
    Last Modified Date: 15 Nov 2025
    Last Modified By: KaijuLogic
    Last Modification Notes: 
		* Added folder creation to separate runlogs and result logs
        * You might notice spelling inconsistency, recently moved and getting used to using difference spelling norms
        * Added [CmdletBinding()] to script parameters.
        * Added parameter validation for -Path and -Extensions. 
        * Recently learned about "Hashsets", trying them out for effeciency if large extension lists are provided
        * Added checks to make sure all names in the extension list are 'normalised'
        * Simplifying a few small things to make things a little less cluttered (ex: moving $user and $computer variables since they were only used once)
        * Added some more error catching
        * Fixed some spelling errors

    TO-DO: Done: Add better notes and more error checking
		   Done: Add simple check for files that may be using multiple extensions
			
#>

#################################### PARAMETERS ###################################
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [ValidateScript({
        if (Test-Path $_ -PathType Container) {
            return $True
        } else {
            Exit
        }

    })]
    [String]$path,

    [Parameter(Mandatory=$true)]
    [ValidateScript({
        if (Test-Path $_ -PathType Leaf) {
            return $True
        } else {
            Exit
        }
    })]
    [String]$extensions
    
)
################################# SET COMMON VARIABLES ################################
$CurrentDate = Get-Date
$CurrentPath = Split-Path -Parent $PSCommandPath
$GetFiles = Get-ChildItem $path -Recurse

$RunLog = "$CurrentPath\runlogs\SusExtensionSearcher-Runlog-$($CurrentDate.ToString("yyyy-MM-dd.HH.mm")).txt"
$Output = "$CurrentPath\results\SusExtensionSearcher-Result-$($CurrentDate.ToString("yyyy-MM-dd.HH.mm")).txt"

#$sw is simply to track how long the script has run for. If it's running too long you might want to break the scan into multiple pieces.
$sw = [Diagnostics.Stopwatch]::StartNew()
$TimeStampFormat = "yyyy-MM-dd HH:mm:ss"
#################################### FUNCTIONS #######################################
#This function is simply used to create a run log for the script. This is useful for troubleshooting and tracking
Function Write-Log{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [ValidateSet("Info","WARN","ERROR","FATAL","DEBUG")]
        [string]
        $level = "INFO",

        [Parameter(Mandatory=$true)]
        [string]
        $Message,

        [Parameter(Mandatory=$true)]
        [string]
        $logfile
    )
    $Stamp = (Get-Date).ToString($TimeStampFormat)
    $Line = "$Stamp | $Level | $Message"
    Add-content $logfile -Value $Line
}
#Creates necessary log folders and path if they do not already exist to allow for logs to be created. 
Function Set-LogFolders {
    ##Tests for and creates necessary folders and files for the script to run and log appropriately
    if (!(Test-Path "$CurrentPath\runlogs\")) {
        Try{
            New-Item -Path "$CurrentPath\runlogs\" -ItemType "directory" | out-null
        }
        Catch {
            Write-Warning "Issue Creating $LogFolder maybe try manual creation? Error: $($_.ErrorDetails.Message)"
        }
    }
    if (!(Test-Path "$CurrentPath\results\")) {
        Try{
            New-Item -Path "$CurrentPath\results\" -ItemType "directory" | out-null
        }
        Catch {
            Write-Warning "Issue Creating $LogFolder maybe try manual creation? Error: $($_.ErrorDetails.Message)"
        }
    }
}
#This function gets a list of files and compares them to the extensions list found in the extensions file. 
Function Get-SusFilesTypes{
    #Initialize counting variables for, well, counting
    $SusItemsCount = 0
    $FileCount = 0
    
    #initialise hashset and import results 
    Write-Log -level INFO -message "Loading extensions list from $extensions" -logfile $RunLog
    $ExtensionsHashSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    #Normalise the extensions list to reduce possiblility of errors: all extensions should start with a "." . 
    try {
        $RawExtensions = Get-Content $extensions -ErrorAction Stop
        foreach ($ext in $RawExtensions) {
            if (-not [string]::IsNullOrWhiteSpace($ext)) {
                $NormaliseExt = if ($ext.StartsWith('.')) { $ext } else { ".$ext" }
                $ExtensionsHashSet.Add($NormaliseExt) | Out-Null
            }
        }
        Write-Log -level INFO -message "Loaded and normalised $($ExtensionsHashSet.Count) case-insensitive extensions." -logfile $RunLog
    }
    catch {
        Write-Log -level FATAL -message "Failed to read or process extensions file '$extensions'. Error: $_" -logfile $RunLog
        Write-Error "Failed to read extensions file. Check runlog for details."
        return
    }

    $message = "$($GetFiles.Count) total files/folders found"
    Write-Output $message | Out-File $output -Append
    Write-Log -level INFO -message $message -logfile $RunLog   

    $message = "Starting scan on path: $path"
    Write-Log -level INFO -message $message -logfile $RunLog  
    Write-Output $message

    #Comapre each item in the designated path to the list in the extensions file.  
    try{
        Get-ChildItem $path -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            $FileCount++
            $file = $_ # Assign to a variable for clarity
            $foundExt = $false # Flag to prevent logging the same file twice

            if ($ExtensionsHashSet.Contains($file.Extension)) {
                    $SusItemsCount++
                    $Fullpath = $file.Fullname
                    
                    # Add context to the output
                    $Message = "Suspicious extension [ $($file.Extension) ] at $Fullpath"
                    Write-Output $Message
                    Add-Content -Path $Output -Value $Message
                    $foundExt = $true
            }

            ### SIMPLE CHECK TO TRY AND FIND HIDDEN EXTENSION
            # This is only a "low hanging fruit" check. Don't rely only on this for file security.
            $hiddenExtension = [System.IO.Path]::GetExtension($file.BaseName)

            if ((-not [string]::IsNullOrEmpty($hiddenExtension)) -and $ExtensionsHashSet.Contains($hiddenExtension)) {
                # Only log this if it wasn't found already
                if (-not $foundExt) {
                    $SusItemsCount++
                    $Fullpath = $file.Fullname
                    
                    $Message = "Suspicious hidden extension [ $hiddenExtension ] at $Fullpath"
                    Write-Output $Message
                    Add-Content -Path $Output -Value $Message
                }
            }
        }
    }
    catch {
        $message = "Something went wrong during file processing scan ERROR: $_ "
        Write-Log -level INFO -message $message -logfile $RunLog  
        Write-Output $message
    }
    Finally{
        #After checking each file give the final results and some stats from the scan. 
        $message = "$SusItemsCount total suspicious files found"
        Write-Output $message
        Add-Content -Path $Output -Value $Message
        Write-Log -level INFO -message $message -logfile $RunLog   

        $sw.stop()

        $message = "Suspicious Extension check took $($sw.elapsed) to run"
        Write-Output $message
        Write-Log -level INFO -message $message -logfile $RunLog
        Add-Content -Path $Output -Value $Message
    }

}
#################################### EXECUTION #####################################

try {
	Set-LogFolders
    Write-Log -level INFO -message "Suspicious extension search script ran by $Env:UserName on $Env:ComputerName" -logfile $RunLog 
    Get-SusFilesTypes
    Write-Log -level INFO -message "Script finished successfully." -logfile $RunLog 
}
catch {
    # Catch any terminating errors from parameter validation or other unhandled exceptions
    Write-Log -level FATAL -message "Script failed to run with a fatal error: $_" -logfile $RunLog
    Write-Error "Script failed for some reason. Check runlog for more details: $RunLog"
}
