# Suspiciuous_Extension_Finder
This script can be used to do a quick search for files that should receive additional review against a list of provided extensions. 

## DESCRIPTION
Certain file types in secure environments should receive additional review to help ensure security. This script will scan a specified path, including folders/subfolders, and compare the file extension of each file found against a list of extensions. If the item is found, the full path to the file will be displayed. The complete list will also be written to a txt file in the directory where the script is run, titled SusExtensionSearcher-Result-yyyy-MM-dd.HH.mm.txt. The script will also create a runlog file that contains a summary of who ran the script, when, how many files were found, and how long the scan took, among other details. Note that this is a basic check for extensions and isn't advanced enough to determine if a file is using more advanced techniques to hide. This script can be helpful,  but should NOT be used as your only check. 

## PARAMETER path
Used to specify what path you want to scan. please be aware of the size of directory and subdirectories you are trying to scan

## PARAMETER extensions
This designates a path to the extensions list you are wanting to check. The file should be a list of extensions with each type on a new line. 

## EXAMPLE
Suspicious_Extension_Finder.ps1 -path C:\Users\Hydrophobia\Downloads -extensions C:\Users\Hydrophobia\Downloads\extensions.txt
