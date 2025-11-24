# Suspiciuous_Extension_Finder
This script can be used to quickly search for files against a list of provided extensions that require additional review.

## DESCRIPTION
Certain file types in secure environments should receive additional review to help ensure security. This script will scan a specified path, including folders/subfolders, and compare the file extension of each file found against a list of extensions. If the item is found, the full path to the file will be displayed. The complete list will also be written to a txt file in the directory where the script is run, titled Suspicious_Extension_Finder-Result-yyyy-MM-dd.HH.mm.txt. The script will also create a runlog file that contains a summary of who ran the script, when, how many files were found, and how long the scan took, among other details. Note that this is a basic check for extensions and isn't advanced enough to determine if a file is using more advanced techniques to hide. This script can be helpful,  but should NOT be used as your only check. 

## FEATURES
- Logging and report generation for review and tracking
- Does a simple "low hanging fruit" check for double extensions in a file name
- Since a hashset is used you can use a very large list of extensions with minimal impact to the scripts efficiency

## EXAMPLE
```PowerShell
Suspicious_Extension_Finder.ps1 -path C:\Users\KaijuLogic\Downloads -extensions C:\Users\KaijuLogic\Downloads\extensions.txt
```

## EXAMPLE OUTPUT
```
2025-11-25 08:26:01 | INFO | Suspicious extension search script ran by KaijuLogic on PC1
2025-11-25 08:26:01 | INFO | Loading extensions list from .\extensions-example.txt
2025-11-25 08:26:01 | INFO | Loaded and normalised 32 case-insensitive extensions.
2025-11-25 08:26:01 | INFO | 154 total files/folders found
2025-11-25 08:26:01 | INFO | Starting scan on path: C:\Users\KaijuLogic\Downloads\
2025-11-25 08:26:01 | WARN | Suspicious extension [ .ps1 ] at C:\Users\KaijuLogic\Downloads\Example.ps1
2025-11-25 08:26:01 | WARN | Suspicious extension [ .ps1 ] at C:\Users\KaijuLogic\Downloads\Test-Powershell.ps1
2025-11-25 08:26:01 | WARN | Suspicious extension [ .zip ] at C:\Users\KaijuLogic\Downloads\ZippedFolder.zip
2025-11-25 08:26:01 | WARN | Suspicious extension [ .iso ] at C:\Users\KaijuLogic\Downloads\debian-13.1.0-amd64-netinst.iso
2025-11-25 08:26:01 | WARN | Suspicious hidden extension [ .ps1 ] at C:\Users\KaijuLogic\Downloads\GodzillaThinking.ps1.jpeg
......
2025-11-25 08:23:11 | INFO | 18 total suspicious files found
2025-11-25 08:23:11 | INFO | Suspicious Extension check took 00:00:00.8554808 to run
2025-11-25 08:23:11 | INFO | Script finished successfully.
```

## EXAMPLE REPORT
Output to .txt file
```
Suspicious extension [ .ps1 ] at C:\Users\KaijuLogic\Downloads\Example.ps1
Suspicious extension [ .ps1 ] at C:\Users\KaijuLogic\Downloads\Test-Powershell.ps1
Suspicious extension [ .zip ] at C:\Users\KaijuLogic\Downloads\ZippedFolder.zip
Suspicious extension [ .iso ] at C:\Users\KaijuLogic\Downloads\debian-13.1.0-amd64-netinst.iso
Suspicious hidden extension [ .ps1 ] at C:\Users\KaijuLogic\Downloads\GodzillaThinking.ps1.jpeg
....
```
