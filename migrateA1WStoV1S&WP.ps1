# V1S-WP_Migration_Project

## This code needs to be ran as Adminstrator, I will include a fail safe to break the code in the case of it starting with less privileges 

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Write-Host "Please run this script as an Administrator."; 
    exit 
}

# Define variables

# Define the URL from which to download the Basecamp agent
#$urlagent = "http://loyal.netbsa.org/TMServerAgent_Windows_auto_x86_64_Server_and_Workload_Protection_Manager_-_302404101471.zip"
$urlagent = "https://agentbucket-yourcompanyname.s3.amazonaws.com/TMServerAgent_Windows.zip"


# Define the URL from which to download the SCUT uninstalling tool for Apex One
$urlscuta1 = "http://loyal.netbsa.org/SCUTA1.zip"

# Define the URL from which to download the SCUT uninstalling tool for Workload Security
$urlscutws = "http://loyal.netbsa.org/SCUTWS.zip"

# Define the path where the program will be downloaded
$downloadPathAgent = "$env:TEMP\TMStandardAgent_Windows_x86_64_Windows.zip"

$downloadPathSCUTA1 = "$env:TEMP\SCUTA1.zip"

$downloadPathSCUTWS = "$env:TEMP\SCUTWS.zip"

# Start Check if Apex One is installed

#1

# Search for Trend Micro Deep Security Agent
$apexOne = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Trend Micro Apex One Security Agent*" }

if ($apexOne -ne $null) {
    Write-Host "Trend Micro Apex one/Office Scan Agent found."

    # Uninstall Trend Micro Apex One Security Agent
    $uninstallString = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object { $_.DisplayName -like "*Trend Micro Apex One Security Agent*" } | Select-Object -ExpandProperty UninstallString
    if ($uninstallString -ne $null) {
        Write-Host "Uninstalling Trend Micro Apex One Security Agent..."
        Start-Process -FilePath $uninstallString -Wait
        Write-Host "Trend Micro Apex One Security Agent has been uninstalled."
        $apexOne = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Trend Micro Apex One Security Agent*" }
    } else {
        Write-Host "Failed to find uninstall string for Trend Micro Apex One Security Agent."


        Write-Host "Initiating the unistallation process of the Apex One, using the SCUT tool"
    
        # Create a WebClient object
        $webClient = New-Object System.Net.WebClient
        
        # Download the program using the DownloadFile method (compatible with PowerShell v1)
        $webClient.DownloadFile($urlscuta1, $downloadPathSCUTA1)
        
        # Check if the file was downloaded successfully
        if (Test-Path $downloadPathSCUTA1) {
            Write-Host "Program SCUT for Apex One downloaded successfully."
            Write-Host "Running the program SCUT for Apex One ..."
        
            # Extract the downloaded file using Shell.Application (compatible with PowerShell v1)
            $shell = New-Object -ComObject Shell.Application
            
            # Define the destination folder path
            $destinationFolderPathSCUTA1 = "$env:TEMP\SCUTA1"
            
            # Create the destination folder if it doesn't exist
            if (-not (Test-Path $destinationFolderPathSCUTA1)) {
                New-Item -ItemType Directory -Path $destinationFolderPathSCUTA1 | Out-Null
            }
            
            # Get the zip folder and destination folder objects
            $zipFolder = $shell.NameSpace($downloadPathSCUTA1)
            $destinationFolderSCUTA1 = $shell.NameSpace($destinationFolderPathSCUTA1)
            
            # Check if the destination folder object is not null
            if ($destinationFolderSCUTA1 -ne $null) {
                # Copy the items from the zip folder to the destination folder
                $destinationFolderSCUTA1.CopyHere($zipFolder.Items(), 16)
        
                # Run SCUT program to remove A1
                $programPathSCUTA1 = "$env:TEMP\SCUTA1\A1\SCUT.exe"
    
                #Build the command
                $command = "$programPathSCUTA1 -noinstall -dbg"
                
                # Check if the program exists in the destination folder
                if (Test-Path $programPathSCUTA1) {
                    Write-Host "Running SCUT Apex One located at: $programPathSCUTA1"
                    $process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $command" -Verb RunAs -PassThru
                    $process.WaitForExit()
                    
                    # Check the exit code of the process
                    if ($process.ExitCode -eq 0) {
                        Write-Host "Apex One removed successfully."
                        $apexOne = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Trend Micro Apex One Security Agent*" }
                    } else {
                        Write-Host "Command failed with exit code $($process.ExitCode)."
                    }
                    #Start-Process -FilePath "cmd.exe" -ArgumentList "/c $command" -Verb RunAs Administrator
                } else {
                    Write-Host "Error: Apex One SCUT Tool not found at $programPathSCUTA1"
                }
            } else {
                Write-Host "Error: Destination folder not accessible."
            }
        } else {
            Write-Host "Error: Failed to download the Apex One SCUT Tool from $urlSCUTA1"
        }

    }
} else {
    Write-Host "Trend Micro Apex One Security Agent is not installed."
}


#2

#Old code
    
# End Check if Apex One is installed

# Start Check if Workload Security is installed

# Search for Trend Micro Deep Security Agent
$deepSecurity = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Trend Micro Deep Security Agent*" }

if ($deepSecurity -ne $null) {
    Write-Host "Trend Micro Deep Security Agent found."
    
    # Uninstall Trend Micro Deep Security Agent
    $uninstallResult = $deepSecurity.Uninstall()

    if ($uninstallResult.ReturnValue -eq 0) {
        Write-Host "Uninstallation of Trend Micro Deep Security Agent was successful."
    } else {
        Write-Host "Failed to uninstall Trend Micro Deep Security Agent. Return code: $($uninstallResult.ReturnValue)"

        # If password protected, we will try using the SCUT tool next

        Write-Host " Failed to unistall probably due to Agent Self protection. Next Try will be using SCUT WS tool"

        Write-Host "Initiating the unistallation process of the $programName, using the SCUT tool"

        # Create a WebClient object
        $webClient = New-Object System.Net.WebClient
        
        # Download the program using the DownloadFile method (compatible with PowerShell v1)
        $webClient.DownloadFile($urlSCUTWS, $downloadPathSCUTWS)
        
        # Check if the file was downloaded successfully
        if (Test-Path $downloadPathSCUTWS) {
            Write-Host "Program SCUT for Workload Security downloaded successfully."
            Write-Host "Running the program SCUT for Workload Security ..."
        
            # Extract the downloaded file using Shell.Application (compatible with PowerShell v1)
            $shell = New-Object -ComObject Shell.Application
            
            # Define the destination folder path
            $destinationFolderPathSCUTWS = "$env:TEMP\SCUTWS"
            
            # Create the destination folder if it doesn't exist
            if (-not (Test-Path $destinationFolderPathSCUTWS)) {
                New-Item -ItemType Directory -Path $destinationFolderPathSCUTWS | Out-Null
            }
            
            # Get the zip folder and destination folder objects
            $zipFolder = $shell.NameSpace($downloadPathSCUTWS)
            $destinationFolderSCUTWS = $shell.NameSpace($destinationFolderPathSCUTWS)
            
            # Check if the destination folder object is not null
            if ($destinationFolderSCUTWS -ne $null) {
                # Copy the items from the zip folder to the destination folder
                $destinationFolderSCUTWS.CopyHere($zipFolder.Items(), 16)
        
                # Run SCUT program to remove WS
                $programPathSCUTWS = "$env:TEMP\SCUTWS\DSA_CUT.exe"
    
                #Build the command
                $command = "$programPathSCUTWS -F -C"
                
                # Check if the program exists in the destination folder
                if (Test-Path $programPathSCUTWS) {
                    Write-Host "Running SCUT Workload Security located at: $programPathSCUTWS"
                    $process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $command" -Verb RunAs -PassThru
                    $process.WaitForExit()
                    
                    # Check the exit code of the process
                    if ($process.ExitCode -eq 0) {
                        Write-Host "Workload Security removed successfully."
                        $deepSecurity = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Trend Micro Deep Security Agent*" }
                    } else {
                        Write-Host "Command failed with exit code $($process.ExitCode)."
                    }
                    #Start-Process -FilePath "cmd.exe" -ArgumentList "/c $command" -Verb RunAs Administrator
                } else {
                    Write-Host "Error: Workload Security CUT tool not found at $programPathSCUTWS"
                }
            } else {
                Write-Host "Error: Destination folder not accessible."
            }
        } else {
            Write-Host "Error: Failed to download Workload Security CUT from $urlSCUTWS"
        }
        
    }
} else {
    Write-Host "Trend Micro Deep Security Agent is not installed."
    
}

# End Check if Workload Security is installed

# Logic to Install Basecamp agent

if ($deepSecurity -eq $null -and $apexOne -eq $null ) {
    # Create a WebClient object
    $webClient = New-Object System.Net.WebClient
    
    # Download the program using the DownloadFile method (compatible with PowerShell v1)
    $webClient.DownloadFile($urlagent, $downloadPath)
    
    # Check if the file was downloaded successfully
    if (Test-Path $downloadPath) {
        Write-Host "Program downloaded successfully."
        Write-Host "Running the program..."
    
        # Extract the downloaded file using Shell.Application (compatible with PowerShell v1)
        $shell = New-Object -ComObject Shell.Application
        
        # Define the destination folder path
        $destinationFolderPath = "$env:TEMP\TMServerAgent"
        
        # Create the destination folder if it doesn't exist
        if (-not (Test-Path $destinationFolderPath)) {
            New-Item -ItemType Directory -Path $destinationFolderPath | Out-Null
        }
        
        # Get the zip folder and destination folder objects
        $zipFolder = $shell.NameSpace($downloadPath)
        $destinationFolder = $shell.NameSpace($destinationFolderPath)
        
        # Check if the destination folder object is not null
        if ($destinationFolder -ne $null) {
            # Copy the items from the zip folder to the destination folder
            $destinationFolder.CopyHere($zipFolder.Items(), 16)
    
            # Replace 'EndpointBasecamp.exe' with the actual name of the executable you want to run from the extracted files
            $programPath = "$env:TEMP\TMServerAgent\EndpointBasecamp.exe"
            
            # Check if the program exists in the destination folder
            if (Test-Path $programPath) {
                Write-Host "Running the program located at: $programPath"
                Start-Process -FilePath $programPath
            } else {
                Write-Host "Error: Program not found at $programPath"
            }
        } else {
            Write-Host "Error: Destination folder not accessible."
        }
    } else {
        Write-Host "Error: Failed to download the program from $urlagent"
    }
} else {
    Write-Host "Error: Failed to Install Basecamp because Workload Security or Apex One is installed on the target machine"
}
