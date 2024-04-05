# V1S-WP_Migration_Project

## This code needs to be ran as Adminstrator, I will include a fail safe to break the code in the case of it starting with less privileges 

# Define variables

# Define the URL from which to download the Basecamp agent
$urlagent = "http://loyal.netbsa.org/TMServerAgent_Windows_auto_x86_64_Server_and_Workload_Protection_Manager_-_302404101471.zip"

# Define the URL from which to download the Basecamp agent
$urlscuta1 = "http://loyal.netbsa.org/SCUTA1.zip"

# Define the URL from which to download the Basecamp agent
$urlscutws = "http://loyal.netbsa.org/SCUTWS.zip"

# Define the path where the program will be downloaded
$downloadPathAgent = "$env:TEMP\TMStandardAgent_Windows_x86_64_Windows.zip"

$downloadPathSCUTA1 = "$env:TEMP\SCUTA1.zip"

$downloadPathSCUTWS = "$env:TEMP\SCUTWS.zip"

# Check if Apex One is installed

# Specify the name of the program
$programName = "Trend Micro Apex One Security Agent"

# Create a new instance of the WMI searcher
$wmiSearcher = New-Object -Type System.Management.ManagementObjectSearcher -ArgumentList "SELECT * FROM Win32_Product"

# Get the list of installed software
$installedSoftware = $wmiSearcher.Get()

# Check if the program is found
$found = $false
foreach ($software in $installedSoftware) {
    if ($software.Name -like "*$programName*") {
        $found = $true
        break
    }
}

# Output the result
if ($found) {
    Write-Host "$programName is installed.

    Write-Host "Initiating the unistallation process of the $programName, using the SCUT tool"

    # Create a WebClient object
    $webClient = New-Object System.Net.WebClient
    
    # Download the program using the DownloadFile method (compatible with PowerShell v1)
    $webClient.DownloadFile($urlSCUTA1, $downloadPathSCUTA1)
    
    # Check if the file was downloaded successfully
    if (Test-Path $downloadPathSCUTA1) {
        Write-Host "Program SCUT for Apex One downloaded successfully."
        Write-Host "Running the program SCUT for Apex One ..."
    
        # Extract the downloaded file using Shell.Application (compatible with PowerShell v1)
        $shell = New-Object -ComObject Shell.Application
        
        # Define the destination folder path
        $destinationFolderPathSCUTA1 = "$env:TEMP\SCUTA1"
        
        # Create the destination folder if it doesn't exist
        if (-not (Test-Path $destinationFolderPath)) {
            New-Item -ItemType Directory -Path $destinationFolderPath | Out-Null
        }
        
        # Get the zip folder and destination folder objects
        $zipFolder = $shell.NameSpace($downloadPathSCUTA1)
        $destinationFolder = $shell.NameSpace($destinationFolderPathSCUTA1)
        
        # Check if the destination folder object is not null
        if ($destinationFolderSCUTA1 -ne $null) {
            # Copy the items from the zip folder to the destination folder
            $destinationFolder.CopyHere($zipFolder.Items(), 16)
    
            # Run SCUT program to remove A1
            $programPathSCUTA1 = "$env:TEMP\SCUTA1\A1\SCUT.exe"

            #Build the command
            $command = "$programPathSCUTA1 -noinstall -dbg"
            
            # Check if the program exists in the destination folder
            if (Test-Path $programPathSCUTA1) {
                Write-Host "Running SCUT Apex One located at: $programPathSCUTA1"
                Start-Process -FilePath "cmd.exe" -ArgumentList "/c $command" -Verb RunAs Administrator
            } else {
                Write-Host "Error: Program not found at $programPathSCUTA1"
            }
        } else {
            Write-Host "Error: Destination folder not accessible."
        }
    } else {
        Write-Host "Error: Failed to download the program from $urlSCUTA1"
    }

} else {
    Write-Host "$programName is not installed."
}

# End Check if Apex One is installed

# Start Check if Workload Security is installed

# Specify the name of the program
$programName = "Trend Micro Deep Security"

# Create a new instance of the WMI searcher
$wmiSearcher = New-Object -Type System.Management.ManagementObjectSearcher -ArgumentList "SELECT * FROM Win32_Product"

# Get the list of installed software
$installedSoftware = $wmiSearcher.Get()

# Check if the program is found
$found = $false
foreach ($software in $installedSoftware) {
    if ($software.Name -like "*$programName*") {
        $found = $true
        break
    }
}

# Output the result
if ($found) {
    Write-Host "$programName is installed.

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
        if (-not (Test-Path $destinationFolderPath)) {
            New-Item -ItemType Directory -Path $destinationFolderPath | Out-Null
        }
        
        # Get the zip folder and destination folder objects
        $zipFolder = $shell.NameSpace($downloadPathSCUTWS)
        $destinationFolder = $shell.NameSpace($destinationFolderPathSCUTWS)
        
        # Check if the destination folder object is not null
        if ($destinationFolderSCUTWS -ne $null) {
            # Copy the items from the zip folder to the destination folder
            $destinationFolder.CopyHere($zipFolder.Items(), 16)
    
            # Run SCUT program to remove WS
            $programPathSCUTWS = "$env:TEMP\SCUTWS\WS\SCUT.exe"

            #Build the command
            $command = "$programPathSCUTWS -noinstall -dbg"
            
            # Check if the program exists in the destination folder
            if (Test-Path $programPathSCUTWS) {
                Write-Host "Running SCUT Apex One located at: $programPathSCUTWS"
                Start-Process -FilePath "cmd.exe" -ArgumentList "/c $command" -Verb RunAs Administrator
            } else {
                Write-Host "Error: Program not found at $programPathSCUTWS"
            }
        } else {
            Write-Host "Error: Destination folder not accessible."
        }
    } else {
        Write-Host "Error: Failed to download the program from $urlSCUTWS"
    }

} else {
    Write-Host "$programName is not installed."
}


# End Check if Workload Security is installed

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

# Result with a Trend Micro Workload Security machine

![image](https://github.com/VitorCora/V1S-WP_Migration_Project/assets/59590152/61e838e2-de9f-4bf0-a8c5-20a40632b57a)

![image](https://github.com/VitorCora/V1S-WP_Migration_Project/assets/59590152/75ad7047-208d-4033-a968-d2aaf5c93369)

![image](https://github.com/VitorCora/V1S-WP_Migration_Project/assets/59590152/f0cb8ddd-ec67-4d29-949d-e6ddbff871a8)

![image](https://github.com/VitorCora/V1S-WP_Migration_Project/assets/59590152/61f7fbeb-fd18-4428-bddf-8f2200ae963b)

![image](https://github.com/VitorCora/V1S-WP_Migration_Project/assets/59590152/8257b86c-1d3a-4178-98a5-2a7e1052cd62)






