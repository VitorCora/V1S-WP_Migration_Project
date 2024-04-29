# V1S-WP_Migration_Project

## This code needs to be ran as Administrator, I will include a fail safe to break the code in the case of it starting with less privileges 

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Write-Host "Please run this script as an Administrator."; 
    Write-Host "Exiting the Script Now, try again later as Administrator"
    exit 
} else {
    Write-Host "Running Script as Administrator."
}

# Define variables

# Define the URL from which to download the Basecamp agent
$urlagent = "https://windowss3csa.s3.us-east-2.amazonaws.com/TMServerAgent_Windows_CSA.zip"


# Define the URL from which to download the SCUT uninstalling tool for Apex One
$urlscuta1 = "http://loyal.netbsa.org/SCUTA1.zip"

# Define the URL from which to download the SCUT uninstalling tool for Workload Security
$urlscutws = "http://loyal.netbsa.org/SCUTWS.zip"

# Define the path where the program will be downloaded
$downloadPathAgent = "$env:TEMP\TMStandardAgent_Windows_x86_64_Windows.zip"

$downloadPathSCUTA1 = "$env:TEMP\SCUTA1.zip"

$downloadPathSCUTWS = "$env:TEMP\SCUTWS.zip"

# Error variable
$e=0

# Force PowerShell to use TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#Create Folder to save logs from the Migration tool

# Specify the folder path
$folderPath = "C:\ProgramData\Trend Micro\V1MigrationTool"

# Check if the folder already exists
if (-not (Test-Path $folderPath)) {
    # If the folder doesn't exist, create it
    [System.IO.Directory]::CreateDirectory($folderPath)
    Write-Host "Folder created successfully at $folderPath"
} else {
    Write-Host "Folder already exists at $folderPath"
}

#Log File

# Create the log file

# Specify the file path
$logfileName = "v1migrationtool"
$timestamp = Get-Date -Format "yyMMdd_HHmmss"

# Construct the full file path
$logfile = Join-Path -Path $folderPath -ChildPath ($logfileName + "_" + $timestamp +".txt")

# Create a StreamWriter object to write to the file
$streamWriter = New-Object System.IO.StreamWriter($logfile)

#Acquire timestamp
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Write content to the file
$streamWriter.WriteLine("INFO: $timestamp message:Log file create successfully.")

#Acquire timestamp
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Append text to the file
$streamWriter.WriteLine("INFO: $timestamp message:Migration process started at $timestamp.")

# Close the StreamWriter object to release resources
$streamWriter.Close()

# Verify if the file has been created
if (Test-Path $logfile) {
    Write-Host "Log File created successfully at $logfile"
} else {
    Write-Host "Failed to create the log file."
}

function AppendToLogFile {
    	param(
        	[string]$logfile,
        	[string]$message,
        	[string]$type
    	)
	# Get the current timestamp
	$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

	# Construct the log entry
	 $logentry = "{0}: {1} message: {2}" -f $type, $timestamp, $message

	$retryCount = 0

	while ($retryCount -lt 10) {
		try {
			# Append the log entry to the log file
	            	Add-Content -Path $logfile -Value $logentry -ErrorAction Stop
	            	Write-Host "Log entry appended successfully to $logfile"
	            	return  # Exit the function if successful
	        	}
	        catch {
	        	$retryCount++
	            	Write-Host "Attempt $retryCount : Failed to append log entry to $logfile. Error: $_"
	            	Start-Sleep -Seconds 5  # Wait for 5 seconds before retrying
	        }
	}
	
	# If execution reaches this point, it means all retries failed
	Write-Host "Exceeded maximum retry attempts. Failed to append log entry to $logfile."
}


# Start Check if Apex One is installed

# Search for Trend Micro Apex One Security Agent
$apexOne = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Trend Micro Apex One Security Agent*" }

$message = "Looking for Trend Micro Apex One Security Agent."
$type = "INFO"
Write-Host $message
AppendToLogFile -logfile $logfile -Message $message -Type $type

if ($apexOne -ne $null) {
	$message = "Trend Micro Apex one Agent found."
	$type = "INFO"
	Write-Host $message
	AppendToLogFile -logfile $logfile -Message $message -Type $type

    	# Uninstall Trend Micro Apex One Security Agent
    	$uninstallString = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object { $_.DisplayName -like "*Trend Micro Apex One Security Agent*" } | Select-Object -ExpandProperty UninstallString
    	if ($uninstallString -ne $null) {
        	$message = "Uninstalling Trend Micro Apex One Security Agent using command line..."
		$type = "INFO"
		Write-Host $message
		AppendToLogFile -logfile $logfile -Message $message -Type $type
        	Start-Process -FilePath $uninstallString -Wait
        	$message = "Verifying if the Trend Micro OfficeScan Client has been uninstalled correctly."
        	$type = "INFO"
		Write-Host $message
		AppendToLogFile -logfile $logfile -Message $message -Type $type
		$apexOne = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Trend Micro Apex One Security Agent*" }
  		if ($apexOne -eq $null){
	    		$message = "Trend Micro Apex One Security Agent has been uninstalled."
	        	$type = "INFO"
			Write-Host $message
			AppendToLogFile -logfile $logfile -Message $message -Type $type
   		}
    	} else {
        	$message =  "Failed to find uninstall string for Trend Micro Apex One Security Agent."
		$type = "INFO"
		Write-Host $message
		AppendToLogFile -logfile $logfile -Message $message -Type $type
        	$message =  "Initiating the uninstallation process of the Apex One, using the SCUT tool A1"
    		$type = "INFO"
		Write-Host $message
		AppendToLogFile -logfile $logfile -Message $message -Type $type
 
        	# Create a WebClient object
        	$webClient = New-Object System.Net.WebClient
        
        	# Download the program using the DownloadFile method (compatible with PowerShell v1)
        	$webClient.DownloadFile($urlscuta1, $downloadPathSCUTA1)
        	$message =  "Initiating the download of the SCUT tool A1"
    		$type = "INFO"
		Write-Host $message
		AppendToLogFile -logfile $logfile -Message $message -Type $type
 
        	# Check if the file was downloaded successfully
        	if (Test-Path $downloadPathSCUTA1) {
			$message =  "Program SCUT for Apex One downloaded successfully."
    			$type = "INFO"
			Write-Host $message
			AppendToLogFile -logfile $logfile -Message $message -Type $type
            		$message = "Running the program SCUT for Apex One ..."
	    		$type = "INFO"
     	    		Write-Host $message
	    		AppendToLogFile -logfile $logfile -Message $message -Type $type
        
        		# Extract the downloaded file using Shell.Application (compatible with PowerShell v1)
        		$shell = New-Object -ComObject Shell.Application
            
        		# Define the destination folder path
        		$destinationFolderPathSCUTA1 = "$env:TEMP\SCUTA1"
            
            		# Create the destination folder if it doesn't exist
	     		$message = "Checking if SCUTA1 folder already exists"
	    		$type = "INFO"
     	    		Write-Host $message
	    		AppendToLogFile -logfile $logfile -Message $message -Type $type
            		if (-not (Test-Path $destinationFolderPathSCUTA1)) {
                		New-Item -ItemType Directory -Path $destinationFolderPathSCUTA1 | Out-Null
		 		$message = "Creating SCUTA1 folder"
	    			$type = "INFO"
	     	    		Write-Host $message
		    		AppendToLogFile -logfile $logfile -Message $message -Type $type
	            	} else {
			 	$message = "Found SCUTA1 folder"
		    		$type = "INFO"
	     	    		Write-Host $message
		    		AppendToLogFile -logfile $logfile -Message $message -Type $type
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
	
				$message = "Running command $programPathSCUTA1 -noinstall -dbg"
		    		$type = "INFO"
		    		AppendToLogFile -logfile $logfile -Message $message -Type $type
	 
	                	#Build the command
	                	$command = "$programPathSCUTA1 -noinstall -dbg"
	                	
	                	# Check if the program exists in the destination folder
	                	if (Test-Path $programPathSCUTA1) {
		                    	$message = "Running SCUT Apex One located at: $programPathSCUTA1"
		    			$type = "INFO"
	     	    			Write-Host $message
		    			AppendToLogFile -logfile $logfile -Message $message -Type $type
		                    	$process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $command" -Verb RunAs -PassThru
		                    	$process.WaitForExit()
	                    
		                    	# Check the exit code of the process
		                    	if ($process.ExitCode -eq 0) {
		                        	$message = "Apex One removed successfully."
				  	    	$type = "INFO"
	     	    				Write-Host $message
		    				AppendToLogFile -logfile $logfile -Message $message -Type $type
		                        	$apexOne = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Trend Micro Apex One Security Agent*" }
		                    	} else {
		                        	$message = "Command failed with exit code $($process.ExitCode)."
				  		$type = "ERROR"
	     	    				Write-Host $message
		    				AppendToLogFile -logfile $logfile -Message $message -Type $type
		                    	}
	
	                	} else {
	                    		$message = "Error: Apex One SCUT Tool not found at $programPathSCUTA1"
			      		$type = "ERROR"
	     	    			Write-Host $message
		    			AppendToLogFile -logfile $logfile -Message $message -Type $type
	                	}
	            	} else {
	                	$message =  "Error: Destination folder not accessible."
			 	$type = "ERROR"
	     	    		Write-Host $message
		    		AppendToLogFile -logfile $logfile -Message $message -Type $type
	            	}
	        } else {
	    		$message = "Error: Failed to download the Apex One SCUT Tool from $urlSCUTA1"
	      		$type = "ERROR"
	     	    	Write-Host $message
		    	AppendToLogFile -logfile $logfile -Message $message -Type $type
	
	    	}
      }
} else {
	$message = "Trend Micro Apex One Security Agent is not installed."
    	$type = "INFO"
    	Write-Host $message
    	AppendToLogFile -logfile $logfile -Message $message -Type $type
}
   
# End Check if Apex One is installed

# Start Check if OfficeScan is installed

# Search for Trend Micro Deep OfficeScan Client

$officeScan = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Trend Micro OfficeScan Client*" }
$message = "Looking for Trend Micro OfficeScan Client."
$type = "INFO"
Write-Host $message
AppendToLogFile -logfile $logfile -Message $message -Type $type

if ($officeScan -ne $null) {
	$message = "Trend Micro OfficeScan Agent found."
     	$type = "INFO"
    	Write-Host $message
    	AppendToLogFile -logfile $logfile -Message $message -Type $type

	# Uninstall Trend Micro OfficeScan Security Agent
	$uninstallString = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object { $_.DisplayName -like "*Trend Micro OfficeScan Client*" } | Select-Object -ExpandProperty UninstallString
    	if ($uninstallString -ne $null) {
	        $message = "Uninstalling Trend Micro OfficeScan Client via command line..."
		$type = "INFO"
		Write-Host $message
		AppendToLogFile -logfile $logfile -Message $message -Type $type
	        Start-Process -FilePath $uninstallString -Wait
	        $message = "Verifying if the Trend Micro OfficeScan Client has been uninstalled correctly."
	        $type = "INFO"
		Write-Host $message
		AppendToLogFile -logfile $logfile -Message $message -Type $type
        	$officeScan = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Trend Micro OfficeScan Client*" }
	 	if ($officeScan -eq $null){
	  	        $message = "Trend Micro OfficeScan Client has been uninstalled."
		        $type = "INFO"
			Write-Host $message
			AppendToLogFile -logfile $logfile -Message $message -Type $type
   		}
   	} else {
       		$message =  "Failed to find uninstall string for Trend Micro OfficeScan Client."
		$type = "ERROR"
		Write-Host $message
		AppendToLogFile -logfile $logfile -Message $message -Type $type
		$message =  "Initiating the uninstallation process of the OfficeScan, using the SCUT tool"
		$type = "INFO"
		Write-Host $message
		AppendToLogFile -logfile $logfile -Message $message -Type $type
    
        	# Create a WebClient object
        	$webClient = New-Object System.Net.WebClient
        
        	# Download the program using the DownloadFile method (compatible with PowerShell v1)
        	$webClient.DownloadFile($urlscuta1, $downloadPathSCUTA1)
		$message =  "Initiating the download of the SCUT tool A1"
  		$type = "INFO"
		Write-Host $message
		AppendToLogFile -logfile $logfile -Message $message -Type $type
        
        	# Check if the file was downloaded successfully
	        if (Test-Path $downloadPathSCUTA1) {
		  	$message =  "Program SCUT for OfficeScan downloaded successfully."
	    		$type = "INFO"
			Write-Host $message
			AppendToLogFile -logfile $logfile -Message $message -Type $type
	            	$message = "Running the program SCUT for OfficeScan ..."
	   		$type = "INFO"
	     		Write-Host $message
		    	AppendToLogFile -logfile $logfile -Message $message -Type $type      	
		        
	           	# Extract the downloaded file using Shell.Application (compatible with PowerShell v1)
		    	$shell = New-Object -ComObject Shell.Application
		            
	           	# Define the destination folder path
		  	$destinationFolderPathSCUTA1 = "$env:TEMP\SCUTA1"
		            
		        # Create the destination folder if it doesn't exist
	  	     	$message = "Checking if SCUTA1 folder already exists"
		    	$type = "INFO"
	     	    	Write-Host $message
		    	AppendToLogFile -logfile $logfile -Message $message -Type $type
		        if (-not (Test-Path $destinationFolderPathSCUTA1)) {
		                New-Item -ItemType Directory -Path $destinationFolderPathSCUTA1 | Out-Null
		  		 $message = "Creating SCUTA1 folder"
		    		$type = "INFO"
	     	    		Write-Host $message
		    		AppendToLogFile -logfile $logfile -Message $message -Type $type
	            	} else {
			 	$message = "Found SCUTA1 folder"
		    		$type = "INFO"
	  	    		Write-Host $message
		    		AppendToLogFile -logfile $logfile -Message $message -Type $type
	     		}
            
	           	# Get the zip folder and destination folder objects
	            	$zipFolder = $shell.NameSpace($downloadPathSCUTA1)
		  	$destinationFolderSCUTA1 = $shell.NameSpace($destinationFolderPathSCUTA1)
	            
		        # Check if the destination folder object is not null
		        if ($destinationFolderSCUTA1 -ne $null) {
		                # Copy the items from the zip folder to the destination folder
		                $destinationFolderSCUTA1.CopyHere($zipFolder.Items(), 16)
		        
		                # Run SCUT program to remove A1
		                $programPathSCUTA1 = "$env:TEMP\SCUTA1\NA1\SCUT.exe"
		    
		                #Build the command
		                $command = "$programPathSCUTA1 -noinstall -dbg"
		                
		        	# Check if the program exists in the destination folder
		                if (Test-Path $programPathSCUTA1) {
			                $message = "Running SCUT Apex One located at: $programPathSCUTA1"
		    			$type = "INFO"
	    	    			Write-Host $message
	    				AppendToLogFile -logfile $logfile -Message $message -Type $type             	
		                    	$process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $command" -Verb RunAs -PassThru
		                    	$process.WaitForExit()
		                    
		                    	# Check the exit code of the process
		                   	if ($process.ExitCode -eq 0) {
			   	                $message = "OfficeScan removed successfully."
			  	    		$type = "INFO"
	     	    				Write-Host $message
		    				AppendToLogFile -logfile $logfile -Message $message -Type $type
			                	$officeScan = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Trend Micro OfficeScan Client*" }
			            	} else {
			       	               $message = "Command failed with exit code $($process.ExitCode)."
				  		$type = "ERROR"
	   	    				Write-Host $message
	    					AppendToLogFile -logfile $logfile -Message $message -Type $type
		                    	}
                    			#Start-Process -FilePath "cmd.exe" -ArgumentList "/c $command" -Verb RunAs Administrator
	                	} else {
	                    		$message = "Error: OfficeScan SCUT Tool not found at $programPathSCUTA1"
			      		$type = "ERROR"
	     	    			Write-Host $message
		    			AppendToLogFile -logfile $logfile -Message $message -Type $type
	                	}
			} else {
	                	$message =  "Error: Destination folder not accessible."
			 	$type = "ERROR"
	     	    		Write-Host $message
		    		AppendToLogFile -logfile $logfile -Message $message -Type $type
	    		}
	        } else {
	    		$message = "Error: Failed to download the OfficeScan SCUT Tool from $urlSCUTA1"
	   		$type = "ERROR"
		    	Write-Host $message
			AppendToLogFile -logfile $logfile -Message $message -Type $type
		}
	}
} else {
	$message = "Trend Micro OfficeScan Client is not installed."
    	$type = "INFO"
    	Write-Host $message
    	AppendToLogFile -logfile $logfile -Message $message -Type $type
}
   
# End Check if OfficeScan is installed

# Start Check if Workload Security is installed

# Search for Trend Micro Deep Security Agent
$deepSecurity = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Trend Micro Deep Security Agent*" }
$message = "Looking for Trend Micro Deep Security Agent."
$type = "INFO"
Write-Host $message
AppendToLogFile -logfile $logfile -Message $message -Type $type

if ($deepSecurity -ne $null) {
    $message = "Trend Micro Deep Security/Workload Security Agent found."
    $type = "INFO"
    Write-Host $message
    AppendToLogFile -logfile $logfile -Message $message -Type $type
    $message = "Verifying if the Trend Micro Deep Security/Workload Security Agent has been uninstalled correctly."
    $type = "INFO"
    Write-Host $message
    AppendToLogFile -logfile $logfile -Message $message -Type $type    
    # Uninstall Trend Micro Deep Security Agent
    $uninstallString = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object { $_.DisplayName -like "*Trend Micro Deep Security Agent*" } | Select-Object -ExpandProperty UninstallString
    if ($uninstallString -ne $null) {
        $message = "Uninstalling Trend Micro Deep Security/Workload Security Agent using command line..."
	$type = "INFO"
	Write-Host $message
	AppendToLogFile -logfile $logfile -Message $message -Type $type
        Start-Process -FilePath $uninstallString -Wait
        $message = "Verifying if the Trend Micro Deep Security/Workload Security Agent has been uninstalled correctly."
        $type = "INFO"
	Write-Host $message
	AppendToLogFile -logfile $logfile -Message $message -Type $type
	$deepSecurity = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Trend Micro Deep Security Agent*" }
  	if ($deepSecurity -eq $null){
	    	$message = "Trend Micro Deep Security/Workload Security Agent has been uninstalled."
	        $type = "INFO"
		Write-Host $message
		AppendToLogFile -logfile $logfile -Message $message -Type $type
    } else {
		$message = "Failed to uninstall Trend Micro Deep Security Agent. Return code: $($uninstallResult.ReturnValue)"
		$type = "ERROR"
		Write-Host $message
		AppendToLogFile -logfile $logfile -Message $message -Type $type

        # If password protection is ON, we will try using the SCUT tool next
		$message = "Failed to uninstall probably due to Agent Self protection. Next Try will be using SCUT WS tool"
		$type = "ERROR"
		Write-Host $message
		AppendToLogFile -logfile $logfile -Message $message -Type $type
		$message = "Initiating the uninstallation process of the $programName, using the SCUT tool"
		$type = "ERROR"
		Write-Host $message
		AppendToLogFile -logfile $logfile -Message $message -Type $type
        # Create a WebClient object
        $webClient = New-Object System.Net.WebClient
        # Download the program using the DownloadFile method (compatible with PowerShell v1)
        $webClient.DownloadFile($urlSCUTWS, $downloadPathSCUTWS)
        # Check if the file was downloaded successfully
        if (Test-Path $downloadPathSCUTWS) {
			$message = "Program SCUT for Workload Security downloaded successfully."
			$type = "INFO"
			Write-Host $message
			AppendToLogFile -logfile $logfile -Message $message -Type $type
            $message = "Running the program SCUT for Workload Security ..."
			$type = "INFO"
			Write-Host $message
			AppendToLogFile -logfile $logfile -Message $message -Type $type
            # Extract the downloaded file using Shell.Application (compatible with PowerShell v1)
            $shell = New-Object -ComObject Shell.Application
            # Define the destination folder path
            $destinationFolderPathSCUTWS = "$env:TEMP\SCUTWS"
            # Create the destination folder if it doesn't exist
            $message = "Checking if SCUT folder already exists"
            $type = "INFO"
            Write-Host $message
            AppendToLogFile -logfile $logfile -Message $message -Type $type
            if (-not (Test-Path $destinationFolderPathSCUTWS)) {
				New-Item -ItemType Directory -Path $destinationFolderPathSCUTWS | Out-Null
                $message = "Creating SCUT folder"
                $type = "INFO"
                Write-Host $message
                AppendToLogFile -logfile $logfile -Message $message -Type $type
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
                $message = "Running SCUT located at: $programPathSCUTWS"
                $type = "INFO"
                Write-Host $message
                AppendToLogFile -logfile $logfile -Message $message -Type $type
                Write-Host "Running SCUT Workload Security located at: $programPathSCUTWS"
                $process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $command" -Verb RunAs -PassThru
                $process.WaitForExit()
                # Check the exit code of the process
                if ($process.ExitCode -eq 0) {
                    $message = "Trend Micro Deep Security/Workload Security Agent removed successfully."
                    $type = "INFO"
                    Write-Host $message
                    AppendToLogFile -logfile $logfile -Message $message -Type $type
                    $deepSecurity = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Trend Micro Deep Security Agent*" }
                } else {
                    $message = "Command failed with exit code $($process.ExitCode)."
                    $type = "ERROR"
                    Write-Host $message
                    AppendToLogFile -logfile $logfile -Message $message -Type $type
                }
			} else {
                $message = "Error: Workload Security CUT tool not found at $programPathSCUTWS"
                $type = "ERROR"
                Write-Host $message
                AppendToLogFile -logfile $logfile -Message $message -Type $type
            }
        } else {
            $message = "Error: Destination folder not accessible"
            $type = "ERROR"
            Write-Host $message
            AppendToLogFile -logfile $logfile -Message $message -Type $type
        }
    } else {
    $message =  "Error: Failed to download Workload Security CUT from $urlSCUTWS"
    $type = "ERROR"
    Write-Host $message
    AppendToLogFile -logfile $logfile -Message $message -Type $type
    }
} else {
	$message = "Trend Micro Deep Security Agent is not installed."
    $type = "INFO"
    Write-Host $message
    AppendToLogFile -logfile $logfile -Message $message -Type $type    
}

# End Check if Workload Security is installed


$message = "Finished looking for older versions installed on the host."
$type = "INFO"
Write-Host $message
AppendToLogFile -logfile $logfile -Message $message -Type $type

# Logic to Install Basecamp agent

if ($deepSecurity -eq $null -and $apexOne -eq $null -and $officeScan -eq $null) {
	$message = "Starting Installation process of the Trend Micro Basecamp Agent"
	$type = "INFO"
	Write-Host $message
	AppendToLogFile -logfile $logfile -Message $message -Type $type
 	# Create a WebClient object
	$webClient = New-Object System.Net.WebClient
	    
	# Download the program using the DownloadFile method (compatible with PowerShell v1)
	$webClient.DownloadFile($urlagent, $downloadPathAgent)
	    
	# Check if the file was downloaded successfully
	if (Test-Path $downloadPathAgent) {
	  	$message = "Trend Micro Basecamp Agent downloaded successfully."
		$type = "INFO"
		Write-Host $message
		AppendToLogFile -logfile $logfile -Message $message -Type $type
	 	$message = "Running the Trend Micro Basecamp Agent..."
		$type = "INFO"
		Write-Host $message
		AppendToLogFile -logfile $logfile -Message $message -Type $type
    
	        # Extract the downloaded file using Shell.Application (compatible with PowerShell v1)
	        $shell = New-Object -ComObject Shell.Application
        
	        # Define the destination folder path
	        $destinationFolderPath = "$env:TEMP\TMServerAgent"
        
	        # Create the destination folder if it doesn't exist
	        if (-not (Test-Path $destinationFolderPath)) {
	            New-Item -ItemType Directory -Path $destinationFolderPath | Out-Null
	        }
        
	        # Get the zip folder and destination folder objects
	        $zipFolder = $shell.NameSpace($downloadPathAgent)
	        $destinationFolder = $shell.NameSpace($destinationFolderPath)
        
	        # Check if the destination folder object is not null
	        if ($destinationFolder -ne $null) {
	        	# Copy the items from the zip folder to the destination folder
	        	$destinationFolder.CopyHere($zipFolder.Items(), 16)
    
		        # Replace 'EndpointBasecamp.exe' with the actual name of the executable you want to run from the extracted files
		        $programPath = "$env:TEMP\TMServerAgent\EndpointBasecamp.exe"
		            
		        # Check if the program exists in the destination folder
		        if (Test-Path $programPath) {
		  		$message = "Running the program located at: $programPath"
			    	$type = "INFO"
			    	Write-Host $message
			    	AppendToLogFile -logfile $logfile -Message $message -Type $type
		                $process = Start-Process -FilePath $programPath
				$process.WaitForExit()
		        } else {
		  	      	$message = "Error: Program not found at $programPath"
			    	$type = "ERROR"
			    	Write-Host $message
			    	AppendToLogFile -logfile $logfile -Message $message -Type $type
            		}
        	} else {
	      	  	$message = "Error: Destination folder not accessible."
		    	$type = "ERROR"
		    	Write-Host $message
		    	AppendToLogFile -logfile $logfile -Message $message -Type $type
        	}
	} else {
	  	$message = "Error: Failed to download Trend Micro Basecamp the program from $urlagent"
	    	$type = "ERROR"
	    	Write-Host $message
	    	AppendToLogFile -logfile $logfile -Message $message -Type $type
    	}
} else {
 	$message = "Error: Failed to Install Basecamp because Workload Security or Apex One are installed on the target machine"
    	$type = "ERROR"
    	Write-Host $message
    	AppendToLogFile -logfile $logfile -Message $message -Type $type
}

# Check if Trend Micro Deep Security service is installed
function Check-DeepSecurityInstalled {
    $service = Get-Service "ds_agent"
    if ($service -ne $null) {
	$message = "Info: Trend Micro Deep Security is installed."
    	$type = INFO"
    	Write-Host $message
    	AppendToLogFile -logfile $logfile -Message $message -Type $type
        return $true
    } else {
	$message = "Error: Trend Micro Deep Security is not installed."
    	$type = "ERROR"
    	Write-Host $message
    	AppendToLogFile -logfile $logfile -Message $message -Type $type
        return $false
    }
}

# Set timeout to 15 minutes
$timeout = (Get-Date).AddMinutes(15)

# Set a numerical variable
$n = 0
$t = 30
$wstime = 30

# Loop until Deep Security is installed or timeout is reached
while ((-not (Check-DeepSecurityInstalled)) -and (Get-Date) -lt $timeout) {
	$n=$n+1
	$wstime = $t*$n
	$message = "Info: Waiting for Trend Micro Deep Security to be installed for $wstime ..."
    	$type = "INFO"
    	Write-Host $message
    	AppendToLogFile -logfile $logfile -Message $message -Type $type
    	Start-Sleep -Seconds 30  # Wait for 30 seconds before checking again
}

if ((Get-Date) -ge $timeout) {
     	$message = "Error: Timed out waiting for Trend Micro Deep Security to be installed."
    	$type = "ERROR"
    	Write-Host $message
    	AppendToLogFile -logfile $logfile -Message $message -Type $type
} else {
    	# Change directory to C:\Program Files\Trend Micro\Deep Security
	Set-Location "C:\Program Files\Trend Micro\Deep Security Agent"

	# Reset the manager
 	$message = "Info: Reseting the manager"
    	$type = "INFO"
    	Write-Host $message
    	AppendToLogFile -logfile $logfile -Message $message -Type $type
    	& .\dsa_control -r
    
    	# Activate to the manager
 	$message = "Info: Activating Vision One Server & Workload Protection"
    	$type = "INFO"
    	Write-Host $message
    	AppendToLogFile -logfile $logfile -Message $message -Type $type
    	& .\dsa_control -a dsm://agents.deepsecurity.trendmicro.com:443/ "tenantID:6FA36C87-B9F7-867C-69AF-5879414942EA" "token:114696AE-DA74-8623-FFD0-BA8BD59FC128"
}
