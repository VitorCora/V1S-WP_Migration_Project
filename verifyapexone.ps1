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
    Write-Host "$programName is installed."
} else {
    Write-Host "$programName is not installed."
}
