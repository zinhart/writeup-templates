<#
.SYNOPSIS
  A script to make your pentesting writeups a bit more structured.  
.DESCRIPTION
  This script creates a bunch of reporting directories to track your progress on different hosts.
.PARAMETER HostName
  The target you will be hacking. A folder will be created with the same name
.EXAMPLE
  New-Host example 
  <Creates a report folder called `example` at .\reports\boxes\example>
.NOTES
    Author: zinhart
    Date:   July 14, 2020  
#>
function New-Folder{
  Param(
    [Parameter(Mandatory=$true)]
    [string]$FolderName
  )
  if(-Not [System.IO.Directory]::Exists($FolderName))
  {
    New-Item $FolderName -ItemType Directory
  }
  else 
  {
    Write-Verbose "Skipping $FolderName PATH Already Exits."
  }
}

function New-Host {
  Param(
      [Parameter(Mandatory=$true)]
      [string]$HostName
  )
  New-Folder -FolderName .\reports\boxes\finished
  New-Folder -FolderName .\reports\boxes\in-progress
  New-Folder -FolderName ".\reports\boxes\to-do\$HostName"
  New-Folder -FolderName ".\reports\boxes\to-do\$Hostname\screenshots\01-recon"
  New-Folder -FolderName ".\reports\boxes\to-do\$Hostname\screenshots\02-information-gathering"
  New-Folder -FolderName ".\reports\boxes\to-do\$Hostname\screenshots\03-initial-foothold"
  New-Folder -FolderName ".\reports\boxes\to-do\$Hostname\screenshots\04-local-information-gathering"
  New-Folder -FolderName ".\reports\boxes\to-do\$Hostname\screenshots\05-privilege-escalation"
  New-Folder -FolderName ".\reports\boxes\to-do\$Hostname\screenshots\06-post-exploitation"
  if (-Not [System.IO.File]::Exists(".\reports\boxes\to-do\$Hostname\writeup-dataview-template.md"))
  {
    Copy-Item .\writeup-dataview-template.md .\reports\boxes\to-do\$Hostname
  }
  else 
  {
    Write-Verbose "Skipping .\reports\boxes\to-do\$Hostname\write-dataview-template.md, File Already Exits."
  }
  
}