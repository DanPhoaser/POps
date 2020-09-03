Function Write-POpsLog {
    <# 
        .SYNOPSIS 
            Write to a log file
     
        .DESCRIPTION 
            Writes to a log file in standard format or in cmtrace format for use with CMTRace.exe
            I created this function as an easy way to log to the console and to a set log file with the option of choosing
            a standard line by line log format or the cmtrace format which is typically used with MDT and SCCM.
            I was seeking something that provided the ability to log in either format, and so I created this function.

            Log type/level can be set as: 
                Error
                Warning
                Verbose
                Debug
                Information
            
            It will then output to the correct severity level for the cmtrace format if parameter
            <-LogFormat 'CMTrace'> is specified.
    
           Warnings will be highlighted in yellow. Errors are highlighted in red. 
    
      
        .EXAMPLE 
            Try{
                Get-Process -Name DoesnotExist -ea stop
            }
            Catch{
                Write-POpsLog -Logfile "C:\output\logfile.log -Message "Unable to get process" -Type Error
                Write-POpsLog -Logfile "C:\output\logfile.log -Message $_ -Type Error
            }
     
           This will write a line to the logfile.log file in c:\output\logfile.log. 
           When using the error record variable, It will extract the errordetails from the object and store it the log file
           and will highlight the line in Red with all the error details on the console. 
           By providing the error record object to the -Message parameter, it will provide extra error details like calling script, function, line where error occured, parameters used, etc.
     
        .EXAMPLE
            Write-POpsLog -Message "This is a verbose message." -MessageType Verbose
    
            This example will write a verbose entry into the log file and also write back to the host. The Write-POpsLog will obey
            the environment preference variables by temporarily switching $verbosepreference to continue and then back to the original value.
            This also applies to Warning, Debug, Information preference variables.
    
        .EXAMPLE
            Write-POpsLog -Message "This is an informational message" -MessageType Information -WriteHost:$false
    
            This example will write the informational message to the log but not back to the host.
    
        .EXAMPLE
            Function Test{
                [cmdletbinding()]
                Param()
                Write-POpsLog -Message "This is a verbose message" -MessageType Verbose
            }
            Test -Verbose
    
            This example shows how to use Write-POpsLog inside a function and then call the function with the -verbose switch.
            The Write-POpsLog function will then print the verbose message.
    
        .NOTES
            Author: DanPhoaser
            Credit: credit to https://wolffhaven.gitlab.io/wolffhaven_icarus_test/powershell/write-cmtracelog-dropping-logs-like-a-boss/
                as function was initially based off of this.
       
    #> 
    [CmdletBinding(SupportsShouldProcess = $false)] 
    Param(
        [parameter(Position = 0, Mandatory = $True)] 
        $Message,	
            
        [parameter(Mandatory = $false)]      
        [String]$LogFile = $null,
    
        [parameter(Mandatory = $false)]
        [ValidateSet('Warning', 'Error', 'Verbose', 'Debug', 'Information')] 
        [Alias('Type')]
        [String]$MessageType = 'Verbose',
    
        [parameter(Mandatory = $false)]
        [ValidateSet('Basic', 'CMTrace')] 
        [String]$LogFormat = 'Basic',
    
        #Write back to the console or just to the log file. 
        [parameter(Mandatory = $false)]
        [Alias('WriteBackToHost')]
        [switch]$WriteHost = $false
    )
    
    #Get preferences
    $CurWarningPref = $PSCmdlet.GetVariableValue('WarningPreference')
    $CurErrActPref = $PSCmdlet.GetVariableValue('ErrorActionPreference')
    $CurVbosPref = $PSCmdlet.GetVariableValue('VerbosePreference')
    $CurDbgPref = $PSCmdlet.GetVariableValue('DebugPreference')
    $CurInfoPref = $PSCmdlet.GetVariableValue('InformationPreference')
    
    #Get the info about the calling script, function etc
    $CallingInfo = (Get-PSCallStack)[1]
        
    #Set Source Information
    #$Source = (Get-PSCallStack)[1].Location
    $Source = "$($MyInvocation.ScriptName | Split-Path -Leaf -ErrorAction SilentlyContinue):$($MyInvocation.ScriptLineNumber)"
    $MessageType = $MessageType.ToUpper()
    
    #Set Component Information
    $Component = (Get-Process -Id $PID).ProcessName
    
    #Set PID Information
    $ProcessID = $PID
    
    #Obtain UTC offset 
    $UtcOffset = [timezone]::CurrentTimeZone.GetUtcOffset([datetime]::Now).TotalMinutes
    $CurTimeHostFormat = $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff')

    $HostMessage = ($CurTimeHostFormat + ' ' + "[$($MessageType)]" + ': ')
    If ($Message.Exception.Message) {
        $HostMessage = ($HostMessage + $Message.Exception.Message + "`n" + $Source)
    }
    Else {
        $HostMessage = ($HostMessage + $Message) 
    }
    If ( $null -eq $LogFile -or $LogFile -eq '') {
        $LogDir = 'C:\Windows\Temp\Write-POpsLog'
        $LogFile = $LogDir + '\Log_'
        $LogPathExists = Test-Path -Path $LogDir
    
        If ( $LogPathExists -eq $false ) {
            $null = New-Item -Path $LogDir -ItemType Directory -Force -WhatIf:$false
        }
        If ( $null -eq $CallingInfo.Command -or $CallingInfo.Command -like '<*>') {
            $LogFile = ($LogFile + 'Console.log')
        }
        Else {
            $LogFile = ($LogFile + $($CallingInfo.Command) + '.log')
        }
    }
    #Write-Host "LogFilePath: $($LogFile)"
        
    #Switch statement to write out to the log and/or back to the host.
    Switch ($MessageType) {    
        'Warning' {
            $Severity = 2
            if ($WriteHost) {
                $WarningPreference = 'Continue'
            }
            Write-Warning -Message $HostMessage
            $WarningPreference = $CurWarningPref
        }
        'Error' {  
            $Severity = 3
            $WriteHost = $true
            if ($null -ne $Message.Exception.Message) {
                $ErrObj = [pscustomobject]@{
                    Time              = $CurTimeHostFormat
                    Category          = $Message.CategoryInfo.Category
                    Reason            = $Message.CategoryInfo.Reason
                    Activity          = $Message.CategoryInfo.Activity
                    TargetName        = $Message.CategoryInfo.TargetName
                    TargetMessageType = $Message.CategoryInfo.TargetMessageType
                    MyCommand         = $Message.InvocationInfo.MyCommand         
                    BoundParameters   = $Message.InvocationInfo.BoundParameters
                    UnboundArguments  = $Message.InvocationInfo.UnboundArguments
                    ScriptName        = $Message.InvocationInfo.ScriptName
                    ScriptLineNumber  = $Message.InvocationInfo.ScriptLineNumber
                    OffsetInLine      = $Message.InvocationInfo.OffsetInLine
                    InvocationName    = $Message.InvocationInfo.InvocationName
                    PSScriptRoot      = $Message.InvocationInfo.PSScriptRoot
                    PSCommandPath     = $Message.InvocationInfo.PSCommandPath
                    Thrown            = $Message.Exception.WasThrownFromThrowStatement
                    Message           = $Message.Exception.Message
                }
                Write-Host "ERROR: $($ErrObj | Out-String)" -ForegroundColor Red -BackgroundColor Black
            }
            Else {
                Write-Host "$($HostMessage)" -ForegroundColor Red -BackgroundColor Black 
            }
        }
        'Verbose' {  
            $Severity = 4
            if ($WriteHost) {
                $VerbosePreference = 'Continue'
            }
            Write-Verbose -Message $($HostMessage)
            $VerbosePreference = $CurVbosPref                               
        }
        'Debug' {  
            $Severity = 5
            if ($WriteHost) {
                $DebugPreference = 'Continue'
            }
            Write-Debug -Message $($HostMessage)
            $DebugPreference = $CurDbgPref
                          
        }      
        'Information' {  
            $Severity = 6
            if ($WriteHost) {
                $InformationPreference = 'Continue'
            }
            Write-Information -Message "$($HostMessage)"
            $InformationPreference = $CurInfoPref
        }
    }#EndSwitch
    If ($LogFormat -eq 'CMTrace') {
        $LogLine = `
            "<![LOG[$($($MessageType.ToUpper()) + ": " + $message)]LOG]!>" + `
            "<time=`"$(Get-Date -Format HH:mm:ss.fff)$($UtcOffset)`" " + `
            "date=`"$(Get-Date -Format MM-dd-yyyy)`" " + `
            "component=`"$Component`" " + `
            "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + `
            "MessageType=`"$severity`" " + `
            "thread=`"$processid`" " + `
            "file=`"$source`">";
    }
    Else {
        $LogLine = $HostMessage
    }
        
    Try {            
        $LogLine | Out-File -Append -Encoding utf8 -FilePath $LogFile -Force -ErrorAction Stop -WhatIf:$false
    }
    Catch {
        Write-Host ("Error saving log: $($Error[0].Exception.Message)") -ForegroundColor Red -BackgroundColor Black
    }
}