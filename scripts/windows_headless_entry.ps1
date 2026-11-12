# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Deliberately avoid PowerShell's named-parameter binder. A rejected named
# parameter can otherwise write a host-generated error containing its source
# path before this script can redact it. The four exact vectors are parsed
# below; every other token sequence reaches the fixed invalid summary.
$entryInput = @($args)
$Operation = ''
$Target = ''
$Platform = ''
$Otp = ''

# The outer process gets one deadline. The inner runner has a shorter fixed
# deadline, leaving time inside this bound to kill the complete descendant tree
# and drain both redirected streams through EOF.
$deadlineByOperation = @{
    'fresh-build' = 600000
    'package-suite' = 1200000
    'runtime-stage' = 150000
    'credential-local' = 3480000
}
$outputLimitBytes = 65536L
$readChunkBytes = 4096
$cleanupReserveMilliseconds = 10000
$runnerMaximumBytes = 2097152L
$launcherMaximumBytes = 2097152L
$escriptMaximumBytes = 134217728L
$clock = [System.Diagnostics.Stopwatch]::StartNew()
$hardDeadlineMilliseconds = 1
$safeOperation = 'invalid'
$safeTarget = 'none'
$safeOtp = 'current'
$safeScope = 'invalid:none:windows-2025'
$safeRerunCommand = 'none'

$stage = 'arguments'
$failureCode = 'none'
$process = $null
$stdoutState = $null
$stderrState = $null
$childStarted = $false
$childJoined = $false
$recursiveTerminationRequested = $false
$deadlineExpired = $false
$outputLimitExceeded = $false
$streamFailure = $false
$runnerIdentityStable = $false
$launcherIdentityStable = $false
$toolIdentityStable = $false
$runtimeIdentityVerified = $false
$innerContractValid = $false
$innerPassed = $false
$innerFailureCode = 'none'
$configuredSteps = 0
$completedSteps = 0
$innerTreeEmpty = $false
$innerConsoleIsolated = $false
$innerDescendantsJoined = $false
$childExitStatus = -1
$stdoutBytes = 0L
$stderrBytes = 0L
$repo = $null
$runner = $null
$runnerHashBefore = $null
$launcherHashBefore = $null
$escriptHashBefore = $null
$escriptPathIdentity = $null
$configurationHash = $null
$safeSteps = @()

function Stop-DescendantTree {
    param([System.Diagnostics.Process]$Child)
    if ($null -eq $Child) {
        return $false
    }
    try {
        $Child.Refresh()
        if ($Child.HasExited) {
            return $false
        }
        # PowerShell 7 runs on a runtime with Process.Kill(Boolean). Requiring
        # that overload avoids a fallback through taskkill.exe or cmd.exe.
        $Child.Kill($true)
        return $true
    }
    catch {
        return $false
    }
}

function New-DrainState {
    param(
        [System.IO.Stream]$Stream,
        [bool]$CaptureEnabled
    )
    return @{
        Stream = $Stream
        Buffer = [byte[]]::new($readChunkBytes)
        ReadTask = $null
        Complete = $false
        Bytes = 0L
        Capture = if ($CaptureEnabled) {
            [System.IO.MemoryStream]::new()
        }
        else {
            $null
        }
    }
}

function Start-DrainRead {
    param([hashtable]$State)
    if (-not $State.Complete -and $null -eq $State.ReadTask) {
        $State.ReadTask = $State.Stream.ReadAsync(
            $State.Buffer, 0, $State.Buffer.Length)
    }
}

function Get-Utf8Sha256 {
    param([string]$Text)
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        return [Convert]::ToHexString(
            $algorithm.ComputeHash($bytes)).ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
    }
}

function Test-Sha256 {
    param([object]$Value)
    return ([string]$Value -cmatch '^[0-9a-f]{64}$')
}

function Test-ExactProperties {
    param(
        [object]$Value,
        [string[]]$Expected
    )
    if ($null -eq $Value) {
        return $false
    }
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    if ($actual.Count -ne $wanted.Count) {
        return $false
    }
    for ($index = 0; $index -lt $wanted.Count; $index++) {
        if ($actual[$index] -cne $wanted[$index]) {
            return $false
        }
    }
    return $true
}

function Test-FixedFailureCode {
    param([object]$Value)
    $candidate = [string]$Value
    return $candidate -cin @(
        'none',
        'deadline_exceeded',
        'output_limit_exceeded',
        'cleanup_unconfirmed',
        'startup_unconfirmed',
        'runtime_missing',
        'runtime_identity_mismatch',
        'child_failed',
        'launcher_failed',
        'unsupported_platform'
    )
}

function Test-OuterFailureCode {
    param([object]$Value)
    $candidate = [string]$Value
    return $candidate -cin @(
        'none',
        'invalid_arguments',
        'unsupported_platform',
        'runtime_identity_unavailable',
        'runtime_identity_mismatch',
        'child_start_failed',
        'outer_output_limit',
        'outer_deadline',
        'runner_identity_changed',
        'launcher_identity_changed',
        'tool_identity_changed',
        'outer_join_unconfirmed',
        'outer_stream_failure',
        'inner_contract_invalid',
        'deadline_exceeded',
        'output_limit_exceeded',
        'cleanup_unconfirmed',
        'startup_unconfirmed',
        'runtime_missing',
        'child_failed',
        'launcher_failed'
    )
}

function Test-JsonBoolean {
    param([object]$Value)
    return $Value -is [bool]
}

function Test-JsonInteger {
    param([object]$Value)
    return (($Value -is [int]) -or ($Value -is [long]))
}

function Test-InnerContract {
    param(
        [object]$Inner,
        [string[]]$ExpectedStepNames,
        [string]$ExpectedTarget,
        [string]$ExpectedOtp
    )
    $topProperties = @(
        'schema', 'report_kind', 'operation', 'target', 'platform', 'otp',
        'state', 'failure_code', 'configured_steps', 'completed_steps',
        'all_tree_empty', 'all_console_isolated', 'descendants_joined',
        'scope', 'source_sha256', 'configuration_sha256', 'tool_sha256',
        'runtime_identity_verified', 'rerun_command', 'steps', 'passed'
    )
    if (-not (Test-ExactProperties -Value $Inner -Expected $topProperties)) {
        return $false
    }
    if (
        -not (Test-JsonInteger -Value $Inner.schema) -or
        -not (Test-JsonInteger -Value $Inner.configured_steps) -or
        -not (Test-JsonInteger -Value $Inner.completed_steps) -or
        -not (Test-JsonBoolean -Value $Inner.all_tree_empty) -or
        -not (Test-JsonBoolean -Value $Inner.all_console_isolated) -or
        -not (Test-JsonBoolean -Value $Inner.descendants_joined) -or
        -not (Test-JsonBoolean -Value $Inner.runtime_identity_verified) -or
        -not (Test-JsonBoolean -Value $Inner.passed) -or
        [int]$Inner.schema -ne 1 -or
        [string]$Inner.report_kind -cne 'windows_headless_entry' -or
        [string]$Inner.operation -cne $Operation -or
        [string]$Inner.target -cne $ExpectedTarget -or
        [string]$Inner.platform -cne 'windows-2025' -or
        [string]$Inner.otp -cne $ExpectedOtp -or
        [string]$Inner.otp -cnotin @('28', '29') -or
        [string]$Inner.state -cnotin @('Ready', 'Failed') -or
        [string]$Inner.scope -cne $safeScope -or
        [string]$Inner.rerun_command -cne $safeRerunCommand -or
        -not (Test-Sha256 -Value $Inner.source_sha256) -or
        -not (Test-Sha256 -Value $Inner.configuration_sha256) -or
        -not (Test-Sha256 -Value $Inner.tool_sha256) -or
        [string]$Inner.source_sha256 -cne $runnerHashBefore -or
        [string]$Inner.configuration_sha256 -cne $configurationHash -or
        [string]$Inner.tool_sha256 -cne $escriptHashBefore -or
        -not (Test-FixedFailureCode -Value $Inner.failure_code)
    ) {
        return $false
    }
    if ($Inner.steps -isnot [System.Array]) {
        return $false
    }
    $steps = @($Inner.steps)
    if (
        [int]$Inner.configured_steps -ne $ExpectedStepNames.Count -or
        $steps.Count -ne $ExpectedStepNames.Count -or
        [int]$Inner.completed_steps -lt 0 -or
        [int]$Inner.completed_steps -gt $ExpectedStepNames.Count
    ) {
        return $false
    }
    $stepProperties = @(
        'step', 'exit_status', 'completed', 'passed', 'failure_code',
        'tree_empty', 'console_isolated', 'descendant_outlived',
        'termination_requested', 'output_limit_exceeded', 'timed_out'
    )
    $observedCompleted = 0
    $observedAllPassed = $steps.Count -eq $ExpectedStepNames.Count
    $observedAllTreeEmpty = $steps.Count -eq $ExpectedStepNames.Count
    $observedAllConsoleIsolated = $steps.Count -eq $ExpectedStepNames.Count
    $observedDescendantsJoined = $steps.Count -eq $ExpectedStepNames.Count
    $observedFailureCode = 'none'
    for ($index = 0; $index -lt $steps.Count; $index++) {
        $step = $steps[$index]
        if (
            -not (Test-ExactProperties -Value $step -Expected $stepProperties) -or
            -not (Test-JsonInteger -Value $step.exit_status) -or
            -not (Test-JsonBoolean -Value $step.completed) -or
            -not (Test-JsonBoolean -Value $step.passed) -or
            -not (Test-JsonBoolean -Value $step.tree_empty) -or
            -not (Test-JsonBoolean -Value $step.console_isolated) -or
            -not (Test-JsonBoolean -Value $step.descendant_outlived) -or
            -not (Test-JsonBoolean -Value $step.termination_requested) -or
            -not (Test-JsonBoolean -Value $step.output_limit_exceeded) -or
            -not (Test-JsonBoolean -Value $step.timed_out) -or
            [string]$step.step -cne $ExpectedStepNames[$index] -or
            -not (Test-FixedFailureCode -Value $step.failure_code) -or
            [int]$step.exit_status -lt -1 -or
            [int]$step.exit_status -gt 255
        ) {
            return $false
        }
        if ([bool]$step.completed) {
            $observedCompleted++
        }
        if (
            -not [bool]$step.passed -and
            $observedFailureCode -ceq 'none'
        ) {
            $observedFailureCode = [string]$step.failure_code
        }
        $observedAllPassed = $observedAllPassed -and [bool]$step.passed
        $observedAllTreeEmpty =
            $observedAllTreeEmpty -and [bool]$step.tree_empty
        $observedAllConsoleIsolated =
            $observedAllConsoleIsolated -and [bool]$step.console_isolated
        $observedDescendantsJoined =
            $observedDescendantsJoined -and
            [bool]$step.tree_empty -and
            -not [bool]$step.descendant_outlived
        if (
            [bool]$step.passed -and (
                -not [bool]$step.completed -or
                -not [bool]$step.tree_empty -or
                -not [bool]$step.console_isolated -or
                [bool]$step.descendant_outlived -or
                [bool]$step.termination_requested -or
                [bool]$step.output_limit_exceeded -or
                [bool]$step.timed_out -or
                [string]$step.failure_code -cne 'none' -or
                [int]$step.exit_status -ne 0
            )
        ) {
            return $false
        }
        if (
            -not [bool]$step.passed -and
            [string]$step.failure_code -ceq 'none'
        ) {
            return $false
        }
    }
    if (
        $observedCompleted -ne [int]$Inner.completed_steps -or
        $observedAllTreeEmpty -ne [bool]$Inner.all_tree_empty -or
        $observedAllConsoleIsolated -ne [bool]$Inner.all_console_isolated -or
        $observedDescendantsJoined -ne [bool]$Inner.descendants_joined
    ) {
        return $false
    }
    $ready = [bool]$Inner.passed
    if (
        $ready -ne ([string]$Inner.state -ceq 'Ready') -or
        ($ready -and [string]$Inner.failure_code -cne 'none') -or
        (-not $ready -and [string]$Inner.failure_code -ceq 'none') -or
        (-not $ready -and
            [string]$Inner.failure_code -cne $observedFailureCode) -or
        ($ready -and -not [bool]$Inner.runtime_identity_verified) -or
        ($ready -and $steps.Count -ne $ExpectedStepNames.Count) -or
        ($ready -and [int]$Inner.completed_steps -ne $ExpectedStepNames.Count) -or
        ($ready -and -not $observedAllPassed) -or
        ($ready -and -not [bool]$Inner.all_tree_empty) -or
        ($ready -and -not [bool]$Inner.all_console_isolated) -or
        ($ready -and -not [bool]$Inner.descendants_joined)
    ) {
        return $false
    }
    return $true
}

try {
    if (
        $entryInput.Count -eq 2 -and
        [string]$entryInput[0] -ceq '-Operation' -and
        [string]$entryInput[1] -ceq 'credential-local'
    ) {
        $Operation = 'credential-local'
    }
    elseif (
        $entryInput.Count -eq 4 -and
        [string]$entryInput[0] -ceq '-Operation' -and
        [string]$entryInput[1] -cin @('fresh-build', 'package-suite') -and
        [string]$entryInput[2] -ceq '-Target'
    ) {
        $Operation = [string]$entryInput[1]
        $Target = [string]$entryInput[3]
    }
    elseif (
        $entryInput.Count -eq 8 -and
        [string]$entryInput[0] -ceq '-Operation' -and
        [string]$entryInput[1] -ceq 'runtime-stage' -and
        [string]$entryInput[2] -ceq '-Target' -and
        [string]$entryInput[4] -ceq '-Platform' -and
        [string]$entryInput[6] -ceq '-Otp'
    ) {
        $Operation = 'runtime-stage'
        $Target = [string]$entryInput[3]
        $Platform = [string]$entryInput[5]
        $Otp = [string]$entryInput[7]
    }
    else {
        throw 'invalid_arguments'
    }
    if (
        [string]::IsNullOrEmpty($Operation) -or
        $Operation -cnotin @(
            'fresh-build',
            'package-suite',
            'runtime-stage',
            'credential-local'
        ) -or
        -not $deadlineByOperation.ContainsKey($Operation)
    ) {
        throw 'invalid_arguments'
    }
    $safeOperation = $Operation
    $hardDeadlineMilliseconds = [int]$deadlineByOperation[$Operation]
    switch ($Operation) {
        'fresh-build' {
            if ($Target -cnotin @('all', 'http', 'http3', 'core')) {
                throw 'invalid_arguments'
            }
            $safeTarget = $Target
            $safeScope = 'fresh-build:' + $safeTarget + ':windows-2025'
            $safeRerunCommand =
                'mise run windows-fresh-build -- -Target ' + $safeTarget
            $expectedStepNames = @('fresh_build')
            $configuredSteps = 1
        }
        'package-suite' {
            if ($Target -cnotin @('http', 'http3', 'core')) {
                throw 'invalid_arguments'
            }
            $safeTarget = $Target
            $safeScope = 'package-suite:' + $safeTarget + ':windows-2025'
            $safeRerunCommand =
                'mise run windows-package-suite -- -Target ' + $safeTarget
            $expectedStepNames = @(
                'canonical_etf_wire_self_test',
                'etf_boundary_audit_self_test',
                'etf_boundary_audit',
                'windows_console_inheritance_audit',
                'package_suite'
            )
            $configuredSteps = 5
        }
        'runtime-stage' {
            if ($Target -cnotin @('http', 'http3', 'core') -or
                $Platform -cne 'windows-2025' -or
                $Otp -cnotin @('28', '29')) {
                throw 'invalid_arguments'
            }
            $safeTarget = $Target
            $safeScope = 'runtime-stage:' + $safeTarget + ':windows-2025'
            $safeRerunCommand =
                'mise run windows-runtime-stage -- -Target ' + $safeTarget +
                ' -Platform windows-2025 -Otp ' + $Otp
            $expectedStepNames = @('runtime_stage')
            $configuredSteps = 1
        }
        'credential-local' {
            $safeScope = 'credential-local:none:windows-2025'
            $safeRerunCommand = 'mise run windows-credential-local'
            $expectedStepNames = @(
                'credential_self_test',
                'credential_fresh_build',
                'credential_matrix'
            )
            $configuredSteps = 3
        }
        default {
            throw 'invalid_arguments'
        }
    }

    $stage = 'preflight'
    if (
        [System.Environment]::OSVersion.Platform -ne
            [System.PlatformID]::Win32NT -or
        $PSVersionTable.PSVersion.Major -lt 7 -or
        $null -eq ([System.Diagnostics.Process]).GetMethod(
            'Kill', [type[]]@([bool]))
    ) {
        throw 'unsupported_platform'
    }

    $stage = 'identity'
    $configuredRuntime = [string]$env:MISE_ERLANG_VERSION
    if ($configuredRuntime -cnotmatch '^(28|29)(?:\.[0-9]+){0,3}$') {
        throw 'runtime_identity_missing'
    }
    $safeOtp = [string]$Matches[1]
    if ($Operation -ceq 'runtime-stage' -and $safeOtp -cne $Otp) {
        throw 'runtime_identity_mismatch'
    }
    $repo = [System.IO.Path]::GetFullPath(
        (Join-Path $PSScriptRoot '..'))
    $runner = [System.IO.Path]::GetFullPath(
        (Join-Path $repo 'scripts\process_runner.escript'))
    $launcherInformation = [System.IO.FileInfo]::new($PSCommandPath)
    if (
        -not $launcherInformation.Exists -or
        $launcherInformation.Length -le 0 -or
        $launcherInformation.Length -gt $launcherMaximumBytes
    ) {
        throw 'launcher_identity_unavailable'
    }
    if (-not [System.IO.File]::Exists($runner)) {
        throw 'runner_missing'
    }
    $runnerInformation = [System.IO.FileInfo]::new($runner)
    if (
        -not $runnerInformation.Exists -or
        $runnerInformation.Length -le 0 -or
        $runnerInformation.Length -gt $runnerMaximumBytes
    ) {
        throw 'runner_identity_unavailable'
    }
    $runnerHashBefore = (
        Get-FileHash -LiteralPath $runner -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    $launcherHashBefore = (
        Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    $escriptCommand = @(Get-Command -Name 'escript.exe' -CommandType Application -ErrorAction Stop | Select-Object -First 1)[0]
    if ($null -eq $escriptCommand) {
        throw 'runtime_missing'
    }
    $escript = [System.IO.Path]::GetFullPath($escriptCommand.Source)
    if (
        [System.IO.Path]::GetFileName($escript) -cne 'escript.exe' -or
        -not [System.IO.File]::Exists($escript)
    ) {
        throw 'runtime_missing'
    }
    $escriptInformation = [System.IO.FileInfo]::new($escript)
    if (
        -not $escriptInformation.Exists -or
        $escriptInformation.Length -le 0 -or
        $escriptInformation.Length -gt $escriptMaximumBytes
    ) {
        throw 'runtime_identity_unavailable'
    }
    $escriptHashBefore = (
        Get-FileHash -LiteralPath $escript -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    $escriptPathIdentity = Get-Utf8Sha256 -Text (
        $escript.Replace('\', '/').ToLowerInvariant())
    $configurationHash = Get-Utf8Sha256 -Text (
        'windows-entry-v1|' + $Operation + '|' + $safeTarget +
        '|windows-2025|' + $safeOtp)
    if ($clock.ElapsedMilliseconds -ge $hardDeadlineMilliseconds) {
        $deadlineExpired = $true
        throw 'outer_deadline'
    }

    $entryArguments = [System.Collections.Generic.List[string]]::new()
    $entryArguments.Add($runner)
    $entryArguments.Add('--windows-entry')
    $entryArguments.Add($Operation)
    switch ($Operation) {
        'fresh-build' {
            $entryArguments.Add($Target)
            $expectedTarget = $Target
        }
        'package-suite' {
            $entryArguments.Add($Target)
            $expectedTarget = $Target
        }
        'runtime-stage' {
            $entryArguments.Add($Target)
            $entryArguments.Add($Platform)
            $entryArguments.Add($Otp)
            $expectedTarget = $Target
        }
        'credential-local' {
            $expectedTarget = 'none'
        }
    }

    $stage = 'start'
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $escript
    $startInfo.WorkingDirectory = $repo
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($entryArgument in $entryArguments) {
        $startInfo.ArgumentList.Add($entryArgument)
    }
    $startInfo.Environment['ERL_AFLAGS'] = ''
    $startInfo.Environment['ERL_FLAGS'] = ''
    $startInfo.Environment['ERL_ZFLAGS'] = ''
    $startInfo.Environment['ERL_CRASH_DUMP_BYTES'] = '0'
    $startInfo.Environment['ERL_CRASH_DUMP_SECONDS'] = '0'
    $startInfo.Environment['HTTP_WINDOWS_EXPECTED_OTP'] = $safeOtp
    $startInfo.Environment['HTTP_WINDOWS_ESCRIPT_SHA256'] =
        $escriptHashBefore
    $startInfo.Environment['HTTP_WINDOWS_ESCRIPT_PATH_ID'] =
        $escriptPathIdentity
    $startInfo.Environment['HTTP_WINDOWS_RUNNER_SHA256'] =
        $runnerHashBefore
    $startInfo.Environment['HTTP_WINDOWS_CONFIGURATION_SHA256'] =
        $configurationHash
    # Do not accept an inherited executable override. Prefer the fixed Git for
    # Windows location; the owned runner may otherwise resolve only bash.exe
    # or bash from its inherited application search path.
    [void]$startInfo.Environment.Remove('HTTP_BASH_EXECUTABLE')
    $gitBash = [System.IO.Path]::GetFullPath(
        (Join-Path $env:ProgramFiles 'Git\bin\bash.exe'))
    if ([System.IO.File]::Exists($gitBash)) {
        $startInfo.Environment['HTTP_BASH_EXECUTABLE'] = $gitBash
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw 'child_start_failed'
    }
    $childStarted = $true
    $stdoutState = New-DrainState -Stream $process.StandardOutput.BaseStream -CaptureEnabled $true
    $stderrState = New-DrainState -Stream $process.StandardError.BaseStream -CaptureEnabled $false
    Start-DrainRead -State $stdoutState
    Start-DrainRead -State $stderrState

    $stage = 'drain'
    while ($true) {
        $remaining = $hardDeadlineMilliseconds - [int]$clock.ElapsedMilliseconds
        if ($remaining -le 0) {
            $deadlineExpired = $true
            if (-not $process.HasExited) {
                $recursiveTerminationRequested =
                    (Stop-DescendantTree -Child $process) -or
                    $recursiveTerminationRequested
            }
            break
        }
        if (
            -not $recursiveTerminationRequested -and
            -not $process.HasExited -and
            $remaining -le $cleanupReserveMilliseconds
        ) {
            $deadlineExpired = $true
            $recursiveTerminationRequested =
                Stop-DescendantTree -Child $process
        }

        $tasks = [System.Collections.Generic.List[System.Threading.Tasks.Task]]::new()
        if ($null -ne $stdoutState.ReadTask) {
            $tasks.Add($stdoutState.ReadTask)
        }
        if ($null -ne $stderrState.ReadTask) {
            $tasks.Add($stderrState.ReadTask)
        }
        if ($tasks.Count -gt 0) {
            $waitMilliseconds = [Math]::Min(250, [Math]::Max(1, $remaining))
            [void][System.Threading.Tasks.Task]::WaitAny(
                $tasks.ToArray(), $waitMilliseconds)
        }
        else {
            [System.Threading.Thread]::Sleep(
                [Math]::Min(25, [Math]::Max(1, $remaining)))
        }

        foreach ($state in @($stdoutState, $stderrState)) {
            if ($null -ne $state.ReadTask -and $state.ReadTask.IsCompleted) {
                try {
                    $read = [int]$state.ReadTask.GetAwaiter().GetResult()
                }
                catch {
                    $read = 0
                    $streamFailure = $true
                }
                $state.ReadTask = $null
                if ($read -eq 0) {
                    $state.Complete = $true
                }
                else {
                    $priorTotal = [long]$stdoutState.Bytes +
                        [long]$stderrState.Bytes
                    $state.Bytes = [Math]::Min(
                        $outputLimitBytes + 1L,
                        [long]$state.Bytes + [long]$read)
                    $nextTotal = [long]$stdoutState.Bytes +
                        [long]$stderrState.Bytes
                    if (
                        $priorTotal + [long]$read -le $outputLimitBytes -and
                        -not $outputLimitExceeded
                    ) {
                        if ($null -ne $state.Capture) {
                            $state.Capture.Write($state.Buffer, 0, $read)
                        }
                    }
                    if ($nextTotal -gt $outputLimitBytes) {
                        $outputLimitExceeded = $true
                        if (-not $process.HasExited) {
                            $recursiveTerminationRequested =
                                (Stop-DescendantTree -Child $process) -or
                                $recursiveTerminationRequested
                        }
                    }
                    Start-DrainRead -State $state
                }
            }
        }

        $process.Refresh()
        if (
            $process.HasExited -and
            $stdoutState.Complete -and
            $stderrState.Complete
        ) {
            $childJoined = $true
            break
        }
    }

    $stdoutBytes = [long]$stdoutState.Bytes
    $stderrBytes = [long]$stderrState.Bytes
    if ($process.HasExited) {
        $childExitStatus = [int]$process.ExitCode
    }

    $stage = 'validate'
    if ($clock.ElapsedMilliseconds -ge $hardDeadlineMilliseconds) {
        $deadlineExpired = $true
    }
    if (-not $deadlineExpired) {
        $runnerHashAfter = (
            Get-FileHash -LiteralPath $runner -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        $launcherHashAfter = (
            Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        $escriptHashAfter = (
            Get-FileHash -LiteralPath $escript -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        $runnerIdentityStable = $runnerHashBefore -ceq $runnerHashAfter
        $launcherIdentityStable =
            $launcherHashBefore -ceq $launcherHashAfter
        $toolIdentityStable = $escriptHashBefore -ceq $escriptHashAfter
        if ($clock.ElapsedMilliseconds -ge $hardDeadlineMilliseconds) {
            $deadlineExpired = $true
        }
    }
    if (
        $childJoined -and
        -not $deadlineExpired -and
        -not $outputLimitExceeded -and
        -not $streamFailure -and
        $stderrBytes -eq 0 -and
        $stdoutBytes -gt 0 -and
        $runnerIdentityStable -and
        $launcherIdentityStable -and
        $toolIdentityStable
    ) {
        try {
            $strictUtf8 = [System.Text.UTF8Encoding]::new($false, $true)
            $innerText = $strictUtf8.GetString($stdoutState.Capture.ToArray())
            $inner = ConvertFrom-Json -InputObject $innerText -Depth 8
            $expectedOtp = $safeOtp
            $innerContractValid = Test-InnerContract -Inner $inner -ExpectedStepNames $expectedStepNames -ExpectedTarget $expectedTarget -ExpectedOtp $expectedOtp
            if ($innerContractValid) {
                $innerPassed = [bool]$inner.passed
                $innerFailureCode = [string]$inner.failure_code
                $safeOtp = [string]$inner.otp
                $completedSteps = [int]$inner.completed_steps
                $safeSteps = @($inner.steps)
                $innerTreeEmpty = [bool]$inner.all_tree_empty
                $innerConsoleIsolated = [bool]$inner.all_console_isolated
                $innerDescendantsJoined = [bool]$inner.descendants_joined
                $runtimeIdentityVerified =
                    [bool]$inner.runtime_identity_verified
                if (
                    ($childExitStatus -eq 0 -and -not $innerPassed) -or
                    ($childExitStatus -ne 0 -and $innerPassed)
                ) {
                    $innerContractValid = $false
                }
            }
        }
        catch {
            $innerContractValid = $false
        }
        if ($clock.ElapsedMilliseconds -ge $hardDeadlineMilliseconds) {
            $deadlineExpired = $true
            $innerContractValid = $false
        }
    }

    if ($outputLimitExceeded) {
        $failureCode = 'outer_output_limit'
    }
    elseif ($deadlineExpired) {
        $failureCode = 'outer_deadline'
    }
    elseif (-not $runnerIdentityStable) {
        $failureCode = 'runner_identity_changed'
    }
    elseif (-not $launcherIdentityStable) {
        $failureCode = 'launcher_identity_changed'
    }
    elseif (-not $toolIdentityStable) {
        $failureCode = 'tool_identity_changed'
    }
    elseif (-not $childJoined) {
        $failureCode = 'outer_join_unconfirmed'
    }
    elseif ($streamFailure) {
        $failureCode = 'outer_stream_failure'
    }
    elseif (-not $innerContractValid) {
        $failureCode = 'inner_contract_invalid'
    }
    elseif (-not $innerPassed) {
        $failureCode = $innerFailureCode
    }
    elseif ($childExitStatus -ne 0) {
        $failureCode = 'child_failed'
    }
}
catch {
    if ($deadlineExpired) {
        $failureCode = 'outer_deadline'
    }
    else {
        $failureCode = switch ($stage) {
            'arguments' { 'invalid_arguments' }
            'preflight' { 'unsupported_platform' }
            'identity' {
                if ($_.Exception.Message -ceq 'runtime_identity_mismatch') {
                    'runtime_identity_mismatch'
                }
                else {
                    'runtime_identity_unavailable'
                }
            }
            'start' { 'child_start_failed' }
            'drain' { 'outer_stream_failure' }
            'validate' { 'inner_contract_invalid' }
            default { 'launcher_failed' }
        }
    }
}
finally {
    if ($null -ne $process) {
        try {
            $process.Refresh()
            if (-not $process.HasExited) {
                $recursiveTerminationRequested =
                    (Stop-DescendantTree -Child $process) -or
                    $recursiveTerminationRequested
            }
            $remaining = $hardDeadlineMilliseconds -
                [int]$clock.ElapsedMilliseconds
            if ($remaining -gt 0 -and $process.WaitForExit($remaining)) {
                $childJoined = $childJoined -or (
                    ($null -eq $stdoutState -or $stdoutState.Complete) -and
                    ($null -eq $stderrState -or $stderrState.Complete)
                )
                $childExitStatus = [int]$process.ExitCode
            }
        }
        catch {
            $childJoined = $false
        }
    }
}

if (-not (Test-OuterFailureCode -Value $failureCode)) {
    $failureCode = 'launcher_failed'
}

$passed = (
    $failureCode -ceq 'none' -and
    $childStarted -and
    $childJoined -and
    $runnerIdentityStable -and
    $launcherIdentityStable -and
    $toolIdentityStable -and
    $runtimeIdentityVerified -and
    $innerContractValid -and
    $innerPassed -and
    $innerTreeEmpty -and
    $innerConsoleIsolated -and
    $innerDescendantsJoined -and
    -not $deadlineExpired -and
    -not $outputLimitExceeded -and
    -not $streamFailure -and
    $childExitStatus -eq 0
)

$summary = [ordered]@{
    schema = 1
    stage = 'windows-headless-entry'
    operation = $safeOperation
    target = $safeTarget
    platform = 'windows-2025'
    otp = $safeOtp
    state = if ($passed) { 'Ready' } else { 'Failed' }
    failure_code = $failureCode
    configured_steps = $configuredSteps
    completed_steps = $completedSteps
    child_started = $childStarted
    child_joined = $childJoined
    child_exit_status = $childExitStatus
    recursive_termination_requested = $recursiveTerminationRequested
    deadline_expired = $deadlineExpired
    output_limit_exceeded = $outputLimitExceeded
    stdout_bytes = $stdoutBytes
    stderr_bytes = $stderrBytes
    streams_drained = (
        $null -ne $stdoutState -and $stdoutState.Complete -and
        $null -ne $stderrState -and $stderrState.Complete
    )
    runner_identity_stable = $runnerIdentityStable
    launcher_identity_stable = $launcherIdentityStable
    tool_identity_stable = $toolIdentityStable
    runtime_identity_verified = $runtimeIdentityVerified
    launcher_sha256 = if ($launcherHashBefore -cmatch '^[0-9a-f]{64}$') {
        $launcherHashBefore
    } else { 'unavailable' }
    source_sha256 = if ($runnerHashBefore -cmatch '^[0-9a-f]{64}$') {
        $runnerHashBefore
    } else { 'unavailable' }
    configuration_sha256 = if ($configurationHash -cmatch '^[0-9a-f]{64}$') {
        $configurationHash
    } else { 'unavailable' }
    tool_name = 'otp-escript'
    tool_sha256 = if ($escriptHashBefore -cmatch '^[0-9a-f]{64}$') {
        $escriptHashBefore
    } else { 'unavailable' }
    scope = $safeScope
    rerun_command = $safeRerunCommand
    steps = $safeSteps
    inner_contract_valid = $innerContractValid
    inner_tree_empty = $innerTreeEmpty
    inner_console_isolated = $innerConsoleIsolated
    inner_descendants_joined = $innerDescendantsJoined
    passed = $passed
}

# Do not forward the child's output. The only public output is this fixed,
# payload-free projection. Its source/tool digests and allowlisted rerun command
# identify the exact bounded run without exposing a path, argv, process id,
# endpoint, credential, exception, or output tail.
$summary | ConvertTo-Json -Compress -Depth 6

if ($null -ne $stdoutState -and $null -ne $stdoutState.Capture) {
    $stdoutState.Capture.Dispose()
}
if ($null -ne $stderrState -and $null -ne $stderrState.Capture) {
    $stderrState.Capture.Dispose()
}
if ($null -ne $process) {
    $process.Dispose()
}

if ($passed) {
    exit 0
}
exit 1
