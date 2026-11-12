# Bounded launcher for the Windows process-supervisor visibility proof.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('28', '29')]
    [string] $OtpMajor,

    [ValidateRange(5000, 30000)]
    [int] $DurationMilliseconds = 30000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = [System.IO.Path]::GetFullPath((Get-Location).Path)
$escriptCommand = Get-Command 'escript.exe' -CommandType Application `
    -ErrorAction SilentlyContinue | Select-Object -First 1
$EscriptExecutable = if ($null -ne $escriptCommand) {
    $escriptCommand.Source
} else { '' }
$PythonExecutable = $env:HTTP_PROCESS_SUPERVISOR_PYTHON
if ([string]::IsNullOrWhiteSpace($PythonExecutable)) {
    $candidate = Get-Command 'python.exe' -CommandType Application `
        -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $candidate) { $PythonExecutable = $candidate.Source }
}
$runtimePathsAvailable = -not (
    [string]::IsNullOrWhiteSpace($EscriptExecutable) -or
    [string]::IsNullOrWhiteSpace($PythonExecutable) -or
    -not [System.IO.File]::Exists($EscriptExecutable) -or
    -not [System.IO.File]::Exists($PythonExecutable)
)
$escript = if ($runtimePathsAvailable) {
    [System.IO.Path]::GetFullPath($EscriptExecutable)
} else { '' }
$python = if ($runtimePathsAvailable) {
    [System.IO.Path]::GetFullPath($PythonExecutable)
} else { '' }
$otpBin = if ($runtimePathsAvailable) {
    [System.IO.Path]::GetDirectoryName($escript)
} else { '' }
$pwsh = Join-Path $PSHOME 'pwsh.exe'
$watchScript = Join-Path $repo 'scripts\windows_process_visibility_watch.ps1'
$runnerScript = Join-Path $repo 'scripts\process_runner.escript'
$workDirectory = Join-Path $repo 'build\test-runner'
[System.IO.Directory]::CreateDirectory($workDirectory) | Out-Null
$resultPath = Join-Path $workDirectory (
    'windows-console-inheritance-otp' + $OtpMajor + '.json')

$bytes = [byte[]]::new(16)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$token = [Convert]::ToHexString($bytes).ToLowerInvariant()
$ready = Join-Path $workDirectory (
    'windows-process-visibility-' + $token + '.ready')
$owner = Join-Path $workDirectory (
    'windows-process-visibility-' + $token + '.owner')
$watchOut = Join-Path $workDirectory ($token + '.watch.stdout')
$watchErr = Join-Path $workDirectory ($token + '.watch.stderr')
$crashDump = Join-Path $workDirectory ($token + '.erl-crash.dump')
$paths = @($ready, $owner, $watchOut, $watchErr, $crashDump)
$watcher = $null
$fixture = $null
$outsider = $null
$fixtureStdoutState = $null
$fixtureStderrState = $null
$outsiderStdoutState = $null
$outsiderStderrState = $null
$clock = [System.Diagnostics.Stopwatch]::StartNew()
$stage = 'initialization'
$watcherFailureCode = 'none'
$readinessDeadlineMilliseconds = 10000
$hardDeadlineMilliseconds =
    $DurationMilliseconds + $readinessDeadlineMilliseconds + 15000
$cleanupReserveMilliseconds = 5000
$readChunkBytes = 4096
$ownedOutputLimitBytes = 133120L
$watcherOutputLimitBytes = 524288L
$reportLimitBytes = 1048576L
$ownedOutputLimitExceeded = $false
$streamFailure = $false
$deadlineExpired = $false
$completedChecks = 0
$escriptHashBefore = $null

function Stop-OwnedProcess {
    param([System.Diagnostics.Process] $Process)
    if ($null -eq $Process) { return }
    try {
        if (-not $Process.HasExited) {
            $Process.Kill($true)
        }
    }
    catch {
        # The final residue check remains authoritative.
    }
}

function Join-OwnedProcess {
    param([System.Diagnostics.Process] $Process)
    if ($null -eq $Process) { return $true }
    try {
        $remaining = $hardDeadlineMilliseconds -
            [int]$clock.ElapsedMilliseconds
        if ($Process.HasExited) { return $true }
        if ($remaining -le 0) { return $false }
        return $Process.WaitForExit($remaining)
    }
    catch {
        return $false
    }
}

function New-DrainState {
    param(
        [System.IO.Stream] $Stream,
        [bool] $CaptureEnabled
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
    param([hashtable] $State)
    if (-not $State.Complete -and $null -eq $State.ReadTask) {
        $State.ReadTask = $State.Stream.ReadAsync(
            $State.Buffer, 0, $State.Buffer.Length)
    }
}

function Read-BoundedText {
    param([string] $Path, [int64] $Limit)
    if (-not [System.IO.File]::Exists($Path)) { return '' }
    $stream = [System.IO.File]::Open(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
    $capture = [System.IO.MemoryStream]::new()
    try {
        $buffer = [byte[]]::new($readChunkBytes)
        while ($true) {
            if ($clock.ElapsedMilliseconds -ge $hardDeadlineMilliseconds) {
                throw 'owned_process_absolute_deadline'
            }
            $read = $stream.Read($buffer, 0, $buffer.Length)
            if ($read -eq 0) { break }
            if ([long]$capture.Length + [long]$read -gt $Limit) {
                throw 'bounded_output_exceeded'
            }
            $capture.Write($buffer, 0, $read)
        }
        $strictUtf8 = [System.Text.UTF8Encoding]::new($false, $true)
        return $strictUtf8.GetString($capture.ToArray())
    }
    finally {
        $capture.Dispose()
        $stream.Dispose()
    }
}

function Write-PublicReport {
    param([string] $Json)
    $encoded = [System.Text.UTF8Encoding]::new($false).GetBytes($Json + "`n")
    if ($encoded.Length -gt $reportLimitBytes) {
        throw 'public_report_limit_exceeded'
    }
    $temporary = $resultPath + '.tmp'
    if ([System.IO.File]::Exists($temporary)) {
        [System.IO.File]::Delete($temporary)
    }
    [System.IO.File]::WriteAllBytes($temporary, $encoded)
    [System.IO.File]::Move($temporary, $resultPath, $true)
}

function Get-BoundedFileSha256 {
    param([string] $Path, [int64] $Limit)
    $information = [System.IO.FileInfo]::new($Path)
    if (
        -not $information.Exists -or
        $information.Length -le 0 -or
        $information.Length -gt $Limit
    ) {
        throw 'bounded_identity_rejected'
    }
    if ($clock.ElapsedMilliseconds -ge $hardDeadlineMilliseconds) {
        $script:deadlineExpired = $true
        throw 'owned_process_absolute_deadline'
    }
    $hashValue = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($clock.ElapsedMilliseconds -ge $hardDeadlineMilliseconds) {
        $script:deadlineExpired = $true
        throw 'owned_process_absolute_deadline'
    }
    return $hashValue.ToLowerInvariant()
}

function Get-Utf8Sha256 {
    param([string] $Text)
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [Convert]::ToHexString($algorithm.ComputeHash(
            [System.Text.Encoding]::UTF8.GetBytes($Text))).ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
    }
}

function Read-LastJson {
    param([string] $Text)
    $lines = @($Text -split "`r?`n" | Where-Object { $_ -match '^\{.*\}$' })
    if ($lines.Count -eq 0) { throw 'json_record_missing' }
    return $lines[$lines.Count - 1] | ConvertFrom-Json
}

function Get-LauncherFailureCode {
    param([string] $Message, [string] $StageName)
    $known = @{
        'runtime_identity_missing' = $true
        'runtime_identity_mismatch' = $true
        'bounded_output_exceeded' = $true
        'json_record_missing' = $true
        'watcher_readiness_rejected' = $true
        'watcher_readiness_timeout' = $true
        'fixture_start_failed' = $true
        'outsider_start_failed' = $true
        'fixture_absolute_deadline' = $true
        'watcher_absolute_deadline' = $true
        'outsider_absolute_deadline' = $true
        'watcher_contract_failed' = $true
        'owned_process_absolute_deadline' = $true
        'owned_output_limit_exceeded' = $true
        'stream_drain_failed' = $true
        'tree_join_unconfirmed' = $true
        'public_report_limit_exceeded' = $true
        'bounded_identity_rejected' = $true
    }
    if ($known.ContainsKey($Message)) { return $Message }
    if ($StageName -match '^[a-z_]{1,48}$') { return $StageName + '_failed' }
    return 'launcher_failed'
}

try {
    if (-not $runtimePathsAvailable) {
        throw 'runtime_identity_missing'
    }
    foreach ($priorReport in @($resultPath, ($resultPath + '.tmp'))) {
        if ([System.IO.File]::Exists($priorReport)) {
            [System.IO.File]::Delete($priorReport)
        }
    }
    foreach ($path in $paths) {
        if ([System.IO.File]::Exists($path)) {
            [System.IO.File]::Delete($path)
        }
    }

    $stage = 'runtime_identity'
    $expectedEscriptHash = [string]$env:HTTP_WINDOWS_ESCRIPT_SHA256
    $expectedEscriptPathIdentity =
        [string]$env:HTTP_WINDOWS_ESCRIPT_PATH_ID
    if (
        $expectedEscriptHash -cnotmatch '^[0-9a-f]{64}$' -or
        $expectedEscriptPathIdentity -cnotmatch '^[0-9a-f]{64}$'
    ) {
        throw 'runtime_identity_missing'
    }
    $escriptHashBefore = Get-BoundedFileSha256 `
        -Path $escript -Limit 134217728
    $actualEscriptPathIdentity = Get-Utf8Sha256 -Text (
        $escript.Replace('\', '/').ToLowerInvariant())
    if (
        $escriptHashBefore -cne $expectedEscriptHash -or
        $actualEscriptPathIdentity -cne $expectedEscriptPathIdentity
    ) {
        throw 'runtime_identity_mismatch'
    }

    $stage = 'watcher_start'
    $watcher = Start-Process -FilePath $pwsh -ArgumentList @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-File', $watchScript,
        '-Stage', 'console-inheritance',
        '-DurationMilliseconds', [string]$DurationMilliseconds,
        '-SamplePeriodMilliseconds', '20',
        '-ReadyToken', $token,
        '-RequireOwnerBinding'
    ) -WorkingDirectory $repo -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput $watchOut -RedirectStandardError $watchErr

    $stage = 'watcher_readiness'
    $readinessAbsoluteMilliseconds = [Math]::Min(
        $hardDeadlineMilliseconds - $cleanupReserveMilliseconds,
        [int]$clock.ElapsedMilliseconds + $readinessDeadlineMilliseconds)
    while (
        -not [System.IO.File]::Exists($ready) -and
        -not $watcher.HasExited -and
        $clock.ElapsedMilliseconds -lt $readinessAbsoluteMilliseconds
    ) {
        Start-Sleep -Milliseconds 20
    }
    if (-not [System.IO.File]::Exists($ready)) {
        if ($watcher.HasExited) {
            $rejectedText = Read-BoundedText -Path $watchOut -Limit 262144
            try {
                $rejectedJson = Read-LastJson -Text $rejectedText
                if ($null -ne $rejectedJson.PSObject.Properties['failure_code']) {
                    $candidateFailureCode = [string]$rejectedJson.failure_code
                    if ($candidateFailureCode -match '^[a-z_]{1,64}$') {
                        $watcherFailureCode = $candidateFailureCode
                    }
                }
                elseif (
                    $null -ne $rejectedJson.PSObject.Properties['passed'] -and
                    $rejectedJson.passed -eq $false
                ) {
                    $watcherFailureCode = 'readiness_not_signaled'
                }
            }
            catch {
                $watcherFailureCode = 'readiness_output_invalid'
            }
            throw 'watcher_readiness_rejected'
        }
        throw 'watcher_readiness_timeout'
    }

    $stage = 'fixture_start'
    $fixtureStart = [System.Diagnostics.ProcessStartInfo]::new()
    $fixtureStart.FileName = $escript
    $fixtureStart.WorkingDirectory = $repo
    $fixtureStart.UseShellExecute = $false
    $fixtureStart.CreateNoWindow = $true
    $fixtureStart.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $fixtureStart.RedirectStandardOutput = $true
    $fixtureStart.RedirectStandardError = $true
    $fixtureStart.ArgumentList.Add($runnerScript)
    $fixtureStart.ArgumentList.Add('--console-self-test')
    $fixtureStart.Environment['PATH'] = (
        $otpBin + [System.IO.Path]::PathSeparator + $env:PATH)
    $fixtureStart.Environment['ERL_AFLAGS'] = ''
    $fixtureStart.Environment['ERL_FLAGS'] = ''
    $fixtureStart.Environment['ERL_ZFLAGS'] = ''
    $fixtureStart.Environment['ERL_CRASH_DUMP'] = $crashDump
    $fixtureStart.Environment['HTTP_PROCESS_SUPERVISOR_PYTHON'] = $python
    $fixture = [System.Diagnostics.Process]::new()
    $fixture.StartInfo = $fixtureStart
    if (-not $fixture.Start()) { throw 'fixture_start_failed' }

    $stage = 'owner_binding_write'
    $ownerRecord = (
        $fixture.Id.ToString([System.Globalization.CultureInfo]::InvariantCulture) +
        ':' +
        $fixture.StartTime.ToUniversalTime().Ticks.ToString(
            [System.Globalization.CultureInfo]::InvariantCulture) +
        "`n")
    $ownerBytes = [System.Text.Encoding]::ASCII.GetBytes($ownerRecord)
    $ownerRecord = $null
    $ownerStream = [System.IO.File]::Open(
        $owner,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None)
    try {
        $ownerStream.Write($ownerBytes, 0, $ownerBytes.Length)
        $ownerStream.Flush($true)
    }
    finally {
        $ownerBytes = $null
        $ownerStream.Dispose()
    }
    $fixtureStdoutState = New-DrainState `
        -Stream $fixture.StandardOutput.BaseStream -CaptureEnabled $true
    $fixtureStderrState = New-DrainState `
        -Stream $fixture.StandardError.BaseStream -CaptureEnabled $false
    Start-DrainRead -State $fixtureStdoutState
    Start-DrainRead -State $fixtureStderrState

    # This independently owned target overlaps the watched interval and must
    # never be attributed to the bound fixture merely because it starts later.
    $stage = 'outsider_start'
    $outsiderStart = [System.Diagnostics.ProcessStartInfo]::new()
    $outsiderStart.FileName = $python
    $outsiderStart.WorkingDirectory = $repo
    $outsiderStart.UseShellExecute = $false
    $outsiderStart.CreateNoWindow = $true
    $outsiderStart.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $outsiderStart.RedirectStandardOutput = $true
    $outsiderStart.RedirectStandardError = $true
    $outsiderStart.ArgumentList.Add('-c')
    $outsiderStart.ArgumentList.Add('import time; time.sleep(2)')
    $outsider = [System.Diagnostics.Process]::new()
    $outsider.StartInfo = $outsiderStart
    if (-not $outsider.Start()) { throw 'outsider_start_failed' }
    $outsiderStdoutState = New-DrainState `
        -Stream $outsider.StandardOutput.BaseStream -CaptureEnabled $false
    $outsiderStderrState = New-DrainState `
        -Stream $outsider.StandardError.BaseStream -CaptureEnabled $false
    Start-DrainRead -State $outsiderStdoutState
    Start-DrainRead -State $outsiderStderrState

    $stage = 'owned_process_drain'
    $drainStates = @(
        $fixtureStdoutState,
        $fixtureStderrState,
        $outsiderStdoutState,
        $outsiderStderrState
    )
    while ($true) {
        $remaining = $hardDeadlineMilliseconds -
            [int]$clock.ElapsedMilliseconds
        if ($remaining -le 0) {
            $deadlineExpired = $true
            Stop-OwnedProcess -Process $fixture
            Stop-OwnedProcess -Process $outsider
            Stop-OwnedProcess -Process $watcher
            break
        }
        if ($remaining -le $cleanupReserveMilliseconds) {
            $deadlineExpired = $true
            Stop-OwnedProcess -Process $fixture
            Stop-OwnedProcess -Process $outsider
            Stop-OwnedProcess -Process $watcher
        }

        $tasks = [System.Collections.Generic.List[System.Threading.Tasks.Task]]::new()
        foreach ($state in $drainStates) {
            if ($null -ne $state.ReadTask) {
                $tasks.Add($state.ReadTask)
            }
        }
        if ($tasks.Count -gt 0) {
            [void][System.Threading.Tasks.Task]::WaitAny(
                $tasks.ToArray(), [Math]::Min(100, [Math]::Max(1, $remaining)))
        }
        else {
            [System.Threading.Thread]::Sleep(
                [Math]::Min(20, [Math]::Max(1, $remaining)))
        }

        foreach ($state in $drainStates) {
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
                    $priorTotal = 0L
                    foreach ($counterState in $drainStates) {
                        $priorTotal += [long]$counterState.Bytes
                    }
                    $state.Bytes = [Math]::Min(
                        $ownedOutputLimitBytes + 1L,
                        [long]$state.Bytes + [long]$read)
                    $nextTotal = 0L
                    foreach ($counterState in $drainStates) {
                        $nextTotal += [long]$counterState.Bytes
                    }
                    if (
                        $priorTotal + [long]$read -le
                            $ownedOutputLimitBytes -and
                        -not $ownedOutputLimitExceeded -and
                        $null -ne $state.Capture
                    ) {
                        $state.Capture.Write($state.Buffer, 0, $read)
                    }
                    if ($nextTotal -gt $ownedOutputLimitBytes) {
                        $ownedOutputLimitExceeded = $true
                        Stop-OwnedProcess -Process $fixture
                        Stop-OwnedProcess -Process $outsider
                        Stop-OwnedProcess -Process $watcher
                    }
                    Start-DrainRead -State $state
                }
            }
        }

        $watcherBytes = 0L
        foreach ($watchPath in @($watchOut, $watchErr)) {
            if ([System.IO.File]::Exists($watchPath)) {
                $watcherBytes += ([System.IO.FileInfo]::new($watchPath)).Length
            }
        }
        if ($watcherBytes -gt $watcherOutputLimitBytes) {
            $ownedOutputLimitExceeded = $true
            Stop-OwnedProcess -Process $fixture
            Stop-OwnedProcess -Process $outsider
            Stop-OwnedProcess -Process $watcher
        }

        $fixture.Refresh()
        $outsider.Refresh()
        $watcher.Refresh()
        $allStreamsComplete = @($drainStates | Where-Object {
            -not $_.Complete
        }).Count -eq 0
        if (
            $fixture.HasExited -and
            $outsider.HasExited -and
            $watcher.HasExited -and
            $allStreamsComplete
        ) {
            break
        }
    }
    if ($deadlineExpired) { throw 'owned_process_absolute_deadline' }
    if ($ownedOutputLimitExceeded) { throw 'owned_output_limit_exceeded' }
    if ($streamFailure) { throw 'stream_drain_failed' }
    if (
        -not $fixture.HasExited -or
        -not $outsider.HasExited -or
        -not $watcher.HasExited -or
        @($drainStates | Where-Object { -not $_.Complete }).Count -ne 0
    ) {
        throw 'tree_join_unconfirmed'
    }

    $fixtureExit = $fixture.ExitCode
    $watchExit = $watcher.ExitCode
    $outsiderExit = $outsider.ExitCode
    $strictUtf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $fixtureStdout = $strictUtf8.GetString(
        $fixtureStdoutState.Capture.ToArray())
    $completedChecks = 1
    $watchStdout = Read-BoundedText -Path $watchOut -Limit 262144
    $watchStderr = Read-BoundedText -Path $watchErr -Limit 262144
    $stage = 'json_parse'
    $fixtureJson = Read-LastJson -Text $fixtureStdout
    $watchJson = Read-LastJson -Text $watchStdout
    if ($null -ne $watchJson.PSObject.Properties['failure_code']) {
        $candidateFailureCode = [string]$watchJson.failure_code
        if ($candidateFailureCode -match '^[a-z_]{1,64}$') {
            $watcherFailureCode = $candidateFailureCode
        }
        else {
            $watcherFailureCode = 'invalid_failure_code'
        }
    }
    if ($null -eq $watchJson.PSObject.Properties['events']) {
        throw 'watcher_contract_failed'
    }
    $completedChecks = 2

    $stage = 'contract_validation'
    $supervisorHash = Get-BoundedFileSha256 `
        -Path (Join-Path $repo 'scripts\process_supervisor.py') -Limit 2097152
    $pythonHash = Get-BoundedFileSha256 -Path $python -Limit 134217728
    $escriptHash = Get-BoundedFileSha256 -Path $escript -Limit 134217728
    $watcherHash = Get-BoundedFileSha256 `
        -Path $watchScript -Limit 2097152
    $runnerHash = Get-BoundedFileSha256 `
        -Path $runnerScript -Limit 2097152
    $launcherHash = Get-BoundedFileSha256 `
        -Path $PSCommandPath -Limit 2097152
    $configurationHash = Get-BoundedFileSha256 `
        -Path (Join-Path $repo '.mise.toml') -Limit 2097152
    $events = @($watchJson.events)
    $pythonEvents = @($events | Where-Object { $_.process_name -eq 'python.exe' })
    $consoleEvents = @($events | Where-Object {
        $_.process_name -in @('conhost.exe', 'OpenConsole.exe')
    })
    $allowedParentResolutions = @(
        'live_parent', 'retained_parent', 'invalid_parent_id',
        'parent_query_failed', 'retained_id_missing',
        'retained_start_after_child', 'retained_lifetime_ended',
        'retained_query_failed', 'retained_parent_unverified'
    )
    $eventDataContract = @($events | Where-Object {
        $_.ever_visible -or
        -not $_.visibility_verified -or
        $_.termination_requested -or
        $_.termination_confirmed -or
        $_.parent_resolution -notin $allowedParentResolutions -or
        $null -ne $_.PSObject.Properties['pid'] -or
        $null -ne $_.PSObject.Properties['process_id'] -or
        $null -ne $_.PSObject.Properties['start_ticks'] -or
        $null -ne $_.PSObject.Properties['identity'] -or
        $null -ne $_.PSObject.Properties['path'] -or
        $null -ne $_.PSObject.Properties['argv'] -or
        $null -ne $_.PSObject.Properties['handle']
    }).Count -eq 0
    $fixturePassed = (
        $fixtureExit -eq 0 -and
        $fixtureStderrState.Bytes -eq 0 -and
        $fixtureJson.schema -eq 1 -and
        $fixtureJson.stage -eq 'console_inheritance' -and
        $fixtureJson.passed -eq $true -and
        $fixtureJson.otp_release -eq $OtpMajor -and
        $fixtureJson.erts_version -match '^[0-9]+(?:\.[0-9]+){1,3}$' -and
        $fixtureJson.generations -eq 2 -and
        $fixtureJson.exit_status -eq 0 -and
        $fixtureJson.status_verified -eq $true -and
        $fixtureJson.marker_observed -eq $true -and
        $fixtureJson.child_exit_observed -eq $true -and
        $fixtureJson.process_supervisor_protocol_valid -eq $true -and
        $fixtureJson.process_supervisor_failure_code -eq 'none' -and
        $fixtureJson.process_supervisor_attestation_failure -eq 'none' -and
        $fixtureJson.process_supervisor_reported_status -eq 0 -and
        $fixtureJson.process_supervisor_observed_status -eq 0 -and
        $fixtureJson.native_tree_empty -eq $true -and
        $fixtureJson.native_console_isolated -eq $true -and
        $fixtureJson.native_descendant_outlived -eq $false -and
        $fixtureJson.native_termination_requested -eq $false -and
        $fixtureJson.output_limit_exceeded -eq $false -and
        $fixtureJson.output_digest_complete -eq $true -and
        $fixtureJson.supervisor_source_sha256 -ceq $supervisorHash -and
        $fixtureJson.python_executable_sha256 -ceq $pythonHash -and
        $escriptHash -ceq $escriptHashBefore
    )
    $outsiderPassed = (
        $outsiderExit -eq 0 -and
        $outsiderStdoutState.Bytes -eq 0 -and
        $outsiderStderrState.Bytes -eq 0
    )
    $unverifiedParentEvents = @($events | Where-Object {
        -not $_.parent_verified
    })
    $rawLineageContract = (
        $watchExit -eq 0 -and
        $watchJson.passed -eq $true -and
        $watchJson.unverified_parent_event_count -eq 0 -and
        $watchJson.lineage_complete -eq $true
    )
    $watcherPassed = (
        $watchExit -eq 0 -and
        $watchStderr.Length -eq 0 -and
        $watchStdout -notmatch [regex]::Escape($token) -and
        $watchJson.schema -eq 1 -and
        $watchJson.stage -eq 'console-inheritance' -and
        $watchJson.source_sha256 -ceq $watcherHash -and
        $null -eq $watchJson.PSObject.Properties['owner_process_id'] -and
        $null -eq $watchJson.PSObject.Properties['owner_start_ticks'] -and
        $null -eq $watchJson.PSObject.Properties['owner_signal_path'] -and
        $null -eq $watchJson.PSObject.Properties['ready_token'] -and
        $watchJson.readiness_signaled -eq $true -and
        $watchJson.readiness_cleanup_confirmed -eq $true -and
        $watchJson.owner_binding_required -eq $true -and
        $watchJson.owner_binding_verified -eq $true -and
        $watchJson.owner_binding_cleanup_confirmed -eq $true -and
        $watchJson.owner_root_observed -eq $true -and
        $watchJson.ignored_unowned_candidate_count -ge 1 -and
        $watchJson.baseline_forbidden_target_count -eq 0 -and
        $watchJson.baseline_visible_conhost_count -eq 0 -and
        $watchJson.baseline_unverified_conhost_count -eq 0 -and
        $watchJson.baseline_observation_failure_count -eq 0 -and
        $watchJson.sample_observation_failure_count -eq 0 -and
        $watchJson.sample_observation_failure_code -eq 'none' -and
        $watchJson.sample_observation_failure_process -eq 'none' -and
        $watchJson.sample_observation_failure_type -eq 'none' -and
        $watchJson.sample_observation_failure_ownership_step -eq 'none' -and
        $watchJson.remaining_observation_failure_count -eq 0 -and
        $watchJson.event_count -eq $events.Count -and
        $watchJson.visible_event_count -eq 0 -and
        $watchJson.unverified_event_count -eq 0 -and
        $watchJson.lineage_required -eq $true -and
        $watchJson.termination_requested_count -eq 0 -and
        $watchJson.termination_confirmed_count -eq 0 -and
        $watchJson.remaining_target_count -eq 0 -and
        $watchJson.observation_complete -eq $true -and
        -not [System.IO.File]::Exists($ready) -and
        -not [System.IO.File]::Exists($owner) -and
        $watchJson.duration_bucket_ms -ge ($DurationMilliseconds - 100) -and
        $eventDataContract -and
        $rawLineageContract -and
        @($pythonEvents | Where-Object {
            $_.parent_process_name -eq 'erl.exe'
        }).Count -eq 1 -and
        @($pythonEvents | Where-Object {
            $_.parent_process_name -eq 'python.exe'
        }).Count -ge 2 -and
        @($consoleEvents | Where-Object {
            $_.parent_process_name -eq 'escript.exe'
        }).Count -ge 1 -and
        @($consoleEvents | Where-Object {
            $_.parent_process_name -eq 'python.exe'
        }).Count -ge 1
    )
    $remainingTargetCount = [int]$watchJson.remaining_target_count
    $passed = (
        $fixturePassed -and
        $outsiderPassed -and
        $watcherPassed -and
        $remainingTargetCount -eq 0
    )
    $completedChecks = 3
    $proofFailureCode = if ($passed) { 'none' } else {
        'watcher_contract_failed'
    }

    $successReport = [ordered]@{
        schema = 1
        operating_system = 'windows'
        otp = $OtpMajor
        state = if ($passed) { 'Ready' } else { 'Failed' }
        failure_code = $proofFailureCode
        scope = 'windows-console-inheritance:otp' + $OtpMajor
        configured_checks = 3
        completed_checks = $completedChecks
        passed = $passed
        fixture_contract_valid = $fixturePassed
        outsider_contract_valid = $outsiderPassed
        watcher_contract_valid = $watcherPassed
        remaining_target_count = $remainingTargetCount
        duration_ms = $DurationMilliseconds
        escript_sha256 = $escriptHash
        python_sha256 = $pythonHash
        process_supervisor_sha256 = $supervisorHash
        process_runner_sha256 = $runnerHash
        launcher_sha256 = $launcherHash
        watcher_sha256 = $watcherHash
        configuration_sha256 = $configurationHash
        fixture_exit = $fixtureExit
        watcher_exit = $watchExit
        fixture_stderr_empty = ($fixtureStderrState.Bytes -eq 0)
        watcher_stderr_empty = ($watchStderr.Length -eq 0)
        owned_streams_drained = $true
        owned_output_bytes = (
            [long]$fixtureStdoutState.Bytes +
            [long]$fixtureStderrState.Bytes +
            [long]$outsiderStdoutState.Bytes +
            [long]$outsiderStderrState.Bytes)
        output_limit_exceeded = $false
        deadline_expired = $false
        fixture = $fixtureJson
        watcher = $watchJson
        rerun_command = 'mise run windows-package-suite -- -Target http'
    }
    $successJson = $successReport | ConvertTo-Json -Depth 8 -Compress
    Write-PublicReport -Json $successJson
    Write-Output $successJson
    if (-not $passed) { exit 1 }
}
catch {
    $failureType = $_.Exception.GetType().Name
    if ($failureType -notmatch '^[A-Za-z0-9_]{1,64}$') {
        $failureType = 'Unknown'
    }
    $innerType = 'none'
    $nativeCode = 0
    if ($null -ne $_.Exception.InnerException) {
        $innerType = $_.Exception.InnerException.GetType().Name
        if ($innerType -notmatch '^[A-Za-z0-9_]{1,64}$') {
            $innerType = 'Unknown'
        }
        if ($_.Exception.InnerException -is [System.ComponentModel.Win32Exception]) {
            $nativeCode = $_.Exception.InnerException.NativeErrorCode
        }
    }
    $failureReport = [ordered]@{
        schema = 1
        operating_system = 'windows'
        otp = $OtpMajor
        failure_code = Get-LauncherFailureCode `
            -Message $_.Exception.Message -StageName $stage
        failure_type = $failureType
        failure_id = 'launcher_failure'
        inner_type = $innerType
        native_code = $nativeCode
        watcher_failure_code = $watcherFailureCode
        owned_streams_drained = (
            $null -ne $fixtureStdoutState -and
            $fixtureStdoutState.Complete -and
            $null -ne $fixtureStderrState -and
            $fixtureStderrState.Complete -and
            $null -ne $outsiderStdoutState -and
            $outsiderStdoutState.Complete -and
            $null -ne $outsiderStderrState -and
            $outsiderStderrState.Complete)
        output_limit_exceeded = $ownedOutputLimitExceeded
        deadline_expired = $deadlineExpired
        scope = 'windows-console-inheritance:otp' + $OtpMajor
        completed_checks = $completedChecks
        configured_checks = 3
        rerun_command = (
            'mise run windows-package-suite -- -Target http')
        passed = $false
    }
    $failureJson = $failureReport | ConvertTo-Json -Compress
    try { Write-PublicReport -Json $failureJson } catch { }
    Write-Output $failureJson
    exit 127
}
finally {
    Stop-OwnedProcess -Process $fixture
    Stop-OwnedProcess -Process $outsider
    Stop-OwnedProcess -Process $watcher
    [void](Join-OwnedProcess -Process $fixture)
    [void](Join-OwnedProcess -Process $outsider)
    [void](Join-OwnedProcess -Process $watcher)
    foreach ($state in @(
        $fixtureStdoutState,
        $fixtureStderrState,
        $outsiderStdoutState,
        $outsiderStderrState
    )) {
        if ($null -ne $state -and $null -ne $state.Capture) {
            $state.Capture.Dispose()
        }
    }
    foreach ($path in $paths) {
        try {
            if ([System.IO.File]::Exists($path)) {
                [System.IO.File]::Delete($path)
            }
        }
        catch {
            # Residual private evidence is handled by the caller's audit.
        }
    }
}
