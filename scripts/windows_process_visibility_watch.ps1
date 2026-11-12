# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
#requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet(
        'process-runner-otp29',
        'process-runner-otp28',
        'console-inheritance',
        'windows-console-audit',
        'failure-secrecy-self-test',
        'failure-secrecy-audit',
        'supervised-format',
        'supervised-http-diagnostic',
        'supervised-http-server-exact',
        'supervised-http-check',
        'supervised-http-test',
        'supervised-quic-check',
        'supervised-quic-test'
    )]
    [string] $Stage,

    [ValidateRange(1000, 600000)]
    [int] $DurationMilliseconds = 120000,

    [ValidateRange(10, 100)]
    [int] $SamplePeriodMilliseconds = 20,

    [ValidateScript({ $_ -eq '' -or $_ -match '^[0-9a-f]{32}$' })]
    [string] $ReadyToken = '',

    [switch] $RequireOwnerBinding,

    [switch] $SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:watcherStep = 'initialization'
$script:readySignalPath = $null
$script:ownerSignalPath = $null
$script:retainedTargets = [System.Collections.Generic.List[object]]::new()
$script:ownerRootIdentity = ''
$script:ownedIdentities = @{}
$script:ownershipStep = 'none'
$script:ownershipFailureStep = 'none'

function Remove-PrivateSignal {
    param([string] $Path)
    if ([string]::IsNullOrEmpty($Path)) { return $true }
    try {
        [System.IO.File]::Delete($Path)
        return -not [System.IO.File]::Exists($Path)
    }
    catch {
        return $false
    }
}

function Get-WatcherFailureCode {
    param([string] $Step)
    $code = switch ($Step) {
        'native_type' { 'watcher_native_type_failed' }
        'baseline_enumeration' { 'watcher_baseline_enumeration_failed' }
        'baseline_visibility' { 'watcher_baseline_visibility_failed' }
        'readiness' { 'watcher_readiness_failed' }
        'owner_binding_wait' { 'watcher_owner_binding_wait_failed' }
        'owner_binding_parse' { 'watcher_owner_binding_parse_failed' }
        'owner_binding_identity' { 'watcher_owner_binding_identity_failed' }
        'owner_binding_cleanup' { 'watcher_owner_binding_cleanup_failed' }
        'sampling_enumeration' { 'watcher_sampling_enumeration_failed' }
        'sampling_identity' { 'watcher_sampling_identity_failed' }
        'sampling_ownership' { 'watcher_sampling_ownership_failed' }
        'sampling_visibility' { 'watcher_sampling_visibility_failed' }
        'sampling_termination' { 'watcher_sampling_termination_failed' }
        'remaining_enumeration' { 'watcher_remaining_enumeration_failed' }
        'publication_identity' { 'watcher_publication_identity_failed' }
        'publication' { 'watcher_publication_failed' }
        default { 'watcher_initialization_failed' }
    }
    return [string] $code
}

function New-WatcherFailureProjection {
    param([string] $StageName, [string] $Step)
    return [ordered]@{
        schema = 1
        stage = $StageName
        failure_code = Get-WatcherFailureCode -Step $Step
        observation_complete = $false
        passed = $false
    }
}

trap {
    [void](Remove-PrivateSignal -Path $script:readySignalPath)
    [void](Remove-PrivateSignal -Path $script:ownerSignalPath)
    foreach ($retained in $script:retainedTargets) {
        try { $retained.process.Dispose() } catch {}
    }
    $failure = New-WatcherFailureProjection `
        -StageName $Stage -Step $script:watcherStep
    [Console]::Out.WriteLine(($failure | ConvertTo-Json -Compress))
    exit 127
}

function Get-PrivateSignalPath {
    param([string] $Token, [ValidateSet('ready', 'owner')] [string] $Kind)
    $directory = [System.IO.Path]::GetFullPath(
        (Join-Path (Get-Location) 'build/test-runner'))
    $leaf = 'windows-process-visibility-' + $Token + '.' + $Kind
    return Join-Path $directory $leaf
}

function ConvertFrom-OwnerBindingBytes {
    param([byte[]] $Bytes)
    if ($Bytes.Length -lt 5 -or $Bytes.Length -gt 48) {
        throw 'owner_binding_shape_invalid'
    }
    $text = [System.Text.Encoding]::ASCII.GetString($Bytes)
    if ($text -notmatch '^(?<pid>[1-9][0-9]{0,9}):(?<ticks>[1-9][0-9]{0,18})\n$') {
        throw 'owner_binding_shape_invalid'
    }
    $processId = [int64]::Parse(
        $Matches.pid, [System.Globalization.CultureInfo]::InvariantCulture)
    $startTicks = [int64]::Parse(
        $Matches.ticks, [System.Globalization.CultureInfo]::InvariantCulture)
    if ($processId -gt [int]::MaxValue -or $startTicks -gt ([DateTime]::MaxValue).Ticks) {
        throw 'owner_binding_range_invalid'
    }
    return @{
        process_id = [int]$processId
        start_ticks = $startTicks
    }
}

if (-not $SelfTest -and $RequireOwnerBinding -and $ReadyToken -eq '') {
    throw 'owner_binding_token_missing'
}
$maximumEvents = 256
$bucketWidthMilliseconds = 100
$targetNames = @{
    'cmd' = 'cmd.exe'
    'openconsole' = 'OpenConsole.exe'
    'conhost' = 'conhost.exe'
    'herd' = 'herd.exe'
    'herdr' = 'herdr.exe'
    'erl' = 'erl.exe'
    'werl' = 'werl.exe'
    'erlexec' = 'erlexec.exe'
    'escript' = 'escript.exe'
    'gleam' = 'gleam.exe'
    'python' = 'python.exe'
    'pythonw' = 'pythonw.exe'
    'beam.smp' = 'beam.smp.exe'
    'rebar3' = 'rebar3.exe'
}
$terminableNames = @{
    'cmd' = $true
    'openconsole' = $true
    'herd' = $true
    'herdr' = $true
    'erl' = $true
    'werl' = $true
    'erlexec' = $true
    'escript' = $true
    'gleam' = $true
    'python' = $true
    'pythonw' = $true
    'beam.smp' = $true
    'rebar3' = $true
}

function Test-LineageRequired {
    param([string] $StageName, [bool] $OwnerBound = $false)
    return $OwnerBound -or $StageName -eq 'console-inheritance'
}

$lineageRequired = Test-LineageRequired `
    -StageName $Stage -OwnerBound ([bool]$RequireOwnerBinding)

function Get-RetainedParentName {
    param(
        [int] $ParentId,
        [int64] $ChildStartTicks,
        [object[]] $Candidates = @($script:retainedTargets)
    )
    $best = $null
    $bestStartTicks = [int64]::MinValue
    $matchingId = $false
    $matchingStart = $false
    $lifetimeRejected = $false
    $candidateQueryFailed = $false
    foreach ($candidate in $Candidates) {
        try {
            if ([int]$candidate.process_id -ne $ParentId) {
                continue
            }
            $matchingId = $true
            $candidateStartTicks = [int64]$candidate.start_ticks
            if (
                $candidateStartTicks -gt $ChildStartTicks -or
                $candidateStartTicks -le $bestStartTicks
            ) {
                continue
            }
            $matchingStart = $true
            $aliveAtChildStart = $true
            if ($candidate.process.HasExited) {
                $exitTicks = $candidate.process.ExitTime.ToUniversalTime().Ticks
                $aliveAtChildStart = $exitTicks -ge $ChildStartTicks
            }
            if ($aliveAtChildStart) {
                $best = $candidate
                $bestStartTicks = $candidateStartTicks
            }
            else {
                $lifetimeRejected = $true
            }
        }
        catch {
            # A retained handle that cannot prove its lifetime is ignored.
            $candidateQueryFailed = $true
        }
    }
    if ($null -ne $best) {
        return @{
            name = [string]$best.name
            verified = $true
            resolution = 'retained_parent'
        }
    }
    $resolution = if (-not $matchingId) {
        'retained_id_missing'
    }
    elseif (-not $matchingStart) {
        'retained_start_after_child'
    }
    elseif ($lifetimeRejected) {
        'retained_lifetime_ended'
    }
    elseif ($candidateQueryFailed) {
        'retained_query_failed'
    }
    else {
        'retained_parent_unverified'
    }
    return @{ name = 'exited'; verified = $false; resolution = $resolution }
}

if ($SelfTest) {
    $expectedFailureCodes = [ordered]@{
        native_type = 'watcher_native_type_failed'
        baseline_enumeration = 'watcher_baseline_enumeration_failed'
        baseline_visibility = 'watcher_baseline_visibility_failed'
        readiness = 'watcher_readiness_failed'
        owner_binding_wait = 'watcher_owner_binding_wait_failed'
        owner_binding_parse = 'watcher_owner_binding_parse_failed'
        owner_binding_identity = 'watcher_owner_binding_identity_failed'
        owner_binding_cleanup = 'watcher_owner_binding_cleanup_failed'
        sampling_enumeration = 'watcher_sampling_enumeration_failed'
        sampling_identity = 'watcher_sampling_identity_failed'
        sampling_ownership = 'watcher_sampling_ownership_failed'
        sampling_visibility = 'watcher_sampling_visibility_failed'
        sampling_termination = 'watcher_sampling_termination_failed'
        remaining_enumeration = 'watcher_remaining_enumeration_failed'
        publication_identity = 'watcher_publication_identity_failed'
        publication = 'watcher_publication_failed'
        unknown = 'watcher_initialization_failed'
    }
    foreach ($entry in $expectedFailureCodes.GetEnumerator()) {
        if ((Get-WatcherFailureCode -Step $entry.Key) -ne $entry.Value) {
            [Console]::Out.WriteLine(
                '{"schema":1,"stage":"watcher-self-test","failure_code":"failure_projection_invalid","passed":false}')
            exit 1
        }
    }
    $projection = New-WatcherFailureProjection `
        -StageName 'console-inheritance' -Step 'sampling_identity'
    $testToken = '0123456789abcdef0123456789abcdef'
    $testReadyPath = Get-PrivateSignalPath -Token $testToken -Kind 'ready'
    $testOwnerPath = Get-PrivateSignalPath -Token $testToken -Kind 'owner'
    $validBinding = ConvertFrom-OwnerBindingBytes -Bytes (
        [System.Text.Encoding]::ASCII.GetBytes("41:638000000000000000`n"))
    $invalidOwnerBindings = @(
        '',
        "0:638000000000000000`n",
        "41:0`n",
        "41:638000000000000000",
        "41:638000000000000000`r`n",
        "41:638000000000000000`n42:638000000000000000`n",
        "2147483648:638000000000000000`n",
        "41:3155378976000000000`n"
    )
    $invalidOwnerBindingsRejected = 0
    foreach ($invalidBinding in $invalidOwnerBindings) {
        try {
            [void](ConvertFrom-OwnerBindingBytes -Bytes (
                [System.Text.Encoding]::ASCII.GetBytes($invalidBinding)))
        }
        catch {
            $invalidOwnerBindingsRejected += 1
        }
    }
    if (
        $projection.Count -ne 5 -or
        $projection.schema -ne 1 -or
        $projection.stage -ne 'console-inheritance' -or
        $projection.failure_code -ne 'watcher_sampling_identity_failed' -or
        $projection.observation_complete -ne $false -or
        $projection.passed -ne $false -or
        $targetNames.Count -ne 14 -or
        $terminableNames.Count -ne 13 -or
        $terminableNames.ContainsKey('conhost') -or
        -not (Test-LineageRequired -StageName 'console-inheritance') -or
        (Test-LineageRequired -StageName 'windows-console-audit') -or
        -not (Test-LineageRequired `
            -StageName 'windows-console-audit' -OwnerBound $true) -or
        [System.IO.Path]::GetFileName($testReadyPath) -cne
            ('windows-process-visibility-' + $testToken + '.ready') -or
        [System.IO.Path]::GetFileName($testOwnerPath) -cne
            ('windows-process-visibility-' + $testToken + '.owner') -or
        $testReadyPath -ceq $testOwnerPath -or
        $validBinding.process_id -ne 41 -or
        $validBinding.start_ticks -ne 638000000000000000 -or
        $invalidOwnerBindingsRejected -ne $invalidOwnerBindings.Count
    ) {
        [Console]::Out.WriteLine(
            '{"schema":1,"stage":"watcher-self-test","failure_code":"projection_contract_invalid","passed":false}')
        exit 1
    }
    # Native visibility calls are validated after Add-Type so this self-test
    # cannot pass when PowerShell cannot invoke the C# boundary.
}

$script:watcherStep = 'native_type'
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

public static class HttpProcessVisibilityNative
{
    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessBasicInformation
    {
        internal IntPtr Reserved1;
        internal IntPtr PebBaseAddress;
        internal IntPtr Reserved2_0;
        internal IntPtr Reserved2_1;
        internal IntPtr UniqueProcessId;
        internal IntPtr InheritedFromUniqueProcessId;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr process,
        int informationClass,
        ref ProcessBasicInformation information,
        int informationLength,
        out int returnLength);

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(IntPtr window);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);

    [DllImport("user32.dll")]
    private static extern IntPtr GetTopWindow(IntPtr window);

    [DllImport("user32.dll")]
    private static extern IntPtr GetWindow(IntPtr window, uint command);

    public static int ParentProcessId(IntPtr process)
    {
        ProcessBasicInformation information = new ProcessBasicInformation();
        int returned;
        int status = NtQueryInformationProcess(
            process,
            0,
            ref information,
            Marshal.SizeOf<ProcessBasicInformation>(),
            out returned);
        if (status != 0 || information.InheritedFromUniqueProcessId == IntPtr.Zero)
            return -1;
        long value = information.InheritedFromUniqueProcessId.ToInt64();
        return value > 0 && value <= Int32.MaxValue ? (int)value : -1;
    }

    // 1 = a visible top-level window, 0 = none, -1 = enumeration failed.
    public static int VisibleWindowState(uint processId)
    {
        const uint NextWindow = 2;
        const int MaximumWindows = 65536;
        HashSet<IntPtr> seen = new HashSet<IntPtr>();
        IntPtr window = GetTopWindow(IntPtr.Zero);
        for (int count = 0; window != IntPtr.Zero && count < MaximumWindows; count++)
        {
            if (!seen.Add(window))
                return -1;
            uint owner;
            GetWindowThreadProcessId(window, out owner);
            if (owner == processId && IsWindowVisible(window))
                return 1;
            window = GetWindow(window, NextWindow);
        }
        return window == IntPtr.Zero ? 0 : -1;
    }
}
'@

if ($SelfTest) {
    $current = [System.Diagnostics.Process]::GetCurrentProcess()
    try {
        $parent = [HttpProcessVisibilityNative]::ParentProcessId($current.Handle)
        $visible = [HttpProcessVisibilityNative]::VisibleWindowState(
            [uint32]$current.Id)
        if ($parent -le 0) {
            [Console]::Out.WriteLine(
                '{"schema":1,"stage":"watcher-self-test","failure_code":"native_parent_invalid","passed":false}')
            exit 1
        }
        if ($visible -lt 0 -or $visible -gt 1) {
            [Console]::Out.WriteLine(
                '{"schema":1,"stage":"watcher-self-test","failure_code":"native_visibility_invalid","passed":false}')
            exit 1
        }
    }
    catch {
        [Console]::Out.WriteLine(
            '{"schema":1,"stage":"watcher-self-test","failure_code":"native_boundary_unavailable","passed":false}')
        exit 1
    }
    finally {
        $current.Dispose()
    }
    $liveMock = [pscustomobject]@{ HasExited = $false; ExitTime = [datetime]::MinValue }
    $exitedMock = [pscustomobject]@{
        HasExited = $true
        ExitTime = [datetime]::new(150, [DateTimeKind]::Utc)
    }
    $retainedFixture = @(
        [pscustomobject]@{
            process_id = 41
            start_ticks = 100
            name = 'python.exe'
            process = $liveMock
        },
        [pscustomobject]@{
            process_id = 42
            start_ticks = 100
            name = 'escript.exe'
            process = $exitedMock
        }
    )
    $liveParent = Get-RetainedParentName `
        -ParentId 41 -ChildStartTicks 200 -Candidates $retainedFixture
    $exitedAfterChild = Get-RetainedParentName `
        -ParentId 42 -ChildStartTicks 120 -Candidates $retainedFixture
    $exitedBeforeChild = Get-RetainedParentName `
        -ParentId 42 -ChildStartTicks 200 -Candidates $retainedFixture
    $futureParent = Get-RetainedParentName `
        -ParentId 41 -ChildStartTicks 50 -Candidates $retainedFixture
    if (
        -not $liveParent.verified -or $liveParent.name -ne 'python.exe' -or
        -not $exitedAfterChild.verified -or
        $exitedAfterChild.name -ne 'escript.exe' -or
        $exitedBeforeChild.verified -or $futureParent.verified
    ) {
        [Console]::Out.WriteLine(
            '{"schema":1,"stage":"watcher-self-test","failure_code":"retained_parent_invalid","passed":false}')
        exit 1
    }
    [Console]::Out.WriteLine(
        '{"schema":1,"stage":"watcher-self-test","controls":32,"passed":true}')
    exit 0
}

function Get-SafeParentName {
    param([System.Diagnostics.Process] $Process)
    $parentId = -1
    try {
        $parentId = [HttpProcessVisibilityNative]::ParentProcessId(
            [IntPtr]$Process.HttpProcessHandle)
        if ($parentId -le 0) {
            return @{
                name = 'unknown'
                verified = $false
                resolution = 'invalid_parent_id'
            }
        }
        $parent = [System.Diagnostics.Process]::GetProcessById($parentId)
        try {
            # Reject a recycled parent PID. The timestamps remain private and
            # are used only to establish the ordering relation.
            if ($parent.StartTime.ToUniversalTime().Ticks -gt
                [int64]$Process.HttpStartTicks) {
                return Get-RetainedParentName `
                    -ParentId $parentId `
                    -ChildStartTicks ([int64]$Process.HttpStartTicks)
            }
            $name = $parent.ProcessName.ToLowerInvariant()
            if ($targetNames.ContainsKey($name)) {
                return @{
                    name = $targetNames[$name]
                    verified = $true
                    resolution = 'live_parent'
                }
            }
            if ($name -match '^[a-z0-9._-]{1,48}$') {
                return @{
                    name = ($name + '.exe')
                    verified = $true
                    resolution = 'live_parent'
                }
            }
            return @{
                name = 'other'
                verified = $true
                resolution = 'live_parent'
            }
        }
        finally {
            $parent.Dispose()
        }
    }
    catch {
        if ($parentId -le 0) {
            return @{
                name = 'exited'
                verified = $false
                resolution = 'parent_query_failed'
            }
        }
        return Get-RetainedParentName `
            -ParentId $parentId `
            -ChildStartTicks ([int64]$Process.HttpStartTicks)
    }
}

function Get-TargetProcesses {
    $result = @()
    foreach ($name in @($targetNames.Keys | Sort-Object)) {
        try {
            foreach ($process in [System.Diagnostics.Process]::GetProcessesByName($name)) {
                try {
                    # Open a kernel process handle while the enumeration result
                    # is live. The cached identity remains bound to this process
                    # instance even if it exits during the same sample.
                    $processHandle = [IntPtr]$process.Handle
                    $processId = $process.Id
                    $startTicks = $process.StartTime.ToUniversalTime().Ticks
                    $process | Add-Member -NotePropertyName HttpTargetName `
                        -NotePropertyValue $name -Force
                    $process | Add-Member -NotePropertyName HttpProcessId `
                        -NotePropertyValue $processId -Force
                    $process | Add-Member -NotePropertyName HttpStartTicks `
                        -NotePropertyValue $startTicks -Force
                    $process | Add-Member -NotePropertyName HttpProcessHandle `
                        -NotePropertyValue $processHandle -Force
                    $result += $process
                    $process = $null
                }
                catch {
                    # A bound observer has no authority over an identity that
                    # cannot be connected to its exact root. Unbound diagnostic
                    # mode retains the older system-wide fail-closed behavior.
                    if (-not $RequireOwnerBinding) { throw }
                }
                finally {
                    if ($null -ne $process) { $process.Dispose() }
                }
            }
        }
        catch {
            foreach ($retained in $result) {
                $retained.Dispose()
            }
            # Discovery is authoritative. An inaccessible target name cannot
            # be silently omitted from a passing observation.
            throw
        }
    }
    return $result
}

function Get-InternalProcessIdentity {
    param([System.Diagnostics.Process] $Process)
    try {
        # StartTime is used only in memory so a reused PID cannot inherit a
        # baseline or prior observation.  Neither component is published.
        $ticks = [int64]$Process.HttpStartTicks
        $processId = [int]$Process.HttpProcessId
        return @{ key = ([string]$processId + ':' + [string]$ticks); verified = $true }
    }
    catch {
        return @{ key = 'unverified'; verified = $false }
    }
}

function Get-RetainedOwnedParent {
    param([int] $ParentId, [int64] $ChildStartTicks)
    foreach ($candidate in $script:retainedTargets) {
        try {
            if (
                -not [bool]$candidate.owned -or
                [int]$candidate.process_id -ne $ParentId -or
                [int64]$candidate.start_ticks -gt $ChildStartTicks
            ) {
                continue
            }
            $aliveAtChildStart = $true
            if ($candidate.process.HasExited) {
                $aliveAtChildStart = (
                    $candidate.process.ExitTime.ToUniversalTime().Ticks -ge
                    $ChildStartTicks)
            }
            if ($aliveAtChildStart) {
                return @{ found = $true; identity = [string]$candidate.identity }
            }
        }
        catch {
            # The caller will continue with a live parent query. An owned
            # ancestry is never inferred from an unreadable retained handle.
        }
    }
    return @{ found = $false; identity = '' }
}

function Test-ProcessOwnership {
    param([System.Diagnostics.Process] $Process)
    $script:ownershipFailureStep = 'none'
    $script:ownershipStep = 'initial_identity'
    $identity = Get-InternalProcessIdentity -Process $Process
    if (-not $identity.verified) {
        return @{ owned = $false; verified = $false; root = $false }
    }
    if (-not $RequireOwnerBinding) {
        return @{ owned = $true; verified = $true; root = $false }
    }
    if ($identity.key -ceq $script:ownerRootIdentity) {
        return @{ owned = $true; verified = $true; root = $true }
    }

    $openedAncestors = [System.Collections.Generic.List[object]]::new()
    $visited = [System.Collections.Generic.HashSet[int]]::new()
    $cursor = $Process
    $cursorHandle = [IntPtr]$Process.HttpProcessHandle
    $childStartTicks = [int64]$Process.HttpStartTicks
    try {
        for ($depth = 0; $depth -lt 64; $depth += 1) {
            $script:ownershipStep = 'parent_query'
            $parentId = [HttpProcessVisibilityNative]::ParentProcessId($cursorHandle)
            if ($parentId -le 0 -or -not $visited.Add($parentId)) {
                return @{ owned = $false; verified = $false; root = $false }
            }
            $script:ownershipStep = 'retained_parent'
            $retained = Get-RetainedOwnedParent `
                -ParentId $parentId -ChildStartTicks $childStartTicks
            if ($retained.found) {
                return @{ owned = $true; verified = $true; root = $false }
            }

            $parent = $null
            $script:ownershipStep = 'live_parent_open'
            try {
                $parent = [System.Diagnostics.Process]::GetProcessById($parentId)
                $parentHandle = [IntPtr]$parent.Handle
                $parentStartTicks = $parent.StartTime.ToUniversalTime().Ticks
            }
            catch {
                if ($null -ne $parent) { $parent.Dispose() }
                return @{ owned = $false; verified = $false; root = $false }
            }
            $openedAncestors.Add($parent)
            $script:ownershipStep = 'parent_identity'
            if ($parentStartTicks -gt $childStartTicks) {
                return @{ owned = $false; verified = $false; root = $false }
            }
            $parentIdentity = (
                [string]$parentId + ':' + [string]$parentStartTicks)
            if (
                $parentIdentity -ceq $script:ownerRootIdentity -or
                $script:ownedIdentities.ContainsKey($parentIdentity)
            ) {
                return @{ owned = $true; verified = $true; root = $false }
            }
            $cursor = $parent
            $cursorHandle = $parentHandle
            $childStartTicks = $parentStartTicks
        }
        return @{ owned = $false; verified = $false; root = $false }
    }
    catch {
        $script:ownershipFailureStep = $script:ownershipStep
        throw
    }
    finally {
        $script:ownershipStep = 'ancestor_disposal'
        foreach ($ancestor in $openedAncestors) { $ancestor.Dispose() }
    }
}

function Add-RetainedOwnedTarget {
    param(
        [System.Diagnostics.Process] $Process,
        [string] $Name,
        [string] $Identity
    )
    foreach ($candidate in $script:retainedTargets) {
        if ([string]$candidate.identity -ceq $Identity) { return $false }
    }
    $script:retainedTargets.Add([ordered]@{
        process_id = [int]$Process.HttpProcessId
        start_ticks = [int64]$Process.HttpStartTicks
        identity = $Identity
        name = $Name
        owned = $true
        process = $Process
    })
    return $true
}

function Stop-ObservedTarget {
    param([System.Diagnostics.Process] $Process)
    try {
        # The Process object and its verified start time bind this action to the
        # observed instance rather than a subsequently reused numeric ID.
        $Process.Kill($true)
        return $Process.WaitForExit(2000)
    }
    catch {
        return $false
    }
}

$baseline = @{}
$baselineConhostStates = @{}
$baselineConhostCount = 0
$baselineForbiddenCount = 0
$baselineObservationFailureCount = 0
$sampleObservationFailureCount = 0
$sampleObservationFailureCode = 'none'
$sampleObservationFailureProcess = 'none'
$sampleObservationFailureType = 'none'
$sampleObservationFailureOwnershipStep = 'none'
$remainingObservationFailureCount = 0
$ownerBindingVerified = $false
$ownerBindingCleanupConfirmed = $true
$ownerRootObserved = $false
$ignoredUnownedCandidates = 0
$script:watcherStep = 'baseline_enumeration'
if (-not $RequireOwnerBinding) {
    foreach ($process in Get-TargetProcesses) {
        try {
            $script:watcherStep = 'baseline_visibility'
            $identity = Get-InternalProcessIdentity -Process $process
            if (-not $identity.verified) {
                $baselineForbiddenCount += 1
            }
            else {
                $name = [string]$process.HttpTargetName
                $baseline[$identity.key] = $name
                if ($name -eq 'conhost') {
                    # An unbound development observation preserves the former
                    # system-wide baseline behavior. Bound qualification runs
                    # never sample an unrelated baseline process.
                    $baselineConhostCount += 1
                    $windowState = [HttpProcessVisibilityNative]::VisibleWindowState(
                        [uint32]$process.HttpProcessId)
                    $baselineConhostStates[$identity.key] = @{
                        ever_visible = ($windowState -eq 1)
                        visibility_verified = ($windowState -ge 0)
                        visibility_samples = 1
                    }
                }
                else {
                    $baselineForbiddenCount += 1
                }
            }
        }
        catch {
            # A target that exits between enumeration and identity/visibility
            # sampling is not safe to silently omit in an unbound observation.
            $baselineObservationFailureCount = [Math]::Min(
                256, $baselineObservationFailureCount + 1)
            $baselineForbiddenCount += 1
        }
        finally {
            $process.Dispose()
        }
    }
}
$seen = @{}
$tracked = @{}
$events = [System.Collections.Generic.List[object]]::new()
$watch = $null
$sampleCount = 0
$observationComplete = $true
$baselineInitiallyUnsafe = @($baselineConhostStates.Values | Where-Object {
    $_.ever_visible -or -not $_.visibility_verified
}).Count -gt 0
$stopObservation = ($baselineForbiddenCount -gt 0 -or $baselineInitiallyUnsafe)
$readinessSignaled = $false
$readinessCleanupConfirmed = $true
if (-not $stopObservation -and $ReadyToken -ne '') {
    $script:watcherStep = 'readiness'
    $readyDirectory = [System.IO.Path]::GetDirectoryName(
        (Get-PrivateSignalPath -Token $ReadyToken -Kind 'ready'))
    [System.IO.Directory]::CreateDirectory($readyDirectory) | Out-Null
    $script:readySignalPath = Get-PrivateSignalPath `
        -Token $ReadyToken -Kind 'ready'
    $readyBytes = [System.Text.Encoding]::ASCII.GetBytes("ready`n")
    $readyStream = [System.IO.File]::Open(
        $script:readySignalPath,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::Read)
    try {
        $readyStream.Write($readyBytes, 0, $readyBytes.Length)
        $readyStream.Flush($true)
    }
    finally {
        $readyStream.Dispose()
    }
    $readinessSignaled = $true
}

if (-not $stopObservation -and $RequireOwnerBinding) {
    $script:ownerSignalPath = Get-PrivateSignalPath `
        -Token $ReadyToken -Kind 'owner'
    $script:watcherStep = 'owner_binding_wait'
    $ownerClock = [System.Diagnostics.Stopwatch]::StartNew()
    $ownerBytes = $null
    while (
        $null -eq $ownerBytes -and
        $ownerClock.ElapsedMilliseconds -lt 10000
    ) {
        if ([System.IO.File]::Exists($script:ownerSignalPath)) {
            try {
                $ownerBytes = [System.IO.File]::ReadAllBytes(
                    $script:ownerSignalPath)
            }
            catch [System.IO.IOException] {
                # The launcher holds FileShare.None until its durable flush and
                # close complete, so a sharing violation is retried finitely.
            }
            catch [System.UnauthorizedAccessException] {
                # A transient sharing denial has the same bounded retry path.
            }
        }
        if ($null -eq $ownerBytes) { Start-Sleep -Milliseconds 10 }
    }
    if ($null -eq $ownerBytes) { throw 'owner_binding_wait_timeout' }

    $script:watcherStep = 'owner_binding_parse'
    $ownerBinding = ConvertFrom-OwnerBindingBytes -Bytes $ownerBytes
    $ownerBytes = $null
    $script:watcherStep = 'owner_binding_identity'
    $ownerProcess = $null
    try {
        $ownerProcess = [System.Diagnostics.Process]::GetProcessById(
            [int]$ownerBinding.process_id)
        $ownerProcessHandle = [IntPtr]$ownerProcess.Handle
        $ownerProcessId = $ownerProcess.Id
        $ownerStartTicks = $ownerProcess.StartTime.ToUniversalTime().Ticks
        $ownerNameKey = $ownerProcess.ProcessName.ToLowerInvariant()
        if (
            $ownerProcessId -ne [int]$ownerBinding.process_id -or
            $ownerStartTicks -ne [int64]$ownerBinding.start_ticks -or
            -not $targetNames.ContainsKey($ownerNameKey)
        ) {
            throw 'owner_binding_identity_mismatch'
        }
        $ownerProcess | Add-Member -NotePropertyName HttpTargetName `
            -NotePropertyValue $ownerNameKey -Force
        $ownerProcess | Add-Member -NotePropertyName HttpProcessId `
            -NotePropertyValue $ownerProcessId -Force
        $ownerProcess | Add-Member -NotePropertyName HttpStartTicks `
            -NotePropertyValue $ownerStartTicks -Force
        $ownerProcess | Add-Member -NotePropertyName HttpProcessHandle `
            -NotePropertyValue $ownerProcessHandle -Force
        $script:ownerRootIdentity = (
            [string]$ownerProcessId + ':' + [string]$ownerStartTicks)
        $script:ownedIdentities[$script:ownerRootIdentity] = $true
        if (-not (Add-RetainedOwnedTarget `
                -Process $ownerProcess `
                -Name $targetNames[$ownerNameKey] `
                -Identity $script:ownerRootIdentity)) {
            throw 'owner_binding_duplicate_identity'
        }
        $ownerProcess = $null
        $ownerBindingVerified = $true
    }
    finally {
        if ($null -ne $ownerProcess) { $ownerProcess.Dispose() }
    }

    $script:watcherStep = 'owner_binding_cleanup'
    $ownerBindingCleanupConfirmed = Remove-PrivateSignal `
        -Path $script:ownerSignalPath
    if (-not $ownerBindingCleanupConfirmed) {
        $observationComplete = $false
        throw 'owner_binding_cleanup_failed'
    }
}

$watch = [System.Diagnostics.Stopwatch]::StartNew()

while (-not $stopObservation -and $watch.ElapsedMilliseconds -lt $DurationMilliseconds) {
    $sampleCount += 1
    $script:watcherStep = 'sampling_enumeration'
    foreach ($process in Get-TargetProcesses) {
        $retainProcess = $false
        try {
            $script:watcherStep = 'sampling_identity'
            $identityResult = Get-InternalProcessIdentity -Process $process
            if (-not $identityResult.verified) {
                $sampleObservationFailureCount = [Math]::Min(
                    256, $sampleObservationFailureCount + 1)
                $observationComplete = $false
                continue
            }
            $identity = $identityResult.key
            $script:watcherStep = 'sampling_ownership'
            $ownership = if (
                $RequireOwnerBinding -and
                $script:ownedIdentities.ContainsKey($identity)
            ) {
                @{
                    owned = $true
                    verified = $true
                    root = ($identity -ceq $script:ownerRootIdentity)
                }
            }
            else {
                Test-ProcessOwnership -Process $process
            }
            if (-not $ownership.owned) {
                $ignoredUnownedCandidates = [Math]::Min(
                    65535, $ignoredUnownedCandidates + 1)
                continue
            }
            if ($ownership.root) { $ownerRootObserved = $true }
            if ($baseline.ContainsKey($identity)) {
                if ($baseline[$identity] -eq 'conhost') {
                    $script:watcherStep = 'sampling_visibility'
                    $windowState = [HttpProcessVisibilityNative]::VisibleWindowState(
                        [uint32]$process.HttpProcessId)
                    $state = $baselineConhostStates[$identity]
                    $state.visibility_samples = [int]$state.visibility_samples + 1
                    if ($windowState -lt 0) {
                        $state.visibility_verified = $false
                        $stopObservation = $true
                    }
                    elseif ($windowState -eq 1) {
                        $state.ever_visible = $true
                        $stopObservation = $true
                    }
                }
                continue
            }
            if (-not $seen.ContainsKey($identity)) {
                if ($events.Count -ge $maximumEvents) {
                    $observationComplete = $false
                }
                else {
                    $nameKey = [string]$process.HttpTargetName
                    $parent = Get-SafeParentName -Process $process
                    $script:watcherStep = 'sampling_visibility'
                    $windowState = [HttpProcessVisibilityNative]::VisibleWindowState(
                        [uint32]$process.HttpProcessId)
                    $bucket = [int64]([Math]::Floor(
                        $watch.ElapsedMilliseconds / $bucketWidthMilliseconds) *
                        $bucketWidthMilliseconds)
                    $events.Add([ordered]@{
                        process_name = $targetNames[$nameKey]
                        parent_process_name = $parent.name
                        parent_verified = [bool]$parent.verified
                        parent_resolution = $parent.resolution
                        ever_visible = ($windowState -eq 1)
                        visibility_verified = ($windowState -ge 0)
                        visibility_samples = 1
                        termination_requested = $false
                        termination_confirmed = $false
                        monotonic_start_bucket_ms = $bucket
                    })
                    $tracked[$identity] = $events[$events.Count - 1]
                    $event = $tracked[$identity]
                    $script:ownedIdentities[$identity] = $true
                    $retainProcess = Add-RetainedOwnedTarget `
                        -Process $process `
                        -Name $targetNames[$nameKey] `
                        -Identity $identity
                    if (
                        $windowState -lt 0
                    ) {
                        $stopObservation = $true
                    }
                    elseif ($windowState -eq 1) {
                        if ($terminableNames.ContainsKey($nameKey)) {
                            $script:watcherStep = 'sampling_termination'
                            $event.termination_requested = $true
                            $event.termination_confirmed = Stop-ObservedTarget -Process $process
                            if (-not $event.termination_confirmed) {
                                $observationComplete = $false
                            }
                        }
                        # A conhost is observed but never terminated by this
                        # watcher. All visible target events stop observation.
                        $stopObservation = $true
                    }
                }
                $seen[$identity] = $true
            }
            elseif ($tracked.ContainsKey($identity)) {
                # A process can create its window after startup.  Visibility is
                # therefore sampled throughout its lifetime and accumulated.
                $script:watcherStep = 'sampling_visibility'
                $windowState = [HttpProcessVisibilityNative]::VisibleWindowState(
                    [uint32]$process.HttpProcessId)
                $event = $tracked[$identity]
                $event.visibility_samples = [int]$event.visibility_samples + 1
                if ($windowState -lt 0) {
                    $event.visibility_verified = $false
                }
                elseif ($windowState -eq 1) {
                    $event.ever_visible = $true
                    if ($terminableNames.ContainsKey(
                            ([string]$process.HttpTargetName))) {
                        $script:watcherStep = 'sampling_termination'
                        $event.termination_requested = $true
                        $event.termination_confirmed = Stop-ObservedTarget -Process $process
                        if (-not $event.termination_confirmed) {
                            $observationComplete = $false
                        }
                    }
                    $stopObservation = $true
                }
            }
        }
        catch {
            # Process exit and access races are expected on a live system, but
            # an incompletely observed target cannot yield a passing proof.
            $sampleObservationFailureCount = [Math]::Min(
                256, $sampleObservationFailureCount + 1)
            $sampleObservationFailureCode = Get-WatcherFailureCode `
                -Step $script:watcherStep
            try {
                $failureNameKey = [string]$process.HttpTargetName
                $sampleObservationFailureProcess = $targetNames[$failureNameKey]
            }
            catch {
                $sampleObservationFailureProcess = 'unknown'
            }
            $sampleObservationFailureType = $_.Exception.GetType().Name
            if ($sampleObservationFailureType -notmatch '^[A-Za-z0-9_]{1,64}$') {
                $sampleObservationFailureType = 'Unknown'
            }
            $reportedOwnershipStep = if (
                $script:ownershipFailureStep -ne 'none'
            ) {
                $script:ownershipFailureStep
            }
            else {
                $script:ownershipStep
            }
            if ($reportedOwnershipStep -in @(
                    'initial_identity', 'parent_query', 'retained_parent',
                    'live_parent_open', 'parent_identity',
                    'ancestor_disposal')) {
                $sampleObservationFailureOwnershipStep = $reportedOwnershipStep
            }
            else {
                $sampleObservationFailureOwnershipStep = 'unknown'
            }
            $observationComplete = $false
            $stopObservation = $true
        }
        finally {
            if (-not $retainProcess) {
                $process.Dispose()
            }
        }
    }
    Start-Sleep -Milliseconds $SamplePeriodMilliseconds
}
$watch.Stop()

if ($null -ne $script:readySignalPath) {
    try {
        [System.IO.File]::Delete($script:readySignalPath)
        $readinessCleanupConfirmed = -not [System.IO.File]::Exists(
            $script:readySignalPath)
    }
    catch {
        $readinessCleanupConfirmed = $false
    }
    if (-not $readinessCleanupConfirmed) {
        $observationComplete = $false
    }
}

$remainingIdentities = @{}
$script:watcherStep = 'remaining_enumeration'
foreach ($process in Get-TargetProcesses) {
    try {
        $identity = Get-InternalProcessIdentity -Process $process
        if (-not $identity.verified) {
            if (-not $RequireOwnerBinding) { $observationComplete = $false }
        }
        else {
            $ownership = if (
                $RequireOwnerBinding -and
                $script:ownedIdentities.ContainsKey($identity.key)
            ) {
                @{ owned = $true; verified = $true; root = $false }
            }
            else {
                Test-ProcessOwnership -Process $process
            }
            if (
                $ownership.owned -and
                -not $baseline.ContainsKey($identity.key)
            ) {
                $remainingIdentities[$identity.key] = $true
            }
        }
    }
    catch {
        if (-not $RequireOwnerBinding) {
            $remainingObservationFailureCount = [Math]::Min(
                256, $remainingObservationFailureCount + 1)
            $observationComplete = $false
        }
    }
    finally {
        $process.Dispose()
    }
}
foreach ($retained in $script:retainedTargets) {
    try {
        if (
            [bool]$retained.owned -and
            -not $retained.process.HasExited
        ) {
            $remainingIdentities[[string]$retained.identity] = $true
        }
        $retained.process.Dispose()
    }
    catch {
        $remainingObservationFailureCount = [Math]::Min(
            256, $remainingObservationFailureCount + 1)
        $observationComplete = $false
    }
}
$script:retainedTargets.Clear()
$remaining = $remainingIdentities.Count
$visibleEvents = @($events | Where-Object { $_.ever_visible }).Count
$baselineVisibleConhosts = @($baselineConhostStates.Values | Where-Object {
    $_.ever_visible
}).Count
$baselineUnverifiedConhosts = @($baselineConhostStates.Values | Where-Object {
    -not $_.visibility_verified
}).Count
$unverifiedEvents = @($events | Where-Object {
    -not $_.visibility_verified
}).Count
$unverifiedParentEvents = @($events | Where-Object {
    -not $_.parent_verified
}).Count
$lineageComplete = $unverifiedParentEvents -eq 0
$terminationRequested = @($events | Where-Object { $_.termination_requested }).Count
$terminationConfirmed = @($events | Where-Object { $_.termination_confirmed }).Count
$script:watcherStep = 'publication_identity'
$sourceHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
$durationBucket = [int64]([Math]::Floor(
    $watch.ElapsedMilliseconds / $bucketWidthMilliseconds) * $bucketWidthMilliseconds)
$passed = (
    $observationComplete -and
    $baselineForbiddenCount -eq 0 -and
    $baselineVisibleConhosts -eq 0 -and
    $baselineUnverifiedConhosts -eq 0 -and
    $visibleEvents -eq 0 -and
    $unverifiedEvents -eq 0 -and
    (-not $lineageRequired -or $lineageComplete) -and
    (-not $RequireOwnerBinding -or (
        $ownerBindingVerified -and
        $ownerBindingCleanupConfirmed -and
        $ownerRootObserved
    )) -and
    $remaining -eq 0
)
$report = [ordered]@{
    schema = 1
    stage = $Stage
    source_sha256 = $sourceHash
    sample_period_ms = $SamplePeriodMilliseconds
    readiness_signaled = $readinessSignaled
    readiness_cleanup_confirmed = $readinessCleanupConfirmed
    owner_binding_required = [bool]$RequireOwnerBinding
    owner_binding_verified = $ownerBindingVerified
    owner_binding_cleanup_confirmed = $ownerBindingCleanupConfirmed
    owner_root_observed = $ownerRootObserved
    ignored_unowned_candidate_count = $ignoredUnownedCandidates
    duration_bucket_ms = $durationBucket
    samples = $sampleCount
    baseline_preexisting_conhost_count = $baselineConhostCount
    baseline_visible_conhost_count = $baselineVisibleConhosts
    baseline_unverified_conhost_count = $baselineUnverifiedConhosts
    baseline_forbidden_target_count = $baselineForbiddenCount
    baseline_observation_failure_count = $baselineObservationFailureCount
    sample_observation_failure_count = $sampleObservationFailureCount
    sample_observation_failure_code = $sampleObservationFailureCode
    sample_observation_failure_process = $sampleObservationFailureProcess
    sample_observation_failure_type = $sampleObservationFailureType
    sample_observation_failure_ownership_step = $sampleObservationFailureOwnershipStep
    remaining_observation_failure_count = $remainingObservationFailureCount
    event_count = $events.Count
    visible_event_count = $visibleEvents
    unverified_event_count = $unverifiedEvents
    unverified_parent_event_count = $unverifiedParentEvents
    lineage_required = $lineageRequired
    lineage_complete = $lineageComplete
    termination_requested_count = $terminationRequested
    termination_confirmed_count = $terminationConfirmed
    remaining_target_count = $remaining
    observation_complete = $observationComplete
    events = $events
    passed = $passed
}
$script:watcherStep = 'publication'
[Console]::Out.WriteLine(($report | ConvertTo-Json -Depth 4 -Compress))
if ($passed) { exit 0 }
exit 1
