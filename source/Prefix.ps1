if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw [System.PlatformNotSupportedException]::new(
        'WindowsAccessControl manages Windows NTFS security descriptors and is supported only on Windows.'
    )
}

# Windows PowerShell resolves parameter type attributes before a function body
# runs, so the directory assembly must be present before the first call.
Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop

# The rights transformation attribute is compiled rather than written as a
# PowerShell class. A class method invoked during parameter binding inside a
# pooled worker runspace faults with a null session state, which silently drops
# that worker's target from a bounded batch; compiled IL has no session state to
# lose. The type is application-domain wide, so an edit to this source needs a
# fresh process rather than a re-import.
if (-not ('WindowsAccessRightsTransformAttribute' -as [type])) {
    # Add-Type replaces the default reference set rather than adding to it, so
    # every assembly the source uses beyond the core library is named here.
    Add-Type -ErrorAction Stop -ReferencedAssemblies @(
        [System.Management.Automation.PSObject].Assembly.Location
        [System.Text.RegularExpressions.Regex].Assembly.Location
    ) -TypeDefinition @'
using System;
using System.Globalization;
using System.Management.Automation;
using System.Text.RegularExpressions;

public sealed class WindowsAccessRightsTransformAttribute : ArgumentTransformationAttribute
{
    private static readonly Regex HexadecimalMask =
        new Regex("^0[xX][0-9a-fA-F]{1,8}$", RegexOptions.CultureInvariant);
    private static readonly Regex DecimalMask =
        new Regex("^-?[0-9]+$", RegexOptions.CultureInvariant);

    public WindowsAccessRightsTransformAttribute(Type rightsType)
    {
        if (rightsType == null)
        {
            throw new ArgumentNullException("rightsType");
        }

        if (!rightsType.IsEnum)
        {
            throw new ArgumentException(
                "RightsType '" + rightsType.FullName + "' is not an enumeration.");
        }

        this.RightsType = rightsType;
    }

    public Type RightsType { get; private set; }

    public override object Transform(EngineIntrinsics engineIntrinsics, object inputData)
    {
        if (inputData == null)
        {
            return inputData;
        }

        object value = inputData;
        PSObject wrapper = value as PSObject;
        if (wrapper != null)
        {
            value = wrapper.BaseObject;
        }

        // Binding re-runs the transformation over an unbound parameter while it
        // resolves a parameter set, so a null has to survive it untouched.
        if (value == null)
        {
            return inputData;
        }

        if (value.GetType() == this.RightsType)
        {
            return value;
        }

        long mask;
        if (!TryGetMask(value, out mask))
        {
            // A name or a comma-separated name list still converts through the
            // engine, which rejects an unknown name and names both the value
            // and the type it could not become.
            return LanguagePrimitives.ConvertTo(value, this.RightsType);
        }

        if (mask < int.MinValue || mask > uint.MaxValue)
        {
            throw new ArgumentOutOfRangeException(
                "inputData", inputData, "An access mask must fit in 32 bits.");
        }

        if (mask > int.MaxValue)
        {
            mask -= 4294967296L;
        }

        // Enum.ToObject keeps every bit, including the generic rights and
        // ACCESS_SYSTEM_SECURITY, that the engine's enum conversion rejects
        // because the enum has no name for them.
        return Enum.ToObject(this.RightsType, (int)mask);
    }

    private static bool TryGetMask(object value, out long mask)
    {
        mask = 0;

        string text = value as string;
        if (text != null)
        {
            text = text.Trim();
            if (HexadecimalMask.IsMatch(text))
            {
                mask = Convert.ToInt64(text.Substring(2), 16);
                return true;
            }

            return DecimalMask.IsMatch(text) &&
                long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out mask);
        }

        if (value is byte || value is sbyte || value is short || value is ushort ||
            value is int || value is uint || value is long || value is ulong)
        {
            mask = Convert.ToInt64(value, CultureInfo.InvariantCulture);
            return true;
        }

        return false;
    }
}
'@
}

$targetLockStateName = 'WindowsAccessControl.TargetLockState'
$currentAppDomain = [System.AppDomain]::CurrentDomain
[System.Threading.Monitor]::Enter($currentAppDomain)
try {
    $targetLockState = $currentAppDomain.GetData($targetLockStateName)
    if (-not $targetLockState) {
        $targetLockState = @{
            SyncRoot = [object]::new()
            Locks    = @{}
        }
        $currentAppDomain.SetData($targetLockStateName, $targetLockState)
    }
} finally {
    [System.Threading.Monitor]::Exit($currentAppDomain)
}
$script:WindowsAccessControlTargetLockSyncRoot = $targetLockState.SyncRoot
$script:WindowsAccessControlTargetLocks = $targetLockState.Locks
$script:WindowsAccessControlMetricSyncRoot = [object]::new()
$script:WindowsAccessControlMetrics = @{}
$script:WindowsADSchemaGuidNames = @{}
$script:WindowsAccessControlBatchWorker =
    [System.Threading.ThreadLocal[bool]]::new()
