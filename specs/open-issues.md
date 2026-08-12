# Open issues

This register tracks agreed validation gaps and deferred extensions to the
accepted specifications. When an item ships, remove it here and record the
change in `CHANGELOG.md`. Rejected out-of-scope ideas remain in the research
note rather than this list.

## OI-31: Stop the intermittent assertion failures in whole-suite runs

Specification: 0005.

`Service access rules.Get-ServiceAccessRule should expose typed SCM rights`
failed twice on 2026-08-11 in a full `./build.ps1 -Tasks test` run and passed
whenever its file ran alone. The failure reads
`Expected [WindowsServiceControlManagerRights], but got
[WindowsServiceControlManagerRights]`. Both affected assertions now compare the
type name and `IsEnum` instead of type identity, which is what they actually
mean.

The duplicate-import explanation this entry used to carry is disproved. Measured
on 2026-08-11 and 2026-08-12 against the built module in PowerShell 7.6.3:

- three consecutive `Import-Module -Force` calls leave exactly **one** runtime
  copy of `WindowsServiceControlManagerRights`, as do a plain re-import and a
  remove followed by an import;
- a batch worker runspace created the way `Invoke-WindowsAccessControlBatch`
  creates one resolves to the same runtime type, same assembly, identity equal;
- with Pester code coverage armed, which is the condition that exposed the other
  intermittent failure in this entry, a bounded batch returning a
  module-defined enumeration still yields one live type and identity equality,
  four times out of four.

PowerShell caches the compiled class assembly per module path and version, so
re-importing the same built module does not define the enumerations again.

So the cause is still unknown, and the repair is not "one shared import" until
something reproduces a second live type. Do not revert the two assertions to
identity comparison on the strength of an import change: that would reintroduce
an intermittent failure whose mechanism nobody has demonstrated. Reproduce the
second live type first, then revert them as the regression guard. Any new
assertion on a module-defined type meanwhile avoids identity.

The second failure is fixed. `NTFS batch execution.Should mutate multiple
independent targets with bounded execution` lost a target in three full
`./build.ps1 -Tasks test` runs on 2026-08-11 and never in isolation. The test
asserted only a rule count, so nothing said why. It now captures the error
stream of both batches, and the next run named the cause:

```text
Invoke-WindowsAccessControlBatch: Cannot process argument transformation on
parameter 'AccessRights'. Object reference not set to an instance of an object.
```

A bounded-parallel worker runspace re-invokes the public command with the
already-bound parameters, `WindowsAccessRightsTransformAttribute` ran again on a
value that was already the target enumeration, and it threw a null reference.
The worker's target then produced no rule, which was the missing second rule.

The captured stack named the mechanism:

```text
System.NullReferenceException
  at ScriptBlock.InvokeWithPipe(...)
  at ScriptBlock.InvokeAsMemberFunction(Object instance, Object[] args)
  at ScriptBlockMemberMethodWrapper.InvokeHelper(Object instance,
      Object sessionStateInternal, Object[] args)
  at WindowsAccessRightsTransformAttribute.Transform(...)
  at ArgumentTransformationAttribute.TransformInternal(...)
  at ParameterBinderBase.BindParameter(...)
```

The fault was in the engine's invocation of the class method body, not in the
method body itself. A PowerShell class instance carries the session state of the
runspace that created it, and the attribute instance bound to the parameter is
invoked from a pooled worker runspace whose session state for that class is not
established, so `sessionStateInternal` was null.

The attribute is now compiled through `Add-Type` in `Prefix.ps1` instead of
being a PowerShell class, so `Transform` is IL with no session state to lose.
Measured on 2026-08-12 over six instrumented iterations of the same Pester file
each: five of six failed with 22 transformation faults before the change and
zero of six failed with none after it. Pester code coverage is what makes the
fault appear, which is why 66 uninstrumented iterations had shown nothing.

Do not loosen the test. It is the only thing that reported the fault.

## See also

- [Specification index](README.md)
- [NTFSSecurity comparison](../docs/research.md#detailed-ntfssecurity-comparison)
