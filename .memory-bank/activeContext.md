---
status: current
last-verified: 2026-09-06
owner: software-engineer
source: current task evidence
---

# Active context

## Current task

GitHub Actions run `34026468199`, attempt 2, partially published
`0.2.0-preview0001` and then failed in `Publish_GitHub_Wiki_Content`. The
GitHub release, its two assets, and the PowerShell Gallery package exist, but
the wiki still contains only its initial `Home.md`. This turn diagnosed the
failure without changing the workflow, source, repository settings, or any
remote state.

## Diagnosis

- The failed command was `git commit --message ...`, not a clone or push.
  It ran for the `Invoke-Git` timeout of 120 seconds and returned sentinel exit
  code `-1` with empty standard output and standard error.
- `DscResource.DocGenerator` 0.13.0 redirects both Git output streams, waits
  for Git to exit, and reads the streams only afterward. The generated archive
  contains 127 files whose per-file create summary is about 6,878 bytes. That
  fills the redirected pipe, so Git blocks waiting for a reader while the
  parent blocks waiting for Git.
- This is the open upstream bug
  [DscResource.DocGenerator#111](https://github.com/dsccommunity/DscResource.DocGenerator/issues/111).
  The latest release and the current upstream source still contain the faulty
  wait-before-read implementation.
- The wiki head remains its 2026-09-02 initial commit
  `e25a0b8b1fe63fb6842eaccdbbc55f741d0fd3da`, with no release tag. The token
  was not the cause: secret validation, GitHub release writes, and Gallery
  publication all succeeded before the local wiki commit hung.

## Partial release state

- GitHub release `v0.2.0-preview0001` exists for commit `764f0b1` with
  `WindowsAccessControl.0.2.0-preview0001.nupkg` and `WikiContent.zip`.
- PowerShell Gallery version `0.2.0-preview0001` was published at
  2026-09-06 10:51:48 UTC.
- A blind rerun can collide with the immutable Gallery version before it
  reaches the wiki task. Remediation and rerun remain explicit follow-up work.

## Next action

Repair or replace the dependency's Git process wrapper so redirected streams
are drained while the process runs, or use a repository-owned wiki publish
step that commits quietly. Account for the existing GitHub release and Gallery
package before rerunning any publish workflow.
