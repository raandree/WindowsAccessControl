<!--
    Thanks for submitting a Pull Request (PR) to this project.
    Your contribution to this project is greatly appreciated!

    Please make sure the PR title is short but a descriptive summary of the PR,
    e.g. "fix(ntfs): bind a hexadecimal rights literal on every command".

    The wording decides the next version, because GitVersion reads the commit
    messages. See the table in CONTRIBUTING.md.

    You may remove this comment block, and the other comment blocks, but please
    keep the headers and the task list.
-->
#### Pull Request (PR) description
<!--
    Replace this comment block with a description of your PR.
-->

#### This Pull Request (PR) fixes the following issues
<!--
    Replace this comment block with the list of issues or n/a.
    Use format:
    - Fixes #123
    - Fixes #124
-->

#### What was run, and what the result was
<!--
    Replace this comment block with the gate you exercised and its outcome, for
    example the test counts and the coverage percentage from
    `.\build.ps1 -Tasks test`. A maintainer should not have to guess.

    Say so here when a change touches the SMB share, Active Directory, Task
    Scheduler, or certificate private-key family and you could not run the
    domain acceptance lab. You do not need the lab to contribute.
-->

#### Task list
<!--
    To aid reviewers in reviewing and merging your PR, please take the time to
    run through the below checklist and make sure your PR has everything updated
    as required.

    Change to [x] for each task in the task list that applies to your pull
    request (PR). For those tasks that do not apply to your PR, leave those
    as is.
-->
- [ ] Added an entry to the change log under the Unreleased section of the file
      CHANGELOG.md. The entry says what changed for someone using the module and
      why, and references the issue being resolved (if applicable).
- [ ] The behavior change starts in a specification under `specs/`, every
      requirement identifier it adds is unique, and each one traces to
      executable evidence in `specs/0005-verification-and-traceability.md`.
- [ ] A durable architectural choice is recorded under `specs/decisions/` and
      indexed in `specs/decisions/README.md`.
- [ ] Comment-based help added or updated for every new or changed command,
      including a synopsis, a description, an example, and every parameter.
- [ ] Documentation added or updated in `README.md` or under `docs/`.
- [ ] Unit tests added or updated, and a bug fix keeps a regression test that
      fails without the fix.
- [ ] Integration or live tests added or updated where the behavior can only be
      measured against a real object.
- [ ] `.\build.ps1 -Tasks test` passes in both supported PowerShell editions,
      including the coverage threshold, with no assertion weakened to get there.
- [ ] `Invoke-ScriptAnalyzer` is clean over everything that changed, and any
      suppression carries a `Justification`.
