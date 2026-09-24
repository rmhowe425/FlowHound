## Description

<!-- Describe what this change does. Be specific about the behavior being added or modified. -->



<!-- Explain why this change is needed. What problem does it solve or what improvement does it provide? -->



<!-- Reference any related GitHub issue(s) below (e.g., "Fixes #1234" or "Related to #5678"). Delete this line if not applicable. -->

**Related Issue:**

## Breaking Changes

<!-- Does this PR change existing behavior, remove options, rename datastore settings?
 If yes, describe what breaks and how users should adapt. Write "None" if not applicable. -->

None




## Test Evidence

<!-- Paste console output, screenshots, or links to screen recordings. Redact sensitive information. -->

<!-- For new modules: include output from the module's `check` method (if applicable) AND successful exploitation or execution against a controlled lab/test environment target. -->

## Environment

| Field | Details |
|-------|---------|
| **Operating System** | <!-- e.g., Ubuntu 22.04, Windows 11, macOS 14.2 --> |
| **Target Software/Hardware** | <!-- Name and version of the software or hardware targeted by this change --> |
| **Docker Image / Vagrant Setup** | <!-- (Optional) Image name or setup instructions if applicable, otherwise remove this row --> |


## Pre-Submission Checklist

- [ ] Included a corresponding documentation markdown file in `documentation/modules` _(new modules only)_
- [ ] No sensitive information (IP addresses, credentials, API keys, hashes) in code or documentation
- [ ] Tested on the target environment specified in the Environment section above
- [ ] Included RSpec tests for library changes _(encouraged for `lib/` changes)_
