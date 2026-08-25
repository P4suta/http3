# Change proposal

## Change

Describe the observable behavior and affected RFC requirement or exclusion.

## Evidence

- [ ] A failing regression reproduced the behavior before the fix, or this is documentation/configuration only.
- [ ] `mise run check` passes.
- [ ] Affected fault, property, fuzz, interop, coverage, or performance gates pass.
- [ ] Public API snapshots were intentionally reviewed if they changed.
- [ ] Conformance and operational documentation reflect the actual state.

## Security and release scope

- [ ] No PID, socket, atom, reference, mailbox shape, credential content, ticket plaintext, or traffic secret crosses the public API or artifacts.
- [ ] Peer-controlled state and every wait introduced here have finite bounds.
- [ ] This change does not tag, publish, upload, push, or change package versions.
