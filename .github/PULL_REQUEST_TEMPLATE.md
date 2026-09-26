<!-- Adding or changing a rule? Use the rule template: append ?template=new_rule.md to the URL. -->

## Summary

<!-- What changes and why. Link related issues. -->

## Verification

- [ ] `make ci` passes.
- [ ] Generated files are regenerated (`make generate`) and committed.
- [ ] `make verify-siem` passes, or is not needed because this change does not touch conversion, detection logic or the pinned pySigma packages.
- [ ] Tests cover the change.
- [ ] `CHANGELOG.md` has an entry under *Unreleased* for user-visible changes.
