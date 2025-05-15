# Contributing

Coding conventions and requirements are captured in the justfile. Check it out to contribute!

## Publish New Crate Versions

1. Update the version in each crate's Cargo.toml and ensure the Cargo.lock is updated as well.
2. Add an entry to each crate's CHANGELOG.md.
3. Commit Cargo and Changelog updates to the main branch.
4. Tag that commit for every crate e.g. `protocol-v0.5.0`. The justfile contains a recipe for this. Must have write permissions on the upstream repository.
5. Checkout the relevant tags and publish the crates.
