# Changelog

## 0.0.1

First release. Installs a binary attached to a tangled tag as a mise tool:
`tangled:<handle-or-did>/<repo>@<version>`.

- Versions come from `git ls-remote --tags`, keeping only the tags that carry an artifact.
- Artifacts are read from the appview (`sh.tangled.repo.listArtifacts`) and downloaded from the
  uploader's PDS with `com.atproto.sync.getBlob`.
- Only the repo owner, the repo DID and the collaborators listed by
  `sh.tangled.repo.listCollaborators` are trusted. Add more with `allowed_uploaders`.
- The sha256 carried by the blob CID is checked after download. Anything that prevents the check
  stops the install.
- Artifact names that are not a bare file name are refused.
- The artifact is picked from the OS and architecture in its name, on token boundaries, or named
  with the `asset` option.
- Archives are extracted, unwrapping a single top-level directory.

Windows is not supported: the install path uses POSIX tools.
