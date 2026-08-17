# mise-tangled

A [mise](https://mise.jdx.dev) backend plugin that installs binaries attached to
[tangled](https://tangled.org) tags.

Tangled release artifacts are `sh.tangled.repo.artifact` records living in the PDS of whoever
uploaded them, with the binary stored as an atproto blob. The plugin resolves a tag to its
artifact and installs it.

## Install

```bash
mise plugin install tangled https://github.com/qjoly/mise-tangled
```

The repo lives on GitHub and is mirrored on tangled.

## Usage

```bash
mise ls-remote 'tangled:tangled.org/core'
mise use 'tangled:tangled.org/core@1.2.0-alpha'
```

Tool syntax is `tangled:<handle-or-did>/<repo>`. Only tags that carry an artifact show up as
versions.

The plugin picks the artifact on its own when the file name contains the OS and the architecture
(`linux`, `darwin`/`macos`, `amd64`/`x86_64`, `arm64`/`aarch64`). Otherwise, name it:

```toml
[tools]
"tangled:tangled.org/core" = { version = "1.2.0-alpha", asset = "appview-v{{version}}-x86_64-linux", bin = "appview" }
```

### Options

| Option | Default | Purpose |
|---|---|---|
| `asset` | auto by os/arch | artifact name, templated with `{{version}}`, `{{os}}`, `{{arch}}` |
| `bin` | repo name | binary name in `bin/` (single-file artifacts only) |
| `appview` | `https://api.tangled.org` | appview XRPC host |
| `resolver` | `https://slingshot.microcosm.blue` | handle -> DID resolver |
| `git_host` | `https://tangled.org` | host used for `git ls-remote` |
| `repo_url` | none | full clone URL, overrides `git_host` |

Self-hosted knot:

```toml
"tangled:did:plc:xxxx/mytool" = { version = "latest", repo_url = "https://knot.example.com/did:plc:xxxx/mytool" }
```

## How it works

1. `git ls-remote --tags --refs` -> tag names and the hash of their tag object
2. `sh.tangled.repo.getRepo` -> the repo's own DID
3. `sh.tangled.repo.listArtifacts` -> artifacts of every uploader, filtered on the tag hash
4. `com.atproto.sync.getBlob` on the uploader's PDS -> the bytes

The blob CID is a CIDv1 `raw` + `sha2-256`. The plugin reads the expected sha256 out of the CID
and checks it after download, so nobody has to publish a checksum file next to the binary.

## Caveats

- The lexicon caps an artifact at 50 MB, so publish large binaries compressed.
- Tags must be annotated. Artifacts point at a tag object, and a lightweight tag creates none.
- `mise ls-remote` hides prereleases, so `1.2.0-alpha` style tags only show up on explicit install.
- Requires `git` in `PATH`.

## Development

```bash
lua test/selfcheck.lua      # offline checks on parsing, artifact matching, CID decoding
mise plugin link --force tangled .
mise cache clear
```

## License

MIT
