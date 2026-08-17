-- Self-check on the pure-Lua parts, no network: lua test/selfcheck.lua
RUNTIME = { osType = "linux", archType = "amd64" }
package.preload["cmd"] = function()
    return {
        exec = function(c)
            local p = io.popen(c)
            local out = p:read("*a")
            p:close()
            return out
        end,
    }
end
package.preload["file"] = function()
    return {
        join_path = function(...)
            return table.concat({ ... }, "/")
        end,
        exists = function(p)
            local fh = io.open(p, "r")
            if fh then
                fh:close()
            end
            return fh ~= nil
        end,
    }
end
package.preload["log"] = function()
    local quiet = function() end
    return { trace = quiet, debug = quiet, info = quiet, warn = quiet, error = quiet }
end
dofile("metadata.lua")

-- Loading the hooks catches a syntax error or a renamed method, which mise would only
-- surface at install time.
for _, hook in ipairs({ "list_versions", "install", "exec_env" }) do
    dofile("hooks/backend_" .. hook .. ".lua")
end
for _, method in ipairs({ "BackendListVersions", "BackendInstall", "BackendExecEnv" }) do
    assert(type(PLUGIN[method]) == "function", "hook " .. method .. " is missing")
end
assert(PLUGIN.name == "tangled" and PLUGIN.version:match("^%d+%.%d+%.%d+$"), "plugin metadata")

local env = PLUGIN:BackendExecEnv({ install_path = "/opt/x" })
assert(env.env_vars[1].key == "PATH" and env.env_vars[1].value == "/opt/x/bin", "exec env exposes bin/")

-- Real record: sh.tangled.repo.artifact tag bytes of tangled core v1.2.0-alpha
assert(
    Tangled.bytes_to_hex("+al7jmvx40ZB7w7PqysBnsMlfvw=") == "f9a97b8e6bf1e34641ef0ecfab2b019ec3257efc",
    "base64 tag bytes -> hex"
)

-- Real blob CID whose sha256 was checked against the downloaded bytes
assert(
    Tangled.cid_sha256("bafkreicqg6ut7ttjfrk4yscwm4jxbkdlqvuivvad4g4oxvh4wl5t5567nm")
        == "5037a93fce692c55cc4856671370a86b85688ad403e1b8ebd4fcb2fb3ef7df6b",
    "CIDv1 -> sha256"
)
assert(Tangled.cid_sha256("Qmfoo") == nil, "CIDv0 is not decoded")
-- dag-cbor instead of raw: same sha256 length, but not the digest of the blob bytes.
assert(Tangled.cid_sha256("bafyreiha3nrxqnd2pmukig6y22rhfhdl3d6aksvqiirqjdegzov6gludzu") == nil, "raw codec only")

local owner, repo = Tangled.parse("tangled.org/core")
assert(owner == "tangled.org" and repo == "core", "parse handle/repo")
owner = Tangled.parse("did:plc:wshs7t2adsemcrrd4snkeqli/core")
assert(owner == "did:plc:wshs7t2adsemcrrd4snkeqli", "parse did/repo")
assert(not pcall(Tangled.parse, "core"), "parse rejects a bare repo")

assert(Tangled.render("app-v{{version}}-{{arch}}-{{os}}", "1.2.0") == "app-v1.2.0-amd64-linux", "render")
assert(Tangled.render("app-v{version}-{arch}-{os}", "1.2.0") == "app-v1.2.0-amd64-linux", "render single braces")
assert(Tangled.render("app-{version}", "1.0%1") == "app-1.0%1", "a % in the version is literal")

local function artifact(name, tag)
    return { uri = "at://did:plc:x/sh.tangled.repo.artifact/1", value = { name = name, tag = { ["$bytes"] = tag } } }
end
local TAG = "+al7jmvx40ZB7w7PqysBnsMlfvw="
local HASH = "f9a97b8e6bf1e34641ef0ecfab2b019ec3257efc"
local items = {
    artifact("tool-v1.2.0-x86_64-linux", TAG),
    artifact("tool-v1.2.0-x86_64-linux.sha256", TAG),
    artifact("tool-v1.2.0-aarch64-darwin", TAG),
    artifact("tool-v1.1.0-x86_64-linux", "AAAAAAAAAAAAAAAAAAAAAAAAAAA="),
}
assert(Tangled.pick(items, HASH, "1.2.0", {}).value.name == "tool-v1.2.0-x86_64-linux", "os/arch match")
assert(
    Tangled.pick(items, HASH, "1.2.0", { asset = "tool-v{{version}}-aarch64-darwin" }).value.name
        == "tool-v1.2.0-aarch64-darwin",
    "explicit asset wins"
)
assert(not pcall(Tangled.pick, items, HASH, "1.2.0", { asset = "nope" }), "unknown asset errors")

RUNTIME.archType = "riscv64"
assert(not pcall(Tangled.pick, items, HASH, "1.2.0", {}), "no artifact for this platform errors")

-- An alias must not match inside a longer token: arm is not arm64, x86 is not x86_64.
RUNTIME.archType = "arm"
assert(not pcall(Tangled.pick, { artifact("tool-linux-arm64", TAG) }, HASH, "1", {}), "arm does not match arm64")
RUNTIME.archType = "386"
assert(not pcall(Tangled.pick, { artifact("tool-linux-x86_64", TAG) }, HASH, "1", {}), "386 does not match x86_64")
assert(Tangled.pick({ artifact("tool-linux-i386", TAG) }, HASH, "1", {}), "i386 still matches")
RUNTIME.archType = "amd64"
assert(Tangled.pick({ artifact("tool_linux_x86_64", TAG) }, HASH, "1", {}), "underscores separate tokens")
assert(Tangled.pick({ artifact("tool.linux.amd64.bin", TAG) }, HASH, "1", {}), "dots separate tokens")

-- Two artifacts of the same name length: refuse rather than pick one at random.
assert(
    not pcall(Tangled.pick, { artifact("tool-linux-amd64", TAG), artifact("evil-linux-amd64", TAG) }, HASH, "1", {}),
    "an ambiguous match errors"
)

-- Real shape: the repo displayed as `Notary` is stored under the record key `notary`.
local repos = {
    { uri = "at://did:plc:o/sh.tangled.repo/gitops", value = { name = "GitOps", repoDid = "did:plc:g" } },
    { uri = "at://did:plc:o/sh.tangled.repo/notary", value = { name = "Notary", repoDid = "did:plc:n" } },
    { uri = "at://did:plc:o/sh.tangled.repo/vacua", value = { repoDid = "did:plc:v" } },
    { uri = "at://did:plc:o/sh.tangled.repo/3liuighjy2h22", value = { name = "core", repoDid = "did:plc:c" } },
}
assert(Tangled.match_repo(repos, "Notary").repoDid == "did:plc:n", "match on the name")
assert(Tangled.match_repo(repos, "notary").repoDid == "did:plc:n", "match on the record key")
assert(Tangled.match_repo(repos, "NOTARY").repoDid == "did:plc:n", "match ignoring case")
assert(Tangled.match_repo(repos, "vacua").repoDid == "did:plc:v", "match a repo with no name")
assert(Tangled.match_repo(repos, "core").repoDid == "did:plc:c", "match a repo keyed by a tid")
assert(Tangled.match_repo(repos, "absent") == nil, "no match returns nil")

-- A null field arrives as userdata in mise, which is truthy: it must not crash the listing.
local NULL = io.stdout
assert(next(Tangled.tagged_hashes({ { value = NULL }, { value = { tag = NULL } } })) == nil, "null tag is skipped")
assert(#Tangled.tagged_hashes({}) == 0, "no artifact means no hash")

-- An artifact name reaching the filesystem must not escape the download directory.
for _, evil in ipairs({ "../../../../tmp/pwn-linux-amd64", "sub/dir-linux-amd64", ".bashrc-linux-amd64" }) do
    assert(not pcall(Tangled.pick, { artifact(evil, TAG) }, HASH, "1.2.0", {}), "rejects name " .. evil)
end

-- Artifacts from a DID that owns neither the repo nor a collaborator seat are dropped.
local function from(did, name)
    return { uri = "at://" .. did .. "/sh.tangled.repo.artifact/1", value = { name = name } }
end
local allowed = { ["did:plc:owner"] = true, ["did:plc:mate"] = true }
local kept = Tangled.filter_uploaders({
    from("did:plc:owner", "a"),
    from("did:plc:stranger", "b"),
    from("did:plc:mate", "c"),
}, allowed)
assert(#kept == 2 and kept[1].value.name == "a" and kept[2].value.name == "c", "keeps owner and collaborator")
assert(#Tangled.filter_uploaders({ { uri = "garbage", value = {} } }, allowed) == 0, "drops an unparsable uri")

-- A file whose bytes do not match the CID must be rejected.
local tmp = os.tmpname()
local fh = assert(io.open(tmp, "w"))
fh:write("not the artifact")
fh:close()
assert(
    not pcall(Tangled.verify, tmp, "bafkreicqg6ut7ttjfrk4yscwm4jxbkdlqvuivvad4g4oxvh4wl5t5567nm"),
    "checksum mismatch is fatal"
)
-- A CID we cannot read a sha256 from must stop the install, not downgrade to a warning.
for _, cid in ipairs({ "Qmfoo", "k2jmtxx8tc9pv6f9ubqf3eqjqhz1lxwu4kb0c5", "zdj7WkRPAX9o9nb9zPbXzwG7JEs" }) do
    assert(not pcall(Tangled.verify, tmp, cid), "unverifiable CID is fatal: " .. cid)
end
os.remove(tmp)

print("selfcheck ok")
