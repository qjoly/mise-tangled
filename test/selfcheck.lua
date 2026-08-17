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
package.preload["log"] = function()
    return { info = function() end, warn = function() end }
end
dofile("metadata.lua")

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

local owner, repo = Tangled.parse("tangled.org/core")
assert(owner == "tangled.org" and repo == "core", "parse handle/repo")
owner = Tangled.parse("did:plc:wshs7t2adsemcrrd4snkeqli/core")
assert(owner == "did:plc:wshs7t2adsemcrrd4snkeqli", "parse did/repo")
assert(not pcall(Tangled.parse, "core"), "parse rejects a bare repo")

assert(Tangled.render("app-v{{version}}-{{arch}}-{{os}}", "1.2.0") == "app-v1.2.0-amd64-linux", "render")

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

-- A file whose bytes do not match the CID must be rejected.
local tmp = os.tmpname()
local fh = assert(io.open(tmp, "w"))
fh:write("not the artifact")
fh:close()
assert(
    not pcall(Tangled.verify, tmp, "bafkreicqg6ut7ttjfrk4yscwm4jxbkdlqvuivvad4g4oxvh4wl5t5567nm"),
    "checksum mismatch is fatal"
)
-- An unknown CID shape only warns, it must not block the install.
assert(pcall(Tangled.verify, tmp, "Qmfoo"), "unknown CID shape is tolerated")
os.remove(tmp)

print("selfcheck ok")
