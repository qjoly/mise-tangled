PLUGIN = { -- luacheck: ignore
    name = "tangled",
    version = "0.1.0",
    description = "Install binaries attached to tangled tags (atproto artifacts)",
    author = "qjoly",
    homepage = "https://github.com/qjoly/mise-tangled",
    license = "MIT",
    notes = {
        "Tool syntax: tangled:<handle-or-did>/<repo>, e.g. tangled:tangled.org/core",
        "Requires git in PATH (version listing uses git ls-remote)",
    },
}

local DEFAULT_APPVIEW = "https://api.tangled.org"
local DEFAULT_RESOLVER = "https://slingshot.microcosm.blue"
local DEFAULT_GIT_HOST = "https://tangled.org"
local MAX_PAGES = 20

-- Shared helpers, exposed as a global so the hooks/ files can reach them.
Tangled = {} -- luacheck: ignore

local ARCHIVE_SUFFIXES = { ".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2", ".tbz2", ".tar.zst", ".zip" }
local IGNORED_SUFFIXES = { ".sha256", ".sha512", ".asc", ".sig", ".pem", ".sbom", ".json", ".txt", ".md" }

local OS_ALIASES = {
    linux = { "linux" },
    darwin = { "darwin", "macos", "apple", "osx" },
    windows = { "windows", "win" },
}

local ARCH_ALIASES = {
    amd64 = { "amd64", "x86_64", "x64" },
    arm64 = { "arm64", "aarch64" },
    ["386"] = { "386", "i386", "x86" },
    arm = { "armv7", "armhf", "arm" },
}

local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local B32 = "abcdefghijklmnopqrstuvwxyz234567"

--- JSON nulls come back as userdata: keep only real strings.
local function as_string(v)
    if type(v) == "string" and v ~= "" then
        return v
    end
    return nil
end

local function opt(options, key, fallback)
    local v = options and options[key]
    if v == nil or v == "" then
        return fallback
    end
    return v
end

local function get_json(url)
    local http = require("http")
    local json = require("json")
    local resp, err = http.get({ url = url })
    if err then
        error("GET " .. url .. " failed: " .. tostring(err))
    end
    if resp.status_code ~= 200 then
        error("GET " .. url .. " returned HTTP " .. resp.status_code .. ": " .. tostring(resp.body))
    end
    return json.decode(resp.body)
end

--- Decodes a base-N string (N = 2^width) into an array of byte values.
local function decode_bits(s, alphabet, width)
    local bytes, acc, nbits = {}, 0, 0
    for i = 1, #s do
        local c = s:sub(i, i)
        local v = alphabet:find(c, 1, true)
        if not v then
            error("invalid character '" .. c .. "' in encoded string")
        end
        acc = acc * 2 ^ width + (v - 1)
        nbits = nbits + width
        while nbits >= 8 do
            nbits = nbits - 8
            local byte = math.floor(acc / 2 ^ nbits)
            bytes[#bytes + 1] = byte
            acc = acc - byte * 2 ^ nbits
        end
    end
    return bytes
end

local function to_hex(bytes, from, to)
    local out = {}
    for i = from or 1, to or #bytes do
        out[#out + 1] = string.format("%02x", bytes[i])
    end
    return table.concat(out)
end

local function ends_with_any(name, suffixes)
    local lower = name:lower()
    for _, s in ipairs(suffixes) do
        if #lower > #s and lower:sub(-#s) == s then
            return s
        end
    end
    return nil
end

local function contains_any(haystack, needles)
    for _, n in ipairs(needles) do
        if haystack:find(n, 1, true) then
            return true
        end
    end
    return false
end

local function shell_quote(s)
    return "'" .. s:gsub("'", "'\\''") .. "'"
end

--- `$bytes` of a record field (standard or url-safe base64) to a hex string.
function Tangled.bytes_to_hex(b64)
    local clean = b64:gsub("-", "+"):gsub("_", "/"):gsub("=", "")
    return to_hex(decode_bits(clean, B64, 6))
end

--- sha256 digest carried by a base32 CIDv1 (raw + sha2-256), or nil if another shape.
function Tangled.cid_sha256(cid)
    if cid:sub(1, 1) ~= "b" then
        return nil
    end
    local ok, bytes = pcall(decode_bits, cid:sub(2), B32, 5)
    if not ok or #bytes < 36 then
        return nil
    end
    -- cidv1 | codec | multihash code 0x12 (sha2-256) | length 0x20
    if bytes[1] ~= 0x01 or bytes[3] ~= 0x12 or bytes[4] ~= 0x20 then
        return nil
    end
    return to_hex(bytes, 5, 36)
end

--- "handle/repo" or "did:plc:xxx/repo" -> owner, repo
function Tangled.parse(tool)
    local owner, repo = tool:match("^([%w%.%-_:]+)/([%w%.%-_]+)$")
    if not owner then
        error("invalid tool '" .. tostring(tool) .. "', expected <handle-or-did>/<repo>")
    end
    return owner, repo
end

function Tangled.resolve_did(owner, options)
    if owner:sub(1, 4) == "did:" then
        return owner
    end
    local resolver = opt(options, "resolver", DEFAULT_RESOLVER)
    local data = get_json(resolver .. "/xrpc/com.atproto.identity.resolveHandle?handle=" .. owner)
    local did = as_string(data.did)
    if not did then
        error("could not resolve handle " .. owner)
    end
    return did
end

function Tangled.resolve_pds(did)
    local doc
    if did:sub(1, 8) == "did:plc:" then
        doc = get_json("https://plc.directory/" .. did)
    elseif did:sub(1, 8) == "did:web:" then
        doc = get_json("https://" .. (did:sub(9):gsub(":", "/")) .. "/.well-known/did.json")
    else
        error("unsupported DID method: " .. did)
    end
    for _, service in ipairs(doc.service or {}) do
        if service.id == "#atproto_pds" or service.id == did .. "#atproto_pds" then
            return service.serviceEndpoint
        end
    end
    error("no #atproto_pds service in DID document of " .. did)
end

--- Repo record from the appview: gives us repoDid (artifact subject) and knot.
function Tangled.get_repo(tool, options)
    local owner, repo = Tangled.parse(tool)
    local did = Tangled.resolve_did(owner, options)
    local appview = opt(options, "appview", DEFAULT_APPVIEW)
    local url = appview .. "/xrpc/sh.tangled.repo.getRepo?repo=at://" .. did .. "/sh.tangled.repo/" .. repo
    local record = get_json(url)
    local value = record.value or {}
    local repo_did = as_string(value.repoDid)
    if not repo_did then
        error("repo " .. tool .. " has no repoDid, it cannot hold artifacts")
    end
    return { did = did, name = repo, repo_did = repo_did, knot = as_string(value.knot) }
end

function Tangled.git_url(tool, options)
    local url = opt(options, "repo_url")
    if url then
        return url
    end
    return opt(options, "git_host", DEFAULT_GIT_HOST) .. "/" .. tool
end

--- Tag names with the hash of their tag object, which is what artifacts point at.
function Tangled.tags(tool, options)
    local cmd = require("cmd")
    local url = Tangled.git_url(tool, options)
    local out = cmd.exec("git ls-remote --tags --refs " .. shell_quote(url))
    local tags = {}
    for line in tostring(out):gmatch("[^\r\n]+") do
        local hash, name = line:match("^(%x+)%s+refs/tags/(.+)$")
        if hash then
            tags[#tags + 1] = { name = name, hash = hash, version = (name:gsub("^v(%d)", "%1")) }
        end
    end
    if #tags == 0 then
        error("no tags found in " .. url)
    end
    return tags
end

--- Every artifact of the repo, aggregated by the appview across uploader PDSes.
function Tangled.artifacts(repo, options)
    local appview = opt(options, "appview", DEFAULT_APPVIEW)
    local base = appview .. "/xrpc/sh.tangled.repo.listArtifacts?limit=100&subject=" .. repo.repo_did
    local items, cursor = {}, nil
    for _ = 1, MAX_PAGES do
        local url = base
        if cursor then
            url = url .. "&cursor=" .. cursor
        end
        local page = get_json(url)
        for _, item in ipairs(page.items or {}) do
            items[#items + 1] = item
        end
        local next_cursor = as_string(page.cursor)
        if not next_cursor or next_cursor == cursor then
            break
        end
        cursor = next_cursor
    end
    return items
end

--- Set of tag-object hashes that actually have an artifact attached.
function Tangled.tagged_hashes(items)
    local hashes = {}
    for _, item in ipairs(items) do
        local raw = item.value and item.value.tag and item.value.tag["$bytes"]
        if raw then
            hashes[Tangled.bytes_to_hex(raw)] = true
        end
    end
    return hashes
end

function Tangled.render(template, version)
    local os_name = RUNTIME.osType
    local arch = RUNTIME.archType
    return (
        template
            :gsub("{{%s*version%s*}}", version)
            :gsub("{{%s*os%s*}}", os_name)
            :gsub("{{%s*arch%s*}}", arch)
    )
end

--- Picks the artifact to install: explicit `asset` option, else os/arch matching.
function Tangled.pick(items, tag_hash, version, options)
    local candidates = {}
    for _, item in ipairs(items) do
        local value = item.value or {}
        local raw = value.tag and value.tag["$bytes"]
        if raw and Tangled.bytes_to_hex(raw) == tag_hash then
            candidates[#candidates + 1] = item
        end
    end

    local names = {}
    for _, item in ipairs(candidates) do
        names[#names + 1] = item.value.name
    end

    if #candidates == 0 then
        error("no artifact attached to tag " .. tag_hash)
    end

    local wanted = opt(options, "asset")
    if wanted then
        wanted = Tangled.render(wanted, version)
        for _, item in ipairs(candidates) do
            if item.value.name == wanted then
                return item
            end
        end
        error("no artifact named '" .. wanted .. "'; available: " .. table.concat(names, ", "))
    end

    local os_names = OS_ALIASES[RUNTIME.osType] or { RUNTIME.osType }
    local arch_names = ARCH_ALIASES[RUNTIME.archType] or { RUNTIME.archType }
    local matches = {}
    for _, item in ipairs(candidates) do
        local name = item.value.name:lower()
        if not ends_with_any(name, IGNORED_SUFFIXES) and contains_any(name, os_names) and contains_any(name, arch_names) then
            matches[#matches + 1] = item
        end
    end

    if #matches == 0 then
        error(
            "no artifact for "
                .. RUNTIME.osType
                .. "/"
                .. RUNTIME.archType
                .. "; available: "
                .. table.concat(names, ", ")
                .. " (use the `asset` option to pick one)"
        )
    end

    -- Shortest name wins: it is the plain binary rather than a variant.
    table.sort(matches, function(a, b)
        return #a.value.name < #b.value.name
    end)
    return matches[1]
end

function Tangled.verify(path, cid)
    local log = require("log")
    local expected = Tangled.cid_sha256(cid)
    if not expected then
        log.warn("tangled: unexpected CID shape " .. cid .. ", skipping checksum")
        return
    end
    local cmd = require("cmd")
    local quoted = shell_quote(path)
    local ok, out = pcall(cmd.exec, "sha256sum " .. quoted .. " 2>/dev/null || shasum -a 256 " .. quoted)
    if not ok then
        log.warn("tangled: no sha256 tool available, skipping checksum")
        return
    end
    local got = tostring(out):match("%x%x%x%x%x%x%x%x+")
    if not got then
        log.warn("tangled: could not read sha256 output, skipping checksum")
        return
    end
    if got:lower() ~= expected then
        error("checksum mismatch: expected " .. expected .. ", got " .. got)
    end
end

function Tangled.download(item, dest)
    local http = require("http")
    local log = require("log")
    local uploader = item.uri:match("^at://([^/]+)/")
    if not uploader then
        error("could not read uploader DID from " .. tostring(item.uri))
    end
    local cid = item.value.artifact.ref["$link"]
    local pds = Tangled.resolve_pds(uploader)
    local url = pds .. "/xrpc/com.atproto.sync.getBlob?did=" .. uploader .. "&cid=" .. cid
    log.info("tangled: downloading " .. item.value.name .. " from " .. pds)
    local err = http.download_file({ url = url }, dest)
    if err then
        error("failed to download " .. item.value.name .. ": " .. tostring(err))
    end
    Tangled.verify(dest, cid)
end

--- Lays the artifact out as install_path/bin/<binary>, extracting archives.
function Tangled.place(downloaded, artifact_name, install_path, tool, options)
    local cmd = require("cmd")
    local file = require("file")
    local strings = require("strings")
    local bin_dir = file.join_path(install_path, "bin")
    cmd.exec("mkdir -p " .. shell_quote(bin_dir))

    if not ends_with_any(artifact_name, ARCHIVE_SUFFIXES) then
        local _, repo = Tangled.parse(tool)
        local target = file.join_path(bin_dir, opt(options, "bin", repo))
        cmd.exec("mv " .. shell_quote(downloaded) .. " " .. shell_quote(target))
        cmd.exec("chmod +x " .. shell_quote(target))
        return
    end

    local archiver = require("archiver")
    local extract_dir = file.join_path(install_path, ".extract")
    archiver.decompress(downloaded, extract_dir)
    cmd.exec("rm -f " .. shell_quote(downloaded))

    -- Archives usually wrap everything in a single top-level directory: unwrap it.
    -- ponytail: breaks if that directory name has spaces, switch to file.list if it ever happens
    local root = strings.trim_space(tostring(cmd.exec(
        "cd "
            .. shell_quote(extract_dir)
            .. ' && if [ "$(ls -1A | wc -l)" -eq 1 ] && [ -d "$(ls -1A)" ];'
            .. ' then printf %s "$PWD/$(ls -1A)"; else printf %s "$PWD"; fi'
    )))

    -- A release that already ships bin/ keeps its layout, a bare binary goes to bin/.
    local dest = install_path
    if not file.exists(file.join_path(root, "bin")) then
        dest = bin_dir
    end
    cmd.exec("cp -R " .. shell_quote(root) .. "/. " .. shell_quote(dest) .. "/")
    cmd.exec("rm -rf " .. shell_quote(extract_dir))
    cmd.exec("chmod -R +x " .. shell_quote(bin_dir))
end
