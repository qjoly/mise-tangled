PLUGIN = { -- luacheck: ignore
    name = "tangled",
    version = "0.0.2",
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
    -- No bare `x86`: it is a prefix of `x86_64` and would claim 64 bit artifacts.
    ["386"] = { "386", "i386" },
    arm = { "armv7", "armhf", "arm" },
}

local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local B32 = "abcdefghijklmnopqrstuvwxyz234567"

--- JSON nulls come back as userdata, which is truthy: `v or {}` would not filter them.
local function as_string(v)
    if type(v) == "string" and v ~= "" then
        return v
    end
    return nil
end

local function as_table(v)
    if type(v) == "table" then
        return v
    end
    return {}
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
    if resp.status_code == 429 then
        error("GET " .. url .. " is rate limited (HTTP 429), retry in a moment")
    end
    if resp.status_code ~= 200 then
        -- An appview error page can be kilobytes of HTML: keep the terminal readable.
        error("GET " .. url .. " returned HTTP " .. resp.status_code .. ": " .. tostring(resp.body):sub(1, 200))
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

--- Plain substring matching would make `arm` match `arm64`, so a match only counts between
--- separators. `-`, `_` and `.` separate, a digit or letter does not.
local function has_token(haystack, token)
    local from = 1
    while true do
        local s, e = haystack:find(token, from, true)
        if not s then
            return false
        end
        local before = s > 1 and haystack:sub(s - 1, s - 1) or ""
        local after = haystack:sub(e + 1, e + 1)
        if not before:match("%w") and not after:match("%w") then
            return true
        end
        from = s + 1
    end
end

local function contains_any(haystack, needles)
    for _, n in ipairs(needles) do
        if has_token(haystack, n) then
            return true
        end
    end
    return false
end

local function shell_quote(s)
    return "'" .. s:gsub("'", "'\\''") .. "'"
end

Tangled.quote = shell_quote

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
    -- cidv1 | codec 0x55 (raw) | multihash code 0x12 (sha2-256) | length 0x20
    if bytes[1] ~= 0x01 or bytes[2] ~= 0x55 or bytes[3] ~= 0x12 or bytes[4] ~= 0x20 then
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
    for _, service in ipairs(as_table(doc.service)) do
        local endpoint = as_string(as_table(service).serviceEndpoint)
        if endpoint and (service.id == "#atproto_pds" or service.id == did .. "#atproto_pds") then
            if endpoint:sub(1, 8) ~= "https://" then
                error("PDS of " .. did .. " is not https: " .. endpoint)
            end
            return endpoint
        end
    end
    error("no #atproto_pds service in DID document of " .. did)
end

--- Pages through an appview list endpoint. Says so instead of truncating in silence.
local function list_all(url_base)
    local items, cursor = {}, nil
    for _ = 1, MAX_PAGES do
        local url = url_base
        if cursor then
            url = url .. "&cursor=" .. cursor
        end
        local page = get_json(url)
        for _, item in ipairs(as_table(page.items)) do
            items[#items + 1] = item
        end
        local next_cursor = as_string(page.cursor)
        if not next_cursor or next_cursor == cursor then
            return items
        end
        cursor = next_cursor
    end
    require("log").warn("tangled: stopped paging after " .. #items .. " records, some may be missing")
    return items
end

--- The record key of a repo is not its name: `Notary` lives under the key `notary`, and a
--- forked repo under a TID. So the repo is looked up by name or by key, exact match first.
function Tangled.match_repo(items, repo)
    local wanted = repo:lower()
    local fuzzy
    for _, item in ipairs(items) do
        local value = as_table(item.value)
        local rkey = tostring(item.uri or ""):match("([^/]+)$") or ""
        local name = as_string(value.name) or ""
        if name == repo or rkey == repo then
            return value
        end
        if not fuzzy and (name:lower() == wanted or rkey:lower() == wanted) then
            fuzzy = value
        end
    end
    return fuzzy
end

--- Repo record from the appview: gives us repoDid (artifact subject) and knot.
function Tangled.get_repo(tool, options)
    local owner, repo = Tangled.parse(tool)
    local did = Tangled.resolve_did(owner, options)
    local appview = opt(options, "appview", DEFAULT_APPVIEW)
    local url = appview .. "/xrpc/sh.tangled.repo.listRepos?limit=100&subject=" .. did
    local value = Tangled.match_repo(list_all(url), repo)
    if not value then
        error("no repo named " .. repo .. " under " .. did)
    end
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

--- DIDs whose artifacts are trusted: the owner, the repo itself and its collaborators.
function Tangled.allowed_uploaders(repo, options)
    local allowed = { [repo.did] = true, [repo.repo_did] = true }
    local appview = opt(options, "appview", DEFAULT_APPVIEW)
    local url = appview .. "/xrpc/sh.tangled.repo.listCollaborators?limit=100&subject=" .. repo.repo_did
    for _, item in ipairs(list_all(url)) do
        local subject = as_string(as_table(item.value).subject)
        if subject then
            allowed[subject] = true
        end
    end
    for did in tostring(opt(options, "allowed_uploaders", "")):gmatch("[^,%s]+") do
        allowed[did] = true
    end
    return allowed
end

--- Anyone can attach a record to anyone's tag, so artifacts from unknown DIDs are dropped.
function Tangled.filter_uploaders(items, allowed)
    local log = require("log")
    local kept = {}
    for _, item in ipairs(items) do
        local uploader = tostring(item.uri or ""):match("^at://([^/]+)/")
        if uploader and allowed[uploader] then
            kept[#kept + 1] = item
        else
            log.debug("tangled: ignoring artifact published by " .. tostring(uploader))
        end
    end
    return kept
end

--- Every artifact of the repo, aggregated by the appview across uploader PDSes.
function Tangled.artifacts(repo, options)
    local appview = opt(options, "appview", DEFAULT_APPVIEW)
    local url = appview .. "/xrpc/sh.tangled.repo.listArtifacts?limit=100&subject=" .. repo.repo_did
    return Tangled.filter_uploaders(list_all(url), Tangled.allowed_uploaders(repo, options))
end

--- Hex tag-object hashes carrying an artifact, as a lookup set.
function Tangled.tagged_hashes(items)
    local hashes = {}
    for _, item in ipairs(items) do
        -- One malformed record must not take down the whole version listing.
        local raw = as_string(as_table(as_table(item.value).tag)["$bytes"])
        local ok, hex = pcall(Tangled.bytes_to_hex, raw or "")
        if raw and ok then
            hashes[hex] = true
        end
    end
    return hashes
end

--- mise strips one brace pair when templating mise.toml, so both forms are accepted.
--- The replacement goes through a function: a `%` in a tag name is not a capture reference.
local function fill(template, key, value)
    return (template:gsub("{{?%s*" .. key .. "%s*}}?", function()
        return value
    end))
end

function Tangled.render(template, version)
    local out = fill(template, "version", version)
    out = fill(out, "os", RUNTIME.osType)
    return fill(out, "arch", RUNTIME.archType)
end

--- An artifact name ends up in a filesystem path, so only a bare file name is accepted.
local function safe_name(name)
    if type(name) ~= "string" or name == "" or name:find("[/\\]") or name:sub(1, 1) == "." then
        error("refusing artifact with unsafe name " .. tostring(name))
    end
    return name
end

--- Picks the artifact to install: explicit `asset` option, else os/arch matching.
function Tangled.pick(items, tag_hash, version, options)
    local candidates = {}
    for _, item in ipairs(items) do
        local value = as_table(item.value)
        local raw = as_string(as_table(value.tag)["$bytes"])
        if raw and Tangled.bytes_to_hex(raw) == tag_hash then
            safe_name(value.name)
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
        if
            not ends_with_any(name, IGNORED_SUFFIXES)
            and contains_any(name, os_names)
            and contains_any(name, arch_names)
        then
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
    -- table.sort is not stable, so a tie would install whatever the appview listed first.
    if #matches > 1 and #matches[1].value.name == #matches[2].value.name then
        error(
            "several artifacts match "
                .. RUNTIME.osType
                .. "/"
                .. RUNTIME.archType
                .. ": "
                .. matches[1].value.name
                .. ", "
                .. matches[2].value.name
                .. " (use the `asset` option to pick one)"
        )
    end
    return matches[1]
end

--- Every failure here is fatal: skipping the check would install unverified bytes.
function Tangled.verify(path, cid)
    local expected = Tangled.cid_sha256(cid)
    if not expected then
        error("unsupported CID shape " .. cid .. ", refusing to install unverified bytes")
    end
    local cmd = require("cmd")
    local quoted = shell_quote(path)
    local ok, out = pcall(cmd.exec, "sha256sum " .. quoted .. " 2>/dev/null || shasum -a 256 " .. quoted)
    if not ok then
        error("no sha256 tool available (sha256sum or shasum), cannot verify " .. path)
    end
    local got = tostring(out):match("%x%x%x%x%x%x%x%x+")
    if not got then
        error("could not read sha256 output for " .. path)
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
    local cid = as_string(as_table(as_table(as_table(item.value).artifact).ref)["$link"])
    if not cid then
        error("artifact " .. tostring(item.uri) .. " carries no blob reference")
    end
    local pds = Tangled.resolve_pds(uploader)
    local url = pds .. "/xrpc/com.atproto.sync.getBlob?did=" .. uploader .. "&cid=" .. cid
    log.info("tangled: downloading " .. item.value.name .. " from " .. pds)
    local err = http.download_file({ url = url }, dest)
    if err then
        error("failed to download " .. item.value.name .. ": " .. tostring(err))
    end
    Tangled.verify(dest, cid)
end

--- The install path shells out to POSIX tools, and a .exe would need renaming anyway.
function Tangled.assert_supported_os()
    if RUNTIME.osType == "windows" then
        error("tangled: windows is not supported yet (the install path needs POSIX tools)")
    end
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
    -- ponytail: a newline in that directory name breaks the count, switch to file.list if it happens
    local root = strings.trim_space(
        tostring(
            cmd.exec(
                "cd "
                    .. shell_quote(extract_dir)
                    .. ' && if [ "$(ls -1A | wc -l)" -eq 1 ] && [ -d "$(ls -1A)" ];'
                    .. ' then printf %s "$PWD/$(ls -1A)"; else printf %s "$PWD"; fi'
            )
        )
    )

    -- A release that already ships bin/ keeps its layout, a bare binary goes to bin/.
    local dest = install_path
    if not file.exists(file.join_path(root, "bin")) then
        dest = bin_dir
    end
    cmd.exec("cp -R " .. shell_quote(root) .. "/. " .. shell_quote(dest) .. "/")
    cmd.exec("rm -rf " .. shell_quote(extract_dir))
    -- Only the binaries directly in bin/, not the licences and libraries an archive may ship.
    cmd.exec("find " .. shell_quote(bin_dir) .. " -maxdepth 1 -type f -exec chmod +x {} +")
end
