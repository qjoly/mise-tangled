--- Lists the installable versions of a tangled repo.
--- @param ctx {tool: string, options: table} tool = "<handle-or-did>/<repo>"
--- @return {versions: string[]} ascending list of versions
function PLUGIN:BackendListVersions(ctx)
    local tool = ctx.tool
    local options = ctx.options or {}
    if not tool or tool == "" then
        error("tool name cannot be empty")
    end

    local tags = Tangled.tags(tool, options)
    local repo = Tangled.get_repo(tool, options)
    local tagged = Tangled.tagged_hashes(Tangled.artifacts(repo, options))

    -- A tag with no artifact is not installable, so it is not a version.
    -- `v1.0` and `1.0` collapse to the same version, hence the dedup.
    local versions, seen = {}, {}
    for _, tag in ipairs(tags) do
        if tagged[tag.hash] and not seen[tag.version] then
            seen[tag.version] = true
            versions[#versions + 1] = tag.version
        end
    end

    if #versions == 0 then
        error("no tag of " .. tool .. " has an artifact attached")
    end

    local semver = require("semver")
    local ok, sorted = pcall(semver.sort, versions)
    if ok then
        return { versions = sorted }
    end
    -- Lexicographic order puts 1.10.0 before 1.9.0, so say it rather than pretend.
    require("log").warn("tangled: tags of " .. tool .. " are not semver, falling back to alphabetical order")
    table.sort(versions)
    return { versions = versions }
end
