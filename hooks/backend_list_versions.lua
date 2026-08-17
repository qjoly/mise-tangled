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
    local versions = {}
    for _, tag in ipairs(tags) do
        if tagged[tag.hash] then
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
    table.sort(versions)
    return { versions = versions }
end
