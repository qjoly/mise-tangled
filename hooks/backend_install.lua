--- Downloads the artifact attached to a tag and installs it.
--- @param ctx {tool: string, version: string, install_path: string, download_path: string, options: table}
--- @return table
function PLUGIN:BackendInstall(ctx)
    local tool = ctx.tool
    local version = ctx.version
    local install_path = ctx.install_path
    local options = ctx.options or {}

    if not tool or tool == "" then
        error("tool name cannot be empty")
    end
    if not version or version == "" then
        error("version cannot be empty")
    end
    if not install_path or install_path == "" then
        error("install path cannot be empty")
    end

    local tag_hash
    for _, tag in ipairs(Tangled.tags(tool, options)) do
        if tag.version == version or tag.name == version then
            tag_hash = tag.hash
            break
        end
    end
    if not tag_hash then
        error("no tag of " .. tool .. " matches version " .. version)
    end

    local repo = Tangled.get_repo(tool, options)
    local item = Tangled.pick(Tangled.artifacts(repo, options), tag_hash, version, options)

    local cmd = require("cmd")
    local file = require("file")
    local download_dir = ctx.download_path or install_path
    cmd.exec("mkdir -p " .. Tangled.quote(download_dir))
    local downloaded = file.join_path(download_dir, item.value.name)

    Tangled.download(item, downloaded)
    Tangled.place(downloaded, item.value.name, install_path, tool, options)

    return {}
end
