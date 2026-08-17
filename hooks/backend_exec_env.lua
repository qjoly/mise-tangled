--- Exposes the installed binaries.
--- @param ctx {tool: string, version: string, install_path: string, options: table}
--- @return {env_vars: table[]}
function PLUGIN:BackendExecEnv(ctx)
    local file = require("file")
    return {
        env_vars = {
            { key = "PATH", value = file.join_path(ctx.install_path, "bin") },
        },
    }
end
