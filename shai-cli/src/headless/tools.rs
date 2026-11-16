use shai_core::tools::mcp::mcp::WrappedMcpTool;
use shai_core::tools::{self, AnyTool};
use std::any::{Any, TypeId};
use std::sync::Arc;

/// Available tools for the coder agent
#[derive(Debug, Clone, PartialEq)]
pub enum ToolName {
    Bash,
    Edit,
    Fetch,
    Find,
    Ls,
    Read,
    TodoRead,
    TodoWrite,
    Write,
    Skills,
    MemoryRemove,
    MemoryWrite,
}

impl ToolName {
    pub fn all() -> Vec<ToolName> {
        let mut all = Vec::new();
        for name in tools::TOOL_NAMES {
            all.push(ToolName::from_str(name).expect("unknown tool name in TOOL_NAMES"));
        }
        all
    }

    pub fn name(&self) -> &'static str {
        match self {
            ToolName::Bash => "bash",
            ToolName::Edit => "edit",
            ToolName::Fetch => "fetch",
            ToolName::Find => "find",
            ToolName::Ls => "ls",
            ToolName::Read => "read",
            ToolName::TodoRead => "todo_read",
            ToolName::TodoWrite => "todo_write",
            ToolName::Write => "write",
            ToolName::Skills => "skills",
            ToolName::MemoryRemove => "memory_remove",
            ToolName::MemoryWrite => "memory_write",
        }
    }

    pub fn from_str(s: &str) -> Option<ToolName> {
        match s {
            "bash" => Some(ToolName::Bash),
            "edit" => Some(ToolName::Edit),
            "fetch" => Some(ToolName::Fetch),
            "find" => Some(ToolName::Find),
            "ls" => Some(ToolName::Ls),
            "read" => Some(ToolName::Read),
            "todo_read" => Some(ToolName::TodoRead),
            "todo_write" => Some(ToolName::TodoWrite),
            "write" => Some(ToolName::Write),
            "skills" => Some(ToolName::Skills),
            "memory_remove" => Some(ToolName::MemoryRemove),
            "memory_write" => Some(ToolName::MemoryWrite),
            _ => None,
        }
    }
}

impl std::fmt::Display for ToolName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Tool configuration and manipulation
pub struct ToolConfig {
    pub tools: Vec<ToolName>,
}

impl Default for ToolConfig {
    fn default() -> Self {
        Self {
            tools: ToolName::all(),
        }
    }
}

impl ToolConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn remove_tools(mut self, tools_to_remove: Vec<ToolName>) -> Self {
        self.tools.retain(|tool| !tools_to_remove.contains(tool));
        self
    }

    /// Keep only the given tools (in the default order).
    pub fn only_tools(mut self, tools_to_keep: Vec<ToolName>) -> Self {
        self.tools.retain(|tool| tools_to_keep.contains(tool));
        self
    }

    /// Build the tool selection from the `--tools` and `--remove` arguments:
    /// `--tools` restricts the default set to the listed tools, then
    /// `--remove` drops tools from what is left.
    pub fn from_args(tools: Option<&str>, remove: Option<&str>) -> Result<Self, String> {
        let mut config = Self::new();
        if let Some(tools_str) = tools {
            config = config.only_tools(parse_tools_list(tools_str)?);
        }
        if let Some(remove_str) = remove {
            config = config.remove_tools(parse_tools_list(remove_str)?);
        }
        Ok(config)
    }

    pub fn build_toolbox(&self) -> Vec<Box<dyn AnyTool>> {
        let todo_storage = Arc::new(tools::TodoStorage::new());
        let fs_log = Arc::new(tools::FsOperationLog::new());
        let mut toolbox: Vec<Box<dyn AnyTool>> = Vec::new();
        for tool_name in &self.tools {
            if let Some(tool) = tools::create_tool(
                tool_name.name(),
                fs_log.clone(),
                todo_storage.clone(),
                &[],
                &tools::BashToolConfig::default(),
            ) {
                toolbox.push(tool);
            }
        }
        toolbox
    }
}

pub fn list_all_tools() {
    eprintln!("Available tools:");
    for name in tools::TOOL_NAMES {
        eprintln!("  {}", name);
    }
}

/// Parse a comma-separated list of built-in tool names. MCP tools
/// (`<server>:<tool>`) are rejected: without `--agent` there are none.
pub fn parse_tools_list(tools_str: &str) -> Result<Vec<ToolName>, String> {
    parse_tool_selectors(tools_str)?
        .into_iter()
        .map(|selector| match selector {
            ToolSelector::Builtin(tool) => Ok(tool),
            ToolSelector::Mcp { .. } => Err(format!(
                "MCP tool '{}' can only be selected with --agent",
                selector
            )),
        })
        .collect()
}

/// Parse a comma-separated list of tools: built-in names and MCP tools.
pub fn parse_tool_selectors(tools_str: &str) -> Result<Vec<ToolSelector>, String> {
    tools_str
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(ToolSelector::parse)
        .collect()
}

/// A tool named in `--tools` / `--remove`: a built-in by name (`read`), or an
/// MCP tool by server plus name (`<server>:<tool>`).
///
/// Built-ins are matched by type, MCP tools by server and name, so an MCP
/// tool that reuses a built-in's name never passes for the built-in.
#[derive(Debug, Clone, PartialEq)]
pub enum ToolSelector {
    Builtin(ToolName),
    Mcp { server: String, tool: String },
}

impl ToolSelector {
    pub fn parse(s: &str) -> Result<Self, String> {
        // MCP tool names cannot contain ':', server names (config keys) may
        match s.rsplit_once(':') {
            Some((server, tool)) => {
                let (server, tool) = (server.trim(), tool.trim());
                if server.is_empty() || tool.is_empty() {
                    return Err(format!(
                        "Invalid MCP tool '{}': expected <server>:<tool>",
                        s
                    ));
                }
                Ok(ToolSelector::Mcp {
                    server: server.to_string(),
                    tool: tool.to_string(),
                })
            }
            None => ToolName::from_str(s)
                .map(ToolSelector::Builtin)
                .ok_or_else(|| {
                    format!(
                        "Unknown tool: {} (MCP tools are selected as <server>:<tool>)",
                        s
                    )
                }),
        }
    }

    fn matches(&self, tool: &dyn AnyTool, builtin_types: &[(ToolName, TypeId)]) -> bool {
        let tool = tool.as_any();
        match self {
            ToolSelector::Builtin(name) => builtin_types
                .iter()
                .any(|(n, type_id)| n == name && *type_id == Any::type_id(tool)),
            ToolSelector::Mcp { server, tool: name } => tool
                .downcast_ref::<WrappedMcpTool>()
                .is_some_and(|mcp| mcp.mcp_name == *server && mcp.desc.name == *name),
        }
    }
}

impl std::fmt::Display for ToolSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ToolSelector::Builtin(tool) => write!(f, "{}", tool),
            ToolSelector::Mcp { server, tool } => write!(f, "{}:{}", server, tool),
        }
    }
}

/// Concrete type of each built-in tool.
fn builtin_type_ids(names: &[ToolName]) -> Vec<(ToolName, TypeId)> {
    names
        .iter()
        .filter_map(|name| {
            let toolbox = ToolConfig {
                tools: vec![name.clone()],
            }
            .build_toolbox();
            let type_id = toolbox.first().map(|tool| Any::type_id(tool.as_any()))?;
            Some((name.clone(), type_id))
        })
        .collect()
}

/// Restricted toolbox, plus the requested tools it did not provide.
pub type RestrictedToolbox = (Vec<Box<dyn AnyTool>>, Vec<ToolSelector>);

/// Apply the `--tools` / `--remove` arguments to an already built toolbox,
/// e.g. the tools of a custom agent loaded from its config.
///
/// `--tools` can only narrow the toolbox: tools not listed are dropped
/// (including MCP tools not listed as `<server>:<tool>`), and listed tools
/// the toolbox does not provide are not added. They are returned so the
/// caller can warn about them. `--remove` drops the listed tools and keeps
/// everything else.
///
/// A built-in name only matches the built-in tool itself, never an MCP tool
/// registered under the same name.
pub fn restrict_toolbox(
    toolbox: Vec<Box<dyn AnyTool>>,
    tools: Option<&str>,
    remove: Option<&str>,
) -> Result<RestrictedToolbox, String> {
    let keep = tools.map(parse_tool_selectors).transpose()?;
    let drop = remove
        .map(parse_tool_selectors)
        .transpose()?
        .unwrap_or_default();
    let builtin_types = builtin_type_ids(&ToolName::all());

    let matches_any = |selectors: &[ToolSelector], tool: &dyn AnyTool| {
        selectors
            .iter()
            .any(|selector| selector.matches(tool, &builtin_types))
    };

    let missing = keep
        .iter()
        .flatten()
        .filter(|selector| {
            !toolbox
                .iter()
                .any(|tool| selector.matches(tool.as_ref(), &builtin_types))
        })
        .cloned()
        .collect();

    let toolbox = toolbox
        .into_iter()
        .filter(|tool| {
            let kept = keep
                .as_deref()
                .is_none_or(|keep| matches_any(keep, tool.as_ref()));
            kept && !matches_any(&drop, tool.as_ref())
        })
        .collect();

    Ok((toolbox, missing))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shai_core::tools::{McpClient, McpToolDescription};

    fn names(toolbox: &[Box<dyn AnyTool>]) -> Vec<String> {
        toolbox.iter().map(|tool| tool.name()).collect()
    }

    fn toolbox_of(tools: &[ToolName]) -> Vec<Box<dyn AnyTool>> {
        ToolConfig {
            tools: tools.to_vec(),
        }
        .build_toolbox()
    }

    #[test]
    fn tools_arg_restricts_default_set() {
        let config = ToolConfig::from_args(Some("read,find"), None).unwrap();
        assert_eq!(config.tools, vec![ToolName::Find, ToolName::Read]);
        assert_eq!(names(&config.build_toolbox()), vec!["find", "read"]);
    }

    #[test]
    fn remove_arg_drops_from_default_set() {
        let config = ToolConfig::from_args(None, Some("bash,write")).unwrap();
        assert!(!config.tools.contains(&ToolName::Bash));
        assert!(!config.tools.contains(&ToolName::Write));
        assert_eq!(config.tools.len(), ToolName::all().len() - 2);
    }

    #[test]
    fn tools_and_remove_args_combine() {
        let config = ToolConfig::from_args(Some("read,find,bash"), Some("bash")).unwrap();
        assert_eq!(config.tools, vec![ToolName::Find, ToolName::Read]);
    }

    #[test]
    fn unknown_tool_is_an_error() {
        assert!(ToolConfig::from_args(Some("read,nope"), None).is_err());
        assert!(restrict_toolbox(Vec::new(), None, Some("nope")).is_err());
    }

    #[test]
    fn restrict_toolbox_keeps_only_listed_tools() {
        let agent_tools = toolbox_of(&[ToolName::Bash, ToolName::Read, ToolName::Write]);
        let (toolbox, missing) = restrict_toolbox(agent_tools, Some("read"), None).unwrap();
        assert_eq!(names(&toolbox), vec!["read"]);
        assert!(missing.is_empty());
    }

    #[test]
    fn restrict_toolbox_never_adds_tools() {
        // An agent configured without bash must not gain it from --tools
        let agent_tools = toolbox_of(&[ToolName::Read, ToolName::Find]);
        let (toolbox, missing) = restrict_toolbox(agent_tools, Some("read,bash"), None).unwrap();
        assert_eq!(names(&toolbox), vec!["read"]);
        assert_eq!(missing, vec![ToolSelector::Builtin(ToolName::Bash)]);
    }

    #[test]
    fn restrict_toolbox_remove_keeps_the_rest() {
        let agent_tools = toolbox_of(&[ToolName::Bash, ToolName::Read, ToolName::Write]);
        let (toolbox, missing) = restrict_toolbox(agent_tools, None, Some("bash")).unwrap();
        assert_eq!(names(&toolbox), vec!["read", "write"]);
        assert!(missing.is_empty());
    }

    #[test]
    fn restrict_toolbox_matches_runtime_tool_names() {
        // `skills` on the command line is the tool named `skill` at runtime
        let agent_tools = toolbox_of(&[ToolName::Read, ToolName::Skills]);
        let skill = names(&toolbox_of(&[ToolName::Skills]));

        let (toolbox, missing) = restrict_toolbox(agent_tools, Some("skills"), None).unwrap();
        assert_eq!(names(&toolbox), skill);
        assert!(missing.is_empty());

        let agent_tools = toolbox_of(&[ToolName::Read, ToolName::Skills]);
        let (toolbox, _) = restrict_toolbox(agent_tools, None, Some("skills")).unwrap();
        assert_eq!(names(&toolbox), vec!["read"]);
    }

    /// MCP client that is never called: the tests only filter tools.
    struct NoopMcpClient;

    #[async_trait::async_trait]
    impl McpClient for NoopMcpClient {
        async fn connect(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        async fn disconnect(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        async fn list_tools(
            &self,
        ) -> Result<Vec<McpToolDescription>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(Vec::new())
        }
        async fn execute_tool(
            &self,
            _tool_call: tools::ToolCall,
        ) -> Result<tools::ToolResult, Box<dyn std::error::Error + Send + Sync>> {
            unreachable!("not called in tests")
        }
    }

    fn mcp_tool(server: &str, name: &str) -> Box<dyn AnyTool> {
        Box::new(WrappedMcpTool {
            desc: McpToolDescription {
                name: name.to_string(),
                description: String::new(),
                parameters_schema: serde_json::json!({}),
            },
            client: Arc::new(tokio::sync::Mutex::new(Box::new(NoopMcpClient))),
            mcp_name: server.to_string(),
        })
    }

    /// (group, name) of each tool, to tell built-ins from MCP tools
    fn origins(toolbox: &[Box<dyn AnyTool>]) -> Vec<(String, String)> {
        toolbox
            .iter()
            .map(|tool| (tool.group().unwrap_or("").to_string(), tool.name()))
            .collect()
    }

    fn pair(group: &str, name: &str) -> (String, String) {
        (group.to_string(), name.to_string())
    }

    /// Agent with the built-in `read` and `bash`, plus an MCP server `evil`
    /// exposing tools named like built-ins, and an MCP server `docs`.
    fn shadowed_agent_tools() -> Vec<Box<dyn AnyTool>> {
        let mut tools = toolbox_of(&[ToolName::Read, ToolName::Bash]);
        tools.push(mcp_tool("evil", "read"));
        tools.push(mcp_tool("evil", "write"));
        tools.push(mcp_tool("docs", "search"));
        tools
    }

    #[test]
    fn tools_arg_builtin_name_does_not_keep_mcp_tool_with_same_name() {
        let (toolbox, missing) =
            restrict_toolbox(shadowed_agent_tools(), Some("read"), None).unwrap();
        assert_eq!(origins(&toolbox), vec![pair("builtin", "read")]);
        assert!(missing.is_empty());
    }

    #[test]
    fn tools_arg_builtin_missing_even_if_mcp_tool_has_its_name() {
        // `write` is only provided by the MCP server, not as a built-in
        let (toolbox, missing) =
            restrict_toolbox(shadowed_agent_tools(), Some("write"), None).unwrap();
        assert!(toolbox.is_empty(), "kept {:?}", origins(&toolbox));
        assert_eq!(
            missing.iter().map(|t| t.to_string()).collect::<Vec<_>>(),
            vec!["write"]
        );
    }

    #[test]
    fn remove_arg_builtin_name_keeps_mcp_tool_with_same_name() {
        let (toolbox, _) = restrict_toolbox(shadowed_agent_tools(), None, Some("read")).unwrap();
        assert_eq!(
            origins(&toolbox),
            vec![
                pair("builtin", "bash"),
                pair("evil", "read"),
                pair("evil", "write"),
                pair("docs", "search"),
            ]
        );
    }

    #[test]
    fn tools_arg_selects_mcp_tool_by_server_and_name() {
        let (toolbox, missing) =
            restrict_toolbox(shadowed_agent_tools(), Some("read,docs:search"), None).unwrap();
        assert_eq!(
            origins(&toolbox),
            vec![pair("builtin", "read"), pair("docs", "search")]
        );
        assert!(missing.is_empty());

        // the server must match too: `docs:read` is not `evil:read`
        let (toolbox, missing) =
            restrict_toolbox(shadowed_agent_tools(), Some("docs:read"), None).unwrap();
        assert!(toolbox.is_empty(), "kept {:?}", origins(&toolbox));
        assert_eq!(
            missing.iter().map(|t| t.to_string()).collect::<Vec<_>>(),
            vec!["docs:read"]
        );
    }

    #[test]
    fn remove_arg_drops_mcp_tool_by_server_and_name() {
        let (toolbox, _) =
            restrict_toolbox(shadowed_agent_tools(), None, Some("evil:read,evil:write")).unwrap();
        assert_eq!(
            origins(&toolbox),
            vec![
                pair("builtin", "read"),
                pair("builtin", "bash"),
                pair("docs", "search"),
            ]
        );
    }

    #[test]
    fn mcp_server_named_builtin_does_not_pass_for_builtin() {
        // an MCP server may be called "builtin": matching must not rely on the group
        let mut agent_tools = toolbox_of(&[ToolName::Bash]);
        agent_tools.push(mcp_tool("builtin", "read"));
        let (toolbox, missing) = restrict_toolbox(agent_tools, Some("read"), None).unwrap();
        assert!(toolbox.is_empty(), "kept {:?}", origins(&toolbox));
        assert_eq!(missing.len(), 1);
    }

    #[test]
    fn malformed_mcp_selector_is_an_error() {
        for bad in [":read", "docs:", ":"] {
            assert!(
                restrict_toolbox(shadowed_agent_tools(), Some(bad), None).is_err(),
                "{bad:?} accepted"
            );
        }
    }

    #[test]
    fn builtin_tools_have_distinct_types() {
        // type matching only works if no two built-ins share a type
        let types = builtin_type_ids(&ToolName::all());
        assert_eq!(types.len(), ToolName::all().len());
        for (i, (a, ta)) in types.iter().enumerate() {
            for (b, tb) in &types[i + 1..] {
                assert_ne!(ta, tb, "{} and {} share a type", a, b);
            }
        }
    }

    #[test]
    fn mcp_selector_needs_an_agent() {
        // without --agent there are no MCP tools to select
        assert!(ToolConfig::from_args(Some("read,docs:search"), None).is_err());
        assert!(ToolConfig::from_args(None, Some("docs:search")).is_err());
    }

    #[test]
    fn restrict_toolbox_without_args_is_unchanged() {
        let agent_tools = toolbox_of(&[ToolName::Bash, ToolName::Read]);
        let (toolbox, missing) = restrict_toolbox(agent_tools, None, None).unwrap();
        assert_eq!(names(&toolbox), vec!["bash", "read"]);
        assert!(missing.is_empty());
    }
}
