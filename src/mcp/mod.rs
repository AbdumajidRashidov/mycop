pub mod convert;
pub mod tools;
pub mod types;

use rmcp::{
    handler::server::ServerHandler,
    model::*,
    service::{RequestContext, RoleServer},
    Error as McpError, ServiceExt,
};

use crate::config::ScanConfig;
use crate::rules::RuleRegistry;

use self::convert::rule_to_output;

use rmcp::model::AnnotateAble;
use std::future::Future;

#[derive(Clone)]
pub struct MycopMcpServer;

impl ServerHandler for MycopMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
            server_info: Implementation {
                name: "mycop".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            instructions: Some(
                "mycop is an AI code security scanner with 100 built-in rules \
                 covering OWASP Top 10 and CWE Top 25. Use 'scan' to check files \
                 for vulnerabilities, 'list_rules' to browse security rules, \
                 'explain_finding' for detailed vulnerability info, 'review' for \
                 deep AI security analysis, and 'check_deps' to detect hallucinated \
                 packages. To fix vulnerabilities, read the scan findings and apply \
                 the fixes yourself using the fix_hint provided in each finding."
                    .to_string(),
            ),
        }
    }

    fn list_tools(
        &self,
        _request: PaginatedRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, McpError>> + Send + '_ {
        std::future::ready(Ok(ListToolsResult {
            tools: tools::tool_box().list(),
            next_cursor: None,
        }))
    }

    #[allow(clippy::manual_async_fn)]
    fn call_tool(
        &self,
        request: CallToolRequestParam,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CallToolResult, McpError>> + Send + '_ {
        async move {
            let tcc = rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
            tools::tool_box().call(tcc).await
        }
    }

    fn list_resources(
        &self,
        _request: PaginatedRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListResourcesResult, McpError>> + Send + '_ {
        std::future::ready(Ok(ListResourcesResult {
            resources: vec![
                RawResource {
                    uri: "mycop://rules/catalog".to_string(),
                    name: "Security Rules Catalog".to_string(),
                    description: Some(
                        "Complete catalog of all built-in security rules as JSON".to_string(),
                    ),
                    mime_type: Some("application/json".to_string()),
                    size: None,
                }
                .no_annotation(),
                RawResource {
                    uri: "mycop://config/schema".to_string(),
                    name: "Configuration Schema".to_string(),
                    description: Some("Default .scanrc.yml configuration template".to_string()),
                    mime_type: Some("text/yaml".to_string()),
                    size: None,
                }
                .no_annotation(),
            ],
            next_cursor: None,
        }))
    }

    fn read_resource(
        &self,
        request: ReadResourceRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ReadResourceResult, McpError>> + Send + '_ {
        std::future::ready(read_resource_sync(&request.uri))
    }
}

fn read_resource_sync(uri: &str) -> Result<ReadResourceResult, McpError> {
    match uri {
        "mycop://rules/catalog" => {
            let registry = RuleRegistry::load_default().map_err(|e| {
                McpError::internal_error(format!("Failed to load rules: {}", e), None)
            })?;
            let rules: Vec<_> = registry
                .all_rules()
                .iter()
                .map(|r| rule_to_output(r))
                .collect();
            let json = serde_json::to_string_pretty(&rules).map_err(|e| {
                McpError::internal_error(format!("Serialization error: {}", e), None)
            })?;

            Ok(ReadResourceResult {
                contents: vec![ResourceContents::text(json, uri)],
            })
        }
        "mycop://config/schema" => {
            let content = ScanConfig::default_content();
            Ok(ReadResourceResult {
                contents: vec![ResourceContents::text(content, uri)],
            })
        }
        _ => Err(McpError::invalid_params(
            format!("Unknown resource: {}", uri),
            None,
        )),
    }
}

impl MycopMcpServer {
    pub async fn run() -> anyhow::Result<()> {
        eprintln!("mycop MCP server starting...");

        let server = Self;
        let transport = rmcp::transport::io::stdio();
        let service = server.serve(transport).await?;

        eprintln!(
            "mycop MCP server v{} running on stdio",
            env!("CARGO_PKG_VERSION")
        );

        service.waiting().await?;
        Ok(())
    }
}
