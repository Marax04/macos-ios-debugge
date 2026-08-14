use std::env;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut bind: Option<String> = None;
    let mut stdio = false;
    for arg in env::args().skip(1) {
        if arg == "--transport=stdio" || arg == "--stdio" {
            stdio = true;
        } else if let Some(rest) = arg.strip_prefix("--transport=sse") {
            let addr = rest.strip_prefix(':').unwrap_or("127.0.0.1:8080");
            bind = Some(addr.to_owned());
        } else if let Some(addr) = arg.strip_prefix("--bind=") {
            bind = Some(addr.to_owned());
        }
    }
    if stdio || bind.is_none() {
        rustre_mcp::run_stdio_wired().await
    } else {
        rustre_mcp::run_http_wired(&bind.unwrap()).await
    }
}
