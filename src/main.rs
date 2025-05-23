use clap::Parser;
use colored::*;
use futures::future::join_all;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

const BANNER: &str = r#"

                                                                     
                                                                     
_______   ______    ______    ______    _______  _______  __    __ 
/       | /      \  /      \  /      \  /       |/       |/  |  /  |
/$$$$$$$/ /$$$$$$  |/$$$$$$  |/$$$$$$  |/$$$$$$$//$$$$$$$/ $$ |  $$ |
$$ |      $$ |  $$ |$$ |  $$/ $$ |  $$/ $$      \$$      \ $$ |  $$ |
$$ \_____ $$ \__$$ |$$ |      $$ |       $$$$$$  |$$$$$$  |$$ \__$$ |
$$       |$$    $$/ $$ |      $$ |      /     $$//     $$/ $$    $$ |
$$$$$$$/  $$$$$$/  $$/       $$/       $$$$$$$/ $$$$$$$/   $$$$$$$ |
                                                          /  \__$$ |
                                                          $$    $$/ 
                                                           $$$$$$/  

"#;

#[derive(Parser, Debug)]
#[command(author = "MorphyKutay", version, about = "CORS Vulnerability Scanner", long_about = None)]
struct Args {
    /// Target URL to scan
    #[arg(short, long)]
    url: Option<String>,

    /// File containing list of URLs
    #[arg(short, long)]
    file: Option<String>,

    /// Verbose output mode
    #[arg(short, long)]
    verbose: bool,

    /// Timeout in seconds
    #[arg(short, long, default_value = "5")]
    timeout: u64,
}

fn normalize_url(url: &str) -> String {
    let url = url.trim();
    if !url.starts_with("http://") && !url.starts_with("https://") {
        format!("http://{}", url)
    } else {
        url.to_string()
    }
}

async fn check_origin(client: reqwest::Client, url: String, origin: String, verbose: bool) -> Result<(), Box<dyn Error>> {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_str("Origin")?,
        HeaderValue::from_str(&origin)?,
    );

    if verbose {
        println!("{}", format!("Testing Origin: {}", origin).yellow());
    }

    let response = client
        .get(&url)
        .headers(headers)
        .send()
        .await?;

    let cors_headers = response.headers();
    
    println!("\n{}", format!("Origin: {}", origin).yellow());
    
    if let Some(allow_origin) = cors_headers.get("access-control-allow-origin") {
        let allow_origin_str = allow_origin.to_str()?;
        
        if allow_origin_str == "*" {
            println!("{}", "⚠️  WARNING: Access-Control-Allow-Origin is set to *!".red());
            println!("{}", "VULNERABLE: Server allows requests from any origin".green());
        } else if allow_origin_str == origin {
            println!("{}", "Access-Control-Allow-Origin found:".white());
            println!("  Value: {}", allow_origin_str);
            println!("{}", "✅ Origin is properly validated.".white());
        } else {
            println!("{}", "Access-Control-Allow-Origin found:".white());
            println!("  Value: {}", allow_origin_str);
            println!("{}", "✅ Origin validation is strict.".white());
        }
    } else {
        println!("{}", "❌ Access-Control-Allow-Origin header not found.".red());
    }

    if let Some(allow_credentials) = cors_headers.get("access-control-allow-credentials") {
        let credentials_str = allow_credentials.to_str()?;
        if credentials_str == "true" {
            println!("{}", "Access-Control-Allow-Credentials found:".white());
            println!("  Value: {}", credentials_str);
            println!("{}", "VULNERABLE: Server allows credentials in CORS requests".green());
        } else {
            println!("{}", "Access-Control-Allow-Credentials found:".white());
            println!("  Value: {}", credentials_str);
        }
    }

    if let Some(allow_methods) = cors_headers.get("access-control-allow-methods") {
        let methods_str = allow_methods.to_str()?;
        if methods_str.contains("*") {
            println!("{}", "Access-Control-Allow-Methods found:".white());
            println!("  Value: {}", methods_str);
            println!("{}", "VULNERABLE: Server allows all HTTP methods".green());
        } else {
            println!("{}", "Access-Control-Allow-Methods found:".white());
            println!("  Value: {}", methods_str);
        }
    }

    if verbose {
        println!("{}", "All headers:".yellow());
        for (name, value) in cors_headers.iter() {
            println!("  {}: {}", name, value.to_str()?);
        }
    }

    Ok(())
}

async fn scan_url(url: &str, verbose: bool, timeout: u64) -> Result<(), Box<dyn Error>> {
    let normalized_url = normalize_url(url);
    println!("\n{}", format!("Scanning URL: {}", normalized_url).cyan());
    
    if verbose {
        println!("{}", "Disabling SSL verification...".yellow());
    }

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(timeout))
        .build()?;
    
    let origins = vec![
        "https://evil.com",
        "null",
        "https://trusted.com",
        "http://localhost",
        "https://example.com",
    ];

    let mut tasks = Vec::new();
    for origin in origins {
        let client = client.clone();
        let url = normalized_url.clone();
        let origin = origin.to_string();
        let verbose = verbose;
        
        tasks.push(tokio::spawn(async move {
            if let Err(e) = check_origin(client, url, origin, verbose).await {
                println!("{}", format!("Error: {}", e).red());
            }
        }));
    }

    join_all(tasks).await;

    Ok(())
}

fn read_urls_from_file<P>(filename: P) -> io::Result<Vec<String>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    let reader = io::BufReader::new(file);
    reader.lines().collect()
}

fn print_help() {
    println!("{}", BANNER.green());
    println!("{}", "Usage:".yellow());
    println!("  corrssy -u <URL>");
    println!("  corrssy -r <file_path>");
    println!("\n{}", "Options:".yellow());
    println!("  -u, --url <URL>        Target URL to scan");
    println!("  -r, --file <file>      File containing list of URLs");
    println!("  -v, --verbose          Verbose output mode");
    println!("  -t, --timeout <sec>    Timeout in seconds (default: 5)");
    println!("  -h, --help             Show this help message");
    println!("\n{}", "Examples:".yellow());
    println!("  corrssy -u https://example.com");
    println!("  corrssy -r urls.txt");
    println!("  corrssy -u https://example.com -v -t 10");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    
    if args.url.is_none() && args.file.is_none() {
        print_help();
        return Ok(());
    }

    println!("{}", BANNER.green());
    println!("{}", "Starting CORS Scanner...".green());

    if let Some(url) = args.url {
        scan_url(&url, args.verbose, args.timeout).await?;
    } else if let Some(file_path) = args.file {
        let urls = read_urls_from_file(file_path)?;
        for url in urls {
            if !url.trim().is_empty() {
                if let Err(e) = scan_url(&url.trim(), args.verbose, args.timeout).await {
                    println!("{}", format!("Error: {} - URL: {}", e, url).red());
                }
            }
        }
    }

    Ok(())
}