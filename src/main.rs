use std::{collections::HashSet, io::Result as IoResult, net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}, sync::Mutex};
use clap::Parser;
use serde::{Deserialize, Serialize};
use chrono::{Utc};
use tracing::{info, warn};
use tracing_subscriber::FmtSubscriber;
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;

/// Simple config via CLI
#[derive(Parser, Debug)]
#[command(name = "rust-honeypot")]
struct Args {
    /// Comma-separated ports to listen on, e.g. 22,80,23
    #[arg(short, long, default_value = "22,80,23")]
    ports: String,

    /// Directory to write logs
    #[arg(short, long, default_value = "logs")]
    log_dir: String,

    /// Maximum bytes to capture per connection
    #[arg(short='m', long, default_value_t = 4096)]
    max_capture: usize,
}

#[derive(Serialize, Deserialize, Debug)]
struct ConnectionRecord {
    timestamp: chrono::DateTime<chrono::Utc>,
    src_addr: String,
    dst_port: u16,
    detected_proto: String,
    bytes_received: usize,
    payload_sample: String,
}

struct Logger {
    dir: PathBuf,
    file: Mutex<std::fs::File>,
}

impl Logger {
    fn new(dir: PathBuf) -> std::io::Result<Self> {
        create_dir_all(&dir)?;
        let file_path = dir.join("connections.jsonl");
        let file = OpenOptions::new().create(true).append(true).open(&file_path)?;
        Ok(Logger { dir, file: Mutex::new(file) })
    }

    async fn write_record(&self, rec: &ConnectionRecord) {
        let mut file = self.file.lock().await;
        if let Ok(json) = serde_json::to_string(rec) {
            if let Err(e) = writeln!(file, "{}", json) {
                warn!("failed to write log: {}", e);
            }
        }
    }
}

#[tokio::main]
async fn main() -> IoResult<()> {
    // initialize tracing
    let subscriber = FmtSubscriber::builder().with_max_level(tracing::Level::INFO).finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting tracing default failed");

    let args = Args::parse();

    let ports: HashSet<u16> = args.ports.split(',')
        .filter_map(|s| s.trim().parse::<u16>().ok())
        .collect();

    let logger = Arc::new(Logger::new(PathBuf::from(args.log_dir.clone())).expect("failed opening log dir"));

    info!("Starting honeypot on ports: {:?}", ports);

    // spawn listener for each port
    let mut handles = vec![];
    for port in ports {
        let logger_clone = logger.clone();
        let max_capture = args.max_capture;
        let bind_addr = format!("0.0.0.0:{}", port);
        let listener = TcpListener::bind(&bind_addr).await?;
        info!("Listening on {}", bind_addr);

        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        let l = logger_clone.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_conn(stream, peer, port, l, max_capture).await {
                                warn!("connection handler error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        warn!("accept failed: {}", e);
                    }
                }
            }
        });
        handles.push(handle);
    }

    // wait forever
    futures::future::join_all(handles).await;
    Ok(())
}

async fn handle_conn(mut stream: TcpStream, peer: SocketAddr, dst_port: u16, logger: Arc<Logger>, max_capture: usize) -> IoResult<()> {
    info!("New connection from {} to port {}", peer, dst_port);

    // set small read timeout via tokio (optional); not setting explicit timeouts to keep code simple
    // read up to max_capture bytes (non-blocking reads, but with some latency)
    let mut buf = vec![0u8; max_capture];
    let mut received = 0usize;

    // attempt a short initial read to fingerprint
    match tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut buf)).await {
        Ok(Ok(n)) => {
            if n == 0 {
                info!("{} closed immediately", peer);
            } else {
                received = n;
            }
        }
        Ok(Err(e)) => {
            warn!("read error from {}: {}", peer, e);
        }
        Err(_) => {
            // timeout
        }
    }

    // Decide protocol based on initial bytes or destination port
    let detected = detect_protocol(dst_port, &buf[..received]);

    // respond with a deception routine
    match detected.as_str() {
        "http" => {
            respond_http(&mut stream).await?;
        }
        "ssh" => {
            respond_ssh(&mut stream).await?;
        }
        "telnet" => {
            respond_telnet(&mut stream, &buf[..received], received, logger.clone()).await?;
            // telnet handler logs payloads itself for interactive data
            return Ok(());
        }
        _ => {
            respond_generic(&mut stream, dst_port).await?;
        }
    }

    // record the connection
    let sample = if received > 0 {
        // show printable portion safely
        sanitize_sample(&buf[..received])
    } else {
        String::new()
    };

    let rec = ConnectionRecord {
        timestamp: Utc::now(),
        src_addr: peer.to_string(),
        dst_port,
        detected_proto: detected,
        bytes_received: received,
        payload_sample: sample,
    };

    logger.write_record(&rec).await;

    // close connection politely
    let _ = stream.shutdown().await;
    Ok(())
}

fn detect_protocol(port: u16, initial: &[u8]) -> String {
    let s = String::from_utf8_lossy(initial).to_lowercase();
    if port == 80 || s.starts_with("get ") || s.starts_with("post ") || s.starts_with("http/") {
        return "http".to_string();
    }
    if port == 22 || s.starts_with("ssh-") {
        return "ssh".to_string();
    }
    if port == 23 || s.contains("telnet") {
        return "telnet".to_string();
    }

    // basic heuristics
    if s.contains("http/") || s.starts_with("get ") || s.starts_with("post ") {
        "http".to_string()
    } else if s.starts_with("ssh-") {
        "ssh".to_string()
    } else {
        "generic".to_string()
    }
}

async fn respond_http(stream: &mut TcpStream) -> IoResult<()> {
    let body = "<html><body><h1>400 Bad Request</h1></body></html>";
    let resp = format!(
        "HTTP/1.1 400 Bad Request\r\nServer: Apache/2.4.41 (Unix)\r\nContent-Length: {}\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(resp.as_bytes()).await?;
    Ok(())
}

async fn respond_ssh(stream: &mut TcpStream) -> IoResult<()> {
    // Send a fake SSH server banner
    let _ = stream.write_all(b"SSH-2.0-OpenSSH_7.9p1 Debian-10+openssh\r\n").await;
    // try to read any client banner and then close
    let mut tmp = [0u8; 256];
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut tmp)).await;
    Ok(())
}

async fn respond_telnet(stream: &mut TcpStream, initial: &[u8], initial_len: usize, logger: Arc<Logger>) -> IoResult<()> {
    // Simple telnet-like prompt: ask for login, read until EOF or timeout, log each line
    let _ = stream.write_all(b"Welcome to remote host\r\nlogin: ").await;

    let mut buf = vec![0u8; 1024];
    // if initial data contains something like a username, process it
    if initial_len > 0 {
        let sample = sanitize_sample(&initial[..initial_len]);
        info!("initial telnet data sample: {}", sample);
    }

    let mut total = Vec::new();
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(120), stream.read(&mut buf)).await {
            Ok(Ok(0)) => {
                // client closed
                break;
            }
            Ok(Ok(n)) => {
                total.extend_from_slice(&buf[..n]);
                // echo back a fake response and ask for password once newline seen
                let s = String::from_utf8_lossy(&buf[..n]).into_owned();
                let _ = stream.write_all(b"\r\n").await;
                let _ = stream.write_all(b"Password: ").await;
                // small log entry
                let rec = ConnectionRecord {
                    timestamp: Utc::now(),
                    src_addr: match stream.peer_addr() { Ok(a) => a.to_string(), Err(_) => "unknown".into() },
                    dst_port: 23,
                    detected_proto: "telnet".into(),
                    bytes_received: total.len(),
                    payload_sample: sanitize_sample(&total),
                };
                logger.write_record(&rec).await;
                if total.len() > 4096 { break; }
            }
            Ok(Err(e)) => {
                warn!("telnet read error: {}", e);
                break;
            }
            Err(_) => {
                // timeout
                break;
            }
        }
    }
    let _ = stream.write_all(b"\r\nConnection closed\r\n").await;
    Ok(())
}

async fn respond_generic(stream: &mut TcpStream, port: u16) -> IoResult<()> {
    let banner = format!("Welcome to service on port {}\r\n", port);
    let _ = stream.write_all(banner.as_bytes()).await;
    Ok(())
}

fn sanitize_sample(bytes: &[u8]) -> String {
    // keep printable subset, limit length
    let mut out = String::new();
    for &b in bytes.iter().take(512) {
        if b.is_ascii_graphic() || b == b' ' || b == b'\r' || b == b'\n' || b == b'\t' {
            out.push(b as char);
        } else {
            out.push_str(&format!("\\x{:02x}", b));
        }
    }
    out
}
