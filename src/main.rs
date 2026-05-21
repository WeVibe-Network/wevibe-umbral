use clap::{Parser, Subcommand};
use wevibe_umbral::cli;
use wevibe_umbral::generated::umbral_sidecar_server::UmbralSidecarServer;
use wevibe_umbral::UmbralSidecarService;
use serde_json::json;
use std::net::SocketAddr;
use tonic::transport::Server;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
#[command(name = "wevibe-umbral")]
#[command(about = "Umbral PRE sidecar - gRPC server and CLI crypto operations")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start gRPC server on 127.0.0.1:4460
    Serve {
        #[arg(long, default_value = "127.0.0.1:4460")]
        addr: String,
    },
    /// Encrypt plaintext under an Umbral public key
    Encrypt {
        /// Epoch Umbral public key (hex, 33 bytes compressed secp256k1)
        #[arg(long)]
        epoch_pk: String,
        /// Plaintext to encrypt (hex)
        #[arg(long)]
        plaintext: String,
    },
    /// Decrypt a re-encrypted capsule
    DecryptReencrypted {
        /// Original Umbral capsule (hex)
        #[arg(long)]
        capsule: String,
        /// Comma-separated re-encrypted capsule fragments (hex)
        #[arg(long)]
        cfrags: String,
        /// Re-encrypted ciphertext - the Umbral-encrypted plaintext (hex)
        #[arg(long)]
        ciphertext: String,
        /// Receiving (member) secret key (hex, 32 bytes)
        #[arg(long)]
        receiving_sk: String,
        /// Delegating (epoch) public key (hex, 33 bytes compressed)
        #[arg(long)]
        delegating_pk: String,
    },
}

async fn run_grpc_server(addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let service = UmbralSidecarService::new();

    tracing::info!("Umbral sidecar listening on {}", addr);
    Server::builder()
        .add_service(UmbralSidecarServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli_args = Cli::parse();

    match cli_args.command {
        None => {
            let addr: SocketAddr = "127.0.0.1:4460".parse()?;
            run_grpc_server(addr).await?;
        }
        Some(Commands::Serve { addr }) => {
            let addr: SocketAddr = addr.parse()?;
            run_grpc_server(addr).await?;
        }
        Some(Commands::Encrypt {
            epoch_pk,
            plaintext,
        }) => {
            if let Err(e) = cli::cmd_encrypt(&epoch_pk, &plaintext) {
                eprintln!("{}", json!({ "error": e.to_string() }));
                std::process::exit(1);
            }
        }
        Some(Commands::DecryptReencrypted {
            capsule,
            cfrags,
            ciphertext,
            receiving_sk,
            delegating_pk,
        }) => {
            if let Err(e) = cli::cmd_decrypt_reencrypted(
                &capsule,
                &cfrags,
                &ciphertext,
                &receiving_sk,
                &delegating_pk,
            ) {
                eprintln!("{}", json!({ "error": e.to_string() }));
                std::process::exit(1);
            }
        }
    }

    Ok(())
}
