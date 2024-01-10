use clap::{ArgAction, Parser};
use manta::client::{Client, Config, LogOptions};

#[derive(Parser)]
#[command(author, version, about)]
#[derive(Debug)]
struct Cli {
    /// Manta Account.
    #[arg(short, long, value_name = "ACCOUNT", env = "MANTA_USER")]
    account: String,

    /// Manta User (login name).
    #[arg(long, visible_alias = "subuser", env = "MANTA_SUBUSER")]
    user: Option<String>,

    /// Assume a role. Use multiple times or once with a list.
    #[arg(long, env = "MANTA_ROLE", action = ArgAction::Append)]
    role: Option<Vec<String>>,

    ///  Do not validate SSL certificate.
    #[arg(short, long = "insecure", action = ArgAction::SetTrue, env = "MANTA_TLS_INSECURE")]
    insecure: bool,

    /// SSH key fingerprint.
    #[arg(
        short,
        long = "keyId",
        visible_alias = "key",
        value_name = "FP",
        env = "MANTA_KEY_ID"
    )]
    key: String,

    /// SSH Auth Socket
    #[arg(
        short,
        long = "ssh-auth-socket",
        visible_alias = "socket",
        value_name = "SOCKET",
        env = "SSH_AUTH_SOCK"
    )]
    ssh_auth_socket: String,

    /// Manta URL.
    #[arg(short, long, env = "MANTA_URL")]
    url: String,

    /// Confirm before deleting objects.
    #[arg(short='I', long, action = ArgAction::SetTrue)]
    interactive: bool,

    /// Limit concurrent operations (default 50)
    #[arg(short, long)]
    parallel: Option<u8>,

    /// Remove directories and their contents recursively.
    #[arg(short, long, action = ArgAction::SetTrue)]
    recursive: bool,

    /// Verbose output, specify multiple times to increase verbosity.
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,

    // Manta path,
    #[arg(default_value = "~~")]
    path: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let config = Config {
        account: cli.account,
        user: cli.user,
        role: cli.role,
        insecure: cli.insecure,
        key: cli.key,
        ssh_auth_socket: cli.ssh_auth_socket,
        url: cli.url,
        log: Some(LogOptions::new(cli.verbose, "mrm")),
    };

    let mut client = Client::new(config);
    for path in cli.path.iter() {
        let _ = client.rm(path).await;
    }

    Ok(())
}
