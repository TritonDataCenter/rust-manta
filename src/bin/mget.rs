use clap::{ArgAction, Parser};
use manta::client::{Client, Config, LogOptions};
use std::path::Path;
use tokio::fs::File;
use tokio::io;

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

    /// Disable progress bar
    #[arg(short, long, action = ArgAction::SetTrue)]
    quiet: bool,

    /// Force the progress bar to draw, even when stderr redirected.
    #[arg(short, long, action = ArgAction::SetTrue)]
    progress: bool,

    /// Verbose output, specify multiple times to increase verbosity.
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,

    /// Write output to <file> instead of stdout.
    #[arg(short, long)]
    output: Option<String>,

    /// Write output to a file using remote object name as filename.
    #[arg(short='O', long="remote-name", action = ArgAction::SetTrue)]
    remote_name: bool,

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
        log: Some(LogOptions::new(cli.verbose, "mget")),
    };

    if cli.output.is_some() && cli.remote_name {
        panic!("Error: Can not specify both --output and --remote-name");
    }

    let mut client = Client::new(config);
    for path in cli.path.iter() {
        let mut stdout = io::stdout();
        let mut stream = client.get(path).await.unwrap();

        if let Some(output) = &cli.output {
            let mut file = File::create(output).await?;
            io::copy(&mut stream, &mut file).await?;
        } else if cli.remote_name {
            // XXX  What if remote is a directory?
            let p = Path::new(path);
            let mut file = File::create(p.file_name().unwrap()).await?;
            io::copy(&mut stream, &mut file).await?;
        } else {
            io::copy(&mut stream, &mut stdout).await?;
        }
    }

    Ok(())
}
