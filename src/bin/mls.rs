use clap::{ArgAction, Parser};
use futures_util::stream::StreamExt;
use manta::client::{Client, Config, DirectoryEntry, LogOptions};
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

    /// Output in JSON.
    #[arg(short, long, action = ArgAction::SetTrue)]
    json: bool,

    /// JSON output, and display the HTTP headers if available.
    #[arg(long = "fulljson", visible_alias = "full-json", action = ArgAction::SetTrue)]
    full_json: bool,

    /// Use a long listing format.
    #[arg(short, long, action = ArgAction::SetTrue)]
    long: bool,

    /// Human readable output when using a long listing format.
    #[arg(short = 'H', long = "human-readable", action = ArgAction::SetTrue)]
    human_readable: bool,

    /// Start listing from MARKER..
    #[arg(short, long)]
    marker: Option<String>,

    /// Reverse order while sorting.
    #[arg(short, long, action = ArgAction::SetTrue)]
    reverse: bool,

    /// only return names of type <type> d=directory, o=object.
    #[arg(long, value_name = "TYPE")]
    r#type: Option<char>,

    /// Sort listing by modification time, newest first.
    #[arg(short, long, action = ArgAction::SetTrue)]
    time: bool,

    /// Verbose output, specify multiple times to increase verbosity
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
        log: Some(LogOptions::new(cli.verbose, "mls")),
    };

    let mut client = Client::new(config);

    for path in cli.path.iter() {
        let mut stream = client.ls(path).await.unwrap(); // XXX
        while let Some(entry) = stream.next().await {
            match &entry {
                Ok(DirectoryEntry::Object(o)) => println!("{}", o.name),
                Ok(DirectoryEntry::Directory(d)) => println!("{}/", d.name),
                Err(e) => eprintln!("Error: {:?}", e), // XXX
            }
        }
    }
    Ok(())
}
