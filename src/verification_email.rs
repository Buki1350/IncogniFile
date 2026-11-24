use lettre::{
    message::Mailbox, transport::smtp::authentication::Credentials, AsyncSmtpTransport,
    AsyncTransport, Message, Tokio1Executor,
};
use std::{path::PathBuf, time::Duration};

pub enum VerificationMailer {
    Local(PathBuf),
    Smtp {
        transport: Box<AsyncSmtpTransport<Tokio1Executor>>,
        from: Mailbox,
    },
}

// sends verification emails to users, either via local file or SMTP
impl VerificationMailer {
    pub fn from_env(origin: &str) -> Result<Self, String> {
        match std::env::var("MAIL_DELIVERY")
            .unwrap_or_else(|_| "local".into())
            .as_str()
        {
            "local" => {
                let uri: axum::http::Uri = origin.parse().map_err(|_| "Invalid APP_ORIGIN")?;
                if !matches!(uri.host(), Some("localhost" | "127.0.0.1" | "[::1]")) {
                    return Err("Local verification mail is allowed only on localhost. Configure MAIL_DELIVERY=smtp or explicitly disable verification for the demonstration.".into());
                }
                Ok(Self::Local(
                    std::env::var_os("MAIL_OUTBOX_DIR")
                        .map(PathBuf::from)
                        .unwrap_or_else(|| ".mail".into()),
                ))
            }
            "smtp" => {
                let host = std::env::var("SMTP_HOST").map_err(|_| "SMTP_HOST required")?;
                let user = std::env::var("SMTP_USER").map_err(|_| "SMTP_USER required")?;
                let password =
                    std::env::var("SMTP_PASSWORD").map_err(|_| "SMTP_PASSWORD required")?;
                let from = std::env::var("MAIL_FROM")
                    .map_err(|_| "MAIL_FROM required")?
                    .parse()
                    .map_err(|_| "Invalid MAIL_FROM")?;
                let port = std::env::var("SMTP_PORT")
                    .unwrap_or_else(|_| "587".into())
                    .parse::<u16>()
                    .map_err(|_| "Invalid SMTP_PORT")?;
                let transport = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)
                    .map_err(|_| "Invalid SMTP host/TLS configuration")?
                    .port(port)
                    .credentials(Credentials::new(user, password))
                    .timeout(Some(Duration::from_secs(10)))
                    .build();
                Ok(Self::Smtp {
                    transport: Box::new(transport),
                    from,
                })
            }
            _ => Err("MAIL_DELIVERY must be local or smtp".into()),
        }
    }

    pub async fn send(&self, user_id: i64, email: &str, link: &str) -> Result<(), String> {
        let body = format!("Potwierdź adres e-mail w IncogniFile:\n\n{link}\n\nLink jest jednorazowy i ważny przez 30 minut. Jeśli nie zakładasz konta, zignoruj tę wiadomość.");
        match self {
            Self::Local(directory) => {
                tokio::fs::create_dir_all(directory)
                    .await
                    .map_err(|_| "Cannot create local outbox")?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    tokio::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
                        .await
                        .map_err(|_| "Cannot protect local outbox")?;
                }
                tokio::fs::write(
                    directory.join(format!("{user_id}.eml")),
                    format!(
                        "To: {email}\nSubject: Potwierdź adres e-mail w IncogniFile\n\n{body}\n"
                    ),
                )
                .await
                .map_err(|_| "Cannot write local mail")?;
            }
            Self::Smtp { transport, from } => {
                let message = Message::builder()
                    .from(from.clone())
                    .to(email.parse().map_err(|_| "Invalid recipient email")?)
                    .subject("Potwierdź adres e-mail w IncogniFile")
                    .body(body)
                    .map_err(|_| "Cannot build verification mail")?;
                transport
                    .send(message)
                    .await
                    .map_err(|_| "SMTP delivery failed")?;
            }
        }
        Ok(())
    }
}
