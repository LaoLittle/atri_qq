pub mod command_policy;
mod digest;
pub mod extra;
mod footer;
pub mod ios;
pub mod metadata;
pub mod proto;
pub mod token;

use command_policy::CommandPolicyState;
use extra::{ExtraEntropy, ExtraState};
use metadata::{MetadataResources, MetadataState};
use token::{TokenError, TokenResources, TokenState};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Context {
    pub uin: Vec<u8>,
    pub qua: Vec<u8>,
    pub machine_id: Vec<u8>,
}

impl Context {
    pub fn new(
        uin: impl Into<Vec<u8>>,
        qua: impl Into<Vec<u8>>,
        machine_id: impl Into<Vec<u8>>,
    ) -> Self {
        let mut context = Self {
            uin: uin.into(),
            qua: qua.into(),
            machine_id: machine_id.into(),
        };
        context.truncate_c_strings();
        context
    }

    fn truncate_c_strings(&mut self) {
        for value in [&mut self.uin, &mut self.qua, &mut self.machine_id] {
            if let Some(end) = value.iter().position(|&byte| byte == 0) {
                value.truncate(end);
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signature {
    Empty,
    Sequence([u8; 16]),
    Full([u8; 48]),
    Ios(ios::signer::Signature),
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Empty => &[],
            Self::Sequence(bytes) => bytes,
            Self::Full(bytes) => bytes,
            Self::Ios(signature) => signature.as_ref(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecureInfo {
    pub sign: Signature,
    pub token: Vec<u8>,
    pub extra: Vec<u8>,
}

pub trait SignResources: ExtraEntropy + TokenResources {
    fn metadata_resources(&mut self, needs_entropy: bool)
    -> Result<MetadataResources, Self::Error>;
}

#[derive(Debug)]
pub enum SignError<E> {
    Entropy(E),
    Token(TokenError),
}

#[derive(Debug)]
pub struct Signer {
    context: Context,
    footer: footer::FooterCipher,
    pub tokens: TokenState,
    pub extra: ExtraState,
    pub metadata: MetadataState,
    pub command_policy: CommandPolicyState,
    pub sign_enabled: bool,
    pub sequence_only: bool,
    desktop_resource_initialized: bool,
    last_token_error: Option<TokenError>,
}

impl Default for Signer {
    fn default() -> Self {
        Self {
            context: Context::default(),
            footer: footer::FooterCipher::default(),
            tokens: TokenState::default(),
            extra: ExtraState::default(),
            metadata: MetadataState::new(),
            command_policy: CommandPolicyState::new(),
            sign_enabled: true,
            sequence_only: false,
            desktop_resource_initialized: false,
            last_token_error: None,
        }
    }
}

impl Signer {
    pub fn new(context: Context, resources: &mut impl TokenResources) -> Result<Self, TokenError> {
        let mut signer = Self::default();
        signer.initialize(context, resources)?;
        Ok(signer)
    }

    pub fn set_footer_seed(&mut self, seed: &[u8; 48]) {
        self.footer.set_seed(seed);
    }

    pub fn initialize_desktop_resource(&mut self) {
        if self.desktop_resource_initialized {
            return;
        }
        self.footer.set_seed(&footer::DESKTOP_SEED);
        self.desktop_resource_initialized = true;
    }

    pub fn context(&self) -> &Context {
        &self.context
    }

    pub fn poll_token(&mut self, resources: &mut impl TokenResources) -> Result<(), TokenError> {
        self.tokens.poll(&self.context.uin, resources)
    }

    pub fn initialize(
        &mut self,
        mut context: Context,
        resources: &mut impl TokenResources,
    ) -> Result<(), TokenError> {
        context.truncate_c_strings();
        if !self.context.uin.starts_with(&context.uin) {
            if let Err(error) = self.tokens.change_account(&context.uin, resources) {
                self.last_token_error = Some(error);
            }
            self.extra.reset();
        }
        self.context = context;
        let read = self.tokens.token(&self.context.uin, resources)?;
        if let Some(error) = read.report_error {
            self.last_token_error = Some(error);
        }
        Ok(())
    }

    pub fn take_token_error(&mut self) -> Option<TokenError> {
        self.last_token_error.take()
    }

    pub fn sign<R: SignResources>(
        &mut self,
        command: &str,
        sequence: i32,
        body: &[u8],
        resources: &mut R,
    ) -> Result<SecureInfo, SignError<R::Error>> {
        let command = command.split('\0').next().unwrap_or("");
        let (sign, prepared_extra) = if !self.sign_enabled {
            (Signature::Empty, None)
        } else if self.sequence_only {
            let mut decimal = [0u8; 11];
            let sequence = decimal_sequence(sequence, &mut decimal);
            (Signature::Sequence(digest::md5(sequence)), None)
        } else {
            let token = self.read_token(resources).map_err(SignError::Token)?;
            let extra = self
                .extra
                .sign_extra(command, body, &self.context.qua, resources)
                .map_err(SignError::Entropy)?;
            let input = digest::md5_parts(&[&token, &extra, body]);
            let clock = resources.clock_ns().map_err(SignError::Entropy)? as i64;
            let mut prepared = digest::prepare_sign(&input, clock);

            prepared[5] = if self.desktop_resource_initialized {
                0
            } else {
                0x80
            };
            let counter = self.command_policy.next(command.as_bytes());
            let facts = resources
                .metadata_resources(self.metadata.requires_entropy())
                .map_err(SignError::Entropy)?;
            let plaintext = self.metadata.encode(
                &prepared,
                counter,
                &self.context.machine_id,
                &self.context.uin,
                facts,
            );
            (
                Signature::Full(self.footer.encrypt(&plaintext)),
                Some(extra),
            )
        };

        let extra = match prepared_extra {
            Some(extra) => extra,
            None => self
                .extra
                .sign_extra(command, body, &self.context.qua, resources)
                .map_err(SignError::Entropy)?,
        };

        let token = self.read_token(resources).map_err(SignError::Token)?;
        Ok(SecureInfo { sign, token, extra })
    }

    fn read_token(&mut self, resources: &mut impl TokenResources) -> Result<Vec<u8>, TokenError> {
        let read = self.tokens.token(&self.context.uin, resources)?;
        if let Some(error) = read.report_error {
            self.last_token_error = Some(error);
        }
        Ok(read.bytes)
    }
}

fn decimal_sequence(value: i32, buffer: &mut [u8; 11]) -> &[u8] {
    let mut magnitude = value.unsigned_abs();
    let mut start = buffer.len();
    loop {
        start -= 1;
        buffer[start] = b'0' + (magnitude % 10) as u8;
        magnitude /= 10;
        if magnitude == 0 {
            break;
        }
    }
    if value < 0 {
        start -= 1;
        buffer[start] = b'-';
    }
    &buffer[start..]
}
