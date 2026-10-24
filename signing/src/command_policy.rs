pub fn is_counted_command(command: &[u8]) -> bool {
    match command.len() {
        4 => command == b"2102" || command == b"2088",
        5 => command == b"810_9",
        13 => command.eq_ignore_ascii_case(b"wtlogin.login"),
        15 => command.eq_ignore_ascii_case(b"wtlogin.qrlogin"),
        47 => {
            command.eq_ignore_ascii_case(b"trpc.login.ecdh.EcdhService.SsoNTLoginEasyLogin")
                || command.eq_ignore_ascii_case(b"trpc.login.ecdh.EcdhService.SsoNTLoginAuthLogin")
        }
        51 => command.eq_ignore_ascii_case(b"trpc.login.ecdh.EcdhService.SsoNTLoginPasswordLogin"),
        58 => command
            .eq_ignore_ascii_case(b"trpc.login.ecdh.EcdhService.SsoNTLoginTGTExchangeFastLogin"),
        60 => {
            command.eq_ignore_ascii_case(
                b"trpc.login.ecdh.EcdhService.SsoNTLoginPasswordLoginNewDevice",
            ) || command.eq_ignore_ascii_case(
                b"trpc.login.ecdh.EcdhService.SsoNTLoginEasyLoginUnusualDevice",
            )
        }
        64 => command.eq_ignore_ascii_case(
            b"trpc.login.ecdh.EcdhService.SsoNTLoginPasswordLoginUnusualDevice",
        ),
        _ => false,
    }
}

#[derive(Debug, Default)]
pub struct CommandPolicyState {
    counter: u16,
}

impl CommandPolicyState {
    pub const fn new() -> Self {
        Self { counter: 0 }
    }

    pub const fn with_counter(counter: u16) -> Self {
        Self { counter }
    }

    pub const fn counter(&self) -> u16 {
        self.counter
    }

    pub fn next(&mut self, command: &[u8]) -> u16 {
        if is_counted_command(command) {
            self.counter = self.counter.saturating_add(1);
            self.counter
        } else {
            0
        }
    }
}
