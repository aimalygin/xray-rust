use tokio::sync::watch;

#[derive(Debug)]
pub struct Shutdown {
    sender: watch::Sender<bool>,
    receiver: watch::Receiver<bool>,
}

impl Shutdown {
    pub fn new() -> Self {
        let (sender, receiver) = watch::channel(false);
        Self { sender, receiver }
    }

    pub fn signal(&self) {
        let _ = self.sender.send(true);
    }

    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.receiver.clone()
    }
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
