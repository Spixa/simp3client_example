pub const MSG_SIZE: usize = 16384;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    Message(String, String, String),
    ClientMessage(String),
    ClientDM(String, String),
    Join(String),
    Leave(String),
    ServerCommand(String),
    ClientRespone(String),
    ServerDM(String),
    Broadcast(String),
    Auth(String, String),
    Ping,
    ChannelJoin(String, String),
    ChannelLeave(String, String),
    List(String),
    _GracefulDisconnect,
    Illegal,
}
