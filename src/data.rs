use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

#[derive(Serialize, Deserialize)]
pub enum Direction {
    ToServer,
    ToClient,
}

impl Display for Direction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Direction::ToServer => write!(f, "C->S"),
            Direction::ToClient => write!(f, "S->C"),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub enum ClientMessage {
    Log(Vec<u8>),
    PacketStart(u16, Direction),
    PacketData(Direction, Vec<u8>),
    PacketFinish(Direction),
}
