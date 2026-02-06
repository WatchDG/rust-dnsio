use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidHeaderLength,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidHeaderLength => {
                write!(f, "DNS header must be at least 12 bytes")
            }
        }
    }
}

impl std::error::Error for Error {}
