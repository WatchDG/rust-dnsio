use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidHeaderLength,
    InsufficientData,
    InvalidDomainName,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidHeaderLength => {
                write!(f, "DNS header must be at least 12 bytes")
            }
            Error::InsufficientData => {
                write!(f, "Insufficient data to decode DNS question")
            }
            Error::InvalidDomainName => {
                write!(f, "Invalid domain name format")
            }
        }
    }
}

impl std::error::Error for Error {}
