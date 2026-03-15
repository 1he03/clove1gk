use http::HeaderMap;

// What comes out of this layer — token type automatically determined
#[derive(Debug, Clone, PartialEq)]
pub enum RawToken {
    Jwt(String),
    LegacyUuid(String),
}

#[derive(Debug)]
pub enum ExtractError {
    MissingHeader,
    InvalidFormat,  // not Bearer or invalid header
    EmptyToken,
}

impl RawToken {
    /// Single entry point — gets token from headers and determines its type
    pub fn from_headers(headers: &HeaderMap) -> Result<Self, ExtractError> {
        let auth_value = headers
            .get("Authorization")
            .ok_or(ExtractError::MissingHeader)?
            .to_str()
            .map_err(|_| ExtractError::InvalidFormat)?;

        let token = auth_value
            .strip_prefix("Bearer ")
            .ok_or(ExtractError::InvalidFormat)?;

        if token.is_empty() {
            return Err(ExtractError::EmptyToken);
        }

        Ok(Self::detect(token.to_string()))
    }

    // JWT = 3 parts separated by dots (header.payload.signature)
    fn detect(token: String) -> Self {
        if token.splitn(4, '.').count() == 3 {
            Self::Jwt(token)
        } else {
            Self::LegacyUuid(token)
        }
    }

    pub fn raw(&self) -> &str {
        match self {
            Self::Jwt(t) | Self::LegacyUuid(t) => t,
        }
    }

    pub fn is_jwt(&self) -> bool {
        matches!(self, Self::Jwt(_))
    }
}
