{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE LambdaCase #-}
module Network.Wai.SAML2.NameIDFormat
    ( NameIDFormat(..)
    , parseNameIDFormat
    ) where

import Data.Text (Text, unpack)
import GHC.Generics (Generic)

-- | Format of the subject identifier.
-- See 8.3 Name Identifier Format Identifiers in https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
data NameIDFormat = Unspecified
    -- ^ The interpretation is left to individual implementations
    | EmailAddress
    -- ^ "addr-spec" as defined in IETF RFC 2822
    | X509SubjectName
    -- ^ contents of the <ds:X509SubjectName> element in the XML Signature Recommendation
    | WindowsDomainQualifiedName
    -- ^ string of the form "DomainName\UserName
    | KerberosPrincipalName
    -- ^ Kerberos principal name using the format name[/instance]@REALM
    | Entity
    -- ^ identifier of an entity that provides SAML-based services
    -- (such as a SAML authority, requester, or responder) or is a participant in SAML profiles (such as a service
    -- provider supporting the browser SSO profile)
    | Provider
    -- ^ identifier of a provider of SAML-based services
    -- (such as a SAML authority) or a participant in SAML
    -- profiles (such as a service provider supporting the browser profiles)
    | Federated
    -- ^ persistent opaque identifier that corresponds to an identity
    -- federation between an identity provider and a service provider
    | Transient
    -- ^ an identifier with transient semantics and SHOULD be treated
    -- as an opaque and temporary value by the relying party
    | Persistent
    -- ^ persistent opaque identifier for a principal that is specific to
    -- an identity provider and a service provider or affiliation of service providers
    deriving (Eq, Ord, Show, Generic)

parseNameIDFormat :: MonadFail m => Text -> m NameIDFormat
parseNameIDFormat = \case
    "urn:oasis:names:tc:SAML:1.1:nameid-format:Kerberos" -> pure KerberosPrincipalName
    "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName" -> pure WindowsDomainQualifiedName
    "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName" -> pure X509SubjectName
    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" -> pure EmailAddress
    "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" -> pure Unspecified
    "urn:oasis:names:tc:SAML:2.0:nameid-format:entity" -> pure Entity
    "urn:oasis:names:tc:SAML:2.0:nameid-format:federated" -> pure Federated
    "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" -> pure Persistent
    "urn:oasis:names:tc:SAML:2.0:nameid-format:provider" -> pure Provider
    "urn:oasis:names:tc:SAML:2.0:nameid-format:transient" -> pure Transient
    unknown -> fail $ "parseNameIDFormat: unknown format " <> unpack unknown
