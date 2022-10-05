{-# LANGUAGE LambdaCase #-}
module Network.Wai.SAML2.EntityDescriptor
    ( IDPSSODescriptor(..)
    , Binding(..)
    ) where

import qualified Crypto.Store.X509 as X509
import qualified Data.X509 as X509
import Data.Text (Text)
import qualified Data.Map as Map
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Network.Wai.SAML2.XML
import Text.XML.Cursor

-- | Datatype describing metadata of an identity provider.
-- See also section 2.4.3 of [Metadata for the OASIS Security Assertion Markup Language (SAML) V2.0](https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf).
data IDPSSODescriptor
    = IDPSSODescriptor {
        entityID :: Text
        -- ^ IdP Entity ID. 'Network.Wai.SAML2.Config.saml2ExpectedIssuer' should be compared against this identifier
    ,   x509Certificate :: X509.SignedExact X509.Certificate
        -- ^ The X.509 certificate for signed assertions
    ,   nameIDFormats :: [Text]
        -- ^ Supported NameID formats
    ,   singleSignOnServices :: Map.Map Binding Text
        -- ^ List of SSO urls corresponding to 'Binding's
    } deriving Show

-- | urn:oasis:names:tc:SAML:2.0:bindings
-- https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
data Binding
    = HTTPPost
    | HTTPRedirect
    | HTTPArtifact
    | PAOS
    | SOAP
    | URLEncodingDEFLATE
    deriving (Show, Eq, Ord)

instance FromXML IDPSSODescriptor where
    parseXML cursor = do
        let entityID = T.concat $ attribute "entityID" cursor
        descriptor <- oneOrFail "IDPSSODescriptor is required"
            $ cursor $/ element (mdName "IDPSSODescriptor")
        rawCertificate <- oneOrFail "X509Certificate is required" $ descriptor
            $/ element (mdName "KeyDescriptor")
            &/ element (dsName "KeyInfo")
            &/ element (dsName "X509Data")
            &/ element (dsName "X509Certificate")
            &/ content
        x509Certificate <- oneOrFail "Fail to parse X509Certificate"
            $ X509.readSignedObjectFromMemory
            $ T.encodeUtf8
            $ T.unlines
            [ "-----BEGIN CERTIFICATE-----"
            , rawCertificate
            , "-----END CERTIFICATE-----"
            ]
        let nameIDFormats = descriptor
                $/ element (mdName "NameIDFormat")
                &/ content
        singleSignOnServices <- fmap Map.fromList
            $ traverse parseService
            $ descriptor $/ element (mdName "SingleSignOnService")
        pure IDPSSODescriptor{..}

parseService :: MonadFail m => Cursor -> m (Binding, Text)
parseService cursor = do
    binding <- oneOrFail "Binding is required" (attribute "Binding" cursor)
        >>= parseBinding
    location <- oneOrFail "Location is required" $ attribute "Location" cursor
    pure (binding, location)

parseBinding :: MonadFail m => Text -> m Binding
parseBinding = \case
    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" -> pure HTTPArtifact
    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" -> pure HTTPPost
    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" -> pure HTTPRedirect
    "urn:oasis:names:tc:SAML:2.0:bindings:PAOS" -> pure PAOS
    "urn:oasis:names:tc:SAML:2.0:bindings:SOAP" -> pure SOAP
    "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE"
        -> pure URLEncodingDEFLATE
    other -> fail $ "Unknown Binding: " <> show other
