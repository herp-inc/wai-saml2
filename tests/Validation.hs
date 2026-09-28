module Validation where

import Control.Monad.Trans.Except
import Crypto.PubKey.RSA (PublicKey)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base64 as Base64
import Data.Time.Format.ISO8601
import qualified Data.X509 as X509
import qualified Data.X509.Memory as X509
import Network.Wai.SAML2
import Network.Wai.SAML2.Validation
import System.FilePath
import Test.Tasty
import Test.Tasty.HUnit

-- | Get a public key from a X.509 certificate
parseCertificate :: B.ByteString -> PublicKey
parseCertificate certificate = case X509.readSignedObjectFromMemory certificate of
    [signedCert] -> case X509.certPubKey $ X509.signedObject $ X509.getSigned signedCert of
        X509.PubKeyRSA key -> key
        other -> error $ "Expected PubKeyRSA, but got " <> show other
    xs -> error $ show xs

run :: FilePath -> String -> FilePath -> IO ()
run certPath timestamp respPath = do
    cert <- B.readFile $ prefix </> certPath
    xml <- B.readFile $ prefix </> respPath
    now <- iso8601ParseM timestamp

    let pub = parseCertificate cert
        cfg = (saml2ConfigNoEncryption pub) {
            saml2ValidationTarget = ValidateEither
        }

    assertion <- runExceptT $ do
        (responseXmlDoc, samlResponse) <- decodeResponse $ Base64.encode xml
        validateSAMLResponse cfg responseXmlDoc samlResponse now

    case assertion of
        Left err -> assertFailure $ show err
        Right _ -> pure ()

runReject :: FilePath -> String -> FilePath -> IO ()
runReject certPath timestamp respPath = do
    cert <- B.readFile $ prefix </> certPath
    xml <- B.readFile $ prefix </> respPath
    now <- iso8601ParseM timestamp

    let pub = parseCertificate cert
        cfg = (saml2ConfigNoEncryption pub) {
            saml2ValidationTarget = ValidateEither
        }
        tampered = replaceDigest xml

    result <- runExceptT $ do
        (responseXmlDoc, samlResponse) <- decodeResponse $ Base64.encode tampered
        validateSAMLResponse cfg responseXmlDoc samlResponse now

    case result of
        Left InvalidDigest -> pure ()
        Left err -> assertFailure $ show err
        Right _ -> assertFailure "expected InvalidDigest"

-- | Replace the first digest with a different value of the same length.
replaceDigest :: B.ByteString -> B.ByteString
replaceDigest xml =
    let open = "<ds:DigestValue>"
        close = "</ds:DigestValue>"
        (before, rest) = B.breakSubstring open xml
        afterOpen = B.drop (B.length open) rest
        (value, afterValue) = B.breakSubstring close afterOpen
    in B.concat
        [ before
        , open
        , B.replicate (B.length value) 65
        , afterValue
        ]

prefix :: FilePath
prefix = "tests/data"

tests :: TestTree
tests = testGroup "Validate SAML2 Response"
    [ testCase "AzureAD signed response"
        $ run "azuread.crt" "2023-05-10T01:20:00Z" "azuread-signed-response.xml"
    , testCase "AzureAD signed assertion"
        $ run "azuread.crt" "2023-05-09T16:00:00Z" "azuread-signed-assertion.xml"
    , testCase "Okta with AttributeStatement"
        $ run "okta.crt" "2023-06-16T06:43:00.000Z" "okta-attributes.xml"
    , testCase "whitespace-preserving response signature"
        $ run "whitespace.crt" "2024-01-15T12:00:00Z" "whitespace-signed-response.xml"
    , testCase "whitespace-preserving assertion signature"
        $ run "whitespace.crt" "2024-01-15T12:00:00Z" "whitespace-signed-assertion.xml"
    , testCase "rejects a digest that does not match"
        $ runReject "whitespace.crt" "2024-01-15T12:00:00Z" "whitespace-signed-response.xml"
    ]
