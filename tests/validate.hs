{-# LANGUAGE LambdaCase #-}
import Crypto.PubKey.RSA (PublicKey)
import Crypto.Hash
import Control.Monad.Except

import Network.Wai.SAML2
import Network.Wai.SAML2.C14N
import Network.Wai.SAML2.Validation
import Network.Wai.SAML2.Response
import Text.XML
import RIO
import System.Environment
import qualified Data.ByteString.Base64 as BS
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.X509 as X509
import qualified Data.X509.Memory as X509
import qualified Text.XML as XML
import qualified Text.XML.Cursor as XML

parseCertificate :: ByteString -> PublicKey
parseCertificate certificate = case X509.readSignedObjectFromMemory certificate of
    [signedCert] -> case X509.certPubKey $ X509.signedObject $ X509.getSigned signedCert of
        X509.PubKeyRSA key -> key
        other -> error $ "Expected PubKeyRSA, but got " <> show other
    xs -> error $ show xs

main :: IO ()
main = getArgs >>= \case
    [certPath, path] -> do
        cert <- readFileBinary certPath
        let pub = parseCertificate cert
            cfg = saml2ConfigNoEncryption pub
        bs <- BS.init <$> readFileBinary path
        normalised <- runExceptT $ do 
            (responseXmlDoc, _samlResponse) <- decodeResponse bs 
            let docMinusSignature = removeSignature responseXmlDoc

            -- then render the resulting document and canonicalise it
            let renderedXml = XML.renderLBS def docMinusSignature
            refCanonResult <- liftIO $ try $ canonicalise (LBS.toStrict renderedXml)

            normalised <- case refCanonResult of
                Left err -> throwError $ CanonicalisationFailure err
                Right result -> pure result

            pure normalised
        case normalised of
            Left err -> print $ show err
            Right n -> BS.putStrLn n
        result <- validateResponse cfg bs
        print result
    [path] -> do
        normalised <- readFileBinary path
        print $ hashWith SHA256 normalised
    _ -> fail "cabal run validate okta.crt okta.b64"
