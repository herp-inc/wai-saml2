--------------------------------------------------------------------------------
-- SAML2 Middleware for WAI                                                   --
--------------------------------------------------------------------------------
-- This source code is licensed under the MIT license found in the LICENSE    --
-- file in the root directory of this source tree.                            --
--------------------------------------------------------------------------------

-- | Cut signature material out of the original SAML XML bytes.
--
-- Re-rendering a parsed document can drop whitespace-only text nodes.
-- These functions keep the bytes the identity provider signed and only
-- remove the enveloped signature, or copy a subtree out with the
-- namespace declarations it needs.
module Network.Wai.SAML2.XML.Source (
    stripEnvelopedSignatures,
    extractAssertion,
    extractSignedInfo
) where

--------------------------------------------------------------------------------

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import Data.List (sort)
import qualified Data.Map.Strict as Map
import Data.Word (Word8)

--------------------------------------------------------------------------------

-- | XML Signature namespace.
xmlDsigNs :: BS.ByteString
xmlDsigNs = BS8.pack "http://www.w3.org/2000/09/xmldsig#"

-- | SAML 2.0 assertion namespace.
samlAssertionNs :: BS.ByteString
samlAssertionNs = BS8.pack "urn:oasis:names:tc:SAML:2.0:assertion"

-- | Namespace bound to the @xml@ prefix.
xmlNamespace :: BS.ByteString
xmlNamespace = BS8.pack "http://www.w3.org/XML/1998/namespace"

-- | Prefix @xml@.
xmlPrefix :: BS.ByteString
xmlPrefix = BS8.pack "xml"

-- | In-scope namespace prefixes. The empty prefix is the default namespace.
type NsMap = Map.Map BS.ByteString BS.ByteString

-- | One element in the original byte string.
data Elem = Elem
    { elStart :: !Int
    , elEnd :: !Int
    , elOpenEnd :: !Int
    , elLocal :: !BS.ByteString
    , elNs :: !BS.ByteString
    , elAttrs :: ![(BS.ByteString, BS.ByteString)]
    , elChildren :: ![Elem]
    , elParentNs :: !NsMap
    }

-- | 'stripEnvelopedSignatures' @xml@ removes each @Signature@ element that
-- is a direct child of the document element. Surrounding text, including
-- whitespace-only text, is left in place.
stripEnvelopedSignatures :: BS.ByteString -> Either String BS.ByteString
stripEnvelopedSignatures xml = do
    root <- parseDocument xml
    let ranges =
            [ (elStart el, elEnd el)
            | el <- elChildren root
            , elLocal el == BS8.pack "Signature"
            , elNs el == xmlDsigNs
            ]
    pure $ deleteRanges xml ranges

-- | 'extractAssertion' @xml assertionId@ copies the first @Assertion@ that
-- is a direct child of the document element, when its @ID@ is
-- @assertionId@. Nested assertions are ignored, so the copied element is
-- the one the response parser returns. Namespace declarations that are in
-- scope from an ancestor are repeated on the copied element.
-- A document that contains a DOCTYPE declaration is rejected.
extractAssertion :: BS.ByteString
                 -> BS.ByteString
                 -> Either String BS.ByteString
extractAssertion xml assertionId
    | containsDoctype xml = Left "DOCTYPE is not allowed"
    | otherwise = do
        root <- parseDocument xml
        el <- case findAssertion assertionId root of
            Just found -> pure found
            Nothing -> Left "Assertion was not found"
        pure $ materialise xml el

-- | 'True' when @xml@ contains a DOCTYPE declaration, ignoring case.
containsDoctype :: BS.ByteString -> Bool
containsDoctype xml =
    BS.isInfixOf (BS8.pack "<!doctype") (BS.map asciiLower xml)
    where
        asciiLower w
            | w >= 65 && w <= 90 = w + 32
            | otherwise = w

-- | 'extractSignedInfo' @xml@ copies the @SignedInfo@ element from the
-- first direct-child @Signature@ of the document element. Namespace
-- declarations in scope from an ancestor are repeated on the copy.
extractSignedInfo :: BS.ByteString -> Either String BS.ByteString
extractSignedInfo xml = do
    root <- parseDocument xml
    sig <- case directChild xmlDsigNs (BS8.pack "Signature") root of
        Just found -> pure found
        Nothing -> Left "Signature was not found"
    info <- case directChild xmlDsigNs (BS8.pack "SignedInfo") sig of
        Just found -> pure found
        Nothing -> Left "SignedInfo was not found"
    pure $ materialise xml info

-- | Find a direct child with the given namespace and local name.
directChild :: BS.ByteString -> BS.ByteString -> Elem -> Maybe Elem
directChild ns local parent = case
    [ el
    | el <- elChildren parent
    , elNs el == ns
    , elLocal el == local
    ] of
        (el:_) -> Just el
        [] -> Nothing

-- | The first direct-child assertion, when its @ID@ is @assertionId@.
-- This follows the response parser, which reads that same element and
-- ignores assertions nested inside other elements.
findAssertion :: BS.ByteString -> Elem -> Maybe Elem
findAssertion assertionId root = case
    [ el
    | el <- elChildren root
    , elNs el == samlAssertionNs
    , elLocal el == BS8.pack "Assertion"
    ] of
        (el:_)
            | lookupAttr (BS8.pack "ID") (elAttrs el) == Just assertionId ->
                Just el
        _ -> Nothing

-- | Look up an attribute by its raw name.
lookupAttr :: BS.ByteString
           -> [(BS.ByteString, BS.ByteString)]
           -> Maybe BS.ByteString
lookupAttr name attrs = lookup name attrs

-- | Copy @el@ and repeat ancestor namespace declarations on its start tag.
materialise :: BS.ByteString -> Elem -> BS.ByteString
materialise xml el =
    BS.concat
        [ BS.take relGt slice
        , renderDecls extra
        , BS.drop relGt slice
        ]
    where
        slice = BS.take (elEnd el - elStart el) (BS.drop (elStart el) xml)
        relGt = elOpenEnd el - elStart el - 1
        declared = xmlnsMap (elAttrs el)
        parent = Map.delete xmlPrefix (elParentNs el)
        extra = Map.difference parent declared

-- | Render namespace declarations, omitting the built-in @xml@ prefix.
renderDecls :: NsMap -> BS.ByteString
renderDecls nsMap = BS.concat
    [ renderDecl prefix uri
    | (prefix, uri) <- Map.toList nsMap
    , prefix /= xmlPrefix
    ]

-- | Render one namespace declaration.
renderDecl :: BS.ByteString -> BS.ByteString -> BS.ByteString
renderDecl prefix uri
    | BS.null prefix = BS.concat
        [ BS8.pack " xmlns=\""
        , escapeAttr uri
        , BS8.pack "\""
        ]
    | otherwise = BS.concat
        [ BS8.pack " xmlns:"
        , prefix
        , BS8.pack "=\""
        , escapeAttr uri
        , BS8.pack "\""
        ]

-- | Escape characters that would end an attribute value.
escapeAttr :: BS.ByteString -> BS.ByteString
escapeAttr = BS8.concatMap escape
    where
        escape '&' = BS8.pack "&amp;"
        escape '"' = BS8.pack "&quot;"
        escape c = BS8.singleton c

-- | Delete half-open ranges, highest offset first.
deleteRanges :: BS.ByteString -> [(Int, Int)] -> BS.ByteString
deleteRanges bs ranges = foldl cut bs (reverse (sort ranges))
    where
        cut acc (start, end) = BS.take start acc <> BS.drop end acc

-- | Namespace declarations on an element.
xmlnsMap :: [(BS.ByteString, BS.ByteString)] -> NsMap
xmlnsMap attrs = Map.fromList
    [ binding
    | (name, value) <- attrs
    , Just binding <- [xmlnsBinding name value]
    ]

-- | Interpret one attribute as a namespace declaration, if it is one.
xmlnsBinding :: BS.ByteString
             -> BS.ByteString
             -> Maybe (BS.ByteString, BS.ByteString)
xmlnsBinding name value
    | name == BS8.pack "xmlns" = Just (BS.empty, value)
    | BS8.pack "xmlns:" `BS.isPrefixOf` name =
        Just (BS.drop 6 name, value)
    | otherwise = Nothing

-- | Add this element's namespace declarations to the parent map.
applyNs :: NsMap -> [(BS.ByteString, BS.ByteString)] -> NsMap
applyNs parent attrs = Map.union (xmlnsMap attrs) parent

-- | Resolve a prefix in @nsMap@. The empty prefix selects the default
-- namespace. An unbound prefix does not match a signed element.
resolveNs :: NsMap -> BS.ByteString -> BS.ByteString
resolveNs nsMap prefix = Map.findWithDefault BS.empty prefix nsMap

-- | Split a qualified name into a prefix and a local name.
splitQName :: BS.ByteString -> (BS.ByteString, BS.ByteString)
splitQName qname = case BS.elemIndex colon qname of
    Nothing -> (BS.empty, qname)
    Just i -> (BS.take i qname, BS.drop (i + 1) qname)
    where
        colon = 58 :: Word8

--------------------------------------------------------------------------------

-- | Parse the document element, skipping a prologue.
parseDocument :: BS.ByteString -> Either String Elem
parseDocument bs = do
    i <- skipMisc bs (skipBom bs)
    (el, _) <- parseElement initialNs bs i
    pure el
    where
        initialNs = Map.singleton xmlPrefix xmlNamespace

-- | Skip a leading UTF-8 byte order mark.
skipBom :: BS.ByteString -> Int
skipBom bs
    | BS.take 3 bs == BS.pack [0xEF, 0xBB, 0xBF] = 3
    | otherwise = 0

-- | Skip whitespace, comments, and processing instructions before the root.
skipMisc :: BS.ByteString -> Int -> Either String Int
skipMisc bs i = do
    j <- skipSpaces bs i
    case byteAt bs j of
        Just 60 -- '<'
            | matchAt bs (j + 1) (BS8.pack "?") ->
                skipMisc bs =<< skipTo bs (j + 2) (BS8.pack "?>")
            | matchAt bs (j + 1) (BS8.pack "!--") ->
                skipMisc bs =<< skipTo bs (j + 4) (BS8.pack "-->")
            | matchAt bs (j + 1) (BS8.pack "!") ->
                skipMisc bs =<< skipTo bs (j + 2) (BS8.pack ">")
            | otherwise -> pure j
        _ -> Left "XML document has no root element"

-- | Parse the element that starts at @i@.
parseElement :: NsMap -> BS.ByteString -> Int -> Either String (Elem, Int)
parseElement parentNs bs i
    | byteAt bs i /= Just 60 = Left "expected an element"
    | otherwise = do
        (qname, attrs, empty, afterTag) <- parseStartTag bs (i + 1)
        let nsMap = applyNs parentNs attrs
            (prefix, local) = splitQName qname
            el = Elem
                { elStart = i
                , elEnd = afterTag
                , elOpenEnd = afterTag
                , elLocal = local
                , elNs = resolveNs nsMap prefix
                , elAttrs = attrs
                , elChildren = []
                , elParentNs = parentNs
                }
        if empty
            then pure (el, afterTag)
            else do
                (children, endAt) <- parseChildren qname nsMap bs afterTag
                pure (el { elChildren = children, elEnd = endAt }, endAt)

-- | Parse the body of an element until its end tag.
parseChildren :: BS.ByteString
              -> NsMap
              -> BS.ByteString
              -> Int
              -> Either String ([Elem], Int)
parseChildren qname nsMap bs i = go i []
    where
        go j acc = do
            k <- nextMarkup bs j
            if matchAt bs (k + 1) (BS8.pack "/")
                then do
                    endAt <- parseEndTag bs k qname
                    pure (reverse acc, endAt)
                else if matchAt bs (k + 1) (BS8.pack "!--")
                    then goNext acc =<< skipTo bs (k + 4) (BS8.pack "-->")
                else if matchAt bs (k + 1) (BS8.pack "?")
                    then goNext acc =<< skipTo bs (k + 2) (BS8.pack "?>")
                else if matchAt bs (k + 1) (BS8.pack "![CDATA[")
                    then goNext acc =<< skipTo bs (k + 9) (BS8.pack "]]>")
                else do
                    (child, j2) <- parseElement nsMap bs k
                    go j2 (child : acc)
        goNext acc j = go j acc

-- | Index of the next @'<'@ at or after @i@.
nextMarkup :: BS.ByteString -> Int -> Either String Int
nextMarkup bs i = case BS.elemIndex 60 (BS.drop i bs) of
    Just rel -> pure (i + rel)
    Nothing -> Left "unclosed element"

-- | Parse an end tag and check that its name is @expected@.
parseEndTag :: BS.ByteString -> Int -> BS.ByteString -> Either String Int
parseEndTag bs i expected = do
    (name, j0) <- readToken bs (i + 2)
    j1 <- skipSpaces bs j0
    case byteAt bs j1 of
        Just 62
            | name == expected -> pure (j1 + 1)
            | otherwise -> Left "end tag does not match the start tag"
        _ -> Left "malformed end tag"

-- | Parse a start tag beginning just after @'<'@.
parseStartTag :: BS.ByteString
              -> Int
              -> Either String (BS.ByteString, [(BS.ByteString, BS.ByteString)], Bool, Int)
parseStartTag bs i = do
    (qname, j0) <- readToken bs i
    readAttrs bs j0 qname []

-- | Read attributes until the start tag ends.
readAttrs :: BS.ByteString
          -> Int
          -> BS.ByteString
          -> [(BS.ByteString, BS.ByteString)]
          -> Either String (BS.ByteString, [(BS.ByteString, BS.ByteString)], Bool, Int)
readAttrs bs i qname acc = do
    j <- skipSpaces bs i
    case byteAt bs j of
        Just 62 -> pure (qname, reverse acc, False, j + 1)
        Just 47 -> do
            j2 <- skipSpaces bs (j + 1)
            case byteAt bs j2 of
                Just 62 -> pure (qname, reverse acc, True, j2 + 1)
                _ -> Left "expected '/>'"
        Just _ -> do
            (attr, j3) <- readAttr bs j
            readAttrs bs j3 qname (attr : acc)
        Nothing -> Left "unclosed start tag"

-- | Read one attribute and its unescaped value.
readAttr :: BS.ByteString
         -> Int
         -> Either String ((BS.ByteString, BS.ByteString), Int)
readAttr bs i = do
    (name, j0) <- readToken bs i
    j1 <- skipSpaces bs j0
    case byteAt bs j1 of
        Just 61 -> pure ()
        _ -> Left "expected '='"
    j2 <- skipSpaces bs (j1 + 1)
    quote <- case byteAt bs j2 of
        Just 34 -> pure 34
        Just 39 -> pure 39
        _ -> Left "expected a quoted attribute value"
    case BS.elemIndex quote (BS.drop (j2 + 1) bs) of
        Nothing -> Left "unclosed attribute value"
        Just rel -> pure
            ( (name, unescape (BS.take rel (BS.drop (j2 + 1) bs)))
            , j2 + 1 + rel + 1
            )

-- | Read a name token.
readToken :: BS.ByteString -> Int -> Either String (BS.ByteString, Int)
readToken bs i = case byteAt bs i of
    Nothing -> Left "expected a name"
    Just w
        | isName w -> pure (BS.take len (BS.drop i bs), i + len)
        | otherwise -> Left "expected a name"
    where
        len = length (takeWhile isNameByte (BS.unpack (BS.drop i bs)))
        isNameByte c = isName c

-- | 'True' for characters that may appear in an XML name token here.
isName :: Word8 -> Bool
isName w = w == 58 || w == 95 || w == 45 || w == 46
    || (w >= 48 && w <= 57)
    || (w >= 65 && w <= 90)
    || (w >= 97 && w <= 122)

-- | Decode the predefined XML entities.
unescape :: BS.ByteString -> BS.ByteString
unescape bs = case BS.elemIndex 38 bs of
    Nothing -> bs
    Just i ->
        let (before, rest) = BS.splitAt i bs
        in case BS.elemIndex 59 rest of
            Nothing -> bs
            Just semi ->
                BS.concat
                    [ before
                    , decodeEnt (BS.take (semi - 1) (BS.drop 1 rest))
                    , unescape (BS.drop (semi + 1) rest)
                    ]

-- | Decode one entity name, not including the leading @'&'@.
decodeEnt :: BS.ByteString -> BS.ByteString
decodeEnt name
    | name == BS8.pack "amp" = BS8.pack "&"
    | name == BS8.pack "lt" = BS8.pack "<"
    | name == BS8.pack "gt" = BS8.pack ">"
    | name == BS8.pack "quot" = BS8.pack "\""
    | name == BS8.pack "apos" = BS8.pack "'"
    | BS8.pack "#" `BS.isPrefixOf` name = decodeNumeric (BS.drop 1 name)
    | otherwise = BS.concat [BS8.pack "&", name, BS8.pack ";"]

-- | Decode a decimal or hexadecimal numeric character reference.
decodeNumeric :: BS.ByteString -> BS.ByteString
decodeNumeric body
    | BS8.pack "x" `BS.isPrefixOf` body || BS8.pack "X" `BS.isPrefixOf` body =
        encodePoint (readHex (BS.drop 1 body))
    | otherwise = encodePoint (readDec body)

-- | Encode a Unicode code point as UTF-8. Unknown input is left empty.
encodePoint :: Int -> BS.ByteString
encodePoint n
    | n < 0x80 = BS.singleton (fromIntegral n)
    | n < 0x800 = BS.pack
        [ fromIntegral (0xC0 + n `div` 64)
        , fromIntegral (0x80 + n `mod` 64)
        ]
    | n < 0x10000 = BS.pack
        [ fromIntegral (0xE0 + n `div` 4096)
        , fromIntegral (0x80 + (n `div` 64) `mod` 64)
        , fromIntegral (0x80 + n `mod` 64)
        ]
    | n < 0x110000 = BS.pack
        [ fromIntegral (0xF0 + n `div` 262144)
        , fromIntegral (0x80 + (n `div` 4096) `mod` 64)
        , fromIntegral (0x80 + (n `div` 64) `mod` 64)
        , fromIntegral (0x80 + n `mod` 64)
        ]
    | otherwise = BS.empty

-- | Parse a decimal integer. Invalid digits yield @-1@.
readDec :: BS.ByteString -> Int
readDec bs
    | BS.null bs = -1
    | otherwise = go 0 (BS.unpack bs)
    where
        go acc [] = acc
        go acc (w:ws)
            | w >= 48 && w <= 57 = go (acc * 10 + fromIntegral (w - 48)) ws
            | otherwise = -1

-- | Parse a hexadecimal integer. Invalid digits yield @-1@.
readHex :: BS.ByteString -> Int
readHex bs
    | BS.null bs = -1
    | otherwise = go 0 (BS.unpack bs)
    where
        go acc [] = acc
        go acc (w:ws)
            | w >= 48 && w <= 57 =
                go (acc * 16 + fromIntegral (w - 48)) ws
            | w >= 65 && w <= 70 =
                go (acc * 16 + fromIntegral (w - 55)) ws
            | w >= 97 && w <= 102 =
                go (acc * 16 + fromIntegral (w - 87)) ws
            | otherwise = -1

-- | Skip XML whitespace.
skipSpaces :: BS.ByteString -> Int -> Either String Int
skipSpaces bs i = case byteAt bs i of
    Just w
        | isXmlSpace w -> skipSpaces bs (i + 1)
        | otherwise -> pure i
    Nothing -> pure i

-- | 'True' for space, tab, carriage return, and line feed.
isXmlSpace :: Word8 -> Bool
isXmlSpace w = w == 32 || w == 9 || w == 10 || w == 13

-- | Byte at an index, if it is in range.
byteAt :: BS.ByteString -> Int -> Maybe Word8
byteAt bs i
    | i >= 0 && i < BS.length bs = Just (BS.index bs i)
    | otherwise = Nothing

-- | 'True' when @pat@ occurs at @i@.
matchAt :: BS.ByteString -> Int -> BS.ByteString -> Bool
matchAt bs i pat = BS.take (BS.length pat) (BS.drop i bs) == pat

-- | Index just after the first occurrence of @pat@ at or after @i@.
skipTo :: BS.ByteString -> Int -> BS.ByteString -> Either String Int
skipTo bs i pat = go i
    where
        go j
            | j > BS.length bs - BS.length pat = Left "unclosed markup"
            | matchAt bs j pat = pure (j + BS.length pat)
            | otherwise = go (j + 1)
