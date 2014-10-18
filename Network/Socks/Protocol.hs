{-
 - ----------------------------------------------------------------------------
 - "THE BEER-WARE LICENSE" (Revision 42):
 - <code@gregorkopf.de> wrote this file. As long as you retain this notice you
 - can do whatever you want with this stuff. If we meet some day, and you
 - think this stuff is worth it, you can buy me a beer in return Gregor Kopf
 - ----------------------------------------------------------------------------
 -}

{-| The SOCKS5 network messages as described in RFC1928 -}

module Network.Socks.Protocol (SocksAuthMethod(..), SocksAddrSpec(..),
                               SocksRequest(..), SocksReply(..),
                               buildServerVersionAuth, buildSocksReply,
                               parseVersionAuth, parseSocksRequest) where

import           Control.Monad
import           Data.Attoparsec.ByteString as AP
import           Data.List
import qualified Data.ByteString as BS
import           Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as C8
import           Data.IP
import           GHC.Word
import           Control.Applicative

-- |Socks authentication method. The client sends a list of supported
-- authentication methods to the server, which selects one of those methods in
-- its response.
data SocksAuthMethod = SocksNoAuth -- ^ No authentication needed
                     | SocksGssapi -- ^ GSSAPI Authentication
                     | SocksUsernamePassword -- ^ Username and password
                     | SocksIana Word8 -- ^ IANA assigned numbers
                     | SocksPrivate Word8 -- ^ Private authentication methods
                     | SocksNoAcceptableAuthMethods -- ^ Only sent by the server
                                                    -- to signal that no
                                                    -- authentication methods
                                                    -- advertised by the client
                                                    -- are supported
                     deriving (Show, Read, Eq)

-- |Socks network address. SOCKS5 supports IPv4 and IPv6 addresses, as well as
-- fully qualified domain names.
data SocksAddrSpec = SocksAddrIPv4 IPv4 -- ^ An IPv4 address
                   | SocksAddrIPv6 IPv6  -- ^ An IPv6 address
                   | SocksAddrFqdn String  -- ^ A fully qualified domain name
                   deriving (Show, Read, Eq)

-- |Socks request. Sent by the client.
data SocksRequest = SocksCmdConnect SocksAddrSpec Int -- ^ SOCKS5 connect request
                  | SocksCmdBind SocksAddrSpec Int -- ^ SOCKS5 bind request
                  | SocksCmdAsssociate SocksAddrSpec Int -- ^ SOCKS5 associate 
                                                         -- request
                  deriving (Show, Read, Eq)

-- |Socks reply. Sent by the server.
data SocksReply = SocksReplySuccess SocksAddrSpec Int -- ^ Success request: the 
                                                      -- server tells the client
                                                      -- the IP address and port
                                                      -- number used for
                                                      -- connecting to the
                                                      -- remote host
                | SocksReplyGeneralFailure -- ^ A general failure
                | SocksReplyConnectionNotAllowed -- ^ Connection not allowed
                | SocksReplyNetworkUnreachable -- ^ Network unreachable
                | SocksReplyHostUnreachable -- ^ Host unreachable
                | SocksReplyConnectionRefused -- ^ Connection refused
                | SocksReplyTTLExpired -- ^ TTL expired
                | SocksReplyCommandNotSupported -- ^ The client sent an
                                                -- unsupported command
                | SocksReplyAddressTypeNotSupported -- ^ Address type not supported
                | SocksReplyUnassigned Word8 -- ^ Custom reply code
                deriving (Show, Read, Eq)

-- Serialization routines

serializeAuthMethod :: SocksAuthMethod -> Word8
serializeAuthMethod SocksNoAuth = 0
serializeAuthMethod SocksGssapi = 1
serializeAuthMethod SocksUsernamePassword = 2
serializeAuthMethod (SocksIana w) | w >= 3 && w <= 0x7F = w
                                  | otherwise = error "Illegal auth method."
serializeAuthMethod (SocksPrivate w) | w >= 0x80 && w <= 0xFE = w
                                     | otherwise = error "Illegal auth method."
serializeAuthMethod SocksNoAcceptableAuthMethods = 0xFF

-- |Generates a ByteString representing the packet that contains the
-- server-selected authentication method.
buildServerVersionAuth :: SocksAuthMethod -> ByteString
buildServerVersionAuth authMethod =
   BS.pack [5, serializeAuthMethod authMethod]

-- |Generates a ByteString representing the packet fro a given SocksReply.
buildSocksReply :: SocksReply -> ByteString
buildSocksReply (SocksReplySuccess adr port) = 
   (BS.pack [5, 0, 0]) `BS.append` (buildSocksAddr adr) `BS.append` 
   buildSocksPort port
buildSocksReply SocksReplyGeneralFailure = 
   BS.append (BS.pack [5, 1]) socksReplyEmpty
buildSocksReply SocksReplyConnectionNotAllowed = 
   BS.append (BS.pack [5, 2]) socksReplyEmpty
buildSocksReply SocksReplyNetworkUnreachable = 
   BS.append (BS.pack [5, 3]) socksReplyEmpty
buildSocksReply SocksReplyHostUnreachable = 
   BS.append (BS.pack [5, 4]) socksReplyEmpty
buildSocksReply SocksReplyConnectionRefused = 
   BS.append (BS.pack [5, 5]) socksReplyEmpty
buildSocksReply SocksReplyTTLExpired = 
   BS.append (BS.pack [5, 6]) socksReplyEmpty
buildSocksReply SocksReplyCommandNotSupported = 
   BS.append (BS.pack [5, 7]) socksReplyEmpty
buildSocksReply SocksReplyAddressTypeNotSupported = 
   BS.append (BS.pack [5, 8]) socksReplyEmpty
buildSocksReply (SocksReplyUnassigned w) 
   | w >= 9 && w <= 0xFF = BS.append (BS.pack [5, w]) socksReplyEmpty
   | otherwise = error "Illegal socks reply"

socksReplyEmpty :: ByteString -- An empty Socks5 reply body
socksReplyEmpty = BS.pack [0, 1, 0, 0, 0, 0, 0, 0]

buildSocksAddr :: SocksAddrSpec -> ByteString
buildSocksAddr (SocksAddrIPv4 ipv4) = 
   BS.pack (1:map fromIntegral (fromIPv4 ipv4))
buildSocksAddr (SocksAddrIPv6 ipv6) =
   BS.pack (4:concat (map mkTwoWord8 (fromIPv6 ipv6)))
buildSocksAddr (SocksAddrFqdn name)
   | length name >= 256 = error "FQDN too long."
   | otherwise = BS.append (BS.pack [3, fromIntegral $ length name])
                           (C8.pack name)

buildSocksPort :: Int -> ByteString
buildSocksPort = BS.pack . mkTwoWord8

mkTwoWord8 :: Int -> [Word8]
mkTwoWord8 x = [fromIntegral $ x `div` 256, fromIntegral $ x `mod` 256]

-- Parsing routines

mkAuthMethod :: Word8 -> SocksAuthMethod
mkAuthMethod m | m == 0 = SocksNoAuth
               | m == 1 = SocksGssapi
               | m == 2 = SocksUsernamePassword
               | m >= 3 && m <= 0x7F = SocksIana m
               | m >= 0x80 && m <= 0xFE = SocksPrivate m
               | otherwise = SocksNoAcceptableAuthMethods

-- |An Attoparsec parser that parses the initial message sent by the client and
-- returns a list of client-advertised authentication methods.
parseVersionAuth :: Parser [SocksAuthMethod]
parseVersionAuth = do
   word8 5 -- We only handle Socks version 5.
   numMethods <- anyWord8
   methods    <- AP.take (fromIntegral numMethods)
   return $ nub $ map mkAuthMethod $ BS.unpack methods

parseSocksCommand :: Parser Word8
parseSocksCommand = word8 1 <|> word8 2 <|> word8 3

parseSocksPortNumber :: Parser Int
parseSocksPortNumber = do
   x <- anyWord8
   y <- anyWord8
   return $ (fromIntegral x) * 256 + (fromIntegral y)

parseSocksAddress :: Parser SocksAddrSpec
parseSocksAddress = 
   (word8 1 >> parseIPv4) <|> (word8 3 >> parseFQDN) <|> (word8 4 >> parseIPv6)

parseIPv4 :: Parser SocksAddrSpec
parseIPv4 = do
   adr <- forM [1..4] (\_ -> anyWord8)
   return $ SocksAddrIPv4 $ toIPv4 $ map fromIntegral adr

parseIPv6 :: Parser SocksAddrSpec
parseIPv6 = do
   adr <- forM [1..8] (\_ -> twoByte)
   return $ SocksAddrIPv6 $ toIPv6 adr
   where twoByte = do x1 <- anyWord8
                      x2 <- anyWord8
                      return $ (fromIntegral x1) * 256 + (fromIntegral x2)

parseFQDN :: Parser SocksAddrSpec
parseFQDN = do
   len <- anyWord8
   (SocksAddrFqdn . C8.unpack . BS.pack ) <$> forM [1..(fromIntegral len)] 
                                              (\_ -> anyWord8)

-- |An Attoparsec parses that parses a SOCKS request sent by the client.
parseSocksRequest :: Parser SocksRequest
parseSocksRequest = do
   word8 5 -- We only handle Socks version 5.
   cmd         <- parseSocksCommand
   anyWord8 -- Reserved field - we accept everything here
   addr        <- parseSocksAddress
   port        <- parseSocksPortNumber
   return $ case cmd of
               1 -> SocksCmdConnect addr port
               2 -> SocksCmdBind addr port
               3 -> SocksCmdAsssociate addr port
