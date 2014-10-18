{-
 - ----------------------------------------------------------------------------
 - "THE BEER-WARE LICENSE" (Revision 42):
 - <code@gregorkopf.de> wrote this file. As long as you retain this notice you
 - can do whatever you want with this stuff. If we meet some day, and you
 - think this stuff is worth it, you can buy me a beer in return Gregor Kopf
 - ----------------------------------------------------------------------------
 -}

{-| A simple implementation of a SOCKS5 server. You can use the functions in
 - this module to build your own SOCKS implementation. -}

module Network.Socks.Server (SocksAuthenticator, SocksRequestHandler,
                             simpleRequestHandler, alwaysSucceedAuthenticator,
                             forkingSocksServer) where

import           Network.Socks.Protocol
import           Network.TCPServer
import           Control.Concurrent.Chan
import qualified Data.ByteString as BS
import           Data.ByteString (ByteString)
import           Data.Attoparsec.ByteString
import           Data.List
import           Control.Monad
import           Network
import qualified Control.Exception as E
import           System.IO
import           Control.Concurrent

-- |A SocksAuthenticator is an IO action that takes an authentication method
-- and a Connection. It does what it needs to do to perform the authentication
-- and returns whether is was successful or not.
type SocksAuthenticator  = SocksAuthMethod -> Connection -> IO Bool

-- |A SocksRequestHandler is an IO action that takes *one* SocksRequest,
-- a Connection and an initial input that was already read from the Connection's
-- Handle.
type SocksRequestHandler = SocksRequest -> Connection -> ByteString -> IO ()

-- |An insecure(!) authenticator that always succeeds.
alwaysSucceedAuthenticator :: SocksAuthenticator
alwaysSucceedAuthenticator _ _ = return True

-- |A simple SOCKS request handler. It will only handle Connect requests.
simpleRequestHandler :: SocksRequestHandler
simpleRequestHandler (SocksCmdConnect addr port) conn clientData = do
   let host = case addr of
                 SocksAddrIPv4 ipv4 -> show ipv4
                 SocksAddrIPv6 ipv6 -> show ipv6
                 SocksAddrFqdn name -> name
   hdl <- E.try $ connectTo host (PortNumber $ fromIntegral port)
   case hdl of
      Right handle -> do let rep = buildSocksReply $ SocksReplySuccess
                                                     -- XXX This is an ugly hack
                                                     (SocksAddrIPv4 (read "127.0.0.1")) 1
                         BS.hPut (connHandle conn) rep
                         hSetBuffering handle NoBuffering
                         _ <- forkIO $ proxy handle (connHandle conn)
                         proxy (connHandle conn) handle
      Left  e -> let e' = e :: E.SomeException in putStrLn $ show e
   where proxy hdl1 hdl2 = do buf <- BS.hGetSome hdl1 1024
                              if BS.length buf == 0
                                then hClose hdl2 
                                else do BS.hPut hdl2 buf
                                        proxy hdl1 hdl2

simpleRequestHandler _ conn clientData = return ()

-- |A simple forking TCP server that handles SOCKS5 requests.
forkingSocksServer ::   String -- ^ Host name to listen on
                     -> Int -- ^ Port number to bind
                     -> [SocksAuthMethod] -- ^ Supported authentication methods,
                                          --   ordered by priority
                     -> SocksAuthenticator -- ^ Authenticator action
                     -> SocksRequestHandler -- ^ Request handler action
                     -> IO ()
forkingSocksServer host port supportedAuthMethods authenticator handler =
   forkingTcpServer host port $ \conn -> do
      presult <- parseWith (BS.hGetSome (connHandle conn) 1024)
                           parseVersionAuth 
                           BS.empty
      let (bs, am) = case presult of
                        Done i r     -> (i, r)
                        Fail _ _ msg -> error msg
      case find (`elem` am) supportedAuthMethods of
         Just am -> do BS.hPut (connHandle conn) $ buildServerVersionAuth am
                       authOk <- authenticator am conn
                       when (not authOk) $ error "Authentication failed."
         Nothing -> error "No supported authentication method."
      
      preq <- parseWith (BS.hGetSome (connHandle conn) 1024)
                        parseSocksRequest
                        bs
      case preq of
         Done i r -> handler r conn i
         _        -> error "Cannot parse request."
