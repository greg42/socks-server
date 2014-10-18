{-
 - ----------------------------------------------------------------------------
 - "THE BEER-WARE LICENSE" (Revision 42):
 - <code@gregorkopf.de> wrote this file. As long as you retain this notice you
 - can do whatever you want with this stuff. If we meet some day, and you
 - think this stuff is worth it, you can buy me a beer in return Gregor Kopf
 - ----------------------------------------------------------------------------
 -}

module Network.TCPServer where

import Prelude 
import Network
import Network.Socket
import System.IO
import Control.Exception as E
import Control.Concurrent
import System.Log.Logger

logError :: String -> IO ()
logError = errorM "TCPServer"

logInfo :: String -> IO ()
logInfo  = infoM  "TCPServer"

-- |A TCP connection
data Connection = Connection {
   connHandle :: Handle
 , connPeerName :: String
 , connPort :: PortNumber
 }

-- |A simple abstration for a forking TCP server.
forkingTcpServer ::    String -- ^ The host name to listen on
                    -> Int -- ^ The port number to listen on
                    -> (Connection -> IO ()) -- ^ A handler function
                    -> IO ()
forkingTcpServer hostname port handler = 
    withSocketsDo $ do
         host <- inet_addr hostname
         sock <- socket AF_INET Stream 0
         setSocketOption sock ReuseAddr 1
         bindSocket sock (SockAddrInet (fromIntegral port) host)
         listen sock 0
         (acceptConn sock handler) `catch` interrupted sock
    where interrupted = \s ex -> do
                          let err = show (ex :: SomeException)
                          logInfo "Closing socket."
                          logError $ "Caught exception: " ++ err
                          Network.Socket.sClose s

acceptConn :: Socket -> (Connection -> IO ()) -> IO ()
acceptConn sock handler = do
  (h,n,p) <- Network.accept sock
  let conn = Connection h n p
  hSetBuffering (connHandle conn) NoBuffering
  _ <- forkIO $ (handler conn) `catch` disconnected `finally` disconnect conn
  acceptConn sock handler
  where disconnected = \ex -> do
                         let err = show (ex :: IOException)
                         logError $ "Failed to echo: " ++ err

disconnect :: Connection -> IO ()
disconnect conn = do
  hClose (connHandle conn)
  logInfo $ "Disconnecting " ++ (connPeerName conn) ++ "."
