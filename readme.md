# Overview
This is a simple library, implementing a SOCKS5 proxy. There is haddock
documentation available, which describes the API. For a real quick-start, open
Network/Socks/Server.hs in ghci and type:
<pre>
forkingSocksServer "127.0.0.1" 1080 [SocksNoAuth] alwaysSucceedAuthenticator simpleRequestHandler
</pre>
You should then be able to use localhost:1080 as a socks proxy. To try it, you
can use your web browser or simply netcat:
<pre>
nc -v -X 5 -x 127.0.0.1:1080 google.com 80
</pre>
