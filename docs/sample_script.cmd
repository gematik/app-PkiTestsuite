echo "Parameters: %*"
set certPath=%1
set certPasswd=%2
set ocspDelay=%3
echo "Hello Sample Script!"
"c:\Program Files\OpenJDK\jdk-17.0.2\bin\java" -version
"c:\Program Files\OpenJDK\jdk-17.0.2\bin\java" -jar ..\pkits-tls-client\target\tlsClient.jar 127.0.0.1 8443 %certPath% %certPasswd%
