openssl req -new -newkey rsa:4096 -nodes -subj "/CN=default\/emailAddress=default/C=US/ST=default/L=default/O=default/OU=default" -keyout tmp.key -out tmp.csr
openssl x509 -req -sha256 -days 365 -in tmp.csr -signkey tmp.key -out tmp.pem
cat tmp.key > cert.pem
cat tmp.pem >> cert.pem