import http.server, ssl

server_ip = 'localhost'
server_port = 4443

print(f"Running at https://{server_ip}:{server_port}")

server_address = ('localhost', 4443)
httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket,
                               server_side=True,
                               certfile='cert.pem',
                               ssl_version=ssl.PROTOCOL_TLS)
httpd.serve_forever()