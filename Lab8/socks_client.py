#!/usr/bin/env python3
import socks

# Set up a SOCKS5 proxy
proxy_ip = "192.168.20.99"  # Host B's IP
proxy_port = 1080          
s = socks.socksocket()
s.set_proxy(socks.SOCKS5, proxy_ip, proxy_port)

# Connect to the target server
server_ip = "93.184.215.14"  # www.example.com's exact IP address
server_port = 80             
s.connect((server_ip, server_port))

# Send an HTTP GET request
hostname = "www.example.com"
req = b"GET / HTTP/1.0\r\nHost: " + hostname.encode('utf-8') + b"\r\n\r\n"
s.sendall(req)

# Receive and print the HTTP response
response = s.recv(2048)
while response:
    print(response.decode('utf-8'))
    response = s.recv(2048)
