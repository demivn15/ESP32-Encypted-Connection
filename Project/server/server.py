import socket

print("Creating server...")
s = socket.socket()
s.bind(('0.0.0.0', 5000))
s.listen(1)

while True:
    client, addr = s.accept()
    while True:
        content = client.recv(32)
        if len(content) == 0:
            break
        else:
            print(content)
    print("Closing connection")
    client.close()