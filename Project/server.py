import socket
from threading import Thread
import json
from config import SERVER_ADDRESS, BUFSIZE

clients = {}

def broadcast(data):
    for client in clients:
        client.send(bytes(json.dumps(data), 'utf8'))

def handle_client(client):
    while True:
        try:
            data = client.recv(BUFSIZE).decode('utf8')
            if data:
                msg = json.loads(data)
                print(msg)

                if msg.get('type') == 'init':
                    clients[client] = msg

                    if len(clients) < 2:
                        client.send(bytes(json.dumps({'type': 'chat_wait', 'text': 'Waiting for others to join...'}), 'utf8'))
                    else:
                        for client1 in clients:
                            for client2 in clients:
                                if client1 != client2:
                                    client1.send(bytes(json.dumps(clients[client2]), 'utf8'))
                                    client1.send(bytes(json.dumps({'type': 'chat_ready', 'text': 'Both clients connected. Click Start Chat to begin chatting."'}), 'utf8'))

                if msg.get('type') == 'message':
                    if msg.get('text') == 'quit':
                        raise Exception('quit')

                    msg['name'] = clients[client].get('name')
                    broadcast(msg)

        except Exception as e:
            if client in clients:
                del clients[client]
            client.close()
            break



if __name__ == '__main__':

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print('[INFO] Server at localhost:8000')
    server.bind(SERVER_ADDRESS)
    server.listen(1)

    while True:
        client, addr = server.accept()
        if len(clients) == 2:
            client.send(bytes(json.dumps({'type': 'system', 'text': 'quit'}),'utf8'))
            # system_message(client, 'quit')
            client.close()
        else:
            Thread(target=handle_client, args=(client,)).start()

    server.close()
