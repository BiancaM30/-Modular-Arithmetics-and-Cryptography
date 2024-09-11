import socket
import json
import threading
import random
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from config import SERVER_ADDRESS, BUFSIZE, MODULUS, BASE
import tkinter as tk
from tkinter import font as tkFont
from PIL import Image, ImageTk

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(SERVER_ADDRESS)

shared_secret = None
fernet_key = None
client_name = None


def connect():
    global sock, secret_key, public_key, fernet_key, shared_secret, client_name, pre_chat_canvas, name_entry_window, enter_name_button_window

    client_name = name_entry.get()
    if not client_name:
        status_label.config(text="Please enter a name.", fg="red")
        return

    pre_chat_canvas.delete(name_entry_window)
    pre_chat_canvas.delete(enter_name_button_window)
    bold_font = tkFont.Font(family="Helvetica", size=15, weight="bold")
    instruction_label.config(text=f"Hello, {client_name}", font=bold_font)

    secret_key = random.randint(1, MODULUS)
    public_key = pow(BASE, secret_key, MODULUS)

    secret_key_label.config(text=f"Secret Key: {secret_key}")
    public_key_label.config(text=f"Public Key: {public_key}")

    y_offset = 300
    pre_chat_canvas.create_window(300, y_offset + 90, window=secret_key_label)
    pre_chat_canvas.create_window(300, y_offset + 120, window=public_key_label)
    pre_chat_canvas.create_window(300, y_offset + 150, window=status_label)
    pre_chat_canvas.create_window(300, y_offset + 180, window=shared_secret_label)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(SERVER_ADDRESS)
        sock.send(bytes(json.dumps({'type': 'init', 'name': client_name, 'pubkey': public_key}), 'utf8'))
        read_thread = threading.Thread(target=handle_read, daemon=True)
        read_thread.start()
    except Exception as e:
        update_chat_box("system", f"Failed to connect to the server: {e}")


def pre_chat_window():
    global pre_chat_root, pre_chat_canvas, bg_photo, instruction_label, name_entry, enter_name_button, secret_key_label, public_key_label, status_label, shared_secret_label, name_entry_window, enter_name_button_window

    pre_chat_root = tk.Tk()
    pre_chat_root.title("Diffie-Hellman Key Exchange")
    pre_chat_root.geometry('600x600')
    pre_chat_canvas = tk.Canvas(pre_chat_root, width=600, height=600)
    pre_chat_canvas.pack(fill="both", expand=True)

    bg_image = Image.open("Login.png")
    bg_photo = ImageTk.PhotoImage(bg_image)
    pre_chat_canvas.create_image(300, 100, image=bg_photo, anchor="n")

    y_offset = 300
    instruction_label = tk.Label(pre_chat_root,
                                 text="Please enter your name below and press 'Enter' or click 'Enter Name'")
    pre_chat_canvas.create_window(300, y_offset, window=instruction_label)

    name_entry = tk.Entry(pre_chat_root, width=40)
    name_entry_window = pre_chat_canvas.create_window(300, y_offset + 30, window=name_entry)

    enter_name_button = tk.Button(pre_chat_root, text="Enter Name", command=connect)
    enter_name_button_window = pre_chat_canvas.create_window(300, y_offset + 60, window=enter_name_button)

    secret_key_label = tk.Label(pre_chat_root, text="Secret Key: Not set")
    public_key_label = tk.Label(pre_chat_root, text="Public Key: Not set")
    status_label = tk.Label(pre_chat_root, text="Please enter your name and click 'Connect'")
    shared_secret_label = tk.Label(pre_chat_root, text="Shared Secret: Not calculated")
    pre_chat_root.mainloop()

def start_chat_window():
    global global_chat_box

    pre_chat_root.destroy()

    chat_root = tk.Tk()
    chat_root.title(f"Chat - {client_name}")

    bg_image = Image.open("teckel.png")
    bg_photo = ImageTk.PhotoImage(bg_image)

    canvas = tk.Canvas(chat_root, width=600, height=600)
    canvas.pack(fill="both", expand=True)
    canvas.create_rectangle(0, 0, canvas.winfo_reqwidth(), canvas.winfo_reqheight(), fill='white')
    canvas.create_image(0, 0, image=bg_photo, anchor="nw")

    chat_box = tk.Text(chat_root, height=15, width=21, borderwidth=2, relief="groove")
    global_chat_box = chat_box
    chat_box_window = canvas.create_window(290, 340, window=chat_box)

    entry_box = tk.Entry(chat_root, width=21, borderwidth=2, relief="groove")
    entry_box_window = canvas.create_window(290, 550, window=entry_box)

    type_label = tk.Label(chat_root, text="Type the message below and hit Enter: ")
    type_label.pack()
    type_label_window = canvas.create_window(290, 510, window=type_label)

    entry_box.bind('<Return>', lambda event: send_message(chat_box, entry_box))

    chat_root.mainloop()

def update_chat_box(chat_box, name, text):
    def _update():
        chat_box.insert(tk.END, f"{name}: {text}\n")
        chat_box.see(tk.END)

    chat_box.after(0, _update)


def generate_fernet_key(shared_secret):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(str(shared_secret).encode())
    return base64.urlsafe_b64encode(digest.finalize()[:32])


def calculate_e2ekey(pubkey):
    global shared_secret, fernet_key
    shared_secret = pow(pubkey, secret_key, MODULUS)
    fernet_key = Fernet(generate_fernet_key(shared_secret))


def send_message(chat_box, entry_box):
    message = entry_box.get()
    if fernet_key:
        ciphertext = fernet_key.encrypt(message.encode('utf-8'))
        encoded_message = base64.b64encode(ciphertext).decode('utf8')
        sock.send(bytes(json.dumps({'type': 'message', 'text': encoded_message}), 'utf8'))
    else:
        sock.send(bytes(json.dumps({'type': 'message', 'text': message}), 'utf8'))
    update_chat_box(chat_box, "You", message)
    entry_box.delete(0, tk.END)


def handle_read():
    global shared_secret, fernet_key, client_name, global_chat_box, pre_chat_canvas, shared_secret_label
    while True:
        try:
            data = sock.recv(BUFSIZE).decode('utf8')
            data = json.loads(data)

            if data.get('type') == 'init':
                pubkey = data.get('pubkey')
                calculate_e2ekey(pubkey)


            elif data.get('type') == 'chat_ready':
                shared_secret_label.config(text=f"Shared Secret: {shared_secret}")
                status_label.config(text="Both clients connected. Click 'Start Chat' to begin chatting.", fg="red")
                start_chat_button = tk.Button(pre_chat_root, text="Start Chat", command=start_chat_window)
                pre_chat_canvas.create_window(300, 550, window=start_chat_button)

            elif data.get('type') == 'chat_wait':
                system_message = data.get('text')
                status_label.config(text=system_message, fg="red")

            elif data.get('type') == 'message':
                sender_name = data.get('name')
                if sender_name != client_name:
                    encoded_message = data['text']
                    decoded = base64.b64decode(encoded_message)
                    text = fernet_key.decrypt(decoded).decode('utf8')
                    if global_chat_box:
                        update_chat_box(global_chat_box, sender_name, text)
        except Exception as e:
            print(f"Error in handle_read: {e}")
            break


if __name__ == '__main__':
    pre_chat_window()
    sock.close()
