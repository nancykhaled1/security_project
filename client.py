import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import hashlib
import threading
import tkinter as tk
from functools import partial

def encrypt(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    return iv, ct

def decrypt(iv, ct, key):
    cipher = AES.new(key, AES.MODE_CBC, b64decode(iv))
    pt = unpad(cipher.decrypt(b64decode(ct)), AES.block_size)
    return pt.decode('utf-8')

def generate_key(original_key):
    hash_object = hashlib.sha256()
    hash_object.update(original_key.encode())
    hashed_key = hash_object.digest()
    return hashed_key[:16]

def send_message_to_server(s, message, key):
    iv, ct = encrypt(message, key)
    encrypted_message = f"{iv}:{ct}"
    s.sendall(encrypted_message.encode())
    print(f"Encrypted message sent:" , encrypted_message)


def receive_message_from_server(s, key, chat_display):
    data = s.recv(1024)
    if not data:
        return None
    iv, ct = data.decode().split(':')
    decrypted_message = decrypt(iv, ct, key)
    chat_display.insert(tk.END, "Server: " + decrypted_message + "\n")

def receive_thread(s, key, chat_display):
    while True:
        received_message = receive_message_from_server(s, key, chat_display)
        if received_message:
            chat_display.insert(tk.END, "Client: " + received_message + "\n")

def setup_gui(s, key):
    root = tk.Tk()
    root.title("Client")
    root.geometry("400x450")

    chat_display = tk.Text(root)
    chat_display.pack()

    entry = tk.Entry(root, width=50)
    entry.pack()

    def send_message_from_gui():
        message = entry.get()
        send_message_to_server(s, message, key)
        chat_display.insert(tk.END, "Client: " + message + "\n")
        entry.delete(0, tk.END)  # Clear the entry field after sending

    send_button = tk.Button(root, text="Send", command=send_message_from_gui)
    send_button.pack()

    threading.Thread(target=receive_thread, args=(s, key, chat_display), daemon=True).start()

    return root


def main():
    host = '127.0.0.1'
    port = 12346

    original_key = "This is my secret key for encryption"
    key = generate_key(original_key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))

        root = setup_gui(s, key)
        root.mainloop()
    
    
if __name__ == "__main__":
    main()
