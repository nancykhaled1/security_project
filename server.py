import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import hashlib
import threading
import tkinter as tk

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

def send_message_to_client(conn, message, key):
    iv, ct = encrypt(message, key)
    encrypted_message = f"{iv}:{ct}"
    conn.sendall(encrypted_message.encode())
    print(f"Encrypted message sent:" , encrypted_message)

def receive_message_from_client(conn, key, chat_display):
    data = conn.recv(1024)
    if not data:
        return None
    iv, ct = data.decode().split(':')
    decrypted_message = decrypt(iv, ct, key)
    chat_display.config(state=tk.NORMAL)
    chat_display.insert(tk.END, "Client: " + decrypted_message + "\n")
    chat_display.see(tk.END)
    chat_display.config(state=tk.DISABLED)

def setup_gui(conn, key):
    root = tk.Tk()
    root.title("Server")
    root.geometry("400x450")
    
    chat_display = tk.Text(root, state=tk.DISABLED)
    chat_display.pack()

    entry = tk.Entry(root, width=50)
    entry.pack()

    def send_message_from_gui():
        message = entry.get()
        if message:
            send_message_to_client(conn, message, key)
            chat_display.config(state=tk.NORMAL)
            chat_display.insert(tk.END, "Server: " + message + "\n")
            chat_display.see(tk.END)
            chat_display.config(state=tk.DISABLED)
            entry.delete(0, tk.END)

    send_button = tk.Button(root, text="Send", command=send_message_from_gui)
    send_button.pack()

    return chat_display, root

def main():
    host = '127.0.0.1'
    port = 12346

    original_key = "This is my secret key for encryption"
    key = generate_key(original_key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(5)
        print(f"Server listening on {host}:{port}")

        conn, addr = s.accept()
        chat_display, root = setup_gui(conn, key)

        threading.Thread(target=receive_message_from_client, args=(conn, key, chat_display), daemon=True).start()

        root.mainloop()

if __name__ == "__main__":
    main()




