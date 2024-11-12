import socket
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import os

def send_message(client_socket, text_area, input_field):
    message = input_field.get()
    if message.strip():
        try:
            client_socket.sendall(message.encode('utf-8'))
            text_area.config(state='normal')
            text_area.insert(tk.END, f"Sent: {message}\n", "sent")
            text_area.config(state='disabled')
            input_field.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {e}")

def send_file(client_socket, text_area):
    file_path = filedialog.askopenfilename(title="Select File to Send")
    if file_path:
        try:
            file_name = os.path.basename(file_path)
            client_socket.sendall(f"FILE:{file_name}".encode('utf-8'))
            with open(file_path, 'rb') as file:
                while chunk := file.read(1024):
                    client_socket.sendall(chunk)
            client_socket.sendall(b"END_OF_FILE")
            
            text_area.config(state='normal')
            text_area.insert(tk.END, f"Sent file: {file_name}\n", "sent")
            text_area.config(state='disabled')
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send file: {e}")

def receive_messages(client_socket, text_area):
    while True:
        try:
            data = client_socket.recv(1024)
            if not data:
                break
            message = data.decode('utf-8')
            text_area.config(state='normal')
            text_area.insert(tk.END, f"Received: {message}\n", "received")
            text_area.config(state='disabled')
        except:
            break
    client_socket.close()

def main():
    root = tk.Tk()
    root.title("Client")
    root.geometry("600x500")
    root.resizable(False, False)

    # Apply a modern theme
    style = ttk.Style(root)
    style.theme_use("clam")

    # Set custom colors for UI
    style.configure("TFrame", background="#282c34")
    style.configure("TButton", background="#61afef", foreground="white", font=("Helvetica", 10, "bold"))
    style.map("TButton", background=[("active", "#528bcc")])
    style.configure("TLabel", background="#282c34", foreground="white", font=("Helvetica", 12))
    style.configure("TEntry", background="#1e2127", foreground="white", font=("Helvetica", 10))

    main_frame = ttk.Frame(root)
    main_frame.pack(fill="both", expand=True)

    # Title Label
    ttk.Label(main_frame, text="Client Console", font=("Helvetica", 16, "bold")).pack(pady=10)

    # ScrolledText for logs
    text_area = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, height=20, font=("Courier New", 10))
    text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
    text_area.config(state='disabled', background="#1e2127", foreground="#abb2bf", insertbackground="white")

    # Highlight for different message types
    text_area.tag_config("sent", foreground="#61afef")
    text_area.tag_config("received", foreground="#98c379")

    # Input Field and Buttons
    input_frame = ttk.Frame(main_frame)
    input_frame.pack(fill=tk.X, pady=5)

    input_field = ttk.Entry(input_frame, font=("Helvetica", 10))
    input_field.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
    style.configure("TEntry", fieldbackground="white", foreground="black")

    send_button = ttk.Button(input_frame, text="Send Message", command=lambda: send_message(client_socket, text_area, input_field))
    send_button.pack(side=tk.LEFT, padx=5)

    file_button = ttk.Button(input_frame, text="Send File", command=lambda: send_file(client_socket, text_area))
    file_button.pack(side=tk.RIGHT, padx=5)

    # Establish connection
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('127.0.0.1', 12345))
        text_area.config(state='normal')
        text_area.insert(tk.END, "Connected to server at 127.0.0.1:12345\n", "info")
        text_area.config(state='disabled')
        
        # Start receiving messages in a separate thread
        threading.Thread(target=receive_messages, args=(client_socket, text_area), daemon=True).start()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to connect to server: {e}")

    root.mainloop()

if __name__ == "__main__":
    main()
