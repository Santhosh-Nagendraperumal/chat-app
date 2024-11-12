import socket
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import os

# Global variable to store the last received file name
received_file = None

def save_file(filename, data):
    """Save the received file data to a file."""
    with open(filename, 'wb') as file:
        file.write(data)
    print(f"File {filename} saved successfully.")
    
    # Save the received file name globally to open it later
    global received_file
    received_file = filename

    # Update UI with file received info
    text_area.config(state='normal')
    text_area.insert(tk.END, f"Received file: {filename}\n", "received")
    text_area.config(state='disabled')

    # Automatically open the file if it's a text file
    open_file(filename)

def open_file(filename):
    """Open the file to display its content (or for any specific file type like text files)."""
    if os.path.exists(filename):
        try:
            # For text files, you can read and display the content
            if filename.lower().endswith('.txt'):
                with open(filename, 'r') as file:
                    file_content = file.read()
                    print(f"Content of {filename}:\n{file_content}")
                    
                    # Display file content in the text area
                    text_area.config(state='normal')
                    text_area.insert(tk.END, f"\n[File Content of {filename}]\n{file_content}\n", "received")
                    text_area.config(state='disabled')
            else:
                messagebox.showinfo("Info", f"File {filename} is not a text file, unable to display content.")
        except Exception as e:
            print(f"Error opening file {filename}: {e}")
            messagebox.showerror("Error", f"Failed to open the file {filename}: {e}")
    else:
        messagebox.showerror("Error", f"File {filename} does not exist.")

def handle_client(client_socket, text_area):
    """Handle client communication."""
    while True:
        try:
            data = client_socket.recv(1024).decode('utf-8')
            if data.startswith("FILE:"):
                # Handle file transfer
                filename = data.split(":")[1]
                print(f"Receiving file: {filename}")
                
                file_data = b""
                while True:
                    chunk = client_socket.recv(1024)
                    if chunk == b"END_OF_FILE":
                        break
                    file_data += chunk

                save_file(filename, file_data)

                # Send acknowledgment to client
                client_socket.sendall(f"Server: File {filename} received successfully.".encode('utf-8'))
            else:
                # Handle normal message
                print(f"Received message: {data}")
                response = f"Server received: {data}"
                text_area.config(state='normal')
                text_area.insert(tk.END, f"Received: {data}\n", "received")
                text_area.config(state='disabled')
                client_socket.sendall(response.encode('utf-8'))
        except:
            break
    client_socket.close()

def open_file_dialog():
    """Open file dialog to select a file and display its content."""
    if received_file:
        open_file(received_file)
    else:
        messagebox.showerror("Error", "No file received yet.")

def start_server():
    """Start the server and handle client connections."""
    global text_area  # To access text_area in the open_file function
    root = tk.Tk()
    root.title("Server")
    root.geometry("600x500")
    root.resizable(False, False)

    # Apply a modern theme
    style = ttk.Style(root)
    style.theme_use("clam")

    # Set custom colors for UI components
    style.configure("TFrame", background="#282c34")
    style.configure("TButton", background="#61afef", foreground="white", font=("Helvetica", 10, "bold"))
    style.map("TButton", background=[("active", "#528bcc")])
    style.configure("TLabel", background="#282c34", foreground="white", font=("Helvetica", 12))
    style.configure("TEntry", fieldbackground="white", foreground="black", font=("Helvetica", 10))

    main_frame = ttk.Frame(root)
    main_frame.pack(fill="both", expand=True)

    # Title Label
    ttk.Label(main_frame, text="Server Console", font=("Helvetica", 16, "bold")).pack(pady=10)

    # ScrolledText for logs
    text_area = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, height=20, font=("Courier New", 10))
    text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
    text_area.config(state='disabled', background="#1e2127", foreground="#abb2bf", insertbackground="white")

    # Highlight for different message types
    text_area.tag_config("received", foreground="#98c379")

    # Open File Button
    open_file_button = ttk.Button(main_frame, text="Open File", command=open_file_dialog)
    open_file_button.pack(pady=10)

    # Start server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 12345))
    server_socket.listen(5)
    text_area.config(state='normal')
    text_area.insert(tk.END, "Server listening on 127.0.0.1:12345...\n", "info")
    text_area.config(state='disabled')

    def accept_connections():
        """Accept incoming client connections."""
        while True:
            client_socket, client_address = server_socket.accept()
            print(f"Accepted connection from {client_address}")
            text_area.config(state='normal')
            text_area.insert(tk.END, f"Accepted connection from {client_address}\n", "received")
            text_area.config(state='disabled')

            # Create a thread to handle the client
            client_handler = threading.Thread(target=handle_client, args=(client_socket, text_area))
            client_handler.start()

    # Start accepting connections in a separate thread
    threading.Thread(target=accept_connections, daemon=True).start()

    root.mainloop()

if __name__ == "__main__":
    start_server()
