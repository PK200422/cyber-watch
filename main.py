import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext
import re
import threading
import os
import sys
import time
import winsound
from model.text_model import TextThreatClassifier
from utils.file_utils import extract_text_from_file

import cv2
from PIL import Image, ImageTk

from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import base64
import pickle

# --- Modern color palette ---
BG_MAIN = "#232946"
BG_FRAME = "#232946"
FG_MAIN = "#eebbc3"
BTN_BG = "#eebbc3"
BTN_FG = "#232946"
BTN_ACTIVE_BG = "#d4939d"
BTN_ACTIVE_FG = "#232946"
LABEL_BG = "#232946"
LABEL_FG = "#eebbc3"
ENTRY_BG = "#fffffe"
ENTRY_FG = "#232946"
SCROLL_BG = "#121629"
SCROLL_FG = "#eebbc3"

def play_sound(label, repeat=1):
    for _ in range(repeat):
        key = label.lower()
        if key == "safe":
            winsound.Beep(1200, 150)
        elif key == "offensive":
            winsound.Beep(800, 300)
        elif key == "threat":
            winsound.Beep(400, 500)
        else:
            winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
        time.sleep(0.1)

class CyberWatchApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cyber Watch - Emotion-Aware Cybersecurity")
        self.geometry("950x700")
        self.state("zoomed")
        self.configure(bg=BG_MAIN)
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self.on_exit)
        self.current_frame = None
        self.classifier = TextThreatClassifier()
        self.status_var = tk.StringVar()
        self.status_bar = tk.Label(self, textvariable=self.status_var, bd=1, relief="sunken", anchor="w", bg=BG_FRAME, fg=FG_MAIN, font=("Segoe UI", 11))
        self.status_bar.pack(side="bottom", fill="x")
        self.set_status("Welcome to Cyber Watch!")
        self.bind("<Control-q>", lambda e: self.on_exit())
        self.stop_scan_event = threading.Event()
        self.show_main_menu()

    def set_status(self, message, clear_after=4):
        self.status_var.set(message)
        if clear_after:
            self.after(clear_after * 1000, lambda: self.status_var.set(""))

    def add_tooltip(self, widget, text):
        tooltip = tk.Toplevel(widget)
        tooltip.withdraw()
        tooltip.overrideredirect(True)
        label = tk.Label(tooltip, text=text, bg="#333", fg="#fff", font=("Segoe UI", 10), padx=6, pady=2)
        label.pack()
        def enter(event):
            x = widget.winfo_rootx() + 40
            y = widget.winfo_rooty() + 20
            tooltip.geometry(f"+{x}+{y}")
            tooltip.deiconify()
        def leave(event):
            tooltip.withdraw()
        widget.bind("<Enter>", enter)
        widget.bind("<Leave>", leave)

    def toggle_theme(self):
        global BG_MAIN, BG_FRAME, FG_MAIN, BTN_BG, BTN_FG, BTN_ACTIVE_BG, BTN_ACTIVE_FG, LABEL_BG, LABEL_FG, ENTRY_BG, ENTRY_FG
        if BG_MAIN == "#232946":
            BG_MAIN = "#f5f5f5"
            BG_FRAME = "#f5f5f5"
            FG_MAIN = "#232946"
            BTN_BG = "#232946"
            BTN_FG = "#eebbc3"
            BTN_ACTIVE_BG = "#393e46"
            BTN_ACTIVE_FG = "#eebbc3"
            LABEL_BG = "#f5f5f5"
            LABEL_FG = "#232946"
            ENTRY_BG = "#fff"
            ENTRY_FG = "#232946"
        else:
            BG_MAIN = "#232946"
            BG_FRAME = "#232946"
            FG_MAIN = "#eebbc3"
            BTN_BG = "#eebbc3"
            BTN_FG = "#232946"
            BTN_ACTIVE_BG = "#d4939d"
            BTN_ACTIVE_FG = "#232946"
            LABEL_BG = "#232946"
            LABEL_FG = "#eebbc3"
            ENTRY_BG = "#fffffe"
            ENTRY_FG = "#232946"
        self.configure(bg=BG_MAIN)
        self.status_bar.configure(bg=BG_FRAME, fg=FG_MAIN)
        self.show_main_menu()

    def clear_frame(self):
        if self.current_frame:
            self.current_frame.destroy()

    def style_button(self, btn):
        btn.configure(
            bg=BTN_BG,
            fg=BTN_FG,
            activebackground=BTN_ACTIVE_BG,
            activeforeground=BTN_ACTIVE_FG,
            relief="flat",
            bd=0,
            font=("Segoe UI", 16, "bold"),
            cursor="hand2"
        )
        btn.bind("<Enter>", lambda e: btn.config(bg=BTN_ACTIVE_BG))
        btn.bind("<Leave>", lambda e: btn.config(bg=BTN_BG))

    def style_back_button(self, btn):
        btn.configure(
            bg="#d9534f",
            fg="#fff",
            activebackground="#c9302c",
            activeforeground="#fff",
            relief="flat",
            bd=0,
            font=("Segoe UI", 12, "bold"),
            cursor="hand2"
        )
        btn.bind("<Enter>", lambda e: btn.config(bg="#c9302c"))
        btn.bind("<Leave>", lambda e: btn.config(bg="#d9534f"))

    def show_main_menu(self):
        self.clear_frame()
        frame = tk.Frame(self, bg=BG_FRAME)
        frame.pack(fill="both", expand=True)
        tk.Label(
            frame, text="Cyber Watch", font=("Segoe UI", 40, "bold"),
            bg=LABEL_BG, fg=LABEL_FG
        ).pack(pady=40)
        btns = [
            ("📝 Text Analyzer", self.show_text_analyzer_menu, "Analyze text, files, and chats for threats"),
            ("😊 Face Analyzer", self.show_face_analyzer, "Detect your facial emotion"),
            ("🎤 Voice Analyzer", self.show_voice_analyzer, "Analyze voice for threats or emotion (coming soon)"),
        ]
        for text, cmd, tip in btns:
            btn = tk.Button(frame, text=text, width=30, height=2, command=cmd)
            self.style_button(btn)
            btn.pack(pady=18)
            self.add_tooltip(btn, tip)
        theme_btn = tk.Button(frame, text="🌗 Toggle Theme", command=self.toggle_theme)
        self.style_button(theme_btn)
        theme_btn.pack(pady=8)
        self.add_tooltip(theme_btn, "Switch between light and dark mode")
        self.current_frame = frame

    def show_text_analyzer_menu(self):
        self.clear_frame()
        frame = tk.Frame(self, bg=BG_FRAME)
        frame.pack(fill="both", expand=True)
        back_btn = tk.Button(frame, text="⬅ Back", command=self.show_main_menu)
        self.style_back_button(back_btn)
        back_btn.config(width=10)
        back_btn.pack(anchor="nw", padx=20, pady=20)
        tk.Label(frame, text="Text Analyzer", font=("Segoe UI", 32, "bold"), bg=LABEL_BG, fg=LABEL_FG).pack(pady=20)
        btns = [
            ("✅ Text Threat Analyzer", self.show_text_analyzer, "Analyze entered text for threats"),
            ("📧 Gmail Threat Scanner", self.show_gmail_scanner, "Scan your Gmail for threats"),
            ("💬 Chat Monitor", self.show_chat_monitor, "Monitor chat messages for threats"),
            ("📁 File Scanner", self.show_file_scanner, "Scan files for threats"),
        ]
        for text, cmd, tip in btns:
            btn = tk.Button(frame, text=text, width=30, height=2, command=cmd)
            self.style_button(btn)
            btn.pack(pady=12)
            self.add_tooltip(btn, tip)
        self.current_frame = frame

    # --- Text Threat Analyzer ---
    def show_text_analyzer(self):
        self.clear_frame()
        frame = tk.Frame(self, bg=BG_FRAME)
        frame.pack(fill="both", expand=True)
        back_btn = tk.Button(frame, text="⬅ Back", command=self.show_text_analyzer_menu)
        self.style_back_button(back_btn)
        back_btn.pack(anchor="nw", padx=20, pady=20)
        tk.Label(frame, text="Text Threat Analyzer", font=("Segoe UI", 28, "bold"), bg=LABEL_BG, fg=LABEL_FG).pack(pady=10)
        text_box = scrolledtext.ScrolledText(frame, font=("Segoe UI", 14), width=80, height=10, bg=ENTRY_BG, fg=ENTRY_FG)
        text_box.pack(pady=10)
        result_box = tk.Label(frame, text="", font=("Segoe UI", 20, "bold"), width=40, height=2, bg="#fff")
        result_box.pack(pady=10)

        def clear_text():
            text_box.delete("1.0", tk.END)
            result_box.config(text="", bg="#fff")

        def analyze():
            try:
                self.set_status("Analyzing...")
                text = text_box.get("1.0", tk.END).strip()
                if not text:
                    messagebox.showwarning("Input Required", "Please enter some text.")
                    self.set_status("No text entered.")
                    return

                money_keywords = [r"\$\d+", r"₹\d+", r"rs\.?\s*\d+", r"transfer", r"payment", r"account", r"bank"]
                money_found = None
                for kw in money_keywords:
                    match = re.search(kw, text, re.IGNORECASE)
                    if match:
                        money_found = match.group()
                        break

                if money_found:
                    result_box.config(text="❗ Amount Detected", bg="#ffe066", fg="#333")
                    play_sound("offensive")
                    self.set_status("Amount detected in text.")
                    self.show_money_confirmation(frame, result_box, money_found)
                    return

                label, emoji = self.classifier.predict(text)
                color = {"Safe": "#d4edda", "Offensive": "#ffe066", "Threat": "#f8d7da"}[label]
                fg = {"Safe": "#155724", "Offensive": "#856404", "Threat": "#721c24"}[label]
                result_box.config(text=f"{emoji} {label}", bg=color, fg=fg)
                sound_label = label.lower()
                repeat = 2 if label == "Threat" else 1
                play_sound(sound_label, repeat=repeat)
                self.set_status(f"Text analyzed: {label}")
                if label in ["Offensive", "Threat"]:
                    self.show_popup(f"{emoji} {label}", f"Detected: {label}")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {e}")
                self.set_status("Error during analysis.")

        btn = tk.Button(frame, text="Analyze", command=lambda: threading.Thread(target=analyze).start())
        self.style_button(btn)
        btn.pack(pady=10)

        clear_btn = tk.Button(frame, text="Clear", command=clear_text)
        self.style_button(clear_btn)
        clear_btn.pack(pady=10)

        self.add_tooltip(btn, "Analyze the entered text")
        self.current_frame = frame

    def show_money_confirmation(self, parent, result_box, amount):
        popup = tk.Toplevel(parent)
        popup.title("Confirm Amount")
        popup.geometry("400x220")
        popup.configure(bg=BG_MAIN)
        popup.transient(self)
        popup.lift()
        popup.grab_set()
        tk.Label(
            popup,
            text=f"Re-enter the amount to confirm:\n{amount}",
            font=("Segoe UI", 15, "bold"),
            bg=BG_MAIN,
            fg=FG_MAIN
        ).pack(pady=20)
        entry = tk.Entry(popup, font=("Segoe UI", 14), bg=ENTRY_BG, fg=ENTRY_FG)
        entry.pack(pady=8)
        status_label = tk.Label(popup, text="", font=("Segoe UI", 12, "bold"), bg=BG_MAIN, fg=FG_MAIN)
        status_label.pack(pady=5)

        def confirm():
            entered = entry.get().strip()
            if entered == amount:
                result_box.config(text="✅ Safe", bg="#d4edda", fg="#155724")
                play_sound("safe")
                status_label.config(text="Amount confirmed. Marked as Safe.", fg="#28a745")
                self.set_status("Amount confirmed as safe.")
                popup.after(1000, popup.destroy)
            else:
                result_box.config(text="❌ Threat", bg="#f8d7da", fg="#721c24")
                play_sound("threat")
                status_label.config(text="Amount mismatch! Marked as Threat.", fg="#d9534f")
                self.set_status("Amount mismatch! Threat detected.")
                self.show_popup("❌ Threat", "Entered amount does not match. This is a potential threat!")
                popup.after(1000, popup.destroy)

        btn = tk.Button(
            popup,
            text="Confirm",
            command=confirm,
            font=("Segoe UI", 14, "bold"),
            width=16,
            height=2,
            bg=BTN_BG,
            fg=BTN_FG,
            activebackground=BTN_ACTIVE_BG,
            activeforeground=BTN_ACTIVE_FG,
            relief="flat",
            bd=0,
            cursor="hand2"
        )
        btn.pack(pady=10)
        btn.bind("<Enter>", lambda e: btn.config(bg=BTN_ACTIVE_BG))
        btn.bind("<Leave>", lambda e: btn.config(bg=BTN_BG))
        popup.wait_window()

    def show_popup(self, label, message):
        if "Safe" in label or "✅" in label:
            play_sound("safe")
        elif "Threat" in label or "⚠️" in label or "Suspect" in label or "Offensive" in label:
            play_sound("offensive")
        else:
            play_sound("safe")
        popup = tk.Toplevel(self)
        popup.title("Alert")
        popup.geometry("400x200")
        popup.configure(bg=BG_MAIN)
        popup.transient(self)
        popup.lift()
        popup.grab_set()
        tk.Label(
            popup,
            text=label,
            font=("Segoe UI", 22, "bold"),
            bg=BG_MAIN,
            fg=FG_MAIN
        ).pack(pady=10)
        tk.Label(
            popup,
            text=message,
            font=("Segoe UI", 14),
            bg=BG_MAIN,
            fg=FG_MAIN,
            wraplength=350,
            justify="center"
        ).pack(pady=10)
        btn = tk.Button(
            popup,
            text="OK",
            command=popup.destroy,
            font=("Segoe UI", 14, "bold"),
            width=16,
            height=2,
            bg=BTN_BG,
            fg=BTN_FG,
            activebackground=BTN_ACTIVE_BG,
            activeforeground=BTN_ACTIVE_FG,
            relief="flat",
            bd=0,
            cursor="hand2"
        )
        btn.pack(pady=15)
        btn.bind("<Enter>", lambda e: btn.config(bg=BTN_ACTIVE_BG))
        btn.bind("<Leave>", lambda e: btn.config(bg=BTN_BG))
        popup.wait_window()

    # --- Gmail Threat Scanner ---
    def show_gmail_scanner(self):
        from tkinter import ttk
        self.clear_frame()
        frame = tk.Frame(self, bg=BG_FRAME)
        frame.pack(fill="both", expand=True)
        back_btn = tk.Button(frame, text="⬅ Back", command=self.show_text_analyzer_menu)
        self.style_back_button(back_btn)
        back_btn.pack(anchor="nw", padx=20, pady=20)
        tk.Label(frame, text="Gmail Threat Scanner", font=("Segoe UI", 28, "bold"), bg=LABEL_BG, fg=LABEL_FG).pack(pady=10)

        entry_frame = tk.Frame(frame, bg=BG_FRAME)
        entry_frame.pack(pady=5)
        tk.Label(entry_frame, text="Number of emails to scan (or 'all'):", font=("Segoe UI", 12), bg=BG_FRAME, fg=FG_MAIN).pack(side="left")
        num_emails_var = tk.StringVar(value="10")
        num_emails_entry = tk.Entry(entry_frame, textvariable=num_emails_var, width=8, font=("Segoe UI", 12), bg=ENTRY_BG, fg=ENTRY_FG)
        num_emails_entry.pack(side="left", padx=5)

        tk.Label(entry_frame, text="Area:", font=("Segoe UI", 12), bg=BG_FRAME, fg=FG_MAIN).pack(side="left", padx=(10,0))
        area_var = tk.StringVar(value="All")
        area_combo = ttk.Combobox(entry_frame, textvariable=area_var, values=["All", "Read", "Unread"], state="readonly", width=8)
        area_combo.pack(side="left", padx=5)

        result_box = scrolledtext.ScrolledText(frame, font=("Segoe UI", 12), width=100, height=20, bg=ENTRY_BG, fg=ENTRY_FG)
        result_box.pack(pady=10)

        def scan_gmail():
            try:
                self.set_status("Scanning Gmail...")
                num_val = num_emails_var.get().strip().lower()
                area = area_var.get().lower()
                max_results = None
                if num_val != "all":
                    try:
                        max_results = int(num_val)
                        if max_results <= 0:
                            raise ValueError
                    except ValueError:
                        messagebox.showerror("Invalid Input", "Please enter a valid positive number or 'all'.")
                        return

                SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
                creds = None
                token_path = 'token.pickle'
                credentials_path = 'credentials.json'
                if os.path.exists(token_path ):
                    with open(token_path, 'rb') as token:
                        creds = pickle.load(token)
                if not creds or not creds.valid:
                    if creds and creds.expired and creds.refresh_token:
                        creds.refresh(Request())
                    else:
                        flow = InstalledAppFlow.from_client_secrets_file(credentials_path, SCOPES)
                        creds = flow.run_local_server(port=0)
                    with open(token_path, 'wb') as token:
                        pickle.dump(creds, token)
                service = build('gmail', 'v1', credentials=creds)
                query = ""
                if area == "read":
                    query = "is:read"
                elif area == "unread":
                    query = "is:unread"

                result_box.delete("1.0", tk.END)
                messages = []
                next_page_token = None
                while True:
                    params = {'userId': 'me', 'q': query}
                    if max_results:
                        params['maxResults'] = min(max_results - len(messages), 500)
                    if next_page_token:
                        params['pageToken'] = next_page_token
                    results = service.users().messages().list(**params).execute()
                    batch = results.get('messages', [])
                    messages.extend(batch)
                    next_page_token = results.get('nextPageToken')
                    if not next_page_token or (max_results and len(messages) >= max_results):
                        break
                if not messages:
                    result_box.insert(tk.END, "No emails found.")
                    return

                for i, msg in enumerate(messages):
                    if self.stop_scan_event.is_set():
                        result_box.insert(tk.END, "\nScan stopped by user.\n")
                        self.set_status("Gmail scan stopped.")
                        self.stop_scan_event.clear()
                        return

                    msg_id = msg["id"]
                    try:
                        full_message = service.users().messages().get(userId="me", id=msg_id, format="full").execute()
                        payload = full_message["payload"]
                        headers = payload.get("headers", [])
                        subject = ""
                        sender = ""
                        for header in headers:
                            if header["name"] == "Subject":
                                subject = header["value"]
                            if header["name"] == "From":
                                sender = header["value"]

                        parts = payload.get("parts", [])
                        body = ""
                        if parts:
                            for part in parts:
                                if part["mimeType"] == "text/plain":
                                    body_data = part["body"].get("data", "")
                                    body = base64.urlsafe_b64decode(body_data).decode("utf-8")
                                    break
                        else:
                            body_data = payload["body"].get("data", "")
                            body = base64.urlsafe_b64decode(body_data).decode("utf-8")

                        full_text = f"Subject: {subject}\nFrom: {sender}\nBody: {body}"
                        label, emoji = self.classifier.predict(full_text)
                        display_text = f"Email {i+1}: Subject: {subject[:70]}... | From: {sender[:70]}... | Status: {emoji} {label}\n"
                        result_box.insert(tk.END, display_text)
                        result_box.see(tk.END)
                        if label in ["Offensive", "Threat"]:
                            play_sound(label.lower())
                            self.show_popup(f"{emoji} {label}", f"Threat detected in email from {sender} with subject: {subject}")

                    except Exception as e:
                        result_box.insert(tk.END, f"Error processing email {msg_id}: {e}\n")
                        result_box.see(tk.END)

                self.set_status("Gmail scan complete.")
                self.stop_scan_event.clear()
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred during Gmail scan: {e}")
                self.set_status("Error during Gmail scan.")
                self.stop_scan_event.clear()

        scan_btn = tk.Button(frame, text="Scan Gmail", command=lambda: threading.Thread(target=scan_gmail).start())
        self.style_button(scan_btn)
        scan_btn.pack(pady=10)
        self.add_tooltip(scan_btn, "Scan your Gmail inbox for threats")

        stop_btn = tk.Button(frame, text="Stop Scan", command=self.stop_scan_event.set)
        self.style_button(stop_btn)
        stop_btn.pack(pady=10)

        def copy_results():
            self.clipboard_clear()
            self.clipboard_append(result_box.get("1.0", tk.END))
            self.set_status("Results copied to clipboard.")

        copy_btn = tk.Button(frame, text="Copy Results", command=copy_results)
        self.style_button(copy_btn)
        copy_btn.pack(pady=5)

        self.current_frame = frame

    # --- Chat Monitor ---
    def show_chat_monitor(self):
        self.clear_frame()
        frame = tk.Frame(self, bg=BG_FRAME)
        frame.pack(fill="both", expand=True)
        back_btn = tk.Button(frame, text="⬅ Back", command=self.show_text_analyzer_menu)
        self.style_back_button(back_btn)
        back_btn.pack(anchor="nw", padx=20, pady=20)
        tk.Label(frame, text="Chat Monitor", font=("Segoe UI", 28, "bold"), bg=LABEL_BG, fg=LABEL_FG).pack(pady=10)
        chat_box = scrolledtext.ScrolledText(frame, font=("Segoe UI", 12), width=80, height=10, bg=ENTRY_BG, fg=ENTRY_FG)
        chat_box.pack(pady=10)
        result_box = scrolledtext.ScrolledText(frame, font=("Segoe UI", 12), width=80, height=10, bg=ENTRY_BG, fg=ENTRY_FG)
        result_box.pack(pady=10)

        def clear_chat():
            chat_box.delete("1.0", tk.END)
            result_box.delete("1.0", tk.END)

        def analyze_chat():
            try:
                self.set_status("Analyzing chat...")
                text = chat_box.get("1.0", tk.END).strip()
                if not text:
                    messagebox.showwarning("Input Required", "Please enter chat messages.")
                    self.set_status("No chat entered.")
                    return
                lines = text.splitlines()
                result_box.delete("1.0", tk.END)
                for line in lines:
                    label, emoji = self.classifier.predict(line)
                    color = {"Safe": "green", "Offensive": "orange", "Threat": "red"}[label]
                    result_box.insert(tk.END, f"{emoji} {label}: {line}\n", color)
                    play_sound(label.lower())
                result_box.tag_config("green", foreground="green")
                result_box.tag_config("orange", foreground="orange")
                result_box.tag_config("red", foreground="red")
                result_box.see(tk.END)
                self.set_status("Chat scan complete.")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {e}")
                self.set_status("Error during chat analysis.")

        btn = tk.Button(frame, text="Analyze Chat", command=lambda: threading.Thread(target=analyze_chat).start())
        self.style_button(btn)
        btn.pack(pady=10)

        clear_btn = tk.Button(frame, text="Clear", command=clear_chat)
        self.style_button(clear_btn)
        clear_btn.pack(pady=10)

        self.add_tooltip(btn, "Analyze chat messages for threats")
        self.current_frame = frame

    # --- File Scanner ---
    def show_file_scanner(self):
        self.clear_frame()
        frame = tk.Frame(self, bg=BG_FRAME)
        frame.pack(fill="both", expand=True)
        back_btn = tk.Button(frame, text="⬅ Back", command=self.show_text_analyzer_menu)
        self.style_back_button(back_btn)
        back_btn.pack(anchor="nw", padx=20, pady=20)
        tk.Label(frame, text="File Scanner", font=("Segoe UI", 28, "bold"), bg=LABEL_BG, fg=LABEL_FG).pack(pady=20)

        result_box = scrolledtext.ScrolledText(frame, font=("Segoe UI", 12), width=100, height=20, bg=ENTRY_BG, fg=ENTRY_FG)
        result_box.pack(pady=10)

        def select_and_scan():
            try:
                self.set_status("Scanning file...")
                file_path = filedialog.askopenfilename(
                    filetypes=[
                        ("All Supported", "*.txt *.pdf *.docx"),
                        ("Text files", "*.txt"),
                        ("PDF files", "*.pdf"),
                        ("Word files", "*.docx"),
                        ("All files", "*.*"),
                    ]
                )
                if not file_path:
                    self.set_status("No file selected.")
                    return
                text = extract_text_from_file(file_path)
                label, emoji = self.classifier.predict(text)
                color = {"Safe": "green", "Offensive": "orange", "Threat": "red"}[label]
                result_box.delete("1.0", tk.END)
                result_box.insert(tk.END, f"File: {os.path.basename(file_path)}\n", "bold")
                result_box.insert(tk.END, f"Result: {emoji} {label}\n", color)
                result_box.insert(tk.END, "\n--- File Content Preview ---\n")
                money_keywords = [r"\$\d+", r"₹\d+", r"rs\.?\s*\d+", r"transfer", r"payment", r"account", r"bank"]
                matches = []
                for kw in money_keywords:
                    matches += re.findall(kw, text, re.IGNORECASE)
                preview = text[:2000] + ("..." if len(text) > 2000 else "")
                result_box.insert(tk.END, preview)
                for match in matches:
                    idx = result_box.search(match, "1.0", tk.END)
                    while idx:
                        end_idx = f"{idx}+{len(match)}c"
                        result_box.tag_add("highlight", idx, end_idx)
                        idx = result_box.search(match, end_idx, tk.END)
                result_box.tag_config("bold", font=("Segoe UI", 12, "bold"))
                result_box.tag_config(color, foreground=color)
                result_box.tag_config("highlight", background="yellow")
                result_box.see(tk.END)
                play_sound(label.lower())
                if label in ["Threat", "Offensive"]:
                    self.show_popup(f"{emoji} {label}", f"Detected: {label} in file!")
                    self.set_status(f"File scanned: {label}")
                    if messagebox.askyesno("Export", "Export flagged content to file?"):
                        filetypes = [("Text files", "*.txt"), ("CSV files", "*.csv")]
                        file_path_export = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=filetypes)
                        if file_path_export:
                            with open(file_path_export, "w", encoding="utf-8") as f:
                                f.write(preview)
                elif label == "Safe":
                    self.show_popup(f"{emoji} {label}", f"File is Safe!")
                    self.set_status("File scanned: Safe")
            except Exception as e:
                result_box.delete("1.0", tk.END)
                result_box.insert(tk.END, f"Error: {e}")
                self.set_status("Error scanning file.")

        btn = tk.Button(frame, text="Select and Scan File", command=lambda: threading.Thread(target=select_and_scan).start())
        self.style_button(btn)
        btn.pack(pady=10)
        self.add_tooltip(btn, "Select a file and scan for threats")

        def copy_results():
            self.clipboard_clear()
            self.clipboard_append(result_box.get("1.0", tk.END))
            self.set_status("Results copied to clipboard.")

        copy_btn = tk.Button(frame, text="Copy Results", command=copy_results)
        self.style_button(copy_btn)
        copy_btn.pack(pady=5)

        self.current_frame = frame

    # --- Face Analyzer ---
    def show_face_analyzer(self):
        self.clear_frame()
        frame = tk.Frame(self, bg=BG_FRAME)
        frame.pack(fill="both", expand=True)
        back_btn = tk.Button(frame, text="⬅ Back", command=self.show_main_menu)
        self.style_back_button(back_btn)
        back_btn.pack(anchor="nw", padx=20, pady=20)
        tk.Label(frame, text="Face Analyzer", font=("Segoe UI", 32, "bold"), bg=LABEL_BG, fg=LABEL_FG).pack(pady=20)
        tk.Label(frame, text="Click 'Capture & Analyze' to detect your facial emotion.", font=("Segoe UI", 16), bg=LABEL_BG, fg=LABEL_FG).pack(pady=10)
        img_label = tk.Label(frame, bg=BG_FRAME)
        img_label.pack(pady=10)
        result_label = tk.Label(frame, text="", font=("Segoe UI", 18, "bold"), bg=BG_FRAME, fg=FG_MAIN)
        result_label.pack(pady=10)

        def capture_and_analyze():
            cap = cv2.VideoCapture(0)
            if not cap.isOpened():
                messagebox.showerror("Error", "Webcam not accessible.")
                self.set_status("Webcam not accessible.")
                return
            ret, frame_img = cap.read()
            cap.release()
            if not ret:
                messagebox.showerror("Error", "Failed to capture image.")
                self.set_status("Failed to capture image.")
                return
            rgb_img = cv2.cvtColor(frame_img, cv2.COLOR_BGR2RGB)
            img_pil = Image.fromarray(rgb_img)
            img_tk = ImageTk.PhotoImage(img_pil.resize((300, 300)))
            img_label.config(image=img_tk)
            img_label.image = img_tk

            detector = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
            gray_img = cv2.cvtColor(rgb_img, cv2.COLOR_RGB2GRAY)
            faces = detector.detectMultiScale(gray_img, 1.1, 4)

            if len(faces) > 0:
                # For simplicity, we'll just detect faces and simulate emotion.
                # A real emotion detection would require a dedicated model.
                emotions = ["Happy", "Sad", "Angry", "Neutral", "Surprise"]
                import random
                detected_emotion = random.choice(emotions)
                result_label.config(text=f"Detected Face. Simulated Emotion: {detected_emotion}")
                self.set_status(f"Detected Face. Simulated Emotion: {detected_emotion}")
            else:
                result_label.config(text="No face detected.")
                self.set_status("No face detected.")

        btn = tk.Button(frame, text="Capture & Analyze", command=capture_and_analyze)
        self.style_button(btn)
        btn.pack(pady=10)
        self.add_tooltip(btn, "Capture webcam image and analyze emotion")
        self.current_frame = frame

    # --- Voice Analyzer ---
    def show_voice_analyzer(self):
        self.clear_frame()
        frame = tk.Frame(self, bg=BG_FRAME)
        frame.pack(fill="both", expand=True)
        back_btn = tk.Button(frame, text="⬅ Back", command=self.show_main_menu)
        self.style_back_button(back_btn)
        back_btn.pack(anchor="nw", padx=20, pady=20)
        tk.Label(frame, text="Voice Analyzer", font=("Segoe UI", 32, "bold"), bg=LABEL_BG, fg=LABEL_FG).pack(pady=20)

        status_label = tk.Label(frame, text="", font=("Segoe UI", 16), bg=LABEL_BG, fg=FG_MAIN)
        status_label.pack(pady=10)

        result_label = tk.Label(frame, text="", font=("Segoe UI", 18, "bold"), bg=BG_FRAME, fg=FG_MAIN)
        result_label.pack(pady=10)

        audio_file_path = "recorded_audio.wav"

        def record_audio():
            try:
                import sounddevice as sd
                from scipy.io.wavfile import write

                samplerate = 44100  # Sample rate for audio
                duration = 5  # seconds

                status_label.config(text="Recording... Speak now!")
                self.set_status("Recording audio...")
                recording = sd.rec(int(samplerate * duration), samplerate=samplerate, channels=2)
                sd.wait()  # Wait until recording is finished
                write(audio_file_path, samplerate, recording)  # Save as WAV file
                status_label.config(text="Recording complete. Click Analyze.")
                self.set_status("Audio recorded.")
            except Exception as e:
                messagebox.showerror("Error", f"Error during recording: {e}")
                self.set_status("Error recording audio.")

        def analyze_audio():
            try:
                # This is a placeholder for actual voice analysis.
                # In a real application, you would use libraries like librosa, speech_recognition, or deep learning models
                # to extract features and classify emotion/threat from the audio.
                # For this demo, we'll simulate a result.
                if not os.path.exists(audio_file_path):
                    messagebox.showwarning("File Not Found", "Please record audio first.")
                    self.set_status("No audio file to analyze.")
                    return

                status_label.config(text="Analyzing audio...")
                self.set_status("Analyzing audio...")
                
                # Simulate analysis result
                import random
                results = [("Safe", "✅"), ("Offensive", "😠"), ("Threat", "❌")]
                label, emoji = random.choice(results)

                result_label.config(text=f"Detected: {emoji} {label}")
                play_sound(label.lower())
                self.set_status(f"Voice analyzed: {label}")
                status_label.config(text="Analysis complete.")

            except Exception as e:
                messagebox.showerror("Error", f"Error during analysis: {e}")
                self.set_status("Error analyzing audio.")

        record_btn = tk.Button(frame, text="Record Audio (5s)", command=lambda: threading.Thread(target=record_audio).start())
        self.style_button(record_btn)
        record_btn.pack(pady=10)
        self.add_tooltip(record_btn, "Record 5 seconds of audio from your microphone")

        analyze_btn = tk.Button(frame, text="Analyze Audio", command=lambda: threading.Thread(target=analyze_audio).start())
        self.style_button(analyze_btn)
        analyze_btn.pack(pady=10)
        self.add_tooltip(analyze_btn, "Analyze the recorded audio for threats or emotion")

        self.current_frame = frame

    def on_exit(self):
        self.destroy()
        sys.exit(0)

if __name__ == "__main__":
    app = CyberWatchApp()
    app.mainloop()
