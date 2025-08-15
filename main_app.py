import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import os
from DataScrambling2 import process_file, generate_key


class DataCryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Data Encryptor/Decryptor")
        self.root.geometry("700x550")
        self.root.resizable(False, False)

        self.bg_color = "#f0f0f0"
        self.btn_color = "#4CAF50"
        self.btn_active_color = "#45a049"
        self.label_font = ("Helvetica", 12)
        self.btn_font = ("Helvetica", 10, "bold")
        self.status_font = ("Helvetica", 10, "italic")

        self.main_frame = tk.Frame(root, padx=20, pady=20, bg=self.bg_color)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self.title_label = tk.Label(self.main_frame, text="Personal Data Encryptor/Decryptor",
                                    font=("Helvetica", 16, "bold"), bg=self.bg_color)
        self.title_label.pack(pady=10)

        # Input file section
        self.input_frame = tk.Frame(self.main_frame, bg=self.bg_color)
        self.input_frame.pack(pady=10, fill=tk.X)
        tk.Label(self.input_frame, text="Select Input File:", font=self.label_font, bg=self.bg_color).pack(side=tk.LEFT)
        self.input_entry = tk.Entry(self.input_frame, width=40, font=self.label_font)
        self.input_entry.pack(side=tk.LEFT, padx=(5, 0))
        tk.Button(self.input_frame, text="Browse", command=self.browse_file, font=self.btn_font, bg=self.btn_color,
                  fg="white", activebackground=self.btn_active_color).pack(side=tk.LEFT, padx=5)

        # Key section
        self.key_frame = tk.Frame(self.main_frame, bg=self.bg_color)
        self.key_frame.pack(pady=10, fill=tk.X)
        tk.Label(self.key_frame, text="Encryption/Decryption Key:", font=self.label_font, bg=self.bg_color).pack(
            side=tk.LEFT)
        self.key_entry = tk.Entry(self.key_frame, width=50, font=self.label_font)
        self.key_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        tk.Button(self.key_frame, text="Generate New Key", command=self.generate_and_set_key, font=self.btn_font).pack(
            side=tk.LEFT)

        # Mode selection
        self.mode_frame = tk.Frame(self.main_frame, bg=self.bg_color)
        self.mode_frame.pack(pady=10)
        self.mode_var = tk.StringVar(value='encrypt')
        tk.Radiobutton(self.mode_frame, text="Encrypt", variable=self.mode_var, value='encrypt', font=self.label_font,
                       bg=self.bg_color).pack(side=tk.LEFT, padx=10)
        tk.Radiobutton(self.mode_frame, text="Decrypt", variable=self.mode_var, value='decrypt', font=self.label_font,
                       bg=self.bg_color).pack(side=tk.LEFT, padx=10)

        # Process button
        self.process_btn = tk.Button(self.main_frame, text="Process Data", command=self.process,
                                     font=("Helvetica", 14, "bold"), bg="#FF5722", fg="white",
                                     activebackground="#E64A19", width=20, height=2)
        self.process_btn.pack(pady=10)

        # Status label
        self.status_label = tk.Label(self.main_frame, text="Enter a file path and key, then choose a mode.",
                                     font=self.status_font, bg=self.bg_color)
        self.status_label.pack(pady=20)

        # Key storage information
        self.key_info = scrolledtext.ScrolledText(self.main_frame, height=5, width=60, font=("Courier", 10))
        self.key_info.pack(pady=5)
        self.key_info.insert(tk.END,
                             "Generated key will appear here. SAVE IT! It is not stored and you need it for decryption.\n")
        self.key_info.config(state=tk.DISABLED)

    def browse_file(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Data Files", "*.csv *.xlsx"), ("All Files", "*.*")]
        )
        if file_path:
            self.input_entry.delete(0, tk.END)
            self.input_entry.insert(0, file_path)
            self.status_label.config(text="File selected. Ready to process.")

    def generate_and_set_key(self):
        new_key = generate_key()
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, new_key)
        self.key_info.config(state=tk.NORMAL)
        self.key_info.delete(1.0, tk.END)
        self.key_info.insert(tk.END,
                             f"NEW KEY GENERATED:\n{new_key}\n\nSAVE THIS KEY! It is essential for decryption and will not be stored.")
        self.key_info.config(state=tk.DISABLED)

    def process(self):
        input_path = self.input_entry.get()
        key_str = self.key_entry.get()
        mode = self.mode_var.get()

        if not input_path:
            messagebox.showerror("Error", "Please select a file.")
            return
        if not key_str:
            messagebox.showerror("Error", "Please enter or generate an encryption/decryption key.")
            return

        try:
            key = key_str.encode()
            if not Fernet.is_valid_key(key):
                messagebox.showerror("Error", "The provided key is invalid.")
                return
        except Exception:
            messagebox.showerror("Error", "Invalid key format.")
            return

        if not os.path.exists(input_path):
            messagebox.showerror("Error", f"File not found: {input_path}")
            return

        try:
            directory, filename = os.path.split(input_path)
            base, ext = os.path.splitext(filename)
            output_path = os.path.join(directory, f"{mode}d_{base}{ext}")

            self.status_label.config(text=f"Processing in progress...")
            self.root.update_idletasks()

            result_message = process_file(input_path, output_path, key, mode=mode)

            if result_message.startswith("Success"):
                self.status_label.config(text=f"Processing complete. Output saved.")
                messagebox.showinfo("Success", f"{result_message}\nOutput saved to:\n{output_path}")
            else:
                self.status_label.config(text="Processing failed.")
                messagebox.showerror("Error", result_message)
        except Exception as e:
            messagebox.showerror("An unexpected error occurred", str(e))
            self.status_label.config(text="Processing failed.")


if __name__ == "__main__":
    root = tk.Tk()
    app = DataCryptoApp(root)
    root.mainloop()