from tkinter import *
from tkinter import filedialog, messagebox
import base64
import png
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

end_of_message = "010110100101011100110101011010110101100000110010001110010110110101011000001100100011000101101100011000110011001101001110011010000101101000110010010101010011110100001010"

class SteganographyApp:
    def __init__(self, master):
        self.master = master
        self.master.withdraw()  # Hide main window initially
        
        # Initialize variables
        self.path1 = self.path2 = ""
        self.encryption_key = None
        self.encryption_algorithm = None
        self.decryption_algorithm = None
        
        # Windows
        self.main_window = None
        self.encode_window = None
        self.decode_window = None
        self.encode_algorithm_window = None
        self.decode_algorithm_window = None
        
        # Widgets
        self.fileAddress1 = None
        self.fileAddress2 = None
        self.msg = None
        self.key_entry = None
        self.decryption_key_entry = None
        
        self.setup_main_window()
        self.show_main_window()
    
    def setup_main_window(self):
        """Initialize the main application window"""
        if self.main_window is None:
            self.main_window = Toplevel(self.master)
            self.main_window.protocol("WM_DELETE_WINDOW", self.close)
            self.main_window.title("Image Steganography Tool")
            self.main_window.geometry("800x600")
            self.main_window.state('zoomed')
            self.main_window.config(background="#9068C7")
            
            # Title frame
            title_frame = Frame(self.main_window, bg="#5A24A4")
            title_frame.pack(fill=X)
            
            Label(title_frame, text="Image Steganography", 
                  font=("Times", 28, "bold", "italic"), 
                  fg="yellow", bg="#5A24A4").pack(pady=30)
            
            # Button frame
            button_frame = Frame(self.main_window, bg="#9068C7")
            button_frame.pack(expand=True)
            
            # Encode button
            encode_btn = Button(button_frame, text="Encode", bg="red", 
                               activebackground="orange", borderwidth=5, 
                               font=("Times", 24), command=self.show_encode_algorithm_window,
                               width=15, height=2)
            encode_btn.pack(pady=30)
            
            # Decode button
            decode_btn = Button(button_frame, text="Decode", bg="cyan", 
                               activebackground="skyblue", borderwidth=5, 
                               font=("Times", 24), command=self.show_decode_algorithm_window,
                               width=15, height=2)
            decode_btn.pack(pady=30)
            
            # Close button
            close_btn = Button(button_frame, text="Close", borderwidth=5, 
                              font=("Times", 24), command=self.close,
                              width=15, height=2)
            close_btn.pack(pady=30)
    
    def show_main_window(self):
        """Show the main window and hide others"""
        self.hide_all_windows()
        if self.main_window:
            self.main_window.deiconify()
            self.main_window.state('zoomed')
    
    def hide_all_windows(self):
        """Hide all windows except main"""
        if self.encode_window: self.encode_window.withdraw()
        if self.decode_window: self.decode_window.withdraw()
        if self.encode_algorithm_window: self.encode_algorithm_window.withdraw()
        if self.decode_algorithm_window: self.decode_algorithm_window.withdraw()
    
    # ====================== ENCODING FUNCTIONS ======================
    def show_encode_algorithm_window(self):
        """Show window for selecting encryption algorithm"""
        self.hide_all_windows()
        
        if self.encode_algorithm_window is None:
            self.encode_algorithm_window = Toplevel(self.master)
            self.encode_algorithm_window.protocol("WM_DELETE_WINDOW", self.show_main_window)
            self.encode_algorithm_window.bind("<Escape>", lambda e: self.show_main_window())
            
            # Main content
            Label(self.encode_algorithm_window, text="Select Encryption Algorithm", 
                  bg="#9068C7", fg="white", font=("Times", 20, "bold")).pack(pady=20)
            
            self.encryption_algorithm = StringVar(value="AES")
            
            algorithm_frame = Frame(self.encode_algorithm_window, bg="#9068C7")
            algorithm_frame.pack(pady=20)
            
            Radiobutton(algorithm_frame, text="AES", variable=self.encryption_algorithm, 
                        value="AES", bg="#9068C7", font=("Times", 16)).pack(anchor=W, pady=5)
            Radiobutton(algorithm_frame, text="DES", variable=self.encryption_algorithm, 
                        value="DES", bg="#9068C7", font=("Times", 16)).pack(anchor=W, pady=5)
            Radiobutton(algorithm_frame, text="RSA", variable=self.encryption_algorithm, 
                        value="RSA", bg="#9068C7", font=("Times", 16)).pack(anchor=W, pady=5)
            
            Button(self.encode_algorithm_window, text="Next", command=self.show_encode_window, 
                   font=("Times", 16), padx=20, pady=5).pack(pady=20)
        
        self.encode_algorithm_window.title("Select Encryption Algorithm")
        self.encode_algorithm_window.geometry("800x600")
        self.encode_algorithm_window.state('zoomed')
        self.encode_algorithm_window.deiconify()
        self.encode_algorithm_window.configure(bg="#9068C7")
    
    def show_encode_window(self):
        """Show the encoding window"""
        if self.encode_algorithm_window:
            self.encode_algorithm_window.withdraw()
        
        if self.encode_window is None:
            self.encode_window = Toplevel(self.master)
            self.encode_window.protocol("WM_DELETE_WINDOW", self.show_main_window)
            self.encode_window.bind("<Escape>", lambda e: self.show_main_window())
            self.encode_window.bind("<Return>", self.encode)
            
            # Main frame
            main_frame = Frame(self.encode_window, bg="#9068C7")
            main_frame.pack(fill=BOTH, expand=True, padx=20, pady=20)
            
            Label(main_frame, text="Encode Message", bg="#9068C7", fg="white", 
                  font=("Times", 20, "bold")).pack(pady=20)
            
            # File selection
            file_frame = Frame(main_frame, bg="#9068C7")
            file_frame.pack(fill=X, pady=10)
            
            Label(file_frame, text="Select PNG File:", bg="#9068C7", fg="white", 
                  font=("Times", 14)).pack(side=LEFT, padx=10)
            
            self.fileAddress1 = Entry(file_frame, width=50, font=("Times", 14))
            self.fileAddress1.pack(side=LEFT, expand=True, fill=X, padx=10)
            
            Button(file_frame, text="Browse", command=self.select_file_for_encoding, 
                   font=("Times", 12)).pack(side=LEFT, padx=10)
            
            # Key entry
            key_frame = Frame(main_frame, bg="#9068C7")
            key_frame.pack(fill=X, pady=10)
            
            Label(key_frame, text="Encryption Key:", bg="#9068C7", fg="white", 
                  font=("Times", 14)).pack(side=LEFT, padx=10)
            
            self.key_entry = Entry(key_frame, width=50, font=("Times", 14))
            self.key_entry.pack(side=LEFT, expand=True, fill=X, padx=10)
            
            # Key info
            Label(main_frame, 
                  text="Key formats:\nAES: 16/24/32 chars\nDES: 8 chars\nRSA: Paste public key",
                  bg="#9068C7", fg="yellow", font=("Arial", 12)).pack(pady=10)
            
            # Message entry
            msg_frame = Frame(main_frame, bg="#9068C7")
            msg_frame.pack(fill=BOTH, expand=True, pady=10)
            
            Label(msg_frame, text="Message to Encode:", bg="#9068C7", fg="white", 
                  font=("Times", 14)).pack(anchor=W, padx=10)
            
            self.msg = Text(msg_frame, font=("Times", 14), wrap=WORD, height=10)
            self.msg.pack(fill=BOTH, expand=True, padx=10, pady=5)
            
            # Buttons
            button_frame = Frame(main_frame, bg="#9068C7")
            button_frame.pack(pady=20)
            
            Button(button_frame, text="Encode", command=self.encode, font=("Times", 16), 
                   padx=20, pady=5).pack(side=LEFT, padx=20)
            Button(button_frame, text="Back", command=self.show_encode_algorithm_window, 
                   font=("Times", 16), padx=20, pady=5).pack(side=LEFT, padx=20)
            Button(button_frame, text="Close", command=self.show_main_window, 
                   font=("Times", 16), padx=20, pady=5).pack(side=LEFT, padx=20)
        
        self.encode_window.title("Encode Message")
        self.encode_window.geometry("800x600")
        self.encode_window.state('zoomed')
        self.encode_window.deiconify()
    
    def select_file_for_encoding(self):
        """Select file for encoding"""
        filename = filedialog.askopenfilename(
            initialdir="Downloads", 
            title="Select a PNG file", 
            filetypes=(("png Files", "*.png"), ("All Files", "*.*"))
        )
        if filename:
            self.fileAddress1.delete(0, END)
            self.fileAddress1.insert(0, filename)
            self.path1 = filename
    
    def encode(self, e=None):
        """Encode the message into the image"""
        if not self.path1:
            self.show_error("Please select a file first!")
            return
        
        message = self.msg.get("1.0", END).strip()
        if not message:
            self.show_error("Please enter a message to encode!")
            return
        
        key = self.key_entry.get().encode()
        if not key:
            self.show_error("Please enter an encryption key!")
            return
        
        try:
            encrypted_message = self.encrypt_message(message, self.encryption_algorithm.get(), key)
            pixels = self.get_pixels_from_image(self.path1)
            bytestring = self.encode_message_as_bytestring(encrypted_message)
            epixels = self.encode_pixels_with_message(pixels, bytestring)
            output_path = self.path1 + "-enc.png"
            self.write_pixels_to_image(epixels, output_path)
            
            self.show_success(f"Encoding Successful!\nFile saved as:\n{output_path}")
            
        except Exception as e:
            self.show_error(f"Encoding failed: {str(e)}")
    
    # ====================== DECODING FUNCTIONS ======================
    def show_decode_algorithm_window(self):
        """Show window for selecting decryption algorithm"""
        self.hide_all_windows()
        
        if self.decode_algorithm_window is None:
            self.decode_algorithm_window = Toplevel(self.master)
            self.decode_algorithm_window.protocol("WM_DELETE_WINDOW", self.show_main_window)
            self.decode_algorithm_window.bind("<Escape>", lambda e: self.show_main_window())
            
            # Main content
            Label(self.decode_algorithm_window, text="Select Decryption Algorithm", 
                  bg="#9068C7", fg="white", font=("Times", 20, "bold")).pack(pady=20)
            
            self.decryption_algorithm = StringVar(value="AES")
            
            algorithm_frame = Frame(self.decode_algorithm_window, bg="#9068C7")
            algorithm_frame.pack(pady=20)
            
            Radiobutton(algorithm_frame, text="AES", variable=self.decryption_algorithm, 
                        value="AES", bg="#9068C7", font=("Times", 16)).pack(anchor=W, pady=5)
            Radiobutton(algorithm_frame, text="DES", variable=self.decryption_algorithm, 
                        value="DES", bg="#9068C7", font=("Times", 16)).pack(anchor=W, pady=5)
            Radiobutton(algorithm_frame, text="RSA", variable=self.decryption_algorithm, 
                        value="RSA", bg="#9068C7", font=("Times", 16)).pack(anchor=W, pady=5)
            
            Button(self.decode_algorithm_window, text="Next", command=self.show_decode_window, 
                   font=("Times", 16), padx=20, pady=5).pack(pady=20)
        
        self.decode_algorithm_window.title("Select Decryption Algorithm")
        self.decode_algorithm_window.geometry("800x600")
        self.decode_algorithm_window.state('zoomed')
        self.decode_algorithm_window.deiconify()
        self.decode_algorithm_window.configure(bg="#9068C7")
    
    def show_decode_window(self):
        """Show the decoding window"""
        if self.decode_algorithm_window:
            self.decode_algorithm_window.withdraw()
        
        if self.decode_window is None:
            self.decode_window = Toplevel(self.master)
            self.decode_window.protocol("WM_DELETE_WINDOW", self.show_main_window)
            self.decode_window.bind("<Escape>", lambda e: self.show_main_window())
            self.decode_window.bind("<Return>", self.decode)
            
            # Main frame
            main_frame = Frame(self.decode_window, bg="#9068C7")
            main_frame.pack(fill=BOTH, expand=True, padx=20, pady=20)
            
            Label(main_frame, text="Decode Message", bg="#9068C7", fg="white", 
                  font=("Times", 20, "bold")).pack(pady=20)
            
            # File selection
            file_frame = Frame(main_frame, bg="#9068C7")
            file_frame.pack(fill=X, pady=10)
            
            Label(file_frame, text="Select Encoded PNG File:", bg="#9068C7", fg="white", 
                  font=("Times", 14)).pack(side=LEFT, padx=10)
            
            self.fileAddress2 = Entry(file_frame, width=50, font=("Times", 14))
            self.fileAddress2.pack(side=LEFT, expand=True, fill=X, padx=10)
            
            Button(file_frame, text="Browse", command=self.select_file_for_decoding, 
                   font=("Times", 12)).pack(side=LEFT, padx=10)
            
            # Key entry
            key_frame = Frame(main_frame, bg="#9068C7")
            key_frame.pack(fill=X, pady=10)
            
            Label(key_frame, text="Decryption Key:", bg="#9068C7", fg="white", 
                  font=("Times", 14)).pack(side=LEFT, padx=10)
            
            self.decryption_key_entry = Entry(key_frame, width=50, font=("Times", 14))
            self.decryption_key_entry.pack(side=LEFT, expand=True, fill=X, padx=10)
            
            # Key info
            Label(main_frame, 
                  text="Key formats:\nAES: 16/24/32 chars\nDES: 8 chars\nRSA: Paste private key",
                  bg="#9068C7", fg="yellow", font=("Arial", 12)).pack(pady=10)
            
            # Buttons
            button_frame = Frame(main_frame, bg="#9068C7")
            button_frame.pack(pady=20)
            
            Button(button_frame, text="Decode", command=self.decode, font=("Times", 16), 
                   padx=20, pady=5).pack(side=LEFT, padx=20)
            Button(button_frame, text="Back", command=self.show_decode_algorithm_window, 
                   padx=20, pady=5, font=("Times", 16)).pack(side=LEFT, padx=20)
            Button(button_frame, text="Close", command=self.show_main_window, 
                   padx=20, pady=5, font=("Times", 16)).pack(side=LEFT, padx=20)
        
        self.decode_window.title("Decode Message")
        self.decode_window.geometry("800x600")
        self.decode_window.state('zoomed')
        self.decode_window.deiconify()
    
    def select_file_for_decoding(self):
        """Select file for decoding"""
        filename = filedialog.askopenfilename(
            initialdir="Downloads", 
            title="Select a PNG file", 
            filetypes=(("png Files", "*.png"), ("All Files", "*.*"))
        )
        if filename:
            self.fileAddress2.delete(0, END)
            self.fileAddress2.insert(0, filename)
            self.path2 = filename
    
    def decode(self, e=None):
        """Decode the message from the image"""
        if not self.path2:
            self.show_error("Please select a file first!")
            return
        
        key = self.decryption_key_entry.get().encode()
        if not key:
            self.show_error("Please enter a decryption key!")
            return
        
        try:
            pixels = self.get_pixels_from_image(self.path2)
            encrypted_message = self.decode_pixels(pixels)
            
            if not encrypted_message:
                self.show_error("No encoded message found in the image!")
                return
                
            decrypted_message = self.decrypt_message(encrypted_message, 
                                                    self.decryption_algorithm.get(), 
                                                    key)
            
            self.show_result("Decrypted Message", decrypted_message)
            
        except Exception as e:
            self.show_error(f"Decoding failed: {str(e)}")
    
    # ====================== HELPER FUNCTIONS ======================
    def show_result(self, title, message):
        """Show result in a new window"""
        result_window = Toplevel(self.master)
        result_window.title(title)
        result_window.geometry("800x600")
        
        text_frame = Frame(result_window)
        text_frame.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        scrollbar = Scrollbar(text_frame)
        scrollbar.pack(side=RIGHT, fill=Y)
        
        result_text = Text(text_frame, wrap=WORD, yscrollcommand=scrollbar.set,
                          font=("Arial", 12), padx=10, pady=10)
        result_text.pack(fill=BOTH, expand=True)
        
        scrollbar.config(command=result_text.yview)
        
        result_text.insert(END, message)
        result_text.config(state=DISABLED)
        
        Button(result_window, text="Close", command=result_window.destroy,
              font=("Arial", 12)).pack(pady=10)
    
    def show_error(self, message):
        """Show error message"""
        messagebox.showerror("Error", message)
    
    def show_success(self, message):
        """Show success message"""
        messagebox.showinfo("Success", message)
    
    def close(self):
        """Close the application"""
        self.master.destroy()
    
    # ====================== STEGANOGRAPHY FUNCTIONS ======================
    def get_pixels_from_image(self, fname):
        """Get pixel data from image"""
        img = png.Reader(fname).read()
        return img[2]
    
    def decode_message_from_bytestring(self, bytestring):
        """Decode message from binary string"""
        bytestring = bytestring.split(end_of_message)[0]
        message = int(bytestring, 2).to_bytes(len(bytestring) // 8, byteorder="big")
        return base64.decodebytes(message).decode("utf8", errors="ignore")
    
    def decode_pixels(self, pixels):
        """Decode message from pixels"""
        bytestring = []
        for row in pixels:
            for c in row:
                bytestring.append(str(c % 2))
        bytestring = "".join(bytestring)
        return self.decode_message_from_bytestring(bytestring)
    
    def decrypt_message(self, encrypted_message, selected_algorithm, key):
        """Decrypt message using specified algorithm"""
        encrypted_message = base64.b64decode(encrypted_message)
        
        if selected_algorithm == "AES":
            nonce = encrypted_message[:16]
            tag = encrypted_message[16:32]
            ciphertext = encrypted_message[32:]
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag).decode()
            
        elif selected_algorithm == "DES":
            # For DES in CBC mode with proper padding handling
            iv = encrypted_message[:8]  # IV is always 8 bytes for DES
            ciphertext = encrypted_message[8:]
            cipher = DES.new(key, DES.MODE_CBC, iv=iv)
            try:
                decrypted = cipher.decrypt(ciphertext)
                return unpad(decrypted, DES.block_size).decode()
            except (ValueError, KeyError) as e:
                raise ValueError("DES decryption failed - incorrect key or corrupted data")
            
        elif selected_algorithm == "RSA":
            key = RSA.import_key(key)
            cipher = PKCS1_OAEP.new(key)
            return cipher.decrypt(encrypted_message).decode()
    
    def write_pixels_to_image(self, pixels, fname):
        """Write pixels to image file"""
        png.from_array(pixels, "RGB").save(fname)
    
    def encode_pixels_with_message(self, pixels, bytestring):
        """Encode message into pixels"""
        enc_pixels = []
        string_i = 0
        for row in pixels:
            enc_row = []
            for i, char in enumerate(row):
                if string_i >= len(bytestring):
                    pixel = row[i]
                else:
                    if row[i] % 2 != int(bytestring[string_i]):
                        pixel = row[i] - 1 if row[i] > 0 else 1
                    else:
                        pixel = row[i]
                enc_row.append(pixel)
                string_i += 1
            enc_pixels.append(enc_row)
        return enc_pixels
    
    def encrypt_message(self, message, algorithm, key):
        """Encrypt message using specified algorithm"""
        if algorithm == "AES":
            if len(key) not in [16, 24, 32]:
                raise ValueError("AES key must be 16, 24, or 32 bytes long")
            cipher = AES.new(key, AES.MODE_EAX)
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(message.encode())
            return base64.b64encode(nonce + tag + ciphertext).decode()
            
        elif algorithm == "DES":
            if len(key) != 8:
                raise ValueError("DES key must be exactly 8 bytes long")
            # Using CBC mode with PKCS7 padding
            cipher = DES.new(key, DES.MODE_CBC)
            iv = cipher.iv
            padded_message = pad(message.encode(), DES.block_size)
            ciphertext = cipher.encrypt(padded_message)
            return base64.b64encode(iv + ciphertext).decode()
            
        elif algorithm == "RSA":
            try:
                key = RSA.import_key(key)
                cipher = PKCS1_OAEP.new(key)
                ciphertext = cipher.encrypt(message.encode())
                return base64.b64encode(ciphertext).decode()
            except ValueError:
                raise ValueError("Invalid RSA public key")
    
    def encode_message_as_bytestring(self, message):
        """Encode message as binary string"""
        b64 = message.encode("utf8")
        bytes_ = base64.encodebytes(b64)
        bytestring = "".join(["{:08b}".format(x) for x in bytes_])
        bytestring += end_of_message
        return bytestring

# Start the application
if __name__ == "__main__":
    root = Tk()
    app = SteganographyApp(root)
    root.mainloop()