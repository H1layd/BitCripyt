import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import base64
import pyperclip

translations = {
    "Русский": {
        "input_label": "Введите текст:",
        "key_label": "Выберите ключ:",
        "encrypt_button": "Зашифровать",
        "decrypt_button": "Рассшифровать",
        "copy_button": "Копировать",
        "paste_button": "Вставить",
        "load_button": "Загрузить файл",
        "output_label": "Результат:",
        "warning_empty_text": "Введите текст для шифрования.",
        "warning_empty_encrypted": "Введите зашифрованный текст для расшифровки.",
        "error_invalid_key": "Неверный ключ",
        "copy_success": "Текст скопирован в буфер обмена.",
        "paste_error": "Не удалось вставить текст: {error}"
    }
}


keys = ["D7YA", "D8YA", "KAFD", "VSU"]

def encrypt(text, shift):
    return ''.join(chr((ord(char) + shift - 32) % 95 + 32) for char in text)

def decrypt(encrypted_text, shift):
    return ''.join(chr((ord(char) - shift - 32) % 95 + 32) for char in encrypted_text)

def utf7_to_base64(text):
    return base64.b64encode(text.encode('utf-7')).decode()

def utf8_to_base64(text):
    return base64.b64encode(text.encode('utf-8')).decode()

def base64_to_utf7(text):
    return base64.b64decode(text).decode('utf-7')

def base64_to_utf8(text):
    return base64.b64decode(text).decode('utf-8')

def process_key(key, input_text):
    if key == "D7YA":
        encoded = utf7_to_base64(input_text)
        encrypted = encrypt(encoded, 0)
        final = utf8_to_base64(encrypted)
        return final
    elif key == "D8YA":
        encoded = utf8_to_base64(input_text)
        encrypted = encrypt(encoded, 0)
        final = utf8_to_base64(encrypted)
        return final
    elif key == "KAFD":
        encoded = utf7_to_base64(input_text)
        encrypted = encrypt(encoded, 3)
        final = base64.b64encode(encrypted.encode()).decode()
        return final
    elif key == "VSU":

        encoded = utf8_to_base64(input_text)
        encrypted = encrypt(encoded, 98)
        final = base64.b64encode(encrypted.encode()).decode()
        return final
    else:
        raise ValueError("Неверный ключ")

def process_encryption():
    text = input_text.get("1.0", tk.END).strip()
    key = key_combobox.get().strip()
    
    if not text:
        messagebox.showwarning("Предупреждение", translations["Русский"]["warning_empty_text"])
        return
    
    try:
        encrypted_text = process_key(key, text)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, encrypted_text)
    except Exception as e:
        messagebox.showerror("Ошибка", str(e))

def process_decryption():
    encrypted_text = input_text.get("1.0", tk.END).strip()
    key = key_combobox.get().strip()
    
    if not encrypted_text:
        messagebox.showwarning("Предупреждение", translations["Русский"]["warning_empty_encrypted"])
        return
    
    try:
        if key == "D7YA":
            decoded = base64_to_utf8(encrypted_text)
            decrypted = decrypt(decoded, 0)
            final = base64_to_utf7(decrypted)
            output_text.delete("1.0", tk.END)
            output_text.insert(tk.END, final)
        elif key == "D8YA":
            decoded = base64_to_utf8(encrypted_text)
            decrypted = decrypt(decoded, 0)
            output_text.delete("1.0", tk.END)
            output_text.insert(tk.END, decrypted)
        elif key == "KAFD":
            decoded = base64.b64decode(encrypted_text).decode()
            decrypted = decrypt(decoded, 3)
            output_text.delete("1.0", tk.END)
            output_text.insert(tk.END, decrypted)
        elif key == "VSU":
            decoded = base64.b64decode(encrypted_text).decode()
            decrypted = decrypt(decoded, 98)
            final = base64_to_utf8(decrypted)
            output_text.delete("1.0", tk.END)
            output_text.insert(tk.END, final)
    except Exception as e:
        messagebox.showerror("Ошибка", str(e))

def load_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, 'r', encoding='utf-8') as file:
            input_text.delete("1.0", tk.END)
            input_text.insert(tk.END, file.read())

def copy_to_clipboard():
    text = output_text.get("1.0", tk.END).strip()
    if text:
        pyperclip.copy(text)
        messagebox.showinfo("Успех", translations["Русский"]["copy_success"])

def paste_from_clipboard():
    try:
        text = pyperclip.paste()
        input_text.delete("1.0", tk.END)
        input_text.insert(tk.END, text)
    except Exception as e:
        messagebox.showerror("Ошибка", translations["Русский"]["paste_error"].format(error=str(e)))


root = tk.Tk()
root.title("Шифрование и расшифрование")
root.geometry("600x600")
root.configure(bg="#f0f0f0")

input_label = tk.Label(root, text=translations["Русский"]["input_label"], bg="#f0f0f0")
input_label.pack(pady=5)

input_text = tk.Text(root, height=10, width=50, wrap=tk.WORD)
input_text.pack(pady=5)

key_label = tk.Label(root, text=translations["Русский"]["key_label"], bg="#f0f0f0")
key_label.pack(pady=5)

key_combobox = ttk.Combobox(root, values=keys, state="readonly")
key_combobox.set(keys[0])
key_combobox.pack(pady=5)


button_frame = tk.Frame(root, bg="#f0f0f0")
button_frame.pack(pady=5)

encrypt_button = tk.Button(button_frame, text=translations["Русский"]["encrypt_button"], command=process_encryption, bg="#4CAF50", fg="white")
encrypt_button.pack(side=tk.LEFT, padx=5)

decrypt_button = tk.Button(button_frame, text=translations["Русский"]["decrypt_button"], command=process_decryption, bg="#f44336", fg="white")
decrypt_button.pack(side=tk.LEFT, padx=5)

load_button = tk.Button(button_frame, text=translations["Русский"]["load_button"], command=load_file, bg="#2196F3", fg="white")
load_button.pack(side=tk.LEFT, padx=5)

copy_button = tk.Button(button_frame, text=translations["Русский"]["copy_button"], command=copy_to_clipboard, bg="#FFC107", fg="white")
copy_button.pack(side=tk.LEFT, padx=5)

paste_button = tk.Button(button_frame, text=translations["Русский"]["paste_button"], command=paste_from_clipboard, bg="#FF5722", fg="white")
paste_button.pack(side=tk.LEFT, padx=5)

output_label = tk.Label(root, text=translations["Русский"]["output_label"], bg="#f0f0f0")
output_label.pack(pady=5)

output_text = tk.Text(root, height=10, width=50, wrap=tk.WORD)
output_text.pack(pady=5)

root.mainloop()