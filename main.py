from function.algoritma_rsa import *
from function.algoritma_sha import *

from tkinter import *
from tkinter import filedialog
from tkinter import ttk



def window_setting(window):
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()

    x_position = (screen_width // 2) - (800 // 2)
    y_position = (screen_height // 2) - (300 // 2)

    window.geometry(f"{800}x{300}+{x_position}+{y_position}")
    return window


# GUI
def start(main_menu):
    main_menu.destroy()
    start_menu = Tk()
    start_menu.title("Implementasi Program Tanda Tangan Digital dengan Menggunakan Algoritma RSA dan Fungsi hash SHA-3")

    start_menu = window_setting(start_menu)

    title = Label(start_menu, text="Pilih Menu!", font=("Arial", 15))
    title.pack(pady=10)

    button1 = ttk.Button(start_menu, text="Generate Key", command=lambda: generate_keypair()).pack(pady=10)
    button2 = ttk.Button(start_menu, text="Digital Sign a File", command=lambda: sign(start_menu)).pack(pady=10)
    button3 = ttk.Button(start_menu, text="Verify Digital Sign", command=lambda: verify(start_menu)).pack(pady=10)

def sign(start_menu):
    start_menu.destroy()
    menu_sign = Tk()
    menu_sign.title("Sign a File")

    menu_sign = window_setting(menu_sign)

    title = Label(menu_sign, text="Sign a File!", font=("Arial", 15))
    title.pack(pady=10)

    file_path = filedialog.askopenfilename(title="Choose a file to sign",
                                           filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
    try:
        file = open(file_path, "r", encoding="latin-1")
    except:
        messagebox.showerror("Error", "File not found!")
        start(menu_sign)
        return
    content = file.read()
    file.close()

    start_sign = content.find("<m>")
    end_sign = content.find("</m>")

    if start_sign != -1 and end_sign != -1:
        messagebox.showerror("Error", "File is already signed!")
        start(menu_sign)
    else:
        label = Label(menu_sign, text="Upload your private key", font=("Arial", 15))
        label.pack(pady=10)
        try:
            (d, n, menu_sign) = upload_key(menu_sign)
        except:
            return
        digital_sign = digitalsign(content, (d, n))
        if file_path[-4:] == ".txt":
            file = open(file_path, "a", encoding="latin-1")
            file.write("<m>" + digital_sign + "</m>")
            file.close()
            messagebox.showinfo("Success", "File signed successfully!")
            start(menu_sign)
        else:
            file = open('signature.pri', 'r')
            content = file.read()
            if content == "":
                file = open('signature.pri', 'a')
                file.write("<m>" + digital_sign + "</m>")
                file.close()
                messagebox.showinfo("Success", "File signed successfully! Check your signature in signature.pri")
                start(menu_sign)
            else:
                messagebox.showerror("Error", "File is already signed!")
                start(menu_sign)


def verify(start_menu):
    start_menu.destroy()
    menu_verify = Tk()
    menu_verify.title("Verify Digital Sign")

    menu_verify = window_setting(menu_verify)

    title = Label(menu_verify, text="Verify Digital Sign!", font=("Arial", 15))
    title.pack(pady=10)

    file_path = filedialog.askopenfilename(title="Choose a file to verify",
                                           filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
    try:
        file = open(file_path, "r", encoding="latin-1")
        if file_path[-4:] != ".txt":
            content_non_txt = file.read()
            label = Label(menu_verify, text="Upload file digital signature!", font=("Arial", 15))
            label.pack(pady=10)
            file_path = filedialog.askopenfilename(title="Choose a file digital signature",
                                                   filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
            try:
                file = open(file_path, "r", encoding="latin-1")
                content = file.read()

                sign = check_sign(content)
                if sign == "File is not signed!":
                    messagebox.showerror("Error", sign)
                    start(menu_verify)
                else:
                    verified = verifysign(content_non_txt, sign, menu_verify)
                    if verified:
                        messagebox.showinfo("Success", "File is verified!")
                        start(menu_verify)
                    else:
                        messagebox.showerror("Error", "File is not verified!")
                        start(menu_verify)
            except:
                messagebox.showerror("Error", "File not found!")
                start(menu_verify)
                return
        else:
            content = file.read()
            sign = check_sign(content)
            if sign == "File is not signed!":
                messagebox.showerror("Error", sign)
                start(menu_verify)
                return
            else:
                content = content.replace("<m>" + sign + "</m>", "")
                verified = verifysign(content, sign, menu_verify)
                if verified:
                    messagebox.showinfo("Success", "File is verified!")
                    start(menu_verify)
                else:
                    messagebox.showerror("Error", "File is not verified!")
                    start(menu_verify)
    except Exception as e:
        messagebox.showerror("Error", e)
        start(menu_verify)
        return
    file.close()


def check_sign(content):
    start_sign = content.find("<m>")
    end_sign = content.find("</m>")
    if start_sign != -1 and end_sign != -1:
        return content[start_sign + 3: end_sign]
    else:
        return "File is not signed!"


def upload_key(menu_sign):
    file_path = filedialog.askopenfilename(title="Choose a file contain your key",
                                           filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
    try:
        file = open(file_path, "r", encoding="latin-1")
    except Exception as e:
        messagebox.showerror("Error", e)
        start(menu_sign)
        return

    content = file.read()
    i = 0
    key = ''
    n = ''
    while i < len(content):
        if content[i] != ' ':
            key += content[i]
            i += 1
        else:
            n = content[i + 1: len(content)]
            i = len(content)

    return int(key), int(n), menu_sign


def digitalsign(message, private_key):
    hashedMessage = sha3(message)
    hashedMessage = bytes.fromhex(hashedMessage)
    sign = encrypt_rsa(hashedMessage, private_key)

    return sign


def verifysign(content, sign, menu_verify):
    label = Label(menu_verify, text="Upload your public key", font=("Arial", 15))
    label.pack(pady=10)
    try:
        (e, n, menu_verify) = upload_key(menu_verify)
    except:
        return
    sign = bytes.fromhex(sign)

    return sha3(content) == decrypt_rsa(sign, (e, n))


menu = Tk()
start(menu)
menu.mainloop()
