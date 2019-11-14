import tkinter
from tkinter import *
import hashlib


class Window(Frame):
    def __init__(self, master=None):
        Frame.__init__(self, master)
        self.master = master
        # Variable to store the user input (Encrypted Message)
        self.input_hash = StringVar()
        self.hash_type = IntVar()
        self.input_message = StringVar()

        self.hashed_message = Label(self.master)

        self.init_window()

    def init_window(self):
        self.master.title("Hash Cracker")

        Label(self.master, text="Encrypted Message: ").grid(row=0, sticky=tkinter.W)

        # hash_input is the text box that the user can type into, text goes to input_hash
        hash_input = Entry(self.master, textvariable=self.input_hash)
        hash_input.grid(row=0, column=1, sticky=tkinter.W)

        result = Label(self.master, text="Decrypted: ")
        result.grid(row=2, sticky=tkinter.W)

        # Decrypt button calls the decrypt function
        decrypt_button = Button(self.master, text="Decrypt", command=self.decrypt)
        decrypt_button.grid(row=3, column=0, sticky=tkinter.W)

        Label(self.master, text="Enter Message: ").grid(row=4, column=0, sticky=tkinter.W)
        text_input = Entry(self.master, textvariable=self.input_message)
        text_input.grid(row=4, column=1, sticky=tkinter.W)

        sha_radio = Radiobutton(self.master, text='SHA1', variable =self.hash_type, value=0)
        md5_radio = Radiobutton(self.master, text='MD5', variable=self.hash_type, value=1)
        sha_radio.grid(row=5, column=0, sticky=tkinter.W)
        md5_radio.grid(row=5, column=1, sticky=tkinter.W)

        Label(self.master, text="Hashed Message: ").grid(row=6, column=0, sticky=tkinter.W)
        hash_button = Button(self.master, text="Hash", command=self.hash)
        hash_button.grid(row=7, sticky=tkinter.W)

        self.hashed_message.grid(row=6, column=1, sticky=tkinter.W)

    def decrypt(self):
        # TODO: Take the text string and pass it to decryption algorithm
        text = self.input_hash.get()

        # TODO: Print the decrypted message
        Label(self.master, text="                                        ").grid(row=1, column=1, sticky=tkinter.W)
        Label(self.master, text=text).grid(row=1, column=1, sticky=tkinter.W)
        print(text)

    def hash(self):
        choice = self.hash_type.get()
        switcher = {
            0:hashlib.sha1,
            1:hashlib.md5,
        }
        hash_func = switcher.get(choice, lambda: 'default')
        
        text = self.input_message.get().strip()

        if text:
            hashed_text = bytes(text, 'utf-8')
            hash_object = hash_func(hashed_text)
            digest = hash_object.hexdigest()
            self.hashed_message.config(text=digest)
            print(digest)



root = Tk()
# size of window
root.geometry("400x200")


app = Window(root)
root.mainloop()
