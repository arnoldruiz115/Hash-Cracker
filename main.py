import re
import requests
import tkinter
from tkinter import *
import requests
import hashlib
import itertools
import string
import sys

class Window(Frame):
    def __init__(self, master=None):
        Frame.__init__(self, master)
        self.master = master
        # Variable to store the user input (Encrypted Message)
        self.input_hash = StringVar()
        self.hash_type = IntVar()
        self.decrypt_type = IntVar()
        self.input_message = StringVar()

        self.hashed_message = Entry(self.master, width=50)

        self.init_window()

    def init_window(self):
        self.master.title("Hash Cracker")

        Label(self.master, text="Enter Password: ").grid(row=4, column=0, sticky=tkinter.W)
        text_input = Entry(self.master, textvariable=self.input_message)
        text_input.grid(row=4, column=1, sticky=tkinter.W)

        sha_radio = Radiobutton(self.master, text='MD5', variable =self.hash_type, value=0)
        md5_radio = Radiobutton(self.master, text='SHA1', variable=self.hash_type, value=1)
        sha_radio.grid(row=5, column=0, sticky=tkinter.W)
        md5_radio.grid(row=5, column=1, sticky=tkinter.W)

        Label(self.master, text="Hashed Password: ").grid(row=6, column=0, sticky=tkinter.W)
        hash_button = Button(self.master, text="Hash", command=self.hash)
        hash_button.grid(row=7, sticky=tkinter.W)
        self.hashed_message.grid(row=6, column=1, sticky=tkinter.W)

        Label(self.master, text="Encrypted Message: ").grid(row=0, sticky=tkinter.W)

        # hash_input is the text box that the user can type into, text goes to input_hash
        hash_input = Entry(self.master, textvariable=self.input_hash, width=50)
        hash_input.grid(row=0, column=1, sticky=tkinter.W)

        result = Label(self.master, text="Decrypted: ")
        result.grid(row=1, sticky=tkinter.W)

        # Decrypt button calls the decrypt function
        decrypt_button = Button(self.master, text="Decrypt", command=self.decrypt)
        decrypt_button.grid(row=3, column=0, sticky=tkinter.W)

        Label(self.master, text="Enter Message: ").grid(row=4, column=0, sticky=tkinter.W)
        text_input = Entry(self.master, textvariable=self.input_message, width=50)
        text_input.grid(row=4, column=1, sticky=tkinter.W)

        sha_radio = Radiobutton(self.master, text='SHA1', variable=self.hash_type, value=0)
        md5_radio = Radiobutton(self.master, text='MD5', variable=self.hash_type, value=1)
        sha_radio.grid(row=5, column=0, sticky=tkinter.W)
        md5_radio.grid(row=5, column=1, sticky=tkinter.W)

        sha_decrypt = Radiobutton(self.master, text='SHA1', variable=self.decrypt_type, value=0)
        md5_decrypt = Radiobutton(self.master, text='MD5', variable=self.decrypt_type, value=1)
        sha_decrypt.grid(row=2, column=0, sticky=tkinter.W)
        md5_decrypt.grid(row=2, column=1, sticky=tkinter.W)

        Label(self.master, text="Hashed Message: ").grid(row=6, column=0, sticky=tkinter.W)
        hash_button = Button(self.master, text="Hash", command=self.hash)
        hash_button.grid(row=7, sticky=tkinter.W)

        self.hashed_message.grid(row=6, column=1, sticky=tkinter.W)

    def decrypt(self):
        # TODO: Take the text string and pass it to decryption algorithm
        user_input_hash = self.input_hash.get()
        user_input_hash.strip()

        choice = self.decrypt_type.get()
        hash_func = self.getHashAlgorithm(choice)

        response = None

        print('Currently Hashing...')
        f = open("wordlists/rockyou.txt", "r", encoding='utf-8')
        for x in f:
            x = x.replace('\n', '')
            print(x)
            temp_hash = bytes(x, 'utf-8')
            hash_object = hash_func(temp_hash)
            digest = hash_object.hexdigest()
            if digest == user_input_hash:
                response = x
        f.close()

        # from web api
        # response = requests.get('https://www.nitrxgen.net/md5db/' + text).text
        if response is not None:
            text_object = StringVar()
            text_object.set(response)
            Label(self.master, text=" " * 80).grid(row=1, column=1, sticky=tkinter.W)
            Entry(self.master, textvariable=text_object, width=50).grid(row=1, column=1, sticky=tkinter.W)

    def hash(self):
        choice = self.hash_type.get()
        hash_func = self.getHashAlgorithm(choice)
        
        text = self.input_message.get().strip()

        if text:
            hashed_text = bytes(text, 'utf-8')
            hash_object = hash_func(hashed_text)
            digest = hash_object.hexdigest()
            digest_object = StringVar()
            digest_object.set(digest)
            self.hashed_message.config(textvariable=digest_object, width=50)

    def getHashAlgorithm(self, algo):
         switcher = {
            0: hashlib.sha1,
            1: hashlib.md5,
         }
         return switcher.get(algo, lambda: 'default')

root = Tk()
# size of window
root.geometry("500x300")


app = Window(root)
root.mainloop()
