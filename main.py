import tkinter
from tkinter import *


class Window(Frame):
    def __init__(self, master=None):
        Frame.__init__(self, master)
        self.master = master
        # Variable to store the user input (Encrypted Message)
        self.input_hash = StringVar()
        self.hash_type = IntVar()

        self.init_window()

    def init_window(self):
        self.master.title("Hash Cracker")

        Label(self.master, text="Encrypted Message").grid(row=0)

        # hash_input is the text box that the user can type into, text goes to input_hash
        hash_input = Entry(self.master, textvariable=self.input_hash)
        hash_input.grid(row=0, column=1)

        md5_radio = Radiobutton(self.master, text='MD5', variable=self.hash_type, value=1)
        sha_radio = Radiobutton(self.master, text='SHA1', variable =self.hash_type, value=2)
        md5_radio.grid(row=1, column=0, sticky=W)
        sha_radio.grid(row=1, column=1, sticky=W)

        result = Label(self.master, text="Decrypted: ")
        result.grid(row=3, sticky=W)

        quit_button = Button(self.master, text="Quit", command=self.master.quit)
        quit_button.grid(row=4, column=0, sticky=tkinter.W)

        # Submit button calls the print_submit function
        submit_button = Button(self.master, text="Enter", command=self.print_submit)
        submit_button.grid(row=4, column=1, sticky=tkinter.W)

    def print_submit(self):
        # TODO: Take the text string and pass it to decryption algorithm
        text = self.input_hash.get()
        
        # TODO: Print the decrypted message
        Label(self.master, text=text).grid(row=1, column=1, sticky=tkinter.W)
        print(text)


root = Tk()
# size of window
root.geometry("400x200")


app = Window(root)
root.mainloop()
