from tkinter import *
from tkinter.filedialog import askopenfilename
import tkinter.filedialog as fdialog
from tkinter import ttk
import tkinter.scrolledtext as Textbox

from Crypto import Random
from Crypto.Cipher import AES
import os
import os.path
from os import listdir
from os.path import isfile, join
from pathlib import Path
import time
import hashlib
import base64




    
class Encryptor:
    def __init__(self, key):
        self.key = key

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message, key, key_size=256):
        #message = message.encode()
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def encrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            plaintext = fo.read()
        enc = self.encrypt(plaintext, self.key)
        with open(file_name + ".enc", 'wb') as fo:
            fo.write(enc)
        os.remove(file_name)

    def decrypt(self, ciphertext, key):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def decrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            ciphertext = fo.read()
        dec = self.decrypt(ciphertext, self.key)
        with open(file_name[:-4], 'wb') as fo:
            fo.write(dec)
        os.remove(file_name)

    def getAllFiles(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        dirs = []
        for dirName, subdirList, fileList in os.walk(dir_path):
            for fname in fileList:
                if (fname != 'script.py' and fname != 'data.txt.enc'):
                    dirs.append(dirName + "\\" + fname)
        return dirs

    def encrypt_all_files(self):
        dirs = self.getAllFiles()
        for file_name in dirs:
            self.encrypt_file(file_name)

    def decrypt_all_files(self):
        dirs = self.getAllFiles()
        for file_name in dirs:
            self.decrypt_file(file_name)
    

def textEncryption():
    text = textBox.get("1.0",END)
    key = passwordEntry.get()
    key = hashlib.sha256(key.encode()).digest()
    print(key)
    encriptor = Encryptor(key)
    encrypted = encriptor.encrypt(text.encode() , key)
    encryptedB64 = base64.b64encode(encrypted, altchars=None)
    print(encryptedB64)
    #answerlabel.config(text= encryptedB64)
    #ent.config(text= encryptedB64)
    tk_name.set(encryptedB64)
    #textBox.insert(encryptedB64)
    
    #label.config(text=str(counter))
    #print(encrypted.decode())
    
def textDecryption():
    text_tab2 = textBox_tab2.get("1.0",END)
    text_tab2 = base64.b64decode(text_tab2, altchars = None)
    key_tab2 = passwordEntry_tab2.get()
    key_tab2 = hashlib.sha256(key_tab2.encode()).digest()
    encryptor = Encryptor(key_tab2)
    decrypted = encryptor.decrypt(text_tab2, key_tab2)
    print(decrypted)
    decrypted_text.set(decrypted)
    
def openFile():
    file = fdialog.askopenfile()
    route_tab3.set(file.name)
    #route_tab3 = str(route_tab3)
    
    
    
    print(file.name)

def encrypFile():
    key_tab3 = passwordEntry_tab3.get()
    key_tab3 = hashlib.sha256(key_tab3.encode()).digest()
    encryptor = Encryptor(key_tab3)
    encryptor.encrypt_file(str(route_tab3.get()))
    
#Window Definition
window = Tk()
window.title('AES Encriptor')
window.geometry('750x750')
window.configure(background='black')

#Style Definition
#backGroundStyle = ttk.Style()
#backGroundStyle.configure("TabStyle", background="black")
style = ttk.Style()
style.configure("BW.TLabel", foreground="white", background="black")   

#Grid definition
counter = 0
rowsNumber = 15
columnsNumber = 15 
while counter < rowsNumber:
    window.rowconfigure(counter, weight=1)
    window.columnconfigure(counter, weight = 1)
    counter += 1

#notebook
nb = ttk.Notebook(window)
nb.grid(row=0, column=0, columnspan = columnsNumber, rowspan=rowsNumber - 1, sticky='SWNE')


tab1 = ttk.Frame(nb , style="BW.TLabel" )
nb.add(tab1 , text='Cifrar Texto')

tab2 = ttk.Frame(nb)
nb.add(tab2 , text='Desifrar Texto')

tab3 = ttk.Frame(nb)
nb.add(tab3 , text='Cifrar Archivo')

tab4 = ttk.Frame(nb)
nb.add(tab4 , text='Desifrar Archivo')




######################Tab1 Content ##########################
label = ttk.Label(tab1, text="Introduzca Texto a Cifrar", width= 30, style="BW.TLabel")
label.grid(column = 0, row = 0, columnspan= 4)


textbox_text = StringVar()
textbox_text.set("HOla mundo")

textBox = Textbox.ScrolledText(tab1, width= 90  )
textBox.grid(column = 0, row = 3  )


passwordLabel = ttk.Label(tab1, text="Contraseña", style="BW.TLabel")
passwordLabel.grid(column = 0, row = 9)


passwordEntry = Entry(tab1,width= 30  )
passwordEntry.grid(column = 0, row = 10)


submitButtonTab1 = ttk.Button(tab1, text="Cifrar", style="BW.TLabel",command=textEncryption)
submitButtonTab1.grid(column = 0, row = 11)

#ent = Entry(tab1, state='readonly', readonlybackground='white', fg='black')
#ent.grid(column = 0, row = 12)
#ent.config( relief='flat')
#ent.insert(1, "jajaja")


tk_name=StringVar()
tk_name.set("")
entry_1 = Entry(tab1, textvariable=tk_name, width=80)
entry_1.grid(row=14, column=0)
#entry_1.focus_set()


temp = Text(tab1, width= 85)
temp.grid(column = 0, row = 16)
 
'''
answerlabel = ttk.Label(tab1, width= 100)
answerlabel.grid(column = 0, row = 12, columnspan= 25)
answerlabel.configure(state="disabled")
answerlabel.configure(bg=tab1.cget('bg'), relief=FLAT)
'''

###########################Tab 2 Content ########################

label_tab2 = ttk.Label(tab2, text="Introduzca Texto Desifrar", width= 30)
label_tab2.grid(column = 0, row = 0, columnspan= 4)


textbox_text_tab2 = StringVar()
textbox_text_tab2.set("")
textBox_tab2 = Textbox.ScrolledText(tab2, width= 90 )
textBox_tab2.grid(column = 0, row = 3  )


passwordLabel_tab2 = ttk.Label(tab2, text="Contraseña")
passwordLabel_tab2.grid(column = 0, row = 9)


passwordEntry_tab2 = Entry(tab2,width= 30 )
passwordEntry_tab2.grid(column = 0, row = 10)


submitButtonTab1 = ttk.Button(tab2, text="Cifrar", command=textDecryption)
submitButtonTab1.grid(column = 0, row = 11)




#ent = Entry(tab1, state='readonly', readonlybackground='white', fg='black')
#ent.grid(column = 0, row = 12)
#ent.config( relief='flat')
#ent.insert(1, "jajaja")

decrypted_text=StringVar()
decrypted_text.set("")
entry_tab2 = Entry(tab2, textvariable=decrypted_text, width=80)
entry_tab2.grid(row=14, column=0)
#entry_1.focus_set()
#############################Tab 3 Content###########################
tittle_label_tab3 = ttk.Label(tab3, text="Seleccione un Archivo a Cifrar", width= 30)
tittle_label_tab3.grid(column = 0, row = 0, columnspan= 4)

route_tab3 = StringVar()
route_tab3.set("")
instruction_label_tab3 = ttk.Label(tab3, text="Ingrese la ruta del archivo o selecione el Archivo")
instruction_label_tab3.grid(column = 0, row = 1)

file_label_tab3 = ttk.Entry(tab3, width = 50, textvariable= route_tab3)
file_label_tab3.grid(column = 0, row= 2)

select_file_tab3 = ttk.Button(tab3, text="Selecionar Archivo", command= openFile)
select_file_tab3.grid(column = 0, row = 3)

passwordLabel_tab3 = ttk.Label(tab3, text='Contraseña')
passwordLabel_tab3.grid(column = 0, row= 4)

passwordEntry_tab3 = ttk.Entry(tab3)
passwordEntry_tab3.grid(column = 0, row= 5 )

submitButton_tab3 = ttk.Button(tab3, text="Cifrar Archivo", command= encrypFile )
submitButton_tab3.grid(column = 0, row = 6)

#############################Tab 4 Content###########################

#Option Menu
'''
encrypthFile = Button(text="Cifrar Archivo").pack()
decrypthFile = Button(text="Desifrar Archivo").pack()
encryothText = Button(text="Cifrar Texto").pack()
decrypthText = Button(text="Desifrar Texto").pack()

'''


    
#submitButton = Button(text="open file", command= openFile).pack()
#tab1.add(submitButton)
window.mainloop()