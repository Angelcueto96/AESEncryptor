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

    def encrypt_file(self, file_name, file_destination, delete):
        with open(file_name, 'rb') as fo:
            plaintext = fo.read()
        enc = self.encrypt(plaintext, self.key)
        with open(file_destination + ".enc", 'wb') as fo:
            fo.write(enc)
        if delete:
            os.remove(file_name)
            
        

    def decrypt(self, ciphertext, key):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def decrypt_file(self, file_name, file_destination, delete):
        with open(file_name, 'rb') as fo:
            ciphertext = fo.read()
        dec = self.decrypt(ciphertext, self.key)
        with open(filee_destination[:-4], 'wb') as fo:
            fo.write(dec)
        if remove:
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
    if text != '' and checkPassword(key):
        key = hashlib.sha256(key.encode()).digest()
        print(key)
        encriptor = Encryptor(key)
        encrypted = encriptor.encrypt(text.encode() , key)
        encryptedB64 = base64.b64encode(encrypted, altchars=None)
        print(encryptedB64)
        textBox.delete("1.0", END)
        textBox.insert("1.0", encryptedB64)
        error_label_tab2.config(text = "")
    else:
        error_label_tab1.config( text = "Verifique  cumplir con lo siguiente: \n Que los campos sean correctos \n Que la contraseña tenga al menos 8 caracteres una letra mayuscla y al menos un digito")
        
        
    
    
def textDecryption():
    text_tab2 = textBox_tab2.get("1.0",END)
    key_tab2 = passwordEntry_tab2.get()
    if text_tab2 != '' and checkPassword(key_tab2):
        try:
            text_tab2 = base64.b64decode(text_tab2, altchars = None)
        except ValueError:
            error_label_tab2.config(text = "Mensaje no Valido")
            
        key_tab2 = hashlib.sha256(key_tab2.encode()).digest()
        encryptor = Encryptor(key_tab2)
        #decryoted = ''
        try:
            decrypted = encryptor.decrypt(text_tab2, key_tab2)
            print(decrypted)
            textBox_tab2.delete("1.0", END)
            textBox_tab2.insert("1.0", decrypted)
            error_label_tab2.config(text = "")
        except ValueError:
            error_label_tab2.config(text = "Mensaje no Valido")
    else:
        error_label_tab2.config( text = "Verifique  cumplir con lo siguiente: \n Que los campos sean correctos \n Que la contraseña tenga al menos 8 caracteres una letra mayuscla y al menos un digito")
        
    
def openFile(tab):
    file = fdialog.askopenfile(filetypes= fileTypes)
    if tab == 3:
        route_tab3.set(file.name)
    elif tab == 4:
        route_tab4.set(file.name)
    #route_tab3 = str(route_tab3)   
    print(file.name)
    
def saveFile():
    file = fdialog.asksaveasfilename(filetypes= fileTypes)
    print(file)
    save_route_tab3.set(file)
    #route_tab4.set(file.name)
    

def encrypFile():
    key_tab3 = passwordEntry_tab3.get()
    key_tab3 = hashlib.sha256(key_tab3.encode()).digest()
    route = str(route_tab3.get())
    destination = save_route_entry_tab3.get()
    
    if route != '' and destination != '' and checkPassword(key_tab3):
        encryptor = Encryptor(key_tab3)
        delete = False
        if delete_selection_tab3.get() == 1:
            delete = True
        try:
            encryptor.encrypt_file( route, destination, delete )
        except ValueError:
            error_label_tab3.config(text = "Verifique que las rutas sean correctas")
    else:
        error_label_tab3.config(text = "Verifique lo siguiente:")
            
                
    
    
def decrypFile():
    key_tab4 = passwordEntry_tab4.get()
    key_tab4 = hashlib.sha256(key_tab4.encode()).digest()
    route = str(route_tab4.get())
    destination = save_route_entry_tab4.get()
    if route != '' and destination != '' and checkPassword(key_tab4):
        encryptor = Encryptor(key_tab4)
        delete = False
        if delete_selection_tab4.get() == 1:
            delete = True
        try:
            encryptor.decrypt_file(route,  destination, delete )
        except ValueError:
            error_label_tab4.config(text = "Verifique que las rutas sean correctas")
    else:
        error_label_tab4.config(text = "Verifique lo siguiente:")
        
            

digits = '123456789'
capital = 'QWERTYUIOPASDFGHJKLÑZXCVBNM'

def checkPassword(password):
    valid = False
    if len(password) >= 8:
        containsDigit = False
        containsCapital = False
        for letter in list(password):
            if letter in digits:
                containsDigit = True
            if letter in capital:
                containsCapital = True
        if containsDigit and containsCapital:
            valid = True
    return valid

def showCharacters(tab):   
    if tab == 1:
        if password_entry_variable.get() == 1:
            passwordEntry.config(show="")
        elif password_entry_variable.get() == 0:
            passwordEntry.config(show="*")
    elif tab == 2:
        if password_entry_variable_2.get() == 1:
            passwordEntry_tab2.config(show="")
        elif password_entry_variable_2.get() == 0:
            passwordEntry_tab2.config(show="*")
    elif tab == 3:
        if password_entry_variable_3.get() == 1:
            passwordEntry_tab3.config(show="")
        elif password_entry_variable_3.get() == 0:
            passwordEntry_tab3.config(show="*")
    elif tab == 4:
        if password_entry_variable_4.get() == 1:
            passwordEntry_tab4.config(show="")
        elif password_entry_variable_4.get() == 0:
            passwordEntry_tab4.config(show="*")
    
fileTypes = [
    ('Text files', '*.txt'),
]    

#Window Definition
window = Tk()
window.title('AES Encriptor')
window.geometry('650x600')
window.configure(background='black')

#Style Definition
#backGroundStyle = ttk.Style()
#backGroundStyle.configure("TabStyle", background="black")
style = ttk.Style()
style.configure("Dark", foreground="white", background="black")   

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
tab1 = ttk.Frame(nb)
nb.add(tab1 , text='Cifrar Texto')
tab2 = ttk.Frame(nb)
nb.add(tab2 , text='Desifrar Texto')
tab3 = ttk.Frame(nb)
nb.add(tab3 , text='Cifrar Archivo')
tab4 = ttk.Frame(nb)
nb.add(tab4 , text='Desifrar Archivo')

######################Tab1 Content ##########################
label = ttk.Label(tab1, text="Introduzca Texto a Cifrar")
label.grid(column = 0, row = 0,sticky='W')

#text box
textbox_text = StringVar()
textbox_text.set("HOla mundo")
textBox = Textbox.ScrolledText(tab1  )
textBox.grid(column = 0, row = 3 ,sticky='N' )

#password Frame
password_frame_tab1 = ttk.Frame(tab1)
password_frame_tab1.grid(column= 0, row =6, sticky='N')
passwordLabel = ttk.Label(password_frame_tab1, text="Contraseña")
passwordLabel.grid(column = 0, row = 0)
password_entry_variable= IntVar()
passwordEntry = Entry(password_frame_tab1, show="*" )
passwordEntry.grid(column = 1, row = 0, pady=20, sticky='N')
show_password_tab1 = ttk.Checkbutton(password_frame_tab1, command = lambda:showCharacters(1) , variable= password_entry_variable)
show_password_tab1.grid(column = 2, row = 0, sticky='E')
show_password_labe_tab1 = ttk.Label(password_frame_tab1, text = "Mostrar")
show_password_labe_tab1.grid(column= 3, row =0, sticky='W')

#submit button
submitButtonTab1 = ttk.Button(tab1, text="Cifrar",command=textEncryption)
submitButtonTab1.grid(column = 0, row = 8)


error_label_tab1 = ttk.Label(tab1)
error_label_tab1.grid(column = 0, row = 9)


###########################Tab 2 Content ########################
label_tab2 = ttk.Label(tab2, text="Introduzca Texto Desifrar")
label_tab2.grid(column = 0, row = 0 , pady=20)
#text box
textbox_text_tab2 = StringVar()
textbox_text_tab2.set("")
textBox_tab2 = Textbox.ScrolledText(tab2)
textBox_tab2.grid(column = 0, row = 3 )
#password Frame
password_frame_tab2 = ttk.Frame(tab2)
password_frame_tab2.grid(column= 0, row =4, sticky='N')
passwordLabel_tab2 = ttk.Label(password_frame_tab2, text="Contraseña")
passwordLabel_tab2.grid(column = 0, row = 0)
password_entry_variable_2= IntVar()
passwordEntry_tab2 = Entry(password_frame_tab2, show="*" )
passwordEntry_tab2.grid(column = 1, row = 0, pady=20, sticky='N')
show_password_tab2 = ttk.Checkbutton(password_frame_tab2, command = lambda:showCharacters(2) , variable= password_entry_variable_2)
show_password_tab2.grid(column = 2, row = 0, sticky='E')
show_password_labe_tab2 = ttk.Label(password_frame_tab2, text = "Mostrar")
show_password_labe_tab2.grid(column= 3, row =0, sticky='W')
#submit button
submitButtonTab1 = ttk.Button(tab2, text="Cifrar", command=textDecryption)
submitButtonTab1.grid(column = 0, row = 11)

error_label_tab2 = ttk.Label(tab2)
error_label_tab2.grid(column = 0, row = 9)

#############################Tab 3 Content###########################

#tit
tittle_label_tab3 = ttk.Label(tab3, text="Seleccione un Archivo a Cifrar")
tittle_label_tab3.grid(column = 0, row = 0, pady=20)

instruction_label_tab3 = ttk.Label(tab3, text="Ingrese la ruta del archivo o selecione el Archivo")
instruction_label_tab3.grid(column = 0, row = 1)

#Open frame 
file_frame_tab3 = ttk.Frame(tab3)
file_frame_tab3.grid(column = 0, row = 2)
route_tab3 = StringVar()
route_tab3.set("")
file_label_tab3 = ttk.Entry(file_frame_tab3, textvariable= route_tab3, width=50)
file_label_tab3.grid(column = 0, row= 0,sticky='W')
select_file_tab3 = ttk.Button(file_frame_tab3, text="Selecionar Archivo", command= lambda: openFile(3))
select_file_tab3.grid(column = 1, row = 0, sticky='E')
#password Frame
password_frame_tab3 = ttk.Frame(tab3)
password_frame_tab3.grid(column= 0, row =6, sticky='N')
passwordLabel_tab3 = ttk.Label(password_frame_tab3, text="Contraseña")
passwordLabel_tab3.grid(column = 0, row = 0)
password_entry_variable_3= IntVar()
passwordEntry_tab3 = Entry(password_frame_tab3, show="*" )
passwordEntry_tab3.grid(column = 1, row = 0, pady=20, sticky='N')
show_password_tab3 = ttk.Checkbutton(password_frame_tab3, command = lambda:showCharacters(3) , variable= password_entry_variable_3)
show_password_tab3.grid(column = 2, row = 0, sticky='E')
show_password_labe_tab3 = ttk.Label(password_frame_tab3, text = "Mostrar")
show_password_labe_tab3.grid(column= 3, row =0, sticky='W')

#save File
save_file_label_tab3 = ttk.Label(tab3, text="Selecione en donde quiere guardar el archivo")
save_file_label_tab3.grid(column = 0 , row = 3, pady=20 )

save_file_frame_tab3 = ttk.Frame(tab3)
save_file_frame_tab3 .grid(column = 0, row = 4)
save_route_tab3 = StringVar()
save_route_tab3.set("")
save_route_entry_tab3 = ttk.Entry(save_file_frame_tab3 , textvariable= save_route_tab3,  width=50)
save_route_entry_tab3.grid(column = 0, row = 0)
save_route_button_tab3 = ttk.Button(save_file_frame_tab3 , text="Guardar Como",command= saveFile )
save_route_button_tab3.grid(column = 1, row = 0)

#Delete File Frame
delete_file_frame_tab3 = ttk.Entry(tab3)
delete_file_frame_tab3.grid(column = 0, row = 10)

delete_file_label_tab3 = ttk.Label(delete_file_frame_tab3, text='Desea Borrar el Archivo Original')
delete_file_label_tab3.grid(column = 0, row= 0)

delete_selection_tab3 = IntVar()
delete_file_input_tab3 = ttk.Checkbutton(delete_file_frame_tab3, variable = delete_selection_tab3)
delete_file_input_tab3.grid(column = 1, row= 0)
#delete_file_input_tab3.state(['disabled'])

submitButton_tab3 = ttk.Button(tab3, text="Cifrar Archivo", command= encrypFile )
submitButton_tab3.grid(column = 0, row = 11, pady=20)

error_label_tab3 = ttk.Label(tab3)
error_label_tab3.grid(column = 0, row = 12)

#############################Tab 4 Content###########################

tittle_label_tab4 = ttk.Label(tab4, text="Seleccione un Archivo a Desifrar")
tittle_label_tab4.grid(column = 0, row = 0, pady=20)

instruction_label_tab4 = ttk.Label(tab4, text="Ingrese la ruta del archivo o selecione el Archivo")
instruction_label_tab4.grid(column = 0, row = 1)

#Open Frame
file_frame_tab4 = ttk.Frame(tab4)
file_frame_tab4.grid(column = 0, row = 2)
route_tab4 = StringVar()
route_tab4.set("")
file_label_tab4 = ttk.Entry(file_frame_tab4, textvariable= route_tab4, width=50)
file_label_tab4.grid(column = 0, row= 0,sticky='W')
select_file_tab4 = ttk.Button(file_frame_tab4, text="Selecionar Archivo", command= lambda: openFile(4))
select_file_tab4.grid(column = 1, row = 0, sticky='E')

#Password Frame
password_frame_tab4 = ttk.Frame(tab4)
password_frame_tab4.grid(column= 0, row =6, sticky='N')
passwordLabel_tab4 = ttk.Label(password_frame_tab4, text="Contraseña")
passwordLabel_tab4.grid(column = 0, row = 0)
password_entry_variable_4= IntVar()
passwordEntry_tab4 = Entry(password_frame_tab4, show="*" )
passwordEntry_tab4.grid(column = 1, row = 0, pady=20, sticky='N')
show_password_tab4 = ttk.Checkbutton(password_frame_tab4, command = lambda:showCharacters(4) , variable= password_entry_variable_4)
show_password_tab4.grid(column = 2, row = 0, sticky='E')
show_password_labe_tab4 = ttk.Label(password_frame_tab4, text = "Mostrar")
show_password_labe_tab4.grid(column= 3, row =0, sticky='W')

#Save File
save_file_label_tab4 = ttk.Label(tab4, text="Selecione en donde quiere guardar el archivo")
save_file_label_tab4.grid(column = 0 , row = 4, pady=20)

save_file_frame_tab4 = ttk.Frame(tab4)
save_file_frame_tab4 .grid(column = 0, row = 5)
save_route_tab4 = StringVar()
save_route_tab4.set("")
save_route_entry_tab4 = ttk.Entry(save_file_frame_tab4 , textvariable= save_route_tab4,  width=50)
save_route_entry_tab4.grid(column = 0, row = 0)
save_route_button_tab4 = ttk.Button(save_file_frame_tab4 , text="Guardar Como",command= saveFile )
save_route_button_tab4.grid(column = 1, row = 0)

#Delete file
delete_file_frame_tab4 = ttk.Entry(tab4)
delete_file_frame_tab4.grid(column = 0, row = 10)
delete_file_label_tab4 = ttk.Label(delete_file_frame_tab4, text='Desea Borrar el Archivo Original')
delete_file_label_tab4.grid(column = 0, row= 0)
delete_selection_tab4 = IntVar()
delete_file_input_tab4 = ttk.Checkbutton(delete_file_frame_tab4, variable = delete_selection_tab4)
delete_file_input_tab4.grid(column = 1, row= 0)

#Submit
submitButton_tab4 = ttk.Button(tab4, text="Cifrar Archivo", command= decrypFile )
submitButton_tab4.grid(column = 0, row = 11, pady=20)

error_label_tab4 = ttk.Label(tab4)
error_label_tab4.grid(column = 0, row = 12)

######################################################################

window.mainloop()