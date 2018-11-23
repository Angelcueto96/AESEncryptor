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
        extention = os.path.splitext(file_name)[1]
        print(extention)
        print("Extention " , extention)
        
        with open(file_name, 'rb') as fo:
            plaintext = fo.read()
        enc = self.encrypt(plaintext, self.key)
        print(file_destination)
        with open(file_destination + ".cfr" + str(extention), 'wb') as fo:
            fo.write(enc)
        if delete:
            os.remove(file_name)
            
        

    def decrypt(self, ciphertext, key):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def decrypt_file(self, file_name, file_destination, delete):
        #print(file_destination[:-4])
        extention = os.path.splitext(file_name)[1]
        with open(file_name, 'rb') as fo:
            ciphertext = fo.read()
        dec = self.decrypt(ciphertext, self.key)
        
        with open(file_destination + str(extention) , 'wb') as fo:
            fo.write(dec)
        if delete:
             os.remove(file_name)
            
    


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
    #print(file)
    #print(file.name)
    #print(os.path.splitext(file.name)[1])
    
def saveFile(tab):
    file = fdialog.asksaveasfilename(filetypes= fileTypes)
    print(file)
    if tab == 3:
        save_route_tab3.set(file)
    elif tab == 4:
        save_route_tab4.set(file)
    #route_tab4.set(file.name)
    

def encrypFile():
    key_tab3 = passwordEntry_tab3.get()
    
    route = str(route_tab3.get())
    destination = save_route_entry_tab3.get()
    
    if route != '' and destination != '' and checkPassword(key_tab3):
        key_tab3 = hashlib.sha256(key_tab3.encode()).digest()
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
    
    route = str(route_tab4.get())
    destination = save_route_entry_tab4.get()
    if route != '' and destination != '' and checkPassword(key_tab4):
        key_tab4 = hashlib.sha256(key_tab4.encode()).digest()
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
    ('Encrypted Files', '*.cfr*'),
]    

decrypFileTypes = [
    ('Encrypted Files', '*.cfr*'),
]   

#Window Definition
window = Tk()
window.title('AES Encriptor')
window.geometry('650x750')
#window.configure(background='black')

#######################Style Definition#####################################

frameStyle = ttk.Style()
frameStyle.configure("Blue.TFrame", foreground="white", background="#113759")   

labelStyle = ttk.Style()
labelStyle.configure("Blue.TLabel", foreground="white", background="#113759", padx ='2')

buttonStyle = ttk.Style()
buttonStyle.configure("Blue.TButton", foreground="#113759", background="white", relief='flat' , padx= '2')

checkButtonStyle = ttk.Style()
checkButtonStyle.configure("Blue.TCheckbutton", foreground="white", background="#113759", padx ='2')

########################Grid definition
counter = 0
rowsNumber = 12
columnsNumber = 12 
while counter < rowsNumber:
    window.rowconfigure(counter, weight=1)
    window.columnconfigure(counter, weight = 1)
    counter += 1

#notebook
nb = ttk.Notebook(window)
nb.grid(row=0, column=0, columnspan = columnsNumber, rowspan=rowsNumber - 1, sticky='SWNE')
tab1 = ttk.Frame(nb, style = "Blue.TFrame")
nb.add(tab1 , text='Cifrar Texto')
tab2 = ttk.Frame(nb,  style = "Blue.TFrame")
nb.add(tab2 , text='Desifrar Texto')
tab3 = ttk.Frame(nb,  style = "Blue.TFrame")
nb.add(tab3 , text='Cifrar Archivo')
tab4 = ttk.Frame(nb,  style = "Blue.TFrame")
nb.add(tab4 , text='Desifrar Archivo')

#Adding grid to tabs 
tabsArray =[tab1, tab2, tab3, tab4]
counterTabs = 0
tabGrid = 10
while counterTabs < tabGrid:
    for tab in tabsArray:
        tab.rowconfigure(counterTabs, weight=1)
        tab.columnconfigure(counterTabs, weight = 1)
    counterTabs += 1

######################Tab1 Content ##########################
label = ttk.Label(tab1, text="Introduzca Texto a Cifrar", style="Blue.TLabel")
label.grid(column = 0, row = 0, pady='20',  columnspan=10)


#text box
textBox = Textbox.ScrolledText(tab1  )
textBox.grid(column = 0, row = 1 ,sticky='N' , columnspan=10)

#password Frame
password_frame_tab1 = ttk.Frame(tab1, style ="Blue.TFrame")
password_frame_tab1.grid(column= 0, row =3, sticky='N',  columnspan=10)
passwordLabel = ttk.Label(password_frame_tab1, text="Contraseña", style="Blue.TLabel")
passwordLabel.grid(column = 0, row = 0)
password_entry_variable= IntVar()
passwordEntry = Entry(password_frame_tab1, show="*" )
passwordEntry.grid(column = 1, row = 0, pady=20, sticky='N')
show_password_tab1 = ttk.Checkbutton(password_frame_tab1, command = lambda:showCharacters(1) , variable= password_entry_variable, style = "Blue.TCheckbutton")
show_password_tab1.grid(column = 2, row = 0, sticky='E')
show_password_labe_tab1 = ttk.Label(password_frame_tab1, text = "Mostrar",style ="Blue.TLabel")
show_password_labe_tab1.grid(column= 3, row =0, sticky='W')

#submit button
submitButtonTab1 = ttk.Button(tab1, text="Cifrar",command=textEncryption, style="Blue.TButton")
submitButtonTab1.grid(column = 0, row = 4,  columnspan=10)


error_label_tab1 = ttk.Label(tab1 , style="Blue.TLabel")
error_label_tab1.grid(column = 0, row = 5, columnspan=10)


###########################Tab 2 Content ########################
label_tab2 = ttk.Label(tab2, text="Introduzca Texto Desifrar", style="Blue.TLabel")
label_tab2.grid(column = 0, row = 0 , pady=20, columnspan=10)
#text box
textbox_text_tab2 = StringVar()
textbox_text_tab2.set("")
textBox_tab2 = Textbox.ScrolledText(tab2)
textBox_tab2.grid(column = 0, row = 1, columnspan=10 )
#password Frame
password_frame_tab2 = ttk.Frame(tab2, style="Blue.TFrame")
password_frame_tab2.grid(column= 0, row =3, sticky='N', columnspan=10)
passwordLabel_tab2 = ttk.Label(password_frame_tab2, text="Contraseña", style="Blue.TLabel")
passwordLabel_tab2.grid(column = 0, row = 0)
password_entry_variable_2= IntVar()
passwordEntry_tab2 = Entry(password_frame_tab2, show="*" )
passwordEntry_tab2.grid(column = 1, row = 0, pady=20, sticky='N')
show_password_tab2 = ttk.Checkbutton(password_frame_tab2, command = lambda:showCharacters(2) , variable= password_entry_variable_2, style="Blue.TCheckbutton")
show_password_tab2.grid(column = 2, row = 0, sticky='E')
show_password_labe_tab2 = ttk.Label(password_frame_tab2, text = "Mostrar" , style="Blue.TLabel")
show_password_labe_tab2.grid(column= 3, row =0, sticky='W')
#submit button
submitButtonTab1 = ttk.Button(tab2, text="Cifrar", command=textDecryption, style="Blue.TButton")
submitButtonTab1.grid(column = 0, row = 4, columnspan=10)

error_label_tab2 = ttk.Label(tab2 ,style="Blue.TLabel")
error_label_tab2.grid(column = 0, row = 5, columnspan=10)

#############################Tab 3 Content###########################

#tit
tittle_label_tab3 = ttk.Label(tab3, text="Seleccione un Archivo a Cifrar", style="Blue.TLabel")
tittle_label_tab3.grid(column = 0, row = 0,  columnspan=10 )

instruction_label_tab3 = ttk.Label(tab3, text="Ingrese la ruta del archivo o selecione el Archivo", style="Blue.TLabel")
instruction_label_tab3.grid(column = 0, row = 1, columnspan=10)

#Open frame 
file_frame_tab3 = ttk.Frame(tab3 , style="Blue.TFrame")
file_frame_tab3.grid(column = 0, row = 2, columnspan=10)
route_tab3 = StringVar()
route_tab3.set("")
file_label_tab3 = ttk.Entry(file_frame_tab3, textvariable= route_tab3, width=50 )
file_label_tab3.grid(column = 0, row= 0,sticky='W', padx = 10)
select_file_tab3 = ttk.Button(file_frame_tab3, text="Selecionar Archivo", command= lambda: openFile(3) , style="Blue.TButton")
select_file_tab3.grid(column = 1, row = 0, sticky='E')

#save File
save_file_label_tab3 = ttk.Label(tab3, text="Selecione en donde quiere guardar el archivo", style="Blue.TLabel")
save_file_label_tab3.grid(column = 0 , row = 3, columnspan=10 )

save_file_frame_tab3 = ttk.Frame(tab3 , style="Blue.TFrame")
save_file_frame_tab3 .grid(column = 0, row = 4, columnspan=10)
save_route_tab3 = StringVar()
save_route_tab3.set("")
save_route_entry_tab3 = ttk.Entry(save_file_frame_tab3 , textvariable= save_route_tab3,  width=50)
save_route_entry_tab3.grid(column = 0, row = 0, padx = 10)
save_route_button_tab3 = ttk.Button(save_file_frame_tab3 , text="Guardar Como",command= lambda: saveFile(3) , style="Blue.TButton")
save_route_button_tab3.grid(column = 1, row = 0)

#password Frame
password_frame_tab3 = ttk.Frame(tab3, style="Blue.TFrame")
password_frame_tab3.grid(column= 0, row =5, sticky='N', columnspan=10)
passwordLabel_tab3 = ttk.Label(password_frame_tab3, text="Contraseña", style="Blue.TLabel")
passwordLabel_tab3.grid(column = 0, row = 0)
password_entry_variable_3= IntVar()
passwordEntry_tab3 = Entry(password_frame_tab3, show="*" )
passwordEntry_tab3.grid(column = 1, row = 0, pady=20, sticky='N', padx = 10)
show_password_tab3 = ttk.Checkbutton(password_frame_tab3, command = lambda:showCharacters(3) , variable= password_entry_variable_3, style="Blue.TCheckbutton")
show_password_tab3.grid(column = 2, row = 0, sticky='E')
show_password_labe_tab3 = ttk.Label(password_frame_tab3, text = "Mostrar", style="Blue.TLabel")
show_password_labe_tab3.grid(column= 3, row =0, sticky='W')



#Delete File Frame
delete_file_frame_tab3 = ttk.Entry(tab3, style="Blue.TFrame")
delete_file_frame_tab3.grid(column = 0, row = 6, columnspan=10)
delete_file_label_tab3 = ttk.Label(delete_file_frame_tab3, text='Desea Borrar el Archivo Original' , style="Blue.TLabel")
delete_file_label_tab3.grid(column = 0, row= 0)
delete_selection_tab3 = IntVar()
delete_file_input_tab3 = ttk.Checkbutton(delete_file_frame_tab3, variable = delete_selection_tab3 , style="Blue.TCheckbutton")
delete_file_input_tab3.grid(column = 1, row= 0)
#delete_file_input_tab3.state(['disabled'])

submitButton_tab3 = ttk.Button(tab3, text="Cifrar Archivo", command= encrypFile , style="Blue.TButton")
submitButton_tab3.grid(column = 0, row = 7, columnspan=10)

error_label_tab3 = ttk.Label(tab3 , style="Blue.TLabel")
error_label_tab3.grid(column = 0, row = 8, sticky="N", columnspan=10)

#############################Tab 4 Content###########################

tittle_label_tab4 = ttk.Label(tab4, text="Seleccione un Archivo a Desifrar", style="Blue.TLabel")
tittle_label_tab4.grid(column = 0, row = 0, pady=20)

instruction_label_tab4 = ttk.Label(tab4, text="Ingrese la ruta del archivo o selecione el Archivo" ,style="Blue.TLabel")
instruction_label_tab4.grid(column = 0, row = 1)

#Open Frame
file_frame_tab4 = ttk.Frame(tab4, style="Blue.TFrame")
file_frame_tab4.grid(column = 0 , row = 2)
route_tab4 = StringVar()
route_tab4.set("")
file_label_tab4 = ttk.Entry(file_frame_tab4, textvariable= route_tab4, width=50)
file_label_tab4.grid(column = 0, row= 0,sticky='W')
select_file_tab4 = ttk.Button(file_frame_tab4, text="Selecionar Archivo", command= lambda: openFile(4), style="Blue.TButton")
select_file_tab4.grid(column = 1, row = 0, sticky='E')

#Password Frame
password_frame_tab4 = ttk.Frame(tab4, style="Blue.TFrame")
password_frame_tab4.grid(column= 0, row =6, sticky='N')
passwordLabel_tab4 = ttk.Label(password_frame_tab4, text="Contraseña" , style="Blue.TLabel")
passwordLabel_tab4.grid(column = 0, row = 0)
password_entry_variable_4= IntVar()
passwordEntry_tab4 = Entry(password_frame_tab4, show="*" )
passwordEntry_tab4.grid(column = 1, row = 0, pady=20, sticky='N')
show_password_tab4 = ttk.Checkbutton(password_frame_tab4, command = lambda:showCharacters(4) , variable= password_entry_variable_4, style="Blue.TCheckbutton")
show_password_tab4.grid(column = 2, row = 0, sticky='E')
show_password_labe_tab4 = ttk.Label(password_frame_tab4, text = "Mostrar", style="Blue.TLabel")
show_password_labe_tab4.grid(column= 3, row =0, sticky='W')

#Save File
save_file_label_tab4 = ttk.Label(tab4, text="Selecione en donde quiere guardar el archivo" , style="Blue.TLabel")
save_file_label_tab4.grid(column = 0 , row = 4, pady=20)

save_file_frame_tab4 = ttk.Frame(tab4 , style="Blue.TFrame")
save_file_frame_tab4 .grid(column = 0, row = 5)
save_route_tab4 = StringVar()
save_route_tab4.set("")
save_route_entry_tab4 = ttk.Entry(save_file_frame_tab4 , textvariable= save_route_tab4,  width=50)
save_route_entry_tab4.grid(column = 0, row = 0)
save_route_button_tab4 = ttk.Button(save_file_frame_tab4 , text="Guardar Como",command= lambda: saveFile(4) , style="Blue.TButton" )
save_route_button_tab4.grid(column = 1, row = 0)

#Delete file
delete_file_frame_tab4 = ttk.Entry(tab4)
delete_file_frame_tab4.grid(column = 0, row = 10)
delete_file_label_tab4 = ttk.Label(delete_file_frame_tab4, text='Desea Borrar el Archivo Original', style="Blue.TLabel")
delete_file_label_tab4.grid(column = 0, row= 0)
delete_selection_tab4 = IntVar()
delete_file_input_tab4 = ttk.Checkbutton(delete_file_frame_tab4, variable = delete_selection_tab4 , style="Blue.TCheckbutton")
delete_file_input_tab4.grid(column = 1, row= 0)

#Submit
submitButton_tab4 = ttk.Button(tab4, text="Cifrar Archivo", command= decrypFile , style="Blue.TButton")
submitButton_tab4.grid(column = 0, row = 11, pady=20)

error_label_tab4 = ttk.Label(tab4, style="Blue.TLabel")
error_label_tab4.grid(column = 0, row = 12)

######################################################################

window.mainloop()