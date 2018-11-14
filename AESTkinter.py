from tkinter import *
from tkinter.filedialog import askopenfilename
import tkinter.filedialog as fdialog
from tkinter import ttk

#Window Definition
window = Tk()
window.title('AES Encriptor')
window.geometry('600x600')


def openFile():
    file = fdialog.askopenfile()
    label = Label(text=file).pack()
    print(file1.name)
    

#Grid definition
counter = 0
rows = 12
while counter < rows:
    window.rowconfigure(counter, weight=1)
    window.columnconfigure(counter, weight = 1)
    counter += 1

#notebook
nb = ttk.Notebook(window)
nb.grid(row=1, column=0, columnspan = rows, rowspan=rows - 1, sticky='SWNE')

tab1 = ttk.Frame(nb)
nb.add(tab1 , text='Cifrar Archivo')

tab2 = ttk.Frame(nb)
nb.add(tab2 , text='Desifrar Archivo')

#label = ttk.Label(tab1, text="que onda bandita")
#label.grid(column = 0, row = 0)

#label = ttk.Label(labelFrame , text="Holam")
submitButton = ttk.Button(tab1, text="open file", command= openFile)




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