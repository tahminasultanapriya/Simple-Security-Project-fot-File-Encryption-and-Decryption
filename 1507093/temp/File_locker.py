from tkinter import *
import os
import random
from Crypto.Util import number
import tkinter
from tkinter import filedialog
from sys import exit
import math
from hashlib import sha256
from random import randint
import random, sys, os, rabinMiller, cryptomath
from Crypto import Random
from Crypto.Cipher import AES
import os.path
from os import listdir
from os.path import isfile, join
import time
DEFAULT_BLOCK_SIZE = 128
BYTE_SIZE = 256 

key = 'abcdefghijklmnopqrstuvwxyz1234567890 '
# Designing window for registration
 
def register():
    global register_screen
    register_screen = Toplevel(main_screen)
    register_screen.title("Register")
    register_screen.geometry("300x250")
 
    global username
    global password
    global username_entry
    global password_entry
    username = StringVar()
    password = StringVar()
 
    Label(register_screen, text="Please enter details below",width="300", height="3", bg="Orange").pack()
    Label(register_screen, text="").pack()
    username_lable = Label(register_screen, text="Username * ",width=20, height=1)
    username_lable.pack()
    username_entry = Entry(register_screen, textvariable=username)
    username_entry.pack()
    password_lable = Label(register_screen, text="Password * ",width=20, height=1)
    password_lable.pack()
    password_entry = Entry(register_screen, textvariable=password, show='*')
    password_entry.pack()
    Label(register_screen, text="").pack()
    Button(register_screen, text="Register", width=17, height=1, bg="orange", command = register_user).pack()
 
 
# Designing window for login 
 
def login():
    global login_screen
    login_screen = Toplevel(main_screen)
    login_screen.title("Login")
    login_screen.geometry("300x250")
    Label(login_screen, text="Please enter details below to login",width="300", height="3", bg="Orange").pack()
    Label(login_screen, text="").pack()
 
    global username_verify
    global password_verify
 
    username_verify = StringVar()
    password_verify = StringVar()
 
    global username_login_entry
    global password_login_entry
 
    Label(login_screen, text="Username * ",width=20, height=1).pack()
    username_login_entry = Entry(login_screen, textvariable=username_verify)
    username_login_entry.pack()
    Label(login_screen, text="").pack()
    Label(login_screen, text="Password * ",width=20, height=1).pack()
    password_login_entry = Entry(login_screen, textvariable=password_verify, show= '*')
    password_login_entry.pack()
    Label(login_screen, text="").pack()
    Button(login_screen, text="Login", width=17, height=1,bg="Orange", command = login_verify).pack()



 
 
# Designing window for login 
 

# Implementing event on register button
def register_user():
    
     
    username_info = username.get()
    password_info = password.get()

    file = open("C:/Users/Priya/Desktop/temp/username_info/"+username_info, "w")
    file.write(username_info + "\n")
    file.write(password_info)
    file.close()

    username_entry.delete(0, END)
    password_entry.delete(0, END)
    Label(register_screen, text="Congratulations!!!!\nRegistration Successful",font=("Courier", 9),width="100", height="2").pack()

   # Label(register_screen, text="Registration Success", fg="green", font=("calibri", 11)).pack()
    

 
# Implementing event on login button 
 
def login_verify():
    username1 = username_verify.get()
    password1 = password_verify.get()
    username_login_entry.delete(0, END)
    password_login_entry.delete(0, END)

    path='C:/Users/Priya/Desktop/temp/username_info/'
    list_of_files = os.listdir(path)
    print(list_of_files)
    if username1 in list_of_files:
        file1 = open('C:/Users/Priya/Desktop/temp/username_info/'+username1, "r")
        verify = file1.read().splitlines()
        if password1 in verify:
            login_sucess()

        else:
            password_not_recognised()

    else:
        user_not_found()
 
# Designing popup for login success
 
def login_sucess():
    global login_success
    login_success= Toplevel(login_screen)
    login_success.geometry("300x250")
    login_success.title("Login Success")
    Label(login_success,text="Select Your Choice", bg="orange", width="300", height="2", font=("Calibri", 13)).pack()
    Label(text=" ").pack()
    Button(login_success, text="Encrypt", height="2", width="30", command = encrypt).pack()
    Label(text=" ").pack()
    Button(login_success, text="Decrypt", height="2", width="30", command= decrypt).pack()
 
    #login_success.mainloop()
 
    
    #Button(login_success_screen, text="OK", command=delete_login_success).pack()
 
# Designing popup for login invalid password
 
def password_not_recognised():
    global password_not_recog_screen
    password_not_recog_screen = Toplevel(login_screen)
    password_not_recog_screen.title("Success")
    password_not_recog_screen.geometry("150x100")
    Label(password_not_recog_screen, text="Invalid Password ").pack()
    Button(password_not_recog_screen, text="OK", command=delete_password_not_recognised).pack()
 
# Designing popup for user not found
 
def user_not_found():
    global user_not_found_screen
    user_not_found_screen = Toplevel(login_screen)
    user_not_found_screen.title("Success")
    user_not_found_screen.geometry("150x100")
    Label(user_not_found_screen, text="User Not Found").pack()
    Button(user_not_found_screen, text="OK", command=delete_user_not_found_screen).pack()
 
# Deleting popups
 
def delete_login_success():
    login_success_screen.destroy()
 
 
def delete_password_not_recognised():
    password_not_recog_screen.destroy()
 
 
def delete_user_not_found_screen():
    user_not_found_screen.destroy()
 
 
# Designing Main(first) window
 
def main_account_screen():
    global main_screen
    main_screen = Tk()
    main_screen.geometry("300x250")
    main_screen.title("Account Login")
    Label(text="Select Your Choice", bg="orange", width="300", height="2", font=("Calibri", 13)).pack()
    Label(text="").pack()
    Button(text="Login", height="2", width="30", command = login).pack()
    Label(text="").pack()
    Button(text="Register", height="2", width="30", command=register).pack()
 
 
    main_screen.mainloop()
    
def encrypt():
    global elogin_success
    elogin_success= Toplevel(login_success)
    elogin_success.geometry("300x250")
    elogin_success.title("Encryption Technique")
    Label(elogin_success,text="Select Your Choice", bg="orange", width="300", height="2", font=("Calibri", 13)).pack()
    Label(text=" ").pack()
    Button(elogin_success, text="Caesar Cipher", height="2", width="30", command = caesar_cipher_e).pack()
    Label(text=" ").pack()
    Button(elogin_success, text="RSA", height="2", width="30", command= rsa_e).pack()
    Label(text=" ").pack()
    Button(elogin_success, text="El-Gamal", height="2", width="30", command= el_gamal_e).pack()
    
    
    
def caesar_cipher_e():
    global eclogin_success
    eclogin_success= Toplevel(elogin_success)
    eclogin_success.geometry("300x250")
    eclogin_success.title("Caesar Cipher")
    Label(eclogin_success,text="Select Your Choice", bg="orange", width="300", height="2", font=("Calibri", 13)).pack()
    Label(text=" ").pack()
    Button(eclogin_success, text="Select A Text File", height="2", width="30", command = select_a_file_c_e).pack()
    Label(text=" ").pack()
    Button(eclogin_success, text="Select An Image File", height="2", width="30", command = msg).pack()


def rsa_e():
    global erlogin_success
    erlogin_success= Toplevel(elogin_success)
    erlogin_success.geometry("300x250")
    erlogin_success.title("RSA")
    Label(erlogin_success,text="Select Your Choice", bg="orange", width="300", height="2", font=("Calibri", 13)).pack()
    Label(text=" ").pack()
    Button(erlogin_success, text="Select A File", height="2", width="30", command = select_a_file_r_e).pack()
    Label(text=" ").pack()
    Button(erlogin_success, text="Select An Image File", height="2", width="30", command = msg).pack()



def el_gamal_e():
    global eelogin_success
    eelogin_success= Toplevel(elogin_success)
    eelogin_success.geometry("300x250")
    eelogin_success.title("EL-Gamal")
    Label(eelogin_success,text="Select Your Choice", bg="orange", width="300", height="2", font=("Calibri", 13)).pack()
    Label(text=" ").pack()
    Button(eelogin_success, text="Select A File", height="2", width="30", command = select_a_file_el_e).pack()
    Label(text=" ").pack()
    Button(eelogin_success, text="Select An Image File", height="2", width="30", command = msg).pack()
    Label(text=" ").pack()
#    Button(eclogin_success, text="Select All Image Files", height="2", width="30", command = select_a_file_s_e).pack()



def decrypt():
    global dlogin_success
    dlogin_success= Toplevel(login_screen)
    dlogin_success.geometry("300x250")
    dlogin_success.title("Decryption Tecnique")
    Label(dlogin_success,text="Select Your Choice", bg="orange", width="300", height="2", font=("Calibri", 13)).pack()
    Label(text=" ").pack()
    Button(dlogin_success, text="Caesar Cipher", height="2", width="30", command = caesar_cipher_d).pack()
    Label(text=" ").pack()
    Button(dlogin_success, text="RSA", height="2", width="30", command= rsa_d).pack()
    Label(text=" ").pack()
    Button(dlogin_success, text="El-Gamal", height="2", width="30", command= el_gamal_d).pack()
    Label(text=" ").pack()


    
def rsa_d():
    global rdlogin_success
    rdlogin_success= Toplevel(dlogin_success)
    rdlogin_success.geometry("300x250")
    rdlogin_success.title("RSA Decryption")
    Label(rdlogin_success,text="Select Your Choice", bg="orange", width="300", height="2", font=("Calibri", 13)).pack()
    Label(text=" ").pack()
    Button(rdlogin_success, text="Decrypt A Text File", height="2", width="30", command = select_a_file_id_e).pack()
    Label(text=" ").pack()
    Button(rdlogin_success, text="Decrypt An Image File", height="2", width="30", command = msg1).pack()





def caesar_cipher_d():
    global ccdlogin_success
    ccdlogin_success= Toplevel(dlogin_success)
    ccdlogin_success.geometry("300x250")
    ccdlogin_success.title("Caesar Cipher Decryption")
    Label(ccdlogin_success,text="Select Your Choice", bg="orange", width="300", height="2", font=("Calibri", 13)).pack()
    Label(text=" ").pack()
    Button(ccdlogin_success, text="Decrypt A Text File", height="2", width="30", command = select_a_file_idc_e).pack()
    Label(text=" ").pack()
    Button(ccdlogin_success, text="Decrypt An Image File", height="2", width="30", command = msg1).pack()



def el_gamal_d():
    global eedlogin_success
    eedlogin_success= Toplevel(dlogin_success)
    eedlogin_success.geometry("300x250")
    eedlogin_success.title("El-Gamal Decryption")
    Label(eedlogin_success,text="Select Your Choice", bg="orange", width="300", height="2", font=("Calibri", 13)).pack()
    Label(text=" ").pack()
    Button(eedlogin_success, text="Decrypt A Text File", height="2", width="30", command = select_a_file_ide_e).pack()
    Label(text=" ").pack()
    Button(eedlogin_success, text="Decrypt An Image File", height="2", width="30", command = msg1).pack()













#Image File
    
    
    


class Encryptor:
    def __init__(self, key):
        self.key = key

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message, key, key_size=256):
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
        fo.close()
        #return filename
        #os.remove(file_name)
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



key = b'[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e'
enc = Encryptor(key)
clear = lambda: os.system('cls')

def msg():
    global icselect_a_file
    icselect_a_file= Toplevel(elogin_success)
    icselect_a_file.geometry("300x250")
    icselect_a_file.title("Image File Encryption")
    global filename
    global filename_entry
    filename = StringVar()

    Label(icselect_a_file, text="Enter the file name with extension(.enc)\nLike(image.jpeg.enc)", bg="orange", width="300", height="2", font=("Calibri", 13)).pack()
    Label(icselect_a_file, text="").pack()
    filename_lable = Label(icselect_a_file, text="Filename * ")
    filename_lable.pack()
    filename_entry = Entry(icselect_a_file, textvariable=filename)
    filename_entry.pack()
    Button(icselect_a_file, text="Ok", bg="orange", width="5", font=("Calibri", 13), command=select_a_file_i_e).pack()
    print(filename.get())


def select_a_file_i_e():
    global icselect_a_file,imfile
    icselect_a_file= Toplevel(elogin_success)
    icselect_a_file.geometry("300x250")
    icselect_a_file.title("Image File Encryption")
   # root = tkinter.Tk()
    file = open("C:/Users/Priya/Desktop/temp/"+filename.get(), "r")
    #print(filename.get())
    #m = file.read()
    #filename = open(icselect_a_file.filename)
    imfile=filename.get()
    enc.encrypt_file(str(filename.get()))
    
    #filename = 'encrypted_file.txt'
    print('Encrypting......')
    #fout=open("/myfolder/"+login_success.filename,"w")
    #print (message)

    #print("Enetr A Key For Encryption/Decrytion")
    #print('Making key files...')
    #makeKeyFiles('r', 1024)
    #print('Key files made.')
    Label(icselect_a_file, text="Congratulations!!!!\nFile Succesfully Encrypted",font=("Courier", 12),width="300", height="5", bg="Green").pack()

def msg1():
    global icselect_a_file
    icselect_a_file= Toplevel(dlogin_success)
    icselect_a_file.geometry("300x250")
    icselect_a_file.title("Image File Decryption")
    global filename
    global filename_entry
    filename = StringVar()

    Label(icselect_a_file, text="Please enter details below", bg="orange", width="300", height="2", font=("Calibri", 13)).pack()
    Label(icselect_a_file, text="").pack()
    filename_lable = Label(icselect_a_file, text="Filename * ")
    filename_lable.pack()
    filename_entry = Entry(icselect_a_file, textvariable=filename)
    filename_entry.pack()
    Button(icselect_a_file, text="Ok", bg="orange", width="5", font=("Calibri", 13), command=select_a_file_is_e).pack()
    print(filename.get())
    

def select_a_file_is_e():
    global iddlogin_success
    iddlogin_success= Toplevel(icselect_a_file)
    iddlogin_success.geometry("300x250")
    iddlogin_success.title("Image File Decryption")
    
    enc.decrypt_file('image.jpeg.enc') 
    print('Decrypting......') 
    #filename1.write(str(getTranslatedMessage(mode, encrypted, dkey)))
    Label(iddlogin_success, text="Congratulations!!!!\nFile Succesfully Decrypted",font=("Courier", 12),width="300", height="5", bg="Green").pack()



  
    
    
    


    
    
    
    
    
    
    
    
    
    
#caesar_cipher encryption and decryption
    
    
def getTranslatedMessage(mode, message, key):
    if mode[0] == 'd':
        key = -key
    translated = ''
    for symbol in message:
        if symbol.isalpha():
            num = ord(symbol)
            num += key
            if symbol.isupper():
                if num > ord('Z'):
                    num -= 26
                elif num < ord('A'):
                    num += 26
            elif symbol.islower():
                if num > ord('z'):
                    num -= 26
                elif num < ord('a'):
                    num += 26
            translated += chr(num)
        else:
            translated += symbol
    return translated


def select_a_file_c_e():
    global cselect_a_file
    cselect_a_file= Toplevel(elogin_success)
    cselect_a_file.geometry("300x250")
    cselect_a_file.title("Caesar Cipher Encryption")
   # root = tkinter.Tk()
    cselect_a_file.filename = tkinter.filedialog.askopenfilename(initialdir = "/",title = "Select file")
    data = cselect_a_file.filename
    global f
    f = open(cselect_a_file.filename)
    #fout=open("/myfolder/"+login_success.filename,"w")
    message = f.read()
    #print (message)
    f.close()
    #print("Enetr A Key For Encryption/Decrytion")
    global dkey 
    dkey = 4
    global encrypted
    #print('Making key files...')
    #makeKeyFiles('r', 1024)
    #print('Key files made.')

    filename = 'encrypted_file.txt'
    print('Encrypting......')
    mode='encrypt'
    encrypted = getTranslatedMessage(mode, message, dkey)
    #print(encrypted)
    f = open(filename,"w")
    f.write(str(encrypted))
    f.close()
    Label(cselect_a_file, text="Congratulations!!!!\nFile Succesfully Encrypted",font=("Courier", 12),width="300", height="5", bg="Green").pack()
    #Button(select_a_file, text="OK", command=login_success).pack()


def select_a_file_idc_e():
    global ddlogin_success
    ddlogin_success= Toplevel(dlogin_success)
    ddlogin_success.geometry("300x250")
    ddlogin_success.title("Caesar Cipher Decryption")
    filename1 = 'decrypted_file.txt' 
    print('Decrypting......') 
    mode='decrypt'
    decryptedText = getTranslatedMessage(mode, encrypted, dkey)
    filename1 = open(filename1,"w")
    filename1.write(str(getTranslatedMessage(mode, encrypted, dkey)))
    Label(ddlogin_success, text="Congratulations!!!!\nFile Succesfully Decrypted",font=("Courier", 12),width="300", height="5", bg="Green").pack()
    
    #f.close()
    #Label(login_success, text="File Succesfully Decrypted").pack()
    
    

    #Button(select_a_file, text="OK", command=login_success).pack()
    
    
    
    
    
  
    
    
    
    
    

#RSA encryption and decryption

    
def select_a_file_r_e():
    global edlogin_success
    edlogin_success= Toplevel(elogin_success)
    edlogin_success.geometry("300x250")
    edlogin_success.title("RSA Encryption")
    #global select_a_file
    #select_a_file= Toplevel(login_success)
    global filename
    global filename1
    global f
#    select_a_file.geometry("300x250")
   # root = tkinter.Tk()
    edlogin_success.filename = tkinter.filedialog.askopenfilename(initialdir = "/",title = "Select file")
    data = edlogin_success.filename
    f = open(edlogin_success.filename)
    #fout=open("/myfolder/"+login_success.filename,"w")
    message = f.read()
    #print (message)
    #f.close()  
    #print message
    f.close()
    print('Making key files...')
    makeKeyFiles('r', 1024)
    print('Key files made.')

    filename = 'r_encryptedfile.txt' # the file to write to/read from
    filename1 = 'r_decryptedfile.txt' 
    #message = '''"Journalists belong in the gutter because that is where the ruling classes throw their guilty secrets." -Gerald Priestland "The Founding Fathers gave the free press the protection it must have to bare the secrets of government and inform the people." -Hugo Black'''
    
    pubKeyFilename = 'r_encryptedfile.txt'

    print('Encrypting and writing to %s...' % (filename))

    encryptedText = encryptAndWriteToFile(filename, pubKeyFilename, message)
    Label(edlogin_success, text="Congratulations!!!!\nFile Succesfully Encrypted",font=("Courier", 12),width="300", height="5", bg="Green").pack()
    
   

 

    #print('Encrypted text:')

    #print(encryptedText)


    
def select_a_file_id_e():
    global rddlogin_success
    rddlogin_success= Toplevel(rdlogin_success)
    rddlogin_success.geometry("300x250")
    rddlogin_success.title("RSA Decryption")
    filename1 ='decrypted_file.txt'

   # Label(select_a_file, text="File Succesfully Decrypted").pack()
    #Button(select_a_file, text="OK", command=login_success).pack()
    
    privKeyFilename = 'r_decryptedfile.txt'
    #filename = 'decrypted_file.txt'
    #filename1 = 'r_decryptedfile.txt' 

    print('Reading from %s and decrypting...' % (filename))
    

    decryptedText = readFromFileAndDecrypt(filename, privKeyFilename)
    filename1 = open(filename1,"w")
    filename1.write((readFromFileAndDecrypt(filename, privKeyFilename)))
    print('Decrypted text:')
    Label(rddlogin_success, text="Congratulations!!!!\nFile Succesfully Decrypted",font=("Courier", 12),width="300", height="5", bg="Green").pack()
    
    

    
def generateKey(keySize):
    print('Generating p prime...')
    p = rabinMiller.generateLargePrime(keySize)
    print('Generating q prime...')
    q = rabinMiller.generateLargePrime(keySize)
    n = p * q
    print('Generating e that is relatively prime to (p-1)*(q-1)...')
    while True:
        e = random.randrange(2 ** (keySize - 1), 2 ** (keySize))
        if cryptomath.gcd(e, (p - 1) * (q - 1)) == 1:
            break
    print('Calculating d that is mod inverse of e...')
    d = cryptomath.findModInverse(e, (p - 1) * (q - 1))
    publicKey = (n, e)
    privateKey = (n, d)
    return (publicKey, privateKey)


def makeKeyFiles(name, keySize):
    publicKey, privateKey = generateKey(keySize)
    print()
    print('The public key is a %s and a %s digit number.' % (len(str(publicKey[0])), len(str(publicKey[1]))))
    print('Writing public key to file %s_encryptedfile.txt...' % (name))
    fo = open('%s_encryptedfile.txt' % (name), 'w')
    fo.write('%s,%s,%s' % (keySize, publicKey[0], publicKey[1]))
    fo.close()
    print()
    print('The private key is a %s and a %s digit number.' % (len(str(publicKey[0])), len(str(publicKey[1]))))
    print('Writing private key to file %s_decryptedfile.txt...' % (name))
    fo = open('%s_decryptedfile.txt' % (name), 'w')
    fo.write('%s,%s,%s' % (keySize, privateKey[0], privateKey[1]))
    fo.close()
 

def getBlocksFromText(message, blockSize=DEFAULT_BLOCK_SIZE):
    messageBytes = message.encode('ascii') # convert the string to bytes
    blockInts = []
    for blockStart in range(0, len(messageBytes), blockSize):
        blockInt = 0
        for i in range(blockStart, min(blockStart + blockSize, len(messageBytes))):
            blockInt += messageBytes[i] * (BYTE_SIZE ** (i % blockSize))
        blockInts.append(blockInt)
    return blockInts



def getTextFromBlocks(blockInts, messageLength, blockSize=DEFAULT_BLOCK_SIZE):
    message = []
    for blockInt in blockInts:
        blockMessage = []
        for i in range(blockSize - 1, -1, -1):
            if len(message) + i < messageLength:
                asciiNumber = blockInt // (BYTE_SIZE ** i)
                blockInt = blockInt % (BYTE_SIZE ** i)
                blockMessage.insert(0, chr(asciiNumber))
        message.extend(blockMessage)
    return ''.join(message)



def encryptMessage(message, key, blockSize=DEFAULT_BLOCK_SIZE):
    encryptedBlocks = []
    n, e = key
    for block in getBlocksFromText(message, blockSize):
        encryptedBlocks.append(pow(block, e, n))
    return encryptedBlocks

 

 
def decryptMessage(encryptedBlocks, messageLength, key, blockSize=DEFAULT_BLOCK_SIZE):
    decryptedBlocks = []
    n, d = key
    for block in encryptedBlocks:
        decryptedBlocks.append(pow(block, d, n))
    return getTextFromBlocks(decryptedBlocks, messageLength, blockSize)



def readKeyFile(keyFilename):
    fo = open(keyFilename)
    content = fo.read()
    fo.close()
    keySize, n, EorD = content.split(',')
    return (int(keySize), int(n), int(EorD))



def encryptAndWriteToFile(messageFilename, keyFilename, message, blockSize=DEFAULT_BLOCK_SIZE):
    keySize, n, e = readKeyFile(keyFilename)
    if keySize < blockSize * 8: # * 8 to convert bytes to bits
        sys.exit('ERROR: Block size is %s bits and key size is %s bits. The RSA cipher requires the block size to be equal to or less than the key size. Either increase the block size or use different keys.' % (blockSize * 8, keySize))
    encryptedBlocks = encryptMessage(message, (n, e), blockSize)
    for i in range(len(encryptedBlocks)):
        encryptedBlocks[i] = str(encryptedBlocks[i])
    encryptedContent = ','.join(encryptedBlocks)
    encryptedContent = '%s_%s_%s' % (len(message), blockSize, encryptedContent)
    fo = open(messageFilename, 'w')
    fo.write(encryptedContent)
    fo.close()
    # Also return the encrypted string
    return encryptedContent



def readFromFileAndDecrypt(messageFilename, keyFilename):
    keySize, n, d = readKeyFile(keyFilename)
    fo = open(messageFilename)
    content = fo.read()
    messageLength, blockSize, encryptedMessage = content.split('_')
    messageLength = int(messageLength)
    blockSize = int(blockSize)
     # Check that key size is greater than block size.
    if keySize < blockSize * 8: # * 8 to convert bytes to bits
        sys.exit('ERROR: Block size is %s bits and key size is %s bits. The RSA cipher requires the block size to be equal to or less than the key size. Did you specify the correct key file and encrypted file?' % (blockSize * 8, keySize))
    encryptedBlocks = []
    for block in encryptedMessage.split(','):
        encryptedBlocks.append(int(block))
    return decryptMessage(encryptedBlocks, messageLength, (n, d), blockSize)


















#el-gamal encryption and decryption

a = random.randint(2, 10) 
  
def gcd(a, b): 
    if a < b: 
        return gcd(b, a) 
    elif a % b == 0: 
        return b; 
    else: 
        return gcd(b, a % b) 
  
# Generating large random numbers 
def gen_key(q): 
  
    key = random.randint(2, q) 
    while gcd(q, key) != 1: 
        key = random.randint(2, q) 
  
    return key 
  
# Modular exponentiation 
def power(a, b, c): 
    x = 1
    y = a 
  
    while b > 0: 
        if b % 2 == 0: 
            x = (x * y) % c; 
        y = (y * y) % c 
        b = int(b / 2) 
  
    return x % c 
  
# Asymmetric encryption 
def encryptel(msg, q, h, g): 
  
    en_msg = [] 
  
    k = gen_key(q)# Private key for sender 
    s = power(h, k, q) 
    p = power(g, k, q) 
      
    for i in range(0, len(msg)): 
        en_msg.append(msg[i]) 
  
    #print("g^k used : ", p) 
    #print("g^ak used : ", s) 
    for i in range(0, len(en_msg)): 
        en_msg[i] = s * ord(en_msg[i]) 
   # print("Encrypted ",en_msg)
    return en_msg, p 
  
def decryptel(en_msg, p, key, q): 
  
    dr_msg = [] 
    h = power(p, key, q) 
    for i in range(0, len(en_msg)): 
        dr_msg.append(chr(int(en_msg[i]/h))) 
          
    return dr_msg 


def select_a_file_el_e():
    global flogin_success
    flogin_success= Toplevel(elogin_success)
    flogin_success.geometry("300x250")
    flogin_success.title("El-Gamal Encryption")
   # root = tkinter.Tk()
    flogin_success.filename = tkinter.filedialog.askopenfilename(initialdir = "/",title = "Select file")
    data = flogin_success.filename
    global f
    f = open(flogin_success.filename)
    #fout=open("/myfolder/"+login_success.filename,"w")
    msg = f.read()
    #print (message)
    f.close() 
    
    global q,g,key,h
    q = random.randint(15, 17) 
    #print("q",q)
    g = random.randint(2, q) 
    #print("g",g)
    key = gen_key(q)# Private key for receiver 
    h = power(g, key, q) 
    #print("g used : ", g) 
    #print("g^a used : ", h) 
    global en_msg,p
    
    filename = 'encrypted_file.txt'
    
  
    en_msg, p = encryptel(msg, q, h, g) 
    f = open(filename,"w")
    f.write(str(en_msg))
    f.close()
    Label(flogin_success, text="Congratulations!!!!\nFile Succesfully Encrypted",font=("Courier", 12),width="300", height="5", bg="Green").pack()


def select_a_file_ide_e():
    global gdlogin_success
    gdlogin_success= Toplevel(dlogin_success)
    gdlogin_success.geometry("300x250")
    gdlogin_success.title("El-Gamal Decryption")
    filename='decrypted_file.txt'
    f = open(filename,'w')
    #f = open(filename,"w")
    dr_msg = decryptel(en_msg, p, key, q) 
    dmsg = ''.join(dr_msg)
    print("Decrypting Message"); 
    f.write(str(dmsg))
    #f.close()
    Label(gdlogin_success, text="Congratulations!!!!\nFile Succesfully Decrypted",font=("Courier", 12),width="300", height="5", bg="Green").pack()
    

 
 
main_account_screen()