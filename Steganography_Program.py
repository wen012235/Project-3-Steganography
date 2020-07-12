import sys
import hashlib


#Main menu and directions for the program.
def mainMenu():
    print("Welcome to the LED Zeplin Steganography Program")
    print(
        "This program will allow you to encrypt an image with a message\n"\
        + "or decrypt a message.\n")
    print(
        "Press 1 if you want to encrypt a file.\n" \
        + "Press 2 if you want to decrypt a file.\n" \
        + "Press 3 to exit.\n")
    choice = input("How would you like to proceed: ")

    if choice.isdigit():
        choice = int(choice)
    else:
        print("Please enter a number from 1-3")
        mainMenu()

    if menu == 1:
        print("Encrypt a message in an image.")
        # this is where we will call the encryption function
    elif menu == 2:
        print("Decrypt a message stored in an image.")
        # this is where we will call the decryption function
    elif menu == 3:
        sys.exit("\n Thank you for using our Steganography Program!\n")
    else:
        print("\n Invalid entry.  Try again.\n")
        mainMenu()

#image file for encryption

            
#encryption algorithm


#decryption algorithm


#file output information

# MD5 Hash
def fileHash(fileName):
    BLOCKSIZE = 65536
    file = fileName
    md5_hash = hashlib.md5()
    with open(file, 'rb') as afile:
        buf = afile.read(BLOCKSIZE)
        while len(buf) > 0:
            md5_hash.update(buf)
            buf = afile.read(BLOCKSIZE)
    hashVal = md5_hash.hexdigest()
    print(fileName + " MD5 hash:" + hashVal + "\n")
    
# ---------------------------------------------------------------------
mainMenu()


