import sys
import hashlib
import binascii
import re
from PIL import Image
#from jpegexif import *
from DrHansen import *

filename = ""
hiddenmessage = ""
# Main Menu and Directions for the program
def mainMenu():
    import jpegexif
    print(
        "Press 1 if you want to encrypt a file.\n" \
        + "Press 2 if you want to decrypt a file.\n" \
        + "Press 3 to exit.\n")

    while True:
        try:
            choice = int(input("How would you like to proceed: "))
            break
        except ValueError:
            print("Please enter a number 1 - 3.")

    if choice == 1:
        print("Encrypt a message in an image.\n")
        hiddenMessage = input("Please enter the message you would like to hide in the image.\n")
        filename = input("Enter the name of the file you want to use to hide a message in:\n")
        img = Image.open(filename)
        n_bytes = img.size[0] * img.size[1] * 3
        if n_bytes > len(hiddenMessage):
            print("You can encrypt your message two ways:\n"
                  "LSB is harder to detect, but may result in your image looking different.\n"
                  "Exif is easier to detect, but the pictures will look identical.\n"
                  "Press 1 to encrypt using LSB.\n" 
                  "Press 2 to encrypt using Exif.\n")
            while True:
                try:
                    encrypt_choice = int(input("How would you like to proceed: "))
                    break
                except ValueError:
                    print("Please enter a number 1 - 2.")
            if encrypt_choice == 1:
                print("coming soon")
                #LSB
            elif encrypt_choice == 2:
                jpegexif.exifhide()

            else:
                print("Invalid entry.  Please enter a number 1 - 2.")

        else:
            exifhide()
        # this is where we will call the encryption function
        """openFile()
        calcJPG()
        asc2bin()
        bytesNeeded()
        fit()
        encryptJPG()"""

    elif choice == 2:
        print("Decrypt a message stored in an image.")
        # this is where we will call the decryption function
    elif choice == 3:
        sys.exit("\n Thank you for using our Steganography Program!\n")
    else:
        print("\n Invalid entry.  Please enter a number from 1-3\n")
        mainMenu()
mainMenu()