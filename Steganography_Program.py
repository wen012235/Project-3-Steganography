import sys
import hashlib
import binascii
import re
from PIL import Image
import cv2            # pip install opencv-python
import numpy as np

#---------
#Global Variables
data = "" # original file information
fileName = "" # original file name
messageList = [] # hold secret message
ln = 0 # letters needed
letListQty = [] #Number of letters that can be stored in each section of the image
tLet = 0 #Total letters that can be stored
cHead = "" # Number of items in headList
headList = [] # Holds stopping points
red = 0 # Red location in PIXEL
green = 1 # Green location in PIXEL
blue = 2 # Blue location in PIXEL


#Main Menu and Directions for the program
def mainMenu():
    print(
        "Press 1 if you want to encrypt a JPG.\n" \
        + "Press 2 if you want to encrypt a PNG.\n" \
        + "Press 3 if you want to decrypt a JPG.\n" \
        + "Press 4 if you want to decrypt a PNG.\n" \
        + "Press 5 to exit.\n")

    while True:
        try:
            choice = int(input("How would you like to proceed: "))
            break
        except ValueError:
            print("Please enter a number 1 - 3.")

    if choice == 1:
        print("Encrypt a message into a JPG image.")
        # this is where we will call the encryption function
        openFile()
        loadDataJPG()
        asc2bin()
        bytesNeeded()
        fit()
        encryptJPG()
    
    elif choice == 2:
        print("Encrypt a message into a PNG image.")
        # this is where we will call the encryption function
        openFile()
        loadDataPNG()
        asc2bin()
        bytesNeeded()
        fit()
        encryptPNG()
    
    elif choice == 3:
        print("Decrypt a message stored in JPG image.")
        # this is where we will call the decryption function

    elif choice == 4:
        print("Decrypt a message stored in PNG image.")
        # this is where we will call the decryption function
        openEncryptedFile()
        decryptPNG()
    
    elif choice == 5:
        sys.exit("\n Thank you for using our Steganography Program!\n")
    
    else:
        print("\n Invalid entry.  Please enter a number from 1-5\n")
        mainMenu()

#ascii to binary
def asc2bin():
    global messageList
    global ln
    hiddenMessage = input("Please enter the message you would like to hide in the image.\n")
    for l in hiddenMessage:
        letter =' '.join(format(i, 'b') for i in bytearray(l, encoding='utf-8'))
        messageList.append(letter)
    ln = len(messageList)
    print(ln)
    print(messageList)

# Generic ASCII to Binary
def binaryconversion(ascii):
    return [ format(char, "08b") for char in ascii ]

#bytes needed to hide the image
def bytesNeeded():
    global messageList
    
    chrInMsg = messageList
    bn = len(chrInMsg)*8
    print("You need " + str(bn) + " bytes to hide the data.")
    
#checks to see if secret message will fit
def fit():
    global ln
    global tLet

    if ln < tLet:
        print("Congratulations!  Your message will fit.")
    else:
        print("Your secret message will not fit in this image.")
        mainMenu()

#binary to ascii

# show image file for encryption
def showFile(file):   
    iFile = Image.open(file)        
    iFile.show()
    return file

# open image file for encryption
def openFile():
    global data
    file = input("Enter the name of the file you want to use to hide a message in:\n")
    
    #Checks to see that the file exists
    while True:
        try:
            imgFile = open(file, 'rb')
            break
        except IOError:
            print('\nThere is no file named ', file)
            file = input("Enter the name of the file you want to use to hide a message in: \n")
    
    #store the original file name to use it in the encoded file name.
    global fileName
    fileName = fileName + file
    
    data = imgFile.read()
    imgFile.close()
    #showFile(file)

# open image file for decryption
def openEncryptedFile():
    global data
    file = input("Enter the name of the file you want to use to decrypt a hidden message from:\n")
    
    #Checks to see that the file exists
    while True:
        try:
            imgFile = open(file, 'rb')
            break
        except IOError:
            print('\nThere is no file named ', file)
            file = input("Enter the name of the file you want to use to decrypt a hidden message from:\n")
    
    #store the original file name to use it in the decoded file name.
    global fileName
    fileName = fileName + file
    
    data = imgFile.read()
    imgFile.close()
    #showFile(file)

# Calculations for JPG Encryption locations
def loadDataJPG():
    global data
    global letListQty
    global tLet
    global cHead
    global headList
    
    SOFList = []
    SOFOList = []
    SOF2List = []
    DHTList = []
    DQTList = []
    DRIList = []
    EOFList = []
    SOSList = []
    COMList = []
    
    
    SOF = b"\xFF\xD8\xFF"
    SOFO = b"\xFF\xC0"
    SOF2 = b"\xFF\xC2"
    DHT = b"\xFF\xC4"
    DQT = b"\xFF\xDB"
    DRI = b"\xFF\xDD"
    EOF = b"\xFF\xD9"
    SOS = b"\xFF\xDA"
    COM = b"\xFF\xFE"
    

    SOFList = [match.start() for match in re.finditer(re.escape(SOF),data)]
    SOFOList = [match.start() for match in re.finditer(re.escape(SOFO),data)]
    SOF2List = [match.start() for match in re.finditer(re.escape(SOF2),data)]
    DHTList = [match.start() for match in re.finditer(re.escape(DHT),data)]
    DQTList = [match.start() for match in re.finditer(re.escape(DQT),data)]
    DRIList = [match.start() for match in re.finditer(re.escape(DRI),data)]
    SOSList = [match.start() for match in re.finditer(re.escape(SOS),data)]
    COMList = [match.start() for match in re.finditer(re.escape(COM),data)]
    EOFList = [match.start() for match in re.finditer(re.escape(EOF),data)]

    print(SOFList)
    print(SOFOList)
    print(SOF2List)
    print(DHTList)
    print(DQTList)
    print(DRIList)
    print(SOSList)
    print(COMList)
    print(EOFList)
    
   
    cDQT = len(DQTList) # Number of DQT headers 
    cSOFO = len(SOFOList) # Number SOFO headers
    cSOF2 = len(SOF2List) # Number SOF2 headers
    cDHT = len(DHTList) # Number DHT headers
    cSOS = len(SOSList) # Number SOS headers
    cCOM = len(COMList) # Number COM headers
    

    #Fill the list with stopping points
    headList.append(SOFList[0])
    for i in range(cDQT):
        headList.append(DQTList[i])
    for i in range(cSOFO):
        headList.append(SOFOList[i])
    for i in range(cSOF2):
        headList.append(SOF2List[i])
    for i in range(cDHT):
        headList.append(DHTList[i])
    for i in range(cSOS):
        headList.append(SOSList[i])
    for i in range(cCOM):
        headList.append(COMList[i])
    headList.append(EOFList[0])
    headList.sort()
    print(headList)


    #calculate if space to hold message
 
    cnt = len(headList)
    for x in range(cnt-1):
        aBytes = headList[x+1] - headList[x] - 6
        letQty = int(aBytes / 8)
        letListQty.append(letQty)
    print(letListQty)

    for item in letListQty:
        tLet = tLet + item
    print(tLet)
    
    
#encryption algorithm for JPG
def encryptJPG():
    global fileName
    global data
    global ln
    global messageList
    global letListQty
    global tLet
    global cHead
    global headList


   
    
    tmpStr = "" # Holds the secret message string

    
    #writes the entire message to a string
    for item in messageList:
        if len(item)==6:
            item = '00'+ item

        if len(item)==7:
            item = '0'+ item
            
        for x in range(8):
            tmpStr = tmpStr + item[x]
        

    tmpStrLen = len(tmpStr)

    cHead = len(headList)

    #file header that should not be written over
    info = data[headList[0]:headList[1]+5]
    
    cnt = headList[1]+5 # starting count for the file
    #Load the info to write to the file
    s = 0 #counter for string
    for h in range(2, cHead):
        for l in range(cnt, headList[h]):
            if s < tmpStrLen:
                enc = data[l]
                val = tmpStr[s]
                #Check to see if the current final bit is the same or different
                #If same do not change - if different change the last bit.
                #If original file value is odd and message needs even subtract 1 to prevent overflow error
                #If original file even and message needs odd add 1 to prevent negative number
                if(int(val)%2==0 and enc%2==0) or (int(val)%2==1 and enc%2==1):
                    v = enc.to_bytes(1,'big')
                    info = info + v
                elif int(val)%2 == 0 and enc % 2 == 1:
                    enc = enc - 1
                    v = enc.to_bytes(1,'big')
                    info = info + v  
                else:
                    enc = enc + 1
                    v = enc.to_bytes(1,'big')
                    info = info + v
                s = s+1
            else:
                enc = data[l]
                v = enc.to_bytes(1,'big')
                info = info + v
        print("Data stop: ", str(h))
        
        if (h)< cHead-1:
            info = info + data[headList[h]: headList[h]+5]
            cnt = headList[h]+5
        else:
            info = info + data[headList[cHead-1]:headList[cHead-1]+2]
        
  


    #Set the name for the file being written
    fName = "encoded_"+fileName
    print(fName)

    #Open the file for writing
    file = open(fName,'ba+')
    file.write(info)
    file.close()

# Calculations for PNG Image Information
def loadDataPNG():
    global fileName, tLet
    png_image = cv2.imread(fileName)

    # Find the total number of letters that can be stored in PNG
    tLet = png_image.shape[0] * png_image.shape[1] * 3 // 8

# encryption algorithm for PNG
# Referenced:  https://www.thepythoncode.com/article/hide-secret-data-in-images-using-steganography-python
def encryptPNG():
    global fileName, messageList, ln, red, green, blue
    counter = 0
    message = ' '.join(messageList)
    binary_message_len = len(message)
    png_image = cv2.imread(fileName)

    for row in png_image:
        for pixel in row:
            # RGB to Binary
            red_pixel = ''.join(binaryconversion(pixel))
            green_pixel = ''.join(binaryconversion(pixel))
            blue_pixel = ''.join(binaryconversion(pixel))

            # Modify Least Significant Bit for Red, Green, and Blue
            
            # Red
            if counter < binary_message_len:
                pixel[red] = int(red_pixel[:-1] + message[counter], 2)
                counter += 1

            # Green
            if counter < binary_message_len:
                pixel[green] = int(green_pixel[:-1] + message[counter], 2)
                counter += 1

            # Blue
            if counter < binary_message_len:
                pixel[blue] = int(blue_pixel[:-1] + message[counter], 2)
                counter += 1
                
            # Done
            if counter >= binary_message_len:
                break
    
    #Set the name for the file being written
    fName = "encoded_"+fileName
    cv2.imwrite(fName, png_image)
    print("Your message has been hidden into:", fName)


# decryption algorithm for PNG
# Referenced:  https://www.thepythoncode.com/article/hide-secret-data-in-images-using-steganography-python
def decryptPNG():
    png_image = cv2.imread(fileName)
    binary = ""
    chars = ""
    
    # Referenced 
    for row in png_image:
        for pixel in row:
            # RGB to Binary
            
            # Red
            red_pixel = ''.join(binaryconversion(pixel))
            binary += red_pixel[-1]

            # Green
            green_pixel = ''.join(binaryconversion(pixel))
            binary += green_pixel[-1]
            
            # Blue
            blue_pixel = ''.join(binaryconversion(pixel))
            binary += blue_pixel[-1]
            
    # Divide up every 8-bits
    split = [ binary[bit: bit+8] for bit in range(0, len(binary), 8) ]

    # Perform Bit to Character Conversion
    for char in split:
        chars += chr(int(char, 2))
        #TODO: Implement Stopping Criteria
    #     if chars[-5:] == :
    #       break

    # print("Decrypted hidden message:", chars[:-5])

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


#----------------
#Run the Program
#----------------
print("Welcome to the LED Zeplin Steganography Program")
#This next line needs to include the type of file to use for the stego tool
print(
    "This program will allow you to encrypt an image with a message\n"\
    + "or decrypt a message.\n")
mainMenu()
