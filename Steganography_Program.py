import sys
import hashlib
import binascii
import re
from PIL import Image
import cv2            # pip install opencv-python
import math ###PNG

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
stringmessage = "" # Global string to store secret message ###PNG


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
            print("Please enter a number 1 - 5.")

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
    global stringmessage ###PNG
    hiddenMessage = input("Please enter the message you would like to hide in the image.\n")
    stringmessage = hiddenMessage ###PNG
    for l in hiddenMessage:
        letter =' '.join(format(i, 'b') for i in bytearray(l, encoding='utf-8'))
        messageList.append(letter)
    ln = len(messageList)
    print(ln)
    print(messageList)

# Generic ASCII to Binary ###PNG
# def binaryconversion(ascii):
    #return [ format(char, "08b") for char in ascii ]

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
# Referenced:  https://dev.to/erikwhiting88/let-s-hide-a-secret-message-in-an-image-with-python-and-opencv-1jf5
def encryptPNG():
    global fileName, stringmessage ###PNG

    # Read PNG Image using OpenCV Python
    png_image = cv2.imread(fileName)
    
    # Generator expresssion using ORD to return unicode character based integer of hidden message
    message = (ord(character) for character in stringmessage)
    
    # Appy the Greatest Common Denominator Method to determine which pixels to change
    gcd_method = math.gcd(len(png_image), len(png_image[0]))
    
    # Iterate through PNG image numpy array to create encoded PNG image
    for width in range(len(png_image)):
        for height in range(len(png_image[0])):
        
            # Offset by 1 to not introduce divide by zero error
            if (width + 1 * height + 1) % gcd_method == 0:
          
                # Attempt to add next character in hidden message
                try:
                    png_image[width - 1][height - 1][0] = next(message)
          
                # If execption is thrown, we have reached the end of the hidden message
                except StopIteration:
                    png_image[width - 1][height - 1][0] = 0
                    break

    #Set the name for the file being written
    fName = "encoded_"+fileName
    cv2.imwrite(fName, png_image)
    print("Your message has been hidden into:", fName)


# decryption algorithm for PNG
# Referenced:  https://dev.to/erikwhiting88/let-s-hide-a-secret-message-in-an-image-with-python-and-opencv-1jf5
def decryptPNG():

    global fileName

    # Read PNG Image using OpenCV Python
    png_image = cv2.imread(fileName)
    
    # Appy the Greatest Common Denominator Method to determine which pixels to change
    gcd_method = math.gcd(len(png_image), len(png_image[0]))
    
    # Initialize Variable
    hidden_message = ''
    
    # Iterate through PNG image numpy array to create encoded PNG image
    for width in range(len(png_image)):
        for height in range(len(png_image[0])):
        
            # Offset by 1 to not introduce divide by zero error
            # Step through Greatest Common Denominator multiples to store non zero values
            if (width - 1 * height - 1) % gcd_method == 0:
                if png_image[width - 1][height - 1][0] != 0:
                    hidden_message = hidden_message + chr(png_image[width - 1][height - 1][0])

                # If current value is 0, then we have reached the end of the hidden message
                else:
                    break

    print("Decrypted hidden message:", hidden_message)

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
