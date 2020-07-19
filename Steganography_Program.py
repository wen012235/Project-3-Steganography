import sys
import hashlib
import binascii
import re
#from PIL import Image

#---------
#Global Variables
data = "" # original file information
fileName = "" # original file name
messageList = [] # hold secret message
ln = 0 # letters needed
letListQty = [] #Number of letters that can be stored in each section of the image
tLet = 0 #Total letters that can be stored

#List of header variables
SOFList = []
SOFOList = []
SOF2List = []
DHTList = []
DQTList = []
DRIList = []
EOFList = []
SOSList = []
COMList = []

#Main Menu and Directions for the program
def mainMenu():
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
        print("Encrypt a message in an image.")
        # this is where we will call the encryption function
        openFile()
        calcJPG()
        asc2bin()
        bytesNeeded()
        fit()
        encryptJPG() 
        
    elif choice == 2:
        print("Decrypt a message stored in an image.")
        # this is where we will call the decryption function
    elif choice == 3:
        sys.exit("\n Thank you for using our Steganography Program!\n")
    else:
        print("\n Invalid entry.  Please enter a number from 1-3\n")
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

# Calculations for JPG Encryption locations
def calcJPG():
    global data
    global messageList
    global tLet
    global SOFList
    global SOFOList
    global SOF2List
    global DHTList
    global DQTList
    global DRIList
    global SOSList
    global EOFList
    global COMList
    global letListQty
    
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

    #counter for headers 
    cnt = 0
    
    if len(DQTList)>0:
        count = len(DQTList)
        cnt = count
        for x in range(count):
            c = x
            if c+1 == count:
                break
            else:
                aBytes = DQTList[x+1]-DQTList[x]-6          
                letQty = int(aBytes / 8)
                letListQty.append(letQty)
            
    if len(SOFOList)>0 and len(SOF2List)>0:
        if SOFOList[0] < SOF2List[0]:
            aBytes = SOFOList[0] - DQTList[cnt-1]-6
            letQty = int(aBytes / 8)
            letListQty.append(letQty)
        else:
            aBytes = SOF2List[0] - DQTList[cnt-1]-6
            letQty = int(aBytes / 8)
            letListQty.append(letQty)
            
    if len(SOFOList)>0:
        count = len(SOFOList)
        aBytes = SOFOList[0] - DQTList[cnt-1]-6
        letQty = int(aBytes / 8)
        letListQty.append(letQty)
        cnt = count
        for x in range(count):
            c = x
            if c+1 == count:
                break
            else:
                aBytes = SOFOList[x+1]-SOFOList[x]-5
                letQty = int(aBytes / 8)
                letListQty.append(letQty)
            
    if len(SOF2List)>0:
        count = len(SOF2List)
        aBytes = SOF2List[0] - DQTList[cnt-1]-6
        letQty = int(aBytes / 8)
        letListQty.append(letQty)
        cnt = count
        for x in range(count):
            c = x
            if c+1 == count:
                break
            else:
                aBytes = SOF2List[x+1]-SOF2List[x]-5
                letQty = int(aBytes / 8)
                letListQty.append(letQty)
            
    if len(DHTList) > 0:
        count = len(DHTList)
        if len(SOFOList)>0 and len(SOF2List)==0:
            aBytes = DHTList[0] - SOFOList[cnt-1]-5
        else:
            aBytes = DHTList[0] - SOF2List[cnt-1]-5
        letQty = int(aBytes / 8)
        letListQty.append(letQty)
        cnt = count
        for x in range(count):
            c = x
            if c+1 == count:
                break
            else:
                aBytes = DHTList[x+1]-DHTList[x]-6
                letQty = int(aBytes / 8)
                letListQty.append(letQty)

    if len(SOSList)>0:
        count = len(SOSList)
        aBytes = SOSList[0] - DHTList[cnt-1]-6
        letQty = int(aBytes / 8)
        letListQty.append(letQty)
        cnt = count
        for x in range(count):
            c = x
            if c+1 == count:
                break
            else:
                aBytes = SOSList[x+1]-SOSList[x]-6          
                letQty = int(aBytes / 8)
                letListQty.append(letQty)
    
    if len(COMList)>0:
        count = len(COMList)
        aBytes = COMList[0] - SOSList[cnt-1]-6
        letQty = int(aBytes / 8)
        letListQty.append(letQty)
        cnt = count
        for x in range(count):
            c = x
            if c+1 == count:
                break
            else:
                aBytes = COMList[x+1]-COMList[x]-6          
                letQty = int(aBytes / 8)
                letListQty.append(letQty)

    aBytes = EOFList[0] - SOSList[cnt-1]-6
    letQty = int(aBytes / 8)
    print(letQty)
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
    global SOFList
    global SOFOList
    global SOF2List
    global DHTList
    global DQTList
    global DRIList
    global EOFList
    global SOSList
    global COMList
    global letListQty


    cnt = DQTList[0]+5 # starting count for the file
    
    tmpStr = "" # Holds the secret message string
    headList = [] # Holds stopping points
    cDQT = len(DQTList) # Number of DQT headers 
    cSOFO = len(SOFOList) # Number SOFO headers
    cSOF2 = len(SOF2List) # Number SOF2 headers
    cDHT = len(DHTList) # Number DHT headers
    cSOS = len(SOSList) # Number SOS headers
    cCOM = len(COMList) # Number COM headers
    cHead = "" # Number of items in headList

    #Fill the list with stopping points
    for i in range(cDQT):
        headList.append(DQTList[i])
    if cSOFO > 0:
        for i in range(cSOFO):
            headList.append(SOFOList[i])
    if cSOF2 > 0:
        for i in range(cSOF2):
            headList.append(SOF2List[i])
    for i in range(cDHT):
        headList.append(DHTList[i])
    for i in range(cSOS):
        headList.append(SOSList[i])
    headList.append(EOFList[0])
    print(headList)
    
    
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
    info = data[SOFList[0]:DQTList[0]+5]
    

    #Load the info to write to the file
    s = 0 #counter for string
    for h in range(1, cHead):
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
        
        if (h)< cHead:
            info = info + data[headList[h]: headList[h]+5]
            cnt = headList[h]+5
        else:
            info = info + data[EOFList[0]:EOFList[0]+2]
        
  


    #Set the name for the file being written
    fName = "encoded_"+fileName
    print(fName)

    #Open the file for writing
    file = open(fName,'ba+')
    file.write(info)
    file.close()

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


#----------------
#Run the Program
#----------------
print("Welcome to the LED Zeplin Steganography Program")
#This next line needs to include the type of file to use for the stego tool
print(
    "This program will allow you to encrypt an image with a message\n"\
    + "or decrypt a message.\n")
mainMenu()
