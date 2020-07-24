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
cHead = "" # Number of items in upper headList
headList = [] # Holds stopping points for message in upper part of image



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
        loadDataJPG()
        asc2bin()
        bytesNeeded()
        fit()
        encryptJPG() 
        
    elif choice == 2:
        print("Decrypt a message stored in an image.")
        # this is where we will call the decryption function
        decrypt()
        
    elif choice == 3:
        sys.exit("\n Thank you for using our Steganography Program!\n")
    else:
        print("\n Invalid entry.  Please enter a number from 1-3\n")
        mainMenu()

def resetVars():
    #resets all variables
    global data
    data = ""
    global fileName
    fileName = ""
    global messageList
    messageList = []
    global ln
    ln = 0
    global letListQty
    letListQty = []
    global tLet
    tLet = 0
    global cHead
    cHead = ""
    global headList
    headList= []

   
#ascii to binary
def asc2bin():
    global messageList
    global ln
    letter = ''
    
    hiddenMessage = input("Please enter the message you would like to hide in the image.\n")

    #This flags how many characters there are in the message for the decrytion process
    flag = len(hiddenMessage)
    #print (flag)
    bflag = bin(flag)
    
    for x in range(2, len(bflag)):
        letter = letter + bflag[x]
    messageList.append(letter)

    for l in hiddenMessage:
        letter =' '.join(format(i, 'b') for i in bytearray(l, encoding='utf-8'))
        messageList.append(letter)
    ln = len(messageList)
    print("Characters: ",ln)

#bytes needed to hide the image
def bytesNeeded():
    global messageList
    
    chrInMsg = messageList
    bn = len(chrInMsg)*8
    #print("You need " + str(bn) + " bytes to hide the data.")
    #print(messageList)
    
#checks to see if secret message will fit
def fit():
    global ln
    global tLet

    if ln < tLet:
        print("Congratulations!  Your message will fit.")
    else:
        print("Your secret message will not fit in this image.")
        resetVars()
        mainMenu()


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

    #print(SOFList)
    #print(SOFOList)
    #print(SOF2List)
    #print(DHTList)
    #print(DQTList)
    #print(DRIList)
    #print(SOSList)
    #print(COMList)
    #print(EOFList)
    
    cDQT = len(DQTList) # Number of DQT headers 
    cSOFO = len(SOFOList) # Number SOFO headers
    cSOF2 = len(SOF2List) # Number SOF2 headers
    cDHT = len(DHTList) # Number DHT headers
    cSOS = len(SOSList) # Number SOS headers
    cCOM = len(COMList) # Number COM headers

    #Lets the end user know there might be distortion to the image returned.
    if cSOFO > 0:
        print("The returned image may be distorted.")
    

    #Fill the list with stopping points
    headList.append(SOFList[0])
    for i in range(cDQT):
        headList.append(DQTList[i])
    for i in range(cSOFO):
        headList.append(SOFOList[i])
    for i in range(cSOF2):
        headList.append(SOF2List[i])
    headList.append(EOFList[0])
    headList.sort()
    #print(headList)


    #calculate if space to hold message
 
    cnt = len(headList)
    for x in range(1,cnt-2):
        aBytes = headList[x+1] - headList[x] - 6
        letQty = int(aBytes / 8)
        letListQty.append(letQty)

    for item in letListQty:
        tLet = tLet + item
    #print(tLet)
    
    
#encryption algorithm for JPG
def encryptJPG():
    global fileName
    global data
    global ln
    global messageList
    global letListQty
    global tLet
    global headList
   
    
    tmpStr = "" # Holds the secret message string

    
    #writes the entire message to a string
    for item in messageList:
        if len(item)==3:
            item = '00000'+ item
            
        if len(item)==4:
            item = '0000'+ item

        if len(item)==5:
            item = '000'+ item
            
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
        
        if (h)< cHead-1:
            info = info + data[headList[h]: headList[h]+5]
            cnt = headList[h]+5
        else:
            info = info + data[headList[h]:headList[h]+2]      
                    
        

    #Set the name for the file being written
    fName = "encoded_"+fileName
    print(fName)

    #Open the file for writing
    file = open(fName,'ba+')
    file.write(info)
    file.close()

#decryption algorithm
def decrypt():
    #Read in the file to decrypt
    file = input("Enter the name of the file you want to use to hide a message in:\n")
    
    #Checks to see that the file exists
    while True:
        try:
            imgFile = open(file, 'rb')
            break
        except IOError:
            print('\nThere is no file named ', file)
            file = input("Enter the name of the file you want to use to hide a message in: \n")

    data = imgFile.read()
    imgFile.close()

    #Identifies the start and stop points for retrieving data
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

    #print(SOFList)
    #print(SOFOList)
    #print(SOF2List)
    #print(DHTList)
    #print(DQTList)
    #print(DRIList)
    #print(SOSList)
    #print(COMList)
    #print(EOFList)
    
    cDQT = len(DQTList) # Number of DQT headers 
    cSOFO = len(SOFOList) # Number SOFO headers
    cSOF2 = len(SOF2List) # Number SOF2 headers
    cDHT = len(DHTList) # Number DHT headers
    cSOS = len(SOSList) # Number SOS headers
    cCOM = len(COMList) # Number COM headers

    #Fill the list with stopping points
    headList = []
    for i in range(cDQT):
        headList.append(DQTList[i])
    for i in range(cSOFO):
        headList.append(SOFOList[i])
    for i in range(cSOF2):
        headList.append(SOF2List[i])
    headList.sort()
    #print(headList)

    # find how long the hidden message is
    msgL = []
    num = 0
    sNum = ""
    for x in range (headList[0]+5, headList[0]+13):
        msgL.append(data[x])

    for item in msgL:
        num = item % 2
        sNum = sNum + str(num)
    num = sNum.encode('utf-8')
    num = int(num, 2)

    # find where to extract the message from
    cnt = len(headList)
    letLQ = []
    tL=0
    msg = ""
    mL = []
    lL = []
    hTot = 0
    b = num*8

    for x in range(cnt-1):
        aBytes = headList[x+1] - headList[x] - 6
        letQ = int(aBytes/8)
        letQ = letQ*8
        hTot = hTot + letQ
        letLQ.append(letQ)

    cletLQ = len(letLQ)
    word = ''

    start = headList[0]+13   
        
    for a in range(cletLQ):
        if b < letLQ[a]:
            for y in range (start, headList[a+1]):
                mL.append(data[y])
            for i in range(b):
                tL = mL[i]%2
                msg = msg + str(tL)
            break
        else:
            for y in range(start, headList[a+1]):
                mL.append(data[y])
            for i in range(letLQ[a]):
                tL = mL[i]%2
                msg = msg + str(tL)
            start = headList[a+1]+5
            mL=[]

   
    for c in range(0,len(msg),8):
        lL.append(msg[c:(c+8)])
    
    clL = len(lL)
    for x in range (clL):
        word = word + chr(int(lL[x],2))
    print("Hidden Message: "+ word) 
            


    
    
        

    
    

    
    
               


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
