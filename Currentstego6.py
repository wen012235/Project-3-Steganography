import sys
import os
import hashlib
import binascii
import re
from PIL import Image
import glob
import piexif
import base64

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
cwd = os.getcwd()
print(cwd)
fileName = ""
hiddenMessage = ""
new_file = ""
pictsindir = []



#Main Menu and Directions for the program
def mainMenu():
    global fileName, new_file
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
        print("Type/Paste your content. Press Enter to get a new line. \n"
              "Press Enter again when you are finished.")
        message = []
        while True:
            i = input()
            if i == '':
                break
            message = message + [i]
            hiddenMessage = message
        pictsearch()
        while True:
            try:
                pictchoose = int(input("choose the file to encode:\n"))
                openit = Image.open(pictsindir[pictchoose - 1])
                fileName = pictsindir[pictchoose - 1]
                id(fileName)
                #openit.show()
                break
            except (IndexError, ValueError):
                print("Please enter a number 1 - " + str(len(pictsindir)))
        img = Image.open(fileName)
        if img.format == 'JPEG':
            openFile()
            loadDataJPG()
            asc2bin(hiddenMessage)
            bytesNeeded()
            fit()
        elif img.format == 'PNG':
            print("nice")

        
    elif choice == 2:
        print("Decrypt a message stored in an image.")
        # this is where we will call the decryption function
        decrypt()
        
    elif choice == 3:
        sys.exit("\n Thank you for using our Steganography Program!\n")
    else:
        print("\n Invalid entry.  Please enter a number from 1-3\n")
        mainMenu()
        
#----------------
#LSB Steg - coded by Bobbie
#----------------
  
#ascii to binary 
def asc2bin(hMessage):
    global messageList
    global hiddenMessage
    global ln
    letter = ''
    msg = ""
    
     
    #This flags how many characters there are in the message for the decrytion process

    for item in hMessage:
        msg = ''.join([str(item)])
    
    flag = len(msg)
    #print (flag)
    bflag = bin(flag)
   
    for x in range(2, len(bflag)):
        letter = letter + bflag[x]
    messageList.append(letter)
    
    
    
    for l in msg:
        letter =' '.join(format(i, 'b') for i in bytearray(l, encoding='utf-8'))
        messageList.append(letter)
    ln = len(messageList)
    print("Characters: ",ln)

#bytes needed to hide the image 
def bytesNeeded():
    global messageList
    
    chrInMsg = messageList
    bn = len(chrInMsg)*8
    print("You need " + str(bn) + " bytes to hide the data.")
    #print(messageList)
    
#checks to see if secret message will fit
def fit():
    global ln
    global tLet

    if ln < tLet:
        encryptJPG()
    else:
        jpegexifhide()
        fileinfo()
        


# show image file for encryption 
def showFile(file):   
    iFile = Image.open(file)        
    iFile.show()
    return file

# open image file for encryption 
def openFile():
    global data
    global fileName
    file = fileName
    
    imgFile = open(file, 'rb')
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
   
    
    tmpStr ='' # Holds the secret message string
    #print(messageList)
    
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
            item ='0'+ item
            
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
    new_file = "embedded_LSB_"+fileName
    print(new_file)

    #Open the file for writing
    file = open(new_file,'ba+')
    file.write(info)
    file.close()
    
    
    
    md5_hash = hashlib.md5()
    file = open(new_file, "rb")
    content = file.read()
    md5_hash.update(content)
    newmd5 = md5_hash.hexdigest()
    
    print("")
    print("------------------------------------------------------------------------")
    print("File Information")
    print("------------------------------------------------------------------------")

    print("New file name: " + str(new_file))
    print("New file size: " + str(os.path.getsize(new_file) // 1000) + " KB")
    print("New file hash: " + str(newmd5))
    print("\n")
    
    md5_hash = hashlib.md5()
    file = open(fileName, "rb")
    content = file.read()
    md5_hash.update(content)
    originalmd5 = md5_hash.hexdigest()

    print("Original file name: " + str(fileName))
    print("Original file size: " + str(os.path.getsize(fileName) // 1000) + " KB")
    print("Original file hash: " + str(originalmd5)) 
    
    print("------------------------------------------------------------------------")
    print("")
    print("------------------------------------------------------------------------")
    
    mainMenu()

#decryption algorithm 
def decrypt():
    #Read in the file to decrypt
    file = input("Enter the name of the file you want to get the message from:\n")
    
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
        
    print("------------------------------------------------------------------------")
    print("------------------------------------------------------------------------")
    print("Hidden Message: "+ word) 
    print("------------------------------------------------------------------------")
    print("------------------------------------------------------------------------")
    print("")
    
    mainMenu()

               

#----------------
#Exif Steg - coded by Nathan
#----------------
def jpegexifhide():
    global filename, new_file
    code = "vizsla"
    img = Image.open(filename)
    exifdata = img.getexif()
    #print(exifdata)

    
    #what = img.info.get('icc_profile', '')
    #print(what)
    #print(img.mode)
    src = hiddenmessage
    xorWord = lambda ss, cc: ''.join(chr(ord(s) ^ ord(c)) for s, c in zip(ss, cc * 100))
    encrypt = xorWord(src, code)
    new = encrypt.encode('ascii')
    encoded = base64.b64encode(new)
    b64message = encoded.decode('ascii')
    exif_dict = piexif.load(filename)
    exif_dict["0th"][piexif.ImageIFD.HostComputer] = b64message
    exif_bytes = piexif.dump(exif_dict)
    piexif.insert(exif_bytes, filename, new_file="embedded_exif:" + filename)
    new_file = "embedded_exif_" + filename
    img.save(new_file, exif=exif_bytes)
    newww = Image.open(new_file)
    newexif = newww.getexif()
    print(newexif)


def jpegexifreveal():
    img = Image.open(file)
    xorWord = lambda ss, cc: ''.join(chr(ord(s) ^ ord(c)) for s, c in zip(ss, cc * 100))
    exif_dict = piexif.load(img.info.get("exif"))
    encoded_message = exif_dict["0th"][piexif.ImageIFD.HostComputer]
    img.close()
    returnencoded = base64.b64decode(encoded_message)
    returnmessage = returnencoded.decode('ascii')
    decrypt = xorWord(returnmessage, code)
    print(decrypt)
def dhexifhide():
    img = Image.open(input_image_file)
    #print(Image.format())
    src = secretmessage
    xorWord = lambda ss, cc: ''.join(chr(ord(s) ^ ord(c)) for s, c in zip(ss, cc * 100))
    encrypt = xorWord(src, code)
    new = encrypt.encode('ascii')
    encoded = base64.b64encode(new)
    b64message = encoded.decode('ascii')
    img = Image.open(urlopen("https://live.staticflickr.com/65535/50142723776_c3ce0b01f4_o.jpg"))

    img.thumbnail([256,512], Image.ANTIALIAS)
    newthumbnail = img.save("html.jpeg")
    img = Image.open(input_image_file)
    exif_dict = piexif.load(input_image_file)
    del exif_dict["thumbnail"]
    exif_bytes = piexif.dump(exif_dict)
    o = io.BytesIO()
    thumb_im = Image.open("html.jpeg")
    thumb_im.thumbnail((512, 512), Image.ANTIALIAS)
    thumb_im.save(o, "jpeg")
    thumbnail = o.getvalue()
    zeroth_ifd = {piexif.ImageIFD.HostComputer: b64message
                  }
    gps_ifd = {piexif.GPSIFD.GPSLatitudeRef: "N",
               piexif.GPSIFD.GPSLatitude: [(43, 1), (4, 1), (11784, 1000)],
               piexif.GPSIFD.GPSLongitudeRef: "W",
               piexif.GPSIFD.GPSLongitude: [(89, 1), (24, 1), (456984, 10000)],
               piexif.GPSIFD.GPSAltitudeRef: (0),
               piexif.GPSIFD.GPSAltitude: (263605, 1000)
               }
    exif_dict = {"0th":zeroth_ifd , "Exif": {}, "GPS": gps_ifd, "1st": {}, "thumbnail":thumbnail}
    exif_bytes = piexif.dump(exif_dict)
    piexif.insert(exif_bytes, filename, new_file="embedded_exif:" + filename)
    new_file = "embedded_exif_" + filename
    img.save(new_file, exif=exif_bytes)
    nf = Image.open(new_file, r)
    print("New file name: " + new_file + "\n" 
          "New file size: " + nf.size() + "\n"
          "New file hash: " + hashlib.md5(new_file))

def pictsearch():
    for file in glob.glob('*.jpg'):
        pictsindir.append(file)
    for file in glob.glob('*.png'):
        pictsindir.append(file)
        #print(pictsindir)
        pictsindir.sort()
    for i in range(len(pictsindir)):
        print(str(i+1) + ": " + pictsindir[i])

def fileinfo():
    global filename, new_file
    md5_hash = hashlib.md5()
    a_file = open(new_file, "rb")
    content = a_file.read()
    md5_hash.update(content)
    newmd5 = md5_hash.hexdigest()

    print("New file name: " + str(new_file))
    print("New file size: " + str(os.path.getsize(new_file) // 1000) + " KB")
    print("New file hash: " + str(newmd5))
    print("\n")
    md5_hash = hashlib.md5()
    a_file = open(filename, "rb")
    content = a_file.read()
    md5_hash.update(content)
    originalmd5 = md5_hash.hexdigest()

    print("Original file name: " + str(filename))
    print("Original file size: " + str(os.path.getsize(filename) // 1000) + " KB")
    print("Original file hash: " + str(originalmd5))

#----------------
#PNG Steg - coded by Preston
#----------------


#----------------
#Run the Program
#----------------
print("Welcome to the LED Zeplin Steganography Program")
#This next line needs to include the type of file to use for the stego tool
print(
    "This program will allow you to encrypt an image with a message\n"\
    + "or decrypt a message.\n")
mainMenu()
