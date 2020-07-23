import piexif
import os
from PIL import Image
import base64





os.chdir('/Users/nathan/Documents/GitHub/project-3-steganography/')
cwd=os.getcwd()
print("hello")
print(cwd)
secretmessage='''hi bobbie!!'''

#input_image_file=filename
#img = input_image_file

def exifhide():
    code = "vizsla"
    img = Image.open(filename)
    what = img.info.get('icc_profile', '')
    exifdata = img.getexif()
    print(exifdata)
    print(what)
    print(img.mode)
    src = hiddenmessage
    xorWord = lambda ss, cc: ''.join(chr(ord(s) ^ ord(c)) for s, c in zip(ss, cc * 100))
    encrypt = xorWord(src, code)
    new = encrypt.encode('ascii')
    encoded = base64.b64encode(new)
    b64message = encoded.decode('ascii')
    exif_dict = piexif.load(img)
    exif_dict["0th"][piexif.ImageIFD.HostComputer] = b64message
    exif_bytes = piexif.dump(exif_dict)
    piexif.insert(exif_bytes, input_image_file)

#exifhide()

def exifreveal(file):
    img = Image.open(file)
    xorWord = lambda ss, cc: ''.join(chr(ord(s) ^ ord(c)) for s, c in zip(ss, cc * 100))
    exif_dict = piexif.load(img.info.get("exif"))
    encoded_message = exif_dict["0th"][piexif.ImageIFD.HostComputer]
    img.close()
    returnencoded = base64.b64decode(encoded_message)
    returnmessage = returnencoded.decode('ascii')
    decrypt = xorWord(returnmessage, code)
    print(decrypt)

#exifreveal()