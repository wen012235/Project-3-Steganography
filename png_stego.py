import cv2  # pip install opencv-python
import math

# Global Variables
fileName = "shrek.png"
stringmessage = "Ogres are like onions."
encoded_filename = "encoded_shrek.png"

def main():

    global fileName

    # ENCODE
    encryptPNG()

    # DECODE
    decryptPNG()


def encryptPNG():
    
    global fileName, stringmessage
    
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


def decryptPNG():
  
    global fileName

    ###################
    #### IMPORTANT ####
    ###################
    # Remove if adding code to master branch code
    # REMOVE START
    global encoded_filename
    fileName = encoded_filename
    # REMOVE END

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

main()