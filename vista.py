from PIL import Image
import os.path
from os import path
import math
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Hash import SHA256
from Crypto import Random
import base64
from colorama import init
from termcolor import cprint
from pyfiglet import figlet_format
from rich import print
from rich.console import Console
from rich.table import Table
import os
import getpass
import sys
import numpy as np
import zlib

DEBUG = False
console = Console()
headerText = "M6nMjy5THr2J"

def encrypt_chacha20(key, plaintext):
    nonce = Random.get_random_bytes(12)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return base64.b64encode(nonce + tag + ciphertext).decode()

def decrypt_chacha20(key, encrypted_data):
    decoded = base64.b64decode(encrypted_data.encode())
    nonce, tag, ciphertext = decoded[:12], decoded[12:28], decoded[28:]
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def encrypt_aes(key, source):
    key = SHA256.new(key).digest()
    IV = Random.new().read(AES.block_size)
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size
    source += bytes([padding]) * padding
    return base64.b64encode(IV + encryptor.encrypt(source)).decode()

def decrypt_aes(key, source):
    source = base64.b64decode(source.encode())
    key = SHA256.new(key).digest()
    IV = source[:AES.block_size]
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])
    padding = data[-1]
    return data[:-padding]

def multi_layer_encrypt(password, message):
    chacha_key = SHA256.new(password.encode()).digest()[:32]
    aes_key = SHA256.new(password.encode()).digest()
    first_layer = encrypt_chacha20(chacha_key, message.encode())
    second_layer = encrypt_aes(aes_key, first_layer.encode())
    return second_layer

def multi_layer_decrypt(password, encrypted_data):
    chacha_key = SHA256.new(password.encode()).digest()[:32]
    aes_key = SHA256.new(password.encode()).digest()
    first_layer = decrypt_aes(aes_key, encrypted_data).decode()
    original_message = decrypt_chacha20(chacha_key, first_layer).decode()
    return original_message

# Existing functions remain unchanged...

def compress_and_encrypt(message, password):
    compressed = zlib.compress(message.encode())  # Compress the message
    compressed_b64 = base64.b64encode(compressed).decode()  # Convert to Base64 string
    return multi_layer_encrypt(password, compressed_b64)  # Encrypt the Base64 string

def decompress_and_decrypt(cipher, password):
    decrypted = multi_layer_decrypt(password, cipher)  # Decrypt first
    decompressed = zlib.decompress(base64.b64decode(decrypted))  # Decode Base64 and decompress
    return decompressed.decode()  # Convert bytes back to string


# Convert image to RGB if needed
def convertToRGB(img):
    try:
        rgba_image = img
        rgba_image.load()
        background = Image.new("RGB", rgba_image.size, (255, 255, 255))
        background.paste(rgba_image, mask=rgba_image.split()[3])
        print("[yellow]Converted image to RGB [/yellow]")
        return background
    except Exception as e:
        print("[red]Couldn't convert image to RGB [/red]- %s" % e)

# Get pixel count in image
def getPixelCount(img):
    width, height = Image.open(img).size
    return width * height

# Calculate pattern size for encoding
def calculate_pattern_size(message_size, image_size):
    return math.ceil(message_size / image_size)

# Error Correction Codes (ECC) parameters
ECC_BLOCK_SIZE = 8  # Number of bits per ECC block
ECC_HAMMING_DISTANCE = 3  # Minimum Hamming distance for error correction

# Encode image with message and ECC
def encodeImage(image, message, filename):
    with console.status("[green]Encoding image..") as status:
        try:
            width, height = image.size
            pix = image.getdata()
            pattern_size = calculate_pattern_size(len(message), width * height)

            # Error Correction Codes (ECC) initialization
            ecc_blocks = math.ceil((len(message) * 8) / ECC_BLOCK_SIZE)
            ecc_encoded_message = []

            if ecc_blocks > width * height:
                raise ValueError("Not enough pixels available for encoding ECC blocks.")

            current_pixel = 0
            tmp = 0
            x = 0
            y = 0
            for ch in message:
                binary_value = format(ord(ch), '08b')

                p1 = pix[current_pixel]
                p2 = pix[current_pixel + int(pattern_size/2)]
                p3 = pix[current_pixel + int(pattern_size/4)]
                three_pixels = [val for val in p1 + p2 + p3]

                # Apply Error Correction Codes (ECC)
                ecc_block_indices = np.random.choice(range(len(three_pixels)), size=min(ecc_blocks, len(three_pixels)), replace=False)
                for ecc_block_index in ecc_block_indices:
                    ecc_encoded_message.append((ecc_block_index, three_pixels[ecc_block_index]))
                    three_pixels[ecc_block_index] ^= 1  # Flip one bit for ECC

                for i in range(0, pattern_size):
                    for j in range(0, 8):
                        current_bit = binary_value[i * 8 + j]
                        if current_bit == '0':
                            if three_pixels[j] % 2 != 0:
                                three_pixels[j] = three_pixels[j] - 1 if three_pixels[j] == 255 else three_pixels[j] + 1
                        elif current_bit == '1':
                            if three_pixels[j] % 2 == 0:
                                three_pixels[j] = three_pixels[j] - 1 if three_pixels[j] == 255 else three_pixels[j] + 1

                current_pixel += 3
                tmp += 1
                if tmp == len(message):
                    if three_pixels[-1] % 2 == 0:
                        three_pixels[-1] = three_pixels[-1] - 1 if three_pixels[-1] == 255 else three_pixels[-1] + 1
                else:
                    if three_pixels[-1] % 2 != 0:
                        three_pixels[-1] = three_pixels[-1] - 1 if three_pixels[-1] == 255 else three_pixels[-1] + 1

                three_pixels = tuple(three_pixels)

                st = 0
                end = 3
                for i in range(0, 3):
                    image.putpixel((x, y), three_pixels[st:end])
                    st += 3
                    end += 3
                    if (x == width - 1):
                        x = 0
                        y += 1
                    else:
                        x += 1

            ecc_encoded_message.extend([(0, 0)] * (ecc_blocks - len(ecc_encoded_message)))
            ecc_encoded_message = [f'{block_index},{block_value}' for block_index, block_value in ecc_encoded_message]

            encoded_filename = filename.split('.')[0] + "_.png"
            image.save(encoded_filename)
            print("\n")
            print("[yellow]Original File: [u]%s[/u][/yellow]" % filename)
            print("[green]Image encoded and saved as [u][bold]%s[/green][/u][/bold]" % encoded_filename)

            return encoded_filename, ecc_encoded_message

        except Exception as e:
            print("[red]An error occurred - [/red]%s" % e)
            sys.exit(0)

# Decode image and retrieve message
def decodeImage(image):
    with console.status("[green]Decoding image..") as status:
        try:
            pix = image.getdata()
            current_pixel = 0
            decoded = ""
            pattern_size = 1
            while True:
                binary_value = ""
                p1 = pix[current_pixel]
                p2 = pix[current_pixel + 1]
                p3 = pix[current_pixel + 2]
                three_pixels = [val for val in p1 + p2 + p3]

                for i in range(0, pattern_size * 8):
                    if three_pixels[i] % 2 == 0:
                        binary_value += "0"
                    elif three_pixels[i] % 2 != 0:
                        binary_value += "1"

                binary_value.strip()
                ascii_value = int(binary_value, 2)
                decoded += chr(ascii_value)
                current_pixel += 3 * pattern_size

                if three_pixels[-1] % 2 != 0:
                    break

            return decoded
        except Exception as e:
            print("[red]An error occurred - [/red]%s" % e)
            sys.exit()

# Credits
def print_credits():
    table = Table(show_header=True)
    table.add_column("Creator", style="yellow")
    table.add_column("Contact", style="yellow")
    table.add_row("Vandit Barola", "technovandit18@gmail.com ")
    console.print(table)

# Main function
import os
import sys
import getpass
from PIL import Image

headerText = "[HIDDEN_DATA]"

def main():
    print("[cyan]Choose one: [/cyan]")
    op = int(input("1. Encode\n2. Decode\n>>"))

    if op == 1:
        print("[cyan]Image path (with extension): [/cyan]")
        img = input(">>")
        if not os.path.exists(img):
            raise Exception("Image not found!")

        img_extension = os.path.splitext(img)[1].lower()
        if img_extension != '.png':
            new_img_path = os.path.splitext(img)[0] + '.png'
            Image.open(img).save(new_img_path, 'PNG')
            img = new_img_path
            print("[yellow]Image converted to PNG format.[/yellow]")

        # Read the message from text.txt
        text_file = "t.txt"
        if not os.path.exists(text_file):
            raise Exception(f"File '{text_file}' not found!")

        with open(text_file, "r", encoding="utf-8") as file:
            message = file.read().strip()

        message = headerText + message
        if (len(message) * 3 > getPixelCount(img)):
            raise Exception("Given message is too long to be encoded in the image.")

        password = ""
        while True:
            print("[cyan]Password to encrypt (leave empty if you want no password): [/cyan]")
            password = getpass.getpass(">>")
            if password == "":
                break
            print("[cyan]Re-enter Password: [/cyan]")
            confirm_password = getpass.getpass(">>")
            if password != confirm_password:
                print("[red]Passwords don't match. Try again. [/red]")
            else:
                break

        cipher = message if password == "" else compress_and_encrypt(message, password)
        cipher = headerText + cipher

        image = Image.open(img)
        if image.mode != 'RGB':
            image = convertToRGB(image)
        newimg = image.copy()
        encoded_filename, ecc_encoded_message = encodeImage(image=newimg, message=cipher, filename=img)

    elif op == 2:
        print("[cyan]Image path (with extension): [/cyan]")
        img = input(">>")
        if not os.path.exists(img):
            raise Exception("Image not found!")

        print("[cyan]Enter password (leave empty if no password): [/cyan]")
        password = getpass.getpass(">>")

        image = Image.open(img)
        cipher = decodeImage(image)

        header = cipher[:len(headerText)]
        if header.strip() != headerText:
            print("[red]Invalid data![/red]")
            sys.exit(0)

        decrypted = ""
        if password != "":
            cipher = cipher[len(headerText):]
            try:
                decrypted = decompress_and_decrypt(cipher, password)
            except Exception:
                print("[red]Wrong password![/red]")
                sys.exit(0)
        else:
            decrypted = cipher

        decrypted = decrypted[len(headerText):]

        print("[green]Decoded Text: \n[bold]%s[/bold][/green]" % decrypted)



if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear')
    cprint(figlet_format('HIDE-X', font='starwars'), 'yellow', attrs=['bold'])
    print_credits()
    print("[bold]IMGHIDE[/bold] allows you to hide texts inside an image. You can also protect these texts with a password using AES-256.")
    main()
