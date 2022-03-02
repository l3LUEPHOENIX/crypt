import base64
import argparse
import os
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Initialize the parser
parser = argparse.ArgumentParser(
    description = """
    Encrypt or decrypt a file or files with a password from the commandline.
    Example: crypt.py -a='encrypt' -f='picture.png' -o='secret.birb'
    Couple Notes on Usage:
        1.) REMEMBER YOUR PASSWORD OR YOUR STUFF IS GONE FOREVER!
        2.) Use caution when using the destroy function
        3.) Do not use -f or -o when utilizing -r.
        4.) Currently, if using the recursive function, crypt.py must be in the same directory as the files you wish to act on.
        5.) Want to encrypt a folder? Compress it (send it to zipped) then pass it as an idividual file.
    """
)

# Add the parameters positional/optional
parser.add_argument('-f','--file', help="The target file", type=str)
parser.add_argument('-o','--outfile', help="Name of the new file", type=str, default='secret.birb')
parser.add_argument('-a','--action', help="Encryption or Decryption", choices=['encrypt', 'decrypt'], required=True, type=str)
parser.add_argument('-r','--recurse', action='store_true', help="Perform action on all files in the current working directory. This will use the same password for every file.")
parser.add_argument('-d','--destroy', action='store_true', help="After the action is performed, destroy the original file.")

# Parse the arguments
args = parser.parse_args()

# Password
password = getpass().encode()

# Cryptography
salt = b'\xd3\x9aNV\x0b,\x0f\x81?\x08\xdevq\xc2\x93x'
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=390000,
)

key = base64.urlsafe_b64encode(kdf.derive(password))
f = Fernet(key)

# Functions
def dcrypt(file, new_name):
    with open(new_name, "wb") as n_file:
        n_file.write(base64.b64decode(f.decrypt(file))) 

def crypt(file, new_name):
    enc_file = base64.b64encode(file)
    item = f.encrypt(enc_file)
    with open(new_name, "wb") as s_file:
        s_file.write(item)

def destroy(thing):
    if os.path.exists(thing):
        os.remove(thing)

def recurse():
    if args.recurse == True:
        for file in os.listdir():
            if file != 'crypt.py' and os.path.isfile(file):
                print(file)
                thing = open(file, "rb").read()
                if args.action == 'encrypt':
                    new_name = file + '.birb'
                    crypt(thing, new_name)
                elif args.action == 'decrypt':
                    if file.endswith('.birb'):
                        new_name = file[:-5] 
                        dcrypt(thing, new_name)
                else:
                    print('Something went wrong!')
                if args.destroy == True:
                    destroy(file)

# Run
print("STARTING PROCESS")
if args.recurse == True:
    recurse()
else:
    print(args.file)
    file = open(args.file, "rb").read()
    new_name = args.outfile
    if args.action == 'encrypt':
        crypt(file, new_name)
    elif args.action == 'decrypt':
        dcrypt(file, new_name)
    else:
        print('Something went wrong!')
    if args.destroy == True:
        destroy(args.file)
