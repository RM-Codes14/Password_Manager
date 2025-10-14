# Password_Manager
Password Manager using MasterKey


import os
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import  PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import base64


class Password_Manager:
    def __init__(self , salt_file = "salt_key"):
        self.salt_file = salt_file
        self.salt = self._load_or_create_salt()
        self.key = self._generate_key()
        self.fernet = Fernet(self.key)


    def _load_or_create_salt(self):
        if os.path.exists(self.salt_file):
            with open (self.salt_file , "rb") as f:
                return f.read()
        else:
            salt = os.urandom(16)
            with open (self.salt_file , "wb") as f:
                f.write(salt)
            return salt


    def _generate_key(self):
        password = getpass("Enter master password ").encode()
        kdf = PBKDF2HMAC (
            algorithm= hashes.SHA256(),
            length= 32,
            salt= self.salt,
            iterations= 390000 ,   
                    )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    def encrypt_password(self , plain_password):
        encrypted = self.fernet.encrypt(plain_password.encode())
        return encrypted
        
    def decrypt_password(self , encrypted_password):
        decrypted = self.fernet.decrypt(encrypted_password.decode())
        return decrypted
    
def main ():
        pm = Password_Manager()
        pwd = input("Enter Password to Encrypt ")
        enc = pm.encrypt_password(pwd)
        print("Encrypted: " , enc)
        
        dec = pm.decrypt_password(enc)
        print("Decrypted: " , dec)

if __name__ == "__main__":
    main()
