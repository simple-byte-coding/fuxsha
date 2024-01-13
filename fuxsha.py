import hashlib
from urllib.request import urlopen
import threading


def sha1():
    input_hash = input("Sha1 input_hash~>: ").lower()
    passlist_input = input("url to raw wordlist~>: ")
    passlist = str(urlopen(passlist_input).read(), 'utf-8')

    for word in passlist.split('\n'):
        hash_attempt = hashlib.sha1(bytes(word, 'utf-8')).hexdigest()
        if hash_attempt == input_hash:
            print(f"Password found! -> {str(word)}")
            quit()
        else:
            continue
    print("Password not found!")


def sha256():
    input_hash = input("sha256 hash~>: ").lower()
    passlist_input = input("url to raw wordlist~>: ")
    passlist = str(urlopen(passlist_input).read(), 'utf-8')

    for word in passlist.split('\n'):
        hash_attempt = hashlib.sha256(bytes(word, 'utf-8')).hexdigest()
        if hash_attempt == input_hash:
            print(f"Password found! -> {str(word)}")
            quit()
        else:
            continue
    print("Password not found!")


def sha512():
    input_hash = input("sha512 hash~>: ").lower()
    passlist_input = input("url to raw wordlist~>: ")
    passlist = str(urlopen(passlist_input).read(), 'utf-8')

    for word in passlist.split('\n'):
        hash_attempt = hashlib.sha512(bytes(word, 'utf-8')).hexdigest()
        if hash_attempt == input_hash:
            print(f"Password found! -> {str(word)}")
            quit()
        else:
            continue
    print("Password not found!")


def main():
    print("Supported hashes: sha1, sha256, sha512")
    hash_type = input("What type of hash do you wish to crack~>: ")

    if hash_type == "sha1":
        t1 = threading.Thread(target=sha1)
        t1.start()
    elif hash_type == "sha256":
        t1 = threading.Thread(target=sha256)
        t1.start()
    elif hash_type == "sha512":
        t1 = threading.Thread(target=sha512)
        t1.start()
    else:
        print("Please choose a valid option!")
        quit()


if __name__ == "__main__":
    main()
