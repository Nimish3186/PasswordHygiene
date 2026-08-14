import hashlib
import requests
from getpass import getpass


def check_pwned_password(password):

    hash_object = hashlib.sha1(password.encode())
    hash_digest = hash_object.hexdigest().upper()  # 40 char length

    hashed_prefix = hash_digest[:5]
    hashed_suffix = hash_digest[5:]
    try:
        url = f"https://api.pwnedpasswords.com/range/{hashed_prefix}"
        req = requests.get(url, timeout=5)

        if req.status_code != 200:
            print(f"Error fetching data: {req.status_code}")
            return None

        for i in req.text.splitlines():
            splitted = i.split(":")
            if splitted[0] == hashed_suffix:
                count = int(splitted[1])
                print(f"Password found! It has been seen {count} times.")
                return count

        print("Password not found in any known breach.")
        return 0

    except requests.RequestException as e:
        print(f"Could not reach HIBP: {e}")
        return None


if __name__ == "__main__":
    user_password = getpass("Please enter the password : ")
    check_pwned_password(user_password)