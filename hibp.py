"""Have I Been Pwned breach lookup using the k-Anonymity range API.

The password never leaves this machine. Only the first 5 characters of its
SHA-1 hash are sent; HIBP returns every breached suffix sharing that
prefix, and the match is done locally.
"""

import hashlib
from getpass import getpass

import requests

API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
REQUEST_TIMEOUT = 5

# HIBP pads short responses with random decoy hashes when this header is
# set, so an observer can't infer anything from the response size. Without
# it, response length leaks roughly how many breached passwords share your
# prefix - a small but free-to-close side channel.
HEADERS = {
    "Add-Padding": "true",
    "User-Agent": "password-hygiene-checker",
}


def check_pwned_password(password, verbose=False):
    """Return breach count (int), 0 if not found, or None if the check failed.

    None and 0 mean very different things - "we could not check" versus
    "checked, and it is clean" - so callers must not conflate them.
    """
    hash_digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = hash_digest[:5], hash_digest[5:]

    try:
        response = requests.get(
            API_URL.format(prefix=prefix), timeout=REQUEST_TIMEOUT, headers=HEADERS
        )
    except requests.RequestException as e:
        if verbose:
            print(f"Could not reach HIBP: {e}")
        return None

    if response.status_code != 200:
        if verbose:
            print(f"Error fetching data: HTTP {response.status_code}")
        return None

    for line in response.text.splitlines():
        # Padding entries have a count of 0 and are meant to be ignored;
        # they fall out naturally since a real hit never has count 0.
        parts = line.strip().split(":")
        if len(parts) != 2:
            continue  # malformed line - skip it rather than crash the run
        candidate_suffix, count_str = parts
        if candidate_suffix != suffix:
            continue
        try:
            count = int(count_str)
        except ValueError:
            if verbose:
                print(f"Malformed count from HIBP for matching hash: {count_str!r}")
            return None
        if verbose:
            print(f"Password found! It has been seen {count:,} times.")
        return count

    if verbose:
        print("Password not found in any known breach.")
    return 0


if __name__ == "__main__":
    check_pwned_password(getpass("Please enter the password : "), verbose=True)
