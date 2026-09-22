from core.banner import show_banner
from core.menu import show_menu, get_choice
from modules.jwt.decoder import decode_jwt, display_jwt
from modules.jwt.inspector import (
    inspect_decoded_jwt,
    display_claims,
)
from modules.flask_cookie.decoder import (
    decode_cookie_payload,
    display_cookie,
)
from modules.identify.identify import identify

from modules.hash_crack.cracker import crack_hash, display_result

def handle_identify():
    """Handle the Identify menu option."""
    print("\n[*] Identify module")
    print("-" * 50)

    try:
        value = input("Enter hash or token: ").strip()

        result = identify(value)

        print(f"\n[+] Type: {result['type']}")
        print(f"[*] Message: {result['message']}")

        matches = result["matches"]

        if matches:
            print("\n[+] Possible matches:")

            for match in matches:
                if isinstance(match, dict):
                    print(f"    Name: {match['name']}")
                    print(f"    Category: {match['category']}")
                    print(f"    Description: {match['description']}")

                    if match["ambiguous"]:
                        print("    [!] Ambiguous match")

                    print()
                else:
                    print(f"    - {match}")

        print("-" * 50)

    except KeyboardInterrupt:
        print("\n[!] Identify cancelled.")

def handle_hash_crack():
    """Handle dictionary-based hash cracking."""
    print("\n--- Decode Dead: Hash Crack ---")

    target = input("Enter target hash: ").strip()

    if not target:
        print("[!] Target hash cannot be empty.")
        return

    algorithm_input = input(
        "Enter algorithm(s) (e.g. md5, sha256, ntlm): "
    ).strip()

    if not algorithm_input:
        print("[!] Algorithm cannot be empty.")
        return

    # Support comma-separated algorithms.
    algorithms = [
        name.strip()
        for name in algorithm_input.split(",")
        if name.strip()
    ]

    custom_path = input(
        "Wordlist path (Enter for default rockyou.txt): "
    ).strip()

    try:
        result = crack_hash(
            target_hash=target,
            algorithms=algorithms,
            wordlist_path=custom_path or None,
        )

        display_result(result)

    except (ValueError, FileNotFoundError, PermissionError) as exc:
        print(f"[!] Error: {exc}")

    except KeyboardInterrupt:
        print("\n[!] Hash cracking cancelled.")

def handle_jwt_decode():
    """Decode JWT and inspect its claims."""
    print("\n--- Decode Dead: JWT Decode ---")
    token = input("Enter JWT: ").strip()

    if not token:
        print("[!] JWT cannot be empty.")
        return

    try:
        decoded = decode_jwt(token)
        display_jwt(decoded)

        inspection = inspect_decoded_jwt(decoded)
        display_claims(inspection)

    except (ValueError, TypeError) as exc:
        print(f"[!] Error: {exc}")

  
    
def handle_flask_decode():
    """Handle Flask session cookie decoding."""
    print("\n--- Decode Dead: Flask Cookie Decoder ---")

    cookie = input("Enter Flask session cookie: ").strip()

    if not cookie:
        print("[!] Cookie cannot be empty.")
        return

    try:
        decoded = decode_cookie_payload(cookie)
        display_cookie(decoded)

    except (ValueError, TypeError) as exc:
        print(f"[!] Error: {exc}")

def dispatch_choice(choice):
    """
    Route the user's chooice to the appropriate handler.

    Returns:
        False when the user chooses Exit.
        True
    """    

    handlers = {
        "1": handle_identify,
        "2": handle_hash_crack,
        "3": handle_jwt_decode,
        "4": handle_flask_decode,
    }

    if choice == "5":
        print("\n[*] Existing Decode Dead. Goodbye!")
        return False

    handler = handlers.get(choice)

    if handler is None:
        print("[!] Invalid choice. Please select 1-5.")
        return True

    handler()
    return True





def main():
    try:

        show_banner()

        while True:
            show_menu()
            choice = get_choice()

            should_continue = dispatch_choice(choice)

            if not should_continue:
                break
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user.")
        print("[*] Exiting Decode Dead. Goodbye!")        

    except EOFError:
        print("\n\n[!] Input stream closed.")
        print("[*] Exiting Decode Dead. Goodbye!")


            # if choice == "1":
            #     print("[#] Identify module - Coming Soon")

            # elif choice == "2":
            #     print("[#] Hash Crack module - Coming soon")    

            # elif choice =="3":
            #     print("[#] JWT Decode module - Coming soon")    

            # elif choice == "4":
            #     print("[#] Flask Decode module - Coming soon")    

            # elif choice == "5":
            #     print("\n[#] Exiting Decode dead. Goodbye!")     
            #     break


if __name__ == "__main__":
    main()        