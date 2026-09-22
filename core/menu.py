def show_menu():
    """Display the main menu"""
    print("\n"+ "="* 50)
    print(" MAIN MENU")
    print("=" * 50)

    print("[1] Identify     - Identify hash/token type")
    print("[2] Hash Crack   - Dictionary-based hash cracking")
    print("[3] JWT Decode   - Decode JWT header and payload")
    print("[4] Flask Decode - Decode Flask session cookie")
    print("[5] Exit         - Exit Decode Dead")

    print("=" * 50)


def get_choice():
    """Get and validate the user's menu selection"""

    while True:
        choice = input("\nSelect an option (1-5): ").strip()

        if choice in ("1","2","3","4","5"):
            return choice

        print("[!] Invalid choice! Please enter a number from 1 to 5.")

# show_menu()
# get_choice()