import csv
from cryptography.fernet import Fernet

class PasswordManager:
    def __init__(self, master_password):
        self.master_password = master_password
        self.fernet = Fernet(Fernet.generate_key())
        self.passwords = {}

    def _encrypt(self, text):
        return self.fernet.encrypt(text.encode())

    def _decrypt(self, text):
        return self.fernet.decrypt(text).decode()

    def add_password(self, account, password):
        encrypted_password = self._encrypt(password)
        self.passwords[account] = encrypted_password

    def get_password(self, account):
        if account in self.passwords:
            encrypted_password = self.passwords[account]
            decrypted_password = self._decrypt(encrypted_password)
            return decrypted_password
        else:
            return None

    def save_passwords_to_csv(self, filename):
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = ['Account', 'Password']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for account, encrypted_password in self.passwords.items():
                decrypted_password = self._decrypt(encrypted_password)
                writer.writerow({'Account': account, 'Password': decrypted_password})

    def load_passwords_from_csv(self, filename):
        try:
            with open(filename, 'r') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    account = row['Account']
                    encrypted_password = self._encrypt(row['Password'])
                    self.passwords[account] = encrypted_password
        except FileNotFoundError:
            print("Password file not found. Creating a new one.")

def main():
    master_password = input("Enter your master password: ")
    password_manager = PasswordManager(master_password)

    # Load passwords from CSV file if it exists
    password_manager.load_passwords_from_csv('passwords.csv')

    while True:
        print("Password Manager Menu:")
        print("1. Add Password")
        print("2. Get Password")
        print("3. Save Passwords")
        print("4. Quit")

        choice = input("Enter your choice: ")

        if choice == "1":
            account = input("Enter account name: ")
            password = input("Enter password: ")
            password_manager.add_password(account, password)
            print("Password added successfully.")
        elif choice == "2":
            account = input("Enter account name: ")
            password = password_manager.get_password(account)
            if password:
                print(f"Password for {account}: {password}")
            else:
                print(f"No password found for {account}.")
        elif choice == "3":
            password_manager.save_passwords_to_csv('passwords.csv')
            print("Passwords saved to CSV file.")
        elif choice == "4":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()
