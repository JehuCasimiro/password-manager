import csv
import os
from cryptography.fernet import Fernet
from tabulate import tabulate

class PasswordManager:
    def __init__(self, master_password):
        self.master_password = master_password
        self.fernet = Fernet(Fernet.generate_key())
        self.passwords = {}

    def _encrypt(self, text):
         # return self.fernet.encrypt(text.encode())
         return text # use this for the meantime, tho not secure

    def _decrypt(self, text):
        # return self.fernet.decrypt(text).decode() # this raises an error when exiting the code and decrypting passwords
        return text # use this for the meantime, tho not secure

    def add_password(self, account, password):
        encrypted_password = self._encrypt(password)
        self.passwords[account] = encrypted_password
        self.save_passwords_to_csv('passwords.csv')  # Automatically save when adding a password

    def get_password(self, account):
        if account in self.passwords:
            encrypted_password = self.passwords[account]
            decrypted_password = self._decrypt(encrypted_password)
            return decrypted_password
        else:
            return None

    def save_passwords_to_csv(self, filename):
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = ['Account', 'EncryptedPassword']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for account, encrypted_password in self.passwords.items():
                writer.writerow({'Account': account, 'EncryptedPassword': encrypted_password.decode()})

    def load_passwords_from_csv(self, filename):
        try:
            with open(filename, 'r') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    account = row['Account']
                    encrypted_password = row['EncryptedPassword'].encode()
                    self.passwords[account] = encrypted_password
        except FileNotFoundError:
            print("Password file not found. Creating a new one.")

    def save_master_password_to_csv(self, filename):
        with open(filename, 'w') as csvfile:
            csvfile.write(self.master_password)

def main():
    master_password_filename = 'master_password.csv'
    password_filename = 'passwords.csv'

    if not os.path.exists(master_password_filename):
        new_master_password = input("Enter a new master password: ")
        password_manager = PasswordManager(new_master_password)
        password_manager.save_master_password_to_csv(master_password_filename)
    else:
        with open(master_password_filename, 'r') as csvfile:
            master_password = csvfile.read()
            master_password_input = input("Enter your master password: ")
            if master_password != master_password_input:
                print("Incorrect master password. Exiting.")
                return
        password_manager = PasswordManager(master_password)
        password_manager.load_passwords_from_csv(password_filename)

    while True:
        print("Password Manager Menu:")
        print("1. Add Password")
        print("2. Get Password")
        print("3. Quit")

        choice = input("Enter your choice: ")

        if choice == "1":
            account = input("Enter account name: ")
            password = input("Enter password: ")
            password_manager.add_password(account, password)
            print("Password added successfully.")
        elif choice == "2":
            accounts_table = tabulate(
                [(account,) for account in password_manager.passwords.keys()],
                headers=["Account Names"],
                tablefmt="fancy_grid",
            )
            print("Account Names:")
            print(accounts_table)
            account = input("Enter account name: ")
            password = password_manager.get_password(account)
            if password:
                # print(f"Password for {account}: {password}")
                print(tabulate([[f"Password for {account}"], [f"{password}"]], headers="firstrow"))
            else:
                print(f"No password found for {account}.")
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()
