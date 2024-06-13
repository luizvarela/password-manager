# Password Manager

A simple command line Password Manager written in Golang, built only for learning purpose. This is not meant to be used with real passwords as it lacks of secutiry rules :) This CLI was inspired by KeePass.

## Usage

The CLI gives you the ability to create a Password Vault to store your records, you can sign in into an existent Vault and fetch the password records store in it in a secure way. The records are stored in a file.

```
What would you like to do?

1. Create a new password vault
2. Sign in to an existing password vault
3. Add a password record to the vault
4. Fetch a password record from the vault

Quit (enter q or quit)
```

## Enhancements

- Improve error handling and user prompts.
- Ensure proper encryption and decryption of passwords.
- Use a global state to store the signed-in vault and derived key.
- Edit and remove password recods in a Valt.
- Improve security.
- Add tests.
- Create an API and build a WEB interface.
