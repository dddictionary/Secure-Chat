# Secure Chat App

## What is it?

This project is a real time end-to-end encrypted secure chat application. This app utilizes AES to encrypt messages, MAC's to ensure message integrity and Diffie-Hellman Key Exchange to generate the AES and HMAC keys. 

## Getting Started
To get started, you must be on a Linux Operating System. 
I am assuming you are on a Linux Operating System moving onward.

1. Clone the repository using the following command:
```terminal
git clone https://github.com/dddictionary/Secure-Chat.git
```
2. Run `make` to compile the files into executables. If there are any issues with compiling, run `make clean` and then running `make`
3. You can run `./chat -h` to view the list of possible commands.
4. To beginning listening on one machine, run `./chat -l`. This will default to listening on port 1337.
5. On another terminal instance, run `./chat -p 1337` to connect to the port. 

**OPTIONAL:**  
If you host a port forward, you can allow others to connect to your computer and chat with you while being connected to different routers!  
The command for that is:
```terminal
./chat -c <ip-address>
```
where `ip-address` is the IP address of the host machine. 

## Credits
The app was made by the following:
- [Abrar Habib](https://github.com/dddictionary)