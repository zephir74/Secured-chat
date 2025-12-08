## Description

This is a secured chat made in C. You have various commands available,
such as:

- /help : display the help menu
- /users : list all active users
- /dir : get the current operating directory
- /ip : get the server's public IP address
- /reboot : restart the server (entire operating system)
- /quit : exit the chat (you can use Crtl+C but you should avoid it)

## How to use

To send a message, you just need to enter your username when connecting, and then enter the string you want to send.
For private messages, enter @<username> <your_message>
You can receive the message + the user who sent it.
To compile the files, open a shell in the repository and enter `make all`.
Then, type `./server -h` `./client -h` to have detailed examples on how to use.
For the certificates, execute `chmod +x generate-cert.sh && ./generate-cert.sh`. You can sign your certificate with your own enterprise name (CN= field)

## Requirements

- gcc compiler (`sudo apt install gcc`)
- openssl additional libraries (`sudo apt install libssl-dev libssl-doc libssl 3t64)
