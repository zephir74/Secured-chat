## Description

This is a CLI chat secured using OpenSSL 3.6.2, with various commands available,
such as:

- /help : display the help menu
- /users : list all active users
- /dir : get the current operating directory
- /ip : get the server's public IP address
- /reboot : restart the server (entire operating system)
- /quit : exit the chat (you can use Crtl+C but you should avoid it as it may crash the server)

There are also a few color codes. Red messages are for fatal errors, yellow messages are for informative errors and cyan messages are just the ones from users.

## How to use

To send a message, you just need to enter the string you want to send.
For private messages, enter `@<username> <your_message>`.
You can receive the message + the user who sent it.
To compile the files, open a shell in the repository and enter `make all`.
Then, type `./server -h` or `./client -h` to have detailed examples on how to use them.
For the certificates, execute `chmod +x generate-cert.sh && ./generate-cert.sh`. You can sign your certificate with your own enterprise name (CN= field).

## Requirements

- make (`sudo apt install make`)
- gcc compiler (`sudo apt install gcc`)
- openssl additional libraries (`sudo apt install libssl-dev libssl-doc libssl-3t64`)

## Additional information:

- If your local network doesn't have an integrated DNS server, you will be limited to IP address only when connecting.
- If there is a firewall on your local network, you might not be able to reach the server.
- You might receive an error saying "Error while receiving : SUCCESS". This is either due to a crash from the server or if you tried to connect with a username that was already used.
