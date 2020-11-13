
## Clipboard

Clipboard synchronization tool.

Support for Gnome by gtk.

### Usage

#### `For Release`:

```
Usage: ./server [-d][-p port]
	Command Summary:
		-d		Start as daemon
		-p port		Specify port for listening

Usage: ./client [-h host] [-p port]
	Command Summary:
		-h host		Specify host of remote connects
		-p port		Specify port for remote connects

```

#### `For development`:

* config.h

    ```c++
    // Default port
    #define SERVER_PORT 1056

    // Max of connection number
    #define MAX_CONNECTION 16

    // Show debug information
    #define DEBUG

    // Default server ip
    #define SERVER_IP "127.0.0.1"
    ```

* Makefile

    * `make` : Compile all files.
    * `make key` : Generate a new key of RSA.(`rsa_private_key.pem` , `rsa_public_key.pem`)
    * `make clean` : As usual, clean all files.



### Dependencies

* libgtk-3-dev

### Working

Add support for `Windows`.
