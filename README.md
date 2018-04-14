Libraries for Common Functionality for Applications
===========================================
## Set of functionality for supporting applications
### app_support_lib.py
**app_support_lib.py** contains utility functions and classes for application development. In particular, it provides functionality to create an application-support directory and a database class that currently supports SQLite3 only, whose files would reside in the application-support directory.

## Set of functionality for ID and public key management
### id_lib.py
**id_lib.py** contains a class whose objects provide autonomous generation of user identifiers and mapping between a set of public keys and a generated identifier. The mapping may only be updated by some designated authority (currently, just by the user represented by the identifier) in a domain. The class also provides standard means to verify that a transaction is signed by correct user or users in light of the mapping.

The following methods are provided:
* **create_user_id()** to autonomously create a user identifier and its initial mapping to a set of public keys.
* **get_mapped_public_keys()** to get public keys mapped to an identifier at a given time.
* **is_mapped()** to see whether an identifier and a public key are (were) mapped at a given time.
* **update()** to update the mapping.
* **verify_signers()** to verify the correctness of signers to a transaction.

## How to Use this library
At this stage (pre-version 1.0), we are in the process of re-organizing the library structures as of version 0.10 of BBc-1 towards version 1.0. When this library is ready, this README will be updated.

