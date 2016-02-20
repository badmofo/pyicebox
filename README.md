# pyicebox
A python library/CLI tool for working with Ethereum [icebox-format](https://github.com/ConsenSys/icebox) mnemonic-based offline wallets.

Requires Python 2.7.x as well as the following libraries:

* ethereum
* bitcoin
* requests
* mnemonic

### Command line interface
```
Command Help:
        
    create
        Generate a new icebox wallet.
        
    keys
        Displays the addresses and private keys for a wallet.
        NOTE: This command will prompt you for your mnemonic.
        
    gas
        Shows the current gas price in WEI (must be online).
        
    lookup <addr>
        Shows the current balance and nonce given an address (must be online).
    
    send <nonce> <recipient address> <amount> <gas price> <gas limit>
        Creates a send transaction (but does not broadcast it).
        NOTE: This command will prompt you for the private key to send from.
        Amount should be specified in ETHERs.
        Gas price should be specified in WEI.
        Gas limit for simple sends should be set to 21000.
        
    export
        Export a private key to a geth-compatible keystore. 
        NOTE: This command will prompt you for the private key and keystore password.
```