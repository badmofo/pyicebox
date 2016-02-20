from __future__ import print_function
from bitcoin import bip32_master_key, bip32_ckd, bip32_descend, bip32_privtopub, encode_privkey
import json
import ethereum.keys
import ethereum.transactions
from ethereum.utils import decode_addr, decode_hex, encode_hex
import requests
from mnemonic import Mnemonic
from rlp import encode

def mnemonic_to_hdkey(mnemonic):
    # if we wanted to avoid the mnemonic dep we could just do: 
    #  pbkdf2_hmac('sha512', mnemonic, 'mnemonic', 2048).encode('hex')
    # to get the seed
    if not Mnemonic('english').check(mnemonic):
        raise Exception('invalid mnemonic')
    seed = Mnemonic('english').to_seed(mnemonic)
    hd_root = bip32_master_key(seed)
    # path is m/0'/0'/0'
    return bip32_ckd(bip32_ckd(bip32_ckd(hd_root, 2**31), 2**31), 2**31)
    
def derive_keypairs(hd_key, keys=3):
    keypairs = []    
    for i in range(keys):
        privkey = encode_privkey(bip32_descend(hd_key, [i]), 'hex')
        addr = decode_addr(ethereum.keys.privtoaddr(privkey)).decode('utf-8')
        keypairs.append((privkey, addr))
    return keypairs

def create_mnemonic():
    return Mnemonic('english').generate()

def gas_price():
    return requests.get('https://etherchain.org/api/gasPrice').json()['data'][0]['price']

def lookup(addr):
    ''' Returns balance and nonce. '''
    # TODO: beware balance is int but nonce is string
    # TODO: use instead https://etherchain.org/api/account/multiple/:ids
    data = requests.get('https://etherchain.org/api/account/%s' % addr).json()['data']
    if data:
        return data[0]
    else:
        return {'balance': 0, 'nonce': '0'}

def send(privkey, nonce, recipient, amount_wei, gas_price_wei, gas_limit=21000):
    # TODO: sanity check incoming args
    tx = ethereum.transactions.Transaction(nonce, gas_price_wei, gas_limit, recipient, amount_wei, '')
    tx.sign(privkey)
    return encode(tx)
    
def export_keystore(privkey, password):
    content = ethereum.keys.make_keystore_json(privkey, password)
    print(content)
    content_json = json.dumps(content, indent=4)
    filename = content["id"] + '.json'
    return filename, content_json

def test_send():
    privkey = decode_hex('a06bab413912bc24726e266a1f6613944ea30bf3399ae3375ccf7a663b73b625')
    recipient = '0x25c6e74ff1d928df98137af4df8430df24f07cd7'
    nonce = 0
    amount = 1000000000000000000
    gas_price = 100000000000
    gas_limit = 30000
    tx = send(privkey, nonce, recipient, amount, gas_price, gas_limit)
    tx_expected = 'f86c8085174876e8008275309425c6e74ff1d928df98137af4df8430df24f07cd7880de0b6b3a7640000801ba03710b1c12686a52ca22a489a7e2323e33cdab723fe174f466d8d7122c5bc65faa077dd10ef5a9f89630aaecf852b2f9e3679c75f98fb39e91275fe76e53948af05'
    assert tx_expected == tx.hex()

def test_mnemonic():
    mnemonic = 'logic one label consider alter keen sweet local blush quit holiday trouble'
    keypairs = [
        ('a06bab413912bc24726e266a1f6613944ea30bf3399ae3375ccf7a663b73b625', '4165c8a7e88c5780ac9214c1d9214a241ab5f078'),
        ('1ba6df9042640c614ba798271b7c1ede4c475d7087dbbb1f4372cf426d7a4cc6', 'b4e264be7f4d3a44ed58f8be183faae8515e78c7'),
        ('e35478c748b6a2891ec518cbc5c62d08c8c02aa62a223103b46ae5366e9be29c', 'e33b9d75798de6fdae6e5073dc3c3c52d1203fa7')]
    assert keypairs == mnemonic_to_hdkey(mnemonic)
    
if __name__ == '__main__':
    import sys
    import getpass
    from decimal import Decimal
    command = sys.argv[1] if len(sys.argv) > 1 else ''
    if command == 'gas':
        print(gas_price())
    elif command == 'lookup':
        addr = sys.argv[2]
        info = lookup(addr)
        print('Balance: %s ETH' % (info['balance']/Decimal(1000000000000000000)))
        print('Nonce:', info['nonce'])
    elif command == 'create':
        mnemonic = create_mnemonic()
        hd_privkey = mnemonic_to_hdkey(mnemonic)
        print('Mnemonic: %s' % mnemonic)
        #print('HDPublicKey: %s' % bip32_privtopub(hd_privkey))
        print('-' * 40)
        for i,(privkey,addr) in enumerate(mnemonic_to_hdkey(hd_privkey)):
            print('Address #%d: 0x%s' % (i, addr))
    elif command == 'keys':
        mnemonic = getpass.getpass('Enter mnemonic:').strip()
        hd_privkey = mnemonic_to_hdkey(mnemonic)
        #print('HDPublicKey: %s' % bip32_privtopub(hd_privkey))
        for i,(privkey,addr) in enumerate(derive_keypairs(hd_privkey)):
            print('Address #%d: 0x%s    Privkey: %s' % (i, addr, privkey))
    elif command == 'send':
        privkey_hex = getpass.getpass('Enter privkey:')
        privkey = decode_hex(privkey_hex)
        assert len(privkey) == 32
        nonce = int(sys.argv[2])
        recipient = sys.argv[3]
        amount = int(Decimal(sys.argv[4]) * Decimal(1000000000000000000))
        gas_price = int(sys.argv[5])
        gas_limit = int(sys.argv[6])
        tx = send(privkey, nonce, recipient, amount, gas_price, gas_limit)
        print('Trasaction:', encode_hex(tx).decode('utf-8'))
    elif command == 'export':
        privkey_hex = getpass.getpass('Enter privkey:')
        privkey = decode_hex(privkey_hex)
        assert len(privkey) == 32
        pw = getpass.getpass('Choose a keystore password:')
        pw2 = getpass.getpass('Repeat password:')
        assert pw == pw2, "Password mismatch"
        print("Applying hard key derivation function.  Please wait ...")
        filename, content_json = export_keystore(privkey, pw)
        print('Wallet saved to file: %s' % filename)
        open(filename, 'w').write(content_json)
    elif command == 'test':
        test_send()
        test_mnemonic()
        print('Tests passed.')
    else:
        print('''Command Help:
        
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
''')