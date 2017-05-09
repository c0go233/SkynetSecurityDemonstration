import struct
import datetime

from Crypto.Cipher import XOR
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import HMAC

from dh import create_dh_key, calculate_dh_secret

ch_enc_code = 'ascii'
mac_length = 32

timestamp_format = "%Y-%m-%d %H:%M:%S.%f"
# get the length of timestamp
timestamp_length = len(datetime.datetime.now().strftime(timestamp_format))

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher_available = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.shared_hash = None
        self.previous_timestamp = None
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret

        ### TODO: Your code here!
        # This can be broken into code run just on the server or just on the client
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), ch_enc_code))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(shared_hash))

            # save hash in byte format for use as key
            self.shared_hash = bytes.fromhex(shared_hash)

        # Set the cipher_available equal to true so that
        # bot can use cipher with shraed_hash to encrypt and decrypt
        self.cipher_available = True

    def send(self, data):
        if self.cipher_available:

            # Initialize Cipher with new iv for every message
            iv = Random.new().read(AES.block_size)
            cipher = AES.new(self.shared_hash, AES.MODE_CFB, iv)

            # Create HMAC and append it to the data
            hMac = HMAC.new(self.shared_hash)
            hMac.update(data)
            hMac_digest = hMac.hexdigest()
            data_to_send = hMac_digest.encode(ch_enc_code) + data
            if self.verbose:
                print("Calculated HMAC: {}".format(hMac_digest))

            # Create Timestamp and append it to the data
            timestamp = datetime.datetime.now().strftime(timestamp_format).encode(ch_enc_code)
            data_to_send = timestamp + data_to_send

            # Encrypt the data with Initialziation Vector
            encrypted_data = iv + cipher.encrypt(data_to_send)

            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]

        encrypted_data = self.conn.recv(pkt_len)

        if self.cipher_available:

            # Initialize cipher with received IV
            iv = encrypted_data[:AES.block_size]
            cipher = AES.new(self.shared_hash, AES.MODE_CFB, iv)

            # Break the data and get timestamp, HMAC and data seprately
            encrypted_data = encrypted_data[AES.block_size:]
            data = cipher.decrypt(encrypted_data)
            timestamp = data[:timestamp_length]
            data = data[timestamp_length:]
            received_hmac = data[:mac_length]
            data = data[mac_length:]

            # Compare received Timestamp against previous timestamp
            # If the timestamp is valid then save it to previous_timestamp variable
            received_timestamp = datetime.datetime.strptime(timestamp.decode(ch_enc_code), timestamp_format)
            if self.previous_timestamp is not None:
                if received_timestamp <= self.previous_timestamp:
                    raise RuntimeError("Invalid Timestamp")
                else:
                    self.previous_timestamp = received_timestamp
            else:
                self.previous_timestamp = received_timestamp


            # Create expected HMAC with received data and shared public key
            # Compare the expected HMAC against received HMAC
            expected_hmac = HMAC.new(self.shared_hash)
            expected_hmac.update(data)
            expected_hmac = expected_hmac.hexdigest().encode(ch_enc_code)

            if self.verbose:
                print("Received HMAC: {}".format(received_hmac))
                print("Expected HMAC: {}".format(expected_hmac))

            if expected_hmac != received_hmac:
                raise RuntimeError("Invalid HMAC")


            # Print information about received data
            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else:
            data = encrypted_data

        return data

    def close(self):
        self.conn.close()
