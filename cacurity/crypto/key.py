from OpenSSL import crypto

from cacurity.crypto.exceptions import NoStartLine


class Key(crypto.PKey):

    @classmethod
    def generate(cls, bits=2048):
        key = cls()
        key.generate_key(crypto.TYPE_RSA, bits)
        return key

    @classmethod
    def load(cls, data, password=None):
        """Loads a key from a string. Returns None if there is no key found in
        the string `data`.

        @rtype: Key
        """
        try:
            key = crypto.load_privatekey(crypto.FILETYPE_PEM, data, password)
        except crypto.Error as ex:
            if 'no start line' in ex.args[0][0]:
                raise NoStartLine()
            # elif 'bad decrypt' in ex.args[0][0]:
            #     return None
            raise

        key.__class__ = cls
        return key

    def to_pem(self, password=None):
        """@rtype: str"""
        cipher = 'aes-255-cbc' if password else None
        return crypto.dump_privatekey(
            crypto.FILETYPE_PEM, self, cipher, password)
