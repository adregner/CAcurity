from OpenSSL import crypto

from cacurity.crypto.exceptions import NoStartLine


class Request(crypto.X509Req):

    def __init__(self, **subject):
        """Parameters to this will be used to fill in the subject of this
        certificate request. They should be attribytes of an X509Name object.

        e.g. Request(
                 CN='foo.com',
                 O='Acme Screw Company',
                 OU='IT Department',
                 L='San Francisco',
                 ST='CA',
                 C='US',
                 emailAddress='it@acme.org',
             )
        """
        super(Request, self).__init__()

        subj = self.get_subject()
        for k, v in subject.items():
            if not v:
                continue
            setattr(subj, k, v)

    @classmethod
    def load(cls, data):
        """Loads a certificate request from a string.

        @rtype: Request
        """
        try:
            req = crypto.load_certificate_request(crypto.FILETYPE_PEM, data)
        except crypto.Error as ex:
            if 'no start line' in ex.args[0][0]:
                raise NoStartLine()
            raise

        req.__class__ = cls
        return req

    def set_key(self, key):
        """Set the public key of this certificate request from the provided
        public or private key object."""
        self.set_pubkey(key)
        self.sign(key, 'sha256')
        return self

    def to_pem(self):
        """@rtype: str"""
        return crypto.dump_certificate_request(crypto.FILETYPE_PEM, self)

    def to_text(self):
        """@rtype: str"""
        return crypto.dump_certificate_request(crypto.FILETYPE_TEXT, self)
