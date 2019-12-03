import os

from flask import Flask, make_response, request

from cacurity.crypto import *


DEFAULT_CERTIFICATE_AGE = 3600
CA_PATH = 'ca'

app = Flask('caurity')


def get_ca(name):
    with open('%s/%s.pem' % (CA_PATH, name), 'r') as fd:
        data = fd.read()

    password = request.headers.get('X-CA-Password')

    try:
        key = Key.load(data, password=password)
    except Exception:
        # well, maybe they didn't want this part anyways
        key = None

    return Certificate.load(data), key


@app.route('/')
def index():
    ca_names = [name.replace('.pem', '') for name in os.listdir(CA_PATH)]
    return response(
        "CAcurity API\n" +
        "\n" +
        "avaliable CAs:\n" +
        "--------------\n" +
        "\n".join(ca_names) + "\n"
    )


@app.route('/<name>/ca')
def ca(name):
    ca_cert, _ = get_ca(name)
    return response("%s%s" % (
        ca_cert.to_text(),
        ca_cert.to_pem(),
    ))


@app.route('/key')
def key():
    bits = int(request.args.get('bits', 2048))
    return response(Key.generate(bits).to_pem())


@app.route('/request', methods=['POST', 'GET'])
def csr():
    key, generated_here = key_from_somewhere()
    req = Request(**subject_from_args())
    req.set_key(key)

    return response("%s%s%s" % (
        req.to_text(),
        req.to_pem(),
        key.to_pem() if generated_here else '',
    ))


@app.route('/certificate', defaults={'ca_name': None}, methods=['POST', 'GET'])
@app.route('/<ca_name>/certificate', methods=['POST', 'GET'])
def cert(ca_name):
    req = key = None
    if request.method == 'POST':
        try:
            data = request.data
            req = Request.load(data)
            generated_here = False
        except NoStartLine:
            # we will instead load or generate a key below
            pass

    if not req:
        key, generated_here = key_from_somewhere()

    age = int(request.args.get('age', DEFAULT_CERTIFICATE_AGE))
    cert = Certificate(req=req, key=key, age=age, **subject_from_args())

    if ca_name:
        ca = get_ca(ca_name)
        if not ca[1]:
            return "CA password is invalid", 401
        cert.issued_by(*ca)

    return response("%s%s%s" % (
        cert.to_text(),
        cert.to_pem(),
        key.to_pem() if generated_here else '',
    ))


def subject_from_args():
    subj = dict(
        CN=request.args.get('name'),
        O=request.args.get('org'),
        OU=request.args.get('unit'),
        L=request.args.get('city'),
        ST=request.args.get('state'),
        C=request.args.get('country'),
        emailAddress=request.args.get('email'),
    )
    for k, v in subj.items():
        if v is None:
            del subj[k]
    return subj


def key_from_somewhere():
    """
    @return: The key and a flag of if it was generated here or not
    @rtype: crypto.Key, bool
    """
    generated_key = False
    if request.method == 'GET':
        bits = int(request.args.get('bits', 2048))
        key = Key.generate(bits)
        generated_key = True
    elif request.method == 'POST':
        data = request.data
        key = Key.load(data)

    return key, generated_key


def response(rv):
    return rv, {'content-type': 'text/plain'}
