#!/usr/bin/env python
import functools
import os

import click
import requests

from cacurity import crypto


DEFAULT_API_URI = "http://127.0.0.1:5333"
USER_AGENT = "CAcurity CLI/1.0"


############################
# Common options
############################
def output_options(func):
    @click.option(
        '--output', type=click.File('wa'), default='-')
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper


def request_options(func):
    @click.option('--key', type=click.File('r'))
    @click.option('--name')
    @click.option('--org')
    @click.option('--org-unit')
    @click.option('--city')
    @click.option('--state')
    @click.option('--country')
    @click.option('--email')
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        kwargs['keyfd'] = kwargs.pop('key')
        return func(*args, **kwargs)
    return wrapper


def cert_options(func):
    @click.option('--age', type=int, default=7200)
    @click.option('--request', type=click.File('r'))
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        kwargs['reqfd'] = kwargs.pop('request')
        return func(*args, **kwargs)
    return wrapper


def key_options(func):
    @click.option('--bits', type=int, default=2048)
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper


@click.group()
def cli():
    pass


############################
# Request
############################
def api(path, params=None, payload=None, **kwargs):
    ctx = click.get_current_context()
    url = ctx.meta.get('api_url').strip('/') + path

    kwargs.setdefault('headers', {}).setdefault('user-agent', USER_AGENT)

    if payload:
        r = requests.post(url, params=params, data=payload, **kwargs)
    else:
        r = requests.get(url, params=params, **kwargs)

    return r.content


@cli.group()
@click.option('--api-url', default=DEFAULT_API_URI)
@click.pass_context
def request(ctx, api_url):
    ctx = click.get_current_context()
    ctx.meta['api_url'] = api_url


@request.command('request')
@output_options
@key_options
@request_options
def req_req(output, bits, keyfd, **subject):
    key = None
    if keyfd:
        key = crypto.Key.load(keyfd.read()).to_pem()

    req = api('/request', {'bits': bits}, key)
    output.write(req)


@request.command('cert')
@output_options
@cert_options
@click.option('--ca', default='')
@key_options
@request_options
def req_cert(output, age, reqfd, ca, bits, keyfd, **subject):
    thing = None
    if reqfd:
        thing = crypto.Request.load(reqfd.read()).to_pem()
    elif keyfd:
        thing = crypto.Key.load(reqfd.read()).to_pem()

    params = {'age': age, 'bits': bits}
    params.update(subject)
    ca_path = "/%s" % ca if ca else ''

    cert = api('%s/certificate' % ca_path, params, thing)
    click.write(cert)


@request.command('key')
@key_options
def req_key(bits):
    key = api('/key', {'bits', bits})
    click.write(key)


############################
# Generate
############################
def to_subject(subject):
    subj = dict(
        CN=subject.get('name'),
        O=subject.get('org'),
        OU=subject.get('unit'),
        L=subject.get('city'),
        ST=subject.get('state'),
        C=subject.get('country'),
        emailAddress=subject.get('email'),
    )
    for k, v in subj.items():
        if v is None:
            del subj[k]
    return subj


@cli.group()
def generate(ca=None):
    pass


@generate.command('request')
@output_options
@key_options
@request_options
def gen_req(output, bits, keyfd, **subject):
    key = None
    if keyfd:
        key = crypto.Key.load(keyfd.read())
    else:
        key = crypto.Key.generate(bits)

    req = crypto.Request(**to_subject(subject))
    req.set_key(key)

    output.write(req.to_pem())

    if not keyfd:
        output.write(key.to_pem())


@generate.command('cert')
@output_options
@cert_options
@click.option('--ca', type=click.File('r'))
@key_options
@request_options
def gen_cert(output, age, reqfd, ca, bits, keyfd, **subject):
    key = req = None
    if keyfd:
        key = crypto.Key.load(keyfd.read())
    elif reqfd:
        req = crypto.Request.load(reqfd.read())
    else:
        key = crypto.Key.generate(bits)

    cert = crypto.Certificate(
        key=key, req=req, age=age, **to_subject(subject))

    if ca:
        ca_data = ca.read()
        ca_cert = crypto.Certificate.load(ca_data)
        ca_key = crypto.Key.load(ca_data)

        cert.issued_by(ca_cert, ca_key)

    output.write(cert.to_pem())

    if not (keyfd or reqfd):
        output.write(key.to_pem())


@generate.command('key')
@output_options
@key_options
def gen_key(output, bits):
    key = crypto.Key.generate(bits)
    output.write(key.to_pem())


if __name__ == '__main__':
    cli()
