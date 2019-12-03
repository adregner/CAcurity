from setuptools import setup

setup(
    name='cacurity',
    author='Andrew Regner',
    author_email='andrew@aregner.com',
    url='https://github.com/adregner/CAcurity',
    version='1.0',
    packages=[
        'cacurity',
        'cacurity.crypto',
    ],
    install_requires=[
        'click',
        'Flask',
        'pyopenssl',
        'requests',
    ],
    entry_points={
        'console_scripts': ['cacurity=cacurity.client:cli'],
    },
)
