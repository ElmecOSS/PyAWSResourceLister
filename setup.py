# __________________
#  [2022] Elmec Informatica
#  Author: Cominoli, Dalle Fratte
#  Data: 11/08/2022
# __________________
import setuptools
from setuptools import setup

setup(
    name='awsresourcelister',
    version='1.9.0',
    packages=setuptools.find_packages(),
    url='',
    author='Cominoli Luca, Dalle Fratte Andrea',
    author_email='luca.cominoli@elmec.it, andrea.dallefratte@elmec.it',
    description='Library for AWS Resource Listing',
    install_requires=[
        'requests>=2.24.0',
        'boto3>=1.20.8',
        'botocore>=1.23.9'
    ],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Plugins',
        'Framework :: AWS CDK :: 2',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Topic :: System :: Monitoring',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
)
