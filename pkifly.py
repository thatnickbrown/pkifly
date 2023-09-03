#!/usr/bin/env python3
# *_* coding: utf-8 *_*
"""PKI on the Fly - creates and manages basic X.509v3 PKIs"""

import argparse
import subprocess
import secrets
import string
import os
import re


def get_commandline_args() -> argparse.Namespace:
    """parse command line arguments and return a Namespace containing them"""
    example_use = "Example use:\n"+\
        "  Create a root CA named MyCa:\n"+\
        "   /pkifly.py ca MyCa\n"+\
        "  Create a server cert and key signed by MyCa\n"+\
        "   ./pkifly.py server MyCa --servername pentest.target.su\n"+\
        "  Create TLS client cert and key signed by MyCa\n"+\
        "   ./pkifly.py client MyCa --clientname bobsmith\n"+\
        "  Create an S/MIME email cert and key signed by MyCA\n"+\
        "   ./pkifly.py email MyCa --email bobsmith@target.su\n\n"+\
        "This software was designed to assist in security testing and research, not production workloads."
    
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='PKI on the Fly: Creates a simple X509v3 PKI',
        epilog=example_use,
    )

    parser.add_argument('type',
                        choices=['ca', 'server', 'client', 'email'],
                        help='specify whether to create a root CA or a user cert and key',)
    parser.add_argument('ca_name',
                        help='the name of the CA to be created or used for signing',)
    parser.add_argument('-s', '--servername',
                        required=False,
                        help='server common name (ignored when creating a CA)',)
    parser.add_argument('-c', '--clientname',
                        required=False,
                        help='client certificate common name (ignored when creating a CA)',)
    parser.add_argument('-e', '--emailaddress',
                        required=False,
                        help='email address (ignored when creating a CA)',)
    parser.add_argument('-o', '--overwrite',
                        required=False,
                        default=False,
                        action='store_true',
                        help="overwrite existing keys and certificates")
    
    return parser.parse_args()


def create_CA(op: str, args: argparse.Namespace):
    """Creates a certificate authority key and signed root certificate.

    Args:
        op (str): path to openssl
        args (argparse.Namespace): parsed command line arguments
    """

    ca_name = args.ca_name
    keyfile = ca_name+'.ca.key'
    certfile = ca_name+'.ca.crt'

    check_file_overwrites(keyfile, args.overwrite)
    check_file_overwrites(certfile, args.overwrite)

    openssl_command = [ op, 'req', '-config', 'pkifly.cnf', '-batch',
                        '-subj', '/CN='+ca_name, 
                        '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
                        '-addext', 'keyUsage=keyCertSign',
                        '-x509', '-new', '-nodes', 
                        '-days', '730', '-newkey', 'rsa:2048', '-keyout', 
                        keyfile, '-out', certfile ]
    execute_openssl_command(openssl_command)
    print(f'😊 Certificate authority root created with key {keyfile} and certificate {certfile}.')


def create_server(op: str, args: argparse.Namespace) -> None:
    """creates a TLS server certificate

    Args:
        op (str): path to openssl
        args (argparse.Namespace): parsed command line arguements
    """
    sn = args.servername

    # determine CA files
    ca = args.ca_name
    ca_keyfile = ca+'.ca.key'
    ca_certfile = ca+'.ca.crt'
    
    # determine new csr, key, and cert files
    csr = sn+'.csr'
    key = sn+'.key'
    crt = sn+'.crt'

    check_file_overwrites(csr, args.overwrite)
    check_file_overwrites(key, args.overwrite)
    check_file_overwrites(crt, args.overwrite)


    # generate the key and CSR
    openssl_command =   [ op, 'req', '-nodes', '-config', 'pkifly.cnf',
                        '-newkey', 'rsa:2048',
                        '-keyout', key, '-out', csr,
                        '-subj', '/CN='+sn, 
                        '-extensions', 'v3_req',
                        '-addext', 'basicConstraints=critical,CA:FALSE',
                        '-addext', 'keyUsage=nonRepudiation,digitalSignature,keyEncipherment',
                        '-addext', 'extendedKeyUsage=critical,serverAuth',
                        '-days', '365' ]
    execute_openssl_command(openssl_command)
    print(f'Created server key {key} and CSR {csr}.')

    # sign the CSR with the CA
    openssl_command =   [ op, 'x509', '-req', 
                        '-extensions', 'v3_req', 
                        '-extfile', 'pkifly.cnf',
                        '-CA', ca_certfile, '-CAkey', ca_keyfile,
                        '-in', csr, '-out', crt,
                        '-copy_extensions', 'copy',
                        ]
    execute_openssl_command(openssl_command)
    print(f'😊 Successfully created key {key} and certificate {crt}.')


def create_client(op: str, args: argparse.Namespace) -> None:
    """creates a TLS client certificate

    Args:
        op (str): openssl path
        args (argparse.Namespace): parsed command line arguements
    """
    cn = args.clientname

    # determine CA files
    ca = args.ca_name
    ca_keyfile = ca+'.ca.key'
    ca_certfile = ca+'.ca.crt'
    
    # determine new csr, key, and cert files
    csr = cn+'.csr'
    key = cn+'.key'
    crt = cn+'.crt'

    check_file_overwrites(csr, args.overwrite)
    check_file_overwrites(key, args.overwrite)
    check_file_overwrites(crt, args.overwrite)

    # generate the key and CSR
    openssl_command =   [ op, 'req', '-nodes', '-config', 'pkifly.cnf',
                        '-newkey', 'rsa:2048',
                        '-keyout', key, '-out', csr,
                        '-subj', '/CN='+cn, 
                        '-extensions', 'v3_req',
                        '-addext', 'basicConstraints=critical,CA:FALSE',
                        '-addext', 'keyUsage=nonRepudiation,digitalSignature,keyEncipherment',
                        '-addext', 'extendedKeyUsage=critical,clientAuth', 
                        '-days', '365',
                        ]
    execute_openssl_command(openssl_command)
    print(f'😊 Successfully created key {key} and CSR {csr}.')

    # sign the CSR with the CA
    openssl_command =   [ op, 'x509', '-req', 
                        '-extensions', 'v3_req', 
                        '-extfile', 'pkifly.cnf',
                        '-CA', ca_certfile, '-CAkey', ca_keyfile,
                        '-in', csr, '-out', crt,
                        '-copy_extensions', 'copy',
                        ]
    execute_openssl_command(openssl_command)
    print(f'😊 Successfully created key {key} and certificate {crt}.')


def create_email(op: str, args: argparse.Namespace) -> None:
    """creates a tls email certificate"""
    cn = args.emailaddress

    # determine CA files
    ca = args.ca_name
    ca_keyfile = ca+'.ca.key'
    ca_certfile = ca+'.ca.crt'
    
    # determine new csr, key, and cert files
    csr = cn+'.csr'
    key = cn+'.key'
    crt = cn+'.crt'

    check_file_overwrites(csr, args.overwrite)
    check_file_overwrites(key, args.overwrite)
    check_file_overwrites(crt, args.overwrite)

    # generate the key and CSR
    openssl_command =   [ op, 'req', '-nodes', '-config', 'pkifly.cnf',
                        '-newkey', 'rsa:2048',
                        '-keyout', key, '-out', csr,
                        '-subj', f'/emailAddress={cn}/CN={cn}', 
                        '-extensions', 'v3_req',
                        '-addext', 'basicConstraints=critical,CA:FALSE',
                        '-addext', 'keyUsage=nonRepudiation,digitalSignature,keyEncipherment',
                        '-addext', 'extendedKeyUsage=critical,emailProtection', 
                        '-days', '365',
                        ]
    execute_openssl_command(openssl_command)
    print(f'😊 Successfully created key {key} and CSR {csr}.')

    # sign the CSR with the CA
    openssl_command =   [ op, 'x509', '-req', 
                        '-extensions', 'v3_req', 
                        '-extfile', 'pkifly.cnf',
                        '-CA', ca_certfile, '-CAkey', ca_keyfile,
                        '-in', csr, '-out', crt,
                        '-copy_extensions', 'copy',
                        ]
    execute_openssl_command(openssl_command)
    print(f'😊 Successfully created key {key} and certificate {crt}.')

    # create a p7b for use with Windows
    create_p7b(op, ca, crt, args.overwrite)

    # create a pfx for use with Windows
    create_pfx(op, ca_certfile, key, crt, args.overwrite)


def create_p7b(op:str, ca:str, crtfile: str, overwrite: bool) -> None:
    """"creates a p7b file including both the ca and user certs

    Args:
        op (str): openssl path
        ca (str): CA name
        crtfile (str): user certificate filename
    """

    cafile = f'{ca}.ca.crt'
    p7bfile = f'{crtfile}.p7b'
    check_file_overwrites(p7bfile, overwrite)

    openssl_command =   [op, 'crl2pkcs7', '-nocrl', 
                        '-certfile', crtfile,
                        '-certfile', cafile,
                        '-out', p7bfile
                        ]
    execute_openssl_command(openssl_command)
    print(f'😊 Successfully created PKCS7 p7b file {p7bfile}')


def create_pfx_passwordfile(pfxfile: str) -> (str, str):
    """Generates a password for a pfx files since the Windows certificate
    import tool requires nonempty passwords with pfx files. The password
    is written to a file for use by openssl because passing it to openssl
    as a command line parameter is icky, and the key it protects is already
    stored in the same directory unencrypted.

    Args:
        pfxfile (str): name of the pfx file
    """
    # generate a random password
    password = str()
    for i in range(12):
        password += ''.join(secrets.choice(string.ascii_uppercase))
    passfn = f'{pfxfile}.password.txt'
    # write the password to a file for use by openssl's -passout
    os.umask(0o177)
    with open(passfn, 'w') as handle:
    #with os.fdopen(os.open(passfn, os.O_WRONLY | os.O_CREAT, 0o600), 'w') as handle:
        # writing creds to disk is the worst option, except all the others
        handle.write(password+"\n")
    return(password, passfn)


def create_pfx(op: str, cacrt: str, userkey: str, usercert: str, overwrite: bool) -> None:
    """create a p12 file and a file containing its password"""
    pfx_filename = f'{userkey}.pfx'
    check_file_overwrites(pfx_filename, overwrite)

    pwd, pwd_file = create_pfx_passwordfile(pfx_filename)
    openssl_command =   [op, 'pkcs12', '-export', '-in', usercert,
                        '-inkey', userkey, '-out', pfx_filename,
                        '-certfile', cacrt, '-passout', 'file:'+pwd_file
                        ]
    execute_openssl_command(openssl_command)
    print(f'😊 Successfully created pfx file {pfx_filename} encrypted with password {pwd},')
    print(f'which can be found in {pwd_file}. You may delete this file if it not needed.')


def create_certificate_keypair(op: str, args: argparse.Namespace):
    """Creates the correct type of key and certificate based on command line args

    Args:
        op (str): openssl path
        args (argparse.Namespace): parsed command line arguements
    """
    if args.type == 'ca':
        create_CA(op, args)
    elif args.type == "server":
        create_server(op, args)
    elif args.type == "client":
        create_client(op, args)
    elif args.type == "email":
        create_email(op, args)


def get_openssl_path() -> str:
    """Verifies openssl is installed and returns its path

    Returns:
        str: path to openssl binary
    """
    which_results = subprocess.run(['/bin/which', 'openssl'], stdout=subprocess.PIPE)
    if which_results.returncode != 0: exit('😡 openssl must be installed')
    return which_results.stdout.decode().strip()

    
def validate_ca_format(ca_name: str) -> None:
    """Verifies the CA name contains characters that are suitable for filenames

    Args:
        ca_name (str): name of the CA
    """
    if not re.fullmatch('[\w\., ]+', ca_name): exit("😡 The specified CA name uses an invalid format")


def check_file_overwrites(filename: str, overwrite: bool) -> None:
    """overwrites existing keys and certificates instead of exiting

    Args:
        filename (str): certificate or key to be checked
        overwrite (bool): overwrite files without prompting
    """
    if not overwrite:
        if os.path.isfile(filename): exit(f'😡 {filename} already exists. Use -o to overwrite files.')


def execute_openssl_command(cmd: list) -> None:
    """Executes a command line operation using subprocess

    Args:
        cmd (list): command and arguments to run
    """
    print(f'🖥️  Executing command: {" ".join(cmd)}')
    newca_sub = subprocess.run(cmd, capture_output=True)
    if newca_sub.returncode != 0:
        exit("😡 Command execution failed.")


if __name__ == '__main__':
    """creates certificates and keys according to the specified command line parameters"""
    # get the command line arguments
    args = get_commandline_args()
    # validate CA name format
    validate_ca_format(args.ca_name)
    # verify openssl is installed and get its path
    openssl_path = get_openssl_path()
    # create a certificate and key pair based on the arguments
    create_certificate_keypair(openssl_path, args)
