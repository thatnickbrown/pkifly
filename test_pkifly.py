from pkifly import *

def test_get_openssl_path():
    assert get_openssl_path()[-7:] == "openssl"


def test_create_pfx_passwordfile():
    (pwd, file) = create_pfx_passwordfile('pytest.deleteme')
    assert len(pwd) == 12
    assert len(file) == len('pytest.deleteme.password.txt')
    assert os.path.isfile('pytest.deleteme.password.txt')
    os.remove('pytest.deleteme.password.txt')

# test full application execution - a generous view of 'unit' testing
def test_full_command_execution():
    subprocess.run(['./pkifly.py', 'ca', 'pytest top to bottom ca'], capture_output=True)
    assert os.path.isfile('pytest top to bottom ca.ca.key')
    assert os.path.isfile('pytest top to bottom ca.ca.crt')
    
    subprocess.run(['./pkifly.py', 'server', 'pytest top to bottom ca', 
                    '-s', 'pytest top to bottom server'], capture_output=True)
    assert os.path.isfile('pytest top to bottom server.key')
    os.remove('pytest top to bottom server.key')
    assert os.path.isfile('pytest top to bottom server.csr')
    os.remove('pytest top to bottom server.csr')
    assert os.path.isfile('pytest top to bottom server.crt')
    os.remove('pytest top to bottom server.crt')

    subprocess.run(['./pkifly.py', 'client', 'pytest top to bottom ca', 
                    '-c', 'pytest top to bottom client'], capture_output=True)
    assert os.path.isfile('pytest top to bottom client.key')
    os.remove('pytest top to bottom client.key')
    assert os.path.isfile('pytest top to bottom client.csr')
    os.remove('pytest top to bottom client.csr')
    assert os.path.isfile('pytest top to bottom client.crt')
    os.remove('pytest top to bottom client.crt')

    subprocess.run(['./pkifly.py', 'email', 'pytest top to bottom ca', 
                    '-e', 'py@test.su'], capture_output=True)
    assert os.path.isfile('py@test.su.key')
    os.remove('py@test.su.key')
    assert os.path.isfile('py@test.su.csr')
    os.remove('py@test.su.csr')
    assert os.path.isfile('py@test.su.crt')
    os.remove('py@test.su.crt')
    assert os.path.isfile('py@test.su.crt.p7b')
    os.remove('py@test.su.crt.p7b')
    assert os.path.isfile('py@test.su.key.pfx.password.txt')
    os.remove('py@test.su.key.pfx.password.txt')
    assert os.path.isfile('py@test.su.key.pfx')
    os.remove('py@test.su.key.pfx')
    # the test CA is no longer needed
    os.remove('pytest top to bottom ca.ca.key')
    os.remove('pytest top to bottom ca.ca.crt')
