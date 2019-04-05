

from setuptools import setup

version = '0.0.1'

with open('requirements.txt', 'r') as req_file, open('test_requirements.txt', 'r') as test_req_file:
    versioned_reqs = req_file.read().split('\n')
    versioned_test_reqs = test_req_file.read().split('\n')

    def get_req_from_versioned_req(versioned_req):
        return versioned_req.split('==')[0]

    unversioned_reqs = [get_req_from_versioned_req(requirement) for requirement in versioned_reqs]
    unversioned_test_reqs = [get_req_from_versioned_req(requirement) for requirement in versioned_test_reqs]

    setup(
        name='distortedsignal-samlauthenticator',
        version=version,
        description='SAML Authenticator for JupyterHub',
        url='https://github.com/distortedsignal/samlauthenticator',
        author='Tom Kelley',
        author_email='distortedsignal@gmail.com',
        license='MIT',
        packages=['samlauthenticator'],
        install_requires=unversioned_reqs,
        extras_require={"tests": unversioned_test_reqs}
    )
