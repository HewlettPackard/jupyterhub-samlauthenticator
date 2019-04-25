'''
(C) Copyright 2019 Hewlett Packard Enterprise Development LP

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
'''

from setuptools import setup

version = '0.0.2.7'

with open('requirements.txt', 'r') as req_file, \
        open('test_requirements.txt', 'r') as test_req_file, \
        open('README.md') as readme_file:
    versioned_reqs = req_file.read().split('\n')
    versioned_test_reqs = test_req_file.read().split('\n')

    readme_text = readme_file.read()

    setup(
        name='jupyterhub-samlauthenticator',
        version=version,
        description='SAML Authenticator for JupyterHub',
        long_description=readme_text,
        long_description_content_type="text/markdown",
        url='https://github.com/bluedatainc/jupyterhub-samlauthenticator',
        author='Tom Kelley',
        author_email='distortedsignal@gmail.com',
        license='MIT',
        packages=['samlauthenticator'],
        install_requires=versioned_reqs,
        classifiers=[
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: MIT License",
            "Operating System :: OS Independent",
        ],
        extras_require={"tests": versioned_test_reqs}
    )
