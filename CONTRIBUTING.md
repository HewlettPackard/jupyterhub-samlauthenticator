<!---
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
--->
# Developing and Contributing

Get the code and create a virtual environment.

```sh
git clone {git@git-source}
cd samlauthenticator
virtualenv --python=python3.6 venv
```

Start the virtual environment and install dependencies

```sh
source venv/bin/activate
pip install -r requirements.txt
pip install -r test_requirements.txt
```

Make sure that unit tests run on your system and complete successfully.

```sh
pytest --cov=samlauthenticator --cov-report term-missing
```
The output should be something like this:
```
============================= test session starts ==============================
collected 45 items

tests/test_authenticator.py ............................................ [ 97%]
.                                                                        [100%]

Name                                     Stmts   Miss  Cover   Missing
----------------------------------------------------------------------
samlauthenticator/__init__.py                1      0   100%
samlauthenticator/samlauthenticator.py     241      2    99%   332, 440
----------------------------------------------------------------------
TOTAL                                      242      2    99%
========================== 45 passed in 1.00 seconds ===========================
```

Make your change, write your unit tests, then send a pull request. The Pull Request text MUST contain the Developer Certificate of Origin, which _should be_ prepopulated in the pull request text. Please note that the developer MUST sign off on the Pull Request and the developer MUST provide their full legal name and email address.
