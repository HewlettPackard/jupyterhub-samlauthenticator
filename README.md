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
# SAMLAuthenticator for JupyterHub

[![Build Status](https://travis-ci.com/bluedatainc/jupyterhub-samlauthenticator.svg?branch=master)](https://travis-ci.com/bluedatainc/jupyterhub-samlauthenticator)
[![codecov](https://codecov.io/gh/bluedatainc/jupyterhub-samlauthenticator/branch/master/graph/badge.svg)](https://codecov.io/gh/bluedatainc/jupyterhub-samlauthenticator)
[![PyPI](https://img.shields.io/pypi/v/jupyterhub-samlauthenticator.svg)](https://pypi.python.org/pypi/jupyterhub-samlauthenticator)

This is a SAML Authenticator for JupyterHub. With this code (and a little elbow grease), you can integrate your JupyterHub instance with a previously setup SAML Single Sign-on system!

## Set Up

This set up section assumes that python 3.6+, pip, and JupyterHub are already set up on the target machine.

If the `jupyterhub_config.py` file has not been generated, this would be a good time to generate it. For a primer on generating the config file, read [here](https://jupyterhub.readthedocs.io/en/stable/getting-started/config-basics.html).

Currently, this Authenticator relies on the IdP being set up beforehand. This Authenticator ONLY supports HTTP-POST based authentication, and ONLY receives SAML Responses at the `/login` and `/hub/login` urls. There are currently no plans to support HTTP-Redirect based authentication or SOAP-based services.

### Installation

In the context in which JupyterHub will be run, install the SAML Authenticator.

```sh
pip install jupyterhub-samlauthenticator
```

### Configuration

Open the `jupyterhub_config.py` file in an available text editor.

Change the configured value of the `authenticator_class` to be `samlauthenticator.SAMLAuthenticator`.

Configure one of the accepted metadata sources. The SAMLAuthenticator can get metadata from three sources:
1. The most preferable option is to configure the SAMLAuthenticator to use a metadata file. This can be done by setting the `metadata_filepath` field of the `SAMLAuthenticator` class to the *_fully justified filepath_* of the metadata file.
1. Another option is to dump the full metadata xml into the JupyterHub configuration file. This is not great because it clutters up the configuration file with a lot of extraneous data. This can be done by setting the `metadata_content` field of the SAMLAuthenticator class.
1. Finally, the least preferable option of the three is to get the metadata from a web request each time a user attempts to log into the server. This is _not recommended_ because DNS poisoning attacks could let a malicious actor impersonate the IdP and gain access to any user private files on the server. However, if this is the configuration that is required, set the `metadata_url` field and the metadata will be refreshed every time a user attempts to log in to the JupyterHub server.

This is all the configuration the Authenticator _usually_ requires, but there are more configuration options to go through.

If the user that should be created and logged in from a given SAML Response is _not_ specified by the NameID element in the SAML Assertion, an alternate field can be specified. Replace the `xpath_username_location` field in the `SAMLAuthenticator` with an XPath that points to the desired field in the SAML Assertion. Note that this value must be able to be compiled to an XPath by Python's `lxml` module. The namespaces that will be present for this XPath are as follows:

```py
{
    'ds'   : 'http://www.w3.org/2000/09/xmldsig#',
    'saml' : 'urn:oasis:names:tc:SAML:2.0:assertion',
    'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol'
}
```

The SAMLAuthenticator expects the SAML Response to be in the `SAMLResponse` field of the POST request that the user makes to authenticate themselves. If this expectation does not hold for a given environment, then the `login_post_field` property of the SAMLAuthenticator should be set to the correct field.

A SAML Audience and Recipient can be defined on the IdP to prevent a malicious service from using a SAML Response to inappropriately authenticate to non-malicious services. If either of these values is set by the IdP, they can be checked by setting the `audience` and `recipient` fields on the SAMLAuthenticator.

By default, the SAMLAuthenticator expects the `NotOnOrAfter` and `NotBefore` fields to be of the format `{four-digit-year}-{two-digit-month}-{two-digit-day}T{two-digit-24-hour-hour-value}:{two-digit-minute}:{two-digit-second}Z` where T and Z are character literals. If this is not a good assumption, an alternate time string can be provided by setting the `time_format_string` value of the SAMLAuthenticator. This string will be consumed by Python's [`datetime.strptime()`](https://docs.python.org/3.6/library/datetime.html#datetime.datetime.strptime), so it might be helpful to read up on [the `strftime()` and `strptime()` behavior](https://docs.python.org/3.6/library/datetime.html#strftime-strptime-behavior).

If the timezone being passed in by the `NotOnOrAfter` and `NotBefore` fields cannot be read by `strptime()`, don't fear! So long as the timezone that the IdP resides in is known, it's possible to set the IdP's timezone. Set the `idp_timezone` field to a string that uniquely designates a timezone that can be looked up by [`pytz`](https://pypi.org/project/pytz/), and login should be able to continue.

The following two configurations are _usually_ on logout handlers, but because SAML is a special login method, we put these on the Authenticator.

If the user's servers should be shut down when they logout, set `shutdown_on_logout` to `True`. This stops all servers that the user was running as part of their session. It is a somewhat dangerous to set this option to `True` because a user may not be done with computations that they are running on those servers.

The SAMLAuthenticator _usually_ attempts to forward users to the SLO URI set in the SAML Metadata. If this is not the desired behavior for whatever reason, set `slo_forward_on_logout` to `False`. This will change the page the user is forwarded to on logout from the page specified in the xml metadata to the standard jupyterhub logout page.

#### Example Configurations

```py
# A simple example configuration.
## Class for authenticating users.
c.JupyterHub.authenticator_class = 'samlauthenticator.SAMLAuthenticator'

# Where the SAML IdP's metadata is stored.
c.SAMLAuthenticator.metadata_filepath = '/etc/jupyterhub/metadata.xml'
```

```py
# A complex example configuration.
## Class for authenticating users.
c.JupyterHub.authenticator_class = 'samlauthenticator.SAMLAuthenticator'

# Where the SAML IdP's metadata is stored.
c.SAMLAuthenticator.metadata_filepath = '/etc/jupyterhub/metadata.xml'

# A field was placed in the SAML Response that contains the user's first name and last name separated by a period.
# Let's use that for the username.
c.SAMLAuthenticator.xpath_username_location = '//saml:Attribute[@Name="DottedName"]/saml:AttributeValue/text()'

# The IdP is sending the SAML Response in a field named 'R'
c.SAMLAuthenticator.login_post_field = 'R'

# We want to make sure that we're the only one receiving this SAML Response
c.SAMLAuthenticator.audience = 'jupyterhub.myorg.com'
c.SAMLAuthenticator.recipient = 'https://jupyterhub.myorg.com/hub/login'

# The IdP is sending dates in the form 'Tue July 20, 2020 18:30:21'
c.SAMLAuthenticator.time_format_string = '%a %B %d, %Y %H:%M%S'

# Looks like we can't get the timezone from the previous string - we need to set it
c.SAMLAuthenticator.idp_timezone = 'US/Eastern'

# Shutdown all servers when the user logs out
c.SAMLAuthenticator.shutdown_on_logout = True

# Don't send the user to the SLO address on logout
c.SAMLAuthenticator.slo_forwad_on_logout = False
```

## Developing and Contributing

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
