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

# Imports from python standard library
from base64 import b64decode
from datetime import datetime, timezone
from urllib.request import urlopen

import asyncio
import pwd
import subprocess

# Imports to work with JupyterHub
from jupyterhub.auth import Authenticator
from jupyterhub.utils import maybe_future
from jupyterhub.handlers.login import LoginHandler, LogoutHandler
from tornado import gen, web
from traitlets import Unicode, Bool

# Imports for me
from lxml import etree
import pytz
from signxml import XMLVerifier

class SAMLAuthenticator(Authenticator):
    metadata_filepath = Unicode(
        default_value='',
        allow_none=True,
        config=True,
        help='''
        A filepath to the location of the SAML IdP metadata. This is the most preferable
        option for presenting an IdP's metadata to the authenticator.
        '''
    )
    metadata_content = Unicode(
        default_value='',
        allow_none=True,
        config=True,
        help='''
        A fully-inlined version of the SAML IdP metadata. Mostly provided for testing,
        but if you want to use this for a "production-type" system, I'm not going to
        judge. This is preferred above getting metadata from a web-request, but not
        preferred above getting the metadata from a file.
        '''
    )
    metadata_url = Unicode(
        default_value='',
        allow_none=True,
        config=True,
        help='''
        A URL where the SAML Authenticator can find metadata for the SAML IdP. This is
        the least preferable method of providing the SAML IdP metadata to the
        authenticator, as it is both slow and vulnerable to Man in the Middle attacks,
        including DNS poisoning.
        '''
    )
    xpath_username_location = Unicode(
        default_value='//saml:NameID/text()',
        allow_none=True,
        config=True,
        help='''
        This is an XPath that specifies where the user's name or id is located in the
        SAML Assertion. This is partly for testing purposes, but there are cases where
        an administrator may want a user to be identified by their email address instead
        of an LDAP DN or another string that comes in the NameID field. The namespace
        bindings when executing the XPath will be as follows:

        {
            'ds'   : 'http://www.w3.org/2000/09/xmldsig#',
            'md'   : 'urn:oasis:names:tc:SAML:2.0:metadata',
            'saml' : 'urn:oasis:names:tc:SAML:2.0:assertion',
            'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol'
        }
        '''
    )
    login_post_field = Unicode(
        default_value='SAMLResponse',
        allow_none=False,
        config=True,
        help='''
        This value specifies what field in the SAML Post request contains the Base-64
        encoded SAML Response.
        '''
    )
    audience = Unicode(
        default_value=None,
        allow_none=True,
        config=True,
        help='''
        The SAML Audience must be configured in the SAML IdP. This value ensures that a
        SAML assertion cannot be used by a malicious service to authenticate to a naive
        service. If this value is not set in the configuration file or if the string
        provided is a "false-y" value in python, this will not be checked.
        '''
    )
    recipient = Unicode(
        default_value=None,
        allow_none=True,
        config=True,
        help='''
        The SAML Recipient must be configured in the SAML IdP. This value ensures that a
        SAML assertion cannot be used by a malicious service to authenticate to a naive
        service. If this value is not set in the configuration file or if the string
        provided is a "false-y" value in python, this will not be checked.
        '''
    )
    time_format_string = Unicode(
        default_value='%Y-%m-%dT%H:%M:%SZ',
        allow_none=False,
        config=True,
        help='''
        A time format string that complies with python's strftime()/strptime() behavior.
        For more information on this format, please read the information at the
        following link:

        https://docs.python.org/3/library/datetime.html#strftime-and-strptime-behavior

        '''
    )
    idp_timezone = Unicode(
        default_value='UTC',
        allow_none=True,
        config=True,
        help='''
        A timezone-specific string that uniquely identifies a timezone using pytz's
        timezone constructor. To view a list of options, import the package and
        inspect the `pytz.all_timezones` list. It is quite long. For more information
        on pytz, please read peruse the pip package:

        https://pypi.org/project/pytz/

        '''
    )
    shutdown_on_logout = Bool(
        default_value=False,
        allow_none=False,
        config=True,
        help='''
        If you would like to shutdown user servers on logout, you can enable this
        behavior with:

        c.SAMLAuthenticator.shutdown_on_logout = True

        Be careful with this setting because logging out one browser does not mean
        the user is no longer actively using their server from another machine.

        It is a little odd to have this property on the Authenticator object, but
        (for internal-detail-reasons) since we need to hand-craft the LogoutHandler
        class, this should be on the Authenticator.
        '''
    )
    slo_forwad_on_logout = Bool(
        default_value=True,
        allow_none=False,
        config=True,
        help='''
        To prevent forwarding users to the SLO URI on logout,
        set this parameter to False like so:

        c.SAMLAuthenticator.slo_forwad_on_logout = False
        '''
    )

    def _get_metadata_from_file(self):
        with open(self.metadata_filepath, 'r') as saml_metadata:
            return saml_metadata.read()

    def _get_metadata_from_config(self):
        return self.metadata_content

    def _get_metadata_from_url(self):
        with urlopen(self.metadata_url) as remote_metadata:
            return remote_metadata.read()

    def _get_preferred_metadata_from_source(self):
        if self.metadata_filepath:
            return self._get_metadata_from_file()

        if self.metadata_content:
            return self._get_metadata_from_config()

        if self.metadata_url:
            return self._get_metadata_from_url()

        return None

    def _log_exception_error(self, exception):
        self.log.warning('Exception: %s', str(exception))

    def _get_saml_doc_etree(self, data):
        saml_response = data.get(self.login_post_field, None)

        if not saml_response:
            # Failed to get the SAML Response from the posted data
            self.log.warning('Could not get SAML Response from post data')
            self.log.warning('Expected SAML response in field %s', self.login_post_field)
            self.log.warning('Posted login data %s', str(data))
            return None

        decoded_saml_doc = None

        try:
            decoded_saml_doc = b64decode(saml_response)
        except Exception as e:
            # There was a problem base64 decoding the xml document from the posted data
            self.log.warning('Got exception when attempting to decode SAML response')
            self.log.warning('Saml Response: %s', saml_response)
            self._log_exception_error(e)
            return None

        try:
            return etree.fromstring(decoded_saml_doc)
        except Exception as e:
            self.log.warning('Got exception when attempting to hydrate response to etree')
            self.log.warning('Saml Response: %s', decoded_saml_doc)
            self._log_exception_error(e)
            return None

    def _get_saml_metadata_etree(self):
        try:
            saml_metadata = self._get_preferred_metadata_from_source()
        except Exception as e:
            # There was a problem getting the SAML metadata
            self.log.warning('Got exception when attempting to read SAML metadata')
            self.log.warning('Ensure that EXACTLY ONE of metadata_filepath, ' +
                             'metadata_content, and metadata_url is populated')
            self._log_exception_error(e)
            return None

        if not saml_metadata:
            # There was a problem getting the SAML metadata
            self.log.warning('Got exception when attempting to read SAML metadata')
            self.log.warning('Ensure that EXACTLY ONE of metadata_filepath, ' +
                             'metadata_content, and metadata_url is populated')
            self.log.warning('SAML metadata was empty')
            return None

        metadata_etree = None

        try:
            metadata_etree = etree.fromstring(saml_metadata)
        except Exception as e:
            # Failed to parse SAML Metadata
            self.log.warning('Got exception when attempting to parse SAML metadata')
            self._log_exception_error(e)

        return metadata_etree

    def _verify_saml_signature(self, saml_metadata, decoded_saml_doc):
        xpath_with_namespaces = self._make_xpath_builder()
        find_cert = xpath_with_namespaces('//ds:KeyInfo/ds:X509Data/ds:X509Certificate/text()')
        cert_value = None

        try:
            cert_value = find_cert(saml_metadata)[0]
        except Exception as e:
            self.log.warning('Could not get cert value from saml metadata')
            self._log_exception_error(e)
            return None

        signed_xml = None
        try:
            signed_xml = XMLVerifier().verify(decoded_saml_doc, x509_cert=cert_value).signed_xml
        except Exception as e:
            self.log.warning('Failed to verify signature on SAML Response')
            self._log_exception_error(e)

        return signed_xml

    def _make_xpath_builder(self):
        namespaces = {
            'ds'   : 'http://www.w3.org/2000/09/xmldsig#',
            'md'   : 'urn:oasis:names:tc:SAML:2.0:metadata',
            'saml' : 'urn:oasis:names:tc:SAML:2.0:assertion',
            'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol'
        }

        def xpath_with_namespaces(xpath_str):
            return etree.XPath(xpath_str, namespaces=namespaces)

        return xpath_with_namespaces

    def _verify_saml_response_against_metadata(self, saml_metadata, signed_xml):
        xpath_with_namespaces = self._make_xpath_builder()

        find_entity_id = xpath_with_namespaces('//saml:Issuer/text()')
        find_metadata_entity_id = xpath_with_namespaces('//md:EntityDescriptor/@entityID')

        saml_metadata_entity_id_list = find_metadata_entity_id(saml_metadata)
        saml_resp_entity_id_list = find_entity_id(signed_xml)

        if saml_resp_entity_id_list and saml_metadata_entity_id_list:
            if saml_metadata_entity_id_list[0] != saml_resp_entity_id_list[0]:
                self.log.warning('Metadata entity id did not match the response entity id')
                self.log.warning('Metadata entity id: %s', saml_metadata_entity_id_list[0])
                self.log.warning('Response entity id: %s', saml_resp_entity_id_list[0])
                return False
        else:
            self.log.warning('The entity ID needs to be set in both the metadata and the SAML Response')
            if not saml_resp_entity_id_list:
                self.log.warning('The entity ID was not set in the SAML Response')
            if not saml_metadata_entity_id_list:
                self.log.warning('The entity ID was not set in the SAML metadata')
            return False

        return True

    def _verify_saml_response_against_configured_fields(self, signed_xml):
        xpath_with_namespaces = self._make_xpath_builder()

        if self.audience:
            find_audience = xpath_with_namespaces('//saml:Audience/text()')
            saml_resp_audience_list = find_audience(signed_xml)
            if saml_resp_audience_list:
                if saml_resp_audience_list[0] != self.audience:
                    self.log.warning('Configured audience did not match the response audience')
                    self.log.warning('Configured audience: %s', self.audience)
                    self.log.warning('Response audience: %s', saml_resp_audience_list[0])
                    return False
            else:
                self.log.warning('SAML Audience was set in authenticator config file, but not in SAML Response')
                return False

        if self.recipient:
            find_recipient = xpath_with_namespaces('//saml:SubjectConfirmationData/@Recipient')
            recipient_list = find_recipient(signed_xml)
            if recipient_list:
                if self.recipient != recipient_list[0]:
                    self.log.warning('Configured recipient did not match the response recipient')
                    self.log.warning('Configured recipient: %s', self.recipient)
                    self.log.warning('Response recipient: %s', recipient_list[0])
                    return False
            else:
                self.log.warning('Could not find recipient in SAML response')
                return False

        return True

    def _is_date_aware(self, created_datetime):
        return created_datetime.tzinfo is not None and \
            created_datetime.tzinfo.utcoffset(created_datetime) is not None

    def _verify_physical_constraints(self, signed_xml):
        xpath_with_namespaces = self._make_xpath_builder()

        find_not_before = xpath_with_namespaces('//saml:Conditions/@NotBefore')
        find_not_on_or_after = xpath_with_namespaces('//saml:Conditions/@NotOnOrAfter')

        not_before_list = find_not_before(signed_xml)
        not_on_or_after_list = find_not_on_or_after(signed_xml)

        if not_before_list and not_on_or_after_list:

            not_before_datetime = datetime.strptime(not_before_list[0], self.time_format_string)
            not_on_or_after_datetime = datetime.strptime(not_on_or_after_list[0], self.time_format_string)

            timezone_obj = None

            if not self._is_date_aware(not_before_datetime):
                timezone_obj = pytz.timezone(self.idp_timezone)
                not_before_datetime = timezone_obj.localize(not_before_datetime)

            if not self._is_date_aware(not_on_or_after_datetime):
                if not timezone_obj:
                    timezone_obj = pytz.timezone(self.idp_timezone)
                not_on_or_after_datetime = timezone_obj.localize(not_on_or_after_datetime)

            now = datetime.now(timezone.utc)

            if now < not_before_datetime or now >= not_on_or_after_datetime:
                self.log.warning('Bad timing condition')
                if now < not_before_datetime:
                    self.log.warning('Sent SAML Response before it was permitted')
                if now >= not_on_or_after_datetime:
                    self.log.warning('Sent SAML Response after it was permitted')
                return False
        else:
            self.log.warning('SAML assertion did not contain proper conditions')
            if not not_before_list:
                self.log.warning('SAML assertion must have NotBefore annotation in Conditions')
            if not not_on_or_after_list:
                self.log.warning('SAML assertion must have NotOnOrAfter annotation in Conditions')
            return False

        return True

    def _verify_saml_response_fields(self, saml_metadata, signed_xml):
        if not self._verify_saml_response_against_metadata(saml_metadata, signed_xml):
            self.log.warning('The SAML Assertion did not match the provided metadata')
            return False

        if not self._verify_saml_response_against_configured_fields(signed_xml):
            self.log.warning('The SAML Assertion did not match the configured values')
            return False

        if not self._verify_physical_constraints(signed_xml):
            self.log.warning('The SAML Assertion did not match the physical constraints')
            return False

        self.log.info('The SAML Assertion matched the configured values')
        return True

    def _test_valid_saml_response(self, saml_metadata, saml_doc):
        signed_xml = self._verify_saml_signature(saml_metadata, saml_doc)

        if signed_xml is None or len(signed_xml) == 0:
            self.log.warning('Failed to verify signature on SAML Response')
            return False, None

        return self._verify_saml_response_fields(saml_metadata, signed_xml), signed_xml

    def _get_username_from_saml_etree(self, signed_xml):
        xpath_with_namespaces = self._make_xpath_builder()

        xpath_fun = xpath_with_namespaces(self.xpath_username_location)
        xpath_result = xpath_fun(signed_xml)
        if xpath_result:
            return xpath_result[0]

        self.log.warning('Could not find name from name XPath')

        return None

    def _get_username_from_saml_doc(self, signed_xml, decoded_saml_doc):
        user_name = self._get_username_from_saml_etree(signed_xml)
        if user_name:
            return user_name

        self.log.info('Did not get user name from signed SAML Response')

        return self._get_username_from_saml_etree(decoded_saml_doc)

    def _optional_user_add(self, username):
        try:
            pwd.getpwnam(username)
            # Found the user, we don't need to create them
            return True
        except KeyError:
            # Return the `not` here because a 0 return indicates success and I want to
            # say something like "if adding the user is successful, return username"
            return not subprocess.call(['useradd', username])

    def _check_username_and_add_user(self, username):
        if self.validate_username(username) and \
                self.check_blacklist(username) and \
                self.check_whitelist(username):
            return self._optional_user_add(username)

        return False

    def _authenticate(self, handler, data):
        saml_doc_etree = self._get_saml_doc_etree(data)

        if saml_doc_etree is None or len(saml_doc_etree) == 0:
            self.log.error('Error getting decoded SAML Response')
            return None

        saml_metadata_etree = self._get_saml_metadata_etree()

        if saml_metadata_etree is None or len(saml_metadata_etree) == 0:
            self.log.error('Error getting SAML Metadata')
            return None

        valid_saml_response, signed_xml = self._test_valid_saml_response(saml_metadata_etree, saml_doc_etree)

        if valid_saml_response:
            self.log.debug('Authenticated user using SAML')
            username = self._get_username_from_saml_doc(signed_xml, saml_doc_etree)
            username = self.normalize_username(username)
            self.log.debug('Optionally create and return user: ' + username)
            username_add_result = self._check_username_and_add_user(username)
            if username_add_result:
                return username

            self.log.error('Failed to add user')
            return None

        self.log.error('Error validating SAML response')
        return None

    @gen.coroutine
    def authenticate(self, handler, data):
        return self._authenticate(handler, data)

    def get_handlers(authenticator_self, app):

        # This is maybe too cute by half, but I want to run with it.
        def get_redirect_from_metadata_and_redirect(element_name, handler_self):
            saml_metadata_etree = authenticator_self._get_saml_metadata_etree()

            handler_self.log.debug('Got metadata etree')

            if saml_metadata_etree is None or len(saml_metadata_etree) == 0:
                handler_self.log.error('Error getting SAML Metadata')
                raise web.HTTPError(500)

            handler_self.log.debug('Got valid metadata etree')

            xpath_with_namespaces = authenticator_self._make_xpath_builder()

            binding = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
            final_xpath = '//' + element_name + '[@Binding=\'' + binding + '\']/@Location'
            handler_self.log.debug('Final xpath is: ' + final_xpath)

            redirect_link_getter = xpath_with_namespaces(final_xpath)

            # Here permanent MUST BE False - otherwise the /hub/logout GET will not be fired
            # by the user's browser.
            handler_self.redirect(redirect_link_getter(saml_metadata_etree)[0], permanent=False)


        class SAMLLoginHandler(LoginHandler):

            async def get(login_handler_self):
                login_handler_self.log.info('Starting SP-initiated SAML Login')
                get_redirect_from_metadata_and_redirect('md:SingleSignOnService', login_handler_self)

        class SAMLLogoutHandler(LogoutHandler):

            async def _shutdown_servers(self, user):
                active_servers = [
                    name
                    for (name, spawner) in user.spawners.items()
                    if spawner.active and not spawner.pending
                ]
                if active_servers:
                    self.log.debug("Shutting down %s's servers", user.name)
                    futures = []
                    for server_name in active_servers:
                        futures.append(maybe_future(self.stop_single_user(user, server_name)))
                    await asyncio.gather(*futures)

            def _backend_logout_cleanup(self, name):
                self.log.info("User logged out: %s", name)
                self.clear_login_cookie()
                self.statsd.incr('logout')

            async def _shutdown_servers_and_backend_cleanup(self):
                user = self.current_user
                if user:
                    await self._shutdown_servers(user)

            async def get(logout_handler_self):
                if authenticator_self.shutdown_on_logout:
                    logout_handler_self.log.debug('Shutting down servers during SAML Logout')
                    await logout_handler_self._shutdown_servers_and_backend_cleanup()

                if logout_handler_self.current_user:
                    logout_handler_self._backend_logout_cleanup(logout_handler_self.current_user.name)

                if authenticator_self.slo_forwad_on_logout:
                    get_redirect_from_metadata_and_redirect('md:SingleLogoutService', logout_handler_self)
                else:
                    html = logout_handler_self.render_template('logout.html')
                    logout_handler_self.finish(html)

        return [('/login', SAMLLoginHandler),
                ('/hub/login', SAMLLoginHandler),
                ('/logout', SAMLLogoutHandler),
                ('/hub/logout', SAMLLogoutHandler)]
