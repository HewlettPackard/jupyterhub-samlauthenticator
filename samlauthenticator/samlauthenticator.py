

# Imports from python standard library
from base64 import b64decode
from datetime import datetime, timezone
from urllib.request import urlopen

import pwd
import subprocess

# Imports to work with JupyterHub
from jupyterhub.auth import Authenticator
from tornado import gen
from traitlets import Unicode, List

# Imports for me
from signxml import XMLVerifier
from lxml import etree

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
    xpath_user_group_location = List(
        default_value=[],
        allow_none=True,
        config=True,
        help='''
        This is a list of XPaths that specify where in the SAML Response the
        Authenticator should be looking to find group information for the authenticated
        user. This should ONLY be used if ALL users with a given group need to have
        access to the same workspace. The namespace bindings when executing the XPaths
        will be as follows:

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
        default_value='%Y-%m-%dT%H:%M:%S%Z',
        allow_none=False,
        config=True,
        help='''
        A time format string that complies with python's strftime()/strptime() behavior.
        For more information on this format, please read the information at the
        following link:

        https://docs.python.org/3/library/datetime.html#strftime-and-strptime-behavior

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
                self.log.error('Metadata entity id did not match the response entity id')
                self.log.error('Metadata entity id: %s', saml_metadata_entity_id_list[0])
                self.log.error('Response entity id: %s', saml_resp_entity_id_list[0])
                return False
        else:
            self.log.error('The entity ID needs to be set in both the metadata and the SAML Response')
            if not saml_resp_entity_id_list:
                self.log.error('The entity ID was not set in the SAML Response')
            if not saml_metadata_entity_id_list:
                self.log.error('The entity ID was not set in the SAML metadata')
            return False

        return True

    def _verify_saml_response_against_configured_fields(self, signed_xml):
        xpath_with_namespaces = self._make_xpath_builder()

        if self.audience:
            find_audience = xpath_with_namespaces('//saml:Audience/text()')
            saml_resp_audience_list = find_audience(signed_xml)
            if saml_resp_audience_list:
                if saml_resp_audience_list[0] != self.audience:
                    self.log.error('Configured audience did not match the response audience')
                    self.log.error('Configured audience: %s', self.audience)
                    self.log.error('Response audience: %s', saml_resp_audience_list[0])
                    return False
            else:
                self.log.error('SAML Audience was set in authenticator config file, but not in SAML Response')
                return False

        if self.recipient:
            find_recipient = xpath_with_namespaces('//saml:SubjectConfirmationData@Recipient')
            recipient_list = find_recipient(signed_xml)
            if recipient_list:
                if self.recipient != recipient_list[0]:
                    self.log.error('Configured recipient did not match the response recipient')
                    self.log.error('Configured recipient: %s', self.recipient)
                    self.log.error('Response recipient: %s', recipient_list[0])
                    return False
            else:
                self.log.error('Could not find recipient in SAML response')
                return False

        return True

    def _verify_physical_constraints(self, signed_xml):
        xpath_with_namespaces = self._make_xpath_builder()

        find_not_before = xpath_with_namespaces('//saml:Conditions/@NotBefore')
        find_not_on_or_after = xpath_with_namespaces('//saml:Conditions/@NotOnOrAfter')

        not_before_list = find_not_before(signed_xml)
        not_on_or_after_list = find_not_on_or_after(signed_xml)

        if not_before_list and not_on_or_after_list:
            not_before_datetime = datetime.strptime(not_before_list[0], self.time_format_string)
            not_on_or_after_datetime = datetime.strptime(not_on_or_after_list[0], self.time_format_string)
            not_before_datetime = not_before_datetime.replace(tzinfo=timezone.utc)
            not_on_or_after_datetime = not_on_or_after_datetime.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            if now < not_before_datetime or now >= not_on_or_after_datetime:
                self.log.error('Bad timing condition')
                if now < not_before_datetime:
                    self.log.error('Sent SAML Response before it was permitted')
                if now >= not_on_or_after_datetime:
                    self.log.error('Sent SAML Response after it was permitted')
                return False
        else:
            self.log.error('SAML assertion did not contain proper conditions')
            if not not_before_list:
                self.log.error('SAML assertion must have NotBefore annotation in Conditions')
            if not not_on_or_after_list:
                self.log.error('SAML assertion must have NotOnOrAfter annotation in Conditions')
            return False

        return True

    def _verify_saml_response_fields(self, saml_metadata, signed_xml):
        # TODO: this
        if not self._verify_saml_response_against_metadata(saml_metadata, signed_xml):
            self.log.error('The SAML Assertion did not match the provided metadata')
            return False

        if not self._verify_saml_response_against_configured_fields(signed_xml):
            self.log.error('The SAML Assertion did not match the configured values')
            return False

        if not self._verify_physical_constraints(signed_xml):
            self.log.error('The SAML Assertion did not match the physical constraints')
            return False

        self.log.info('The SAML Assertion matched the configured values')
        return True

    def _test_valid_saml_response(self, saml_metadata, decoded_saml_doc):
        signed_xml = self._verify_saml_signature(saml_metadata, decoded_saml_doc)

        if not signed_xml:
            self.log.error('Failed to verify signature on SAML Response')
            return False, None

        return self._verify_saml_response_fields(saml_metadata, signed_xml), signed_xml

    def _get_username_from_signed_saml_doc(self, signed_xml):
        xpath_with_namespaces = self._make_xpath_builder()

        for xpath_str in self.xpath_user_group_location:
            xpath_fun = xpath_with_namespaces(xpath_str)
            xpath_result = xpath_fun(signed_xml)
            if xpath_result:
                return xpath_result[0]

        self.log.info('Did not get user location from SAML Response group XPaths')

        xpath_fun = xpath_with_namespaces(self.xpath_username_location)
        xpath_result = xpath_fun(signed_xml)
        if xpath_result:
            return xpath_result[0]

        self.log.info('Could not find name from name XPath')

        return None

    def _get_username_from_decoded_saml_doc(self, decoded_saml_doc):
        xpath_with_namespaces = self._make_xpath_builder()

        for xpath_str in self.xpath_user_group_location:
            xpath_fun = xpath_with_namespaces(xpath_str)
            xpath_result = xpath_fun(decoded_saml_doc)
            if xpath_result:
                return xpath_result[0]

        self.log.info('Did not get user location from SAML Response group XPaths in decoded doc')

        xpath_fun = xpath_with_namespaces(self.xpath_username_location)
        xpath_result = xpath_fun(decoded_saml_doc)
        if xpath_result:
            return xpath_result[0]

        self.log.error('Failed to find valid user name')

        return None

    def _get_username_from_saml_doc(self, signed_xml, decoded_saml_doc):
        user_name = self._get_username_from_signed_saml_doc(signed_xml)
        if user_name:
            return user_name

        self.log.info('Did not get user name from signed SAML Response')

        return self._get_username_from_decoded_saml_doc(decoded_saml_doc)

    def _optional_user_add(self, username):
        try:
            pwd.getpwnam(username)
            # Found the user, we don't need to create them
            return True
        except KeyError:
            # Return the `not` here because a 0 return indicates success and I want to
            # say something like "if adding the user is successful, return username"
            return not subprocess.call(['useradd', username])

    @gen.coroutine
    def authenticate(self, handler, data):
        saml_doc_etree = self._get_saml_doc_etree(data)
        
        if not saml_doc_etree:
            self.log.error('Error getting decoded SAML Response')
            return None

        saml_metadata_etree = self._get_saml_metadata_etree()

        if not saml_metadata_etree:
            self.log.error('Error getting SAML Metadata')
            return None

        valid_saml_response, signed_xml = self._test_valid_saml_response(saml_metadata_etree, saml_doc_etree)

        if valid_saml_response:
            self.log.debug('Authenticated user using SAML')
            Un = self._get_username_from_saml_doc(signed_xml, saml_doc_etree)
            self.log.debug('Optionally create and return user: ' + Un)
            if self._optional_user_add(Un):
                return Un
            else:
                self.log.error('Failed to add user')
                return None

        self.log.error('Error validating SAML response')
        return None
