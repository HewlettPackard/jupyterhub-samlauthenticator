'''
(C) Copyright 2019 Hewlett Packard Enterprise Development LP

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the 'Software'),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
'''
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

import pytest
import unittest

from samlauthenticator import SAMLAuthenticator

from lxml import etree
from signxml import XMLVerifier
from tornado.web import HTTPError

from . import test_constants


class TestMetadataRetrieval(unittest.TestCase):
    # TODO: move metadata xml inside this object
    def _test_high_level_metadata_retrieval_functions(self, authenticator):
        assert authenticator._get_preferred_metadata_from_source() == test_constants.sample_metadata_xml

        metadata_etree = authenticator._get_saml_metadata_etree()
        local_etree = etree.fromstring(test_constants.sample_metadata_xml)

        assert etree.tostring(metadata_etree) == etree.tostring(local_etree)

    def _test_readable_mock(self, authenticator, mock_obj):
        # Make sure that we called this from inside a context handler
        # so that if it exits unexpectedly, we don't have to do manual cleanup
        mock_obj().__enter__.assert_called_once()
        mock_obj().__exit__.assert_called_once()

        self._test_high_level_metadata_retrieval_functions(authenticator)

    @patch('samlauthenticator.samlauthenticator.open')
    def test_file_read(self, mock_fileopen):
        entered_obj = MagicMock()
        entered_obj.read.return_value = test_constants.sample_metadata_xml
        mock_fileopen().__enter__.return_value = entered_obj

        a = SAMLAuthenticator()
        a.metadata_url = 'bad_data'
        a.metadata_content = 'bad_data'
        a.metadata_filepath = '/completely/legitimate/filepath'

        assert a._get_metadata_from_file() == test_constants.sample_metadata_xml
        # Check that we have, at least once, called open with the provided filepath
        # TODO: Figure out how to do this so we can use 'assert_called_once_with'
        mock_fileopen.assert_any_call(a.metadata_filepath, 'r')
        # Check that we're reading the file
        entered_obj.read.assert_called_once()

        self._test_readable_mock(a, mock_fileopen)

    def test_metadata_field(self):
        a = SAMLAuthenticator()
        a.metadata_url = 'bad_data'
        a.metadata_content = test_constants.sample_metadata_xml

        assert a._get_metadata_from_config() == test_constants.sample_metadata_xml
        self._test_high_level_metadata_retrieval_functions(a)

    @patch('samlauthenticator.samlauthenticator.urlopen')
    def test_metadata_url(self, mock_urlopen):
        entered_obj = MagicMock()
        entered_obj.read.return_value = test_constants.sample_metadata_xml
        mock_urlopen().__enter__.return_value = entered_obj

        a = SAMLAuthenticator()
        a.metadata_url = 'http://foo'

        # Check that we're getting the right value
        assert a._get_metadata_from_url() == test_constants.sample_metadata_xml
        # Check that we have, at least once, called open with the provided url
        # TODO: Figure out how to do this so we can use 'assert_called_once_with'
        mock_urlopen.assert_any_call(a.metadata_url)
        # Check that we're reading the file
        entered_obj.read.assert_called_once()

        self._test_readable_mock(a, mock_urlopen)

    @patch('samlauthenticator.samlauthenticator.open')
    def test_file_fail(self, mock_fileopen):
        entered_obj = MagicMock()
        entered_obj.read.side_effect = IOError('Fake IO Error')
        mock_fileopen().__enter__.return_value = entered_obj

        a = SAMLAuthenticator()
        a.metadata_url = 'bad_data'
        a.metadata_content = 'bad_data'
        a.metadata_filepath = '/completely/illegitimate/filepath'

        with pytest.raises(IOError):
            a._get_metadata_from_file()

        with pytest.raises(IOError):
            a._get_preferred_metadata_from_source()

        assert a._get_saml_metadata_etree() is None

    @patch('samlauthenticator.samlauthenticator.urlopen')
    def test_urlopen_fail(self, mock_urlopen):
        entered_obj = MagicMock()
        entered_obj.read.side_effect = IOError('Fake IO Error')
        mock_urlopen().__enter__.return_value = entered_obj

        a = SAMLAuthenticator()
        a.metadata_url = 'http://foo'

        with pytest.raises(IOError):
            a._get_metadata_from_url()

        with pytest.raises(IOError):
            a._get_preferred_metadata_from_source()

        assert a._get_saml_metadata_etree() is None

    def test_no_metadata_configured(self):
        a = SAMLAuthenticator()
        assert a._get_preferred_metadata_from_source() is None

        assert a._get_saml_metadata_etree() is None

    def test_malformed_metadata(self):
        a = SAMLAuthenticator()
        bad_xml = 'not an xml document'
        a.metadata_content = bad_xml

        assert a._get_metadata_from_config() == bad_xml
        assert a._get_preferred_metadata_from_source() == bad_xml
        assert a._get_saml_metadata_etree() is None


class TestSAMLDocRetrieval(unittest.TestCase):
    # TODO: move SAMLResponse inside this object
    def test_get_saml_doc_etree(self):
        # We expect the SAML Response to be coming in base 64 encoded
        a = SAMLAuthenticator()
        fake_data = {a.login_post_field: test_constants.b64encoded_response_xml}

        faked_etree = a._get_saml_doc_etree(fake_data)
        real_etree = etree.fromstring(test_constants.sample_response_xml)

        assert etree.tostring(faked_etree) == etree.tostring(real_etree)

    def test_get_saml_doc_different_location(self):
        a = SAMLAuthenticator()
        a.login_post_field = 'test'
        fake_data = {a.login_post_field: test_constants.b64encoded_response_xml}

        faked_etree = a._get_saml_doc_etree(fake_data)
        real_etree = etree.fromstring(test_constants.sample_response_xml)

        assert etree.tostring(faked_etree) == etree.tostring(real_etree)

    def test_with_failed_get(self):
        a = SAMLAuthenticator()
        fake_data = {}

        assert a._get_saml_doc_etree(fake_data) is None

    def test_bad_decode(self):
        a = SAMLAuthenticator()
        fake_data = {a.login_post_field: 'this is not base 64 encoded data'}

        assert a._get_saml_doc_etree(fake_data) is None

    @patch('samlauthenticator.samlauthenticator.b64decode')
    def test_not_valid_xml(self, mock_b64decode):
        a = SAMLAuthenticator()
        fake_data = {a.login_post_field: 'this string isn\'t important'}

        mock_b64decode.return_value = 'bad xml string'

        assert a._get_saml_doc_etree(fake_data) is None


class TestValidSamlResponse(unittest.TestCase):
    response_etree = etree.fromstring(test_constants.sample_response_xml)
    metadata_etree = etree.fromstring(test_constants.sample_metadata_xml)
    verified_signed_xml = XMLVerifier().verify(response_etree, x509_cert=test_constants.x509_cert).signed_xml

    @patch('samlauthenticator.samlauthenticator.datetime')
    def test_valid_saml_auth(self, mock_datetime):
        mock_datetime.now.return_value = datetime(2019, 4, 9, 21, 35, 0, tzinfo=timezone.utc)
        mock_datetime.strptime = datetime.strptime

        a = SAMLAuthenticator()

        signed_xml = a._verify_saml_signature(self.metadata_etree, self.response_etree)

        assert etree.tostring(signed_xml) == etree.tostring(self.verified_signed_xml)

        response_is_valid, signed_xml = a._test_valid_saml_response(self.metadata_etree, self.response_etree)

        assert response_is_valid
        # Check the signed xml is the subset of the xml that is returned by signxml
        assert etree.tostring(signed_xml) == etree.tostring(self.verified_signed_xml)

    def test_tampered_saml_response(self):
        a = SAMLAuthenticator()
        tampered_etree = etree.fromstring(test_constants.tampered_sample_response_xml)

        bad_signed_xml = a._verify_saml_signature(self.metadata_etree, tampered_etree)

        assert bad_signed_xml is None

        response_is_valid, signed_xml = a._test_valid_saml_response(self.metadata_etree, tampered_etree)

        assert not response_is_valid
        assert signed_xml is None

    def test_no_metadata_cert(self):
        a = SAMLAuthenticator()
        no_cert_metadata_etree = etree.fromstring(test_constants.sample_metadata_no_cert_xml)

        bad_signed_xml = a._verify_saml_signature(no_cert_metadata_etree, self.response_etree)

        assert bad_signed_xml is None

        response_is_valid, signed_xml = a._test_valid_saml_response(no_cert_metadata_etree, self.response_etree)

        assert not response_is_valid
        assert signed_xml is None

    def test_metadata_entity_no_match(self):
        a = SAMLAuthenticator()
        tampered_metadata_etree = etree.fromstring(test_constants.sample_metadata_tampered_entity)

        assert a._verify_saml_response_against_metadata(tampered_metadata_etree, self.verified_signed_xml) is False

        assert a._verify_saml_response_fields(tampered_metadata_etree, self.verified_signed_xml) is False

        response_is_valid, signed_xml = a._test_valid_saml_response(tampered_metadata_etree, self.response_etree)

        assert not response_is_valid
        assert etree.tostring(signed_xml) == etree.tostring(self.verified_signed_xml)

    def test_metadata_no_entity(self):
        a = SAMLAuthenticator()
        no_metadata_entity_etree = etree.fromstring(test_constants.sample_metadata_no_entity)

        assert a._verify_saml_response_against_metadata(no_metadata_entity_etree, self.verified_signed_xml) is False

        assert a._verify_saml_response_fields(no_metadata_entity_etree, self.verified_signed_xml) is False

        response_is_valid, signed_xml = a._test_valid_saml_response(no_metadata_entity_etree, self.response_etree)

        assert not response_is_valid
        assert etree.tostring(signed_xml) == etree.tostring(self.verified_signed_xml)

    def test_assertion_no_issuer(self):
        a = SAMLAuthenticator()

        tampered_etree = etree.fromstring(test_constants.tampered_assertion_no_issuer)

        assert not a._verify_saml_response_against_metadata(self.metadata_etree, tampered_etree)
        assert not a._verify_saml_response_fields(self.metadata_etree, tampered_etree)

    def test_signed_xml_bad_audience(self):
        a = SAMLAuthenticator()
        a.audience = '''bad_audience'''

        assert not a._verify_saml_response_against_configured_fields(self.verified_signed_xml)
        assert not a._verify_saml_response_fields(self.metadata_etree, self.verified_signed_xml)

        response_is_valid, signed_xml = a._test_valid_saml_response(self.metadata_etree, self.response_etree)
        assert not response_is_valid
        # We will get the signed xml back, but the response is not valid, so it doesn't really matter
        assert etree.tostring(self.verified_signed_xml) == etree.tostring(signed_xml)

    def test_signed_xml_no_audience(self):
        a = SAMLAuthenticator()
        a.audience = '''audience_should_exist'''

        tampered_etree = etree.fromstring(test_constants.tampered_assertion_no_audience)

        assert not a._verify_saml_response_against_configured_fields(tampered_etree)
        assert not a._verify_saml_response_fields(self.metadata_etree, tampered_etree)

    @patch('samlauthenticator.samlauthenticator.datetime')
    def test_signed_xml_good_audience(self, mock_datetime):
        mock_datetime.now.return_value = datetime(2019, 4, 9, 21, 35, 0, tzinfo=timezone.utc)
        mock_datetime.strptime = datetime.strptime

        a = SAMLAuthenticator()
        a.audience = '''{audience}'''

        assert a._verify_saml_response_against_configured_fields(self.verified_signed_xml)
        assert a._verify_saml_response_fields(self.metadata_etree, self.verified_signed_xml)

        response_is_valid, signed_xml = a._test_valid_saml_response(self.metadata_etree, self.response_etree)
        assert response_is_valid
        assert etree.tostring(self.verified_signed_xml) == etree.tostring(signed_xml)

    @patch('samlauthenticator.samlauthenticator.datetime')
    def test_signed_xml_good_recipient(self, mock_datetime):
        mock_datetime.now.return_value = datetime(2019, 4, 9, 21, 35, 0, tzinfo=timezone.utc)
        mock_datetime.strptime = datetime.strptime

        a = SAMLAuthenticator()
        a.recipient = '''{recipient}'''

        assert a._verify_saml_response_against_configured_fields(self.verified_signed_xml)
        assert a._verify_saml_response_fields(self.metadata_etree, self.verified_signed_xml)

        response_is_valid, signed_xml = a._test_valid_saml_response(self.metadata_etree, self.response_etree)
        assert response_is_valid
        assert etree.tostring(self.verified_signed_xml) == etree.tostring(signed_xml)

    def test_signed_xml_bad_recipient(self):
        a = SAMLAuthenticator()
        a.recipient = 'bad_recipient'

        assert not a._verify_saml_response_against_configured_fields(self.verified_signed_xml)
        assert not a._verify_saml_response_fields(self.metadata_etree, self.verified_signed_xml)

        response_is_valid, signed_xml = a._test_valid_saml_response(self.metadata_etree, self.response_etree)
        assert not response_is_valid
        assert etree.tostring(self.verified_signed_xml) == etree.tostring(signed_xml)

    def test_signed_xml_no_recipient(self):
        a = SAMLAuthenticator()
        a.recipient = 'unimportant_recipient'

        tampered_etree = etree.fromstring(test_constants.tampered_assertion_no_recipient)

        assert not a._verify_saml_response_against_configured_fields(tampered_etree)
        assert not a._verify_saml_response_fields(self.metadata_etree, tampered_etree)

    @patch('samlauthenticator.samlauthenticator.datetime')
    def test_now_before_allowed(self, mock_datetime):
        mock_datetime.now.return_value = datetime(2018, 4, 9, 21, 35, 0, tzinfo=timezone.utc)
        mock_datetime.strptime = datetime.strptime

        a = SAMLAuthenticator()

        assert not a._verify_physical_constraints(self.verified_signed_xml)
        assert not a._verify_saml_response_fields(self.metadata_etree, self.verified_signed_xml)

        response_is_valid, signed_xml = a._test_valid_saml_response(self.metadata_etree, self.response_etree)
        assert not response_is_valid
        assert etree.tostring(self.verified_signed_xml) == etree.tostring(signed_xml)

    @patch('samlauthenticator.samlauthenticator.datetime')
    def test_now_after_allowed(self, mock_datetime):
        mock_datetime.now.return_value = datetime(2020, 4, 9, 21, 35, 0, tzinfo=timezone.utc)
        mock_datetime.strptime = datetime.strptime

        a = SAMLAuthenticator()

        assert not a._verify_physical_constraints(self.verified_signed_xml)
        assert not a._verify_saml_response_fields(self.metadata_etree, self.verified_signed_xml)

        response_is_valid, signed_xml = a._test_valid_saml_response(self.metadata_etree, self.response_etree)
        assert not response_is_valid
        assert etree.tostring(self.verified_signed_xml) == etree.tostring(signed_xml)

    def test_no_not_on_or_after(self):
        a = SAMLAuthenticator()

        tampered_etree = etree.fromstring(test_constants.tampered_assertion_no_on_or_after)

        assert not a._verify_physical_constraints(tampered_etree)
        assert not a._verify_saml_response_fields(self.metadata_etree, tampered_etree)

    def test_no_not_before(self):
        a = SAMLAuthenticator()

        tampered_etree = etree.fromstring(test_constants.tampered_assertion_no_not_before)

        assert not a._verify_physical_constraints(tampered_etree)
        assert not a._verify_saml_response_fields(self.metadata_etree, tampered_etree)


class TestGetUsername(unittest.TestCase):
    response_etree = etree.fromstring(test_constants.sample_response_xml)
    verified_signed_xml = XMLVerifier().verify(response_etree, x509_cert=test_constants.x509_cert).signed_xml

    def test_get_username_from_saml_doc(self):
        a = SAMLAuthenticator()

        assert 'Bluedata' == a._get_username_from_saml_etree(self.verified_signed_xml)
        assert 'Bluedata' == a._get_username_from_saml_etree(self.response_etree)
        assert 'Bluedata' == a._get_username_from_saml_doc(self.verified_signed_xml, self.response_etree)

    def test_get_username_no_nameid(self):
        tampered_assertion_etree = etree.fromstring(test_constants.tampered_assertion_no_nameid)
        tampered_response_etree  = etree.fromstring(test_constants.tampered_response_no_nameid)

        a = SAMLAuthenticator()

        assert a._get_username_from_saml_etree(tampered_assertion_etree) is None
        assert a._get_username_from_saml_etree(tampered_response_etree) is None
        assert a._get_username_from_saml_doc(tampered_assertion_etree, tampered_response_etree) is None
        assert 'Bluedata' == a._get_username_from_saml_doc(tampered_assertion_etree, self.response_etree)


class TestCreateUser(unittest.TestCase):
    @patch('samlauthenticator.samlauthenticator.subprocess')
    @patch('samlauthenticator.samlauthenticator.pwd')
    def test_create_existing_user(self, mock_pwd, mock_subprocess):
        mock_pwd.getpwnam.return_value = True

        a = SAMLAuthenticator()

        assert a._optional_user_add('Bluedata')

        mock_pwd.getpwnam.assert_called_once_with('Bluedata')
        mock_subprocess.call.assert_not_called()

    @patch('samlauthenticator.samlauthenticator.subprocess')
    @patch('samlauthenticator.samlauthenticator.pwd')
    def test_create_not_existing_user(self, mock_pwd, mock_subprocess):
        mock_pwd.getpwnam.side_effect = KeyError('Bad username')
        mock_subprocess.call.return_value = 0

        a = SAMLAuthenticator()

        assert a._optional_user_add('Bluedata')

        mock_pwd.getpwnam.assert_called_once_with('Bluedata')
        mock_subprocess.call.assert_called_once_with(['useradd', 'Bluedata'])

    @patch('samlauthenticator.samlauthenticator.subprocess')
    @patch('samlauthenticator.samlauthenticator.pwd')
    def test_create_user_fails(self, mock_pwd, mock_subprocess):
        mock_pwd.getpwnam.side_effect = KeyError('Bad username')
        mock_subprocess.call.return_value = 1

        a = SAMLAuthenticator()

        assert not a._optional_user_add('Bluedata')

        mock_pwd.getpwnam.assert_called_once_with('Bluedata')
        mock_subprocess.call.assert_called_once_with(['useradd', 'Bluedata'])

    def test_check_username_valid_username_no_black_lists(self):
        a = SAMLAuthenticator()
        a._optional_user_add = MagicMock()
        a._optional_user_add.return_value = True
        a.whitelist = {'bluedata'}

        assert a._check_username_and_add_user('bluedata')

        a._optional_user_add.assert_called_once_with('bluedata')

        a.whitelist = {'not_bluedata'}
        a._optional_user_add.reset_mock()

        assert not a._check_username_and_add_user('bluedata')

        a._optional_user_add.assert_not_called()

    def test_check_username_valid_username_no_white_lists(self):
        a = SAMLAuthenticator()
        a._optional_user_add = MagicMock()
        a._optional_user_add.return_value = True
        a.blacklist = {'bluedata'}

        assert not a._check_username_and_add_user('bluedata')

        a._optional_user_add.assert_not_called()

        a.blacklist = {'not_bluedata'}

        assert a._check_username_and_add_user('bluedata')

        a._optional_user_add.assert_called_once_with('bluedata')

    def test_check_username_invalid_username(self):
        a = SAMLAuthenticator()
        a._optional_user_add = MagicMock()

        assert not a._check_username_and_add_user('bluedata/')

        a._optional_user_add.assert_not_called()


class TestAuthenticate(unittest.TestCase):
    def _confirm_tom(self, saml_data, mock_datetime, mock_pwd):
        mock_datetime.now.return_value = saml_data.datetime_stamp
        mock_datetime.strptime = datetime.strptime
        mock_pwd.getpwnam.return_value = True

        a = SAMLAuthenticator()
        a.metadata_content = saml_data.metadata_xml

        assert 'tom' == a._authenticate(None, {a.login_post_field: saml_data.b64encoded_response})
        mock_datetime.now.assert_called_once_with(timezone.utc)
        mock_pwd.getpwnam.assert_called_once_with('tom')

    def test_low_strength_cert_sha_1_fingerprint(self):
        saml_data = test_constants.metadata_encoded_xml_dict['low_strength_cert']['SHA-1']
        with patch('samlauthenticator.samlauthenticator.datetime') as mock_datetime, \
                patch('samlauthenticator.samlauthenticator.pwd') as mock_pwd:
            self._confirm_tom(saml_data, mock_datetime, mock_pwd)

    def test_low_strength_cert_sha_256_fingerprint(self):
        saml_data = test_constants.metadata_encoded_xml_dict['low_strength_cert']['SHA-256']
        with patch('samlauthenticator.samlauthenticator.datetime') as mock_datetime, \
                patch('samlauthenticator.samlauthenticator.pwd') as mock_pwd:
            self._confirm_tom(saml_data, mock_datetime, mock_pwd)

    def test_low_strength_cert_sha_384_fingerprint(self):
        saml_data = test_constants.metadata_encoded_xml_dict['low_strength_cert']['SHA-384']
        with patch('samlauthenticator.samlauthenticator.datetime') as mock_datetime, \
                patch('samlauthenticator.samlauthenticator.pwd') as mock_pwd:
            self._confirm_tom(saml_data, mock_datetime, mock_pwd)

    def test_low_strength_cert_sha_512_fingerprint(self):
        saml_data = test_constants.metadata_encoded_xml_dict['low_strength_cert']['SHA-512']
        with patch('samlauthenticator.samlauthenticator.datetime') as mock_datetime, \
                patch('samlauthenticator.samlauthenticator.pwd') as mock_pwd:
            self._confirm_tom(saml_data, mock_datetime, mock_pwd)

    def test_standard_strength_cert_sha_1_fingerprint(self):
        saml_data = test_constants.metadata_encoded_xml_dict['standard_strength_cert']['SHA-1']
        with patch('samlauthenticator.samlauthenticator.datetime') as mock_datetime, \
                patch('samlauthenticator.samlauthenticator.pwd') as mock_pwd:
            self._confirm_tom(saml_data, mock_datetime, mock_pwd)

    def test_standard_strength_cert_sha_256_fingerprint(self):
        saml_data = test_constants.metadata_encoded_xml_dict['standard_strength_cert']['SHA-256']
        with patch('samlauthenticator.samlauthenticator.datetime') as mock_datetime, \
                patch('samlauthenticator.samlauthenticator.pwd') as mock_pwd:
            self._confirm_tom(saml_data, mock_datetime, mock_pwd)

    def test_standard_strength_cert_sha_384_fingerprint(self):
        saml_data = test_constants.metadata_encoded_xml_dict['standard_strength_cert']['SHA-384']
        with patch('samlauthenticator.samlauthenticator.datetime') as mock_datetime, \
                patch('samlauthenticator.samlauthenticator.pwd') as mock_pwd:
            self._confirm_tom(saml_data, mock_datetime, mock_pwd)

    def test_standard_strength_cert_sha_512_fingerprint(self):
        saml_data = test_constants.metadata_encoded_xml_dict['standard_strength_cert']['SHA-512']
        with patch('samlauthenticator.samlauthenticator.datetime') as mock_datetime, \
                patch('samlauthenticator.samlauthenticator.pwd') as mock_pwd:
            self._confirm_tom(saml_data, mock_datetime, mock_pwd)

    def test_bad_post_data(self):
        a = SAMLAuthenticator()
        # None because we can't get the response
        assert a._authenticate(None, {}) is None

    def test_bad_metadata_config(self):
        a = SAMLAuthenticator()
        # None because we can't get the metadata
        assert a._authenticate(None, {a.login_post_field: test_constants.b64encoded_response_xml}) is None

    def test_tampered_response(self):
        a = SAMLAuthenticator()
        a.metadata_content = test_constants.sample_metadata_xml
        assert a._authenticate(None, {a.login_post_field: test_constants.tampered_sample_response_encoded}) is None

    def test_add_user_fail(self):
        with patch('samlauthenticator.samlauthenticator.pwd') as mock_pwd, \
                patch('samlauthenticator.samlauthenticator.datetime') as mock_datetime, \
                patch('samlauthenticator.samlauthenticator.subprocess') as mock_subprocess:
            mock_pwd.getpwnam.side_effect = KeyError('No User')
            mock_datetime.now.return_value = datetime(2019, 4, 9, 21, 35, 0, tzinfo=timezone.utc)
            mock_datetime.strptime = datetime.strptime
            mock_subprocess.call.return_value = 1
            a = SAMLAuthenticator()
            a.metadata_content = test_constants.sample_metadata_xml
            assert a._authenticate(None, {a.login_post_field: test_constants.b64encoded_response_xml}) is None
            mock_pwd.getpwnam.assert_called_once_with('bluedata')
            mock_datetime.now.assert_called_once_with(timezone.utc)
            mock_subprocess.call.assert_called_once_with(['useradd', 'bluedata'])


class TestGetRedirect(unittest.TestCase):

    def test_get_valid_login_redirect(self):
        a = SAMLAuthenticator()
        a.metadata_content = test_constants.sample_metadata_xml

        mock_handler_self = MagicMock()

        a._get_redirect_from_metadata_and_redirect('md:SingleSignOnService', mock_handler_self)

        mock_handler_self.redirect.assert_called_once_with(
            'https://bluedata-test-before-deploy.onelogin.com/trust/saml2/http-redirect/sso/719630',
            permanent=False)

    def test_get_valid_logout_redirect(self):
        a = SAMLAuthenticator()
        a.metadata_content = test_constants.sample_metadata_xml

        mock_handler_self = MagicMock()

        a._get_redirect_from_metadata_and_redirect('md:SingleLogoutService', mock_handler_self)

        mock_handler_self.redirect.assert_called_once_with(
            'https://bluedata-test-before-deploy.onelogin.com/trust/saml2/http-redirect/slo/719630',
            permanent=False)

    def test_get_invalid_xml_element(self):
        a = SAMLAuthenticator()
        a.metadata_content = test_constants.sample_metadata_xml

        mock_handler_self = MagicMock()

        with self.assertRaises(IndexError):
            a._get_redirect_from_metadata_and_redirect('md:BadElement', mock_handler_self)

    def test_get_empty_metadata(self):
        a = SAMLAuthenticator()
        a.metadata_filepath = None
        a.metadata_content = None
        a.metadata_url = None

        mock_handler_self = MagicMock()

        with self.assertRaises(HTTPError):
            a._get_redirect_from_metadata_and_redirect('md:BadElement', mock_handler_self)


class TestMakeSPMetadata(unittest.TestCase):
    org_name_org_metadata = '''
    <Organization>
        <OrganizationName>org_name</OrganizationName>
        
        
    </Organization>
            '''
    org_display_name_org_metadata = '''
    <Organization>
        
        <OrganizationDisplayName>org_display_name</OrganizationDisplayName>
        
    </Organization>
            '''
    org_url_org_metadata = '''
    <Organization>
        
        
        <OrganizationURL>org_url</OrganizationURL>
    </Organization>
            '''

    def test_make_org_metadata_no_org_info(self):
        a = SAMLAuthenticator()
        a.organization_name = ''
        a.organization_display_name = ''
        a.organization_url = ''

        assert a._make_org_metadata() == ''

    def test_make_org_metadata_org_name(self):
        a = SAMLAuthenticator()
        a.organization_name = 'org_name'
        a.organization_display_name = ''
        a.organization_url = ''

        assert a._make_org_metadata() == self.org_name_org_metadata

    def test_make_org_metadata_org_display_name(self):
        a = SAMLAuthenticator()
        a.organization_name = ''
        a.organization_display_name = 'org_display_name'
        a.organization_url = ''

        assert a._make_org_metadata() == self.org_display_name_org_metadata

    def test_make_org_metadata_org_url(self):
        a = SAMLAuthenticator()
        a.organization_name = ''
        a.organization_display_name = ''
        a.organization_url = 'org_url'

        assert a._make_org_metadata() == self.org_url_org_metadata
