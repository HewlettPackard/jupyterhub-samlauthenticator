
from unittest.mock import patch, MagicMock

from lxml import etree

from samlauthenticator import SAMLAuthenticator

sample_simplified_xml = '''
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://app.onelogin.com/saml/metadata/705399">
  <IDPSSODescriptor xmlns:ds="http://www.w3.org/2000/09/xmldsig#" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://bluedata-test-before-deploy.onelogin.com/trust/saml2/http-redirect/slo/705399"/>
  </IDPSSODescriptor>
</EntityDescriptor>
'''


class TestMetadataRetrieval(object):
    def _test_high_level_metadata_retrieval_functions(self, authenticator):
        assert authenticator._get_preferred_metadata_from_source() == sample_simplified_xml

        metadata_etree = authenticator._get_saml_metadata_etree()
        local_etree = etree.fromstring(sample_simplified_xml)

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
        entered_obj.read.return_value = sample_simplified_xml
        mock_fileopen().__enter__.return_value = entered_obj

        a = SAMLAuthenticator()
        a.metadata_url = 'bad_data'
        a.metadata_content = 'bad_data'
        a.metadata_filepath = 'completely/legitimate/filepath'

        assert a._get_metadata_from_file() == sample_simplified_xml
        # Check that we have, at least once, called open with the provided filepath
        # TODO: Figure out how to do this so we can use 'assert_called_once_with'
        mock_fileopen.assert_any_call(a.metadata_filepath, 'r')
        # Check that we're reading the file
        entered_obj.read.assert_called_once()

        self._test_readable_mock(a, mock_fileopen)

    def test_metadata_field(self):
        a = SAMLAuthenticator()
        a.metadata_url = 'bad_data'
        a.metadata_content = sample_simplified_xml

        assert a._get_metadata_from_config() == sample_simplified_xml
        self._test_high_level_metadata_retrieval_functions(a)

    @patch('samlauthenticator.samlauthenticator.urlopen')
    def test_metadata_url(self, mock_urlopen):
        entered_obj = MagicMock()
        entered_obj.read.return_value = sample_simplified_xml
        mock_urlopen().__enter__.return_value = entered_obj

        a = SAMLAuthenticator()
        a.metadata_url = 'http://foo'

        # Check that we're getting the right value
        assert a._get_metadata_from_url() == sample_simplified_xml
        # Check that we have, at least once, called open with the provided url
        # TODO: Figure out how to do this so we can use 'assert_called_once_with'
        mock_urlopen.assert_any_call(a.metadata_url)
        # Check that we're reading the file
        entered_obj.read.assert_called_once()

        self._test_readable_mock(a, mock_urlopen)


# class TestSAMLDocRetrieval(object):
#     def test_one(self):
#         x = "this"
#         assert 'h' in x

#     def test_two(self):
#         assert 1 == 2

# class TestValidSamlResponse(object):
#     def test_one(self):
#         x = "this"
#         assert 'h' in x

#     def test_two(self):
#         assert 1 == 2

# class TestGetUsername(object):
#     def test_one(self):
#         x = "this"
#         assert 'h' in x

#     def test_two(self):
#         assert 1 == 2

# class TestAuthenticate(object):
#     def test_one(self):
#         x = "this"
#         assert 'h' in x

#     def test_two(self):
#         assert 1 == 2
        
