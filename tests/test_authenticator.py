
from unittest.mock import patch, MagicMock

from lxml import etree

import pytest

from samlauthenticator import SAMLAuthenticator


class TestMetadataRetrieval(object):
    def _test_high_level_metadata_retrieval_functions(self, authenticator):
        assert authenticator._get_preferred_metadata_from_source() == sample_simplified_metadata_xml

        metadata_etree = authenticator._get_saml_metadata_etree()
        local_etree = etree.fromstring(sample_simplified_metadata_xml)

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
        entered_obj.read.return_value = sample_simplified_metadata_xml
        mock_fileopen().__enter__.return_value = entered_obj

        a = SAMLAuthenticator()
        a.metadata_url = 'bad_data'
        a.metadata_content = 'bad_data'
        a.metadata_filepath = '/completely/legitimate/filepath'

        assert a._get_metadata_from_file() == sample_simplified_metadata_xml
        # Check that we have, at least once, called open with the provided filepath
        # TODO: Figure out how to do this so we can use 'assert_called_once_with'
        mock_fileopen.assert_any_call(a.metadata_filepath, 'r')
        # Check that we're reading the file
        entered_obj.read.assert_called_once()

        self._test_readable_mock(a, mock_fileopen)

    def test_metadata_field(self):
        a = SAMLAuthenticator()
        a.metadata_url = 'bad_data'
        a.metadata_content = sample_simplified_metadata_xml

        assert a._get_metadata_from_config() == sample_simplified_metadata_xml
        self._test_high_level_metadata_retrieval_functions(a)

    @patch('samlauthenticator.samlauthenticator.urlopen')
    def test_metadata_url(self, mock_urlopen):
        entered_obj = MagicMock()
        entered_obj.read.return_value = sample_simplified_metadata_xml
        mock_urlopen().__enter__.return_value = entered_obj

        a = SAMLAuthenticator()
        a.metadata_url = 'http://foo'

        # Check that we're getting the right value
        assert a._get_metadata_from_url() == sample_simplified_metadata_xml
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

        assert a._get_saml_metadata_etree() == None

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

        assert a._get_saml_metadata_etree() == None


class TestSAMLDocRetrieval(object):
    def test_get_saml_doc_etree(self):
        # We expect the SAML Response to be coming in base 64 encoded
        a = SAMLAuthenticator()
        fake_data = {a.login_post_field: b64encoded_response_xml}

        faked_etree = a._get_saml_doc_etree(fake_data)
        real_etree = etree.fromstring(sample_response_xml)

        assert etree.tostring(faked_etree) == etree.tostring(real_etree)

    def test_get_saml_doc_different_location(self):
        a = SAMLAuthenticator()
        a.login_post_field = 'test'
        fake_data = {a.login_post_field: b64encoded_response_xml}

        faked_etree = a._get_saml_doc_etree(fake_data)
        real_etree = etree.fromstring(sample_response_xml)

        assert etree.tostring(faked_etree) == etree.tostring(real_etree)

    def test_with_failed_get(self):
        a = SAMLAuthenticator()
        fake_data = {}

        assert a._get_saml_doc_etree(fake_data) == None

    def test_bad_decode(self):
        a = SAMLAuthenticator()
        fake_data = {a.login_post_field: 'this is not base 64 encoded data'}

        assert a._get_saml_doc_etree(fake_data) == None

    @patch('samlauthenticator.samlauthenticator.b64decode')
    def test_not_valid_xml(self, mock_b64decode):
        a = SAMLAuthenticator()
        fake_data = {a.login_post_field: 'this string isn\'t important'}

        mock_b64decode.return_value = 'bad xml string'

        assert a._get_saml_doc_etree(fake_data) == None



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
        

sample_simplified_metadata_xml = '''
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://app.onelogin.com/saml/metadata/705399">
  <IDPSSODescriptor xmlns:ds="http://www.w3.org/2000/09/xmldsig#" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://bluedata-test-before-deploy.onelogin.com/trust/saml2/http-redirect/slo/705399"/>
  </IDPSSODescriptor>
</EntityDescriptor>
'''

sample_response_xml = '''<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R7907c947a7cdb96dd8224acad39b7ddc9dfb573b" Version="2.0" IssueInstant="2019-04-09T01:34:38Z" Destination="{recipient}"><saml:Issuer>https://app.onelogin.com/saml/metadata/719630</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Version="2.0" ID="pfxdd2387bb-874d-5419-3c9f-b2b0e2fc1689" IssueInstant="2019-04-09T01:34:38Z"><saml:Issuer>https://app.onelogin.com/saml/metadata/719630</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#pfxdd2387bb-874d-5419-3c9f-b2b0e2fc1689"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>2JD13x166K0e1kT6FvqRZNBf9Gg=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>jQ/ZFtgwncr6sN5T9VA3ijd51/3g0WPoS6qp77WpEHH8DV8c/KC6kU77ZPVfD9WNZsOrwwT7wlA3f0HqLNC/j4o0mdoLZYNF8GKoXZkmA2QcAeThL3FMgKTCmosaKw4VWzH0bCzsaYs5v+XG8T77+q0ghuf9PstQN25u60FJ80ADlnFfo9dGr6JKHi+74GRV0NzMcKYjJgN6HnL2XeDZ7zszkFJVEY5dOe/ruRAcNE455XaRr1GwYvCTAPb76rHbiZ7R+CQypaKqodGDyRt9Rz9obx2wMH1u2xHqWFvuqqwj1ZqF3ReOXWTWgZ8/J1SaMApdscMXABDJg3y6TisUXg==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIEGjCCAwKgAwIBAgIUQdwG5mt42m3PyuaN1Z8yOJ+7t/kwDQYJKoZIhvcNAQEFBQAwWTELMAkGA1UEBhMCVVMxETAPBgNVBAoMCEJsdWVkYXRhMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxIDAeBgNVBAMMF09uZUxvZ2luIEFjY291bnQgMTEzOTY1MB4XDTE3MDkxMDIxMjIwN1oXDTIyMDkxMTIxMjIwN1owWTELMAkGA1UEBhMCVVMxETAPBgNVBAoMCEJsdWVkYXRhMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxIDAeBgNVBAMMF09uZUxvZ2luIEFjY291bnQgMTEzOTY1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3nj/I3GIRmH63996E6RdSmZd96m6A+sZVYM6pWoarw+VQWp2ClgJCy75oRB1/Or4Ft9U8LiwR0R7Qae5Il7dx6mCfe72yUZArckN+XPT7KpEY1a5W1bksRJoFVOq81/qe+Y+hnbZRUw4tkkrc2Ta9OGKHwZYjwp/hF2AyZAWcceZI8HVhQ9b+c9bDAD+8/+/NqkX2yIO1KxDmZ+kE85f07pDTllwE4/LFYsBlIuVp8Dixz1xLFmOnhRz9crP/yaiy9G+zaYdh/5yOHIWCaO31Sumhf4k47TPbyGVQ5BYFGWGbKkx33jm7FvEDN55p8+G++sAxdVi5/Ohgq5BSgjJWQIDAQABo4HZMIHWMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFLFct2rRVYPkwbU2Kz7aT2rXLhMBMIGWBgNVHSMEgY4wgYuAFLFct2rRVYPkwbU2Kz7aT2rXLhMBoV2kWzBZMQswCQYDVQQGEwJVUzERMA8GA1UECgwIQmx1ZWRhdGExFTATBgNVBAsMDE9uZUxvZ2luIElkUDEgMB4GA1UEAwwXT25lTG9naW4gQWNjb3VudCAxMTM5NjWCFEHcBuZreNptz8rmjdWfMjifu7f5MA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQUFAAOCAQEAtvSTp+IzERaOMx7ODKJWMskhOBKl39r5RYe+BX2/6vub7rTlEbGGeGboiDqX3yCaDxwK4QI2E3Q5BWeCjqLqIF3Ou6FLD5Bc6sNNhluwjKYajKrP5bozaiguCCuhqSWKeCQ7/hR2CQEHPHBNKXXs270pMtm4GT6dGn7b3wqImBcBKbVVjJCSalWaI2wUZVs+2UP2peo8DmCXdxTqN3TnhxlgiEEH7cc8uBMJhZTRQyN1SVKPYJ/oP5AgNoSbEuAaeA2RAKPKcNcSkDvhIG68c16Hm76+8gezVcIQzp/x5//Srpp1Y1UEdF/xc9FOTNqpwjPzd2ZPNLfVWzwa1Gob5Q==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">tkelley@bluedata.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2019-04-09T01:37:38Z" Recipient="{recipient}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2019-04-09T01:31:38Z" NotOnOrAfter="2019-04-09T01:37:38Z"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2019-04-09T01:34:37Z" SessionNotOnOrAfter="2019-04-10T01:34:38Z" SessionIndex="_c873ef90-3c89-0137-1764-0a47cde2b5c6"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="memberOf" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string"/></saml:Attribute><saml:Attribute Name="User.email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">tkelley@bluedata.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name="User.FirstName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Tom</saml:AttributeValue></saml:Attribute><saml:Attribute Name="PersonImmutableID" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">joel</saml:AttributeValue></saml:Attribute><saml:Attribute Name="User.LastName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Bluedata</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>'''

b64encoded_response_xml = bytearray('''PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0
YzpTQU1MOjIuMDphc3NlcnRpb24iIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6
bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIElEPSJSNzkwN2M5NDdhN2Nk
Yjk2ZGQ4MjI0YWNhZDM5YjdkZGM5ZGZiNTczYiIgVmVyc2lvbj0iMi4wIiBJ
c3N1ZUluc3RhbnQ9IjIwMTktMDQtMDlUMDE6MzQ6MzhaIiBEZXN0aW5hdGlv
bj0ie3JlY2lwaWVudH0iPjxzYW1sOklzc3Vlcj5odHRwczovL2FwcC5vbmVs
b2dpbi5jb20vc2FtbC9tZXRhZGF0YS83MTk2MzA8L3NhbWw6SXNzdWVyPjxz
YW1scDpTdGF0dXM+PHNhbWxwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNp
czpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIvPjwvc2FtbHA6
U3RhdHVzPjxzYW1sOkFzc2VydGlvbiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6
bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIiB4bWxuczp4cz0iaHR0cDov
L3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDov
L3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIFZlcnNpb249
IjIuMCIgSUQ9InBmeGRkMjM4N2JiLTg3NGQtNTQxOS0zYzlmLWIyYjBlMmZj
MTY4OSIgSXNzdWVJbnN0YW50PSIyMDE5LTA0LTA5VDAxOjM0OjM4WiI+PHNh
bWw6SXNzdWVyPmh0dHBzOi8vYXBwLm9uZWxvZ2luLmNvbS9zYW1sL21ldGFk
YXRhLzcxOTYzMDwvc2FtbDpJc3N1ZXI+PGRzOlNpZ25hdHVyZSB4bWxuczpk
cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+PGRzOlNp
Z25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGht
PSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48
ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5v
cmcvMjAwMC8wOS94bWxkc2lnI3JzYS1zaGExIi8+PGRzOlJlZmVyZW5jZSBV
Ukk9IiNwZnhkZDIzODdiYi04NzRkLTU0MTktM2M5Zi1iMmIwZTJmYzE2ODki
PjxkczpUcmFuc2Zvcm1zPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRw
Oi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25h
dHVyZSIvPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3Lncz
Lm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L2RzOlRyYW5zZm9ybXM+
PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3Jn
LzIwMDAvMDkveG1sZHNpZyNzaGExIi8+PGRzOkRpZ2VzdFZhbHVlPjJKRDEz
eDE2NkswZTFrVDZGdnFSWk5CZjlHZz08L2RzOkRpZ2VzdFZhbHVlPjwvZHM6
UmVmZXJlbmNlPjwvZHM6U2lnbmVkSW5mbz48ZHM6U2lnbmF0dXJlVmFsdWU+
alEvWkZ0Z3duY3I2c041VDlWQTNpamQ1MS8zZzBXUG9TNnFwNzdXcEVISDhE
VjhjL0tDNmtVNzdaUFZmRDlXTlpzT3J3d1Q3d2xBM2YwSHFMTkMvajRvMG1k
b0xaWU5GOEdLb1haa21BMlFjQWVUaEwzRk1nS1RDbW9zYUt3NFZXekgwYkN6
c2FZczV2K1hHOFQ3NytxMGdodWY5UHN0UU4yNXU2MEZKODBBRGxuRmZvOWRH
cjZKS0hpKzc0R1JWME56TWNLWWpKZ042SG5MMlhlRFo3enN6a0ZKVkVZNWRP
ZS9ydVJBY05FNDU1WGFScjFHd1l2Q1RBUGI3NnJIYmlaN1IrQ1F5cGFLcW9k
R0R5UnQ5Uno5b2J4MndNSDF1MnhIcVdGdnVxcXdqMVpxRjNSZU9YV1RXZ1o4
L0oxU2FNQXBkc2NNWEFCREpnM3k2VGlzVVhnPT08L2RzOlNpZ25hdHVyZVZh
bHVlPjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YT48ZHM6WDUwOUNlcnRpZmlj
YXRlPk1JSUVHakNDQXdLZ0F3SUJBZ0lVUWR3RzVtdDQybTNQeXVhTjFaOHlP
Sis3dC9rd0RRWUpLb1pJaHZjTkFRRUZCUUF3V1RFTE1Ba0dBMVVFQmhNQ1ZW
TXhFVEFQQmdOVkJBb01DRUpzZFdWa1lYUmhNUlV3RXdZRFZRUUxEQXhQYm1W
TWIyZHBiaUJKWkZBeElEQWVCZ05WQkFNTUYwOXVaVXh2WjJsdUlFRmpZMjkx
Ym5RZ01URXpPVFkxTUI0WERURTNNRGt4TURJeE1qSXdOMW9YRFRJeU1Ea3hN
VEl4TWpJd04xb3dXVEVMTUFrR0ExVUVCaE1DVlZNeEVUQVBCZ05WQkFvTUNF
SnNkV1ZrWVhSaE1SVXdFd1lEVlFRTERBeFBibVZNYjJkcGJpQkpaRkF4SURB
ZUJnTlZCQU1NRjA5dVpVeHZaMmx1SUVGalkyOTFiblFnTVRFek9UWTFNSUlC
SWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQTNuai9J
M0dJUm1INjM5OTZFNlJkU21aZDk2bTZBK3NaVllNNnBXb2FydytWUVdwMkNs
Z0pDeTc1b1JCMS9PcjRGdDlVOExpd1IwUjdRYWU1SWw3ZHg2bUNmZTcyeVVa
QXJja04rWFBUN0twRVkxYTVXMWJrc1JKb0ZWT3E4MS9xZStZK2huYlpSVXc0
dGtrcmMyVGE5T0dLSHdaWWp3cC9oRjJBeVpBV2NjZVpJOEhWaFE5YitjOWJE
QUQrOC8rL05xa1gyeUlPMUt4RG1aK2tFODVmMDdwRFRsbHdFNC9MRllzQmxJ
dVZwOERpeHoxeExGbU9uaFJ6OWNyUC95YWl5OUcremFZZGgvNXlPSElXQ2FP
MzFTdW1oZjRrNDdUUGJ5R1ZRNUJZRkdXR2JLa3gzM2ptN0Z2RURONTVwOCtH
KytzQXhkVmk1L09oZ3E1QlNnakpXUUlEQVFBQm80SFpNSUhXTUF3R0ExVWRF
d0VCL3dRQ01BQXdIUVlEVlIwT0JCWUVGTEZjdDJyUlZZUGt3YlUyS3o3YVQy
clhMaE1CTUlHV0JnTlZIU01FZ1k0d2dZdUFGTEZjdDJyUlZZUGt3YlUyS3o3
YVQyclhMaE1Cb1Yya1d6QlpNUXN3Q1FZRFZRUUdFd0pWVXpFUk1BOEdBMVVF
Q2d3SVFteDFaV1JoZEdFeEZUQVRCZ05WQkFzTURFOXVaVXh2WjJsdUlFbGtV
REVnTUI0R0ExVUVBd3dYVDI1bFRHOW5hVzRnUVdOamIzVnVkQ0F4TVRNNU5q
V0NGRUhjQnVacmVOcHR6OHJtamRXZk1qaWZ1N2Y1TUE0R0ExVWREd0VCL3dR
RUF3SUhnREFOQmdrcWhraUc5dzBCQVFVRkFBT0NBUUVBdHZTVHArSXpFUmFP
TXg3T0RLSldNc2toT0JLbDM5cjVSWWUrQlgyLzZ2dWI3clRsRWJHR2VHYm9p
RHFYM3lDYUR4d0s0UUkyRTNRNUJXZUNqcUxxSUYzT3U2RkxENUJjNnNOTmhs
dXdqS1lhaktyUDVib3phaWd1Q0N1aHFTV0tlQ1E3L2hSMkNRRUhQSEJOS1hY
czI3MHBNdG00R1Q2ZEduN2Izd3FJbUJjQktiVlZqSkNTYWxXYUkyd1VaVnMr
MlVQMnBlbzhEbUNYZHhUcU4zVG5oeGxnaUVFSDdjYzh1Qk1KaFpUUlF5TjFT
VktQWUovb1A1QWdOb1NiRXVBYWVBMlJBS1BLY05jU2tEdmhJRzY4YzE2SG03
Nis4Z2V6VmNJUXpwL3g1Ly9TcnBwMVkxVUVkRi94YzlGT1ROcXB3alB6ZDJa
UE5MZlZXendhMUdvYjVRPT08L2RzOlg1MDlDZXJ0aWZpY2F0ZT48L2RzOlg1
MDlEYXRhPjwvZHM6S2V5SW5mbz48L2RzOlNpZ25hdHVyZT48c2FtbDpTdWJq
ZWN0PjxzYW1sOk5hbWVJRCBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpT
QU1MOjEuMTpuYW1laWQtZm9ybWF0OmVtYWlsQWRkcmVzcyI+dGtlbGxleUBi
bHVlZGF0YS5jb208L3NhbWw6TmFtZUlEPjxzYW1sOlN1YmplY3RDb25maXJt
YXRpb24gTWV0aG9kPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6Y206
YmVhcmVyIj48c2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uRGF0YSBOb3RPbk9y
QWZ0ZXI9IjIwMTktMDQtMDlUMDE6Mzc6MzhaIiBSZWNpcGllbnQ9IntyZWNp
cGllbnR9Ii8+PC9zYW1sOlN1YmplY3RDb25maXJtYXRpb24+PC9zYW1sOlN1
YmplY3Q+PHNhbWw6Q29uZGl0aW9ucyBOb3RCZWZvcmU9IjIwMTktMDQtMDlU
MDE6MzE6MzhaIiBOb3RPbk9yQWZ0ZXI9IjIwMTktMDQtMDlUMDE6Mzc6Mzha
Ij48c2FtbDpBdWRpZW5jZVJlc3RyaWN0aW9uPjxzYW1sOkF1ZGllbmNlPnth
dWRpZW5jZX08L3NhbWw6QXVkaWVuY2U+PC9zYW1sOkF1ZGllbmNlUmVzdHJp
Y3Rpb24+PC9zYW1sOkNvbmRpdGlvbnM+PHNhbWw6QXV0aG5TdGF0ZW1lbnQg
QXV0aG5JbnN0YW50PSIyMDE5LTA0LTA5VDAxOjM0OjM3WiIgU2Vzc2lvbk5v
dE9uT3JBZnRlcj0iMjAxOS0wNC0xMFQwMTozNDozOFoiIFNlc3Npb25JbmRl
eD0iX2M4NzNlZjkwLTNjODktMDEzNy0xNzY0LTBhNDdjZGUyYjVjNiI+PHNh
bWw6QXV0aG5Db250ZXh0PjxzYW1sOkF1dGhuQ29udGV4dENsYXNzUmVmPnVy
bjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3Jk
UHJvdGVjdGVkVHJhbnNwb3J0PC9zYW1sOkF1dGhuQ29udGV4dENsYXNzUmVm
Pjwvc2FtbDpBdXRobkNvbnRleHQ+PC9zYW1sOkF1dGhuU3RhdGVtZW50Pjxz
YW1sOkF0dHJpYnV0ZVN0YXRlbWVudD48c2FtbDpBdHRyaWJ1dGUgTmFtZT0i
bWVtYmVyT2YiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1M
OjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMiPjxzYW1sOkF0dHJpYnV0ZVZh
bHVlIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hl
bWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciLz48L3NhbWw6QXR0
cmlidXRlPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJVc2VyLmVtYWlsIiBOYW1l
Rm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5hbWUt
Zm9ybWF0OmJhc2ljIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4c2k9
Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4
c2k6dHlwZT0ieHM6c3RyaW5nIj50a2VsbGV5QGJsdWVkYXRhLmNvbTwvc2Ft
bDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjxzYW1sOkF0dHJp
YnV0ZSBOYW1lPSJVc2VyLkZpcnN0TmFtZSIgTmFtZUZvcm1hdD0idXJuOm9h
c2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF0dHJuYW1lLWZvcm1hdDpiYXNpYyI+
PHNhbWw6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHNpPSJodHRwOi8vd3d3Lncz
Lm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0
cmluZyI+VG9tPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1
dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IlBlcnNvbkltbXV0YWJsZUlEIiBO
YW1lRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXR0cm5h
bWUtZm9ybWF0OmJhc2ljIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4
c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNl
IiB4c2k6dHlwZT0ieHM6c3RyaW5nIj5qb2VsPC9zYW1sOkF0dHJpYnV0ZVZh
bHVlPjwvc2FtbDpBdHRyaWJ1dGU+PHNhbWw6QXR0cmlidXRlIE5hbWU9IlVz
ZXIuTGFzdE5hbWUiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpT
QU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMiPjxzYW1sOkF0dHJpYnV0
ZVZhbHVlIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxT
Y2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPkJsdWVkYXRh
PC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PC9zYW1s
OkF0dHJpYnV0ZVN0YXRlbWVudD48L3NhbWw6QXNzZXJ0aW9uPjwvc2FtbHA6
UmVzcG9uc2U+Cgo=''', encoding='utf-8')
