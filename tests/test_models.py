
from unittest import TestCase

from py_email_verifier.models import EmailAddress


class TestModels(TestCase):
    def setUp(self):
        self.email = EmailAddress('Timothe@digitalille.fr')

    def test_email_address(self):
        self.assertEqual(self.email.ace_formatted_domain, 'digitalille.fr')
        self.assertEqual(self.email.user, 'Timothe')
        self.assertIsNone(self.email.get_literal_ip)
        self.assertEqual(self.email.restructure, self.email)
        self.assertIsInstance(self.email.json_response(), dict)

    def test_ns_lookup(self):
        result = self.email.ns_lookup()
        self.assertIsInstance(result, tuple)

        for item in result:
            with self.subTest(itemm=item):
                self.assertIsInstance(item, list)
