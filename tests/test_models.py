
from unittest import TestCase

from py_email_verifier.models import EmailAddress


class TestModels(TestCase):
    def test_email_address(self):
        instance = EmailAddress('Timothe@digitalille.fr')

        self.assertEqual(instance.ace_formatted_domain, 'digitalille.fr')
        self.assertEqual(instance.user, 'Timothe')
        self.assertIsNone(instance.get_literal_ip)
        self.assertEqual(instance.restructure, instance)
        self.assertIsInstance(instance.json_response(), dict)
