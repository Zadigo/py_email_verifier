from unittest import TestCase

from dns.resolver import Answer
from py_email_verifier.models import EmailAddress
from py_email_verifier.verifiers.dns_verifier import (clean_mx_records,
                                                      get_mx_records,
                                                      verify_dns)
from py_email_verifier.verifiers.email_verifier import (check_is_ip_address,
                                                        validate_email)
from py_email_verifier.verifiers.smtp_verifier import SMTPVerifier, simple_verify_smtp


class TestMixin:
    def setUp(self):
        self.email = EmailAddress('Timothe@digitalille.fr')
        self.valid_mx_record = 'mta-gw.infomaniak.ch'


class TestEmailVerifiers(TestMixin, TestCase):
    def test_validate_email(self):
        emails = [
            'k.akshay9721@gmail.com',
            'some.email.address.that.does.not.exist@gmail.com',
            'foo@bar.com',
            'ex@example.com'
        ]

        for email in emails:
            email = EmailAddress(email)

            with self.subTest(email=email):
                result = validate_email(email)
                self.assertTrue(result)

    def test_check_is_ip_address(self):
        result = check_is_ip_address('192.168.1.1')
        self.assertTrue(result)


class TestDNSVerifiers(TestMixin, TestCase):
    def test_get_mx_records(self):
        result = get_mx_records(self.email)
        self.assertIsInstance(result, Answer)

    def test_clean_mx_recors(self):
        result = clean_mx_records(self.email)
        self.assertIsInstance(result, set)

        for item in result:
            with self.subTest(item=item):
                self.assertIsInstance(item, str)

    def test_verify_dns(self):
        result = verify_dns(self.email)

        self.assertIsInstance(result, set)

        for item in result:
            with self.subTest(item=item):
                self.assertIsInstance(item, str)

    def test_multiple_emails(self):
        emails = [
            'benoit.hennequin@unilever.com',
            'jerome.cerisier@bmstores.fr',
            'dbarner@newyorker.eu',
            'pierre.boulle@getir.com'
        ]

        for email in emails:
            with self.subTest(email=email):
                result = verify_dns(EmailAddress(email))
                print(result)


class TestSMTPVerifier(TestMixin, TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sender = EmailAddress('Timothe@digitalille.fr')
        cls.recip = EmailAddress('Timothe@digitalille.fr')

    def _create_instance(self):
        return SMTPVerifier(self.sender, self.recip)

    def test_structure(self):
        email = EmailAddress('benoit.hennequin@unilever.com')
        records = clean_mx_records(email)
        result = simple_verify_smtp(records, email)
        print(result)
