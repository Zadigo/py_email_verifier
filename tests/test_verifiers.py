from unittest import TestCase

from dns.resolver import Answer

from py_email_verifier.dns_verifier import get_mx_records, clean_mx_records, verify_dns
from py_email_verifier.email_verifier import (check_is_ip_address,
                                              validate_email)
from py_email_verifier.models import EmailAddress


class TestMixin:
    def setUp(self):
        self.email = EmailAddress('Timothe@digitalille.fr')


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
        result = get_mx_records('digitalille.fr', 10, self.email)
        self.assertIsInstance(result, Answer)

    def test_clean_mx_recors(self):
        result = clean_mx_records('digitalille.fr', 10, self.email)
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
