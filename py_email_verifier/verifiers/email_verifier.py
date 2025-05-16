from ipaddress import IPv4Address, IPv6Address
from typing import Literal

from py_email_verifier.constants import HOST_REGEX, LITERAL_REGEX, USER_REGEX
from py_email_verifier.models import EmailAddress


def validate_ipv4_address(value: str):
    try:
        IPv4Address(value)
    except:
        return False
    else:
        return True


def validate_ipv6_address(value: str):
    try:
        IPv6Address(value)
    except:
        return False
    else:
        return True


def check_is_ip_address(value: str):
    """Validates that a value is either an
     IPv4 or IPv6 address"""
    return validate_ipv4_address(value) or validate_ipv6_address(value)


def validate_email(email: 'EmailAddress') -> Literal[True]:
    """Validates the structure of the email address but does not
    check the deliverarility

    >>> email = EmailAddress('test@gmail.com')
    ... validate_email(email)
    """
    if not isinstance(email, EmailAddress):
        raise ValueError("'email' should be an instance of EmailAddress")

    if not USER_REGEX.match(email.user):
        raise ValueError(f'Invalid email address. Got: {email}')

    if email.get_literal_ip is not None:
        result = LITERAL_REGEX.match(email.ace_formatted_domain)
        if result is None:
            raise ValueError(f'Invalid email address. Got: {email}')

        if not validate_ipv6_address(result[1]):
            raise ValueError(f'Invalid email address. Got: {email}')
    else:
        if HOST_REGEX.match(email.ace_formatted_domain) is None:
            raise ValueError(f'Invalid email address. Got: {email}')

    return True
