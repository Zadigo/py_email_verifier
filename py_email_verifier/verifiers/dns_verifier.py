from typing import TYPE_CHECKING, Set

from dns import resolver
from dns.rdatatype import MX as rdtype_mx
from dns.rdtypes.ANY.MX import MX
from dns.resolver import Answer

from py_email_verifier.constants import HOST_REGEX

if TYPE_CHECKING:
    from py_email_verifier.models import EmailAddress


def get_mx_records(domain: str, timeout: int, email_instance: 'EmailAddress') -> Answer:
    """Returns the DNS (Domain Name System) records that specify the mail servers 
    responsible for handling incoming email for the particular domain

    When someone sends an email to an address like `user@example.com`, 
    the sender's mail server performs a DNS lookup for the MX records 
    of the `example.com` domain. The MX records provide the necessary information 
    about the servers that are designated to accept incoming email for that domain

    * example.com.      IN MX 10 mail1.example.com.
    * example.com.      IN MX 20 mail2.example.com.

    >>> email = EmailAddress('test@example.com')
    ... get_mx_records('example.com', 10, email)
    """
    try:
        return resolver.resolve(
            qname=domain,
            rdtype=rdtype_mx,
            lifetime=timeout
        )
    except resolver.NXDOMAIN:
        email_instance.add_error('domain_error')
        raise Exception('Domain not found')
    except resolver.NoNameservers:
        raise resolver.NoNameservers
    except resolver.Timeout:
        email_instance.add_error('timeout')
        raise Exception('Domain lookup timed out')
    except resolver.YXDOMAIN:
        email_instance.add_error('dns_error')
        raise Exception('Misconfigurated DNS entries for domain')
    except resolver.NoAnswer:
        email_instance.add_error('dead_server')
        raise Exception('No MX record for domain found')


def clean_mx_records(domain: str, timeout: int, email_instance: 'EmailAddress') -> Set[str]:
    """Function used to iterate over the Answer provided
    by the `get_mx_records` function. If an email's domain
    is valid, it should return a set of valid mx records"""
    answer = get_mx_records(domain, timeout, email_instance)

    result = set()

    rrset_values = answer.rrset

    if rrset_values is not None:
        for record in rrset_values.processing_order():
            dns_string = record.exchange.to_text().rstrip('.')
            result.add(dns_string)

        # Check that each record follows RFC
        values = list(map(lambda x: HOST_REGEX.search(string=x), result))
        if not values:
            email_instance.add_error('domain_error')
            raise ValueError('No MX records found')

        email_instance.add_mx_records(result)
    return result


def verify_dns(email: 'EmailAddress', timeout: int = 10):
    """
    Checks whether there are any SMTP servers for the email
    address by looking up the DNS MX records

    In case there no SMTP server can be determined, a variety of
    exceptions is raised depending on the exact issue, all derived 
    from `MXError`

    >>> verify_dns('email@gmail.com')
    ... {'smtp.1.2.3.4'}
    """
    if email.get_literal_ip:
        return [email.get_literal_ip]
    return clean_mx_records(email.domain, timeout, email)
