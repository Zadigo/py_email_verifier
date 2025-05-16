from functools import cached_property, lru_cache
from typing import Dict, List, Set, Tuple, Union

import idna
from nslookup import Nslookup


class EmailAddress:
    """Represents the raw email object"""

    evaluation: Set[str] = set()
    mx_records: Set[str] = set()
    messages = []
    errors = {}

    def __init__(self, email: str):
        self.email = email

        try:
            self.user, self.domain = self.email.rsplit('@', 1)
        except Exception:
            raise ValueError(f'Email is not valid. Got: {email}')

        if self.get_literal_ip is None:
            self.ace_formatted_domain = self.domain
        else:
            try:
                self.ace_formatted_domain = idna.encode(
                    self.domain).decode('ascii')
            except idna.IDNAError:
                raise

    def __repr__(self):
        return f'<EmailAddress: {self.email}>'

    def __str__(self):
        return self.email

    def __eq__(self, value: Union['EmailAddress', str]) -> bool:
        return value == self.email

    def __hash__(self):
        return hash((self.email))

    @cached_property
    def get_literal_ip(self):
        logic = [
            self.domain.startswith('['),
            self.domain.endswith(']')
        ]
        return self.domain[1:-1] if all(logic) else None

    @cached_property
    def restructure(self):
        """The ASCII-compatible encoding for the email address"""
        return '@'.join((self.user, self.ace_formatted_domain))

    @property
    def is_risky(self):
        return any([
            'protected' in self.evaluation
        ])

    @lru_cache(maxsize=100)
    def ns_lookup(self) -> Tuple[list[str], list[str]]:
        instance = Nslookup(dns_servers=['1.1.1.1'])
        ips_record = instance.dns_lookup(self.domain)
        return ips_record.response_full, ips_record.answer

    def add_error(self, error: str):
        self.evaluation.add(error)

    def add_mx_records(self, records: Set[str]):
        """Adds the records to the current email
        address instance"""
        self.mx_records = records

        for record in records:
            if 'protection' in record:
                self.add_error('protected')

    def add_message(self, host: str, code: int, message: str):
        message = message.encode('utf-8').decode('utf-8')
        self.messages.append([host, code, message])

    def json_response(self) -> Dict[str, str | bool | List[str]]:
        return {
            'risky': self.is_risky,
            'email': self.email,
            'evaluation': list(self.evaluation)
        }
