from smtplib import (SMTP, SMTPNotSupportedError, SMTPResponseException,
                     SMTPServerDisconnected)
from socket import timeout
from ssl import SSLError
from typing import TYPE_CHECKING, Optional, Set

from py_email_verifier.exceptions import AddressNotDeliverableError

if TYPE_CHECKING:
    from py_email_verifier.models import EmailAddress


class SMTPVerifier(SMTP):
    """
    Performs an MTA validation, also known as Mail Transfer Agent validation 
    by verifying the integrity and deliverability of email addresses by 
    simulating email delivery and interacting with the recipient's mail server
    """

    def __init__(self, local_hostname: str, timeout: int, debug: bool, sender: 'EmailAddress', recip: 'EmailAddress'):
        super().__init__(local_hostname=local_hostname, timeout=timeout)
        debug_level = 2 if debug else False
        self.set_debuglevel(debug_level)

        self._sender = sender
        self._recip = recip
        self._command = None
        self._host = None
        self.errors = {}
        self.sock = None

    def putcmd(self, cmd, args=''):
        self._command = f'{cmd} {args}' if args else cmd
        super().putcmd(cmd, args)

    def starttls(self, *args, **kwargs):
        try:
            super().starttls(*args, **kwargs)
        except SMTPNotSupportedError:
            # The server does not support the STARTTLS extension
            pass
        except RuntimeError:
            # SSL/TLS support is not available to your Python interpreter
            pass
        except (SSLError, timeout) as error:
            raise Exception(error)

    def mail(self, sender, options=[]):
        """Establishes the legitimacy of the sender's address and assists in the verification process. 
        The recipient's server can perform checks on the sender's address, such as 
        verifying its existence or analyzing the sending domain's reputation, 
        to determine whether to accept or reject the email
        """
        code, message = super().mail(sender=sender, options=options)
        if code >= 400:
            self._sender.add_error('attempt_rejected')
            raise SMTPResponseException(code, message)
        return code, message

    def rcpt(self, recip, options=()):
        """Step in which the sending server confirms whether 
        the recipient's email address is valid and can 
        accept incoming emails
        """
        code, message = super().rcpt(recip=recip, options=options)
        if code >= 500:
            # Address clearly invalid
            # print('rcpt', code, message)
            self._sender.add_error('unknown_email')
            raise AddressNotDeliverableError(code, message)
        elif code >= 400:
            # print('rcpt', code, message)
            self._sender.add_error('attempt_rejected')
            raise SMTPResponseException(code, message)
        return code, message

    def quit(self):
        """
        Like `smtplib.SMTP.quit`, but make sure that everything is
        cleaned up properly even if the connection has been lost before.
        """
        try:
            return super().quit()
        except Exception:
            self.ehlo_resp = self.helo_resp = None
            self.esmtp_features = {}
            self.does_esmtp = False
            self.close()

    def connect(self, host='localhost', port=0, source_address=None):
        """Tries to establish a connection to the email host"""
        self._command = 'connect'
        self._host = host
        try:
            code, message = super().connect(
                host=host,
                port=port,
                source_address=source_address
            )
        except OSError as error:
            self._sender.add_error('smtp_protocol')
            raise SMTPServerDisconnected(str(error))
        else:
            if code >= 400:
                raise SMTPResponseException(code, message)
            message = message.decode()
            self._sender.add_message(host, code, message)
            return code, message

    def check(self, record):
        """Starts the MTA validation on a single record"""
        try:
            self.connect(host=record)
            self.starttls()
            # Start the standard MTA email validation
            # ehlo/helo -> mail -> rcpt
            self.ehlo_or_helo_if_needed()
            self.mail(sender=self._sender.restructure)
            code, message = self.rcpt(recip=self._recip.restructure)
        except SMTPServerDisconnected as e:
            self._sender.add_error('dead_server')
            return False
        except SMTPResponseException as e:
            if e.smtp_code >= 500:
                self._sender.add_error('dead_server')
                raise Exception(
                    f'Communication error: {self._host} / {message}')
            else:
                # self.errors[self._host] = message
                self._sender.add_message(self._host, code, message)
            return False
        finally:
            self.quit()
        return code < 400

    def check_multiple(self, records: Set[str]):
        """Checks multiple MX records at once"""
        result = [self.check(x) for x in records]
        if self.errors:
            raise Exception(f'Host errors: {self.errors}')
        return result


def smtp_check(email: 'EmailAddress', mx_records: Set[str], timeout: int = 10, helo_host: Optional[str] = None, from_address: Optional[str] = None, debug: bool = False):
    """
    Perform an MTA validation, also known as Mail Transfer Agent validation 
    by verifying the integrity and deliverability of an email address"""
    sender = from_address or email
    instance = SMTPVerifier(helo_host, timeout, debug, sender, email)
    return instance.check_multiple(mx_records)
