import asyncio
import asgiref
import socket
import smtplib
from smtplib import (SMTP, SMTPNotSupportedError, SMTPResponseException,
                     SMTPServerDisconnected)
from socket import timeout
from ssl import SSLError
from typing import TYPE_CHECKING, Optional, Set

import asgiref.sync

from py_email_verifier.exceptions import AddressNotDeliverableError

if TYPE_CHECKING:
    from py_email_verifier.models import EmailAddress


class SMTPVerifier(SMTP):
    """
    Performs an MTA validation, also known as Mail Transfer Agent validation 
    by verifying the integrity and deliverability of email addresses by 
    simulating email delivery and interacting with the recipient's mail server
    """

    def __init__(self, sender: 'EmailAddress', recip: Optional['EmailAddress'] = None, local_hostname: Optional[str] = None, timeout: int = 10, debug: bool = False):
        super().__init__(local_hostname=local_hostname, timeout=timeout)

        debug_level = 2 if debug else False
        self.set_debuglevel(debug_level)

        self._sender = sender
        self._recip = recip
        self._command = None
        self._host = None
        self.errors = {}
        self.sock = None

    def __str__(self):
        name = self.__class__.__name__
        return f'<{name} [{self._sender} -> {self._recip}]>'

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

    def connect(self, host='localhost', port=25, source_address=None):
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
        except Exception as e:
            self._sender.add_error('error')
            print(e)
        else:
            if code >= 400:
                raise SMTPResponseException(code, message)
            message = message.decode()
            self._sender.add_message(host, code, message)
            return code, message

    def check(self, record: str):
        """Starts the MTA validation on a single record"""
        try:
            self.connect(host=record, port=25)
            self.starttls()
            # Start the standard MTA email validation
            # ehlo/helo -> mail -> rcpt
            self.ehlo_or_helo_if_needed()
            self.mail(sender=self._sender.restructure)
            code, message = self.rcpt(recip=self._recip.restructure)
        except SMTPServerDisconnected as e:
            self._sender.add_error('Timeout or dead server or port 25 blocked')
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


def smtp_check(email: 'EmailAddress', timeout: int = 10, helo_host: Optional[str] = None, from_address: Optional['EmailAddress'] = None, debug: bool = False):
    """
    Perform an MTA validation, also known as Mail Transfer Agent validation 
    by verifying the integrity and deliverability of an email address"""
    sender = from_address or email
    # instance = SMTPVerifier(helo_host, timeout, debug, sender, email)
    instance = SMTPVerifier(
        sender,
        local_hostname=helo_host,
        timeout=timeout,
        debug=debug
    )
    return instance.check_multiple(email.mx_records)


async def _simple_verify_smtp(mx_record: str, email: 'EmailAddress', timeout=20):
    try:
        smtp = SMTP(mx_record, timeout=timeout)
        status, _ = smtp.ehlo()

        if status >= 400:
            smtp.quit()
            return False

        smtp.mail('')
        status, _ = smtp.rcpt(str(email))

        if status >= 400:
            print(f'{mx_record} answer: {status} - {_}')
            result = False

        if status >= 200 and status <= 250:
            result = True

        print(f'{mx_record} answer: {status} - {_}')

        smtp.quit()
    except smtplib.SMTPServerDisconnected:
        print(
            f'Server does not permit verify user, {mx_record} disconnected')
    except smtplib.SMTPConnectError:
        print(f'Unable to connect to {mx_record}.\n')
    except socket.timeout as e:
        print(f'Timeout connecting to server {mx_record}: {e}')
        return None
    except socket.error as e:
        print(f'ServerError or socket.error exception raised {e}')
        return None

    return result


async def _simple_verify_smtp_records(records: Set[str], email: 'EmailAddress', timeout: int = 20):
    aws = list(map(lambda x: _simple_verify_smtp(x, email, timeout), records))
    async for aw in asyncio.as_completed(aws):
        print(await aw)


def simple_verify_smtp(records: Set[str], email: 'EmailAddress', timeout: int = 20):
    return asgiref.sync.async_to_sync(_simple_verify_smtp_records)(records, email, timeout)
