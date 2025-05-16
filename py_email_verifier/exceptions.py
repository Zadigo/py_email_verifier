class BaseException(Exception):
    message = None

    def __init__(self, message, email=None):
        super().__init__(message)
        self.email = email


class SMTPError(BaseException):
    pass


class AddressNotDeliverableError(BaseException):
    message = 'Email address undeliverable: {email}'

    def __init__(self, email, message):
        message = self.message.format(email=email)
        super().__init__(message, email=email)
