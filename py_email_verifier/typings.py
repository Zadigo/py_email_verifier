from typing import TYPE_CHECKING, Protocol


if TYPE_CHECKING:
    from py_email_verifier.models import EmailAddress


class EmailEvaluationMixinProtocol(Protocol):
    email: str
