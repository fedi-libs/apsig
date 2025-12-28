class SignatureError(Exception):
    pass


class MissingSignatureError(SignatureError):
    pass


class UnknownSignatureError(SignatureError):
    pass


class VerificationFailedError(SignatureError):
    pass
