class SignatureError(Exception):
    pass

class MissingSignature(SignatureError):
    pass

class UnknownSignature(SignatureError):
    pass

class VerificationFailed(SignatureError):
    pass