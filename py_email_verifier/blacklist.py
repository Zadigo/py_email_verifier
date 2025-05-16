class Blacklist:
    """Checks if the domain is blacklisted or not"""
    
    def __init__(self, whitelist=[], blacklist=[]):
        self.whitelist = [x.lower() for x in whitelist]
        self.blacklist = [x.lower() for x in blacklist]

    def __call__(self, email):
        from zemailer.validation.models import EmailAddress
        if not isinstance(email, EmailAddress):
            raise

        if email.domain in self.whitelist:
            return True

        if email.domain in self.blacklist:
            return False
        return True


blacklist = Blacklist()
