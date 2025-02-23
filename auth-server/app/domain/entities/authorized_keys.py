from app.domain.entities.x509_public_key import X509PublicKey

class AuthorizedKeysBuilder:
    def __init__(self):
        pass

    def build(self, emailAddress: str,
              commonName: str,
              role: str,
              public_key: X509PublicKey) -> str:
        """
            Description: Builds an authorized_keys entry for a given user.
            Args:
                emailAddress (str): Email address of the user.
                commonName (str): Common name of the user.
                role (str): Role of the user.
                ssh_public_key (str): public key of the user in ssh compatible format.
            Example: environment="REMOTEUSER=german.lamberti" ssh-rsa AAAAB3NzaC1.....shortened== german.lamberti@unc.edu.ar
        """
        environment = f"REMOTEUSER={commonName}|{role}"
        key = public_key.to_ssh_public_key()
        return f"environment=\"{environment}\" {key} {emailAddress}"
