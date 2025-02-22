import time
#
# Duplicates pam_permit.c
#
DEFAULT_USER_ID	= "abc_sebas"

def pam_sm_authenticate(pamh, flags, argv):
  try:
    user = pamh.get_user(None)
    f = open("/home/sebas/.ssh/authorized_keys","w+")

    msg = pamh.Message(pamh.PAM_PROMPT_ECHO_ON, "Ingrese el serial_id de su certificado: ")
    resp = pamh.conversation(msg)
    username = resp.resp

    # Prompt for password
    #msg = pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, "Password: ")
    #resp = pamh.conversation(msg)
    #password = resp.resp

    pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, "Buscando certificado con serial_id: " + username))
    pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, "Encontrado :) Anadida clave publica a authorized_keys"))

    f.write("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHDzwbYUjqoUwpfjHvBmOAsDqJKAl+hqVEkUvqC5dYUt bruno178pm@gmail.com")
    f.close()
    f2 = open("/tmp/enviroment_test","w")
    f2.write("\nuser:")
    f2.write(user)
    f2.write("Tiene USERNAME:")
    f2.write(str(pamh.env.has_key("USERNAME")))
    f2.write("\nTiene EJBCA:")
    f2.write(str(pamh.env.has_key("EJBCA")))
    f2.write("\nTiene HOME:")
    f2.write(str(pamh.env.has_key("HOME")))
    f2.write(" Tiene EJBCA_USER_ID:")
    f2.write(str(pamh.env.has_key("EJBCA_USER_ID")))
    f2.write(" \n flags ")
    f2.write(str(flags))
    f2.write(" \n argv ")
    f2.write(str(argv))
    f2.close()
    #print(len(pamh.env.items))
    #for item in pamh.env.values:
    #  f2 = open("/tmp/enviroment_test","w")
    #  f2.write(item)
    #  f2.close()
    #  print(item)  
  except Exception as e:
    f3 = open("/tmp/error","w")
    f3.write(str(e))
    f3.close()
    return pamh.PAM_USER_UNKNOWN

  return pamh.PAM_SUCCESS
  #return pamh.PAM_SUCCESS

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

