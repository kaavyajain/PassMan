#Python version 3.6 is needed for the cryptography library
#MySQL should be installed and configured

#importing libraries
import base64, mysql.connector, os
from cryptography.fernet import Fernet #fernet is for doing symmetric encryption
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.kdf.kbkdf import (CounterLocation, KBKDFHMAC, Mode)
from dotenv import load_dotenv, set_key, dotenv_values
from gooey import Gooey, GooeyParser #to make GUI
from mysql.connector import Error
from os.path import join, dirname

#constants
HOST = "localhost"
DB_NAME = "passManager"
NUM_ENV_DB = 4
NUM_ENV_AUTH = 4

#load .env file
dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path, override=True)

#initialization functions
def generate_env():
    ''' generates an .env file with user-specified username/password for DB connection '''

    print("Generating .env for local DB connection")

    username = ""
    password = ""

    # prompt user for DB user/password
    while len(username) < 1:
        username = input("Enter a database username (minimum 1 char): ")

    while len(password) < 1:
        password = input("Enter a database password (minimum 1 char): ")

    # write selected DB username/password and constant host/db_name to ENV vars
    os.environ["HOST"] = HOST
    os.environ["USER"] = username.strip()
    os.environ["PASS"] = password.strip()
    os.environ["DB_NAME"] = DB_NAME

    # write selected DB username/password and constant host/db_name to .env
    set_key(dotenv_path, "HOST", HOST)
    set_key(dotenv_path, "USER", username.strip())
    set_key(dotenv_path, "PASS", password.strip())
    set_key(dotenv_path, "DB_NAME", DB_NAME)

def is_valid_env():
    ''' checks if the .env file is valid (for our purposes) '''

    counter = 0
    env_vars = dotenv_values(".env")

    for var in env_vars:
        if counter < 4 and len(env_vars[var]) < 1:
            print("Missing environment variables for DB connection...")
            return False
        counter += 1

    return True


def init():
    ''' initializes the app for first-time users '''

    # check for valid .env or generate it
    if not is_valid_env():
        print("Valid .env not found...")
        generate_env()

    try:
        # connect to MySQL server
        db = mysql.connector.connect(
            host=os.environ["HOST"],
            user=os.environ["USER"],
            passwd=os.environ["PASS"]
        )

        # check for existing database
        cursor = db.cursor()
        cursor.execute("SHOW DATABASES")
        db_exists = False
        for item in cursor:
            if os.environ["DB_NAME"].lower() == item[0].lower():
                db_exists = True

        # database not found, setting up database and tables
        if not db_exists:
            # create a database
            print("\nCreating a database...")
            cursor.execute("CREATE DATABASE {}".format(os.environ["DB_NAME"]))
            cursor.execute("USE {}".format(os.environ["DB_NAME"]))

            # create a user_table
            cursor.execute(
                "CREATE TABLE user_table (username VARCHAR(100) PRIMARY KEY, eutk TEXT, eKEK TEXT, ev TEXT, esk TEXT)")

            cursor.execute(
                "CREATE TABLE services (username VARCHAR(100), service VARCHAR(100), ep TEXT, ek TEXT, PRIMARY KEY(username, service));")

        db.commit()
        cursor.close()
        db.close()
        return True

    except Error as e:
        print(f"\nThe error '{e}' occurred")
        print("Perhaps you need to edit your .env?")

    return False


def create_connection():
    ''' creates a connection to the MySQL DB '''

    connection = None

    try:
        connection = mysql.connector.connect(
            host=os.environ["HOST"],
            user=os.environ["USER"],
            passwd=os.environ["PASS"],
            database=os.environ["DB_NAME"]
        )
        print("Connection to MySQL DB successful!")

    except Error as e:
        print(f"The error '{e}' occurred")
        print("Perhaps you need to edit your .env?")

    return connection


def generate_master_key(master_password):
    ''' generates a master_key used for verifying user authentication '''
    # master_password - user supplied master password. The pm does not store this, the user must remember it.
    # this is generated only once per user, it needs to be stored in order to regenerate the master key for authentication

    # Password Based Key Derivation, a slow hashing function
    otherinfo = b"concatkdf-example"
    ckdf = ConcatKDFHash(
        algorithm=hashes.SHA256(),
        length=32,
        otherinfo=otherinfo,)

    safely = str.encode(master_password)
    master_key = base64.urlsafe_b64encode(ckdf.derive(safely))
    return master_key


def generate_user_table_key(KEK):
    ''' generates a key to encrypt passwords added to the user_table '''

    # key-based key derivation
    kdf = KBKDFHMAC(
        algorithm=hashes.SHA256(),
        mode=Mode.CounterMode,
        length=32,
        rlen=4,
        llen=4,
        location=CounterLocation.BeforeFixed,
        label=b"KBKDF HMAC Label",
        context=b"KBKDF HMAC Context",
        fixed=None)
    key = kdf.derive(KEK)
    return key

def generate_service_table_key():
    ''' generates a key to encrypt passwords added to the service_table '''

    key = Fernet.generate_key()
    return key


#Actions for authenticated users

def create_user(username, master_password):
    ''' create a user with master_password, and make a user_table '''

    # keys are of type bytes
    key_encryption_key = generate_master_key(master_password)
    user_table_key = generate_user_table_key(key_encryption_key)
    service_key = generate_service_table_key()

    # make the fernet objects used to encrypt
    KEK = Fernet(key_encryption_key)
    b64_user_table_key = base64.urlsafe_b64encode(user_table_key)
    UTK = Fernet(b64_user_table_key)

    # encrypt keys
    encrypted_user_table_key = KEK.encrypt(user_table_key)
    encrypted_KEK = UTK.encrypt(key_encryption_key)
    encrypted_validator = UTK.encrypt(user_table_key)
    encrypted_service_key = UTK.encrypt(service_key)

    # convert to strings
    str_encrypted_user_table_key = bytes.decode(encrypted_user_table_key)
    str_en_KEK = bytes.decode(encrypted_KEK)
    str_en_validator = bytes.decode(encrypted_validator)
    str_en_service_key = bytes.decode(encrypted_service_key)

    # write to DB
    connection = create_connection()
    cursor = connection.cursor()
    cursor.execute("INSERT INTO user_table (username, eutk, eKEK, ev, esk) VALUES (%s, %s, %s, %s, %s)",
                   (username, str_encrypted_user_table_key, str_en_KEK, str_en_validator, str_en_service_key))
    connection.commit()
    cursor.close()
    connection.close()

    return


def authenticate_user(username, master_password):
    ''' authenticates a user if they supply a valid username and master_password '''

    connection = create_connection()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT esk FROM user_table WHERE username = (%s)", (username,))

    esk = cursor.fetchone()

    cursor.execute(
        "SELECT eKEK FROM user_table WHERE username = (%s)", (username,))

    eKEK = cursor.fetchone()

    cursor.execute(
        "SELECT eutk FROM user_table WHERE username = (%s)", (username,))

    encrypted_user_table_key = cursor.fetchone()

    cursor.execute(
        "SELECT ev FROM user_table WHERE username = (%s)", (username,))

    encrypted_validator = cursor.fetchone()

    connection.commit()
    cursor.close()
    connection.close()

    encrypted_user_table_key = str.encode(encrypted_user_table_key[0])
    encrypted_validator = str.encode(encrypted_validator[0])
    byte_KEK = generate_master_key(master_password)
    KEK = Fernet(byte_KEK)
    attempted_utk = generate_user_table_key(byte_KEK)
    supposed_eutk = KEK.encrypt(attempted_utk)

    table_key = KEK.decrypt(encrypted_user_table_key)
    b64_UTK = base64.urlsafe_b64encode(table_key)
    key_table_key = Fernet(b64_UTK)
    validator = key_table_key.decrypt(encrypted_validator)

    if validator == table_key:
        eKEK = str.encode(eKEK[0])
        decrypted_KEK = key_table_key.decrypt(eKEK)
        if decrypted_KEK == byte_KEK:
            byte_esk = str.encode(esk[0])
            decrypted_service_table_key = key_table_key.decrypt(byte_esk)
            return [True, decrypted_KEK, table_key, decrypted_service_table_key]

    return [False, None, None, None, None]
