from time import sleep

import requests
from mo_dots import Null
from mo_files import File
from mo_json import value2json, json2value
from mo_kwargs import override
from mo_times import Date, HOUR
from mozilla_aws_cli.login import Login


@override
def MAWS(
    client_id="N7lULzWtfVUDGymwDs0yDEq6ZcwmFazj",
    idtoken_for_roles_url="https://roles-and-aliases.security.mozilla.org/roles",
    well_known_url="https://auth.mozilla.auth0.com/.well-known/openid-configuration",
    authorization_endpoint=None,
    issuer=None,
    issuer_domain="aws.sso.mozilla.com",
    token_endpoint=None,
    kwargs=None,
):
    keyfile = File("~/.maws/credentials.json")
    # try:
    #     previous_credentials = json2value(keyfile.read())
    # except Exception:
    #     previous_credentials = Null
    #
    # if Date(previous_credentials.expiry) > Date.now() + HOUR:
    #     return previous_credentials

    openid_configuration = kwargs | requests.get(well_known_url).json()
    jwks = requests.get(openid_configuration["jwks_uri"]).json()

    maws = Login(
        authorization_endpoint=openid_configuration["authorization_endpoint"],
        batch=False,
        client_id=client_id,
        idtoken_for_roles_url=idtoken_for_roles_url,
        jwks=jwks,
        openid_configuration=openid_configuration,
        token_endpoint=openid_configuration["token_endpoint"],
        web_console=False,
        issuer_domain=issuer_domain,
        cache=True,
        print_url=False,
    )

    maws.print_output_map = False
    maws.login()

    fresh_credentials = {
        "aws_access_key_id": maws.credentials["AccessKeyId"],
        "aws_secret_access_key": maws.credentials["SecretAccessKey"],
        "aws_session_token": maws.credentials["SessionToken"],
        "expiry": maws.credentials["Expiration"],
    }

    keyfile.write(value2json(fresh_credentials))
    return fresh_credentials

MAWS()
