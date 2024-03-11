from setuptools import setup

setup(
    name = "vulture-gui",
    version = "2.15.0",
    packages = ["home", "vulture_os"],
    author = "VultureProject",
    author_email = "contact@vultureproject.org",
    description = "GUI for VultureOS based on Django",
    license = "GNU GENERAL PUBLIC LICENSE",
    url = "https://github.com/VultureProject/vulture-gui/",
    classifiers=[],
    install_requires = [
        "django~=4.2.0",
        "djongo[json]",
        "pymongo",
        "jinja2",
        "iptools",
        "django-crontab",
        "requests",
        "pyOpenSSL",
        "redis~=4.5",
        "cryptography",
        "python-ldap~=3.3",
        "authy",
        "pyotp",
        "qrcode",
        "captcha",
        "beautifulsoup4",
        "robobrowser",
        "python-magic",
        "kerberos",
        "pyrad",
        "maxminddb",
        "validators",
        "boto3",
        "edgegrid-python",
        "meraki",
        "requests-oauthlib",
        "gunicorn",
        "pyjwt ~= 2.3",
        "websocket-client ~= 1.3.2",
        "google-auth",
        "google-api-python-client",
        "add_setup-py",
        "defusedxml",
    ],
)