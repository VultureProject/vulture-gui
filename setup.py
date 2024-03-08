from setuptools import setup
import pathlib
import pkg_resources

with pathlib.Path('requirements.txt').open() as requirements_txt:
    install_requires = [
        str(requirement) for requirement in pkg_resources.parse_requirements(requirements_txt)
    ]

setup(
    name = "vulture-gui",
    version = "2.15.0",
    author = "VultureProject",
    author_email = "contact@vultureproject.org",
    description = "GUI for VultureOS based on Django",
    license = "GNU GENERAL PUBLIC LICENSE",
    url = "https://github.com/VultureProject/vulture-gui/",
    classifiers=[],
    install_requires = install_requires,
)