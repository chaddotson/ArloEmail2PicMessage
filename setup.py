from setuptools import setup

version = '0.1.0'

temp_install_reqs = []
install_reqs = []
dependency_links = []

with open("requirements.txt", "r") as f:
    temp_install_reqs = list(map(str.strip, f.readlines()))

for req in temp_install_reqs:
    # This if should be expanded with all the other possibilities that can exist.  However, this
    # simple version works for this program.
    if req.startswith("https://"):
        dependency_links.append(req)
        install_reqs.append(req[req.find("egg=") + 4:].replace("-", "==", 1))
    else:
        install_reqs.append(req)

setup(
    name='ArloEmail2PicMessage',
    version=version,
    packages=['scripts'],
    url='',
    license='',
    author='Chad Dotson',
    author_email='chad@cdotson.com',
    description='',
    install_requires=install_reqs,
    dependency_links=dependency_links,
    entry_points={
        'console_scripts': [
            'ArloEmail2PicMessage = scripts.main:main',
        ]
    },
)
