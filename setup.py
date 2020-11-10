from setuptools import setup, find_packages


setup(
    name="openssh-network-parser",
    description="Framework to decrypt and parse OpenSSH traffic.",
    packages=find_packages(),
    use_scm_version=True,
    include_package_data=True,
    setup_requires=['setuptools_scm'],
    python_requires='>=2.7, <3', #pynids is not compatible with py3 :(
    dependency_links=[
        'git+https://github.com/MITRECND/pynids.git#egg=pynids'
    ],
    install_requires=[
        'dissect.cstruct',
        'psutil',
        'tabulate',
        'gevent',
        'libnacl',
        'cryptography',
    ],
    entry_points = {
        'console_scripts': [
            'network-parser=openssh_network_parser.tools.network_parser:main',
        ]
    }
)
