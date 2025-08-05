from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="cross-crypto-py",
    version="1.1.2",
    description="Cifrado híbrido seguro con interoperabilidad entre lenguajes como Python, TypeScript y Rust, basado en AES-GCM (256 bits) y RSA-OAEP (4096 bits)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Jose Fabian Soltero Escobar",
    author_email="acadyne@gmail.com",
    url="https://github.com/acadyne/cross-crypto-py",
    license="MIT",
    packages=find_packages(),
    package_data={
        "cross_crypto_py": ["*.pyi"], 
    },    
    classifiers=[
        'Development Status :: 5 - Production/Stable',

        # Audiencia y propósito
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Topic :: Security',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',

        # Licencia
        'License :: OSI Approved :: MIT License',

        # Versiones de Python soportadas
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',

        # Interoperabilidad
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: JavaScript',
        'Framework :: AsyncIO',

        # Sistemas operativos
        'Operating System :: OS Independent',

        # Características especiales
        'Environment :: Web Environment',
        'Natural Language :: English',
        'Typing :: Typed'
    ],
    python_requires=">=3.7",
    install_requires=[
        'cryptography>=40.0.2',
        'pycryptodome>=3.17',
        'dill>=0.3.6'
    ],
    include_package_data=True,
    keywords=[
        "encryption",
        "cryptography",
        "security",
        "typescript",
        "python",
        "rsa",
        "aes",
        "hybrid-encryption",
        "cross-platform",
        "secure-communication",
        "data-protection",
        "crypto",
        "gcm",
        "oaep"
    ],
    project_urls={
    'Documentation': 'https://github.com/acadyne/cross-crypto-py#readme',
    'Source': 'https://github.com/acadyne/cross-crypto-py',
    'Tracker': 'https://github.com/acadyne/cross-crypto-py/issues',
    },
)