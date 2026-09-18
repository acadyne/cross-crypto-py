from pathlib import Path

from setuptools import find_packages, setup

ROOT = Path(__file__).parent

setup(
    name="cross-crypto-py",
    version="3.0.0rc4",
    description="Cross-Crypto Protocol v3 para interoperabilidad Python con browser/TypeScript/JavaScript.",
    long_description=(ROOT / "README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    author="Jose Fabian Soltero Escobar",
    author_email="acadyne@gmail.com",
    url="https://github.com/acadyne/cross-crypto-py",
    license="MIT",
    packages=find_packages(),
    package_data={"cross_crypto_py": ["py.typed"]},
    python_requires=">=3.9",
    install_requires=["cryptography>=45.0.0"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Typing :: Typed",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
