
from setuptools import setup, find_packages, Extension


_crypto = Extension(
    name="arka.crypto",
    sources=["crypto/cryptomodule.c"],
    include_dirs=["crypto"],
)

setup(
    name="arka",
    version="0.0.1",
    description="short description",
    long_description="long description",
    packages=find_packages(where="."),
    python_requires=">=3.10, <4",
    ext_modules=[_crypto]
)
