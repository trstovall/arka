
from setuptools import setup, find_packages, Extension


_crypto = Extension(
    name="arka._crypto",
    sources=["arka/cryptomodule.c"],
    include_dirs=["arka"],
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
