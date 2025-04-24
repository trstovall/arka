
from setuptools import setup, find_packages, Extension


_crypto = Extension(
    name="arka._crypto",
    sources=["arka/cryptomodule.c"],
    include_dirs=["arka"],
)


setup(
    name="arka",
    version="0.0.2",
    author="T. R. Stovall",
    author_email="arkacoin.io@gmail.com",
    description="A community managed digital money supply",
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    url="https://github.com/trstovall/arka",
    license="MIT",
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
    ],
    packages=find_packages(where="."),
    python_requires=">=3.10, <4",
    ext_modules=[_crypto]
)
