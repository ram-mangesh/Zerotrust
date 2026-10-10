from setuptools import setup, find_packages

setup(
    name="vajranetra-ztna-sdk",
    version="1.0.0",
    description="Python SDK and middleware for VajraNetra Zero Trust Network Access",
    author="VajraNetra Security Team",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[],
    extras_require={
        "fastapi": ["starlette", "fastapi"],
        "flask": ["flask"],
    },
)
