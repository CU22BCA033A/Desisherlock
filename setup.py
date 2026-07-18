from setuptools import setup, find_packages

with open("requirements.txt") as f:
    requirements = [line.strip() for line in f if line.strip()]

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="desisherlock",
    version="0.1.0",
    description="Recon, vulnerability-assessment, and reporting toolkit for security professionals",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Desisherlock contributors",
    license="MIT",
    packages=find_packages(include=["desisherlock", "desisherlock.*"]),
    include_package_data=True,
    package_data={
        "desisherlock": ["data/*.txt"],
    },
    install_requires=requirements,
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "Desisherlock=desisherlock.cli:main",
            "desisherlock=desisherlock.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
        "Environment :: Console",
    ],
)
