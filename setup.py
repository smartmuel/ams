import setuptools
import subprocess
import sys

'''def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package, "--trusted-host","pypi.org", "--trusted-host","files.pythonhosted.org"])

Lib = ["Selenium", "requests", "paramiko", "chromedriver_autoinstaller", "bps_restpy"]
for i in Lib:
    try:
        install(i)
    except:
        print(f"Falled to Download {i}")'''
with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="ams", # Replace with your own username
    version="0.0.2",
    author="Example Author",
    author_email="author@example.com",
    description="A small example package",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/pypa/sampleproject",
    packages=setuptools.find_packages(),
    install_requires=[
            'Selenium',
            'requests',
            'paramiko',
            'chromedriver_autoinstaller',
            'bps_restpy'
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
