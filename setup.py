from setuptools import setup, find_packages

setup(
    name='odpsc',
    version='1.0.0',
    description='ODP Support Collector - Diagnostic collection for Hadoop/ODP clusters',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='ODP Team',
    license='Apache-2.0',
    packages=find_packages(),
    python_requires='>=3.6',
    install_requires=[
        'flask>=2.0,<4.0',
        'schedule>=1.1,<2.0',
        'requests>=2.25,<3.0',
        'psutil>=5.8,<6.0',
        'cryptography>=3.4,<43.0',
    ],
    extras_require={
        'dev': [
            'pytest>=7.0,<9.0',
            'pytest-cov>=4.0,<6.0',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
    ],
)
