from setuptools import setup, find_packages

setup(
    name='srei',
    version='0.1.0',
    description='Shellcode Reflective ELF Injection',
    long_description='Converts Linux shared libraries (.so) into '
                     'position-independent shellcode for in-memory execution. '
                     'Self-contained pure Python.',
    author='SREI Project',
    license='MIT',
    python_requires='>=3.6',
    packages=find_packages(where='python'),
    package_dir={'': 'python'},
    entry_points={
        'console_scripts': [
            'srei=srei:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Topic :: Security',
    ],
)
