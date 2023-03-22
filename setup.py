from setuptools import setup

try:
    import pypandoc
    long_description = pypandoc.convert_file('README.md', 'rst')
except(IOError, ImportError):
    long_description = open('README.md').read()


setup(
    name='boman-cli',
    version='1.03',    
    description='CLI tool of boman.ai',
    long_description_content_type="text/markdown",
    long_description=long_description,
    url='https://boman.ai',
    author='Sumeru Software Solutions Pvt. Ltd.',
    author_email='support@boman.ai',
    license='BSD 2-clause',
    packages=['bomancli'],
    entry_points = {
        'console_scripts': ['boman-cli=bomancli.main:default'],
    },
    install_requires=['docker',
                      'requests',
                      'pyyaml',
                      'coloredlogs','xmltodict'                     
                      ],

    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',  
        'Operating System :: OS Independent',        
    ],
)
