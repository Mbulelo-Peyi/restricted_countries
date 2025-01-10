from setuptools import setup, find_packages

setup(
    name='django-restricted-countries',  # Name of your package
    version='0.1.0',  # Version of your package
    description='Django middleware to restrict access based on the client\'s country',
    long_description=open('README.md').read(),  # Read the content of README.md
    long_description_content_type='text/markdown',
    author='Mbulelo Phillip Peyi',
    author_email='your.email@example.com',
    url='https://github.com/yourusername/django-restricted-countries',  # GitHub repository URL
    packages=find_packages(),  # Find all packages in the current directory
    keywords=['django', 'restricted access', 'web', 'country', 'logging'],
    classifiers=[
        'Programming Language :: Python :: 3',
        'Framework :: Django',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    install_requires=[
        'Django>=3.1',
        'geoip2>=4.0',
        'ipware>=2.1',
    ],
    include_package_data=True,
    python_requires='>=3.6',
)
