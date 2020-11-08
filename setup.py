import setuptools

with open('README.md', 'r') as f:
    long_description = f.read()

setuptools.setup(
    name='misakoba-mail',
    version='0.0.1',
    author='Dan Garubba',
    author_email='dan.garubba@gmail.com',
    description=('A simple form handling service for sending an email from a '
                 'web page'),
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/misakoba/mail',
    packages=setuptools.find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.8',
)
