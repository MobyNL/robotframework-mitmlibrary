from distutils.core import setup
setup(
  name = 'robotframework-mitmlibrary',
  packages = ['MitmLibrary'],
  version = '0.1.1',
  license='MIT',
  description = 'Wrapper for mitmproxy with Robot Framework',
  author = 'Mark Moberts',
  author_email = 'markmoberts@gmail.com',
  url = 'https://github.com/MobyNL/robotframework-mitmlibrary',
  download_url = 'https://github.com/MobyNL/robotframework-mitmlibrary/archive/refs/tags/0.1.tar.gz',
  keywords = ['robotframework', 'automation', 'testautomation','testing','mitm','maninthemiddle'],
  install_requires=[
          'mitm',
          'robotframework',
      ],
  classifiers=[
    'Development Status :: 3 - Alpha',
    'Intended Audience :: Developers',
    'Topic :: Software Development :: Build Tools',
    'License :: OSI Approved :: MIT License',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.10',
    'Programming Language :: Python :: 3.11',
  ]
)