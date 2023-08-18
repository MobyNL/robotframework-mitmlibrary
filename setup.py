from distutils.core import setup
setup(
  name = 'MitmLibrary',
  packages = ['MitmLibrary'],
  version = '0.1',
  license='MIT',
  description = 'Wrapper for mitmproxy with robotframework',
  author = 'Mark Moberts',
  author_email = 'markmoberts@gmail.com',
  url = 'https://github.com/MobyNL/robotframework-mitmlibrary',
  download_url = 'https://github.com/user/reponame/archive/v_01.tar.gz',
  keywords = ['robotframework', 'automation', 'testautomation','testing','mitm','maninthemiddle'],
  install_requires=[
          'mitm',
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