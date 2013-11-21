{  
'variables': {
   },
  "targets": [
    {
    
        "target_name": "ca",
        "sources": [ 
            "src/init.cc",
            "src/ca.cc"
        ]
        ,
        'conditions': [
                ['OS=="win"',  {
                      'conditions': [
                        # "openssl_root" is the directory on Windows of the OpenSSL files
                        ['target_arch=="x64"', {
                          'variables': {
                            'openssl_root%': 'C:/OpenSSL-Win64'
                          },
                        }, {
                          'variables': {
                            'openssl_root%': 'C:/OpenSSL-Win32'
                          },
                        }],
                      ],
                      'defines': [
                        'uint=unsigned int',
                      ],
                      'libraries': [ 
                        '-l<(openssl_root)/lib/libeay32.lib',
                      ],
                      'include_dirs': [
                        '<(openssl_root)/include',
                      ],
                }, { # 'OS!="win"'
                  'libraries': [
                    '<!@(pkg-config openssl --libs)',
                   ]
                }]
        ]
    }
    
  ]
}

