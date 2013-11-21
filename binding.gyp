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
                ['OS=="win"', {
                    'include_dirs': [
                    '<(node_root_dir)/deps/openssl/openssl/include'
                      ],
                      "conditions" : [
                        ["target_arch=='ia32'", {
                          "include_dirs": [ "<(node_root_dir)/deps/openssl/config/piii" ]
                        }],
                        ["target_arch=='x64'", {
                          "include_dirs": [ "<(node_root_dir)/deps/openssl/config/k8" ]
                        }],
                        ["target_arch=='arm'", {
                          "include_dirs": [ "<(node_root_dir)/deps/openssl/config/arm" ]
                        }]
                      ]
                  
                }, { # 'OS!="win"'
                  'libraries': [
                    '<!@(pkg-config openssl --libs)',
                   ]
                }]
        ]
    }
    
  ]
}

