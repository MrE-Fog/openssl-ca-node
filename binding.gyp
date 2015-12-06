{  
"variables": {
   },
  "targets": [
    {
    
        "target_name": "ca",
        "sources": [ 
#            "src/init.cc",
            "src/ca.cc"
        ],
        "libraries": [
            "<!@(pkg-config openssl --libs)",
        ],
        "include_dirs": [
    	  "<!(node -e \"require('nan')\")"
    	]
    }
    
  ]
}

