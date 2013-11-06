

#ifndef REQ_H
#define REQ_H

#include <node.h>
#include <v8.h>

#include <node_buffer.h>
#include <node_object_wrap.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>


class CA : public node::ObjectWrap {
 public:
  static void Init(v8::Handle<v8::Object> exports);

 private:
  CA();
  ~CA();
  
  EVP_PKEY *pkey; 
  EVP_PKEY *ca_pkey;
  X509 *ca_cert;
  static v8::Handle<v8::Value> New(const v8::Arguments& args);
  static v8::Handle<v8::Value> LoadPKey(const v8::Arguments& args);
  static v8::Handle<v8::Value> LoadCA(const v8::Arguments& args);
  static v8::Handle<v8::Value> Gen(const v8::Arguments& args);
 
  static v8::Persistent<v8::Function> constructor;
 
};

#endif

