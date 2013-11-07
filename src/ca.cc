
#include "ca.h"

using namespace v8;


CA::CA(){}

CA::~CA(){}


// create/load pkey
// pkey#req 
// create/load ca
// ca#sing


void CA::Init(Handle<Object> exports) {

    // Prepare constructor template
    Local<FunctionTemplate> tpl = FunctionTemplate::New(New);
    tpl->SetClassName(String::NewSymbol("CA"));
    tpl->InstanceTemplate()->SetInternalFieldCount(1);
    // Prototype
    tpl->PrototypeTemplate()->Set(String::NewSymbol("createCertificate"), FunctionTemplate::New(Gen)->GetFunction());
    tpl->PrototypeTemplate()->Set(String::NewSymbol("loadPrivateKey"), FunctionTemplate::New(LoadPKey)->GetFunction());
    tpl->PrototypeTemplate()->Set(String::NewSymbol("loadCA"), FunctionTemplate::New(LoadCA)->GetFunction());
    tpl->PrototypeTemplate()->Set(String::NewSymbol("generatePrivateKey"), FunctionTemplate::New(GenPKey)->GetFunction());
    
    Persistent<Function> constructor = Persistent<Function>::New(tpl->GetFunction());
    exports->Set(String::NewSymbol("CA"), constructor);
}


Handle<Value> CA::New(const Arguments& args) {
    CA* obj = new CA();
    obj->Wrap(args.This());
    return args.This();
}


Handle<Value> CA::GenPKey(const Arguments& args) {
    HandleScope scope;

    CA* obj = ObjectWrap::Unwrap<CA>(args.This());
    
    int bits = 1024;
    
    if(args[0]->IsNumber())
        bits = args[0]->NumberValue();
    
    
    RSA* rsa = RSA_generate_key(bits, RSA_F4, NULL, NULL);
    obj->pkey = EVP_PKEY_new();
    if (!EVP_PKEY_assign_RSA(obj->pkey, rsa)){
        obj->pkey = NULL;
        return ThrowException(Exception::Error(String::New("error EVP_PKEY_assign_RSA" )));
    }
    
    BIO *bp = BIO_new(BIO_s_mem());
    
    PEM_write_bio_RSAPrivateKey(bp, rsa, NULL, NULL, 0, NULL, NULL);

    BUF_MEM *bptr;
    BIO_get_mem_ptr(bp, &bptr);
    char *rsa_buf = (char *) malloc(bptr->length+1);
    memcpy(rsa_buf, bptr->data, bptr->length-1);
    rsa_buf[bptr->length-1] = 0;
    Local<String> rsa_str = String::New(rsa_buf);
    free(rsa_buf);
    
    BIO_free(bp);
     
    return scope.Close(rsa_str);
}


Handle<Value> CA::LoadPKey(const Arguments& args) {
    HandleScope scope;

    CA* obj = ObjectWrap::Unwrap<CA>(args.This());
        
    char *data;
    size_t data_len;
          
    if (node::Buffer::HasInstance(args[0])) {
        Local<Object> buf = args[0]->ToObject();
        data = node::Buffer::Data(buf);
        data_len = node::Buffer::Length(buf);
    }
    else return ThrowException(Exception::Error(String::New("PEM body must be a Buffer" )));
        
      
    BIO *bio = BIO_new_mem_buf(data, data_len);
    obj->pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    
    BIO_free_all(bio);
    
    if (!obj->pkey)
            return ThrowException(Exception::Error(String::New( "PEM not load" )));
    
    return scope.Close(Boolean::New(1));
}

Handle<Value> CA::LoadCA(const Arguments& args) {
    HandleScope scope;

    CA* obj = ObjectWrap::Unwrap<CA>(args.This());
        
    char *data;
    size_t data_len;
    BIO *bio;
         
    if (node::Buffer::HasInstance(args[0])) {
        Local<Object> buf = args[0]->ToObject();
        data = node::Buffer::Data(buf);
        data_len = node::Buffer::Length(buf);
    }
    else return ThrowException(Exception::Error(String::New( "PEM body must be a Buffer" )));
        
      
    bio = BIO_new_mem_buf(data, data_len);
    obj->ca_pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
       
    if (!obj->ca_pkey)
            return ThrowException(Exception::Error(String::New( "ca_pkey PEM not load" )));
    
    BIO_free_all(bio);
          
    if (node::Buffer::HasInstance(args[1])) {
        Local<Object> buf = args[1]->ToObject();
        data = node::Buffer::Data(buf);
        data_len = node::Buffer::Length(buf);
    }
    else return ThrowException(Exception::Error(String::New( "PEM body must be a Buffer" )));
        
      
    bio = BIO_new_mem_buf(data, data_len);
    obj->ca_cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    
    BIO_free_all(bio);
     
    if (!obj->ca_cert)
            return ThrowException(Exception::Error(String::New( "ca_cert PEM not load" )));

    return scope.Close(Boolean::New(1));
}


int add_ext(X509 *cert, int nid, const char *value){
        X509_EXTENSION *ex;
        X509V3_CTX ctx;
        /* This sets the 'context' of the extensions. */
        /* No configuration database */
        X509V3_set_ctx_nodb(&ctx);
        /* Issuer and subject certs: both the target since it is self signed,
         * no request and no CRL
         */
        X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
        ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, (char *)value);
        if (!ex)
                return 0;

        X509_add_ext(cert,ex,-1);
        X509_EXTENSION_free(ex);
        return 1;
}

Handle<Value> CA::Gen(const Arguments& args) {
    HandleScope scope;
    CA* obj = ObjectWrap::Unwrap<CA>(args.This());
    
    if(!obj->pkey) 
        return ThrowException(Exception::Error(String::New("error not load pkey ")));
        
        
     X509 *xcert = X509_new();
    
    //#ifdef X509_V3
       X509_set_version(xcert, 2);
    // #endif
   
    //X509_REQ *req = X509_REQ_new();
    
    
    //if (!X509_REQ_set_version(req,0L))
    //   return ThrowException(Exception::Error(String::New("error X509_REQ_set_version")));

    Local<Object> arg_obj = args[0]->ToObject();
    
   // X509_NAME *subj  = X509_REQ_get_subject_name(req);
    
    X509_NAME *subj = X509_get_subject_name(xcert);
    
    if(arg_obj->Has(v8::String::NewSymbol("subject"))){    
        
        Local<Object> subj_obj =  arg_obj->Get(v8::String::NewSymbol("subject"))->ToObject();
        Local<v8::Array> names = subj_obj->GetPropertyNames();
        
        for (unsigned int i= 0; i<names->Length(); i++ ) {
            v8::Local<v8::String> name = names->Get(i)->ToString();
           
            if(subj_obj->Get(name)->IsString()){
                if (!X509_NAME_add_entry_by_txt(subj, (const char*)(* String::AsciiValue(name) ) , MBSTRING_ASC,  (const unsigned char*)( * String::AsciiValue(subj_obj->Get(name))), -1,-1,0)) {
                     return ThrowException(Exception::Error(String::New("error X509_NAME_add_entry_by_txt")));
                }
            }
        }
    }
   
    //if (!X509_REQ_set_pubkey(req,obj->pkey))
    //    return ThrowException(Exception::Error(String::New("error X509_REQ_set_pubkey")));
    
    //const EVP_MD *digest = EVP_sha1();
    
    //if (!X509_REQ_sign(req, obj->pkey, digest))
     //   return ThrowException(Exception::Error(String::New("error X509_REQ_sign")));
   
   
    /// gen cert
   
   
    
    int serial = 1;
    if(arg_obj->Has(v8::String::NewSymbol("serial")))
        serial = arg_obj->Get(v8::String::NewSymbol("serial"))->IntegerValue();
        
    ASN1_INTEGER_set(X509_get_serialNumber(xcert), serial); 
    
    X509_set_issuer_name(xcert,X509_get_subject_name(obj->ca_cert));
    
    //X509_gmtime_adj(X509_get_notBefore(xcert), 0);
    //ASN1_TIME_set_string(X509_get_notBefore(xcert),"000101000000-0000");
    time_t startTime = NULL;
    
    if( arg_obj->Has(v8::String::NewSymbol("startDate")) ){
        Local<v8::Date> date = v8::Date::Cast(*arg_obj->Get(v8::String::NewSymbol("startDate")));
        startTime = (time_t)(date->NumberValue()/1000);
    }
    
    X509_time_adj(X509_get_notBefore(xcert), 0, &startTime);
    
    
    int days = 360;
    if(arg_obj->Has(v8::String::NewSymbol("days")))
        days = arg_obj->Get(v8::String::NewSymbol("days"))->IntegerValue();
    
    X509_time_adj_ex(X509_get_notAfter(xcert),days, 0, NULL);
    
    
    //X509_set_subject_name(xcert,subj);
      
    //X509_set_pubkey(xcert,X509_REQ_get_pubkey(req));
    X509_set_pubkey(xcert,obj->pkey);
    
    //int OBJ_sn2nid(const char *sn); #include <openssl/objects.h>
    /* Add various extensions: standard extensions */
    //add_ext(xcert, NID_basic_constraints, "critical,CA:TRUE");
    //add_ext(xcert, NID_key_usage, "critical,keyCertSign,cRLSign");
    //add_ext(xcert, NID_subject_key_identifier, "hash");
    /* Some Netscape specific extensions */
    //add_ext(xcert, NID_netscape_cert_type, "sslCA");
    //add_ext(xcert, NID_netscape_comment, "example comment extension");

    
    X509_sign(xcert, obj->ca_pkey , EVP_sha1() );
    

   
   
    BIO *bp = BIO_new(BIO_s_mem());
    
    PEM_write_bio_X509(bp, xcert);

    BUF_MEM *bptr;
    BIO_get_mem_ptr(bp, &bptr);
    char *x509_buf = (char *) malloc(bptr->length+1);
    memcpy(x509_buf, bptr->data, bptr->length-1);
    x509_buf[bptr->length-1] = 0;
    Local<String> x509_str = String::New(x509_buf);
    free(x509_buf);
    BIO_free(bp);
     
    //return v8::External::New(req);
    //return scope.Close(v8::External::New(req));
    return scope.Close(x509_str);
}
