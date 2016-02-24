
#include <nan.h>
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


using namespace node;
using namespace v8;

class CA;


class MakeCertWorker : public Nan::AsyncWorker {
	public:
	MakeCertWorker(Nan::Callback *callback) : Nan::AsyncWorker(callback) {}
	~MakeCertWorker() {}
	
	void Execute();
	void HandleOKCallback();
	
	BIO *bp_xcert;
	X509 *xcert;
	CA *obj;
	bool self_signed;
};

int add_ext(X509 *cert, int nid, const char *value) {
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	/* This sets the 'context' of the extensions. */
	/* No configuration database */
	X509V3_set_ctx_nodb(&ctx);
	/* Issuer and subject certs: both the target since it is self signed,
	 * no request and no CRL
	 */
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, (char *) value);
	if (!ex)
		return 0;

	X509_add_ext(cert, ex, -1);
	X509_EXTENSION_free(ex);
	return 1;
}



class CA: public Nan::ObjectWrap {
	public:

	EVP_PKEY *pkey;
	EVP_PKEY *ca_pkey;
	X509 *ca_cert;
	
	static inline Nan::Persistent<v8::Function> & constructor() {
    	static Nan::Persistent<v8::Function> my_constructor;
    	return my_constructor;
	}

	
	static BIO * buffer2bio( v8::Local<v8::Value> val ){
		Nan::HandleScope scope;
		char *data;
		size_t data_len;
		
		//Local<Object> obj = val->ToObject();
		
		if (node::Buffer::HasInstance(val)) {
			data = node::Buffer::Data(val);
			data_len = node::Buffer::Length(val);
		} else
			return NULL;
		
		BIO *bio = BIO_new_mem_buf(data, data_len);

		return bio;
	}
	
	CA(EVP_PKEY *_pkey,EVP_PKEY *_ca_pkey,X509 *_ca_cert) {
		pkey = _pkey;
		ca_pkey = _ca_pkey;
		ca_cert = _ca_cert;
		CRYPTO_add(&pkey->references, 10, CRYPTO_LOCK_EVP_PKEY);
		CRYPTO_add(&ca_pkey->references, 10, CRYPTO_LOCK_EVP_PKEY);

	}
	
	~CA() {
		
		if(pkey) EVP_PKEY_free(pkey);
		if(ca_pkey) EVP_PKEY_free(ca_pkey);
		if(ca_cert) X509_free(ca_cert);
		
	}

	static NAN_METHOD(New) {
		if (!info.IsConstructCall()) {
		    const int argc = 1; 
		    v8::Local<v8::Value> argv[argc] = {info[0]};
		    v8::Local<v8::Function> cons = Nan::New(constructor());
		    info.GetReturnValue().Set(cons->NewInstance(argc, argv));
		    return;
		}
		
		EVP_PKEY *pkey;
		EVP_PKEY *ca_pkey;
		X509 *ca_cert;
		
		
		BIO *bp;
		
		bp = buffer2bio(info[0]);
		if(!bp) return Nan::ThrowError("error PKEY"); 
		pkey = PEM_read_bio_PrivateKey(bp, NULL, NULL, NULL);
		BIO_free_all(bp);
		if(!pkey) return Nan::ThrowError("error load PKEY"); 
		
		bp = buffer2bio(info[1]);
		if(!bp) return Nan::ThrowError("error CA PKEY");
		ca_pkey = PEM_read_bio_PrivateKey(bp, NULL, NULL, NULL);
		BIO_free_all(bp);
		if(!ca_pkey) return Nan::ThrowError("error load CA PKEY"); 

		bp = buffer2bio(info[2]);
		if(!bp) Nan::ThrowError("error CA CERT"); 
		ca_cert = PEM_read_bio_X509(bp, NULL, NULL, NULL);
		BIO_free_all(bp);
		
		if(!ca_cert) return Nan::ThrowError("error load CA CERT");
			

		
		CA* obj = new CA(pkey,ca_pkey,ca_cert);
		
		obj->Wrap(info.This());
		//obj->Ref();
		info.GetReturnValue().Set(info.This());
	}
	
	static void generatePrivateKey(const Nan::FunctionCallbackInfo<v8::Value>&  args) {
		Nan::HandleScope scope;

		int bits = 1024;

		if (args[0]->IsNumber())
			bits = args[0]->NumberValue();

		RSA* rsa = RSA_generate_key(bits, RSA_F4, NULL, NULL);
		EVP_PKEY *pkey = EVP_PKEY_new();
		if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
			pkey = NULL;
			return Nan::ThrowError("error EVP_PKEY_assign_RSA");
		}

		BIO *bp = BIO_new(BIO_s_mem());

		PEM_write_bio_RSAPrivateKey(bp, rsa, NULL, NULL, 0, NULL, NULL);

		BUF_MEM *bptr;
		BIO_get_mem_ptr(bp, &bptr);
		Local<String> rsa_str = Nan::New<v8::String>( (char *)bptr->data , bptr->length ).ToLocalChecked();;
		BIO_free(bp);
		EVP_PKEY_free(pkey);
		
		args.GetReturnValue().Set(rsa_str);
	}

	static void createCertificate(const Nan::FunctionCallbackInfo<v8::Value>& args) {
		
		Nan::HandleScope scope;
		CA* obj = ObjectWrap::Unwrap<CA>(args.This());

		if (args.Length() < 2) {
			return Nan::ThrowError("Expecting 2 arguments");
		}

		if (!args[1]->IsFunction()) {
			return Nan::ThrowError("Second argument must be a callback function");
		}

		Local<Object> arg_obj = args[0]->ToObject();
		
		Nan::Callback *callback = new Nan::Callback(args[1].As<v8::Function>());
		MakeCertWorker* worker = new MakeCertWorker(callback);
		
		X509 *xcert = worker->xcert = X509_new();
		worker->obj = obj;
		
/*
		baton->ca_pkey = EVP_PKEY_new();
		baton->pkey = EVP_PKEY_new();
		CRYPTO_add(&obj->pkey->references, 1, CRYPTO_LOCK_EVP_PKEY);
		EVP_PKEY_copy_parameters(baton->ca_pkey,obj->ca_pkey);
		EVP_PKEY_copy_parameters(baton->pkey,obj->pkey);
*/

/*
		baton->ca_pkey = obj->ca_pkey;
		baton->pkey = obj->pkey;

		CRYPTO_add(&obj->ca_pkey->references, 2, CRYPTO_LOCK_EVP_PKEY);
		CRYPTO_add(&obj->pkey->references, 2, CRYPTO_LOCK_EVP_PKEY);
*/


// set X509 cert

		X509_set_version(xcert, 2);
		// #endif

		//X509_REQ *req = X509_REQ_new();

		//if (!X509_REQ_set_version(req,0L))
		//   return ThrowException(Exception::Error(String::New("error X509_REQ_set_version")));
		// X509_NAME *subj  = X509_REQ_get_subject_name(req);

		X509_NAME *subj = X509_get_subject_name(xcert);

		if (arg_obj->Has(Nan::New("subject").ToLocalChecked())) {

			Local<Object> subj_obj = arg_obj->Get(Nan::New("subject").ToLocalChecked())->ToObject();
			Local<v8::Array> names = subj_obj->GetPropertyNames();

			for (unsigned int i = 0; i < names->Length(); i++) {
				v8::Local<v8::String>name = names->Get(i)->ToString();

				if(subj_obj->Get(name)->IsString()){
					if (!X509_NAME_add_entry_by_txt(subj, (const char*)( *Nan::Utf8String(name) ) , MBSTRING_ASC,  (const unsigned char*)( *Nan::Utf8String(subj_obj->Get(name))), -1,-1,0)) {
						return Nan::ThrowError("error X509_NAME_add_entry_by_txt");
					}
				}
			}
		}
		
		if (arg_obj->Has(Nan::New("selfSigned").ToLocalChecked()) && arg_obj->Get(Nan::New("selfSigned").ToLocalChecked())->IsTrue()) {
			worker->self_signed = true;
		}else{
			worker->self_signed = false;
		}
		
		//if (!X509_REQ_set_pubkey(req,obj->pkey))
		//    return ThrowException(Exception::Error(String::New("error X509_REQ_set_pubkey")));

		//const EVP_MD *digest = EVP_sha1();

		//if (!X509_REQ_sign(req, obj->pkey, digest))
		//   return ThrowException(Exception::Error(String::New("error X509_REQ_sign")));

		/// gen cert

		int serial = 1;
		if (arg_obj->Has(Nan::New("serial").ToLocalChecked()))
			serial = arg_obj->Get(Nan::New("serial").ToLocalChecked())->IntegerValue();

		ASN1_INTEGER_set(X509_get_serialNumber(xcert), serial);
		
		X509_set_issuer_name(xcert, worker->self_signed  ? subj : X509_get_subject_name(obj->ca_cert));
				//X509_gmtime_adj(X509_get_notBefore(xcert), 0);
		//ASN1_TIME_set_string(X509_get_notBefore(xcert),"000101000000-0000");
		time_t startTime = 0;

		if (arg_obj->Has(Nan::New("startDate").ToLocalChecked())) {
			v8::Date * date = v8::Date::Cast((v8::Value *)*arg_obj->Get(Nan::New("startDate").ToLocalChecked()));
			
			startTime = (time_t)(date->NumberValue() / 1000);
		}
		

		
		X509_time_adj(X509_get_notBefore(xcert), 0, &startTime);

		int days = 360;
		if (arg_obj->Has(Nan::New("days").ToLocalChecked()))
		days = arg_obj->Get(Nan::New("days").ToLocalChecked())->IntegerValue();

		X509_time_adj_ex(X509_get_notAfter(xcert), days, 0, NULL);
		
		
		v8::Local<v8::String> sym_subjectAltName = Nan::New("subjectAltName").ToLocalChecked();
		
		if (arg_obj->Has(sym_subjectAltName) && arg_obj->Get(sym_subjectAltName)->IsString()){
			add_ext(xcert, NID_subject_alt_name,(const char *)(*Nan::Utf8String(arg_obj->Get(sym_subjectAltName))));
		}
		
		
		Nan::AsyncQueueWorker(worker);
		
		args.GetReturnValue().SetUndefined();
	}

	static NAN_MODULE_INIT(Initialize) {
		Nan::HandleScope scope;
		
		v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
		
		tpl->SetClassName(Nan::New("CA").ToLocalChecked());
		tpl->InstanceTemplate()->SetInternalFieldCount(1);
		
		Nan::SetPrototypeMethod(tpl, "createCertificate", createCertificate);
		//Nan::SetPrototypeMethod(tpl, "generatePrivateKey", generatePrivateKey);
		
		constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
		
		Nan::Set(target, Nan::New("CA").ToLocalChecked(), Nan::GetFunction(tpl).ToLocalChecked());
		Nan::Set(Nan::GetFunction(tpl).ToLocalChecked(), Nan::New<String>("generatePrivateKey").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(generatePrivateKey)).ToLocalChecked());
    
	}
};





	// Executed inside the worker-thread.
	// It is not safe to access V8, or V8 data structures
	// here, so everything we need for input and output
	// should go on `this`.
void MakeCertWorker::Execute () {


		//X509_set_subject_name(xcert,subj);

		//X509_set_pubkey(xcert,X509_REQ_get_pubkey(req));
		X509_set_pubkey(xcert, obj->pkey);

		//int OBJ_sn2nid(const char *sn); #include <openssl/objects.h>
		/* Add various extensions: standard extensions */
		//add_ext(xcert, NID_basic_constraints, "critical,CA:TRUE");
		//add_ext(xcert, NID_key_usage, "critical,keyCertSign,cRLSign");
		//add_ext(xcert, NID_subject_key_identifier, "hash");
		/* Some Netscape specific extensions */
		//add_ext(xcert, NID_netscape_cert_type, "sslCA");
		//add_ext(xcert, NID_netscape_comment, "example comment extension");

		X509_sign(xcert, self_signed ? obj->pkey : obj->ca_pkey, EVP_sha256());

		bp_xcert = BIO_new(BIO_s_mem());

		PEM_write_bio_X509(bp_xcert, xcert);
		X509_free(xcert);

		//BUF_MEM *bptr;
		//BIO_get_mem_ptr(bp, &bptr);
		//char *x509_buf = (char *) malloc(bptr->length+1);
		//memcpy(x509_buf, bptr->data, bptr->length-1);
		//x509_buf[bptr->length-1] = 0;
		//Local<String> x509_str = String::New(x509_buf);

		//free(x509_buf);
		//bptr->data[bptr->length - 1] = 0;
		//baton->x509_buf = bptr->data;
		//BIO_free(bp);
}

	// Executed when the async work is complete
	// this function will be run inside the main event loop
	// so it is safe to use V8 again
void MakeCertWorker::HandleOKCallback () {
 		Nan::HandleScope scope;

		if (!xcert) {
			
			Local<Value> err = Exception::Error(Nan::New("error").ToLocalChecked());
			const unsigned argc = 1;
			Local<Value> argv[argc] = { err };

			Nan::TryCatch try_catch;
			callback->Call(Nan::GetCurrentContext()->Global(), argc, argv);
			if (try_catch.HasCaught())
				Nan::FatalException(try_catch);
				
		} else {
			
			BUF_MEM *bptr;
			BIO_get_mem_ptr(bp_xcert, &bptr);
			
			const unsigned argc = 2;
			Local<Value> argv[argc] = {
				Nan::Null(), ( bptr->data ? Nan::New<v8::String>( bptr->data , bptr->length ).ToLocalChecked() : Nan::EmptyString() )
			};

			Nan::TryCatch try_catch;
			callback->Call(Nan::GetCurrentContext()->Global(), argc, argv);
			if (try_catch.HasCaught())
				Nan::FatalException(try_catch);
		}

		if(bp_xcert)
			BIO_free(bp_xcert);
}




NAN_MODULE_INIT(init) {
	CA::Initialize(target);
}

NODE_MODULE(ca, init);

