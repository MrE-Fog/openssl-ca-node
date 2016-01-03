
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

struct Baton {
	uv_work_t request;
	Nan::Callback *callback;

	char *x509_buf;
	BIO *bp;
	bool error;
	Local < Value > errorValue ;
	CA* obj;
	X509 *xcert;
	EVP_PKEY *ca_pkey;
	EVP_PKEY *pkey;
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


Nan::Persistent<v8::Function> constructor;

class CA: public ObjectWrap {
public:
	EVP_PKEY *pkey;
	EVP_PKEY *ca_pkey;
	X509 *ca_cert;

	CA() {}
	~CA() {}

	static void New(const Nan::FunctionCallbackInfo<v8::Value>& info) {
		if (info.IsConstructCall()) {
			CA* obj = new CA();
			obj->Wrap(info.This());
			info.GetReturnValue().Set(info.This());
		}else {
		    const int argc = 1; 
		    v8::Local<v8::Value> argv[argc] = {info[0]};
		    v8::Local<v8::Function> cons = Nan::New(constructor);
		    info.GetReturnValue().Set(cons->NewInstance(argc, argv));
		}
	}

	static void generatePrivateKey(const Nan::FunctionCallbackInfo<v8::Value>&  args) {
		Nan::HandleScope scope;

		CA* obj = ObjectWrap::Unwrap < CA > (args.This());

		int bits = 1024;

		if (args[0]->IsNumber())
			bits = args[0]->NumberValue();

		RSA* rsa = RSA_generate_key(bits, RSA_F4, NULL, NULL);
		obj->pkey = EVP_PKEY_new();
		if (!EVP_PKEY_assign_RSA(obj->pkey, rsa)) {
			obj->pkey = NULL;
			return Nan::ThrowError("error EVP_PKEY_assign_RSA");
		}

		BIO *bp = BIO_new(BIO_s_mem());

		PEM_write_bio_RSAPrivateKey(bp, rsa, NULL, NULL, 0, NULL, NULL);

		BUF_MEM *bptr;
		BIO_get_mem_ptr(bp, &bptr);
		char *rsa_buf = (char *) malloc(bptr->length + 1);
		memcpy(rsa_buf, bptr->data, bptr->length - 1);
		rsa_buf[bptr->length - 1] = 0;
		Local<String> rsa_str = Nan::New(rsa_buf).ToLocalChecked();
		free(rsa_buf);

		BIO_free(bp);
		
		args.GetReturnValue().Set(rsa_str);
	}

	static void loadPrivateKey(const Nan::FunctionCallbackInfo<v8::Value>& args) {
		Nan::HandleScope scope;

		CA* obj = ObjectWrap::Unwrap<CA>(args.This());

		char *data;
		size_t data_len;

		if (node::Buffer::HasInstance(args[0])) {
			Local < Object > buf = args[0]->ToObject();
			data = node::Buffer::Data(buf);
			data_len = node::Buffer::Length(buf);
		} else
			return Nan::ThrowError("PEM body must be a Buffer");

		BIO *bio = BIO_new_mem_buf(data, data_len);
		obj->pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);

		BIO_free_all(bio);


		if (!obj->pkey)
			return Nan::ThrowError("PEM not load");
		
		args.GetReturnValue().Set(Nan::True());
	}

	static void loadCA(const Nan::FunctionCallbackInfo<v8::Value>& args) {
		Nan::HandleScope scope;

		CA* obj = ObjectWrap::Unwrap <CA> (args.This());

		char *data;
		size_t data_len;
		BIO *bio;

		if (node::Buffer::HasInstance(args[0])) {
			Local < Object > buf = args[0]->ToObject();
			data = node::Buffer::Data(buf);
			data_len = node::Buffer::Length(buf);
		} else
			return Nan::ThrowError("PEM body must be a Buffer");

		bio = BIO_new_mem_buf(data, data_len);
		obj->ca_pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);

		if (!obj->ca_pkey)
			return Nan::ThrowError("ca_pkey PEM not load");




		BIO_free_all(bio);

		if (node::Buffer::HasInstance(args[1])) {
			Local < Object > buf = args[1]->ToObject();
			data = node::Buffer::Data(buf);
			data_len = node::Buffer::Length(buf);
		} else
			return Nan::ThrowError("PEM body must be a Buffer");

		bio = BIO_new_mem_buf(data, data_len);
		obj->ca_cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);

		BIO_free_all(bio);

		if (!obj->ca_cert)
			return Nan::ThrowError("ca_cert PEM not load");

		args.GetReturnValue().Set(Nan::True());
	}

	static void createCertificate(const Nan::FunctionCallbackInfo<v8::Value>& args) {
		Nan::HandleScope scope;
		CA* obj = ObjectWrap::Unwrap<CA> (args.This());

		if (args.Length() < 2) {
			return Nan::ThrowError("Expecting 2 arguments");
		}

		if (!args[1]->IsFunction()) {
			return Nan::ThrowError("Second argument must be a callback function");
		}

		Local<Object> arg_obj = args[0]->ToObject();


		Baton* baton = new Baton();
		baton->error = false;
		baton->request.data = baton;
		baton->callback = new Nan::Callback( args[1].As<v8::Function>() );
		baton->obj = obj;
		baton->x509_buf = NULL ;
		X509 *xcert = baton->xcert = X509_new();
		baton->bp = NULL;

/*
		baton->ca_pkey = EVP_PKEY_new();
		baton->pkey = EVP_PKEY_new();
		CRYPTO_add(&obj->pkey->references, 1, CRYPTO_LOCK_EVP_PKEY);
		EVP_PKEY_copy_parameters(baton->ca_pkey,obj->ca_pkey);
		EVP_PKEY_copy_parameters(baton->pkey,obj->pkey);
*/

		baton->ca_pkey = obj->ca_pkey;
		baton->pkey = obj->pkey;

		CRYPTO_add(&obj->ca_pkey->references, 2, CRYPTO_LOCK_EVP_PKEY);
		CRYPTO_add(&obj->pkey->references, 2, CRYPTO_LOCK_EVP_PKEY);

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
			baton->self_signed = true;
		}else{
			baton->self_signed = false;
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
		
		X509_set_issuer_name(xcert, baton->self_signed  ? subj : X509_get_subject_name(obj->ca_cert));
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
		
		int status = uv_queue_work(uv_default_loop(),
		&baton->request,
		CA::DetectWork,
		(uv_after_work_cb)CA::DetectAfter);


		assert(status == 0);
		args.GetReturnValue().SetUndefined();
	}

	static void DetectWork(uv_work_t* req) {

		Baton* baton = static_cast<Baton*>(req->data);


		//CA* obj = baton->obj;
		X509 *xcert = baton->xcert;

		//X509_set_subject_name(xcert,subj);

		//X509_set_pubkey(xcert,X509_REQ_get_pubkey(req));
		X509_set_pubkey(xcert, baton->pkey);

		//int OBJ_sn2nid(const char *sn); #include <openssl/objects.h>
		/* Add various extensions: standard extensions */
		//add_ext(xcert, NID_basic_constraints, "critical,CA:TRUE");
		//add_ext(xcert, NID_key_usage, "critical,keyCertSign,cRLSign");
		//add_ext(xcert, NID_subject_key_identifier, "hash");
		/* Some Netscape specific extensions */
		//add_ext(xcert, NID_netscape_cert_type, "sslCA");
		//add_ext(xcert, NID_netscape_comment, "example comment extension");

		X509_sign(xcert, baton->self_signed ? baton->pkey : baton->ca_pkey, EVP_sha256());

		BIO *bp = BIO_new(BIO_s_mem());

		PEM_write_bio_X509(bp, xcert);
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
		baton->bp = bp;
		//BIO_free(bp);

	}

	static void DetectAfter(uv_work_t* req) {
		Nan::HandleScope scope;
		Baton* baton = static_cast<Baton*>(req->data);

		if (baton->error || !baton->bp) {

			const unsigned argc = 1;
			Local<Value> argv[argc] = { baton->errorValue };

			Nan::TryCatch try_catch;
			baton->callback->Call(Nan::GetCurrentContext()->Global(), argc, argv);
			if (try_catch.HasCaught())
				Nan::FatalException(try_catch);
		} else {
			
			BUF_MEM *bptr;
			BIO_get_mem_ptr(baton->bp, &bptr);
			
			const unsigned argc = 2;
			Local<Value> argv[argc] = {
				Nan::Null(),
				( bptr->data ? Nan::New<v8::String>( bptr->data , bptr->length ).ToLocalChecked() : Nan::EmptyString() )
			};

			Nan::TryCatch try_catch;
			baton->callback->Call(Nan::GetCurrentContext()->Global(), argc, argv);
			if (try_catch.HasCaught())
				Nan::FatalException(try_catch);
		}

		if(baton->bp)
			BIO_free(baton->bp);

		if(baton->ca_pkey)
			EVP_PKEY_free(baton->ca_pkey);

		if(baton->pkey)
			EVP_PKEY_free(baton->pkey);
			
		delete baton->callback;
		delete baton;
	}

	static NAN_MODULE_INIT(Initialize) {
		Nan::HandleScope scope;
		
		v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
		
		tpl->SetClassName(Nan::New("CA").ToLocalChecked());
		tpl->InstanceTemplate()->SetInternalFieldCount(1);
		
		Nan::SetPrototypeMethod(tpl, "createCertificate", createCertificate);
		Nan::SetPrototypeMethod(tpl, "loadPrivateKey", loadPrivateKey);
		Nan::SetPrototypeMethod(tpl, "loadCA", loadCA);
		Nan::SetPrototypeMethod(tpl, "generatePrivateKey", generatePrivateKey);
		
		constructor.Reset(Nan::GetFunction(tpl).ToLocalChecked());
		
		Nan::Set(target, Nan::New("CA").ToLocalChecked(), Nan::GetFunction(tpl).ToLocalChecked());
	}
};

NAN_MODULE_INIT(init) {
	CA::Initialize(target);
}

NODE_MODULE(ca, init);

