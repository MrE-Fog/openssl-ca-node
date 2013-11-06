

#include <node.h>
#include <v8.h>

#include "ca.h"

using namespace v8;

void init(Handle<Object> target) {
    HandleScope scope;
    CA::Init(target);
};

NODE_MODULE(ca, init);