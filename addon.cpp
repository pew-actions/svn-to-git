#include <napi.h>
#include <string>
#include <vector>
#include <windows.h>

#pragma comment(lib, "Crypt32.lib")

Napi::String encrypt(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1) {
    Napi::TypeError::New(env, "Expected 1 argument").ThrowAsJavaScriptException();
    return Napi::String::New(env, "");
  }

  if (!info[0].IsString()) {
    Napi::TypeError::New(env, "Both arguments must be strings").ThrowAsJavaScriptException();
    return Napi::String::New(env, "");
  }

  Napi::String dataRaw = info[0].As<Napi::String>();
  std::string data = dataRaw.Utf8Value();

  const WCHAR description[] = L"auth_svn.simple.wincrypt";

  DATA_BLOB blobin, blobout;
  blobin.pbData = reinterpret_cast<BYTE*>(data.data());
  blobin.cbData = static_cast<DWORD>(data.size());

  BOOL result = CryptProtectData(&blobin, const_cast<WCHAR*>(description), nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &blobout);
  if (!result) {
    Napi::Error::New(env, "Failed to protect data").ThrowAsJavaScriptException();
    return Napi::String::New(env, "");
  }

  std::vector<char> buffer;
  buffer.resize(blobout.cbData * 4);
  DWORD bufferSize = static_cast<DWORD>(buffer.size());

  result = CryptBinaryToStringA(blobout.pbData, blobout.cbData, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, buffer.data(), &bufferSize);
  LocalFree(blobout.pbData);
  if (!result) {
    Napi::Error::New(env, "Failed to encode data").ThrowAsJavaScriptException();
    return Napi::String::New(env, "");
  }

  return Napi::String::New(env, std::string(buffer.data(), buffer.data() + bufferSize));
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set("encrypt", Napi::Function::New(env, encrypt));
  return exports;
}

NODE_API_MODULE(addon, Init)
