import std/[times, random]

{.passL: "-lssl -lcrypto".}
{.passC: "-Wno-deprecated-declarations -DOPENSSL_API_COMPAT=0x10100000L".}

type EVP_PKEY = pointer
type X509 = pointer
type X509_NAME = pointer  
type BIO = pointer
type RSA = pointer
type BIGNUM = pointer
type ASN1_INTEGER = pointer

const
  MBSTRING_ASC = 0x1000
  NID_basic_constraints = 87
  NID_key_usage = 83
  NID_ext_key_usage = 126
  NID_subject_alt_name = 85
  RSA_F4 = 0x10001

{.push importc, dynlib: "libcrypto.so", header: "openssl/evp.h".}
proc EVP_PKEY_new(): EVP_PKEY
proc EVP_PKEY_free(pkey: EVP_PKEY)
proc EVP_PKEY_assign_RSA(pkey: EVP_PKEY, key: RSA): cint
proc EVP_sha256(): pointer
proc OPENSSL_init_crypto(flags: culong, settings: pointer): cint
{.pop.}

{.push importc, dynlib: "libcrypto.so", header: "openssl/rsa.h".}
proc RSA_new(): RSA
proc RSA_generate_key_ex(rsa: RSA, bits: cint, e: BIGNUM, cb: pointer): cint
{.pop.}

{.push importc, dynlib: "libcrypto.so", header: "openssl/bn.h".}
proc BN_new(): BIGNUM
proc BN_free(bn: BIGNUM)
proc BN_set_word(a: BIGNUM, w: culong): cint
{.pop.}

{.push importc, dynlib: "libcrypto.so", header: "openssl/x509.h".}
proc X509_new(): X509
proc X509_free(x: X509)
proc X509_set_version(x: X509, version: clong): cint
proc X509_get_serialNumber(x: X509): ASN1_INTEGER
proc ASN1_INTEGER_set(a: ASN1_INTEGER, v: clong): cint
proc X509_gmtime_adj(s: pointer, adj: clong): pointer
proc X509_get_notBefore(x: X509): pointer
proc X509_get_notAfter(x: X509): pointer
proc X509_set_pubkey(x: X509, pkey: EVP_PKEY): cint
proc X509_get_subject_name(x: X509): X509_NAME
proc X509_set_issuer_name(x: X509, name: X509_NAME): cint
proc X509_NAME_add_entry_by_txt(name: X509_NAME, field: cstring, `type`: cint, 
                                bytes: cstring, len: cint, loc: cint, set: cint): cint
proc X509_sign(x: X509, pkey: EVP_PKEY, md: pointer): cint
proc X509_add1_ext_i2d(x: X509, nid: cint, value: pointer, crit: cint, flags: culong): cint
{.pop.}

{.push importc, dynlib: "libcrypto.so", header: "openssl/x509v3.h".}
proc X509V3_EXT_conf_nid(conf: pointer, ctx: pointer, ext_nid: cint, value: cstring): pointer
{.pop.}

{.push importc, dynlib: "libcrypto.so", header: "openssl/pem.h".}
proc BIO_new_file(filename: cstring, mode: cstring): BIO
proc BIO_free(a: BIO): cint
proc PEM_write_bio_PrivateKey(bp: BIO, x: EVP_PKEY, enc: pointer, kstr: cstring, 
                              klen: cint, cb: pointer, u: pointer): cint
proc PEM_write_bio_X509(bp: BIO, x: X509): cint
{.pop.}

proc genRsaKey(bits: int): EVP_PKEY =
  var pkey = EVP_PKEY_new()
  var rsa = RSA_new()
  var e = BN_new()
  discard BN_set_word(e, RSA_F4)
  discard RSA_generate_key_ex(rsa, bits.cint, e, nil)
  discard EVP_PKEY_assign_RSA(pkey, rsa)
  BN_free(e)
  return pkey

proc addExt(x: X509, nid: cint, value: cstring, crit: int) =
  # No X509V3_CTX needed = no segfault
  let ext = X509V3_EXT_conf_nid(nil, nil, nid, value)
  if ext != nil:
    discard X509_add1_ext_i2d(x, nid, ext, crit.cint, 0)

proc genCert(pkey: EVP_PKEY, issuerKey: EVP_PKEY, issuerCert: X509,
             cn: cstring, days: int, isCa: bool, eku: cstring): X509 =
  var x = X509_new()
  discard X509_set_version(x, 2)
  discard ASN1_INTEGER_set(X509_get_serialNumber(x), rand(1000000))
  
  discard X509_gmtime_adj(X509_get_notBefore(x), 0)
  discard X509_gmtime_adj(X509_get_notAfter(x), days * 24 * 60 * 60)
  
  discard X509_set_pubkey(x, pkey)
  
  var name = X509_get_subject_name(x)
  discard X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, cn, -1, -1, 0)
  
  if issuerCert != nil:
    discard X509_set_issuer_name(x, X509_get_subject_name(issuerCert))
  else:
    discard X509_set_issuer_name(x, name)
  
  # Add extensions without X509V3_CTX
  let bc = if isCa: "CA:true" else: "CA:false"
  addExt(x, NID_basic_constraints, bc, if isCa: 1 else: 0)
  addExt(x, NID_key_usage, "digitalSignature,keyEncipherment", 1)
  
  if eku != nil:
    addExt(x, NID_ext_key_usage, eku, 0)
  
  if not isCa and eku == "serverAuth":
    addExt(x, NID_subject_alt_name, "DNS:localhost,IP:127.0.0.1", 0)
  
  let signKey = if issuerKey != nil: issuerKey else: pkey
  discard X509_sign(x, signKey, EVP_sha256())
  return x

proc saveKey(file: string, pkey: EVP_PKEY) =
  var bio = BIO_new_file(file, "wb")
  discard PEM_write_bio_PrivateKey(bio, pkey, nil, nil, 0, nil, nil)
  discard BIO_free(bio)

proc saveCert(file: string, cert: X509) =
  var bio = BIO_new_file(file, "wb")
  discard PEM_write_bio_X509(bio, cert)
  discard BIO_free(bio)

when isMainModule:
  randomize()
  discard OPENSSL_init_crypto(0, nil)
  
  let caKey = genRsaKey(4096)
  let caCert = genCert(caKey, nil, nil, "MyTest CA", 3650, true, nil)
  saveKey("ca.key", caKey)
  saveCert("ca.crt", caCert)
  
  let srvKey = genRsaKey(2048)
  let srvCert = genCert(srvKey, caKey, caCert, "localhost", 365, false, "serverAuth")
  saveKey("server.key", srvKey)
  saveCert("server.crt", srvCert)
  
  let cliKey = genRsaKey(2048)
  let cliCert = genCert(cliKey, caKey, caCert, "client1", 90, false, "clientAuth")
  saveKey("client1.key", cliKey)
  saveCert("client1.crt", cliCert)
  
  X509_free(caCert); X509_free(srvCert); X509_free(cliCert)
  EVP_PKEY_free(caKey); EVP_PKEY_free(srvKey); EVP_PKEY_free(cliKey)
  
  echo "[+] Generated ca.key ca.crt server.key server.crt client1.key client1.crt"