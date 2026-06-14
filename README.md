# Key-gen
An x509 key generator in Nim using libcrypto. The standard library's openssl doesn't have evp and x509 so i decided to make calls direcrly to the crypro library.
The library comes mostly by default on linux and maybe on wibdows after installing GCC

# Usage

Compile using:
	```nim c -d:ssl main.nim```

Run using:
	```./main```

> Happy Hacking
