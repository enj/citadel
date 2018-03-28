# Welcome to Citadel!

Citadel (c5l) is a simple daemon that implements the Kubernetes Key Management Service (KMS)
interface by acquiring a key encryption key (KEK) from an arbitrary command.
This makes it easy to plug in your own key management solution as a simple unix
command that returns the KEK.

## How does it work?

When c5l starts, it runs the command you provide it. This command returns the
KEK on standard output. If this command fails during startup, c5l will exit.
Otherwise, it will use the KEK from the command to encrypt and decrypt input
from Kubernetes.

c5l caches the KEK, and thus does not call the command on every incoming
request. The time limit of this cache is specified by the `timeout` argument.
If c5l is not able to refresh the cache after trying several times, it will
purge the KEK and report errors to Kubernetes. If c5l eventually succeeds
in acquiring the KEK, normal operation will resume.

To specify the socket to create, use the `endpoint` argument. Otherwise,
socket activation is assumed.

## Arguments

### Required

 * `--command string`: the command to retrieve the key encryption key

### Optional

 * `--endpoint string`: the listen address (ex. `unix:///tmp/socket`)

 * `--timeout duration`: maximum time to cache KEK locally (default 1h)

 * `--mode string`: encryption mode to use, the options are \[aescbc\] (default "aescbc")

## Crypto Details

The KEK is currently used to do AES-CBC encryption. This does not provide
ciphertext authentication. Other methods are being considered with the intent
of providing cryptographic agility and features such as authentication.
