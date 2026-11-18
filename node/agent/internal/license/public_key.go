package license

const publicKeyPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAg2RJCQObk6HJsoEC5fdvxFWWtOlNNv23gmi42WZS5tM=
-----END PUBLIC KEY-----
`

// Keep the original release signer trusted so existing customer licenses remain valid.
// The second key belongs to HM-Keygen and signs the current license format.
const keygenPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAuHkja1vrS7YZbxaaClM5sVO4xnrNlv9A4r3KrwJkT38=
-----END PUBLIC KEY-----
`

var trustedPublicKeyPEMs = []string{publicKeyPEM, keygenPublicKeyPEM}
