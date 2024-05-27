#Mémo
openssl genpkey -algorithm RSA -out wallet_key.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in wallet_key.pem -pubout -out wallet_key.pub

#Mémo
openssl genpkey -algorithm Ed25519 -out ed25529_priv.pem
openssl pkey -in ed25529_priv.pem -pubout -out ed25529_pub.pem
