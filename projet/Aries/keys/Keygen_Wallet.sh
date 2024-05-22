#Mémo
openssl genpkey -algorithm RSA -out wallet_key.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in wallet_key.pem -pubout -out wallet_key.pub

