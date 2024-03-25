import requests
import json
import config

class requetes_keycloak:

    def requete_jeton_user(utilisateur,mdp):
        url = 'http://'+config.ip_kc+':'+config.port_kc+'/realms/'+config.realm_name+'/protocol/openid-connect/token'
        charge_utile = {
            'client_id':config.client_id,
            'client_secret': config.client_secret,
            'username':utilisateur,
            'password':mdp, 
            'grant_type':'password',
            'scope': 'openid'
        }
        reponse = requests.post(url, data = charge_utile)
        r_json = reponse.json()
        return reponse.status_code, r_json

    def requete_deconnecter(access_token,refresh_token):
        url = 'http://'+config.ip_kc+':'+config.port_kc+'/realms/'+config.realm_name+'/protocol/openid-connect/logout'
        charge_utile = {
            'client_id':config.client_id,
            'client_secret': config.client_secret,
            'Authorization': 'Bearer '+access_token, 
            'refresh_token':refresh_token, 
            }
        reponse = requests.post(url, data = charge_utile)
        return reponse.status_code

    def requete_jeton_client(client_secret): 
        url = 'http://'+config.ip_kc+':'+config.port_kc+'/realms/'+config.realm_name+'/protocol/openid-connect/token'
        charge_utile = {
            'client_id': config.client_id,
            'client_secret': config.client_secret,
            'grant_type': 'client_credentials',
            'scope': 'openid',
        }
        #only testing here 
        url = 'http://'+config.ip_kc+':'+config.port_kc+'/realms/master/protocol/openid-connect/token'
        charge_utile = {
            "client_id": "admin-cli",
            "username": "admin",
            "password": "admin",
            "grant_type": "password",
            
        }
        reponse = requests.post(url, data = charge_utile)
        r_json = reponse.json()
        return reponse.status_code, r_json

    def requete_infos(bearer):
        url = 'http://'+config.ip_kc+':'+config.port_kc+'/realms/'+config.realm_name+'/protocol/openid-connect/userinfo'
        headers = {
            'client_id': config.client_id,
            'client_secret': config.client_secret,
            'Authorization': 'Bearer ' + bearer,
            'grant_type': 'client_credentials',
            }
        reponse = requests.get(url, headers=headers)
        r_json = reponse.json()
        return reponse.status_code, r_json

    def requete_s_enregister(utilisateur,mdp,prenom,nom,email,access_token):
        #201 good
        url = 'http://'+config.ip_kc+':'+config.port_kc+'/admin/realms/'+config.realm_name+'/users'
        headers = {
            # 'Accept-Encoding': 'gzip, deflate',
            'authorization': 'Bearer '+ access_token,
            'content-type': 'application/json',
        }

        charge_utile = {
            "username": utilisateur,
            "email": email,
            "firstName": prenom,
            "lastName": nom,
            "requiredActions": [],
            "emailVerified": False,
            "groups": [],
            "enabled": True,
            "credentials": [{
                "type": "password",
                "value": mdp,
            }]
        }

        reponse = requests.post(url, headers=headers, json=charge_utile)
        r_json = reponse#.json()
        return reponse.status_code, r_json
    
    
    def requete_get_pubkey():
        url = 'http://'+config.ip_kc+':'+config.port_kc+'/realms/'+config.realm_name
        reponse = requests.get(url)
        r_json = reponse.json()
        public_key = "-----BEGIN PUBLIC KEY-----\n"+r_json['public_key']+"\n-----END PUBLIC KEY-----"
        return public_key
    


#ONLY FOR TESTING
#r,r_json = requetes_keycloak.requete_jeton_user("firstuser","test")
#r,r_json = requetes_keycloak.requete_jeton_client(config.client_secret)
#print(r_json)
#print(r_json['access_token'])

#r,r_json = requetes_keycloak.requete_s_enregister("testuserert7415m","psw","prenom","nom","b32222at2edz85@gmail.com",r_json['access_token'])
#print(r)
#print(str(r_json))