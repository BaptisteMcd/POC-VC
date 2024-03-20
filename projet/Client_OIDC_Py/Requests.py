import requests
import json
import config

class requetes_keycloak:

    def requete_jeton_user(utilisateur,mdp):
        #WORKS
        url = 'http://'+config.ip_kc+':'+config.port_kc+'/realms/DevRealm/protocol/openid-connect/token'
        charge_utile = {
            'username':utilisateur,
            'password':mdp, 'grant_type':'password',
            'client_id':config.client_id,
            'client_secret': config.client_secret,
            'scope': 'openid'
        }
        reponse = requests.post(url, data = charge_utile)
        r_json = reponse.json()
        
        return reponse.status_code, r_json

    def requete_deconnecter(access_token,refresh_token):
        #204 = ça marche 
        url = 'http://'+config.ip_kc+':'+config.port_kc+'/realms/DevRealm/protocol/openid-connect/logout'
        charge_utile = {
            'Authorization': 'Bearer '+access_token, 
            'refresh_token':refresh_token, 
            'client_id':config.client_id,
            'client_secret': config.client_secret,
            
            }
        reponse = requests.post(url, data = charge_utile)
        #print(reponse.reason)
        return reponse.status_code

    def requete_jeton_client(client_secret): 
        url = 'http://'+config.ip_kc+':'+config.port_kc+'/realms/DevRealm/protocol/openid-connect/token'
        charge_utile = {
            'client_secret': config.client_secret,
            'grant_type': 'client_credentials',
            'client_id': config.client_id,
            'scope': 'openid'
        }
        reponse = requests.post(url, data = charge_utile)
        r_json = reponse.json()
        return reponse.status_code, r_json

    def requete_infos(bearer):
        url = 'http://'+config.ip_kc+':'+config.port_kc+'/realms/DevRealm/protocol/openid-connect/userinfo'
        headers = {
            'Authorization': 'Bearer ' + bearer,
            'client_secret': config.client_secret,
            'client_id': config.client_id,
            'grant_type': 'client_credentials',
            
            }
        reponse = requests.get(url, headers=headers)
        
        
        #r_json = reponse#.text()
        return reponse.status_code, reponse.json()
#r,r_json = requetes_keycloak.requete_jeton_user("firstuser","test")
#print("1eme rep " + str(r_json))
##r,r_json = requetes_keycloak.requete_jeton_client(config.client_secret)
#r,r_json = requetes_keycloak.requete_infos(r_json['access_token'])
#print("la seconde réponse est " + str(r_json.reason))
#print("2eme rep " + str(r_json.text))
#
#print(r_json)
#print("réponse json" + str(r_json))
#print(r_json['access_token'])
#print(r_json['refresh_token'])
#r,r_json2 = requetes_keycloak.requete_deconnecter(r_json['access_token'],r_json['refresh_token'])
