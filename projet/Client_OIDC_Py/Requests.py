import requests
import json
import config

class requetes_keycloak:

    def requete_jeton_user(utilisateur,mdp):
        url = 'http://'+config.ip_kc+':'+config.port_kc+'/realms/DevRealm/protocol/openid-connect/token'
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
        url = 'http://'+config.ip_kc+':'+config.port_kc+'/realms/DevRealm/protocol/openid-connect/logout'
        charge_utile = {
            'client_id':config.client_id,
            'client_secret': config.client_secret,
            'Authorization': 'Bearer '+access_token, 
            'refresh_token':refresh_token, 
            }
        reponse = requests.post(url, data = charge_utile)
        return reponse.status_code

    def requete_jeton_client(client_secret): 
        url = 'http://'+config.ip_kc+':'+config.port_kc+'/realms/DevRealm/protocol/openid-connect/token'
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
        url = 'http://'+config.ip_kc+':'+config.port_kc+'/realms/DevRealm/protocol/openid-connect/userinfo'
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
        #
        url = 'http://'+config.ip_kc+':'+config.port_kc+'/admin/realms/DevRealm/users'
        en_tete = { #unothorized
            'content-type': 'application/json',
            'authorization': "Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJUZlJuODROU2RQak9zTkVDNzM2UjBWS3l1aURGQ2lYcTlXR3p0c2RkYWxzIn0.eyJleHAiOjE3MTEwMzY4ODIsImlhdCI6MTcxMTAzNjgyMiwianRpIjoiZmZmMGU0ZWItNTRmMi00MTdkLThkMWQtNTNjNjVmZTQ5ZTI2IiwiaXNzIjoiaHR0cDovLzE3Mi4yNi4xNDIuMjo4MDgwL3JlYWxtcy9tYXN0ZXIiLCJzdWIiOiIyOWEzMTRlNy0zZGQxLTQyNjQtOGQ3Yi00ZGY2MmUxYWU2YjciLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhZG1pbi1jbGkiLCJzZXNzaW9uX3N0YXRlIjoiZTc1NzlmYTItOGQ2OC00M2I0LTk1ZWMtOWEzNzJjMjA5ZjhjIiwiYWNyIjoiMSIsInNjb3BlIjoiZW1haWwgcHJvZmlsZSIsInNpZCI6ImU3NTc5ZmEyLThkNjgtNDNiNC05NWVjLTlhMzcyYzIwOWY4YyIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWRtaW4ifQ.vHXIzkqPAOsdFT___Nb8mKBhbwRz6kncN-en9mDvFulPHk2eHuWOLgVjRBb_wyo4phqCID8rzvIRzEawMPYIXrXUHCQhqb_uNZXH22_xArqPcUw9ICU_dh1k8-MbDzTxY37GHn0SphOGXHr33LIEnjoS8DntkHmPESFdU3aOuLMvrbBds19UUymHmOVbgQd4gbJ5YzE7qgtFgiZTp1KNBukuHrf9OKRZV-lk1mQL0QERQDOf3r_ldoJMHA_iCleXT4Kw5ymg6erv6yuLWICmc3vIGafQ_XTEp4BjVWw_1_J7KKsUquaBBaKa-cOpeAxdBXfqGXt7SBewWRDBeY7Tcg"
            }
        
        url = 'http://172.26.142.2:8080/admin/realms/DevRealm/users'

        charge_utile = {
            "username": "aaaa2222",
            "email": "azzz2222a@example.cf",
            "firstName": "a",
            "lastName": "a",
            "requiredActions": [],
            "emailVerified": False,
            "groups": [],
            "enabled": True
        }
        reponse = requests.post(url, headers=en_tete, data = charge_utile)
        r_json = reponse.json()
        return reponse.status_code, r_json
        
#ONLY FOR TESTING
#r,r_json = requetes_keycloak.requete_jeton_user("firstuser","test")
#print("1eme rep " + str(r_json))
#r,r_json = requetes_keycloak.requete_jeton_client(config.client_secret)
#print(r_json)
#print(r_json['access_token'])

#r,r_json = requetes_keycloak.requete_s_enregister("testuser","psw","prenom","nom","bat2edz@gmail.com",r_json['access_token'])
#print(r)
#print(r_json)
#r,r_json = requetes_keycloak.requete_infos(r_json['access_token'])
#print("la seconde réponse est " + str(r_json.reason))
#print("2eme rep " + str(r_json.text))
#
#print(r_json)
#print("réponse json" + str(r_json))
#print(r_json['access_token'])
#print(r_json['refresh_token'])
#r,r_json2 = requetes_keycloak.requete_deconnecter(r_json['access_token'],r_json['refresh_token'])
