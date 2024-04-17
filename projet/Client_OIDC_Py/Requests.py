import requests
import json
import config
import curlify

class requetes_keycloak:
    """ Classe contenant les requêtes préparées pour Keycloak
    """
    
    def requete_jeton_user(utilisateur,mdp):
        """ Effectue une requête à un client KC pour obtenir un jeton d'accès pour un utilisateur 
        Parameters
        ----------
            utilisateur (str): Nom d utilisateur
            mdp (str): Mot de passe
        Returns
        -------
            int: Code de statut de la requête. 200 si OK
            dict: Réponse de la requête
        """
        
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
        # print("curlify en dessous : ")
        # print(curlify.to_curl(reponse.request))
        r_json = reponse.json()
        return reponse.status_code, r_json

    def requete_deconnecter(access_token,refresh_token):
        """ Effectue une requête à un client KC pour déconnecter un utilisateur
        Parameters
        ----------
            access_token (str): Jeton d accès
            refresh_token (str): Jeton de rafraîchissement
        Returns
        -------
            int: Code de statut de la requête, 204 si OK
        """

        url = 'http://'+config.ip_kc+':'+config.port_kc+'/realms/'+config.realm_name+'/protocol/openid-connect/logout'
        charge_utile = {
            'client_id':config.client_id,
            'client_secret': config.client_secret,
            'Authorization': 'Bearer '+access_token, 
            'refresh_token':refresh_token, 
            }
        reponse = requests.post(url, data = charge_utile)
        # print(curlify.to_curl(reponse.request))
        return reponse.status_code

    def requete_jeton_client(): 
        """ Effectue une requête à un client KC pour obtenir un jeton d'accès pour le client
        Returns
        -------
            int: Code de statut de la requête, 201 si OK
            dict: Réponse de la requête
        """
        
        url = 'http://'+config.ip_kc+':'+config.port_kc+'/realms/'+config.realm_name+'/protocol/openid-connect/token'
        charge_utile = {
            'client_id': config.client_id,
            'client_secret': config.client_secret,
            'grant_type': 'client_credentials',
            'scope': 'openid',
        }
        reponse = requests.post(url, data = charge_utile)
        print(reponse.request.url)
        r_json = reponse.json()
        return reponse.status_code, r_json

    def requete_infos(bearer):
        """ Effectue une requête à un client KC pour obtenir des informations sur un utilisateur
        Parameters
        ----------
            bearer (str): Jeton d accès du client administrateur
        Returns
        -------
            int: Code de statut de la requête, 204 si OK
            dict: Réponse de la requête
        """
        
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

    def requete_s_enregister(access_token,utilisateur,mdp,prenom,nom,email):
        """ Effectue une requête à un client KC pour enregistrer un utilisateur
        Parameters
        ----------
            access_token (str): Jeton d accès du client administrateur
            utilisateur (str): Nom d utilisateur
            mdp (str): Mot de passe
            prenom (str): Prénom
            nom (str): Nom
            email (str): Adresse email
        Returns
        -------
            int: Code de statut de la requête, 201 si OK
            dict: Réponse de la requête
        """
        
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
        """ Effectue une requête à un client KC pour obtenir sa clé publique
        Returns
        -------
            str: Clé publique format PEM
        """
        
        url = 'http://'+config.ip_kc+':'+config.port_kc+'/realms/'+config.realm_name
        reponse = requests.get(url)
        r_json = reponse.json()
        public_key = "-----BEGIN PUBLIC KEY-----\n"+r_json['public_key']+"\n-----END PUBLIC KEY-----"
        print(curlify.to_curl(reponse.request))
        return public_key
    

#ONLY FOR TESTING
#r,r_json = requetes_keycloak.requete_jeton_user("firstuser","test")

# r,r_json = requetes_keycloak.requete_jeton_user("firstuser","test")
# print(r_json)
# print(r_json['access_token'])
# input()
#r,r_json = requetes_keycloak.requete_s_enregister(r_json['access_token'],"testuserert7415m","psw","prenom","nom","b32222at2edz85@gmail.com")
# r = requetes_keycloak.requete_deconnecter(r_json['access_token'],r_json['refresh_token'])
# print(r)
# print(str(r_json))
# requetes_keycloak.requete_get_pubkey()


