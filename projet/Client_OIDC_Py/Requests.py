import requests
import json



def requete_jeton(utilisateur,mdp): 

    url = 'http://172.26.142.2:8080/realms/DevRealm/protocol/openid-connect/token'
    client_id = 'Client-test'
    charge_utile = {'username':utilisateur, 'password':mdp, 'grant_type':'password','client_id':'Client-test'}
    reponse = requests.post(url, data = charge_utile)
    r_json = reponse.json()
    print(reponse)
    print(r_json)
    try :
        jeton = r_json['access_token']
        jeton_rafraichissement  = r_json['refresh_token']
    except: 
        print("error")


requete_jeton('firstuser','test')