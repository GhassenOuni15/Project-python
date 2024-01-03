import re
import hashlib

def enregistrer(email, pwd):
    with open("Enregistrement.txt", "a") as fichier:
        fichier.write(f"{email},{pwd}\n")

def verifier_credentials(email, pwd):
    with open("Enregistrement.txt", "r") as fichier:
        for ligne in fichier:
            enregistrement = ligne.strip().split(',')
            if enregistrement[0] == email and enregistrement[1] == pwd:
                return True
    return False

def hacher_mot(mot):
    hashed_mot = hashlib.sha256(mot.encode()).hexdigest()
    return hashed_mot

def attaquer_dictionnaire(mot_hache):
    dictionnaire = [] 
    if mot_hache in dictionnaire:
        return f"Mot trouvé dans le dictionnaire : {mot_hache}"
    else:
        return "Mot non trouvé dans le dictionnaire"

def decale_cesar(mot, decalage, alphabet):
    result = ""
    for char in mot:
        if char in alphabet:
            index = (alphabet.index(char) + decalage) % len(alphabet)
            result += alphabet[index]
        else:
            result += char
    return result


def menu_cesar():
    print("Options de décalage par CESAR:")
    mot_a_chiffrer = input("Entrez le mot à chiffrer : ")

    print("Choisissez le type de décalage:")
    print("1. Cesar avec code ASCII")
    print("2. Cesar dans les 26 lettres")
    choix_cesar = input("Choisissez l'option (1 ou 2) : ")

    if choix_cesar == "1":
        decalage = int(input("Entrez le décalage (entier) : "))
        alphabet = [chr(i) for i in range(32, 127)]  
        mot_chiffre = decale_cesar(mot_a_chiffrer, decalage, alphabet)
        print(f"Mot chiffré : {mot_chiffre}")

    elif choix_cesar == "2":
        decalage = int(input("Entrez le décalage (entier) : "))
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        mot_chiffre = decale_cesar(mot_a_chiffrer.upper(), decalage, alphabet)
        print(f"Mot chiffré : {mot_chiffre}")

    else:
        print("Option invalide.")

elif choix_menu == "B":
    menu_cesar()


def menu():
    while True:
        print("\nMenu Principal:")
        print("1. Enregistrement")
        print("2. Authentification")
        choix = input("Choisissez l'option (1 ou 2): ")

        if choix == "1":
            email = input("Entrez votre adresse e-mail : ")
            while not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                print("Adresse e-mail invalide. Veuillez réessayer.")
                email = input("Entrez votre adresse e-mail : ")

            pwd = input("Entrez votre mot de passe : ")
            while not re.match(r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()_+])[A-Za-z\d!@#$%^&*()_+]{8}$", pwd):
                print("Mot de passe invalide. Veuillez réessayer.")
                pwd = input("Entrez votre mot de passe : ")

            enregistrer(email, pwd)
            print("Enregistrement réussi.")

        elif choix == "2":
            email_auth = input("Entrez votre adresse e-mail : ")
            pwd_auth = input("Entrez votre mot de passe : ")

            if verifier_credentials(email_auth, pwd_auth):
                print("Authentification réussie. Bienvenue!")

                while True:
                    print("\nMenu après Authentification:")
                    print("A. Hacher un mot")
                    print("B. Décalage par CESAR")
                    print("C. Collecter une Dataset")
                    print("Q. Quitter")

                    choix_menu = input("Choisissez l'option (A, B, C ou Q) : ")

                    if choix_menu == "A":
                        mot_a_hacher = input("Entrez le mot à hacher : ")
                        mot_hache = hacher_mot(mot_a_hacher)
                        print(f"Mot haché : {mot_hache}")

                        print("\nOptions après le hachage:")
                        print("a. Attaquer par dictionnaire")
                        print("b. Revenir au menu principal")

                        choix_hachage = input("Choisissez l'option (a ou b) : ")

                        if choix_hachage == "a":
                            resultat_attaque = attaquer_dictionnaire(mot_hache)
                            print(resultat_attaque)

                    elif choix_menu == "B":
                        print("Options de décalage par CESAR:")
                        menu_cesar()

                    elif choix_menu == "C":
                        print("Options de collecte de Dataset:")

                    elif choix_menu == "Q":
                        print("Déconnexion.")
                        break

                    else:
                        print("Option invalide. Veuillez réessayer.")

            else:
                print("Authentification échouée. Veuillez vous enregistrer.")

        else:
            print("Option invalide. Veuillez réessayer.")

if __name__ == "__main__":
    menu()
