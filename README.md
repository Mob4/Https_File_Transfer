# Https_File_Transfer
Mise en oeuvre d'un serveur et d'un client HTTPS.


Serveur (élémentaire) de fichiers sécurisé par le protocôle HTTPS.

Client (élémentaire) pour ce serveur de fichiers.

Le serveur est développé par composition avec la classe com.sun.net.httpserver.HttpsServer. Il est capable de reconnaître les paramètres de requètes suivants :

upload dont la valeur sera le nom d'un fichier présent sur la machine du client. Cette requète permet au client d'expédier, vers le serveur, le contenu du fichier dont le nom sera la valeur du paramètre upload.

Exemple : https://localhost:8888/fileserver?upload=rapport.pdf

download dont la valeur sera le nom d'un fichier et qui renvoie au client émetteur de la requète le contenu du fichier dont le nom sera la valeur du paramètre download.

Exemple : https://localhost:8888/fileserver?download=tiger.jpeg

Contraintes

Le client et le serveur procédent à une authentification mutuelle, i.e. le serveur s'identifie auprès du client et le client s'identifie auprès du serveur. Pour cette identification, les certificats du serveur et des clients peuvent être générés par l'application. En effet, si l'URL du serveur change, l'application peut générer un nouveau certificat serveur suite à cette modification.

Client:

Le client est essentiellement développé à l'aide de l'API javax.net.HttpsURLConnection qui appartient à 'API javax.net.ssl. Ce client enverra au serveur des requètes HTTP GET avec l'un des deux paramètres upload ou download définis ci-dessus et exploite la réponse renvoyée par le serveur.

Dans le cas d'une demande d'envoi de fichier au serveur (via la paramètre upload), si le fichier existe déjà sur le serveur, alors son contenu sera mis à jour. S'il n'existe pas encore sur le serveur, alors il sera ajouté dans la base de documents du serveur.

Dans le cas d'une demande de récupération de fichier depuis le serveur (via la paramètre download), si le fichier réclamé est effectivement disponible auprès du serveur alors le client devra être capable de le récupérer et le stocker.
