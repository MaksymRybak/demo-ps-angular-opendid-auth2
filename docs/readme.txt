Link al corso https://app.pluralsight.com/library/courses/openid-and-oauth2-securing-angular-apps/table-of-contents

Security big picture
	considerazioni di sicurezza (nel momento di design dell'app)
		autenticazione
		autorizzazione
		transport protection 
			da usare HTTPS in tutte le chiamate (si appoggia' su TLS)
			da usare HTTPS in tutte le chiamate che contengono i dati sensibili
		CORS (Cross Origin Resourse Sharing)
			e' il protocollo di sicurezza che usa il browser per limitare le richiesta che puo' fare il client (es. client JS)
			cmq HttpClient di Angular gestisce tutti headers del protocollo CORS
		CSRF (Crisso Site Request Forgery)
			usato nel momento di utilizzo di cookie x mantenere in sync la sessione con il relativo Back End
			forms auth - utilizzo di cookie nel momento di login per es.
			il browser invia cookie in ogni richiesta fatta al corrispondente server
			quindi, se un utente fa la login in un tab del browser, dopo apre un'altro tab, e fa la richiesta allo stesso server, browser inviera' il cookie ricevuto durante la login nel primo tab,
				al server richiesta dal secondo tab
			CSRF si evita usando OAuth e OpenID, che non prevedono nessun automatismo da parte del browser e il token deve esserci inserito nell'header di autorizzazione in modo esplicito dall'app
		XSS (Cross Site scripting)
			utente non deve avere la possibilita' ad inserire il codice eseguibile (es. JS) nelle pagine di una web app
	client vs server security
		a livello di una web app, client side non riusciamo a garantire una sicurezza 100%
			qualsiasi utente puo' aprire il tool x gli sviluppatori nel browser e eseguire qualsiasi modifica
		possiamo rendere questa operazione piu' dissificile minimizzando e minificando il codice della nostra web app
		la protezzione principale avviene server side
			possiamo filtrare i dati
			controllare gli accessi alle nostre API
	architettura di sicurezza in una app angular
		site separati per il hosting (web app) e api (web api REST)
		quando usiamo OpenID abbiamo un site dedicato al nostro Identity provider
			la richiesta di login verra' indirizzata a questo site
			avendo il site dedicato ad Identity provider abbiamo un punto centralizzato dove gestiremo le autorizzazioni di nostri utenti
			le API di BE riceveranno solo il token che identifica univocamente l'utente
			Identity provider ci permette anche di fare SSO tra diversi app
	autenticazione e autorizzazione
		autenticazione 
			server x determinare chi e' l'utente/cliente/caller e fornisce un ID temporaneo
			utente fornisce login e pwd, riconoscimento biometrico, smart card
			la richiesta viene reindirizzata alla pagina di login se utente risulta non autenticato
			il risultato di autenticazione e' una stringa chiamata Shared Secret (risultato di un algoritmo hash, permette univocita e difficolta ad indovinarla partendo dall'input che la prodotta)
				e' un token x una app/api specifica (scope)
			es. in mondo reale la stessa procedura vediamo durante la registrazione in una azienda dove forniamo il nostro ID (es. carta d'identita') e riceviamo il badge che ci permette ad accedere 
				alle aree interne in cui abbiamo permesso di entrare -> equivale alla procedura di OpenID authentication, dove Identity provider e' l'ufficio di sicurezza aziendale, ID e' la login e pwd,
				token e' il badge
		autorizzazione
			segue autenticazione, conoscendo utente, viene configurato cosa puo' vedere/accedere
			puo' essere basato sul sistema di ruoli, conoscendo il ruolo dell'utente sappiamo a cosa puo' accedere
			NOTA: permessi di un utente sono specifici x l'app, quindi Identity provider non puo' contenere questi info (e' cross app!)
				verra' approfondito successivamente
	terminologia da conoscere
		Identity provider, altri sopranomi
			- authentication server
			- authorization server
			- SSO server
			- STS (Security Token Server)
			NOTA: il nome corretto e' cmq Identity provider o STS, altre tre opzioni rappresentano solo una parte di quello che fa un Identity provider
		User agent
			e' un pezzo di sw, non utente, puo' essere l'app o sistema operativo che usa l'utente
		Client
			e' un pezzo di sw, non utente, con quale interagisce un utente
		Risorsa
			e' qualcosa acceduto/richiesta dall'utente
			es. sono API in una app angular
			puo' essere cmq anche un web site, db, data storage
		Scope
			e' una parte di configurazione di un Identity provider
			rappresenta la risorsa protetta da Identity provider
			quando client accede all'Identity provider, specifica la risorsa richiesta -> identity provider verifica che il client e' stato configurato x poter accedere alla risorsa richiesta
			un utente, che usa un Identity provider esterno come Google o Facebook, vede gli scopes nella maschera di richiesta, dove sono elencati le risorse (es. email, nome, cognome, lista di amici)
				alle quali l'app potra' accedere
		JWT (JSON Web Token)
			e' un formato di codifica, usato x codificare le informazioni di un utente autenticato + identity token + claims (info a cosa puo' accedere fornito in forma di scopes)
			e' lo standard usato sia in OpenID che in OAuth2
	OpenID Connect e OAuth2
		nasce prima di OpenID con la prima versione nel 2006
			versione basate sulle API di twitter
			dal 2010 e' uno standard approvato
		OAuth2 segue, con focus sul web, mobile, desktop apps e APIs
			diventa uno stadard approvato nel 2012
		il problema base di OAuth e' stata la mancanza della parte che gestisca l'autenticazione
			e' un protocollo dedicata all'autorizzazione 
			questa mancanza fa nascere OpendID Connect
		OpenID Connect 
			deriva da OAuth2
			usa stesso formato di token - JWT
			da x scontato che viene usato OAuth2 per la parte di autorizzazione
			prevede la generazione di un Identity token e di un Access token
				access token determina i permessi dell'utente che e' stato autenticato x accedere ad una specifica risorsa (scope)
			divento lo standard nel 2014
			standardizza il processo di raccolta delle credenziali producendo in uscita un token
	Identity providers
		ci sono N scelte
		la scelta dipende dal target degli utenti della nostra app
		provider piu' noti sono Google, Facebook, Twitter
		la nostra app cmq e' meglio che abbiamo un provider proprio in modo da dare la possibilita' all'utente di registrarsi senza usare il proprio account di una rete social
		se vogliamo implementare un nostro Identity provider
			ci sono soluzioni sia cloud che on premise
			esempi
				Microsoft (MS)
					Azure Active Directory v1 (No OpenID Connect, MS accounts only)
					Azure Active Directory v2 (OpendID Connect support, MS org and personal accounts)
					AAD business to consumer (B2C), OpenID Connect + all MS accounts + custom accounts
				Identity as a service providers
					Auth0
					okta
					Ping identity
					IdentityServer4
						open source identity provider framework
						richiede di scrivere un po' di codice e configurazione
						e' on premise, dobbiamo installarlo in locale
						una soluzione flessibile per SSO federation scenarios 
						e' certificato da OpenID Foundation, vedi altri provider compliant qui https://openid.net/certification/
	Librerie client 
		angular-jwt
			permette di ottenere access token generato da identity provider
			i inviarlo in ogni richiesta http alle nostre APIs
		ADAL (MS Azure Acrive Directory Authentication Library)
			x usare con Active Directory, non e' compliantt con OpenID Connect
		MSAL (MS Auth. Lib.)
			usa sia OpenID che OAuth2 
			da usare se il nostro STS e' un Azure Active Directory
		oidc-client
			implementata dallo stesso team che ha implementato Identity Server 
			da preferire!
			certificata da OpenID foundation come 100% compliant con i protocolli 
	Demo app
		utenti da usare sono: alice@globomantics.com, admin@globomantics.com, bob@globomantics.com, mary@globomantics.com con pwd Test123!!!
		l'app e' un piccolo gestionale x progetti con possibilita' di editare i ruoli di utenti per singoli progetti
Autenticazione con OpenID Connect
	Perche' usare OpenID Connect x l'autenticazione nella nostra app
		recap: Identity provider rilascia al richiedente un ID e Access control token 
			   un disaccopiamento con il sw principale
			   permette di avere lo scenario SSO
			   abbiamo un gestore delle credenziali centralizzato
			   
	Dettagli di OpenID
		si basa su JWT contenente info come	
			- Utente
			- Client App (es. app angular)
			- Identity provider
			- Risorsa (es. le API che intendiamo chiamare)
			- Protocollo
		e' una firma digitale basate sulla crittografia
		e' il risultato della procedura di autenticazione eseguita da Identity provider
		sono rilasciati 2 token dopo una autenticazione OpenID
			1 - ID token (info riguardanti sessione autenticata sicura, posseduta da Utente o App Client)
			2 - Access token basato sul protocollo Auth2
		viene usata una chiave crittografica x firmare i token e verificare la firma
		il modo in cui configuriamo le chiavi di firma determinano 3 possibili modalita' di funzionamento Open ID
	OpenID Connect flows (flussi)
			1 - Authorization code flow
				Utente richiede la login accedendo ad una pagine dedicata dell'app -> l'app esegue il redirect verso Identity Provider (STS) -> STS fornisce 
					una sua pagina di login -> Utente inscerisce credenziali -> STS valida le credenziali -> e esegue redirect verso l'app dell'Utente -> 
					l'app invia la richiesta contenente il codice di autorizzazione a STS ad un endpoint che fornisce i token -> STS risponde con i tokens ->
					client continua ad usare l'app che in background usa i token x fare le chiamate alle API di BE 
			2 - Hybrid flow
					inizia nello stesso modo che Authorization code flow, aggiungendo una parte lato Back End (ottiene un delegated token da STS x eseguire le chiamate a BE
						agli endpoint terzi in modo come se fosse eseguite direttamente dall'Utente che sta usando l'app) 
			3 - Implicit flow
					prima di 2019 era' un flow consigliato per le app SPA, ma aveva delle vulnerabilita' e dal 2019 e' stato sconsigliato da IETF
					le best practice di riferimento proposte da IETF sono
						OAuth2 sec best current practive https://noyes.me/oauth2-sbcp
						OAuth2 for browser based apps https://noyes.me/obba
					tutto cio' e' stato guidato dal supporto da parte di browser di CORS e Same-site Cookies
			il passaggio da Implicit a Authorization code flow e' stato influenzato dallo standard PKCE (Proof Key for Code Exchange), pronunciato "Pixie"
				disegnato originariamente per le app native
				si sono accorti che si addatta bene anche per le app Javascript e quelle mobile
			Protocollo PKCE garantisce
				- flusso sicuro di Authorization code x i client pubblici (es. client JS, dove il codice puo' essere visualizzato e modificato a livello di browser)
				- genera e applicata una funzione HASH ad un codice/chiave ulteriore, dedicata al Client (es. browser, tab del browser) e STS - questo codice viene inviato insieme ai token in ogni
					chiamate alle API
			Passando ad Authorization code flow noi evitiamo la vulnerabilita' che implici flow ha - il modo in cui ID e Access token ritornati da STS venivano messi nell'Url di redirect come
				frammenti hash, questo permetteva a qualcuno con accesso al PC dell'Utente di ottenere Access token e usarlo con un Client diverso (altro browser, tab), aperto anche su un PC diverso,
				finche il token non era' scaduto (cmq una app ben sviluppata rendeva questa modalita' di furto molto difficile..)
			Quindi, all'inizio del 2019, Authorization Code + PKCE hanno deprecato Implicit flow
			se l'app usa una buona libreria client e un Identity provider recente, il passaggio da Implicit flow a Authorization code e' molto piu' facile 
		x una app viene scelto e usato un solo flusso specifico
	Utilizzo di Authorization code flow con PKCE 
		caso angular: le guardie sono usate per controllare che un utente accede alla view richiesta
		flusso di login: app client genere cosi detto "code verifier" -> usando algoritmo hash genera hash del codice generato prima, ottenendo cosi detto "code challenge" 
						 -> client esegue il redirect verso STS passando "code challenge" -> STS pensa a carica la pagina di login x autenticare il client 
						 -> utente inserisce le credenziali usando la pagina di login -> login form fa submit verso STS -> STS verifica le credenziali usando il proprio storage 
						 -> se tutto ok, STS esegue il redirect verso url passato dal client nel momento di invio "code challenge", aggiungendo "code challenge" nella richiesta di redirect
						 -> client esegue la chiamata al token endpoint di STS passando il codice di autorizzazione e "code verifier"
						 -> STS applica lo stesso algoritmo di hash al "code verifier" e confronta il risulatto con il "code challenge" inviato dal client all'inizio di processo (vedi prima)
						 -> in questo modo STS verifica che chi sta usando authorization code sia lo stesso client
						 -> nel body della risposta dal token endpoint viene inviato ID + Access Token, usati successivamente dal client x fare le chiamate alle API di BE
						 -> client in ogni chiamata REST invia Access Token 
					NOTA: il flusso descritto prima viene reso trasparente x noi se usiamo una libreria come oidc-client
	oidc-client library
		ogni tanto riceve critiche che sia una lib "heavy weight", la versione minificata non compressa pesa 370KB
			la maggior parte di questa dimensione e' relativa alle librerie di crittografia dalle quali dipende
			la dimensione e' il prezzo che noi paghiamo x avere un certo livello di sicurezza
			giusto come un confronto, una app angular8 "Hello World" senza dipensenza, pacchetto finale pronto x il deploy cuba circa 210KB
				e una app con dipendenze, librerie di componenti etc, puo' cubare anche 20MB
			che cmq il client attende solo la prima volta il download completo, dopo di che il browser carica i bundle dalla propria cache, finche il file rimane invariato lato server
		NOTA: cmq e' meglio non implementare il flusso descritto prima "in casa", e evitare i buchi di sicurezza vari
	App di esempio che useremo nel corso, elenco funzionalita'
		Home page con il menu
		View My Projects
		View Manage Projects
		View Project Details
		View New Project
		View Manage Permissions
	App di BE x l'app angular
		la soluzione e' composta da 2 progetti, progetto delle API e progetto di Identity Server, tecnologia .NET Core
		cmq il BE e' pubblicato anche in cloud, quindi volendo, in locale possiamo non impostare la parte delle API
		lato BE ci sono due DB, uno per le API e uno per Identity Server
			eseguire InitData.sql x crearli
		in VS si puo' configurare i due progetti per farli partire contemporaneamente
		lato app FE si configurano nuove stringhe di connessione per le API e STS 
	Aggiunta di oidc-client e Auth Service lato app angular
		installiamo la lib oidc-client nell'app angular (npm i oidc-client --save)
		creiamo auth-service.component.ts, il servizio responsabile della gestione di autenticazione usando OpenID Connect
	Configurazione oidc-client x una connessione al nostro STS
		i tipi principali della lib oidc-client sono UserManager e User
			UserManager completa il processo di login, gestisce tutta la logica del protocollo OpenID Connect, ci nascondo tutto la comunicazione tra la nostra app e identity provider
			User incapsula i dettagli dell'utento loggato lato client, contiene ID e Access tokens, ritornati da Identity Provider, e info che riguardano il profilo dell'utente
				nel formato di claims, e siamo in grado di capire quando il token dell'utente e' scaduto
		la creazione di UserManager richiedere un oggetto con le impostazioni che riguardano STS
			- authority, indirizzo a Identity Server
			- client_id
			- redirect_uri, indirizzo di ritorno che consente completare il processo di sign-in lato app angular
			- scope (per specificare le risorse, cioe' le API, che app intende consumare), specifichiamo 'openid (usiamo questo protocollo) profile (opzionale), projects_api (API di BE)'
				NOTA: se il client specifica gli scope che non sono state configurate per esso lato STS, ricevera' l'errore nella fase di login
			- response_type (x specificare il tipo di risposta che client vuole ricevere), usando Pixie, specifichiamo 'code' (in implicit flow per es. specifichiamo 'id_token token'
			- post_logout_redirect_uri (dove vogliamo che STS invia la riposta nel processo di logout)
			NOTA: sia il processo di login che logout, devono passare da STS, e propri li che viene salvata info relativa alla durata di token 
	Aggiunta di Login lato app
		creiamo il metodo di logic lato il nostro servizio angular
			il metodo di login ritorna la promise ritornata a sua volta dal metodo signinRedirect() di UserManager
		UserManager salva in Session Storage del browser l'oggetto User ottenuto dopo la fase di login
			questo oggetto usiamo x esempio per recuperare Access Token da inviare in ogni richiesta alle nostre API di BE
			User contiene anche il flag che indica se Access Token e' scaduto
		quando il processo di login termina e STS esegue la chiamata all'URI di callback (post login), noi dobbiamo aggiornare l'app mettendo i dati dell'utente loggato nell'area dedicata
			x aggiornare il FE usiamo RxJS e Observable (vedi esempio nella demo, oggetto Subject)
		NOTA: se utente nel browser (tab) dove e' stata caricata l'app naviga verso un sito nuovo e subito dopo torna indietro usando <- del browser, per l'app e' un nuovo caricamento (da zero), 
			stessa cosa succede quando STS esegue il redirect verso l'URI di callback dopo il processo di login.
			QUINDI, x gestire questa situazione, il nostro componente root puo' gestire la casistica usando UserManager di prima verificando se esiste gia' un User valido (autenticato)
				il componente root usa il nostro AuthService che incapsula l'utilizzo di UserManager di oidc-client
	Loggin in STS
		avviando l'app di FE, BE e STS, cliccando login, vediamo la pagina di STS con la richiesta di login e pwd
		usando Fiddler possiamo vedere cosa succede a livello di comunicazione tra l'app e STS (ci sono tre richieste)
			richiesta 1 - recupero metadati (JSON) di STS utili alle richieste successive, richiesta a .well-known/openid-configuration
			richiesta 2 - richiesta a connect/authorize, passando la configurazione impostata lato client (web app, tutto quello che abbiamo visto prima)
				questa richiesta comporta al redirect da parte di STS verso la sua pagina di login
				NOTA: se qualcosa passato dal client non matcha lato STS riceviamo un errore, x capire il motivo dobbiamo guardare i log di STS
				eseguiamo la login in STS, anche qui avvengono N richieste prima che app angular ci mostra la pagina dell'app con i dati dell'utente loggato
			richiesta 3 - richiesta POST in STS per la login
				questa richiesta esegue il redirect verso endpoint connect/authorize/callback settando il cookie utile per la sessione di login lato STS 
					(questo cookie e' valido per la durata di apertura del browser, anche se cambiamo URL, tornando indietro all'app, NON dobbiamo rieseguire la login, STS se ne accorge 
					della sessione controllando il cookie menzionato prima)
			richiesta 4 - redirect da STS verso l'url di callback dell'app passando nella QueryStrign il param code (codice di autorizzazione)
				NOTA: il codice di autorizzazione si aggiorna ogni volta che facciamo il passaggio da STS (anche se abbiamo gia' la sessione STS creata)
	aggiunta della pagina di post login 
		AuthService si sottoscrive a signinRedirectCallback di UserManager, metodo dedicato, invocato dal componente dalla view aperta con la callback di STS di fine login
		NOTA: giusto per ricordare, UserManager esegue una chiamata all'endpoint connect/token di STS x recuperare id_token, accesso_token e altri info relativi all'autenticazione
	gestione stato di login lato app, processo di logout
		aggiungiamo il pulsante di logout lato app
		x fare il logout lato STS chiamiamo userManager.signoutRedirect() (anche qui creiamo un metodo dedicato all'interno di AuthService)
		idem x userManager.signoutRedirectCallback(), x completare il processo di logout lato app
			questa chiamata comporta alla pulizia dell'oggetto User salvato nella sessione lato browser
		STS invalida i token 
	debug degli errori client side
		NOTA: la configurazione lato client deve fare il match con quella presente in STS (Id provider)
		due errori piu' comuni
			- clientid errato, specificare lo stesso codice sia lato app che sts
			- URLs di redirect, occhio agli spazi nella config + slash '/' alla fine di URL
		se STS viene lanciato come una console app, gli errori si vedono direttamente nella console
	inspecting errori di token JWT
		i token sono recuperabili dal Session Storage del browser, una volta fatto il login
		possiamo prendere il token e decodificarlo usando per es il tool jwt.io
		NOTA: ricordiamo che i token non sono criptati ma solo protetti dalla firma digitale (hash) per evitare la variazione 
			  e sono codificati in base64 per la trasmissione in rete (alla fine e' un JSON con N proprieta')
		troviamo seguenti valori nel id_token
			- nbf (not before), il timestamp quando il token e' stato generato
			- exp (expiration), quando il token scade
			- iss (issuer), IdP chi ha generato il token 
			- aud (audience), client id, codice identificatore dell'app client
			- sub (subject identifier), id dell'app client
		troviamo seguenti valori nel access_token
			oltre i valori comuni con id_token troviamo
				- scope (scope di riferimento, richiesti nella fase di login)
				- aud (contenente indirizzo delle API)
	registrazione dell'utente
		NON fa parte del protocollo Open ID Connect
		e' gestita da una app dedicata usata dagli amministrazione del sistema che configurano ogni utente utilizzatore
		puo' essere gestito da STS, un modulo/pagina dedicata alla registrazione degli utenti
Connettersi agli altri OpenID Connect providers
	Integrazione con gli altri provider 
		- cambia di solito la configurazione, il protocollo implementato rimane sempre quello
		- i vendor principali hanno di solito una sua librerie client x facilitare l'integrazione con loro
		Auth0 e' un provider di sicurezza in cloud (Security as a service)
	Configurazione di app Client, APIs, e Users in Auth0
		questo e' quello che cambia nel passaggio da un IdP all'altro
		vedi https://auth0.com/ x fare delle prove, sotto un esempio di configurazione
			NOTA: quando si crea una nuova application, anche se ti propone la tipologia SPA (x angular, react, view), noi abbiamo selezionato Native,
				in teoria auth0 non supporta ancora la configurazione Pixie x le app SPA (da verificare cmq)
				alla conferma di creazione nuova application, ci porta al dettaglio dove possiamo recuperare la configurazione (es. Client ID che serve lato app client)
				nel campo 'Allowed Callback URLs' mettiamo il nostro url di callback, http://localhost:4200/signin-callback
				nel campo 'Allowed Logout URLs' mettiamo http://localhost:4200/signout-callback
				nel campo 'Allowed Origins (CORS)' mettiamo http://localhost:4200
				nelle impostazioni avanzate, tab Grant Types, lasciamo solo 'Authorization Code' 
			come passo successivo dobbiamo definire risorse API x il nostro progetto
				sono risorse protette dalla autenticazione Auth0
				menu APIs -> creeate API -> il nome definisce il nostro progetto, Identifier e' una stringa qualsiasi che viene inserita nel parametro audience del flusso di protocollo
					-> create
				andiamo nel tab Permissions di API creata -> creiamo il permesso usato per accesso alle API
			come ultimo passo dobbiamo configurare gli utenti che possano accedere al tenant IdP creato
				menu Users & Roles -> Users -> create user 
					creato utente rybak.maksym@gmail.com con la pwd mcZZa#tV%u98-a4
			il passo successivo e' cambiare la configurazione dell'app anguler per accedere al nuovo IdP
	Modifica app client x usare auth0.com
		NOTA: Identity Server che abbiamo usato prima e' un framework x costruire il proprio IdP in casa, e' open source, invece auth0.com e' a pagamento
		la configurazione relativa ad un IdP puo' essere a livello di codice, file di configurazione, DB
		aggiorniamo la config. nell'app
			- aggiorniamo Client ID 
			- aggiorniamo stsAuthority (mettiamo https://rybak.eu.auth0.com/)
			avviamo l'app e vediamo se nel momento di login viene fatto il redirect su auth0 -> inserimento credenziali -> richiesta consenso all'utente -> redirect nell'app
		possiamo vedere il contenuto di Session Storage del browser, oggetto JS che contiene 
			access_token (Es. lONnsDdj1re2FuiQAoYnXU4OHFIOGjwv), NOTA: e' piu' corto di id_token, NON e' un JWT, di default auth0 NON genere un JWT x access_token
				MA a noi servirebbe un JWT che potrebbe contenere i claims (ruoli) dell'utente, x la parte di autorizzazione dell'app
			id_token, invece e' molto piu' lungo, ed e' un JWT codificato in base64
		con il codice AS IS, se proviamo a fare il logout, riceviamo l'errore 'no end session endpoint', vedo sotto x la risoluzione
	Risoluzione di differenze nella configurazione di STS
		AS IS con auth0: non possiamo fare il logout (x errore di prima), access_token non e' un JWT
		servono delle modifiche alla configurazione del client
			- dobbiamo aggiungere dei metadati nell'oggetto stsSettings
			- praticamente dobbimo settare 6 diversi URL che servono per il workflow gestito da auth0.com
				tutti questi url sono recuperabili dalla configurazione di auth0.com
					config -> config. avanzata -> tab Endpoints
				NOTA: url per il parametro end_session_endpoint viene costruito seguendo la documentazione di auth0.com
			riprovando il logout, ora funziona
		per avere access_token nel formato JWT, nei metadati di prima, il parametro authorization_endpoint deve avere la QueryString con il parametro audience={Identifier impostato nella 
			config di auth0.com, es. projects-api}
	NOTA: auth0 dovrebbe fornire anche una sua libreria x client (nelle demo usiamo oidc-client x vedere meglio le differenze tra un IdP e altro)
Autorizzare le call alle API di BE usando OAuth2
	Intro
		in questo modulo ci basiamo sul tema di autorizzazione e il protocollo OAuth2
	OAuth2 terminologia / ruoli
		NOTA: ci sono molto somiglianze con OpenID Connect, che deriva proprio dal protocollo OAuth
		qui il termine Ruoli (roles) sono relativi alla specifica OAuth2 
			DA NON CONFONDERE con un sistema di accesso role based
		termini di OAuth2:
			- Resource Owner, nel contesto di app angular rappresenta singolo utente, che ha diversi permessi x leggere/scrivere chiamando le API di BE
			- Resource Server, e' quello che va protetto da OAuth, sono delle API di BE / altre risorse di BE (storage etc.)
			- Client, l'applicazione client, che esegue chiamate a Resource Server
				ma puo' essere anche un componente di BE che esegue la chiamata alle API terzi
			- Authorization server (sinonimo x STS / IdP), app server side, che gestisce la login, producendo un access_token
	OAuth2 Grant types
		il flusso in che modo l'utente ottiene il token usato x l'autorizzazione, in una app angular, esiste solo un flusso che ha senso - Authorization Code Grant Type
			(corrisponde ad Authentication Code with Pixie visto in OpenID)
		ci sono altri tre tipi di Grant Type, da tenere in considerazione quando ci sono altre tecnologie a FE e BE:
			- Implicit Grant Type, corrisponde a Implicit visto in OpenID Connect 
				(deprecato, da preferire Authentication Code (+ PKCE))
			- Resource Owner Password Credential Grant Type, disegnato per le app desktop, mobile, che usano le funzionalita' del sistema operativo x ottenere access_token
			- Client Credential Grant Type, disegnato x una comunicazione Service - Service, quando non abbiamo un utente nel flusso 
				(sono chiamate BE to BE)
	OAuth2 tokens
		ci sono due tipi di token
			1. Access token
			2. Refresh token
		Accesso token
			di solito e' un token JWT ma puo' essere anche una stringa qualsiasi che rappresenta la sessione di autorizzazione
			in questo corso usiamo la versione JWT di access token
			un accesso token (JWT) contiene i dati come:
				- Client ID, rappresenta l'app client in STS
				- Subject ID, rappresente utente finale in STS
				- Issuer (iss), quale IdP (Identity Provider) ha rilasciato access token
				- Issue timestamp (nbf), quando il token e' stato rilasciato
				- Expiration timestamp (exp), quando scade il token
				- Audience (aud), rappresente le risorse (es. APIs) al quale il token puo' accedere
				- Scope claims (scope), IDs di controllo accesso che possano rappresentare le risorse piu' granulari (es. singole APIs)
				- Additional claims, qualsiasi numero di altri claims, configurati a livello di STS
			NOTA: tutti questi dati NON sono predisposti x poter essere consumati a livello di FE (un ambiente NON sicuro)
				sono letti (previa validazione, check) a livello di Resource Server!
				il Server
					- decodifica il token
					- valida la firma e scadenza
					- check dell'autorizzazione e permessi codificati nel token
				il BE deve prevedere un endpoint (es. Security Context API) che valida tutte le info e risponde all'app client con i dati relativi all'utente
		Refresh token
			NON deve essere usato con le app angular
			e' un token di durata elevata utile a richiedere altri token 
			se e' presente a FE, puo' essere facilmente recuperato con i tool di sviluppo del browser, e usato successivamente a richiedere altri token di accesso 
			esiste cmq la possibilita' di aggiornare 'in background' questi token anche in una app angular (vedi piu' avanti)
	Richiesta di consenso
		e' importante quando IdP e' esterno all'organizzazione, non sviluppato in casa, e al quale l'app si appoggia' per autenticazione e autorizzazione
		(es. Microsoft, Google, Fb)
		in questo caso apparte una pagina, con i permessi (scopes) che sta richiedendo l'app per poter usare per i propri scopi
			questi permessi/scope sono le risorse che potra' usare l'app
			richiesta del consenso e' qualcosa che puo' essere disabilitato, per es. se usiamo auth0.com
	Demo
		introduciamo OAuth2 nella nostra app
		switchiamo indetro su IdentityServer che abbiamo in locale
		dobbiamo prevedere lato app lo steo di autenticazione, dal quale otteniamo access_token, che va inviato al BE per ogni richiesta alle nostre API
		x abilitare l'autenticazione lato le API (qui dipende dallo stack tecnologico che usiamo), in un app ASP.NET Core, dobbiamo
			1. aggiungere il servizio di autenticazione (Bearer) in Startup.cs (specifichiamo Authority, Audience, altri dati se servono)
			2. nel metodo Configure() di Startup.cs, mettiamo app.useAuthentication()
			(con questi due punti abbiamo impostato un STS di riferimento)
			3. impostiamo cosa vogiamo proteggere (i singoli API, Controller), qui possiamo applicare la regola a livello di tutto il host, a livello di un Controller, 
				oppure a livello di un singolo endpoint del Controller
				usiamo [Authorize] - in questo modo un utente deve essere autenticato x poter chiamare endpoint, x momento nessun controllo di permessi (access_token)
				x proteggere intero host si usa un filtro, registrato a livello dell'app
	Demo
		configuriamo il client x passare access token nelle chiamate REST
		la specifiche OAuth2 dice di passare il token nell'Authorization header con il prefisso Bearer 
		vedi il codice, usiamo AuthService nel nostro ProjectService per recuperare il token e passarlo nel header giusto della richiesta HTTP
		x centralizzare l'injection del token in ogni chiamata HTTP usiamo HTTP_INTERCEPTOR 
			NOTA: da filtrare solo le richieste che vanno verso le API di BE
	Filtrare i dati in base ai claims
		a livello di BE abbiamo accesso a Security Context che ci permette di capire a che cosa puo' accedere il caller
		qui tutto dipende dalla tecnologia di BE
		in .NET Security Principle viene creato in base al contenuto di Access Token
			a livello di codice usiamo ClaimsPrinciple.Claims - contiene tutti i claims presenti nel access token, dopo un iter di validazione
			a livello di Controller accediamo usando la classe statis ClaimsPrincipal.Current
			questo permette di filtrare i dati ritornati dal BE
			se stampiamo le claims di .NET vediamo che tanti hanno URL nei propri ID, per motivi storici ancora e' cosi, ma non e' una specifica di Auth
			usando Identity Server, possiamo switchare dalla gestione Microsoft di autenticazione a quella di IdentityServer, e' un package nuget che possiamo installare 
				questo switch stampa claims rispettando la specifica OAuth
		a livello di endpoint, recuperiamo utente dal contesto di sicurezza, e usiamo questi dati (es. permessi) x filtrare i dati che inviato nella risposta
	Eseguire controlli in endpoint che modifichino i dati 
		anche qui, abbiamo il contesto di sicurezza a livello di Controller, sapiamo chi e' l'utente e che permessi ha (recuperati dal DB)
		controlliamo accesso endpoint x endpoint se serve
		NOTA: ricordiamo sempre che questo check deve avvenire a BE, anche se a FE abbiamo disabilitato/nascosto questa funzionalita'!!!
	Uso di Ruolo o Claim custom per i filtri (richieste GET) e controlli di accesso (richieste POST, PUT, DELETE)
		questo e' un'altra possibilita' per implementare le nostre regole di autorizzazione
		la condifigurazione di claims cambia da STS a STS
		NOTA: Ruolo e Claim sono dei sinonimi
			se abbiamo il BE in .NET, possiamo fare il check del genere User.IsInRole('Admin'), dove Admin e' il Claim/Ruolo configurato lato STS (IdP)
			oppure possiamo usare attributo [Authorize(Roles = "Admin")] a livello di endpoint/controller, utenti che non hanno questo ruolo riceveranno 401 (forbidden)
		NOTA: i claim configurati in STS sono x tutte le app! E' meglio NON introdurre le configurazioni dedicate alle singole app a livello di STS, x mantenere alto livello di 
			disaccoppiamento. Se serve, usiamo i permessi a livello dell'app.
Miglioramento dell'esperienza utente a livello della security
	Intro
		lato client possiamo
			- aggiornare il token, quando scade
			- fornire al client tutte le info del contesto di sicurezza (ruoli, permessi, etc.)
	Review della gestione di token
		access token scadono velocemente (es. ogni 30min)
		se la chiamata al BE arriva con il token scaduto, la risposta e' 401 Unauthorized
			in teoria, in questo momento dobbiamo ridirigere l'utente a STS x ottenere un token nuovo
			pero, questo comporto il completo unload dell'app angular dalla memoria
			come soluzione potrebbe essere l'incremento della durata del token o scegliere di salvarlo nel Local Storage e non Sessione Storage
				questo comporterebbe all'aumento di rischio dovuti agli attacchi hacker
			dobbiamo in qualche modo aggiornare logicamente il token, ma NON possiamo usare OAuth2 refresh tokenc con Implicit Flow
		come e' stato menzionato anche prima, quando utente eseguo il login in STS, tra il browser e IdP viene stabilita una sessione cookie based
			quindi, ogni richiesta dal browser verso Idp, cintiene il cookie scambiato nel momento di login
			ogni volta che la nostra app invia una richiesta a STS (/authorize), STS rimanda indietro il cookie aggiornato
			se la sessione cookie based e' piu' lunga da quella di token, STS aggiornera' il token in background (sliding expiration)
		qualche nota su Cookie based authentication
			- la tendenza e' di abbandonare questa strada ma non x motivi di sicurezza
			- finche usiamo un framework / libreria nota, i nostri cookie rispettano HTTP e non c'e' nessun pericolo
			- cookie x site specific, viene ritornato dal browser se la richiesta e' verso host di origine
			- cmq abbiamo i seguenti svantaggi
				XSS, cross site scripting
				CSRF, cross site request forgery
			- uno dei motivi di 'sgancio' da cookie based auth e' x permettere un SSO, cross organizations, cross tenants
				qui finiamo nell'uso di tokens 
		cmq x una app angular l'approccio da preferire q' quello misto, usare una sessione cookie based con STS e OpenID Connect con OAuth2 x SSO, protezione risorse di BE etc.
		in che modo viene usato un aggiornamento del token in background (sliding refresh of secured session with STS)
			periodicamente inviamo una richiesta a STS
			x fare cio' usiamo un iframe nascosto, x inviare una richiesta di autorizzazione all'endpoint di STS
			(NOTA: nella Query String specifichiamo una cosa del genere ?prompt=none, dove prompt e' un parametri del protocollo OpenID Connect, che indica a 
				STS di autenticare l'utente senza mostrare una UI, che va a buon fine finche session cookie di STS e' valido)
			se tutto va a buon fine, STS ritorna nuovo access_token, in modo identico quando utente esegue una login
			NOTA: tutta questa gestione e' gia' implementata da oidc-client
				dobbiamo impostare il parametro che abilita silent renew + fornire la callback x silent renew
				UserManager client di oidc-client tiene sotto monitoraggio la scadenza del token, crea un iframe nascosto, invia la richiesta a STS, e crea un nuovo User 
					con token aggiornato
	Demo
		facciamo subscribe a addAccessTokenExpired di UserManager di oidc-client
		in stsSettings aggiungiamo automaticSilentRenew, silent_redirect_uri
		NOTA: url di redirect nel giro di 'silent renew' deve essere configurato/abilitato lato STS
		UserManager lancia il gestore dell'evento addAccessTokenExpired 60sec prima della scadenza di token
	Fornire Security Context al Client
		possiamo mostrare/nascondere elementi, bloccare la navigazione verso le view non autorizzate
		ricordiamo cmq che tutto quello che succede client side puo' essere forzato da un hacker
		iter x fornire al cliente le info del contesto di sicurezza
			- creare lato BE endpoint chiamato subito dopo la login x fornire al client le info necessarie
			- mappiamo i tipi lato FE (es. AuthContext, UserClaim)
			- authContext lato FE fa la chiamata all'endpoint e morizza il risultato in un parametro locale
			- aggiungiamo la chiamata all'endpoint di BE nel gestore dell'evento addUserLoaded di UserManager di oidc-client
			cmq aggiorniamo il contesto di sicurezza client side ogni volta che cambia il token 
			recap: AuthContext ha 2 props { userProfile, claims }
	Customizzazione esperienza utente in base ai permessi
		conviene modificare AuthContext aggiungendo la prop. get isAdmin() chiamato in vari punti dell'app
		usiamo ngIf x visualizzare/nascondere UI
		usiamo [disabled] a abilitare/disabilitare UI
	Usare le guardie angular per disabilitare la navigazione verso le view non abilitare 
		NOTA: se la navigazione avviene verso una pagina non consentita, il BE deve rispondere con errore 403 Forbidden
		una guardia angular e' una classe dove viene inserita la logica di controllo se la navigazione e' permessa
		es. admin-route-guard.ts
		la guardia va inserita nella lista providers del modulo relativo
		la configurazione della rotta contiene il parametro canActivate, dove possiamo impostare la guardia necessaria
		
	Demo
		un'altra app ASP.NET MVC x mostrare SSO in azione

			
			
			
		
		