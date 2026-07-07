# fortilog — Analyseur de logs FortiGate (détection de compromission)

[![CI](https://github.com/flab75/fortilog/actions/workflows/ci.yml/badge.svg)](https://github.com/flab75/fortilog/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.11%20|%203.12-blue)
![Platforms](https://img.shields.io/badge/platform-Linux%20|%20Windows%20|%20macOS-lightgrey)

Analyse des exports de logs FortiCloud/FortiGate (`clé="valeur"`) : détection
automatique du type, parsing, grille d'audit de compromission, comparaison
multi-dates / multi-boîtiers, sortie **rapport texte** + **classeur Excel**.

> **Principe :** l'outil **signale et structure** ; le **verdict reste humain**.
> Il ne produit aucune conclusion que les logs ne permettent pas (certaines
> vérifications exigent l'IAM FortiCloud ou la configuration du boîtier).

## Licence

[GNU Affero General Public License v3.0](LICENSE) — le code source de tout dérivé distribué
ou exposé en service réseau doit être publié sous la même licence.

## Prérequis
- Python 3.11+
- Installation recommandée (depuis le dépôt cloné ou directement depuis GitHub) :

  ```bash
  pip install .                                          # depuis le dépôt cloné
  pip install ".[ui]"                                    # + UI Streamlit
  pip install ".[dev]"                                   # + tests pytest
  pip install git+https://github.com/flab75/fortilog    # sans cloner
  ```

  > **Note :** pour développer (modifications prises en compte sans réinstaller) :
  > `pip install -e .` ou `pip install -e ".[ui,dev]"`.

  Les fichiers `requirements*.txt` restent disponibles pour les environnements
  qui gèrent les dépendances sans `pyproject.toml` (déploiements CI, virtualenvs manuels) :

  ```bash
  pip install -r requirements.txt        # moteur d'analyse seul
  pip install -r requirements-ui.txt     # + UI Streamlit
  pip install -r requirements-dev.txt    # + tests pytest
  ```

## Configuration (référentiel)

Le `config.yaml` versionné est **anonymisé** (valeurs d'exemple : `adminA`, IP de
documentation `203.0.113.x`, chemins relatifs). Pour analyser de **vrais** logs,
copiez-le en `config.local.yaml` (déjà dans `.gitignore`) et renseignez vos vraies
valeurs (admins, IP WAN, utilisateurs, chemins absolus des bases). Puis :
```bash
fortilog --input ./logs --config config.local.yaml --output ./rapport
```

**Amorcer le référentiel depuis vos `.conf`** : plutôt que tout saisir à la main, générez
un brouillon depuis un ou plusieurs backups FortiGate, puis **relisez-le** avant usage :
```bash
fortilog-confgen FW-T1.conf FW-T2.conf -o config.generated.yaml   # --force pour écraser
```
Dérive admins, plages internes, pool SSL-VPN (`vpn ssl settings` → `tunnel-ip-pools`),
utilisateurs/groupes VPN, peers IPsec et DNS ; les
paramètres d'analyse prennent les défauts du projet. Le `mgmt` est heuristique (à vérifier)
et `fichiers_boitier` est à compléter. Aucun secret n'est extrait. Également disponible dans
l'UI Streamlit (section « 🧩 Générer un référentiel »). Renommez ensuite en `config.local.yaml`.

## Usage

### Interface graphique (Streamlit)
```bash
streamlit run app.py
```
Ouvre un navigateur : déposez vos fichiers `.log`, choisissez un `config.yaml`
optionnel, cliquez **Lancer l'analyse**. Les résultats s'affichent en onglets
(événements signalés colorés, tableau de bord, rafales, différentiels) et le
rapport `.xlsx` est téléchargeable directement.

### Ligne de commande (CLI)
```bash
fortilog --input ./logs --config config.yaml --output ./rapport
```
- `--input` : dossier contenant les fichiers `.log` (un ou plusieurs).
- `--config` : référentiel « du normal » + paramètres (voir `config.yaml`).
- `--output` : produit `rapport_fortigate.txt` et `rapport_fortigate.xlsx`.
- `--etat` : chemin du fichier d'état de suivi (défaut : `<output>/etat_suivi.json`).

> Sans installation (`pip install`), les commandes `python -m fortilog.main`,
> `python -m fortilog.confdiff`, `python -m fortilog.confgen` et `python -m fortilog.ack` fonctionnent aussi.

## Sorties (classeur, 14 feuilles)
0. `Rapport` — **synthèse** qui décrit les résultats et explique les problèmes, en distinguant
   **[AVÉRÉ]** (état de config, volumes) de **[À CONFIRMER]** (suspicions). Chaque section
   (config, events, IP externes) détaille les constats les plus sévères individuellement
   (réglable via `rapport.max_constats`, défaut 5). Aussi en tête du rapport texte et dans
   l'onglet « Rapport » de l'UI Streamlit.
1. `Tableau de bord` — agrégats par boîtier/jour (échecs, logins OK, lockouts, SSL-VPN, passwd_invalid, IP uniques).
2. `UTM descriptif` — top signatures/attaques, domaines/catégories, verdicts pour
   `utm/ips`/`utm/webfilter`/`utm/dns`/`utm/antivirus` — **descriptif, sans règle
   d'alerte** (voir « Agrégats descriptifs UTM » ci-dessous).
3. `Evenements signales` — événements à risque, colorés par sévérité (info→critique), enrichis portée/pays/ASN/réputation.
4. `Acteurs a risque` — IP externes et comptes agrégés depuis les événements, triés par un
   **score de priorisation transparent** : `score = 100×n_critique + 30×n_eleve + 10×n_moyen
   + 3×n_faible + 50×(réputation non vide) + 20×(nb règles distinctes − 1)` (pondérations :
   `acteurs.poids`, plafond `acteurs.max_lignes` défaut 100). Le score sert à **trier** les
   entités à investiguer, **jamais à conclure**. IP d'infrastructure connue (WAN/mgmt,
   peers/DNS) exclues.
5. `Chaines suspectes` — séquences corrélées (accès→compte→exfiltration) — **à confirmer**.
6. `IP malveillantes` — sources présentes dans une liste de réputation (threat intel) — **à confirmer**.
7. `Audit config` — constats sur les `.conf` FortiGate importés (comptes, accès, automation) — **à confirmer**.
8. `Comparaison config` — écarts (ajout/suppr/modif) vs une config de référence + attribution qui/quand — **à confirmer**.
9. `Sources externes` — top des IP externes par volume (contexte géo/ASN) — voir « Enrichissement ».
10. `Rafales` — pics détectés (seuils **adaptatifs** ajustables).
11. `Differentiels` — entités apparues/disparues entre dates et entre boîtiers (Prio 1 alertées).
12. `Donnees unifiees` — données parsées/dédupliquées (plafonnée, cf. limites).
13. `Referentiel` — la configuration du « normal » utilisée.

Le rapport de synthèse comporte aussi une **frise chronologique** des événements de
sévérité ≥ `timeline.severite_min` (défaut `eleve`) : rafales consécutives de même
(règle, acteur) dans la même heure regroupées en « × N similaires de HH:MM à HH:MM »
au-delà de `timeline.max_par_groupe` (défaut 3) — le compte exact est toujours conservé.

## Détection (grille d'audit, 13 règles)
- Login admin réussi depuis source **externe** (critique) / compte hors référentiel (élevé).
- Brute-force sur **compte valide** (`passwd_invalid`, élevé) vs compte inexistant.
- Tunnel **SSL-VPN** établi hors référentiel (critique).
- **Création/modif** de compte admin/SSO/API (Add=élevé ; auteur inconnu=critique).
- Nom de compte **potentiellement voyou** (motif jetable/mail anonyme — SUSPICION).
- **Exfiltration** : téléchargement de config/logs via GUI.
- **Automation déclenchée** → info (l'event log ne donne pas l'action-type : vérifier en config).
- **Réseau** : sortie boîtier vers destination non listée (moyen).
- **Réseau** : accès depuis pool VPN → interface de management (élevé). Le pool est
  configurable via `pool_vpn` (un CIDR ou une liste ; défaut `10.212.134.0/24` si absent).
- **UTM/app-ctrl** : application bloquée par FortiGate (élevé) ; `apprisk="critical"` non bloquée
  hors whitelist (moyen, SUSPICION) ; catégorie Proxy hors whitelist (élevé). Whitelist configurable
  (`app_ctrl_whitelist`) — exclut par défaut `proxy-safebrowsing.googleapis.com` (Safe Browsing).
- **Brute-force potentiellement réussi** : login admin réussi précédé d'≥ N échecs (défaut 5) sur la
  même IP/compte dans une fenêtre (défaut 60 min) → critique (source externe) / élevé (interne).
  Paramétrable (`bruteforce.seuil_echecs`, `bruteforce.fenetre_minutes`). SUSPICION, pas une preuve.
- **Horaires inhabituels** : login admin réussi hors plage ouvrée (`horaires_ouvres`, défaut 7h-20h)
  ou le week-end → faible (SUSPICION comportementale, tunable au rythme de l'organisation).
- **Rafale d'échecs sur comptes inexistants** (`name_invalid`) : ≥ N échecs (défaut 20,
  `bruteforce_name_invalid.seuil_echecs`) depuis une même IP dans une fenêtre (défaut 60 min)
  → **un seul événement par (IP, rafale continue)** — déclenchement au seuil par fenêtre,
  puis la rafale s'étend tant que les échecs s'enchaînent à moins d'une fenêtre d'écart —
  moyen (IP externe) / faible (interne). SUSPICION —
  du bruit d'Internet le plus souvent : l'intérêt est le volume et l'entrée au score acteur.

Chaque événement porte une colonne `mitre` (technique MITRE ATT&CK associée à la règle,
ex. `T1110 — Brute Force`). Ce mapping est **indicatif** (aide au reporting), jamais une
attribution.

## Types de logs UTM
- `utm/app-ctrl` : analysé par les règles R10.
- `utm/ips`, `utm/webfilter`, `utm/dns`, `utm/antivirus` : reconnus, marqués "(sans règles dédiées)",
  parsing générique. Des exemples réels de ces types sont nécessaires avant d'écrire des règles dédiées.
- `event/security-rating` : bilan de durcissement FortiGate — intégré au rapport texte (section
  **BILAN HARDENING**), pas une détection de compromission, pas de feuille Excel.

## Corrélation temporelle (chaînes IoC)
- Reconstitue la **séquence ordonnée** `accès → création/modif de compte → exfiltration`
  par un même **acteur** ou une même **IP**, dans une fenêtre paramétrable (défaut 1 h,
  `correlation.fenetre_minutes`). Une chaîne complète est marquée **critique**.
- Pour éviter le bruit, une chaîne ne démarre que sur un **accès anormal** (login
  externe/hors-référentiel, VPN hors-référentiel) ; l'activité admin légitime de
  routine n'en génère pas.
- **Garde-fou** : une chaîne est une **corrélation temporelle**, jamais une preuve —
  toujours affichée « à confirmer ».

## Enrichissement géo/ASN (hors-ligne, optionnel)
- **Portée** de chaque IP source (interne / externe / réservé) — calculée **sans aucune base**,
  d'après `plages_internes`. Toujours disponible.
- **Pays / ASN / organisation** des IP externes — uniquement si des **bases locales** sont
  fournies dans `config.yaml` :
  - `geo_db_path` : DB-IP Lite **Country CSV** (`start_ip,end_ip,country`, licence CC-BY-4.0).
  - `asn_db_path` : iptoasn **ip2asn-v4.tsv** (`start end asn country org`, domaine public).
  - **100 % hors-ligne**, aucune dépendance ajoutée. Ne pas utiliser MaxMind GeoLite2 (EULA/compte).
  - **Téléchargement des bases : voir [docs/PROCEDURE_BASES_GEO.md](docs/PROCEDURE_BASES_GEO.md).**
- **Top sources externes** : classe les IP externes par volume (révèle les brute-force
  `name_invalid` non signalés par les règles), en **excluant l'infrastructure connue**
  (WAN/mgmt des boîtiers, peers/DNS légitimes).
- **Sans base** : la portée reste calculée, les colonnes pays/ASN sont vides + mention honnête.
  Aucun pays/ASN n'est jamais inventé. La géo est du **contexte**, ni preuve ni absolution.

## Listes de réputation (threat intel, hors-ligne, optionnel)
- Marque les IP sources présentes dans des **listes d'IP malveillantes connues** (`reputation_lists`
  dans `config.yaml` : `[{nom, path}]`), au format CIDR/`.netset`/`.ipset` (FireHOL, abuse.ch…).
  License-clean uniquement. Réutilise le moteur de plages de la géo.
- Sortie : feuille **« IP malveillantes »** + section rapport + colonne `srcip_reputation` sur les
  événements. Sur les vrais logs, **4 455 IP attaquantes** sont dans FireHOL Level 1.
- **Matching externe uniquement** : les listes type FireHOL incluent les bogons (10/8, 192.168/16…)
  → une IP **interne** n'est jamais signalée (évite le faux positif classique).
- **À CONFIRMER** : présence en liste = signal fort, pas une preuve (listes parfois larges/datées).

## Fraîcheur des bases géo/ASN/réputation
- À chaque run, l'âge (mtime) de chaque fichier de base configuré (`geo_db_path`,
  `asn_db_path`, `fortinet_ranges_file`, chaque entrée de `reputation_lists`) est calculé
  et stocké dans `meta["bases"]` (`[{nom, path, age_jours, perime}]`).
- **Seuil** : `bases.age_max_jours` dans `config.yaml` (défaut 90 jours). Au-delà,
  avertissement en tête du rapport — « ⚠ La base « X » a N jours — les correspondances
  peuvent être obsolètes » — et une ligne dédiée dans la feuille **« Referentiel »**.
  L'UI affiche le même rapport (onglet **Rapport**).
- **Jamais bloquant** : base absente ou vieillie n'interrompt jamais l'analyse.

## Agrégats descriptifs UTM (sans règle d'alerte)
- Pour `utm/ips`, `utm/webfilter`, `utm/dns`, `utm/antivirus` (types reconnus mais sans
  règle de détection dédiée), la feuille **« UTM descriptif »** et une section du
  rapport listent les valeurs les plus fréquentes : signatures/attaques (`ips` :
  `attack`+`severity`), domaines/catégories bloqués (`webfilter` : `hostname`+
  `catdesc`+`action` ; `dns` : `qname`+`catdesc`+`action`), verdicts (`antivirus` :
  `virus`). **Purement descriptif** — aucune sévérité, aucune détection, marqué
  « (descriptif, sans règle d'alerte) ».
- Nombre de valeurs par type réglable via `utm_descriptif.top_n` (config.yaml, défaut
  20). Un champ absent des logs fournis (profil non journalisé par le boîtier) fait
  omettre la ligne correspondante, jamais de valeur inventée ; un type UTM absent des
  logs n'apparaît simplement pas.

## Audit de configuration FortiGate (.conf)
Importez un ou plusieurs **backups de configuration** (`.conf`) — en CLI (déposez-les
dans le dossier `--input`) ou via l'UI Streamlit (zone de dépôt `.conf`). L'outil parse
le CLI FortiGate et vérifie des **indices de compromission**, comparés au référentiel :
- Compte admin **hors référentiel** (`config system admin`/`sso-admin`) → critique (SUSPICION).
- Admin **sans trusted-host** (joignable de toute IP) → élevé.
- Nom d'admin **voyou** (motif) → élevé ; **automation** `cli-script`/`webhook` (persistance) → élevé.
- Accès admin **exposé** : `telnet`, ou GUI/SSH sur interface `role wan` → élevé.
- Config **sauvegardée par un compte hors référentiel** (en-tête `user=`) → moyen.

On peut analyser des `.conf` **seuls** (sans logs). Tout est marqué **à confirmer** :
un admin légitime récent peut être hors référentiel — ce n'est jamais une preuve.

## Comparaison de deux configurations (.conf)
Compare une config **de référence / validée** à une config **actuelle / suspecte** : ce qui a
**changé** (objets ajoutés / supprimés / modifiés : admins, règles firewall, VPN, interfaces,
routes, automation, users…), **par qui** et **quand**.
```bash
fortilog-diff reference.conf actuel.conf --logs ./logs    # --all pour toutes les sections
```
- **« par qui / quand »** vient des **logs** (events « Object attribute configured » :
  `cfgobj`/`user`/`action`/timestamp). Le `.conf` seul ne donne que qui a *sauvegardé* le backup
  (en-tête `user=`). Hors fenêtre de logs → « inconnu » (jamais inventé).
- Hashs/secrets (mots de passe, clés, psksecret) → **« (valeur masquée) »**.
- Aussi dans l'UI Streamlit : section **« 🔁 Comparer deux configurations »** (les logs déposés
  servent à l'attribution).
- **Intégré à l'analyse générale** : fournissez une config de référence et la comparaison entre
  dans le **rapport global** (feuille Excel « Comparaison config », section du rapport, synthèse) :
  ```bash
  fortilog --input ./logs --config config.local.yaml --output ./rapport \
           --ref-conf reference.conf
  ```
  Dans Streamlit : déposez un fichier dans **« Config de référence / validée »** avant de lancer
  l'analyse (onglet « 🔁 Comparaison config »).
- Un écart de config n'est **pas** une compromission — à confirmer.

## Suivi entre analyses & acquittement

Chaque constat (événement, audit config, diff config) porte une **identité stable**
(`constat_id`, sha256 tronqué de `famille|règle|boîtier|acteur` — ni timestamp ni
volume : un même brute-force étalé sur 2 jours = un même constat). L'état est
persisté dans `etat_suivi.json` (dossier `--output`, surchargeable par `--etat`),
JSON lisible et éditable.

- À chaque run, les constats sont marqués `nouveau` / `connu` / `acquitte`
  (colonne `suivi` des feuilles Excel et de l'UI) ; la synthèse ouvre par
  « X constats dont Y NOUVEAUX depuis l'analyse du JJ/MM/AAAA ».
- **Acquittement** (faux positif assumé, documenté) :
  ```bash
  fortilog-ack --etat rapport/etat_suivi.json --list          # table id/statut/résumé
  fortilog-ack --etat rapport/etat_suivi.json ID… --motif "…" # bascule en acquitté
  ```
  Un constat acquitté **reste signalé** (tag `[ACQUITTÉ le JJ/MM/AAAA]` dans le
  détail) ; il est seulement **exclu du décompte d'alerte** de la synthèse — l'outil
  ne cache jamais rien.
- État absent = premier run (tout est `nouveau`) ; état corrompu → warning explicite,
  analyse normale sans suivi, fichier laissé intact.

## Format & parsing
- `clé="valeur"` (espaces gérés). **Guillemets et backslash échappés** par FortiGate
  (`\"`, `\\`) à l'intérieur d'une valeur sont correctement déséchappés sans décaler les
  champs suivants (vérifié sur 806 064 lignes réelles).

## Comparaison
- Agrégats **jour** (défaut) ou **heure**.
- **Rafales** : fenêtre glissante (défaut 1 h), seuil **adaptatif** (≥ facteur × médiane) ou fixe — paramétrable dans `config.yaml`.
- **Différentiel** sur 6 entités (priorité 1→3) ; Prio 3 (IP d'attaque, noms ciblés) résumées en compteurs.

## Référentiel & rattachement boîtier
- Les exports ne contiennent pas de `devname` → le boîtier est déduit par **IP**
  (WAN/mgmt). Pour les logs sans IP du boîtier (event/user, event/vpn,
  traffic/forward), un **indice par nom de fichier** (`fichiers_boitier`) permet
  le rattachement. Sinon : `inconnu` (comportement honnête, pas de devinette).
- Règle VPN : les utilisateurs VPN viennent d'IP résidentielles dynamiques →
  référence = **user + groupe + pool**, jamais l'IP source. La détection
  « source externe » ne s'applique qu'aux accès **admin**.

## Performance & limites (mesuré)
- ~0,6 s/Mo ; **pic mémoire ≈ 4× la taille d'entrée** (P5 phases 1+2 : parsing
  colonnaire + séparation colonnes d'analyse/affichage). Mesuré sur T1
  (397 Mo / 392 541 lignes) : **1 599 Mo** de pic RSS, sorties identiques.
- Pour de **très gros volumes** (> ~600 Mo cumulés sur peu de RAM) : traiter par
  **batches** (par jour ou par boîtier).
- Excel plafonne à ~1 048 576 lignes → la feuille `Donnees unifiees` est
  **tronquée** (paramètre `max_lignes_donnees_unifiees`, défaut 200 000) ; les
  **agrégats et détections portent sur la TOTALITÉ** des données.
- Type de log inconnu → parsing générique + marquage, **jamais** d'analyse inventée.

## Tests

Suite pytest versionnée : **173 tests rapides** + **9 tests sur vrais logs** (@slow) = **182 au total**.

```bash
# Tests rapides (fixtures synthétiques)
python -m pytest tests/ --ignore=tests/fixtures -m "not slow"

# Tests sur vrais logs (nécessite les exports dans /path/to/logs/)
python -m pytest tests/ --ignore=tests/fixtures -m "slow"

# Tous les tests
python -m pytest tests/ --ignore=tests/fixtures
```

Couverture des tests :
- **parse.py** : 12 cas (quotées/espaces, mixtes, vide, ligne réelle, échappements `\"`/`\\`).
- **ingest.py** : 7 cas (chaque type connu + inconnu + UTM générique, listage).
- **normalize.py** : 6 cas (timestamp, boîtier par IP/fichier/inconnu, dédup).
- **detect.py** : 28 cas (R1-R9 pos/nég, 6 cas R10a/b/c, 3 cas R11 brute-force, 2 cas R12 horaires).
- **geo.py** : 22 cas (portée, lookup CSV/TSV/CIDR, enrichissement géo + réputation,
  dégradation, top sources, exclusion infra, exclusion bogon interne).
- **confaudit.py** : 11 cas (parsing CLI, C1-C6, config propre sans critique, tri par sévérité).
- **analysis.py** : 13 cas (sections, constats détaillés par règle, `max_constats` configurable,
  tag [À CONFIRMER] sur SUSPICION, top events §3/§4, corrélation WAN↔brute-force, alerte brèche,
  mode config-seul, vide).
- **confdiff.py** : 12 cas (ajout/suppr/modif admin, nouvelle règle, param global, masquage secret,
  attribution qui/quand depuis logs, absence de logs, en-tête « sauvé par », compte cloud → info).
- **compare.py** : 5 cas (agrégats, rafales, différentiel).
- **correlate.py** : 11 cas (chaîne complète, bénin, activité admin légitime, ordre,
  fenêtre trop courte, mapping d'étapes, IP effective).
- **validate.py** : 16 cas — config valide + erreurs distinctes (CIDR, IP, regex, seuils,
  corrélation, whitelist app-ctrl, `rapport.max_constats`).
- **ui_helpers.py** : 16 cas — tri sévérité, métriques, chaînes, formatage timestamps, couleurs.
- **confgen.py** : 6 cas rapides + 1 @slow (extraction basique, plages+mgmt heuristique, VPN,
  aucun secret, YAML valide, multi-conf, vrais .conf T1).
- **intégration** : scénario compromission (≥3 critiques), scénario bénin (0 FP),
  parsing vrais logs T1/T2, détection sur vrai fichier event/system, whitelist app-ctrl T1.

## Validation du config.yaml

Le fichier `config.yaml` est **validé au démarrage**. En cas d'erreur :
message explicite + arrêt (exit 1). Vérifie :
- Présence des clés requises (`boitiers`, `admins_connus`, `plages_internes`,
  `destinations_legitimes`, `rafales`).
- Validité des CIDR, adresses IP, expressions régulières.
- Seuils de rafale (valeurs numériques positives, mode `adaptatif` ou `fixe`).

## Tests historiques (validés sur données réelles)
- Déduplication des fenêtres qui se chevauchent (42 353 doublons retirés sur un jeu réel).
- **Détection positive** : scénario de compromission → 3 critiques + 4 élevés.
- **Absence de faux positifs** sur logs bénins (brute-force échoué → 0 alerte de compte voyou).
- Montée en charge : T1 post-P5 — 397 Mo / 392 541 lignes → **1 599 Mo** pic RSS (−34 % vs avant P5).
