# CLAUDE.md — Projet `fortilog`

Contexte projet destiné à un agent de code. À lire avant toute modification.

## Ce qu'est le projet
Analyseur Python (3.11+) de logs FortiGate/FortiCloud (format `clé="valeur"`)
pour détecter des **indices de compromission** et structurer les résultats en
rapport texte + classeur Excel. Né d'un audit réel de deux pare-feu FortiGate-60F
(FW-SITE-A / FW-SITE-B) : l'outil reproduit la logique de cet audit.

## Principe directeur — NON NÉGOCIABLE
**L'outil signale et structure ; le verdict reste humain.** Il ne conclut jamais
à une compromission que les logs ne prouvent pas. Certaines confirmations sont
**hors périmètre des logs** (IAM FortiCloud, configuration du boîtier). Toute
détection « compte voyou » est une **SUSPICION** à confirmer, jamais une preuve.
Ne jamais inventer de comportement, de chiffre, ni d'analyse sur un type de log
inconnu (dans ce cas : parsing générique + marquage explicite).

## Architecture
```
fortilog/
├── config.yaml      # référentiel "du normal" + paramètres (éditable, hors-code)
├── README.md
├── pytest.ini       # config pytest (mark slow)
├── app.py           # UI Streamlit (streamlit run app.py) — s'appuie sur fortilog.main.run()
├── fortilog/
│   ├── parse.py     # parse_line : clé=valeur, valeurs quotées + échappements Fortinet (\" \\)
│   ├── ingest.py    # list_log_files + detect_type (par type/subtype/logid)
│   ├── normalize.py # build_timestamp, assign_boitier (par IP + indice fichier), deduplicate
│   ├── detect.py    # run_detection VECTORISÉE (masques pandas) -> événements + sévérité
│   ├── compare.py   # aggregate (jour/heure), detect_bursts (adaptatif), diff_entities (6 entités)
│   ├── correlate.py # correlate_chains : chaînes IoC ordonnées (accès→compte→exfil) par acteur/IP
│   ├── geo.py       # enrichissement géo/ASN HORS-LIGNE + portée + top sources + réputation
│   ├── confaudit.py # parse + audit de compromission des .conf FortiGate (comptes, accès, automation)
│   ├── confdiff.py  # comparaison 2 .conf (ajout/suppr/modif) + attribution qui/quand via logs ; CLI
│   ├── analysis.py  # build_analysis : rapport de SYNTHÈSE (décrit/explique, [AVÉRÉ]/[À CONFIRMER])
│   ├── report.py    # build_report (texte détaillé) + rappel des limites
│   ├── excel.py     # write_workbook (xlsxwriter, 11 feuilles, « Rapport » en 1re)
│   ├── validate.py  # validate_config : vérifie le config.yaml au démarrage (CIDR, regex, seuils)
│   ├── ui_helpers.py # prepare_events/metrics/agg/bursts/diff — helpers testables hors-UI
│   └── main.py      # run(input, config, output) + CLI argparse
└── tests/
    ├── conftest.py      # fixtures partagées, helpers, chemins vers vrais logs
    ├── fixtures/        # fichiers .log synthétiques (1 pos + 1 nég par règle)
    ├── test_parse.py    # parsing clé=valeur
    ├── test_ingest.py   # détection de type
    ├── test_normalize.py # timestamp, boîtier, dédup
    ├── test_detect.py   # 9 règles : R1-R9 (pos + nég)
    ├── test_compare.py  # agrégats, rafales, diff
    ├── test_correlate.py # chaînes IoC (complète, bénin, ordre, fenêtre, IP effective)
    ├── test_geo.py      # portée, lookup plages, enrichissement, dégradation, top sources
    ├── test_validate.py # validation config (valide + cas d'erreur)
    ├── test_ui_helpers.py   # 13 tests hors-UI (prepare_events, metrics, diff, badge…)
    └── test_integration.py # scénario compromission + bénin + vrais logs (@slow)
```

## Flux (`main.run`)
**validate_config** → **audit .conf** (confaudit) → ingest → parse → concat → build_timestamp →
assign_boitier → deduplicate → (catégorisation mémoire) → detect (R1-R12) → **correlate** →
**enrichissement géo + réputation** → aggregate + bursts + diffs → report + excel.
`run()` accepte logs ET/OU `.conf` ; **mode audit-config seul** si aucun log fourni
(import de configs uniquement, p.ex. depuis l'UI Streamlit). `_emit()` calcule la
**synthèse** (`analysis.build_analysis`), l'écrit en 1re feuille Excel « Rapport » +
en tête du rapport texte, et la stocke dans `meta["analysis"]` (onglet Streamlit « Rapport »).

## Comparaison de configurations (`confdiff.py`)
- Compare une config **de référence/validée** à une config **actuelle** : objets
  **ajoutés / supprimés / modifiés** par section sensible (admins, sso, api-user, firewall
  policy, vpn, interface, route, dns, automation, user…). `all_sections=True` pour tout.
- **Attribution « par qui / quand »** : corrélation avec les logs (`cfgobj`/`cfgpath`/`user`/
  `action`/timestamp des events « Object attribute configured »). Le `.conf` seul ne porte que
  qui a *sauvegardé* le backup (en-tête `user=`). Hors fenêtre de logs → « inconnu » (jamais inventé).
- Secrets/hashs (password, psksecret, private-key…) → **« (valeur masquée) »**.
- Comptes SSO **FortiGate Cloud** (section `system sso-fortigate-cloud-admin`, format
  `serial@fortigatecloud.com`) : auto-provisionnés → criticité **info** + mention (pas critique).
- Accès : `python -m fortilog.confdiff ref.conf actuel.conf [--logs DIR] [--all]` ; section
  « 🔁 Comparer deux configurations » dans l'UI Streamlit. **Hors `main.run`** (outil dédié).
- Garde-fou : un écart de config n'est pas une compromission (à confirmer).

## Rapport de synthèse (`analysis.py`)
- Décrit les résultats et **explique** les problèmes, en distinguant **[AVÉRÉ]** (état de
  config, volumes de logs) de **[À CONFIRMER]** (compte hors référentiel, chaîne, nom voyou).
- **Lecture d'ensemble** : relie les constats (GUI exposée sur WAN ↔ volume de brute-force ↔
  IP en réputation) et conclut explicitement « aucune compromission avérée » quand c'est le cas
  (jamais de conclusion non prouvée). Data-driven (compte les sévérités, règles, IP, échecs…).

## Audit de configuration FortiGate (`confaudit.py`)
- Parse le CLI FortiGate (`config/edit/set/next/end`) en arbre, puis applique une grille
  ANCRÉE sur le format réel (jamais inventée), comparée au référentiel `config.yaml` :
  - **C1** compte admin (`system admin`/`sso-admin`) hors `admins_connus` → critique (SUSPICION).
  - **C2** admin sans `trusthost` (joignable de toute IP) → élevé.
  - **C3** nom d'admin matchant `comptes_suspects_regex` → élevé (SUSPICION).
  - **C4** `automation-action` de type `cli-script`/`webhook` (persistance/exfil) → élevé.
  - **C5** `allowaccess` avec `telnet`, ou `http/https/ssh` sur interface `role wan` → élevé.
  - **C6** config sauvée par un compte hors référentiel (en-tête `user=`) → moyen.
- Sortie : table `config_audit` → feuille Excel « Audit config » + section rapport.
- **Garde-fou** : tout est SUSPICION/à confirmer (un admin légitime récent peut être hors
  référentiel). Vérifié sur vrais .conf : 0 admin voyou, mais admins sans trusthost + **GUI
  admin exposé sur WAN** (corrèle avec le brute-force massif observé dans les logs).

## Conventions
- **Lancement CLI :** `python -m fortilog.main --input ./logs --config config.yaml --output ./rapport`.
- **API stable :** `fortilog.main.run(input_dir, config_path, output_dir) -> (tables, meta)`.
  Toute UI doit s'appuyer dessus, pas réimplémenter la logique.
- **Référentiel = `config.yaml`**, jamais en dur dans le code. Valeurs actuelles
  vérifiées sur les exports réels (boîtiers par IP, admins connus, utilisateurs
  VPN/locaux, groupes VPN, plages internes, destinations légitimes, motifs de
  comptes suspects, paramètres de rafale).
- **Dépendances :** pandas, xlsxwriter, pyyaml, openpyxl.

## Règles de détection implémentées (`detect.py`, 14 règles)
1. Login admin réussi depuis source **externe** → critique ; compte hors référentiel → élevé ; interne+connu → info.
2. Brute-force sur **compte valide** (`passwd_invalid`) → élevé.
3. Tunnel **SSL-VPN** établi hors référentiel (user/groupe inconnu) → critique.
4. Création/modif de compte admin/SSO/API → Add=élevé ; auteur hors référentiel=critique ; sinon moyen.
5. Nom de compte **potentiellement voyou** (motif jetable/mail anonyme) → élevé
   **uniquement** sur opération de config-compte OU login réussi (jamais sur un
   échec de brute-force — le `user` y est le nom *tenté*, pas un compte existant).
6. Téléchargement de config via GUI → moyen ; de logs → faible.
7. Automation déclenchée → info (l'event log ne donne pas l'action-type ; vérifier en config).
8. Trafic sortant du boîtier (traffic/local) vers destination non listée → moyen.
9. Accès depuis pool VPN (10.212.134.0/24) vers interface de management → élevé.
10. **UTM/app-ctrl** (P3.2) :
    - 10a. Application **bloquée** par FortiGate → élevé.
    - 10b. Application `apprisk="critical"` non bloquée et hors `app_ctrl_whitelist` → moyen (SUSPICION).
    - 10c. Catégorie **Proxy** hors `app_ctrl_whitelist` → élevé (possible outil de contournement).
    - Whitelist `app_ctrl_whitelist` dans `config.yaml` : exclut `proxy-safebrowsing.googleapis.com`
      (Safe Browsing Apple/Google — tunnel CONNECT légitime, classé "critical" à tort par FortiGate).
11. **Brute-force potentiellement réussi** (corrélation temporelle) : un login admin RÉUSSI
    précédé d'au moins `bruteforce.seuil_echecs` (défaut 5) échecs sur la **même IP OU le même
    compte** dans `bruteforce.fenetre_minutes` (défaut 60) → **critique** si source externe,
    **élevé** si interne. SUSPICION (helper `_bruteforce_success_mask`, recherche dichotomique
    numpy sur les timestamps d'échec). Vérifié : **0 alerte** sur vrais logs (aucune brèche ;
    l'admin interne avec 5 échecs étalés sur la journée n'est pas un faux positif).
12. **Horaires inhabituels** : login admin RÉUSSI hors plage ouvrée (`horaires_ouvres.debut`/
    `fin`, défaut 7h-20h) ou le week-end (`alerte_weekend`) → **faible** (SUSPICION
    comportementale, tunable). Vérifié sur vrais logs : remonte les connexions adminA
    de ~06h45 (avant 7h) — visible sans être alarmant.

## Comparaison (`compare.py`)
- Agrégats par **jour** (défaut) ou **heure**.
- **Rafales** : fenêtre glissante (défaut 60 min), seuil **adaptatif** (≥ facteur ×
  médiane) ou fixe, paramétrable.
- **Différentiel** apparu/disparu/persistant sur 6 entités (Prio 1→3) ; les
  entités Prio 3 (IP d'attaque, noms ciblés — fort renouvellement) sont
  **résumées en compteurs**, pas listées.

## Corrélation temporelle / chaînes IoC (`correlate.py`)
- Reconstitue la **séquence ordonnée** `ACCES → COMPTE → EXFILTRATION` par un
  même **acteur** (`user`) OU une même **IP** dans une fenêtre de N min (config
  `correlation.fenetre_minutes`, défaut 60). Sortie : feuille « Chaines suspectes ».
- Étapes dérivées de la **sémantique du log** (`logdesc`/`action`/`cfgpath`), pas
  du libellé de règle → déduplique les lignes flaggées par 2 règles.
- **IP effective** : `srcip` si présent, sinon IP extraite du champ `ui`
  (`GUI(x.x.x.x)`) — indispensable car les events de config n'ont pas de `srcip`.
- **Garde-fou anti-bruit** : le maillon ACCÈS ne démarre une chaîne que s'il est
  **anormal** (sévérité ≠ info : login externe/hors-réf., VPN hors-réf.). Un login
  admin interne connu de routine ne déclenche aucune chaîne (vérifié sur vrai T1).
- **Garde-fou directeur** : une chaîne est une **corrélation temporelle**, jamais
  une preuve. Libellé « À CONFIRMER » dans rapport, Excel et UI.
- Séquence requise paramétrable (`correlation.sequence_requise`).

## Enrichissement géo/ASN (`geo.py`, P6.1)
- **100 % hors-ligne**, aucune requête réseau, aucune dépendance ajoutée (csv/bisect/ipaddress).
- **Portée** (`srcip_portee` : interne/externe/réservé) calculée SANS base, depuis `plages_internes`.
- **Géo/ASN** (`srcip_pays`/`srcip_asn`/`srcip_org`) seulement si bases locales fournies via
  `config.yaml` (`geo_db_path` = DB-IP Lite Country CSV ; `asn_db_path` = iptoasn ip2asn-v4.tsv).
  Formats à plages d'entiers, recherche dichotomique. **License-clean** (CC-BY / domaine public) ;
  **ne PAS bundler MaxMind GeoLite2** (EULA + compte requis).
- **Dégradation honnête** : base absente/illisible → colonnes géo vides + mention explicite,
  jamais de pays/ASN inventé. La portée reste calculée.
- **Top sources externes** : classe les IP externes par volume (surface les brute-force
  `name_invalid` que R2 ne signale pas). **Exclut l'infrastructure connue** (WAN/mgmt des
  boîtiers, peers IPsec/DNS légitimes) pour ne pas polluer avec des IP externes légitimes.
- **Garde-fou directeur** : la géo est du **contexte**, ni preuve ni absolution.

## Listes de réputation / threat intel (`geo.py`, ReputationDB)
- Listes d'IP malveillantes connues **hors-ligne** (`reputation_lists` : `[{nom, path}]`),
  format CIDR/`.netset`/`.ipset` (FireHOL, abuse.ch…). `RangeTable.from_cidr_file` réutilise
  le moteur de plages de la géo. **License-clean uniquement.**
- `reputation_sources(full,…)` → table « IP malveillantes » (feuille Excel + section rapport) ;
  `enrich_events` ajoute la colonne `srcip_reputation`.
- **Garde-fou critique** : matching **EXTERNE uniquement**. Les listes type FireHOL incluent les
  **bogons** (10/8, 192.168/16…) → matcher une IP interne serait un faux positif (bug réel
  rencontré et corrigé : l'admin interne 10.10.1.62 matchait FireHOL via 10/8).
- **Garde-fou directeur** : présence en liste = **signal fort mais À CONFIRMER** (listes larges,
  datées, CGNAT/cloud partagés). Vérifié : **4 455 IP attaquantes** des vrais logs sont dans
  FireHOL L1, 0 faux positif interne.

## Échappements (`parse.py`, P4.1)
- Valeur quotée : motif `("(?:\\.|[^"\\])*"|\S*)` (linéaire, pas de backtracking).
  Déséchappe `\"`→`"` et `\\`→`\`. **Préserve l'alignement des champs APRÈS `msg`**
  (critique pour app-ctrl où `apprisk`/`scertcname` suivent `msg`).
- Vérifié sur 806 064 lignes réelles : 0 anomalie, ~67k lignes/s.

## Rattachement boîtier (point délicat)
Les exports ne contiennent pas de `devname`. Boîtier déduit par **IP** (WAN/mgmt).
Pour les logs sans IP du boîtier (event/user, event/vpn, traffic/forward), un
**indice par nom de fichier** (`fichiers_boitier` dans `config.yaml`) sert de
repli. Sinon : `inconnu` — comportement volontaire, **ne pas** deviner.
Règle VPN : les utilisateurs VPN viennent d'**IP résidentielles dynamiques** → la
référence stable est **user + groupe + pool**, jamais l'IP. La détection « source
externe » ne s'applique qu'aux accès **admin**.

## Types de logs reconnus (`ingest.py`)
- **Avec règles de détection** : `event/system`, `event/user`, `event/vpn`, `traffic/local`,
  `traffic/forward`, `utm/app-ctrl`.
- **Reconnus, sans règles dédiées** (`UTM_NO_RULES`) : `utm/ips`, `utm/webfilter`, `utm/dns`,
  `utm/antivirus`, `utm/waf` → parsing générique + marquage "(UTM reconnu, sans règles dédiées)".
- **Bilan hardening** : `event/security-rating` → intégré au rapport texte uniquement
  (pas une détection de compromission).
- **Inconnu** : tout autre type → parsing générique + marquage "(NON RECONNU)".

## État vérifié (tests réellement passés)
- **Suite pytest : 158 tests rapides + 8 tests sur vrais logs** (`pytest -m "not slow"` / `pytest -m slow`).
- **Comparaison config** vérifiée sur vrais .conf : 127 écarts T1↔T2 ; attribution réelle
  (ex. « AdminHMBM modifié par AdminLGS le 2026-06-22 11:26 ») ; hashs masqués.
- **Rapport de synthèse** vérifié sur vrai T1 : relie GUI exposée WAN ↔ 128 422 échecs de login
  ↔ 4 472 IP en réputation, conclut « aucune compromission avérée » (aucun brute-force abouti).
- **Audit .conf** : sur les vrais backups, 0 admin hors référentiel ; 3 admins sans trusthost +
  GUI/SSH exposé sur WAN (constats réels, expliquent la surface d'attaque du brute-force).
- **R11 brute-force réussi** : 0 alerte sur vrais logs (aucune brèche externe ; admin interne
  non faux-positivé). Fixtures : 6 échecs→succès externe = critique ; 2 échecs = rien.
- **Threat intel** : 4 455 IP attaquantes des vrais logs présentes dans FireHOL L1 ; bug du
  bogon interne (10.10.1.62 via 10/8) rencontré puis corrigé (matching externe uniquement).
- **P4.1 échappements** : `user="\\"` (brute-force SSH réel) → un backslash, champs suivants alignés ;
  guillemet littéral dans `msg` d'une ligne app-ctrl → `apprisk` toujours aligné. 806k lignes OK.
- **P6.1 géo** : sur vraies données T2, 85.11.187.120 → GB / AS60068 DATACAMP-LTD, 4907 logins
  échoués ; plages hors base → vides (pas d'invention) ; WAN propre du boîtier exclu du classement.
- Parsing quoté avec espaces ; détection auto de type + dégradation propre sur inconnu.
- Déduplication : 42 353 doublons retirés sur des exports réels qui se chevauchent.
- Détection **positive** : scénario de compromission → 3 critiques + 4 élevés + 1 moyen.
- **R10 (app-ctrl)** : UltraSurf bloqué → élevé ; TunnelBear critique non-WL → moyen+élevé ;
  `proxy-safebrowsing.googleapis.com` whitelisté → **0 alerte** (vérifié sur 40 000 lignes réelles T1).
- **Corrélation** : scénario remonté comme **1 chaîne complète** (ACCES→COMPTE→EXFIL,
  critique) ; **0 chaîne** sur logs bénins ET sur activité admin légitime (login
  interne + changement mdp + download logs en fenêtre) ; **0 chaîne** sur le vrai
  fichier event/system T1.
- **Zéro faux positif** sur logs bénins (brute-force échoué non confondu avec comptes voyous).
- Échelle : 118 Mo / 287 133 événements en 73 s, pic 1,05 Go RAM.
- **Validation config** : config invalide → message explicite + arrêt (exit 1) ;
  config valide → RAS. Vérifie CIDR, IP, regex, seuils, clés requises.

## Limites connues (documentées, à ne pas masquer)
- **Mémoire ≈ 9× la taille d'entrée** ; ~380 Mo cumulés saturent un environnement
  contraint → recommander le traitement par batch (jour/boîtier) en attendant P5.
- **Excel ~1 048 576 lignes** : feuille « Données unifiées » tronquée
  (`max_lignes_donnees_unifiees`, défaut 200 000) ; agrégats/détections sur la
  **totalité** des données.
- Persistance par automation : le type d'action (`cli-script`/`webhook`) n'est pas
  dans l'event log → vérification en configuration requise.
- **Géo/ASN** : qualité = celle de la base locale fournie ; sans base, seule la portée
  interne/externe est disponible. IPv6 → portée seulement (géo/ASN à enrichir plus tard).

## Règles pour toute évolution
1. Tester sur de **vrais** logs avant de déclarer fonctionnel.
2. Préserver le **CLI** et l'API `run(...)`.
3. Mettre à jour `README.md` et ce `CLAUDE.md`.
4. Ajouter des tests pytest (non-régression) — voir le plan dans le prompt de mission.
5. Ne jamais affaiblir les **garde-fous** (signaler sans conclure ; marquer les
   suspicions ; dégrader proprement sur type inconnu ; ne rien inventer).
6. **Demande-moi de clarifier, n'invente rien et ne code pas sans mon aval.**
