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
│   ├── common.py    # constantes/helpers partagés : SEV_ORDER, CFG_ACCOUNT_PATHS, str_col
│   ├── parse.py     # parse_line : clé=valeur, valeurs quotées + échappements Fortinet (\" \\)
│   ├── ingest.py    # list_log_files + detect_type ; load_file (parsing colonnaire,
│   │                #   ANALYSIS_COLS) + load_columns_for_rows (2e passe colonnes d'affichage)
│   ├── normalize.py # build_timestamp, assign_boitier (par IP + indice fichier), deduplicate
│   ├── detect.py    # run_detection VECTORISÉE (masques pandas) -> événements + sévérité
│   ├── compare.py   # aggregate (jour/heure), detect_bursts (adaptatif), diff_entities (6 entités)
│   ├── correlate.py # correlate_chains : chaînes IoC ordonnées (accès→compte→exfil) par acteur/IP
│   ├── geo.py       # enrichissement géo/ASN HORS-LIGNE + portée + top sources + réputation
│   ├── confaudit.py # parse + audit de compromission des .conf FortiGate (comptes, accès, automation)
│   ├── confdiff.py  # comparaison 2 .conf (ajout/suppr/modif) + attribution qui/quand via logs ; CLI
│   ├── confgen.py   # génère un config.yaml (BROUILLON) depuis des .conf (référentiel dérivé) ; CLI
│   ├── fetch_fortinet_ranges.py # GÉNÉRATION (réseau) : plages IP Fortinet via ARIN -> .netset ; CLI
│   ├── analysis.py  # build_analysis : rapport de SYNTHÈSE (décrit/explique, [AVÉRÉ]/[À CONFIRMER])
│   ├── report.py    # build_report (texte détaillé) + rappel des limites
│   ├── excel.py     # write_workbook (xlsxwriter, 12 feuilles, « Rapport » en 1re)
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
- Accès : (1) outil dédié `python -m fortilog.confdiff ref.conf actuel.conf [--logs DIR] [--all]`
  + section « 🔁 Comparer deux configurations » dans l'UI ; (2) **intégré à l'analyse générale** :
  `run(..., ref_conf=...)` / `--ref-conf` / dépôt « config de référence » dans Streamlit → compare
  les `.conf` du dossier à la référence (attribution via les logs chargés), table `config_diff`
  → feuille « Comparaison config » + section rapport + **synthèse globale** (`analysis`).
- Garde-fou : un écart de config n'est pas une compromission (à confirmer).

## Rapport de synthèse (`analysis.py`)
- Décrit les résultats et **explique** les problèmes, en distinguant **[AVÉRÉ]** (état de
  config, volumes de logs) de **[À CONFIRMER]** (compte hors référentiel, chaîne, nom voyou).
- **Lecture d'ensemble** : relie les constats (GUI exposée sur WAN ↔ volume de brute-force ↔
  IP en réputation) et conclut explicitement « aucune compromission avérée » quand c'est le cas
  (jamais de conclusion non prouvée). Data-driven (compte les sévérités, règles, IP, échecs…).
- **Détail par section** : §2 (config) groupe les constats **par règle** et détaille, SOUS chaque
  règle, ses constats individuels (détail confaudit + boîtier) ; §3 (events) et §4 (IP externes/
  réputation) listent les lignes les plus sévères. Nombre réglable via `rapport.max_constats`
  (config.yaml, défaut 5 ; au-delà : « … et N autres »). Le tag [À CONFIRMER] couvre tout libellé
  « — SUSPICION » (pas seulement « hors référentiel »/« voyou »).

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

## Génération du référentiel (`confgen.py`)
- **Amorce un `config.yaml`** depuis un ou plusieurs `.conf` : DÉRIVE le référentiel
  (admins via `system admin`/`sso-admin` ; `plages_internes` via interfaces role lan/dmz ;
  `boitiers.wan` via role wan ; `mgmt` HEURISTIQUE → marqué « à vérifier » ; `utilisateurs_locaux`
  via `user local` ; `groupes_vpn_legitimes` via `vpn ssl settings`/authentication-rule ;
  `utilisateurs_vpn_actifs` = membres ∩ users locaux ; `destinations_legitimes` via phase1
  `remote-gw` + `system dns`). Les **paramètres** (rafales, seuils, regex, géo…) = **défauts**.
- **Ne devine rien d'autre, n'extrait aucun secret.** Le fichier produit est un **BROUILLON à relire**.
  Réutilise le parseur de `confaudit`. Sortie passe `validate_config`.
- Accès : CLI `python -m fortilog.confgen FW-T1.conf [FW-T2.conf ...] [-o config.generated.yaml] [--force]`
  (refuse d'écraser sans `--force`) + section Streamlit « 🧩 Générer un référentiel ».
  `config.generated.yaml` est gitignored (vraies valeurs) ; à relire puis renommer en `config.local.yaml`.

## Conventions
- **Lancement CLI :** `python -m fortilog.main --input ./logs --config config.yaml --output ./rapport`.
- **API stable :** `fortilog.main.run(input_dir, config_path, output_dir) -> (tables, meta)`.
  Toute UI doit s'appuyer dessus, pas réimplémenter la logique.
- **Référentiel = `config.yaml`**, jamais en dur dans le code. Valeurs actuelles
  vérifiées sur les exports réels (boîtiers par IP, admins connus, utilisateurs
  VPN/locaux, groupes VPN, plages internes, destinations légitimes, motifs de
  comptes suspects, paramètres de rafale).
- **Dépendances :** pandas, xlsxwriter, pyyaml, openpyxl.

## Règles de détection implémentées (`detect.py`, 15 règles)
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
   Exclusions automatiques : IP WAN propres des boîtiers, `destinations_legitimes`
   (IP **ou CIDR**), et **toutes les plages Fortinet** (FortiGuard/FortiCloud/FortiSASE)
   par DEUX mécanismes complémentaires : (A) fichier statique `fortinet_ranges_file`
   (énumération ARIN par propriété — capte les anycast hébergés chez AWS, invisibles d'un
   filtre ASN) ; (B) org ASN « FORTINET » au runtime via la base iptoasn (`enricher` passé
   à `run_detection`). Régénérer (A) : `python -m fortilog.fetch_fortinet_ranges`.
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
- **Suite pytest : 160 tests rapides + 8 tests sur vrais logs** (`pytest -m "not slow"` / `pytest -m slow`).
- **Comparaison config** vérifiée sur vrais .conf : 127 écarts T1↔T2 ; attribution réelle
  (ex. « adminB modifié par adminA le 2026-06-22 11:26 ») ; hashs masqués.
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
- **Mémoire (P5 phase 1+2 faite)** : parsing colonnaire + frame d'analyse restreint à
  `ANALYSIS_COLS` (colonnes d'affichage relues en 2e passe pour la seule feuille unifiée).
  Pic mesuré sur vrais logs T1 (392 541 lignes) : **2424 → 1599 Mo (−34 %)**, sorties
  identiques. Reste à attaquer si besoin : transitoires de `detect` (densification des
  colonnes `category` par `str_col`, copies par règle) et le chunking par lot.
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

---

## TODO / Backlog (validé 2026-07-02, à implémenter dans cet ordre)

Chaque item ci-dessous est spécifié pour être codé tel quel. Règles transverses,
valables pour TOUS les items : respecter les garde-fous du projet (signaler sans
conclure, [À CONFIRMER] sur toute suspicion, ne rien inventer, dégradation honnête),
préserver l'API `run(input_dir, config_path, output_dir, ref_conf=None) -> (tables, meta)`
et le CLI existant, tout nouveau paramètre va dans `config.yaml` avec un défaut
rétro-compatible + validation dans `validate.py` + doc README, tout nouveau code a ses
tests pytest rapides (fixtures synthétiques) et, si pertinent, un test @slow sur vrais
logs (chemins via env `FORTILOG_LOGS_T1`/`FORTILOG_LOGS_T2`, skip propre si absents).
Une PR par item (ou par sous-groupe cohérent), CI verte avant merge.

### P1a — Feuille « Acteurs à risque » — ✅ FAIT (PR #11 mergée le 2026-07-07, module actors.py)
**Pourquoi** : les sorties actuelles sont des listes plates d'événements ; l'auditeur
veut d'abord « les 5 entités à investiguer ». **Quoi** : un nouveau module
`fortilog/actors.py` avec `build_actors(events, full, meta, cfg) -> pd.DataFrame`,
appelé depuis `main.run()` après l'enrichissement géo/réputation.
- **Agrégation** : deux axes concaténés dans la même table, colonne `acteur_type`
  (`ip` | `compte`). Pour chaque IP source externe apparaissant dans `events` et pour
  chaque `user` apparaissant dans `events` : nb d'événements par sévérité (colonnes
  `n_critique/n_eleve/n_moyen/n_faible/n_info`), nb de règles distinctes déclenchées,
  sévérité max, `premiere_vue`/`derniere_vue` (min/max timestamp), volume total
  d'échecs de login associés (depuis `full` : `logdesc` échec + même srcip/user),
  `pays`/`asn`/`org` (colonnes déjà présentes sur events si géo dispo, sinon vides),
  `reputation` (colonne `srcip_reputation`), `boitiers` touchés (liste jointe par « , »).
- **Score** : transparent et documenté DANS le code et le README — somme pondérée
  affichable : `score = 100*n_critique + 30*n_eleve + 10*n_moyen + 3*n_faible
  + 50*(reputation non vide) + 20*(nb_regles_distinctes - 1)`. Le score sert à TRIER,
  jamais à conclure ; libellé de colonne : `score_priorisation (tri, pas un verdict)`.
  Pondérations dans `config.yaml` (`acteurs.poids: {critique: 100, eleve: 30, moyen: 10,
  faible: 3, reputation: 50, regle_supplementaire: 20}`) avec ces défauts.
- **Bornage** : top `acteurs.max_lignes` (défaut 100) après tri décroissant.
- **Sorties** : table `tables["acteurs"]` → nouvelle feuille Excel « Acteurs à risque »
  (insérée après « Evenements signales »), section dans `analysis.py` (top 5 avec le
  détail des composantes du score) et onglet Streamlit. Exclure les IP d'infrastructure
  connue (WAN/mgmt boîtiers, peers/DNS — réutiliser l'exclusion de `geo.top_external_sources`).
- **Tests** : fixtures avec 2 IP (une multi-règles + réputation, une mono-règle) →
  ordre du tri, composantes exactes du score, exclusion infra, table vide si 0 événement.

### P1b — Timeline des événements critiques — ✅ FAIT (PR #11 mergée le 2026-07-07, actors.build_timeline, section 3ter du rapport)
**Pourquoi** : le rapport corrèle mais ne raconte pas *quand*. **Quoi** : fonction
`build_timeline(events, cfg) -> pd.DataFrame` (dans `analysis.py` ou `actors.py`) :
événements de sévérité ≥ `timeline.severite_min` (défaut `eleve`), triés
chronologiquement, colonnes `timestamp, boitier, severite, regle, acteur (user ou srcip),
detail`. Regrouper les rafales : si > `timeline.max_par_groupe` (défaut 3) événements
consécutifs de même (règle, acteur) dans la même heure, les résumer en une ligne
« × N similaires de HH:MM à HH:MM » (ne jamais perdre le compte exact).
- **Sorties** : section « FRISE CHRONOLOGIQUE » dans le rapport texte (format
  `JJ/MM HH:MM [SEVERITE] règle — acteur — détail`), même contenu dans l'onglet
  Streamlit « Rapport ». PAS de nouvelle feuille Excel (la feuille événements triée
  existe déjà) sauf demande ultérieure.
- **Tests** : ordre chronologique, filtre de sévérité, regroupement de rafale exact
  (compte préservé), vide si aucun événement ≥ seuil.

### P2 — Suivi entre analyses : état persistant + acquittement — ✅ FAIT (PR #12 mergée le 2026-07-07, suivi.py + ack.py)
**Pourquoi** : les diffs actuels sont intra-run ; rien ne permet de dire « quoi de neuf
depuis la dernière analyse » ni d'acquitter un faux positif. **Quoi** : nouveau module
`fortilog/suivi.py`.
- **Identité stable d'un constat** : `constat_id = sha256` tronqué à 16 hex de la
  concaténation normalisée `regle|boitier|acteur|champ_discriminant` — PAS le timestamp
  ni le volume (un même brute-force sur 2 jours = même constat). Champ discriminant par
  famille : événements → `user+srcip` ; audit config → `code C1-C6 + objet` ; diff
  config → `section+objet`. Documenter le choix dans le module.
- **Fichier d'état** : `etat_suivi.json` dans le dossier `--output` (chemin surchargeable
  par `--etat PATH`). Structure : `{version: 1, analyses: [{date, n_constats}], constats:
  {id: {premiere_vue, derniere_vue, statut, regle, resume}}}`. `statut` ∈
  `nouveau | connu | acquitte`. JSON lisible/éditable à la main (tri des clés, indent 2).
- **Cycle** : au début de `_emit()`, charger l'état s'il existe ; marquer chaque constat
  courant `nouveau` (jamais vu) ou `connu` ; les constats `acquitte` restent signalés
  mais avec le tag `[ACQUITTÉ le JJ/MM/AAAA]` et sont EXCLUS du décompte d'alerte de la
  synthèse (jamais supprimés : l'outil ne cache rien). Réécrire l'état en fin de run.
- **Acquittement** : sous-commande CLI `fortilog-ack` (nouveau point d'entrée
  `fortilog/ack.py`, console-script dans `pyproject.toml`) : `fortilog-ack --etat PATH
  --list` (table des constats + id + statut) et `fortilog-ack --etat PATH ID [ID…]
  [--motif "texte"]` (bascule en `acquitte`, motif stocké). Pas d'UI Streamlit pour
  l'acquittement dans un premier temps (lecture seule : badge « nouveau/connu/acquitté »
  sur l'onglet événements).
- **Rapport** : la synthèse (`analysis.py`) ouvre par « X constats dont Y NOUVEAUX
  depuis l'analyse du JJ/MM » quand un état antérieur existe ; sans état antérieur,
  aucune mention (comportement actuel inchangé).
- **Garde-fous** : jamais de suppression silencieuse — un constat acquitté reste visible
  avec son tag ; le fichier d'état absent/corrompu → warning explicite + run normal
  sans suivi (dégradation honnête).
- **Tests** : run 1 → tous `nouveau` ; run 2 mêmes fixtures → tous `connu` ; ack d'un id
  → tag présent + exclu du décompte ; état corrompu → warning + run OK ; stabilité de
  `constat_id` (même entrée = même id, timestamp différent = même id).

### P3a — Fraîcheur des bases géo/ASN/réputation — ✅ FAIT (PR #13 mergée le 2026-07-07, module bases.py)
**Quoi** : à chaque run, calculer l'âge (mtime) de chaque fichier de base utilisé
(`geo_db_path`, `asn_db_path`, chaque entrée de `reputation_lists`,
`fortinet_ranges_file`). Stocker dans `meta["bases"]` : `[{nom, path, age_jours}]`.
- **Seuil** : `bases.age_max_jours` (défaut 90) dans `config.yaml`. Au-delà →
  avertissement en tête de la synthèse (`analysis.py`) : « ⚠ La base X a N jours —
  les correspondances peuvent être obsolètes » + même mention dans la feuille
  « Referentiel » et l'UI. JAMAIS bloquant.
- **Tests** : base récente → pas de mention ; base vieillie (mtime forcé par
  `os.utime`) → mention exacte ; base absente → comportement actuel inchangé.

### P3b — Règle R13 : rafale d'échecs `name_invalid` par IP — ✅ FAIT (PR #10 mergée le 2026-07-07)
NB implémentation : déclenchement au seuil par fenêtre, puis fusion des fenêtres contiguës
(un événement par (IP, rafale CONTINUE), sinon 4075 événements sur T2 au lieu de 191).
La campagne T1 est un spray distribué (~12 échecs/h max par IP) → R13 silencieux par
conception sur T1 ; le test @slow pointe sur T2 (memory-event-system-2026_06_29).
**Pourquoi** : R2 ne couvre que `passwd_invalid` ; les campagnes sur comptes inexistants
ne sont visibles que via « Sources externes », sans sévérité ni entrée dans le score P1a.
**Quoi** : dans `detect.py`, nouvelle règle vectorisée : pour chaque IP source, compter
les `Admin login failed` avec `reason == "name_invalid"` dans une fenêtre glissante de
`bruteforce_name_invalid.fenetre_minutes` (défaut 60) ; si ≥ `seuil_echecs` (défaut 20 —
plus haut que R11 car aucun compte valide n'est en jeu), émettre UN événement par
(IP, fenêtre) — pas un par ligne (sinon 128k lignes → 128k événements) : prendre la
ligne du premier échec de la rafale comme porteuse, détail
`« N tentatives name_invalid depuis srcip entre HH:MM et HH:MM, M comptes distincts »`.
Sévérité : `moyen` si IP externe, `faible` si interne. Libellé avec « (SUSPICION) » —
c'est du bruit d'Internet dans la majorité des cas ; l'intérêt est le VOLUME et l'entrée
au score acteur. Implémentation : réutiliser l'approche `searchsorted` de
`_bruteforce_success_mask` (groupby IP, timestamps triés, fenêtre glissante).
- **Tests** : 25 échecs name_invalid même IP en 30 min → 1 événement (pas 25), compte
  et bornes horaires exacts dans le détail ; 5 échecs → rien ; passwd_invalid n'entre
  pas dans R13 (déjà couvert par R2) ; @slow sur vrais logs T1 : la campagne massive
  connue remonte en un nombre raisonnable d'événements (< 1000).

### P3c — Mapping MITRE ATT&CK des règles — ✅ FAIT (PR #10 mergée le 2026-07-07, ID vérifiés sur attack.mitre.org)
**Quoi** : dans `common.py`, dict statique `MITRE_MAP = {libellé_ou_prefixe_de_regle:
"Txxxx — nom technique"}` couvrant R1-R13 : R1/R11 → T1078 (Valid Accounts) + T1110
(Brute Force) pour R2/R11/R13, R3 → T1133 (External Remote Services), R4/R5 → T1136
(Create Account), R6 → T1005/T1567 (Data from Local System / Exfiltration Over Web),
R7 → T1053 (Scheduled Task/Job — automation), R8 → T1571/T1041 (Non-Standard Port /
Exfil Over C2), R9 → T1021 (Remote Services), R10 → T1090 (Proxy), R12 → T1078
(anomalie d'usage de compte valide). VÉRIFIER chaque ID sur attack.mitre.org avant de
figer (ne pas faire confiance à cette liste de mémoire). Colonne `mitre` ajoutée aux
événements dans `run_detection()` (map sur `regle`, vide si pas de correspondance),
reprise dans la feuille Excel « Evenements signales » et l'export. Une ligne en légende
du README : le mapping est indicatif (aide au reporting), pas une attribution.
- **Tests** : chaque règle des fixtures porte un `mitre` non vide et au format
  `T\d{4}( — .+)?` ; règle inconnue → champ vide (pas d'erreur).

### P4 — Correctifs courts — ✅ FAIT (PR #9 mergée le 2026-07-07)
1. **Pool VPN en dur** (`detect.py` : `vpn_net = [ipaddress.ip_network("10.212.134.0/24")]`)
   → nouvelle clé `pool_vpn` dans `config.yaml` (défaut `10.212.134.0/24` si absente,
   rétro-compatible), validée par `validate.py` (CIDR), utilisée par R9. Mettre à jour
   le config.yaml versionné (valeur anonymisée actuelle) + confgen (dériver le pool
   depuis `vpn ssl settings` → `tunnel-ip-pools` si présent dans le .conf, sinon défaut).
2. **R1 avec `srcip` vide** : un login admin réussi SANS srcip est aujourd'hui classé
   « externe → critique » (une chaîne vide n'est pas interne). Corriger : les lignes
   `srcip == ""` sortent du masque « externe » et reçoivent leur propre libellé
   « Login admin réussi, source indéterminée (srcip absent) » sévérité `moyen`, jamais
   inventer une portée. Test : fixture login OK sans srcip → moyen/indéterminé, pas critique.
3. **Diff multi-boîtiers** (`main.py` : seuls les 2 premiers boîtiers de `unique()` sont
   comparés, ordre non déterministe) : comparer TOUTES les paires de boîtiers connus
   (ordre alphabétique, `itertools.combinations`) — avec 2 boîtiers le comportement est
   identique à l'actuel. Test : 3 boîtiers synthétiques → 3 paires comparées, ordre stable.

### P5 — Fil de l'eau (chacun autonome, prendre dans l'ordre au choix)
1. **Agrégats descriptifs UTM sans règles** — ✅ FAIT (PR #14 mergée le 2026-07-07,
   module utm_stats.py) : pour `utm/ips`, `utm/webfilter`, `utm/dns`,
   `utm/antivirus` présents dans les logs, ajouter au tableau de bord (feuille « Tableau
   de bord » + section rapport) des top-N PUREMENT DESCRIPTIFS : top signatures/attaques
   (ips : champs `attack`/`severity`), top domaines/catégories bloqués (webfilter :
   `hostname`/`catdesc`/`action`), top verdicts (antivirus). AUCUNE sévérité, aucune
   détection — description marquée « (descriptif, sans règle d'alerte) ». Ne s'appuyer
   QUE sur des champs réellement présents dans les fichiers fournis ; champ absent →
   omettre la ligne (ne rien inventer). Tests avec fixtures minimales par type.
2. **Nouveauté comportementale par compte admin** — ✅ FAIT (PR #15 mergée le 2026-07-07,
   règles R14/R15 dans `detect.py`) : première IP source / premier pays jamais vu pour un
   compte admin sur la période analysée → info (SUSPICION comportementale). Sans l'état
   persistant P2, « jamais vu » = « pas vu plus tôt dans la MÊME analyse » (dit dans le
   libellé) ; branché sur l'état P2 (`etat_suivi.json`, clé `comptes_vus`, `premiere_vue`
   par couple compte×pays) quand il existe. *Impossible travel* (2 pays incompatibles <
   `comportement.fenetre_minutes`, défaut 60) → eleve (SUSPICION) — nécessite la géo ;
   sans base, la détection est silencieusement absente (mention dans la synthèse comme
   pour la géo).
3. **`RangeTable` dans detect.py** : remplacer `_load_cidr_networks` + `_internal_map`
   sur `fortinet_ranges_file` (O(IP×réseaux)) par `geo.RangeTable.from_cidr_file`
   (dichotomie, déjà testé). Comportement identique attendu — vérifier par test A/B sur
   fixtures (mêmes IP exclues) ; garder `_internal_map` pour `plages_internes` (peu de
   réseaux, pas le point chaud).
4. **Sorties machine + ergonomie CLI** : options `--json DIR` (chaque table en
   `<nom>.json` orient="records", dates ISO) et `--csv DIR` (idem en .csv UTF-8) SANS
   changer les sorties actuelles ; code retour du CLI = 0 (rien ≥ eleve), 1 (au moins
   un eleve), 2 (au moins un critique) — documenté dans README pour usage cron/CI, et
   NE PAS casser les tests existants qui appellent `run()` (le code retour vit dans
   `main()` seulement) ; `--quiet` (supprime le print du rapport, garde les fichiers) ;
   progression pendant l'ingestion : une ligne par fichier `« fichier N/M : nom (X
   lignes) »` sur stderr, désactivée par `--quiet`.
5. **P5 mémoire phase 3** (uniquement si un besoin réel > 600 Mo apparaît) : réduire les
   transitoires de `detect.run_detection` — `flag()` copie chaque sous-frame et `str_col`
   densifie les colonnes `category` ; piste : ne matérialiser que les colonnes utiles au
   détail dans `flag()`, et/ou chunking par lot avec fusion des événements. Mesurer
   avant/après sur vrais logs T1 (procédure : pic RSS, sorties identiques — cf. P5
   phases 1+2).
6. **UI Streamlit** : filtres persistants (sévérité, boîtier, règle, plage de dates)
   sur l'onglet événements via `st.session_state`, + bouton « télécharger la sélection
   filtrée » (CSV). Logique de filtrage dans `ui_helpers.py` (testable hors UI).
