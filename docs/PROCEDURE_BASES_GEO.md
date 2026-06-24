# Procédure — Bases géo/ASN hors-ligne (P6)

Active l'enrichissement **pays + ASN** des IP externes dans `fortilog`. Tout est
**hors-ligne** : on télécharge deux fichiers une fois, on indique leur chemin dans
`config.yaml`. Sans ces bases, l'outil fonctionne quand même (portée interne/externe
seule). La géo est du **contexte**, jamais une preuve.

> **Licences (à respecter) :**
> - **DB-IP IP-to-Country Lite** — CC-BY-4.0 → attribution obligatoire (voir §5).
> - **iptoasn ip2asn** — libre d'usage (attribution appréciée).
> - **Ne PAS utiliser MaxMind GeoLite2** : EULA + compte requis, non redistribuable.

---

## 1. Choisir un emplacement

Par convention, un sous-dossier du projet (à adapter) :

```bash
mkdir -p /path/to/fortilog/data/geo
cd /path/to/fortilog/data/geo
```

Les fichiers sont volumineux (~5–7 Mo compressés) : ne pas les committer si le projet
est versionné (ajouter `data/geo/` à `.gitignore`).

---

## 2. Télécharger la base PAYS (DB-IP Lite, mensuelle)

Page officielle (lien du mois en cours) :
**https://db-ip.com/db/download/ip-to-country-lite**

Téléchargement direct (adapter `AAAA-MM` au mois courant, ici 2026-06) :

```bash
curl -L -o dbip-country-lite.csv.gz \
  https://download.db-ip.com/free/dbip-country-lite-2026-06.csv.gz
gunzip -f dbip-country-lite.csv.gz
# -> dbip-country-lite.csv
```

Format attendu (sans en-tête) : `ip_debut,ip_fin,code_pays`
```
1.0.0.0,1.0.0.255,AU
85.11.0.0,85.11.255.255,GB
```
> Le fichier mélange IPv4 et IPv6 ; `fortilog` ne lit que l'IPv4 (les lignes IPv6 sont
> ignorées sans erreur). Cohérent avec la limite IPv6 documentée.

---

## 3. Télécharger la base ASN (iptoasn, IPv4)

Page officielle : **https://iptoasn.com/**

Téléchargement direct (URL stable) :

```bash
curl -L -o ip2asn-v4.tsv.gz https://iptoasn.com/data/ip2asn-v4.tsv.gz
gunzip -f ip2asn-v4.tsv.gz
# -> ip2asn-v4.tsv
```

Format attendu (TSV, sans en-tête) : `ip_debut <TAB> ip_fin <TAB> ASN <TAB> pays <TAB> organisation`
```
85.11.0.0	85.11.255.255	60068	GB	DATACAMP-LTD
```

---

## 4. Renseigner `config.yaml`

Mettre les **chemins absolus** :

```yaml
geo_db_path: data/geo/dbip-country-lite.csv
asn_db_path: data/geo/ip2asn-v4.tsv
top_sources_externes: 50
```

(Laisser `null` désactive l'enrichissement ; la portée interne/externe reste calculée.)

---

## 5. Vérifier sur les vrais logs

```bash
cd /path/to/fortilog
python -m fortilog.main --input /path/to/logs/Log_T2 \
  --config config.yaml --output ./rapport
```

Dans le rapport, la section **TOP SOURCES EXTERNES** doit afficher un pays/ASN, p.ex. :
```
85.11.187.120 [GB / 60068 / DATACAMP-LTD] : 4907 occ. (4907 logins échoués)
```
La feuille Excel **« Sources externes »** porte les colonnes `srcip_pays/asn/org`.

Vérification ciblée sans lancer toute l'analyse :
```bash
python -c "from fortilog import geo; e=geo.load_enricher({'geo_db_path':'data/geo/dbip-country-lite.csv','asn_db_path':'data/geo/ip2asn-v4.tsv'}); print('base active:', e.available); print(e.lookup('85.11.187.120'))"
```

---

## 6. Mise à jour

- **DB-IP pays** : nouvelle version **chaque mois** → re-télécharger en bumpant `AAAA-MM`.
- **iptoasn ASN** : régénéré **chaque heure** ; un rafraîchissement mensuel suffit pour
  un usage d'audit (même URL, écrase le fichier).

Un simple script de refresh (à planifier si besoin) :
```bash
#!/bin/sh
cd /path/to/fortilog/data/geo || exit 1
MOIS=$(date +%Y-%m)
curl -fL -o dbip-country-lite.csv.gz "https://download.db-ip.com/free/dbip-country-lite-${MOIS}.csv.gz" && gunzip -f dbip-country-lite.csv.gz
curl -fL -o ip2asn-v4.tsv.gz "https://iptoasn.com/data/ip2asn-v4.tsv.gz" && gunzip -f ip2asn-v4.tsv.gz
```

---

## 6 bis. Listes de réputation (threat intel, optionnel)

Marque les IP sources présentes dans des **listes d'IP malveillantes connues**.

```bash
cd /path/to/fortilog/data/geo
# FireHOL Level 1 (CC-BY) — faible taux de faux positifs
curl -fL -o firehol_level1.netset \
  https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset
```

Format : un CIDR ou une IP par ligne, `#` = commentaire. Puis dans `config.yaml` :

```yaml
reputation_lists:
  - { nom: "FireHOL L1", path: data/geo/firehol_level1.netset }
```

> **Matching externe uniquement** : ces listes incluent les bogons (10/8, 192.168/16…) ;
> une IP interne n'est donc jamais signalée. Une présence en liste est un **signal fort
> mais À CONFIRMER** (listes parfois larges/datées). Sortie : feuille « IP malveillantes ».

## 7. Attribution (obligation DB-IP)

DB-IP Lite étant en **CC-BY-4.0**, toute diffusion d'un rapport s'appuyant sur cette
base doit mentionner, de façon visible :

> *IP Geolocation by DB-IP (https://db-ip.com)*

(Pour iptoasn, l'attribution n'est pas exigée mais reste courtoise.)
