# hermes-contamination

Plugin [Hermes Agent](https://github.com/NousResearch/hermes-agent) contre l'injection de prompt indirecte.
Vérifié sur Hermes `0d69d07b` (6 octobre 2026) et `v0.21.6`.

Une session qui a lu du contenu externe devient **contaminée** jusqu'à `/new`. En session contaminée :
- les lectures pures passent sans arrêt ;
- chaque action à effet s'arrête. Un explicateur (un LLM sur un endpoint dédié) dit en français ce qu'elle va faire, si elle correspond à ta demande, et donne un avis ;
- les cas flagrants sont bloqués sans question.

Une session propre se comporte exactement comme avant : aucune question, aucune latence.

## Ce que tu vois dans Matrix

La carte d'approbation native d'Hermes (✅ une fois, 🌀 session, ♾️ toujours, ❌ refuser) porte l'explication dans sa ligne « Why it was flagged » :

```
⚠️ Hermes wants to run a command that needs your OK
<terminal> (plugin approval rule)
Why it was flagged: ⚠️ Session exposée à du contenu externe (via web_extract : docs[.]python[.]org)
Ce que Hermes veut faire : modifie pyproject.toml pour viser Python 3.12 puis relance la compilation
Lien avec ta demande : oui — tu as demandé de réparer le build
Points d'attention : exécute une commande sur ta machine ; écrit : pyproject.toml
Avis : ACCEPTER (risque moyen) — cohérent avec ta demande
If you don't answer within 5 minutes it will NOT run.
```

Rien n'y est cliquable : URL, domaines et IP sont défangés (`hxxps://`, `[.]`), car un aperçu de lien peut faire fuiter des données.

## Installation (sur la machine Hermes)

1. Cloner le dépôt, puis copier le plugin dans le profil et l'activer :
   ```bash
   git clone https://github.com/leflakk/hermes-contamination.git ~/hermes-contamination
   ~/hermes-contamination/scripts/install.sh
   ```
   Pour un autre profil : `HERMES_HOME=~/.hermes/profiles/<nom> ~/hermes-contamination/scripts/install.sh`.
2. Configurer l'explicateur dans `~/.hermes/.env` (voir plus bas), puis redémarrer la passerelle : `hermes gateway restart`.
3. Vérifier l'intégration et l'endpoint (deux appels de test à l'explicateur) :
   ```bash
   hermes contamination doctor
   ```
4. Mettre à jour plus tard : `git -C ~/hermes-contamination pull && ~/hermes-contamination/scripts/install.sh`, puis redémarrer.

Pourquoi pas `hermes plugins install` : le scanner de sécurité d'Hermes lit les motifs de détection du plugin (`sudo`, `~/.ssh`, `/etc/sudoers`…) comme du code dangereux. Le verdict « dangerous » ne se force pas. Ce scanner ne tourne qu'à l'installation et à la mise à jour, jamais au chargement : la copie suivie de `hermes plugins enable` suffit, sans le désactiver. `hermes plugins validate` affichera le même faux positif.

## Explicateur

C'est un endpoint compatible OpenAI, sur une instance séparée (GPU 2), avec sa propre clé sans droits admin. Il doit servir un **modèle instruct différent du modèle principal**, de préférence sans phase de réflexion. Il se configure par variables d'environnement du processus Hermes :

| Variable | Rôle | Défaut |
|---|---|---|
| `CONTAMINATION_EXPLAINER_URL` | base `…/v1` ou URL complète `…/chat/completions` | — |
| `CONTAMINATION_EXPLAINER_KEY` | clé API | — |
| `CONTAMINATION_EXPLAINER_MODEL` | nom du modèle | — |
| `CONTAMINATION_EXPLAINER_TIMEOUT` | délai en secondes (toujours plafonné sous le délai des hooks) | 20 |
| `CONTAMINATION_EXPLAINER_JSON` | `schema` (response_format json_schema), `object`, `tabby` (champ `json_schema` de TabbyAPI), `none` | `schema` |
| `CONTAMINATION_EXPLAINER_MAX_TOKENS` | | 400 |
| `CONTAMINATION_EXPLAINER_USE_PROXY` | `1` pour passer par HTTP(S)_PROXY | ignoré |

Ce que l'explicateur reçoit :
- tes messages, demande initiale toujours en tête ;
- le registre des arrêts précédents de la session, avec la décision prise pour chacun ;
- les faits extraits par programme ;
- l'action (outil et arguments), traitée comme une donnée non fiable, avec les marqueurs de template neutralisés.

Il ne reçoit **jamais** de résultat d'outil. Sa sortie est validée strictement (résumé, lien, raison, risque, avis). Le risque final ne descend jamais sous le plancher fixé par les faits. Si l'appel échoue (délai, réponse invalide, endpoint injoignable), la carte montre les faits seuls et rien n'est accepté par défaut.

L'appel tient dans le délai des hooks : budget = `plugins.hook_callback_timeout` (30 s par défaut) − 4 s. C'est important, car un hook `pre_tool_call` qui dépasse ce délai bloque l'outil et fait suspendre le plugin pendant 60 s par Hermes.

## Règles

**Ce qui contamine** (un résultat d'outil reçu, même en erreur) :
- web (`web_search`, `web_extract`, `x_search`) et tous les outils `browser_*` ;
- MCP (`mcp__<serveur>__*`), sauf les serveurs de confiance ;
- connecteurs (`connectors__*`) et sous-agents (`delegate_task`, notifications relayées) ;
- `vision_analyze` / `video_analyze` sur une URL ;
- téléchargements via le terminal (curl, wget, nc, gh, scp, dig…) ou via du code réseau (`execute_code`, `python -c`…) ;
- les messages entrants des plateformes `webhook`, `msgraph_webhook` et `email`.

Les installations de paquets (pip, npm, apt, cargo…) et `git clone/fetch/pull` ne contaminent pas : c'est voulu.

La contamination survit à un redémarrage et suit la conversation quand l'identifiant change :
- compression du contexte (nouvel identifiant de session sans hook dédié) ;
- sous-agents ;
- appels internes d'`execute_code`.

`/new` repart propre.

**En session contaminée** :
- Passent : lectures pures (`read_file`, `search_files`, `session_search`, `skill_view`, recherches web, snapshots du navigateur…) et commandes shell en lecture pure (`ls`, `cat`, `grep`, `git status/log/diff`… ; analyseur prudent : la moindre redirection, substitution ou option qui écrit ou exécute en fait une action).
- Passent aussi les outils internes à la conversation : `todo_list`, `clarify`, `react_to_message`.
- S'arrête : tout le reste, y compris les outils inconnus.
- S'arrête aussi, même avec un outil de lecture : une URL jamais vue. Une URL est « vue » si elle figure telle quelle dans une page lue ou dans un de tes messages ; un domaine nu dans ton message vaut pour sa racine. Il en va de même pour un appel de lecture qui transporte un secret connu.

**Faits extraits par programme** (plancher de risque que le LLM ne peut pas abaisser) :
- hôtes contactés ;
- accès à des secrets : fichiers sensibles, variables, dumps d'environnement, jetons en clair, et valeurs réelles des secrets connus, même encodées en base64, hex, URL ou à l'envers ;
- persistance : mémoire, skills, cron, fichiers de démarrage, `authorized_keys`, `~/.hermes`, `AGENTS.md`… ;
- relais vers une autre session : `start_chat`, tâche kanban, prompt de cron ;
- code caché ou encodé ;
- élévation de privilèges ;
- destruction de données ;
- données transportées dans une URL jamais vue.

**Blocages automatiques** (sans question ; l'agent doit te le signaler sans contourner ; pour forcer, ouvre une session propre) :
- secrets et réseau dans la même action ;
- risque élevé sans aucun lien avec ta demande ;
- tentative de joindre l'endpoint de l'explicateur.

**Repli `/contamination`** : quand Hermes ne demanderait rien à personne, l'arrêt devient un blocage. C'est le cas en `/yolo`, avec `approvals.mode: off`, en isolation `host` du plugin ou si une API interne manque.
- `/contamination` affiche l'explication telle quelle.
- `/contamination ok <réf>` autorise **une seule fois** l'appel identique (valable 30 min) ; tu dis ensuite à Hermes de réessayer.
- En cron, en `-q` et sur les plateformes sans humain, c'est un refus pur et simple : voulu, puisque personne ne peut répondre.

Commandes : `/contamination`, `/contamination ok|non|voir <réf>`, `/contamination aide`.

## Réglages (facultatifs)

Dans `config.yaml` :

```yaml
plugins:
  entries:
    contamination:
      settings:
        trusted_mcp_servers: [mes-notes]       # leurs résultats ne contaminent pas
        read_only_tools: ["mcp__docs__search"] # motifs fnmatch traités comme lectures pures
        pass_tools: []                         # traités comme internes (passent)
        effect_tools: []                       # toujours arrêtés (prioritaire)
        extra_sources: []                      # outils supplémentaires qui contaminent
        untrusted_platforms: [webhook, msgraph_webhook, email]
        fallback: auto        # auto (défaut) | always (blocage systématique + /contamination) | never
        manual_ttl_minutes: 30
```

## Limites et recommandations

- **Risque d'oracle** : en backend terminal `local`, le terminal de l'agent peut lire `~/.hermes/.env`, donc l'URL et la clé de l'explicateur. Atténuations en place : dans une session contaminée, tout appel réseau est arrêté, toute action qui vise l'hôte:port de l'explicateur est bloquée, et la clé fait partie des secrets surveillés. Pour que l'endpoint ne soit joignable *que* par le processus Hermes, il faut un backend terminal isolé (docker ou ssh) dont le réseau ne voit pas GPU 2, ou une règle de pare-feu. Avec le backend `local`, c'est impossible : même utilisateur, même machine.
- **Réponses de l'agent** : le plugin défange ses propres messages, pas les réponses de l'agent. Un agent piégé peut écrire un lien porteur de données dans sa réponse finale. Les aperçus d'URL sont désactivés par défaut par Element dans les salons chiffrés ; garde-les désactivés.
- **♾️ « toujours »** vaut ici « cette action exacte, dans cette session » : la règle porte l'identifiant de session et un hachage de l'action. Hermes inscrit quand même une ligne `plugin_rule:contamination:…` inerte dans `command_allowlist` ; préfère ✅ ou 🌀.
- Après une compression du contexte, une action approuvée « pour la session » peut être redemandée une fois (nouvel identifiant de session).
- La revue mémoire/skills qu'Hermes lance en arrière-plan après un tour partage l'identifiant de session. En session contaminée, ses écritures sont arrêtées comme les autres, en pratique bloquées faute de lien avec ta demande.

## Tests

```bash
~/hermes-contamination/scripts/run_tests.sh   # [dossier hermes-agent], défaut ~/.hermes/hermes-agent
```

Le script crée un venv jetable (pytest), sans toucher à celui d'Hermes. Il lance :
- 192 tests unitaires et scénarios, sans Hermes ;
- 10 tests d'intégration qui chargent le plugin par le vrai `PluginManager` d'Hermes et font passer les arrêts par sa vraie porte d'approbation, avec un faux notificateur de passerelle (✅, ❌, ♾️, silence, `/yolo`). Ils tournent dans un `HERMES_HOME` jetable : ton profil n'est pas touché.

Procédure de test en live : [docs/TEST_LIVE.md](docs/TEST_LIVE.md). Inconnues levées dans le code d'Hermes : [docs/INCONNUES.md](docs/INCONNUES.md).

## Code

`contamination/` est le dossier du plugin, sans dépendance hors bibliothèque standard.

| Module | Rôle |
|---|---|
| `__init__.py` | `register(ctx)`, `hermes contamination doctor` |
| `core.py` | moteur des hooks, `/contamination` |
| `classify.py` | sources de contamination, lecture ou effet |
| `shell.py` | lecteur shell prudent |
| `facts.py` | faits et plancher de risque, carnet de secrets |
| `explainer.py` | client, prompt, validation |
| `render.py` | messages et défangage |
| `state.py` | état par session, filiation |
| `hermes_compat.py` | accès gardés aux internes d'Hermes |
| `urls.py`, `tlds.py` | URL, défangage, liste IANA |
