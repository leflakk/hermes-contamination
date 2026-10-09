# Inconnues levées dans le code d'Hermes

Lu dans le commit installé chez toi, `0d69d07b` (6 octobre 2026), puis comparé à `v0.21.6` : aucune différence sur ces points. Les références `fichier:ligne` renvoient à `0d69d07b`. Chaque conclusion est aussi vérifiée par `tests/integration`, qui fait tourner le vrai code d'Hermes sur les deux versions.

## 1. Affichage dans Matrix d'une approbation demandée par un plugin

`approve` passe par `request_tool_approval` (`tools/approval.py:1104`), puis par la même porte que les commandes dangereuses. La passerelle reçoit :
- `command` = `<nom_outil> (plugin approval rule)` : une étiquette fixe, **jamais la commande brute** ;
- `description` = **notre message**.

Les deux passent par `redact_sensitive_text`. La carte est construite par `_format_exec_approval` (`gateway/platforms/base.py:2850`) : en-tête, étiquette dans un bloc de code, puis `Why it was flagged: <notre message>`. Le message n'est **pas tronqué** (`_EA_REASON_BUDGET = 0`, `base.py:2799`). Le rendu Markdown de Matrix (extension `nl2br`) conserve nos retours à la ligne. Réactions proposées (`plugins/platforms/matrix/adapter.py:1669`) : ✅ une fois, 🌀 session, ♾️ toujours, ❌ refuser. Ligne finale : « sans réponse sous N minutes, l'action ne s'exécute pas ».

→ L'explication s'affiche en entier, seule et lisible. Le repli « bloquer + `/contamination` » n'est pas nécessaire dans le cas normal.

## 2. Le mode `smart` décide-t-il à la place de l'utilisateur ?

Non pour les approbations de plugin : `_run_approval_gate` (`tools/approval.py:951`) appelle `_human_decision` sans `smart`. Le gardien LLM ne voit que les commandes shell et `execute_code`. Le test d'intégration le confirme : en mode `smart`, le gardien n'est jamais appelé et la carte part chez l'humain.

**En revanche**, la porte accepte d'elle-même une approbation de plugin quand :
- `/yolo` est actif dans la session, ou que `--yolo` / `HERMES_YOLO_MODE` est donné au lancement ;
- `approvals.mode: off` ;
- en cron avec `approvals.cron_mode: approve`, ou en `-q` avec `approvals.single_query_mode: approve`.

Le plugin détecte ces cas (`hermes_compat.gate_status`) et bloque alors lui-même, avec le repli `/contamination` quand un humain peut répondre. S'il ne peut pas prouver qu'un humain sera interrogé, il bloque.

## 3. Ce que fait ♾️ « toujours » sur une approbation de plugin

`_persist_choice` (`tools/approval.py:381`) :
- 🌀 ajoute `plugin_rule:<rule_key>` aux approbations de la session (par clé de session de la passerelle) ;
- ♾️ fait la même chose **et** l'écrit dans `command_allowlist` de `config.yaml`, de façon permanente et valable pour toutes les sessions.

La portée est donc celle du `rule_key`. Si le plugin n'en fournit pas, Hermes prend **le nom de l'outil** (`hermes_cli/plugins.py:2069`) : un seul ♾️ sur `terminal` aurait laissé passer à vie tout `terminal` signalé par le plugin.

Le plugin fournit donc `rule_key = contamination:<hachage de l'identifiant de session>:<hachage de l'action exacte>`. ♾️ revient à 🌀 pour cette action exacte dans cette session. Il laisse une ligne inerte dans `config.yaml`, vérifié par le test d'intégration.

Deux effets de bord :
- deux demandes identiques simultanées sont fusionnées, et la seconde adopte 🌀, ♾️ ou ❌ de la première (`approval_gateway_wait.py:141`) ;
- une réaction Matrix résout la plus ancienne demande en attente de la session (`resolve_gateway_approval`, `approval.py:139`). Ce n'est pas gênant : l'exécuteur sérialise les demandes d'un lot parallèle.

## 4. Valeurs de `status` dans `post_tool_call`

- `ok` et `error` : déduits du résultat (`model_tools.py:658`) ;
- `blocked` : bloqué par un plugin, par la porte d'approbation (refus, délai dépassé, annulation) ou par un garde-fou ;
- `cancelled` : interruption, ou outil sauté ;
- `timeout` : délai de l'outil dépassé.

Il n'y a pas de valeur distincte pour « refusé » : le refus arrive en `blocked`, avec `error_message` = le message `BLOCKED: …` d'Hermes.

Le plugin enregistre la décision exacte par le hook `post_approval_response` (`choice` = `once`, `session`, `always`, `deny`, `timeout`, `cancelled` ou `notify_failed`), et `post_tool_call` sert de secours. La contamination est notée pour tout statut sauf `blocked`.

## 5. Stabilité de l'identifiant de session

- **Matrix** : l'identifiant est stable pour un salon tant qu'il n'y a ni `/new` ni remise à zéro par inactivité. `/new` crée un nouvel identifiant et déclenche `on_session_reset` avec l'ancien et le nouveau (`gateway/slash_commands_session.py:213`). La clé de session de la passerelle (`agent:main:matrix:…`) reste la même.
- **Compression du contexte** : un **nouvel identifiant** est créé (`agent/conversation_compression.py:3369`) **sans aucun hook de plugin**. De plus, `pre_llm_call.parent_session_id` n'est pas mis à jour : il vaut `agent._parent_session_id`, fixé à la création de l'agent (`agent/turn_context.py:803`).
  Le plugin suit donc la rotation par trois moyens, dans l'ordre : la clé de session de la passerelle ou le `task_id`, puis la colonne `parent_session_id` de `state.db` (lecture seule), en dernier recours.
  Une session avec historique hérite de la contamination. Une session sans historique (`/new`) part propre.
- **Sous-agents** : chacun a son propre identifiant. `subagent_start` donne le parent et l'enfant, et l'enfant hérite de la contamination du parent. Le résultat de `delegate_task` contamine le parent.
- **`execute_code`** : les appels d'outils faits depuis le script arrivent avec `session_id=""` et le `task_id` du parent (`tools/code_execution_rpc.py:30`). Le plugin retrouve la session par le `task_id`.
- **Revue mémoire/skills en arrière-plan** : après un tour, un agent dérivé **réutilise l'identifiant de session** (`agent/background_review.py:1025`) sans déclencher `pre_llm_call`. Ses écritures dans une session contaminée sont donc arrêtées comme les autres.

## 6. Stockage de l'état selon le profil

- Convention Hermes : `<HERMES_HOME>/plugin-data/<plugin>/` (`plugins/plugin_storage.py:27`), recalculé à chaque appel. Ce dossier suit le profil actif : `~/.hermes/plugin-data/contamination/` pour le profil par défaut, `~/.hermes/profiles/<nom>/plugin-data/contamination/` pour un autre.
- Le plugin s'installe dans `<HERMES_HOME>/plugins/contamination/`. Hermes efface ce dossier à la désinstallation et le remplace à la mise à jour : l'état ne doit pas y vivre.
- Le plugin écrit un JSON par session contaminée dans `plugin-data/contamination/sessions/`, en mode 600, avec une purge à 30 jours. Les sessions propres restent en mémoire. Aucun résultat d'outil n'est stocké : seulement les URL vues, les sources et le registre.

## Autres constats utiles

- **Délai des hooks** : un `pre_tool_call` qui dépasse `plugins.hook_callback_timeout` (30 s) bloque l'outil, et Hermes **suspend le callback 60 s**, ce qui bloque tous les outils pendant ce temps (`hermes_cli/plugins_dispatch.py:55`). Le plugin garde donc une marge de 4 s et un délai dur côté explicateur.
- **Échec d'un hook** : si `pre_tool_call` lève une exception, Hermes bloque (fail-closed). Si `post_tool_call` ou `pre_llm_call` lève une exception, Hermes ignore l'erreur (fail-open). Le plugin écrit donc le drapeau de contamination en premier.
- **Tool Search** : le pont `tool_call` est déballé avant les hooks (`agent/tool_executor.py:393`), qui voient le vrai nom de l'outil. Pour un lot de connecteurs, chaque entrée repasse par `pre_tool_call`.
- **Tours synthétiques** : les fins de processus en arrière-plan et les résultats de sous-agents asynchrones arrivent comme un message « utilisateur » commençant par `[SYSTEM: …`. Le plugin ne les compte pas comme des messages de l'utilisateur.
- **`MATRIX_APPROVAL_REQUIRE_SENDER`** vaut `true` par défaut : seul l'auteur de la demande peut réagir (`adapter.py:890`).
- **`plugins.isolation: host`** sort les plugins du processus Hermes. Le plugin ne voit alors plus `/yolo` et bloque systématiquement, avec `/contamination`.
- Nom des outils MCP : `mcp__<serveur>__<outil>`. Le plugin accepte aussi l'ancienne forme `mcp_<serveur>_<outil>`.
- **Scanner de sécurité des plugins** (`tools/plugin_guard.py`) : il tourne à `hermes plugins install`, `update` et `validate`, **pas au chargement**. Il classe ce plugin « dangerous » à cause de ses motifs de détection, et `--force` ne passe pas outre. D'où l'installation par copie (`scripts/install.sh`) puis `hermes plugins enable`.
